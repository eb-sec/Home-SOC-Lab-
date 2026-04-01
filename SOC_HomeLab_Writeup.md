# Home SOC Lab – Brute-Force-Angriff erkennen und analysieren

**Autor:** Elias Bach  
**Datum:** April 2026  
**Tools:** Wazuh 4.7, VirtualBox 7.x, Ubuntu Server 22.04, Kali Linux 2024  
**Schwerpunkt:** Log-Analyse, Alert-Triage, Detection Engineering

---

## Was ich mir dabei gedacht habe

Ich wollte nicht nur TryHackMe-Labs machen, sondern einmal den kompletten Ablauf selbst durchspielen: Angriff simulieren, Logs beobachten, Alerts verstehen, eigene Regel schreiben. Ich habe vorher bereits einen eigenen Python-basierten Nmap-Scanner gebaut und dabei verstanden, wie Netzwerkscanning auf Protokollebene funktioniert. Dieses Lab war der nächste logische Schritt: zu sehen, was auf der Empfängerseite passiert, wenn jemand scannt und angreift.

---

## Architektur

```
+------------------+        +-------------------+        +------------------+
|   Kali Linux VM  | -----> |  Ubuntu Server VM | -----> |   Wazuh SIEM VM  |
|  (Angreifer)     |  SSH   |  (Ziel/Agent)     |  Logs  |  (Manager)       |
+------------------+        +-------------------+        +------------------+
```

Alle drei Maschinen laufen unter VirtualBox in einem isolierten internen Netzwerk (kein Internetzugang, kein Zugriff auf das Heimnetz). Der Wazuh Agent auf der Zielmaschine schickt Logs an den Wazuh Manager, der sie auswertet und im Dashboard anzeigt.

| VM | Betriebssystem | Rolle | RAM |
|---|---|---|---|
| Wazuh Manager | Ubuntu 22.04 LTS | SIEM | 4 GB |
| Zielmaschine | Ubuntu 22.04 LTS | Agent / Angriffsziel | 2 GB |
| Angreifer | Kali Linux 2024 | Simulation | 2 GB |

---

## Aufbau der Umgebung

### Schritt 1 – VirtualBox und Netzwerk

Alle drei VMs wurden unter VirtualBox 7.x aufgesetzt. Netzwerkadapter jeweils auf **Internes Netzwerk** gestellt, damit die Maschinen untereinander kommunizieren können, aber vom restlichen Netzwerk getrennt bleiben.

### Schritt 2 – Wazuh Manager installieren

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Das Skript installiert Manager, Indexer und Dashboard in einem Durchgang. Anschließend ist das Dashboard über `https://<Manager-IP>` erreichbar.

### Schritt 3 – Wazuh Agent auf der Zielmaschine installieren

Ab Ubuntu 22.04 ist `apt-key add` deprecated. Der aktuelle Weg:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /etc/apt/keyrings/wazuh.gpg
echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='<Manager-IP>' apt-get install wazuh-agent
systemctl enable --now wazuh-agent
```

### Schritt 4 – SSH aktivieren

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

---

## Simulation des Angriffs

Von der Kali-VM wurde ein SSH-Brute-Force-Angriff mit Hydra gestartet:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<Ziel-IP> -t 4
```

`-t 4` bedeutet vier parallele Verbindungen gleichzeitig. Mit rockyou.txt kommen so innerhalb kurzer Zeit hunderte fehlgeschlagene Authentifizierungsversuche zusammen, die alle im `/var/log/auth.log` der Zielmaschine landen.

---

## Alert-Analyse im Wazuh Dashboard

### Ausgelöste Regeln

Die ersten Alerts erschienen innerhalb weniger Sekunden nach Angriffsstart:

| Rule ID | Beschreibung | Level |
|---|---|---|
| 5711 | sshd: Attempt to login using a non-existent user | 5 |
| 5712 | SSHD brute force trying to get access to the system | 10 |

### Log-Beispiel (auth.log)

```
Apr 01 14:23:11 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54872 ssh2
Apr 01 14:23:11 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54873 ssh2
Apr 01 14:23:12 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54874 ssh2
```

### Triage-Einschätzung

**Angriffstyp:** SSH Brute Force (Password Guessing)  
**Quell-IP:** 192.168.56.101 (Kali VM)  
**Ziel:** Ubuntu Server, Port 22  
**Ergebnis:** Kein erfolgreicher Login

**Timeline:**

| Zeit | Ereignis |
|---|---|
| 14:23:11 | Erste fehlgeschlagene Authentifizierung von 192.168.56.101 |
| 14:23:11–14:24:08 | Kontinuierliche Fehlversuche, Peak bei ca. 8 Versuchen/Sekunde |
| 14:23:14 | Rule 5712 feuert erstmals (Brute Force erkannt) |
| 14:24:09 | Hydra gestoppt, letzte fehlgeschlagene Verbindung |
| 14:24:15 | IP-Blockierung über ufw gesetzt |
| 14:24:20 | Kontrollversuch bestätigt: keine neuen Auth-Log-Einträge |

Rule 5712 hat den Angriff korrekt identifiziert. Die hohe Frequenz fehlgeschlagener Logins von derselben IP innerhalb kurzer Zeit ist ein klarer Indikator für einen automatisierten Angriff. In einer produktiven Umgebung wäre jetzt eine Eskalation mit dieser Timeline fällig sowie eine sofortige IP-Blockierung auf Perimeter-Ebene.

---

## Eigene Detection Rule

Die Standardregel 5712 feuert relativ früh. Ich habe eine zusätzliche Regel geschrieben, die beim zehnten Fehlversuch von derselben IP innerhalb von 30 Sekunden einen Alert auf Level 12 auslöst:

```xml
<rule id="100001" level="12" frequency="10" timeframe="30">
  <if_matched_sid>5711</if_matched_sid>
  <same_source_ip />
  <description>High-frequency SSH brute force from single source IP</description>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5</group>
</rule>
```

`frequency="10"` bedeutet: die Regel feuert beim zehnten Treffer der Basisregel 5711 innerhalb des definierten Zeitfensters. Das reduziert False Positives bei Nutzern, die sich ein paarmal vertippen, ohne echte Angriffe zu verpassen.

Bewusst gewählt wurde 5711 als Basis und nicht 5712. Rule 5712 ist selbst bereits eine aggregierte Regel. Sie feuert erst, nachdem Wazuh intern mehrere Einzelereignisse gezählt hat. Wer eine Custom Rule auf 5712 aufbaut, stapelt zwei Zähler übereinander und verliert die Kontrolle über den genauen Schwellenwert. Mit 5711 als Basis wird direkt auf dem Rohereignis gezählt, jedem einzelnen fehlgeschlagenen Login und das Zeitfenster lässt sich sauber kalibrieren.

---

## Gegenmaßnahme

Die Quell-IP wurde manuell auf der Zielmaschine geblockt:

```bash
sudo ufw deny from 192.168.56.101 to any
sudo ufw reload
```

Anschließend wurde der Angriff erneut gestartet. Neue Verbindungsversuche wurden von der Firewall verworfen, `auth.log` blieb still.

---

## MITRE ATT&CK Mapping

| Technik | ID | Beschreibung |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Automatisiertes Durchprobieren von Passwörtern gegen SSH |

---

## Was ich mitgenommen habe

Den größten Lerneffekt hatte nicht der Angriff selbst, sondern das Schreiben der eigenen Detection Rule. Erst dabei habe ich verstanden, wie Wazuh intern mit Frequenz und Zeitfenster arbeitet und warum die Standardregeln manchmal zu früh oder zu spät feuern. Der Unterschied zwischen einem Alert, der erscheint und einem Alert, der etwas bedeutet, liegt oft in dieser Kalibrierung.

Außerdem: SSH auf Port 22 mit aktivem Root-Login ist in einem echten System keine gute Idee. Fail2ban hätte die IP nach wenigen Fehlversuchen automatisch gesperrt. Beides habe ich nach dem Lab entsprechend angepasst.

---

## Nächster Schritt

Geplant ist ein Phishing-Szenario mit simulierter Payload-Ausführung und anschließender Log-Analyse auf dem Endpoint.

---

## Umgebung zum Nachbauen

| Komponente | Version | Link |
|---|---|---|
| VirtualBox | 7.x | https://www.virtualbox.org |
| Wazuh | 4.7 | https://wazuh.com |
| Ubuntu Server | 22.04 LTS | https://ubuntu.com |
| Kali Linux | 2024.x | https://www.kali.org |
