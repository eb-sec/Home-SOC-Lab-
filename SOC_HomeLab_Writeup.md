Home SOC Lab – Detecting and Analyzing a Brute-Force Attack
Author: Elias Bach
Date: April 2026
Tools: Wazuh 4.7, VirtualBox 7.x, Ubuntu Server 22.04, Kali Linux 2024
Focus: Log Analysis, Alert Triage, Detection Engineering

My Reasoning
I didn't want to just work through TryHackMe labs — I wanted to run the complete cycle myself: simulate an attack, observe logs, understand alerts, and write my own detection rule. I had already built a Python-based Nmap scanner and through that gained a solid understanding of how network scanning works at the protocol level. This lab was the logical next step: seeing what happens on the receiving end when someone scans and attacks.

Architecture
```
+------------------+        +-------------------+        +------------------+
|   Kali Linux VM  | -----> |  Ubuntu Server VM | -----> |   Wazuh SIEM VM  |
|  (Attacker)      |  SSH   |  (Target/Agent)   |  Logs  |  (Manager)       |
+------------------+        +-------------------+        +------------------+
```


All three machines run under VirtualBox in an isolated internal network (no internet access, no access to the home network). The Wazuh Agent on the target machine forwards logs to the Wazuh Manager, which evaluates them and displays them in the dashboard.
VMOperating SystemRoleRAMWazuh ManagerUbuntu 22.04 LTSSIEM4 GBTarget MachineUbuntu 22.04 LTSAgent / Attack Target2 GBAttackerKali Linux 2024Simulation2 GB

Environment Setup
Step 1 – VirtualBox and Networking
All three VMs were set up under VirtualBox 7.x. Network adapters were each set to Internal Network, so the machines can communicate with each other while remaining isolated from the rest of the network.
Step 2 – Install Wazuh Manager
bashcurl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
The script installs Manager, Indexer, and Dashboard in a single pass. The dashboard is then accessible via https://<Manager-IP>.
Step 3 – Install Wazuh Agent on the Target Machine
As of Ubuntu 22.04, apt-key add is deprecated. The current approach:
bashcurl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /etc/apt/keyrings/wazuh.gpg
echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='<Manager-IP>' apt-get install wazuh-agent
systemctl enable --now wazuh-agent
Step 4 – Enable SSH
bashsudo apt install openssh-server
sudo systemctl enable --now ssh

Attack Simulation
An SSH brute-force attack was launched from the Kali VM using Hydra:
bashhydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<Target-IP> -t 4
```

`-t 4` means four parallel connections simultaneously. With rockyou.txt, hundreds of failed authentication attempts accumulate within a short time — all landing in `/var/log/auth.log` on the target machine.

---

## Alert Analysis in the Wazuh Dashboard

### Triggered Rules

The first alerts appeared within seconds of the attack starting:

| Rule ID | Description | Level |
|---|---|---|
| 5711 | sshd: Attempt to login using a non-existent user | 5 |
| 5712 | SSHD brute force trying to get access to the system | 10 |

### Log Sample (auth.log)
```
Apr 01 14:23:11 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54872 ssh2
Apr 01 14:23:11 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54873 ssh2
Apr 01 14:23:12 ubuntu sshd[1842]: Failed password for root from 192.168.56.101 port 54874 ssh2
Triage Assessment
Attack Type: SSH Brute Force (Password Guessing)
Source IP: 192.168.56.101 (Kali VM)
Target: Ubuntu Server, Port 22
Outcome: No successful login
Timeline:
TimeEvent14:23:11First failed authentication from 192.168.56.10114:23:11–14:24:08Continuous failed attempts, peak at approx. 8 attempts/second14:23:14Rule 5712 fires for the first time (brute force detected)14:24:09Hydra stopped, last failed connection14:24:15IP block applied via ufw14:24:20Control attempt confirmed: no new auth.log entries
Rule 5712 correctly identified the attack. The high frequency of failed logins from the same IP within a short period is a clear indicator of an automated attack. In a production environment, this timeline would trigger an escalation as well as an immediate IP block at the perimeter level.

Custom Detection Rule
The default rule 5712 fires relatively early. I wrote an additional rule that triggers a Level 12 alert on the tenth failed attempt from the same IP within 30 seconds:
xml<rule id="100001" level="12" frequency="10" timeframe="30">
  <if_matched_sid>5711</if_matched_sid>
  <same_source_ip />
  <description>High-frequency SSH brute force from single source IP</description>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5</group>
</rule>
frequency="10" means the rule fires on the tenth hit of the base rule 5711 within the defined time window. This reduces false positives for users who mistype their password a few times, without missing real attacks.
The choice to use 5711 as the base rather than 5712 was deliberate. Rule 5712 is itself already an aggregated rule — it only fires after Wazuh has internally counted several individual events. Building a custom rule on top of 5712 stacks two counters on top of each other and loses precise control over the threshold. Using 5711 as the base means counting directly on the raw event — each individual failed login — and the time window can be cleanly calibrated.

Countermeasure
The source IP was manually blocked on the target machine:
bashsudo ufw deny from 192.168.56.101 to any
sudo ufw reload
The attack was then restarted. New connection attempts were dropped by the firewall; auth.log remained silent.

MITRE ATT&CK Mapping
TechniqueIDDescriptionBrute Force: Password GuessingT1110.001Automated password guessing against SSH

Key Takeaways
The biggest learning effect came not from the attack itself, but from writing the custom detection rule. Only through that process did I truly understand how Wazuh handles frequency and time windows internally — and why default rules sometimes fire too early or too late. The difference between an alert that appears and an alert that means something often comes down to that calibration.
Also worth noting: SSH on port 22 with root login enabled is not a good idea on a real system. Fail2ban would have automatically blocked the IP after just a few failed attempts. Both of these were adjusted accordingly after the lab.

Next Step
A phishing scenario with simulated payload execution and subsequent endpoint log analysis is planned.

Reproducing the Environment
ComponentVersionLinkVirtualBox7.xhttps://www.virtualbox.orgWazuh4.7https://wazuh.comUbuntu Server22.04 LTShttps://ubuntu.comKali Linux2024.xhttps://www.kali.org
