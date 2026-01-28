# Detection-and-Response-Using-Suricata-and-Wazuh-Project
SOC Detection and Response Project
# Detection & Response Lab – Suricata IDS + Wazuh SIEM/XDR (SOC + IR + Threat Hunting Portfolio)
![Uploading image.png…]()


> **CyberNova Academy – 100% Hands-On SOC & GRC Training**  
This project demonstrates a real-world **SOC detection + incident response workflow** using **Suricata (IDS/NSM)** and **Wazuh (SIEM/XDR)**.  
It includes **end-to-end setup**, **telemetry onboarding**, **alerting**, **IR triage**, and **threat hunting** with evidence, screenshots, and repeatable steps.

---

## Project Summary (What This Proves)
This lab proves practical capability in:
- **IDS deployment & tuning** (Suricata, ET rules, custom rules, Eve JSON)
- **SIEM onboarding & agent management** (Wazuh Manager, Agents, Indexer, Dashboard)
- **Telemetry pipelines** (Suricata Eve → Wazuh ingestion)
- **SOC alert triage** (severity, enrichment, pivots, evidence)
- **Incident Response** (containment actions, endpoint validation, reporting)
- **Threat Hunting** (repeatable hunts, IoC pivoting, validation tests)

---

## Architecture (Lab Design)

| Component | Role |
|---|---|
| **Ubuntu 22.04 (Sensor)** | Suricata IDS monitoring traffic |
| **Wazuh Server (All-in-one)** | Wazuh Manager + Indexer + Dashboard |
| **Windows 10/11 Endpoint** | Wazuh Agent + Sysmon telemetry |
| **Linux Endpoint** | Wazuh Agent + auth/system logs |
| **Attacker VM (Kali)** | Simulated attacks: scans, brute force, C2-like patterns |

**Traffic Flow**
- Suricata inspects traffic → writes **EVE JSON**
- Wazuh ingests Suricata logs → creates correlated alerts in Dashboard
- Agents provide endpoint context → enrich investigation

---

## Lab Requirements

### Recommended Specs
- Wazuh Server: **4 vCPU / 8–16 GB RAM / 100GB disk**
- Suricata Sensor: **2 vCPU / 4GB RAM**
- Endpoints: Windows + Linux (2 vCPU / 4GB RAM)

### Network Layout (Example)
- SOC-Lab Network: `192.168.56.0/24`
- Wazuh Server: `192.168.56.10`
- Suricata Sensor: `192.168.56.20`
- Windows Endpoint: `192.168.56.30`
- Linux Endpoint: `192.168.56.40`
- Kali: `192.168.56.50`

> Replace IPs to match your lab.

---

# 1) Install Wazuh (All-in-One)

## 1.1 Update System
```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install curl unzip apt-transport-https lsb-release gnupg

1.2 Install Wazuh (All-in-One)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

1.3 Capture Credentials (IMPORTANT)
At the end, Wazuh prints dashboard credentials. Save them securely.

1.4 Verify Services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

✅ Screenshot (Add to README):
images/wazuh-services-running.png
images/wazuh-dashboard-login.png

2) Install Wazuh Agent on Endpoints
2.1 Linux Agent (Ubuntu/Debian)
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER="192.168.56.10" dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

✅ Screenshot:
images/linux-agent-connected.png

2.2 Windows Agent (Recommended + Sysmon)
Download Wazuh Agent from official site and install.
During install, set Wazuh Manager to 192.168.56.10.

Install Sysmon (Windows)
Download Sysmon from Microsoft Sysinternals, then:

Sysmon64.exe -accepteula -i sysmonconfig.xml

3) Install Suricata Sensor (Ubuntu 22.04)
3.1 Install Suricata

sudo apt update
sudo apt -y install suricata jq tcpdump
suricata --build-info | head

3.2 Identify Sensor Interface
ip a
sudo ethtool -i <interface>

Example:
Interface: ens33
3.3 Enable Promiscuous Mode (for monitoring)

sudo ip link set ens33 promisc on
ip link show ens33

✅ Screenshot:

images/suricata-interface-promisc.png

4) Install & Update Rules (ET Open Rules)
4.1 Enable and Update Suricata Rules

sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open
sudo suricata-update

4.2 Validate Suricata Configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

✅ Screenshot:
images/suricata-config-test.png

5) Configure Suricata for EVE JSON Output

Suricata writes detections to:

/var/log/suricata/eve.json

Confirm in:
sudo grep -n "eve-log" -n /etc/suricata/suricata.yaml | head -n 30

Ensure enabled: yes and file path is correct.
Restart Suricata:

sudo systemctl enable suricata
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager

Tail logs:
sudo tail -f /var/log/suricata/eve.json

6) Send Suricata Logs to Wazuh (Integration)
6.1 Install Wazuh Agent on the Suricata Sensor

curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER="192.168.56.10" dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

6.2 Configure Wazuh Agent to Monitor Suricata eve.json

Edit:

sudo nano /var/ossec/etc/ossec.conf

Add under <localfile>:

<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>


Restart agent:

sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager


✅ Screenshot:

images/wazuh-agent-reading-suricata.png

7) Validate Detection – Generate Attacks (Kali)
7.1 Nmap Scan (Network Recon)
sudo nmap -sS -sV -Pn -T4 192.168.56.30
sudo nmap -A 192.168.56.40

7.2 Brute Force Simulation (SSH)
hydra -l test -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.40 -t 4

7.3 Suspicious HTTP Requests
curl -s "http://192.168.56.30/?cmd=whoami"
curl -s "http://192.168.56.30/?../../../../etc/passwd"


✅ Screenshots:

images/kali-nmap-attack.png

images/kali-hydra-attack.png

images/kali-suspicious-curl.png

8) SOC Alert Triage (Wazuh Dashboard)
8.1 What to Capture (Evidence Checklist)

In Wazuh Dashboard, capture:

Alert name / signature

Severity level

Source IP → Destination IP

Protocol and port

Timestamp

Rule ID + decoder output

Suricata metadata (ET category / signature)

MITRE mapping (if available in your tuning)

✅ Screenshots:

images/wazuh-alert-suricata-nmap.png

images/wazuh-alert-suricata-bruteforce.png

images/wazuh-alert-suricata-webattack.png

9) Threat Hunting (Repeatable Hunts)

The goal here is to demonstrate SOC analyst thinking: pivoting, timelines, clustering, and validation.

9.1 Hunt 1 – Top Source IPs Triggering Alerts (Suricata Events)

Use Wazuh Dashboard search to filter for Suricata events.
Example fields depend on your JSON parsing, but common pivots include:

src_ip, dest_ip, alert.signature, proto, dest_port

Hunting approach:

Filter last 24h → Suricata alerts only

Group by src_ip and alert.signature

Identify repeated patterns

✅ Screenshot:

images/hunt-top-src-ips.png

9.2 Hunt 2 – Recon to Exploit Chain

Hunting approach:

Find first recon indicator (nmap, scan)

Pivot same src_ip forward in time

Identify follow-on behaviors (brute force, web attacks)

✅ Screenshot:

images/hunt-recon-to-exploit.png

9.3 Hunt 3 – Confirm on Endpoint Telemetry (Wazuh Agent)

Hunting approach:

Pivot from network alert to endpoint events

For Windows: review Sysmon/Windows Security logs near time of alert

Confirm evidence of access attempts or suspicious process activity

✅ Screenshot:

images/hunt-endpoint-correlation.png

10) Incident Response Workflow (IR Case Notes)
10.1 IR Playbook (Tier 1 → Tier 2 Workflow)

1. Detect

Suricata signature alert triggers in Wazuh

2. Triage

Confirm severity, scope, affected host, traffic type, confidence

3. Contain

Block source IP on firewall (lab simulation)

Isolate endpoint (if confirmed compromise)

4. Eradicate

Remove malicious artifacts, close exposed services, patch

5. Recover

Restore services, validate, monitor for recurrence

6. Lessons Learned

Tune Suricata rules and Wazuh decoding

Add detection coverage

✅ Add Evidence Screenshots:

images/ir-case-timeline.png

images/ir-case-summary.png

11) Hardening & Detection Improvements (What Makes This “Advanced”)
11.1 Custom Suricata Rule (Demonstrates Detection Engineering)

Create:

sudo nano /etc/suricata/rules/local.rules


Add rule (example: suspicious user-agent):

alert http any any -> any any (msg:"LOCAL Suspicious UA - curl"; flow:to_server,established; http.user_agent; content:"curl"; nocase; classtype:bad-unknown; sid:9000001; rev:1;)


Ensure local.rules is included in suricata.yaml:

sudo grep -n "local.rules" /etc/suricata/suricata.yaml


Restart Suricata:

sudo systemctl restart suricata


Test:

curl -A "curl" http://192.168.56.30/


✅ Screenshot:

images/custom-rule-detection.png

11.2 Alert Noise Reduction (Tuning)

Disable noisy ET rules for your environment

Add thresholds/suppressions for known scanners in lab

Maintain a tuning log in repo

✅ Screenshot:

images/tuning-changes.png

12) Documentation & Reporting (Portfolio Deliverables)

This repository includes:

/docs/IR-Report.md (executive + technical)

/docs/Hunt-Notes.md (queries/pivots/timelines)

/docs/Detections.md (rules + mapping + tuning)

/images/ (screenshots evidence pack)

✅ Screenshots to include (Required):

Wazuh services running

Agent connection status (Linux/Windows/Sensor)

Suricata running + eve.json generating

Wazuh alerts for Nmap, brute force, web attack

Hunt pivots (top IPs, recon → exploit chain, endpoint correlation)

Custom rule detection

Repository Structure (Suggested)
.
├── README.md
├── docs
│   ├── IR-Report.md
│   ├── Hunt-Notes.md
│   ├── Detections.md
│   └── Tuning-Log.md
└── images
    ├── wazuh-services-running.png
    ├── wazuh-dashboard-login.png
    ├── suricata-config-test.png
    ├── suricata-eve-json-logs.png
    ├── wazuh-alert-suricata-nmap.png
    ├── wazuh-alert-suricata-bruteforce.png
    ├── hunt-recon-to-exploit.png
    └── custom-rule-detection.png

Key Skills Demonstrated

SOC Engineering: IDS setup, rule management, telemetry pipelines

Detection Engineering: ET rules + custom rules + tuning

SIEM/XDR: agent onboarding, log ingestion, alert triage

Threat Hunting: pivots, correlation, hypothesis-led hunts

Incident Response: playbook-driven response, reporting, lessons learned

Contact:

LinkedIn: https://www.linkedin.com/company/109275899/admin/page-posts/published/

Email: training@cybernovaacademy.com.au

Portfolio: https://github.com/cybernovaacademy/Detection-and-Response-Using-Suricata-and-Wazuh-Project/edit/main/README.md
