# Water Treatment ICS Security Assessment

![OT Security](https://img.shields.io/badge/Assessment-OT%2FICS%20Security-red)
![IEC 62443](https://img.shields.io/badge/Framework-IEC%2062443-blue)
![Modbus TCP](https://img.shields.io/badge/Protocol-Modbus%20TCP-orange)
![SOCI Act](https://img.shields.io/badge/Legislation-SOCI%20Act%202018-green)
![Python](https://img.shields.io/badge/Tools-Python%20%7C%20Wireshark%20%7C%20Docker-lightgrey)

## Reproducing the 2023 CyberAv3ngers Attack on Municipal Water Infrastructure

**Author:** Deepak Varma  
**Background:** 9 years 9 months operations, Security and process safety at Reliance Industries (world's largest oil refinery) and Tata Steel  
**Assessment Type:** OT Vulnerability Assessment, Penetration Test, and Remediation Verification  
**Target Sector:** Water and Wastewater - Australian Critical Infrastructure (SOCI Act 2018)  
**Frameworks:** IEC 62443 | MITRE ATT&CK for ICS | Purdue Reference Model | NIST SP 800-82  

---

## Executive Summary

In November 2023, Iranian Government-affiliated threat group CyberAv3ngers compromised Unitronics PLCs at the Municipal Water Authority of Aliquippa, Pennsylvania by exploiting unauthenticated Modbus TCP access. This project reproduces that attack in a controlled lab environment, demonstrates the complete attack chain with technical evidence, implements three IEC 62443 compensating controls, and verifies their effectiveness.

**Key Finding:** Modbus TCP has no built-in authentication. Any device that can reach port 502 can read all process values and send arbitrary write commands to the PLC with zero credentials.

---

## Lab Architecture

![Lab Architecture - Purdue Reference Model](diagrams/lab_architecture_purdue.png)

---

## Repository Structure

|    Folder      |              File                             |         Description                   |
|----------------|-----------------------------------------------|---------------------------------------|
| `/`            | `README.md`                                   | Project overview and evidence summary |
| `reports/`     | `OT_ICS_Security_Assessment_Report_Final.pdf` | 23-page OT security assessment report |
| `reports/`     | `Incident_Response_Report_INC-2026-001.pdf`   | 22-page incident response report      |
| `scripts/`     | `modbus_read.py`                              | Unauthenticated Modbus read exploit   |
| `scripts/`     | `modbus_write.py`                             | Unauthenticated Modbus write exploit  |
| `scripts/`     | `modbus_proxy.py`                             | Modbus function code filter proxy     |
| `scripts/`     | `water_booster_station.st`                    | OpenPLC PLC program                   |
| `screenshots/` | `01_openplc_monitoring_live_values.png`       | OpenPLC 4 live process variables      |
| `screenshots/` | `02_scadalts_watchlist_before_attack.png`     | Scada-LTS live values before attack   |
| `screenshots/` | `03_wireshark_modbus_plaintext.png`           | Unencrypted Modbus traffic capture    |
| `screenshots/` | `04_wireshark_modbus_coil_values.png`         | Coil values visible in plaintext      |
| `screenshots/` | `05_modbus_read_unauthenticated.png`          | Python read with zero credentials     |
| `screenshots/` | `06_attack_demonstration_full.png`            | Side by side attack and SCADA impact  |
| `screenshots/` | `07_scadalts_after_attack.png`                | SCADA dashboard showing all zeros     |
| `screenshots/` | `08_scadalts_attack_timeline_chart.png`       | 30-minute attack timeline chart       |
| `screenshots/` | `09_iptables_firewall_rules.png`              | Control 1 firewall rules evidence     |
| `screenshots/` | `10_iptables_with_logging.png`                | Control 3 audit logging evidence      |
| `screenshots/` | `11_modbus_proxy_running.png`                 | Control 2 proxy startup               |
| `screenshots/` | `12_retest_read_blocked.png`                  | Read blocked after controls           |
| `screenshots/` | `13_retest_write_blocked.png`                 | Write blocked after controls          |
| `screenshots/` | `14_proxy_blocking_write_FC5.png`             | Proxy blocking FC05 write command     |
| `screenshots/` | `15_scadalts_full_timeline_recovery.png`      | Complete recovery timeline            |
| `diagrams/`    | `lab_architecture_purdue.png`                 | Purdue model lab architecture         |


---

## Assessment Stages

### Stage 1 - Vulnerability Findings

**Finding 1 - Unauthenticated Read Access**  
Severity: Critical | CVSS: 9.8

Wireshark confirmed all Modbus TCP traffic is transmitted in cleartext. 
Python script read all 4 process variables with zero credentials.

![Unauthenticated Read](screenshots/05_modbus_read_unauthenticated.png)

**Finding 2 - Unauthenticated Write Access**  
Severity: Critical | CVSS: 10.0

Python script stopped the booster pump and disabled chlorination using Modbus FC05 write commands. No authentication required. Impact immediately visible in Scada-LTS SCADA dashboard.

![Attack Demonstration](screenshots/06_attack_demonstration_full.png)

![Attack Timeline](screenshots/08_scadalts_attack_timeline_chart.png)

---

### Stage 2 - Mitigations Implemented

| Control |                       Description                                                           | IEC 62443 |
|---------|---------------------------------------------------------------------------------------------|-----------|
| C-001   | IP allowlist firewall - iptables restricts port 502 to authorised SCADA IP only             |   SR 5.1  |
| C-002   | Modbus function code filter - Python proxy blocks FC05/06/15/16 from non-authorised sources |   SR 3.5  |
| C-003   | Audit logging - iptables LOG rule records all blocked attempts with MODBUS-BLOCKED prefix   |   SR 6.1  |

![Firewall Rules](screenshots/10_iptables_with_logging.png)

![Proxy Blocking FC05](screenshots/14_proxy_blocking_write_FC5.png)

---

### Stage 3 - Retest Results

|      Test                      | Before Controls | After Controls  |
|--------------------------------|-----------------|-----------------|
| Unauthorised read port 502     |   Succeeded     |   Blocked       |
| Unauthorised write port 502    |   Succeeded     |   Blocked       |
| Write FC05 via proxy port 5020 |   N/A           |   Blocked       |
| Authorised SCADA operation     |   Working       |   Still working |
| Blocked attempts logged        |   No            |   Yes           |

![Retest Read Blocked](screenshots/12_retest_read_blocked.png)

![Full Recovery Timeline](screenshots/15_scadalts_full_timeline_recovery.png)

---

## Full Reports

| Document | Description |
|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| [OT/ICS Security Assessment Report](reports/OT_ICS_Security_Assessment_Report_Final.pdf) | 23-page professional assessment report covering findings, IEC 62443 gap analysis, SOCI Act obligations, risk register, and remediation roadmap            |
| [Incident Response Report](reports/Incident_Response_Report_INC-2026-001.pdf)            | 22-page incident response report covering detection, timeline, MITRE ATT&CK mapping, root cause analysis, SOCI Act notification, and lessons learned      |

---

## Tools Used

OpenPLC Runtime v3 | Scada-LTS v2.8.0 | Wireshark 4.6.7 | Python 3.12 | pymodbus | Docker Desktop | iptables | draw.io

---

## Frameworks Referenced

- IEC 62443 - Industrial Automation and Control Systems Security
- MITRE ATT&CK for ICS - T0801, T0855, T0831, T0816
- Purdue Reference Model - ISA-95
- NIST SP 800-82 - Guide to ICS Security
- Australian SOCI Act 2018 - Security of Critical Infrastructure

## Real-World Relevance - OSINT Validation

To validate that the vulnerabilities demonstrated in this lab exist at scale in production environments, I conducted passive OSINT research using Shodan.

### Australian Exposure (port:502 country:AU)
- 3,310 devices in Australia respond on Modbus TCP port 502
- After filtering noise (honeypots, web servers, cloud instances), approximately 53 are confirmed Schneider Electric PLCs and industrial controllers directly internet-exposed
- Real OT devices identified include Modicon M221, M241, M340 series PLCs and ATV630 Variable Speed Drives
- Devices were geolocated across industrial and agricultural regions including rural Victoria's water management corridor
- All confirmed OT devices responded to unauthenticated Modbus queries — consistent with the vulnerability demonstrated in this lab

### Key Finding
Schneider Electric ATV630 Variable Speed Drives (22kW motor controllers) were identified internet-exposed in an agricultural water infrastructure region of Victoria. These devices control physical pump motors. Unauthenticated Modbus write access to a VSD allows remote motor speed manipulation - stopping, overspeeding, or rapidly cycling pumps with potential for water supply disruption and mechanical damage.

### What This Means
The three compensating controls implemented in this lab: IP allowlist firewall (IEC 62443 SR 5.1), Modbus function code filter (SR 3.5), and audit logging (SR 6.1) directly address this real-world exposure. Had these controls been in place, none of these devices would be reachable from the internet and none would appear in Shodan results.

### Methodology Note
All research was conducted passively using Shodan's existing scan data. No devices were connected to, probed, or interacted with in any way. Specific IP addresses and operator identities are not published in accordance with responsible disclosure principles.
