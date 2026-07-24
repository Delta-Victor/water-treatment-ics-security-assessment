# Water Treatment ICS Security Assessment

## Reproducing the 2023 CyberAv3ngers Attack on Municipal Water Infrastructure

**Author:** Deepak Varma  
**Background:** 9+ years operations and process safety at Reliance Industries (world's largest oil refinery) and Tata Steel  
**Assessment Type:** OT Vulnerability Assessment, Penetration Test, and Remediation Verification  
**Target Sector:** Water and Wastewater - Australian Critical Infrastructure (SOCI Act 2018)  
**Frameworks:** IEC 62443 | MITRE ATT&CK for ICS | Purdue Reference Model | NIST SP 800-82  

---

## Executive Summary

In November 2023, Iranian Government-affiliated threat group CyberAv3ngers compromised Unitronics PLCs at the Municipal Water Authority of Aliquippa, 
Pennsylvania by exploiting unauthenticated Modbus TCP access. This project reproduces that attack in a controlled lab environment, demonstrates the 
complete attack chain with technical evidence, implements three IEC 62443 compensating controls, and verifies their effectiveness.

**Key Finding:** Modbus TCP has no built-in authentication. Any device that can reach port 502 can read all process values and send arbitrary write 
commands to the PLC with zero credentials.

---

## Lab Architecture

![Lab Architecture - Purdue Reference Model](diagrams/lab_architecture_purdue.png)

---

## Repository Structure
water-treatment-ics-security-assessment/
│
├── README.md
│
├── reports/
│ ├── OT_ICS_Security_Assessment_Report_Final.pdf
│ └── Incident_Response_Report_INC-2026-001.pdf
│
├── scripts/
│ ├── modbus_read.py
│ ├── modbus_write.py
│ ├── modbus_proxy.py
│ └── water_booster_station.st
│
├── screenshots/
│ ├── 01 to 15 - Evidence screenshots
│
└── diagrams/
├── lab_architecture_purdue.png


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

Python script stopped the booster pump and disabled chlorination using Modbus FC05 write commands. No authentication required. Impact immediately 
visible in Scada-LTS SCADA dashboard.

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

