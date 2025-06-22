# 🕵️ Suspected Data Exfiltration
## Suspicious Insider Activity: John Doe Data Exfiltration Risk

In this investigation, we respond to a potential insider threat involving a disgruntled employee, John Doe, who was recently placed on a performance improvement plan (PIP). The security team suspects that John, who has administrative access to his corporate Windows device (`r3dant-ls-lab6`), may be attempting to exfiltrate proprietary information before resigning.

_**Inception State:**_ John is actively using his device. No official indicators of compromise yet, but behavior concerns have triggered a proactive hunt. The system is live, and no data loss has been confirmed.

_**Completion State:**_ Suspicious actions such as archiving files, using removable media, or uploading data to a personal cloud service are either confirmed or ruled out. All investigative findings are logged, mapped to MITRE ATT&CK, and mitigations are implemented.

---

## 🧰 Technology Utilized

- **Microsoft Defender for Endpoint (MDE)** – behavior and file tracking, device timeline, investigation tools  
- **Azure Log Analytics + Microsoft Sentinel** – centralized event collection and KQL detection queries  
- **PowerShell** – for scripting automation and local validation  
- **Splunk (Alternative)** – parallel log review and alerting using Windows logs and Sysmon

---

## 📑 Table of Contents

- [🕵️ Suspicious Insider Activity](#suspicious-insider-activity-john-doe-data-exfiltration-risk)  
- [🧰 Technology Utilized](#-technology-utilized)  
- [📑 Table of Contents](#-table-of-contents)  
- [🎯 Hypothesis & Investigation Scope](#-hypothesis--investigation-scope)  
- [🔍 Phase 1: Detect File Archiving Behavior](#-phase-1-detect-file-archiving-behavior)  
- [🌐 Phase 2: Detect External File Transfers](#-phase-2-detect-external-file-transfers)  
- [📤 Phase 3: Cloud App or Email Usage](#-phase-3-cloud-app-or-email-usage)  
- [🧩 MITRE ATT&CK Mapping](#-mitre-attck-mapping)  
- [🔧 Recommended Mitigations](#-recommended-mitigations)  
- [📊 Summary Table](#-summary-table)

---

## 🎯 Hypothesis & Investigation Scope

**Hypothesis:**  
John Doe may be compressing and archiving sensitive files to exfiltrate company IP using removable drives, personal email, or cloud storage tools like Google Drive or Dropbox.

**Why This Is Needed:**  
This scenario mirrors real-world insider threats. Admin privileges and emotional motivation (PIP status) create a perfect condition for intentional sabotage or theft.

**Enterprise Context:**  
Behavioral analysis is crucial for threat hunting. This project simulates a proactive security team using MDE and Sentinel to flag anomalous user behavior and mitigate risk before damage occurs.

---

## 🔍 Phase 1: Detect File Archiving Behavior

### ✅ Microsoft Defender KQL Query

```kql
let target_machine = "r3dant-ls-lab6";
DeviceFileEvents 
| where DeviceName == target_machine
| where FileName endswith ".zip"
| order by Timestamp desc
```


