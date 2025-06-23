# 🕵️ Suspected Data Exfiltration
## Suspicious Insider Activity: John Doe Data Exfiltration Risk

In this investigation, we respond to a potential insider threat involving a disgruntled employee, John Doe, who was recently placed on a performance improvement plan (PIP). The security team suspects that John, who has administrative access to his corporate Windows device (`r3dant-ls-lab6`), may be attempting to exfiltrate proprietary information before resigning.

_**Inception State:**_ John is actively using his device. No official indicators of compromise yet, but behavior concerns have triggered a proactive hunt. The system is live, and no data loss has been confirmed.

_**Completion State:**_ Suspicious actions such as archiving files, using removable media, or uploading data to a personal cloud service are either confirmed or ruled out. All investigative findings are logged, mapped to MITRE ATT&CK, and mitigations are implemented.

---

## 🧰 Technology Utilized

- **Microsoft Defender for Endpoint (MDE)** – behavior and file tracking, device timeline, investigation tools  
- **PowerShell** – for scripting automation and local validation  

---

## 📑 Table of Contents

- [🕵️ Suspicious Insider Activity](#suspicious-insider-activity-john-doe-data-exfiltration-risk)  
- [🧰 Technology Utilized](#-technology-utilized)  
- [📑 Table of Contents](#-table-of-contents)  
- [🎯 Hypothesis & Investigation Scope](#-hypothesis--investigation-scope)  
- [🔍 Phase 1: Detect File Archiving Behavior](#-phase-1-detect-file-archiving-behavior)  
- [🌐 Phase 2: Correlate Process Activity Around the ZIP Event](#-phase-2-correlate-process-activity-around-the-zip-event)  
- [📤 Phase 3: Check for Network Exfiltration Activity](#-phase-3-check-for-network-exfiltration-activity)
- [🚨 Incident Response Actions](#-incident-response-actions)
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

To begin the investigation, I examined whether the employee attempted to compress or archive sensitive files. Compression is often a precursor to exfiltration, especially when bundled before being sent to cloud storage or removable drives.

### ✅ Microsoft Defender KQL Query

```kql
let target_machine = "r3dant-ls-lab6";
DeviceFileEvents 
| where DeviceName == target_machine
| where FileName endswith ".zip"
| order by Timestamp desc
```

**🧠 Why This Was Run:**
This search looks at .zip files created, renamed, or moved, which could indicate an effort to bundle multiple files together before exfiltration.

This timestamp was collected from one of the times it appeared the employee was participating in suspicious activity: 

2025-06-22T18:52:27.6025442Z

![image](https://github.com/user-attachments/assets/d1a0158d-76db-4f53-ae7a-4b357c7ea8f0)

While no overtly suspicious filenames (e.g., “Confidential”, “Passwords”) appeared, the regular compression of files in the user’s profile folder raises a flag when tied to behavioral concerns from HR.

---

## 🌐 Phase 2: Correlate Process Activity Around the ZIP Event  

After spotting repeated ZIP creation in **Phase 1**, we pivoted to the surrounding **process activity** to learn *how* the archives were generated.

### ✅ Microsoft Defender KQL Query (± 2 minutes window)

```kql
let VMName      = "r3dant-ls-lab6";
let specificTime = datetime(2025-06-22T18:52:27.6025442Z);   // ZIP creation time
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between (specificTime - 2m .. specificTime + 2m)
| order  by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```

Looking ± 2 minutes around the ZIP event reveals the exact chain of execution that produced the archive and surfaces any automation (scripts, scheduled tasks) the user might hide behind.


![image](https://github.com/user-attachments/assets/fc105366-2192-48f7-9516-f0be80b072f8)

Since I didn't know exactly what was going on with these files, I went to my trusted source to see if they could give me further insight on what may be happening here:


![image](https://github.com/user-attachments/assets/09b4af6b-6dec-4919-99d6-d454aa0c7309)


🔎 Findings:

A hidden PowerShell script (exfiltrateddata.ps1) installs 7-Zip quietly (/S) and immediately compresses sensitive data, a classic insider-threat tactic to stage files for exfiltration. 



| Timestamp (UTC)      | ActionType         | FileName         | ProcessCommandLine (trimmed)                                                        |
|----------------------|--------------------|------------------|--------------------------------------------------------------------------------------|
| 2025-06-22 18:52:24Z | **ProcessCreated** | `powershell.exe` | `-ExecutionPolicy Bypass -File C:\programdata\exfiltrateddata.ps1`                  |
| 2025-06-22 18:52:21Z | **ProcessCreated** | `7z2408-x64.exe` | `7z2408-x64.exe /S`                                                                  |
| 2025-06-22 18:52:19Z | **ProcessCreated** | `7z.exe`         | `"C:\Program Files\7-Zip\7z.exe" a "employee-data-20250622.zip" "C:\ProgramData\*"` |


---

## 📤 Phase 3: Check for Network Exfiltration Activity

After confirming the ZIP archive was created and staged using 7-Zip in **Phase 2**, I turned my focus to possible **network-based exfiltration attempts** (e.g., uploading the archive to cloud services or FTP/SFTP destinations).

---

### ✅ KQL Used in Microsoft Defender for Endpoint

```kql
let VMName       = "r3dant-ls-lab6";
let specificTime = datetime(2025-06-22T18:52:27.6025442Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

Despite suspicious ZIP activity on the VM, no outbound connections were logged during the same timeframe. Specifically:

- No HTTP/HTTPS connections to external domains (e.g., drive.google.com, dropbox.com, gmail.com)
- No unusual IPs or port activity indicating file transfer
- No use of FTP, SFTP, SCP, or similar exfiltration tools

The lack of outbound activity suggests the exfiltration step hasn’t happened...**YET**...the compressed archive may be staged locally (possibly to a backup folder or removable media) for delayed exfiltration.
This aligns with an early-stage insider threat, where staging occurs first and data transfer is executed later (e.g., outside of business hours or using offline methods).

---

## 🚨 Incident Response Actions

1. **Immediate Isolation**   
   As soon as repeated archiving activity was confirmed, `r3dant-ls-lab6` was **isolated in Microsoft Defender for Endpoint** to halt any potential data movement.

2. **Management Notification**   
   A detailed report containing timestamps, PowerShell script evidence, and ZIP creation intervals, was sent to John's manager and HR.

3. **No Confirmed Exfiltration**   
   Phase 3 showed **no network-based data transfer** in the window examined. We are monitoring for deferred or offline exfiltration.

4. **Awaiting Next Steps**   
   The security team is standing by for management’s direction on forensic imaging, user interview, or device reinstatement.

---

## 🧩 MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                   | Evidence in This Incident                                                                                   |
|---------------------|-------------|------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Execution**       | `T1059.001` | Command & Scripting Interpreter — PowerShell                     | PowerShell script silently downloaded and installed 7-Zip.                                                  |
| **Defense Evasion** | `T1218.001` | Signed Binary Proxy Execution — PowerShell                        | Leveraged trusted `powershell.exe` to evade basic application controls.                                     |
| **Collection**      | `T1119`     | Automated Collection                                             | Script iterated through `C:\ProgramData\*` to identify files for archiving.                                 |
| **Exfiltration**    | `T1560.001` | Archive Collected Data — Archive via Utility (7-Zip)             | 7-Zip compressed files into `employee-data-*.zip`.                                                          |
| **Persistence** 🔄   | `T1053.005` | Scheduled Task/Job — Scheduled Task                              | Interval pattern suggests a possible scheduled task (needs confirmation).                                   |
| **Discovery** 🔍    | `T1083`     | File and Directory Discovery                                     | Script likely enumerated directories to build the archive list (implied by breadth of files captured).      |

> **Next Action Items:** Run a Defender *Live Response* session to search for scheduled tasks, confirm persistence, and image the system for full forensic analysis if management approves.

---

## 🔧 Recommended Mitigations

| Category            | Mitigation Action                                                                 | Tool / Method                       | Priority |
|---------------------|------------------------------------------------------------------------------------|-------------------------------------|----------|
| Access Control       | Revoke local admin rights for high-risk users                                     | Intune, GPO, Defender XDR           | 🔴 High   |
| Application Control | Block unauthorized use of PowerShell and 7-Zip                                    | AppLocker / WDAC                    | 🟡 Medium |
| Endpoint Monitoring | Enable PowerShell script block logging                                             | GPO, Defender for Endpoint          | 🟡 Medium |
| Data Loss Prevention| Monitor for ZIP creation in sensitive directories                                  | Microsoft Sentinel, File Audit      | 🟠 Medium |
| Exfiltration Alerting| Configure rules to detect access to personal cloud services (e.g., Dropbox, Gmail)| Azure Firewall, Sentinel Analytics  | 🔴 High   |
| USB Control         | Block or restrict USB write access                                                 | Intune Device Restrictions          | 🟠 Medium |
| Scheduled Task Scan | Regular audit for unauthorized recurring jobs/tasks                                | MDE Live Response, Sysinternals     | 🔴 High   |

---

## 📊 Summary Table

| Phase       | Action Taken                                      | Status         | Evidence Captured                            |
|-------------|----------------------------------------------------|----------------|-----------------------------------------------|
| Phase 1     | Detected recurring ZIP creation on device          | ✅ Complete     | `DeviceFileEvents`, archive paths, timestamps |
| Phase 2     | Correlated process chain (PowerShell → 7-Zip)      | ✅ Complete     | `DeviceProcessEvents`, script details         |
| Phase 3     | Checked for outbound exfiltration activity         | ✅ Complete     | `DeviceNetworkEvents`, no exfil found         |
| Response    | Isolated system, informed management               | ✅ Complete     | Isolation timestamp, escalation summary       |
| ATT&CK Map  | Mapped observed behavior to MITRE techniques       | ✅ Complete     | `T1059.001`, `T1560.001`, `T1218.001`, etc.    |
| Mitigation  | Outlined preventive and detective countermeasures  | ✅ Complete     | Sentinel rules, GPO hardening recommendations |





