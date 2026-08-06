# Suspicious Windows Service Creation Detection

Detects Windows services installed from **user-writable or otherwise suspicious directories**, a common persistence technique used by attackers to automatically execute malware after system startup.

---

## MITRE ATT&CK

| Tactic | Technique |
|---------|-----------|
| Persistence | T1543.003 – Create or Modify System Process: Windows Service |

----
## Rule Information

| Property | Value |
|----------|-------|
| Rule Name | Suspicious Windows Service Creation |
| Severity | High |
| Risk Score | 73 |
| Event ID | 7045 |
| Data Source | Windows System Logs |
| Provider | Service Control Manager |

---

## Detection Logic (KQL)

```kql
event.code:7045 and
(
    winlog.event_data.ImagePath:*Users* or
    winlog.event_data.ImagePath:*Temp* or
    winlog.event_data.ImagePath:*AppData* or
    winlog.event_data.ImagePath:*Downloads* or
    winlog.event_data.ImagePath:*Desktop*
)
```

---

## Why This Detection Matters

Windows services are commonly used by attackers to establish **persistence** because they can automatically start during system boot and run with elevated privileges.

Legitimate services are typically installed under trusted directories such as:

- `C:\Windows\`
- `C:\Program Files\`
- `C:\Program Files (x86)\`

Services installed from locations like:

- `C:\Users\`
- `C:\Temp\`
- `C:\Downloads\`
- `C:\AppData\`
- `C:\Desktop\`

should be investigated because these directories are writable by standard users and are frequently abused by malware.

---

# Lab Environment

- Windows 10 Pro
- Elastic Security 8.x
- Elastic Agent
- Windows Event Logs
- PowerShell

---

# Attack Simulation

The following command simulates an attacker creating a Windows service whose executable resides inside a suspicious directory.

```powershell
sc.exe create attacktest binPath= "C:\Temp\cmd.exe"
```

Expected Windows Event:

```
Event ID: 7045
Provider: Service Control Manager
```

---

# Validation

The service installation generated **Windows Event ID 7045**.

The custom Elastic detection rule matched the event and generated a **High Severity Alert**.

---

# Investigation

During triage an analyst should verify:

- Service Name
- Executable Path
- Service Account
- Parent Process
- File Hash
- Digital Signature
- VirusTotal Reputation
- Whether the service is currently running
- Additional persistence mechanisms

---

# 
# Detection Summary

| Item | Result |
|------|--------|
| Event Generated | ✅ |
| Rule Triggered | ✅ |
| Alert Created | ✅ |
| Severity | High |
| MITRE Mapping | T1543.003 |

---

## Key Takeaway

This detection identifies one of the most common persistence techniques used by attackers. By monitoring Windows Service installations whose executables are located in user-writable directories, defenders can quickly identify suspicious or unauthorized services before they become long-term persistence mechanisms.
