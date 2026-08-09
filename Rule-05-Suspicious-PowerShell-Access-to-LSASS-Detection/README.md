# Suspicious PowerShell Access to LSASS Detection

Detects **PowerShell processes attempting to access the LSASS process with a high-privilege process access mask**, a behavior that may indicate credential access or LSASS memory dumping activity.

---

## MITRE ATT&CK

| Tactic | Technique |
| -------- | -------- |
| Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory |

---

## Rule Information

| Property | Value |
| -------- | -------- |
| Rule Name | Suspicious PowerShell Access to LSASS |
| Severity | High |
| Risk Score | 73 |
| Event ID | 10 |
| Data Source | Sysmon Operational Logs |
| Provider | Microsoft-Windows-Sysmon |
| Event Action | ProcessAccess |

---

## Detection Logic (KQL)

```kql
event.code:10 and
winlog.event_data.TargetImage:*lsass.exe* and
process.name:"powershell.exe" and
winlog.event_data.GrantedAccess:"0x1f3fff"
```

---

## Why This Detection Matters

`lsass.exe` is a critical Windows process responsible for authentication and security operations.

Attackers may attempt to access LSASS memory to obtain sensitive authentication material such as:

- Password hashes
- NTLM credentials
- Kerberos credentials
- Cached authentication information
- Other credential material stored in LSASS memory

A PowerShell process accessing LSASS with a high-privilege access mask is suspicious because PowerShell is commonly used during post-exploitation and credential-access activity.

The detection focuses on:

- Sysmon Event ID 10
- PowerShell as the source process
- `lsass.exe` as the target process
- High-privilege `GrantedAccess` value `0x1F3FFF`

---

# Lab Environment

- Windows 10 Pro
- Elastic Security 8.x
- Elastic Agent
- Sysmon
- Sysmon Event ID 10
- PowerShell

---

# Attack Simulation

The activity was simulated using PowerShell to request high-privilege access to the LSASS process.

The following PowerShell code was used:

```powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class LSASSAccess
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        int processId
    );
}
"@

$lsass = Get-Process lsass
[LSASSAccess]::OpenProcess(0x1F0FFF, $false, $lsass.Id)
```

The script retrieves the LSASS process ID and calls the Windows `OpenProcess` API with a high-privilege access mask.

This generated a Sysmon **Event ID 10 – ProcessAccess** event.

---

# Windows Event

## Event ID 10 — Process Access

Sysmon Event ID **10** records when one process opens another process.

The generated event contained the following important information:

```text
Event ID: 10
Event Action: ProcessAccess
Source Process: powershell.exe
Target Process: lsass.exe
GrantedAccess: 0x1F3FFF
Source User: DESKTOP-0DFKSAT\gamal
Target User: NT AUTHORITY\SYSTEM
```

Observed event:

```text
SourceImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetImage:
C:\Windows\system32\lsass.exe

GrantedAccess:
0x1F3FFF
```

---

# GrantedAccess

The `GrantedAccess` field represents the permissions requested when the source process accesses the target process.

The observed value was:

```text
0x1F3FFF
```

This represents a very high level of process access.

A high access mask against `lsass.exe` is suspicious because attackers may request powerful permissions when attempting to read or interact with LSASS memory.

However, **Event ID 10 alone does not prove credential dumping**. Legitimate software can also access LSASS, so the activity must be investigated in context.

---

# Detection Rule

## Rule Name

**Suspicious PowerShell Access to LSASS**

## Detection Query

```kql
event.code:10 and
winlog.event_data.TargetImage:*lsass.exe* and
process.name:"powershell.exe" and
winlog.event_data.GrantedAccess:"0x1f3fff"
```

## Rule Configuration

| Setting | Value |
| ------------- | ----------------------------------------------- |
| Rule Type | Custom Query |
| Severity | High |
| Risk Score | 73 |
| Event ID | 10 |
| MITRE ATT&CK | T1003.001 – OS Credential Dumping: LSASS Memory |
| Index Pattern | `logs-*` |

---

# Validation

The PowerShell simulation successfully generated **Sysmon Event ID 10**.

Elastic Discover showed the matching event with:

- `process.name: powershell.exe`
- `TargetImage: C:\Windows\system32\lsass.exe`
- `GrantedAccess: 0x1f3fff`

The custom Elastic detection rule successfully matched the event and generated a **High Severity Security Alert**.

---

# Detection Alert

Elastic Security generated the following alert:

**Suspicious PowerShell Access to LSASS**

Alert details:

| Field | Value |
| -------------- | -------------- |
| Severity | High |
| Risk Score | 73 |
| Source Process | powershell.exe |
| Target Process | lsass.exe |
| Event ID | 10 |
| GrantedAccess | 0x1f3fff |

The alert confirmed that the detection logic successfully identified the simulated suspicious process access.

---

# Investigation

During triage, a SOC analyst should verify:

- Source process
- Target process
- Source user
- Target user
- GrantedAccess value
- Process command line
- Parent process
- Process hash
- Digital signature
- PowerShell activity
- PowerShell Operational logs
- Network connections
- Other processes accessing LSASS
- Evidence of credential dumping
- Whether the activity was authorized

The analyst should correlate **Sysmon Event ID 10** with additional endpoint telemetry to determine whether the activity was legitimate or malicious.

---

# Investigation Workflow

```text
Alert
  ↓
Identify Source Process
  ↓
Confirm Target = LSASS
  ↓
Review GrantedAccess
  ↓
Identify Source User
  ↓
Check Parent Process
  ↓
Review Process Creation Event
  ↓
Review PowerShell Activity
  ↓
Check Command Line
  ↓
Check File Hash & Digital Signature
  ↓
Look for Credential Dumping Indicators
  ↓
Check Network Activity
  ↓
Determine Legitimate vs Malicious
  ↓
Contain / Escalate
```

---

# Investigation Questions

When this alert fires, the analyst should ask:

### 1. Is PowerShell expected?

Determine whether PowerShell was launched by an authorized user, administrator, or legitimate application.

### 2. What launched PowerShell?

Review the parent process and process creation telemetry.

For example:

```text
explorer.exe → powershell.exe
```

requires different investigation from:

```text
winword.exe → powershell.exe
```

### 3. What command was executed?

Review PowerShell Operational logs and other available PowerShell telemetry.

Look for:

- Credential access
- Memory dumping
- Encoded commands
- Download activity
- Suspicious scripts
- Security tool discovery

### 4. Is the source process legitimate?

Verify:

- File path
- Digital signature
- File hash
- User
- Parent process
- Execution context

### 5. Are there additional LSASS access events?

Search for other processes accessing LSASS around the same timestamp.

Multiple suspicious processes accessing LSASS may provide additional evidence of credential-access activity.

---



# Detection Summary

| Item | Result |
| --------------------------------- | --------- |
| Sysmon Event ID 10 Generated | ✅ |
| PowerShell Accessed LSASS | ✅ |
| High-Privilege Access Detected | ✅ |
| GrantedAccess `0x1F3FFF` Observed | ✅ |
| KQL Rule Triggered | ✅ |
| Alert Created | ✅ |
| Severity | High |
| MITRE Mapping | T1003.001 |

---

## MITRE ATT&CK Mapping

**T1003.001 – OS Credential Dumping: LSASS Memory**

LSASS memory may contain sensitive authentication material. Attackers can attempt to access or dump LSASS memory as part of credential-access activity.

This detection focuses specifically on suspicious PowerShell process access to LSASS using a high-privilege access mask.

---

## Why Sysmon Event ID 10 Is Important

Sysmon Event ID **10 – ProcessAccess** provides visibility into processes accessing other processes.

Monitoring access to security-sensitive processes such as:

```text
lsass.exe
```

can help identify:

- Credential dumping
- Credential theft
- Malicious memory access
- Post-exploitation activity
- Suspicious PowerShell behavior

Because legitimate applications may also access LSASS, Event ID 10 should be investigated alongside process creation, command-line, user, parent-process, and other endpoint telemetry.

---

## Key Takeaway

This detection identifies suspicious **PowerShell access to LSASS** using Sysmon Event ID 10 and a high-privilege `GrantedAccess` value.

The lab demonstrated the complete SOC detection workflow:

**Attack Simulation → Sysmon Event 10 → Elastic Discover → KQL Detection → Elastic Alert → Investigation**

The combination of:

**PowerShell + LSASS + High GrantedAccess**

creates a strong investigation signal for potential credential-access activity.
```
