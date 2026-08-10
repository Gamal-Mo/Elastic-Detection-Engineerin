# Suspicious Scheduled Task Creation Detection

Detects the creation of new Windows Scheduled Tasks, a common technique attackers may abuse to establish persistence or execute commands automatically.

---

## MITRE ATT&CK

| Tactic | Technique |
| -------- | -------- |
| Persistence | T1053.005 – Scheduled Task/Job: Scheduled Task |

---

## Rule Information

| Property | Value |
| -------- | -------- |
| Rule Name | Suspicious Scheduled Task Creation |
| Severity | Medium |
| Risk Score | 47 |
| Event ID | 4698 |
| Data Source | Windows Security Logs |
| Provider | Microsoft-Windows-Security-Auditing |

---

## Detection Logic (KQL)

```kql
event.code:4698 and
event.outcome:"success"
```

---

## Why This Detection Matters

Windows Scheduled Tasks can be used by attackers to execute commands or programs automatically at a specific time, during system startup, or when a particular condition is triggered.

Attackers may abuse Scheduled Tasks for:

- Persistence
- Automated malware execution
- Command execution
- Privilege escalation
- Defense evasion
- Periodic execution of malicious payloads

A newly created Scheduled Task should therefore be investigated, especially when it executes suspicious commands, scripts, or binaries.

---

# Lab Environment

- Windows 10 Pro
- Elastic Security 8.x
- Elastic Agent 8.12.2
- Windows Security Logs
- PowerShell
- Windows Task Scheduler

---

# Attack Simulation

The Scheduled Task was created using the Windows `schtasks` utility.

The following command was used to simulate Scheduled Task creation:

```powershell
schtasks /create /tn "SOC-Lab-attack-Test" /tr "C:\Windows\System32\cmd.exe /c echo SOC-Lab" /sc once /st 23:59
```

Expected result:

```text
SUCCESS: The scheduled task "SOC-Lab-attack-Test" has successfully been created.
```

This generated **Windows Security Event ID 4698**.

---

# Windows Event 4698

## Event ID 4698 — A Scheduled Task Was Created

Windows Security Event ID **4698** records the creation of a new scheduled task.

Important information observed in the lab:

| Field | Value |
| -------- | -------- |
| Event ID | 4698 |
| Event Action | scheduled-task-created |
| Outcome | success |
| Account | gamal |
| Host | DESKTOP-0DFKSAT |
| Task Name | `\SOC-Lab-attack-Test` |
| Client Process ID | `3292` |
| Parent Process ID | `1620` |
| Command | `C:\Windows\System32\cmd.exe /c echo SOC-Lab` |

The event was successfully collected by Elastic Agent and indexed in the `system.security` data stream.

---

# Detection Rule

## Rule Name

**Suspicious Scheduled Task Creation**

## Detection Query

```kql
event.code:4698 and
event.outcome:"success"
```

## Rule Configuration

| Setting | Value |
| -------- | -------- |
| Rule Type | Custom Query |
| Severity | Medium |
| Risk Score | 47 |
| Event ID | 4698 |
| MITRE ATT&CK | T1053.005 – Scheduled Task/Job: Scheduled Task |
| Index Pattern | `logs-*` |

---

# Validation

The attack simulation successfully created the scheduled task:

```text
SOC-Lab-attack-Test
```

Windows generated:

```text
Event ID: 4698
```

Elastic successfully ingested the event and the custom detection rule matched the activity.

The rule generated a **Medium Severity Alert** in Elastic Security.

---

# Elastic Alert

The resulting Elastic Security alert contained:

```text
Rule:
Suspicious Scheduled Task Creation

Severity:
Medium

Risk Score:
47

Alert Reason:
iam, configuration event by gamal on desktop-0dfksat
created medium alert Suspicious Scheduled Task Creation.
```

The alert confirms that the scheduled task creation was successfully detected.

---

# Investigation

During triage, a SOC analyst should investigate:

- Task name
- Account that created the task
- Process responsible for creating the task
- Parent process
- Command executed by the task
- Executable or script path
- Task execution time
- Task trigger
- Task privileges
- Whether the account is authorized
- Whether the task was created by legitimate software
- Related PowerShell activity
- Related process creation events
- Related network activity

The analyst should pay particular attention to tasks that execute:

```text
PowerShell
cmd.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
regsvr32.exe
```

or execute files from suspicious locations such as:

```text
C:\Users\
C:\Users\Public\
C:\Temp\
C:\Windows\Temp\
C:\AppData\
C:\Downloads\
```

---

# Investigation Workflow

```text
Alert
  ↓
Identify Task Name
  ↓
Identify Account That Created the Task
  ↓
Inspect Task Action / Command
  ↓
Identify Client Process
  ↓
Identify Parent Process
  ↓
Review Process Creation Events
  ↓
Review PowerShell Activity
  ↓
Review Network Activity
  ↓
Determine Legitimate vs Malicious
  ↓
Contain / Escalate
```

---

# Event Correlation

Event ID **4698** should not always be treated as malicious by itself.

A stronger investigation can correlate the Scheduled Task creation with other Windows events.

### Useful Events

| Event ID | Description |
| -------- | -------- |
| 4698 | Scheduled Task Created |
| 4702 | Scheduled Task Updated |
| 4699 | Scheduled Task Deleted |
| 4688 | Process Creation |
| 4624 | Successful Logon |
| 4625 | Failed Logon |

For example:

```text
4698
Scheduled Task Created
        ↓
4688
Process Created
        ↓
PowerShell / CMD Execution
        ↓
Network Connection
        ↓
Potential Malicious Activity
```

---


## 5. Detection Alert

Elastic Security successfully generated a **Medium Severity Alert** for the Scheduled Task creation.

---

# Detection Summary

| Item | Result |
| -------- | -------- |
| Scheduled Task Created | ✅ |
| Event ID 4698 Generated | ✅ |
| Event Ingested by Elastic | ✅ |
| Detection Rule Triggered | ✅ |
| Alert Created | ✅ |
| Severity | Medium |
| Risk Score | 47 |
| MITRE Mapping | T1053.005 |

---

## MITRE ATT&CK Mapping

**T1053.005 – Scheduled Task/Job: Scheduled Task**

Attackers can abuse Windows Scheduled Tasks to execute malicious programs automatically and maintain persistence on compromised systems.

Scheduled Tasks are particularly useful to attackers because execution can be configured to occur at specific times or system events.

---

## Key Takeaway

This investigation demonstrates the complete SOC detection workflow:

```text
Attack Simulation
      ↓
Windows Security Event 4698
      ↓
Elastic Agent Collection
      ↓
KQL Detection Rule
      ↓
Elastic Security Alert
      ↓
SOC Investigation
```
