# Rule 01 - Suspicious Encoded PowerShell Execution

## Objective

Detect PowerShell executions that use the `-EncodedCommand` or `-enc` arguments, a technique frequently used to obfuscate malicious commands.

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |

---

## Detection Logic

The rule detects PowerShell processes that include encoded command arguments.

### KQL Query

```kql
event.code:1 and
process.name:("powershell.exe" or "pwsh.exe") and
(
  process.args:"-enc" or
  process.args:"-EncodedCommand"
)
```

---

## Test Environment

| Component | Version |
|-----------|---------|
| Windows | Windows 10 Pro |
| Elastic Stack | 8.12.0 |
| Elastic Agent | 8.12.2 |
| Sysmon | Installed |
| Data Source | Microsoft-Windows-Sysmon/Operational |

---

## Attack Simulation

The following command was executed to simulate the attack:

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACIA
```

---

## Raw Event Evidence

The following information was observed from the generated Sysmon event:

| Field | Value |
|------|-------|
| Event ID | 1 |
| Provider | Sysmon |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| User | gamal |
| Integrity Level | High |

---

## Detection Rule Configuration

| Setting | Value |
|---------|-------|
| Rule Type | Custom Query |
| Severity | Medium |
| Risk Score | 50 |
| Interval | 1 Minute |
| Look-back | 2 Minutes |

---

## Alert Generated

The detection rule successfully generated a Security Alert.

### Alert Index

```text
.internal.alerts-security.alerts-default-000001
```

---

## Investigation

The generated alert was successfully linked to the original Sysmon event.

### Reviewed Fields

- `process.command_line`
- `process.args`
- `process.parent.name`
- `user.name`
- `host.name`
- `event.code`

---

## Detection Outcome

✅ **Detection Successful**

The custom detection rule successfully generated a Security Alert whenever PowerShell was executed using encoded command arguments.

---
