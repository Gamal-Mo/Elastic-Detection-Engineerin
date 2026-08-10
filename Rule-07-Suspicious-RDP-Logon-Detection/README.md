# Suspicious RDP Logon Detection

Detects successful Windows **Remote Desktop Protocol (RDP) logons** using Security Event ID **4624** with **Logon Type 10 (RemoteInteractive)**.

RDP is commonly used for legitimate remote administration, but attackers may abuse it using stolen or compromised credentials to gain remote access to Windows systems.

This detection helps identify successful RDP logons that should be investigated based on the source IP, user account, login time, and activity following the login.

---

## MITRE ATT&CK

| Tactic | Technique |
| -------- | -------- |
| Initial Access | T1021.001 – Remote Services: Remote Desktop Protocol |

---

## Rule Information

| Property | Value |
| -------- | -------- |
| Rule Name | Suspicious RDP Logon |
| Severity | Medium |
| Risk Score | 47 |
| Event ID | 4624 |
| Logon Type | 10 – RemoteInteractive |
| Data Source | Windows Security Logs |
| Provider | Microsoft Windows Security Auditing |
| Rule Type | Custom Query |
| Index Pattern | `logs-*` |

---

## Detection Logic (KQL)

```kql
event.code:4624 and
winlog.event_data.LogonType:"10" and
event.outcome:"success"
```

---

## Why This Detection Matters

**RDP (Remote Desktop Protocol)** allows users to remotely access and control a Windows system.

While RDP is commonly used by administrators and legitimate users, attackers can abuse exposed or compromised RDP services to gain access to Windows endpoints.

Successful RDP logons may indicate:

- Unauthorized remote access
- Compromised credentials
- Initial access
- Lateral movement
- Remote administration abuse
- Post-exploitation activity

A successful RDP login should therefore be investigated based on the user, source address, time, and activity following the login.

---

# Lab Environment

- Windows 10 Pro
- Elastic Security 8.x
- Elastic Agent
- Windows Security Logs
- VirtualBox
- Remote Desktop Protocol (RDP)

---

# Attack Simulation

The RDP activity was simulated by connecting to the Windows endpoint using **Remote Desktop Connection**.

The connection successfully created a Windows Security **Event ID 4624**.

The important field was:

```text
Logon Type: 10
```

Logon Type 10 represents:

```text
RemoteInteractive
```

This indicates that the account was successfully authenticated through a remote interactive session such as RDP.

---

# Windows Event Analysis

## Event ID 4624 — Successful Logon

Event ID **4624** is generated when an account is successfully logged on.

The captured event contained:

```text
Event ID: 4624
Logon Type: 10
Account Name: gamal
Account Domain: DESKTOP-0DFKSAT
Logon Process: User32
Authentication Package: Negotiate
Elevated Token: Yes
```

The event also contained the source address:

```text
Source Network Address:
fe80::e62e:1916:426a:9435
```

The process associated with the logon was:

```text
C:\Windows\System32\svchost.exe
```

---

# Important Fields

| Field | Value |
| -------- | -------- |
| Event ID | `4624` |
| Logon Type | `10` |
| Logon Type Name | `RemoteInteractive` |
| User | `gamal` |
| Host | `DESKTOP-0DFKSAT` |
| Authentication Package | `Negotiate` |
| Logon Process | `User32` |
| Elevated Token | Yes |
| Source IP | `fe80::e62e:1916:426a:9435` |
| Process | `svchost.exe` |

---

# Detection Rule

## Rule Name

**Suspicious RDP Logon**

## Detection Query

```kql
event.code:4624 and
winlog.event_data.LogonType:"10" and
event.outcome:"success"
```

## Rule Configuration

| Setting | Value |
| -------- | -------- |
| Rule Type | Query |
| Severity | Medium |
| Risk Score | 47 |
| Event ID | 4624 |
| Logon Type | 10 |
| MITRE ATT&CK | T1021.001 |
| Index Pattern | `logs-*` |

---

# Validation

The RDP connection successfully generated Windows Security Event ID **4624** with **Logon Type 10**.

Elastic successfully matched the event using the detection query and generated a **Medium Severity Security Alert**.

The alert was displayed in Elastic Security as:

```text
Suspicious RDP Logon
```

The detection successfully identified the remote interactive logon for the `gamal` account.

---

# Elastic Alert

The generated alert contained:

```text
Rule:
Suspicious RDP Logon

Severity:
Medium

Risk Score:
47

Event:
4624

Logon Type:
10 - RemoteInteractive

User:
gamal
```

The alert confirms that the detection rule successfully identified the simulated RDP activity.

---

# Investigation

When investigating a successful RDP logon, a SOC analyst should verify:

- Username
- Source IP address
- Destination host
- Logon time
- Logon Type
- Whether the user normally uses RDP
- Whether the source IP is expected
- Whether the account is privileged
- Whether the login occurred outside normal working hours
- Previous failed logons
- Other successful logons from the same source
- Process activity after the login
- PowerShell activity
- Command-line activity
- Network connections
- File creation
- Scheduled task creation
- Account changes
- Privilege escalation activity

---

# Investigation Workflow

```text
Alert
  ↓
Identify User
  ↓
Confirm Logon Type 10
  ↓
Identify Source IP
  ↓
Identify Destination Host
  ↓
Check User's Normal RDP Activity
  ↓
Review Previous Failed Logons
  ↓
Review Successful Logons
  ↓
Check Process Activity
  ↓
Check PowerShell Activity
  ↓
Check Network Activity
  ↓
Check Persistence / Privilege Escalation
  ↓
Determine Legitimate vs Malicious
  ↓
Contain / Escalate
```

---

# Correlation Opportunities

A successful RDP logon should not always be considered malicious by itself.

The alert becomes more suspicious when correlated with additional activity.

### Example 1 — Brute Force Followed by Successful RDP

```text
Multiple 4625 Failed Logons
        ↓
Successful 4624 Logon
        ↓
Logon Type 10
        ↓
Possible Credential Compromise
```

### Example 2 — RDP Followed by PowerShell

```text
4624
Logon Type 10
        ↓
PowerShell Execution
        ↓
Suspicious Commands
        ↓
Possible Post-Exploitation
```

### Example 3 — RDP Followed by Persistence

```text
4624
Logon Type 10
        ↓
Scheduled Task Creation
        ↓
Event ID 4698
        ↓
Possible Persistence
```

---


Alert:

```text
Suspicious RDP Logon
```

Severity:

```text
Medium
```

Risk Score:

```text
47
```

---

## 3. Detection Rule

Shows the Elastic Security detection rule configuration.

Query:

```kql
event.code:4624 and
winlog.event_data.LogonType:"10" and
event.outcome:"success"
```

---

## 4. Event ID 4624

Shows the Windows Security Event ID 4624 containing:

```text
Logon Type: 10
Account Name: gamal
Source Network Address: fe80::e62e:1916:426a:9435
```

---

## 5. Event Investigation

Shows the expanded Event ID 4624 document in Elastic Discover for detailed investigation.

---

# Detection Summary

| Item | Result |
| -------- | -------- |
| RDP Connection Simulated | ✅ |
| Event ID 4624 Generated | ✅ |
| Logon Type 10 Detected | ✅ |
| Successful Authentication | ✅ |
| Elastic Rule Triggered | ✅ |
| Alert Created | ✅ |
| Severity | Medium |
| Risk Score | 47 |
| MITRE Mapping | T1021.001 |

---

## MITRE ATT&CK Mapping

**T1021.001 – Remote Services: Remote Desktop Protocol**

Attackers may use RDP to remotely access Windows systems using valid or compromised credentials.

RDP can be used for:

- Initial Access
- Lateral Movement
- Remote Administration
- Post-Exploitation

Monitoring successful RDP authentication events helps security teams identify potentially unauthorized remote access.

---

## Why Logon Type 10 Is Important

Windows Logon Type **10** represents a **RemoteInteractive** logon.

It is commonly associated with Remote Desktop Services / RDP sessions.

Example:

```text
Event ID: 4624
Logon Type: 10
```

This combination indicates that an account successfully authenticated through a remote interactive session.

However, Logon Type 10 by itself does **not** prove malicious activity.

The SOC analyst must investigate the context surrounding the login.

---

## Key Takeaway

This detection identifies successful Windows **RDP logons** by monitoring Security Event ID **4624** with **Logon Type 10**.

The lab demonstrated the complete SOC detection workflow:

**RDP Simulation → Windows Security Event 4624 → Logon Type Analysis → KQL Detection → Elastic Alert → Investigation**

The most important investigation points are the **user account, source IP, login time, and activity following the RDP session**.

```
