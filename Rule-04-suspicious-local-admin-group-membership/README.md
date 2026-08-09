# Suspicious Local Administrator Group Membership Detection

Detects successful additions of accounts to the **local Administrators group**, a common technique attackers may use to obtain elevated privileges and maintain persistence on a Windows endpoint.

---

## MITRE ATT&CK

| Tactic | Technique |
| -------- | -------- |
| Privilege Escalation | T1098 – Account Manipulation |

---

## Rule Information

| Property | Value |
| -------- | -------- |
| Rule Name | Suspicious Local Administrator Group Membership |
| Severity | High |
| Risk Score | 73 |
| Event ID | 4732 |
| Data Source | Windows Security Logs |
| Provider | Microsoft Windows Security Auditing |

---

## Detection Logic (KQL)

```kql
event.code:4732 and
user.target.group.name:"Administrators" and
event.outcome:"success"
```

---

## Why This Detection Matters

Adding an account to the **Administrators** group grants the account elevated privileges on the Windows endpoint.

Attackers may abuse this behavior to:

- Gain administrative privileges
- Establish persistence
- Execute privileged commands
- Disable security controls
- Install malicious software
- Continue post-exploitation activity

A newly created or unexpected account added to the Administrators group should therefore be investigated.

---

# Lab Environment

- Windows 10 Pro
- Elastic Security 8.x
- Elastic Agent
- Windows Security Logs
- PowerShell

---

# Attack Simulation

The attack was simulated in two stages.

### 1. Create a Local User

The following command was used to create a new local Windows account:

```powershell
net user socattacker P@sword123 /add
```

This generated **Windows Event ID 4720**, indicating that a new user account was created.

Expected result:

```text
The command completed successfully.
```

---

### 2. Add the User to Administrators

The newly created account was added to the local Administrators group:

```powershell
net localgroup Administrators socattacker /add
```

Expected result:

```text
The command completed successfully.
```

This generated **Windows Event ID 4732**, indicating that a member was added to a security-enabled local group.

---

# Windows Events

## Event ID 4720 — User Account Created

The first stage of the simulation generated Event ID **4720**.

Important information observed:

- Account Name: `socattacker`
- Event ID: `4720`
- Action: User Account Created

This event provides useful context for determining whether the account added to Administrators was newly created.

---

## Event ID 4732 — Member Added to Administrators

The second stage generated Event ID **4732**.

Important information observed:

- Event ID: `4732`
- Target Group: `Administrators`
- Outcome: `Success`
- Added Account: `socattacker`

This is the primary event used by the detection rule.

---

# Detection Rule

## Rule Name

**Suspicious Local Administrator Group Membership**

## Detection Query

```kql
event.code:4732 and
user.target.group.name:"Administrators" and
event.outcome:"success"
```

## Rule Configuration

| Setting | Value |
| -------- | -------- |
| Rule Type | Custom Query |
| Severity | High |
| Risk Score | 73 |
| Event ID | 4732 |
| MITRE ATT&CK | T1098 – Account Manipulation |
| Index Pattern | `logs-*` |

---

# Validation

The simulated activity successfully generated Windows Security Event IDs **4720** and **4732**.

The Elastic detection rule successfully matched the Event ID 4732 activity and generated a **High Severity Security Alert**.

The detection was tested using the `socattacker` account and was successfully identified after the account was added to the local Administrators group.

---

# Investigation

During triage, a SOC analyst should verify:

- Account name that was added
- Account that performed the action
- Target group
- Whether the account was newly created
- Source host
- Associated logon activity
- Process responsible for the change
- Whether the activity was authorized
- Activity performed by the newly privileged account
- Additional persistence mechanisms
- Additional privilege escalation activity

The analyst should correlate **Event ID 4720** with **Event ID 4732** to determine whether a newly created account was immediately granted administrative privileges.

---

# Investigation Workflow

```text
Alert
  ↓
Identify Added Account
  ↓
Identify Actor
  ↓
Check Event ID 4720
  ↓
Determine Whether Account Was Newly Created
  ↓
Review Logon Activity
  ↓
Review Process Activity
  ↓
Review PowerShell Activity
  ↓
Check Network Activity
  ↓
Determine Legitimate vs Malicious
  ↓
Contain / Escalate
```

---



# Detection Summary

| Item | Result |
| -------- | -------- |
| User Created | ✅ |
| Event ID 4720 Generated | ✅ |
| User Added to Administrators | ✅ |
| Event ID 4732 Generated | ✅ |
| Rule Triggered | ✅ |
| Alert Created | ✅ |
| Severity | High |
| MITRE Mapping | T1098 |

---

## MITRE ATT&CK Mapping

**T1098 – Account Manipulation**

Attackers may manipulate accounts or group memberships to obtain additional privileges or maintain access to a compromised system.

Adding a compromised or newly created account to a privileged group can provide the attacker with elevated access to the endpoint.

---

## Why Event ID 4732 Is Important

Event ID **4732** records when a member is added to a security-enabled local group.

Monitoring additions to privileged groups such as **Administrators** can help identify:

- Privilege escalation
- Persistence
- Unauthorized account changes
- Post-exploitation activity
- Compromised administrator accounts

The event should always be investigated in context because legitimate administrators and software installations can also modify group membership.

---

## Key Takeaway

This detection identifies successful additions of accounts to the local **Administrators** group.

The lab demonstrated the complete SOC detection workflow:

**Attack Simulation → Windows Security Logs → Event Analysis → KQL Detection → Elastic Alert → Investigation**

The correlation between **Event ID 4720 (User Account Created)** and **Event ID 4732 (Member Added to Administrators)** provides valuable context for identifying suspicious account creation and privilege escalation activity.
