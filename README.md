# Wazuh + Sysmon Lab 10
# Detecting Encoded PowerShell Execution

## Objective

This lab demonstrates how Sysmon and Wazuh detect PowerShell processes executed with the **-EncodedCommand** parameter.

Attackers frequently use Base64-encoded PowerShell commands to hide malicious activity from defenders.

The goal is to generate the activity safely, collect telemetry, investigate the event, and understand why it is considered suspicious.

---

## MITRE ATT&CK

Technique:
T1059.001 – PowerShell

Tactic:
Execution

---

## Lab Environment

Windows 11

Sysmon

Wazuh Agent

Wazuh Manager

PowerShell

---

## Scenario

A user launches PowerShell using the **-EncodedCommand** argument.

Sysmon records the complete process creation event.

Wazuh ingests the Sysmon logs.

The SOC analyst investigates:

- Process Creation
- Parent Process
- Command Line
- Encoded Command
- User Context
- Process Hashes

---

## Commands Used

Create encoded command:

```powershell
$Command = "Write-Output 'Hello Wazuh'"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
```

Execute:

```powershell
powershell.exe -EncodedCommand $Encoded
```

Verify Sysmon Event ID 1:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
-FilterXPath "*[System[(EventID=1)]]" `
-MaxEvents 50 |
Where-Object {$_.Message -match "EncodedCommand"}
```

---

## Investigation Steps

1. Execute encoded PowerShell

2. Verify command executes successfully

3. Confirm Sysmon Event ID 1

4. Open Wazuh Threat Hunting

5. Search for:

```

data.win.eventdata.commandLine:*EncodedCommand*

```

6. Review:

- Parent Process
- Process Image
- Command Line
- User
- Hashes
- Current Directory

---

## Detection

Sysmon Event ID

Event ID 1

Process Creation

Interesting Field

CommandLine

Detection Indicator

EncodedCommand

---

## MITRE Mapping

Execution

T1059.001

PowerShell

---

## Learning Outcomes

✔ Process Creation telemetry

✔ Encoded PowerShell detection

✔ Parent-child process analysis

✔ Command-line hunting

✔ Wazuh Threat Hunting

✔ MITRE ATT&CK mapping

---


- Wazuh Threat Hunting
- Event Details
