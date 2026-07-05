# Investigation Notes

## Alert

Encoded PowerShell execution detected.

---

## Initial Observation

PowerShell was started using the **-EncodedCommand** argument.

The command line contains a Base64-encoded payload.

---

## Evidence Collected

### Event ID

1

(Process Creation)

---

### Process

powershell.exe

---

### Parent Process

pwsh.exe

---

### User

DESKTOP-9MMM37V\Dell

---

### Command Line

```
powershell.exe -EncodedCommand <Base64 String>
```

---

### Process Hashes

SHA1

SHA256

MD5

Captured successfully.

---

### Current Directory

C:\Windows\System32

---

## Why Attackers Use EncodedCommand

Attackers commonly encode PowerShell commands to:

- Evade simple detections
- Hide malicious scripts
- Deliver malware
- Download payloads
- Execute in-memory attacks

Although Base64 encoding is not encryption, it helps conceal command content from casual inspection.

---

## MITRE ATT&CK

Technique

T1059.001

PowerShell

---

## Detection Logic

Look for:

-EncodedCommand

or

-enc

within Process Creation events.

---

## Severity

Medium

If combined with:

- Network connections
- Script downloads
- Credential dumping

Severity becomes High or Critical.

---

## Analyst Conclusion

This lab successfully demonstrated detection of encoded PowerShell execution using Sysmon Event ID 1 and Wazuh Threat Hunting.

The command line was captured, allowing defenders to identify potentially obfuscated PowerShell activity.
