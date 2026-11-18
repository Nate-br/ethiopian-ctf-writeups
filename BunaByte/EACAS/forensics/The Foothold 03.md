---
title: "The Foothold 03"
category: forensics
platform: EACAS
difficulty: Medium
points: 200
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Foothold 03

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> After the malicious file from Challenge 2 was executed, it didn't just run once the attacker wanted to make sure they could get back in even after a reboot.
>
> The malware created a Windows Scheduled Task that runs every time the system starts up, calling back to the attacker's server. This is how the attacker maintained persistent access to the network for days before deploying the ransomware.
>
> We've exported the Windows Security Event Logs from the compromised workstation. Find the name of the malicious scheduled task the attacker created.

**Files:** `the foothold.zip` → `artifacts/security_events.evtx` (Windows Event Log, 69,632 bytes)

**Environment & prerequisites:**

- **OS:** Linux
- **Key tools:** `unzip`, `strings`, `python3`, `python-evtx`

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Download 02 — Phishing Payload]]
- **Next:** [[The Coverup 04]]
- **Related:** [[The Foothold — Scheduled Task Persistence]]

## Solution

### 1. Extract the Challenge Archive

```bash
$ unzip -o "the foothold.zip"
Archive:  the foothold.zip
   creating: artifacts/
  inflating: artifacts/security_events.evtx
```

The archive extracts a single Windows Event Log file: `artifacts/security_events.evtx`.

### 2. Windows Event Log Triage

Inspecting the `.evtx` file using `python-evtx` reveals 10 events recorded across a narrow 7-minute window on 2026-06-17:

| EventRecordID | Time (UTC) | Event ID | Description / Activity |
|---|---|---|---|
| 739323 | 19:50:58 | 4624 | SYSTEM logon (`services.exe`) |
| 739324 | 19:50:58 | 4672 | Special privileges assigned to SYSTEM |
| 739325 | 19:55:30 | 4624 | SYSTEM logon (`svchost.exe`) |
| 739326 | 19:55:30 | 4672 | Special privileges assigned to SYSTEM |
| 739327 | 19:55:33 | 4624 | SYSTEM logon (`svchost.exe`) |
| 739328 | 19:55:33 | 4672 | Special privileges assigned to SYSTEM |
| 739329 | 19:55:37 | 4799 | Security-enabled local group membership enumerated (Administrators) |
| 739330 | 19:55:37 | 4799 | Security-enabled local group membership enumerated (Backup Operators) |
| 739331 | 19:57:34 | **4719** | Audit policy modified by user **A** (Detailed Tracking / Subcategory `%%12804`) |
| 739332 | 19:57:38 | **4698** | **Scheduled task created by user A** |

### 3. Extracting and Analyzing Event ID 4698

Windows logs **Event ID 4698** whenever a scheduled task is created. Extracting this record using a Python script:

```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

with evtx.Evtx("artifacts/security_events.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        eid = root.find(".//ns:EventID", ns).text
        if eid == "4698":
            for data in root.findall(".//ns:Data", ns):
                name = data.attrib.get("Name")
                print(f"{name}: {data.text}")
```

Alternatively, searching the log for UTF-16LE strings confirms the task registration:

```bash
$ strings -e l artifacts/security_events.evtx | grep -A 10 "TaskName"
TaskName
TaskContent
ClientProcessStartKey
ClientProcessId
ParentProcessId
RpcCallClientLocality
FQDN
\System_Telemetry_Updater<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Microsoft Windows System Telemetry Update Service.</Description>
```

#### Scheduled Task Configuration Details:

- **Task Name:** `\System_Telemetry_Updater` (or `System_Telemetry_Updater`)
- **Description:** `Microsoft Windows System Telemetry Update Service.` (spoofed legitimate service name)
- **Trigger:** `<LogonTrigger>` (fires on every system boot / interactive logon)
- **Principal:** `S-1-5-18` (`NT AUTHORITY\SYSTEM`), `RunLevel: HighestAvailable`
- **Settings:** `<Hidden>true</Hidden>` (hidden from standard GUI Task Scheduler listings)
- **Action:** `<Exec><Command>C:\Windows\System32\calc.exe</Command></Exec>`
- **Creator Account:** User `A` (`S-1-5-21-1517760472-681045901-2887825990-1002`)

### 4. Attack Chain & Persistence Mechanism

1. **Audit Policy Tampering (19:57:34 UTC — Event 4719):**
   The attacker / malware interacted with audit policy changes (`%%8449`) for subcategory GUID `{0cce9227-69ae-11d9-bed3-505054503030}` (Scheduled Task Detailed Tracking).
2. **Backdoor Persistence Installation (19:57:38 UTC — Event 4698):**
   The attacker installed `\System_Telemetry_Updater` running as SYSTEM with highest privileges. Masquerading under legitimate telemetry terminology (`Microsoft Windows System Telemetry Update Service`) and marking the task as hidden ensures persistence across reboots while minimizing discovery.

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Event ID 4698** is the primary Windows Security audit event for detecting scheduled task creation and persistence techniques (MITRE ATT&CK T1053.005).
- Adversaries frequently masquerade malicious tasks under plausible Windows maintenance names (such as "System Telemetry Updater") and set the `<Hidden>` flag to evade casual scrutiny.
- Even in brief event log snippets, correlating security audit modifications (Event 4719) with subsequent administrative actions (Event 4698) highlights deliberate staging by the threat actor.
