---
title: "The Foothold — Scheduled Task Persistence"
category: forensics
platform: EACAS
difficulty: Medium
points: 200
solves: 3
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Foothold — Scheduled Task Persistence

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> After the malicious file from Challenge 2 was executed, it didn't just run once — the attacker wanted to make sure they could get back in even after a reboot.
>
> The malware created a Windows Scheduled Task that runs every time the system starts up, calling back to the attacker's server. This is how the attacker maintained persistent access to the network for days before deploying the ransomware.
>
> We've exported the Windows Security Event Logs from the compromised workstation. Find the name of the malicious scheduled task the attacker created.

**Files:** `security_events.evtx` (69 KB)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Download — Phishing Payload]]
- **Next:** [[The Coverup — Prefetch Analysis]]

## Solution

### 1. Analyze the Security Event Log

The EVTX file contains 10 events spanning a 7-minute window on 2026-06-17:

| Time (UTC) | Event ID | Description |
|---|---|---|
| 19:50:58 | 4624 | SYSTEM logon (services.exe) |
| 19:50:58 | 4672 | Special privileges assigned |
| 19:55:30 | 4624 | SYSTEM logon (service host) |
| 19:55:30 | 4672 | Special privileges assigned |
| 19:55:33 | 4624 | SYSTEM logon (service host) |
| 19:55:33 | 4672 | Special privileges assigned |
| 19:55:37 | 4799 | Security-enabled local group membership (x2) |
| 19:57:34 | **4719** | Audit policy changed by user **A** |
| 19:57:38 | **4698** | **Scheduled task created by user A** |

### 2. Identify the Malicious Task

The only Event ID 4698 in the log reveals:

```
TaskName: \System_Telemetry_Updater
```

**Task details:**

- **Name:** `\System_Telemetry_Updater`
- **Description:** "Microsoft Windows System Telemetry Update Service" (spoofed)
- **Trigger:** LogonTrigger (runs every time a user logs in)
- **Principal:** SYSTEM (S-1-5-18), HighestAvailable run level
- **Hidden:** Enabled (hidden from normal task scheduler view)
- **Action:** Executes `C:\Windows\System32\calc.exe`
- **Created by:** User `A` (SID: S-1-5-21-1517760472-681045901-2887825990-1002)

### 3. Attack Chain

1. **19:57:34** — User `A` enables the "Detailed Tracking" subcategory audit policy (Event 4719) to ensure scheduled task creation is logged.
2. **19:57:38** — User `A` creates `\System_Telemetry_Updater` (Event 4698), a hidden scheduled task masquerading as a legitimate Windows telemetry service.

The task is designed to blend in with legitimate Microsoft tasks while providing persistent backdoor access on every system boot.

## Flag

```
[REDACTED]
```

The attacker disguised a persistence mechanism as a legitimate `System_Telemetry_Updater` service — a classic masquerading technique that relies on users not inspecting scheduled tasks closely.

## Key Takeaways

- **Event ID 4698** records scheduled task creation; **Event ID 4719** records audit policy changes — both are key hunting events in Windows security logs.
- Masquerading: naming a malicious task like a legitimate Microsoft telemetry service (with a spoofed description) hides it from casual inspection.
- Hidden tasks running as SYSTEM on logon are a persistent, stealthy foothold — inspect scheduled tasks for unknown LogonTrigger entries.
