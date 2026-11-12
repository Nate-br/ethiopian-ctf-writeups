---
title: "The Coverup — Prefetch Analysis"
category: forensics
platform: BunaByte
difficulty: Medium
points: 200
solves: 2
flag: "[REDACTED] (to verify)"
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Coverup — Prefetch Analysis

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> The attacker was careful. Before deploying the ransomware, they deleted most of their tools from the compromised system. The files are gone, and the Recycle Bin was emptied.
>
> But Windows keeps a secret record. Every time a program runs, Windows Prefetch creates a trace file in `C:\Windows\Prefetch`. Even after the executable is deleted, the Prefetch file remains proving the program was executed.
>
> We pulled a Prefetch file from the compromised workstation. **We suspect the attacker ran a well-known credential-dumping tool.** Analyze the Prefetch file to identify what was executed.

**Files:** `artifacts.zip` → `MIMIKATZ.EXE-F084BEA4.pf` (Windows Prefetch file, 3850 bytes)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Foothold — Scheduled Task Persistence]]
- **Next:** [[The Ransom — XOR Decryption]]
- **Related:** [[The Coverup 4 — Full Walkthrough]] (detailed technical walkthrough)

## Solution

### 1. Identify the Prefetch File

The extracted file is a Windows Prefetch file — name format `EXECUTABLE.EXE-HASH.pf`:

```
MIMIKATZ.EXE-F084BEA4.pf
```

The filename immediately reveals:

- **Executable:** `MIMIKATZ.EXE`
- **Path Hash:** `F084BEA4`

### 2. Confirm the Tool

**Mimikatz** is the most well-known Windows credential-dumping tool. It extracts plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication material from memory (`sekurlsa::logonpasswords`).

The Prefetch file confirms execution was traced to `C:\Windows\Prefetch\MIMIKATZ.EXE-F084BEA4.pf`, proving the attacker ran the tool on the compromised workstation despite later deleting the executable and emptying the Recycle Bin.

## Flag

```
[REDACTED]
```

*Note: this flag was marked "to verify" in the original writeup; the full walkthrough of the same challenge reports `[REDACTED]` — see [[The Coverup 4 — Full Walkthrough]].*

## Key Takeaways

- Windows Prefetch files survive even when the source executable is deleted — they are forensically valuable artifacts that prove program execution.
- The `.pf` filename encodes the executable name and a path hash, giving instant identification of the executed tool.
- Prefetch analysis caught the attacker red-handed running a credential dumper.
