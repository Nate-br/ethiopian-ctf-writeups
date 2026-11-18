---
title: "The Coverup 04"
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

# The Coverup 04

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> The attacker was careful. Before deploying the ransomware, they deleted most of their tools from the compromised system. The files are gone, and the Recycle Bin was emptied.
>
> But Windows keeps a secret record. Every time a program runs, Windows Prefetch creates a trace file in `C:\Windows\Prefetch`. Even after the executable is deleted, the Prefetch file remains proving the program was executed.
>
> We pulled a Prefetch file from the compromised workstation. We suspect the attacker ran a well-known credential-dumping tool. Analyze the Prefetch file to identify what was executed.

**Files:** `artifacts.zip` → `artifacts/MIMIKATZ.EXE-F084BEA4.pf` (Windows Prefetch file, 3,850 bytes)

**Environment & prerequisites:**

- **OS:** Linux
- **Key tools:** `unzip`, `strings`, `python3` (or Rust `prefetch4n6` / `prefetch-core`)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Foothold — Scheduled Task Persistence]]
- **Next:** [[The Ransom — XOR Decryption]]
- **Related:** [[The Coverup 4 — Full Walkthrough]]

## Solution

### 1. Extract the Challenge Archive

```bash
$ unzip -o artifacts.zip
Archive:  artifacts.zip
   creating: artifacts/
  inflating: artifacts/MIMIKATZ.EXE-F084BEA4.pf
```

The extracted file is `artifacts/MIMIKATZ.EXE-F084BEA4.pf`.

### 2. File Identification & Prefetch Naming

In Windows, Prefetch files follow the naming standard:

$$\text{<EXECUTABLE\_NAME>}-\text{<HASH>}.\text{pf}$$

The filename itself immediately reveals:
- **Target Executable:** `MIMIKATZ.EXE`
- **Prefetch Hash:** `F084BEA4`

### 3. Header Analysis & MAM Decompression

Inspecting the file header:

```python
with open('artifacts/MIMIKATZ.EXE-F084BEA4.pf', 'rb') as f:
    header = f.read(16)
print(header)
# b'MAM\x04bE\x00\x00\xa4\xbb\xc6\xbc\xb7\xcc\xcc\xcc'
```

- Magic bytes **`MAM\x04`** indicate a Windows 10/11 compressed Prefetch container using **Microsoft XPRESS Huffman** compression.
- Bytes `4..8` contain the uncompressed file size (`0x4562` = 17,762 bytes).

Decompressing with Python (`dissect.util.compression.lzxpress_huffman`) or Rust (`prefetch-core`):

```python
import struct
from dissect.util.compression import lzxpress_huffman

with open('artifacts/MIMIKATZ.EXE-F084BEA4.pf', 'rb') as f:
    data = f.read()

payload = data[8:]
decompressed = lzxpress_huffman.decompress(payload)

with open('decompressed.pf', 'wb') as f:
    f.write(decompressed)
```

The decompressed file starts with version `0x1F` (Windows 11) and the `SCCA` signature.

### 4. Forensic Artifact Extraction

Using `prefetch4n6` or extracting UTF-16LE strings:

```bash
$ prefetch4n6 artifacts/MIMIKATZ.EXE-F084BEA4.pf --files
MIMIKATZ.EXE  ran 1x  last 2026-06-17T19:57:47Z  from \VOLUME{01dc98679b182722-269b4b6f}\USERS\A\APPDATA\LOCAL\TEMP\CTF_CH4_1148861462\MIMIKATZ.EXE
  loaded files: 29
```

**Forensic Artifact Summary:**

| Artifact | Extracted Value |
|---|---|
| **Program Name** | `MIMIKATZ.EXE` |
| **Run Count** | `1` |
| **Execution Timestamp** | `2026-06-17 19:57:47 UTC` |
| **Original Path** | `C:\Users\A\AppData\Local\Temp\CTF_CH4_1148861462\MIMIKATZ.EXE` |
| **Volume Serial** | `269B4B6F` |
| **Loaded Modules** | 29 files (including `ntdll.dll`, `kernel32.dll`, `advapi32.dll`, `bcryptprimitives.dll`, `sechost.dll`) |

### 5. Identifying the Executed Tool

The artifact confirms execution of **Mimikatz** (`mimikatz`), a well-known open-source utility utilized by adversaries for dumping credentials (NTLM hashes, plaintext credentials, Kerberos tickets) from LSASS memory.

## Flag

```
[REDACTED]
```

## Key Takeaways

- Windows Prefetch files (`.pf`) in `C:\Windows\Prefetch` remain on disk after the executable itself has been deleted and the Recycle Bin emptied, serving as definitive evidence of program execution.
- Modern Windows Prefetch files are compressed with MAM (XPRESS Huffman) and must be decompressed to analyze full execution metadata, loaded modules, and original volume paths.
- The prefetch hash and path prove the tool was executed directly from a user temporary staging directory (`AppData\Local\Temp\CTF_CH4_1148861462`).
