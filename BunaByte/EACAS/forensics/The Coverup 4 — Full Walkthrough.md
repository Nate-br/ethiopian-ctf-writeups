---
title: "The Coverup 4 — Full Walkthrough"
category: forensics
platform: EACAS
difficulty: Medium
points: 200
flag: [REDACTED]
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Coverup 4 — Full Walkthrough

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> The attacker deployed ransomware on a compromised workstation, but before doing so, deleted their tools and emptied the Recycle Bin to cover their tracks.
>
> However, Windows Prefetch maintains execution artifacts in `C:\Windows\Prefetch`. Even after an executable is deleted, its Prefetch file remains as evidence of past execution. We were provided with a zip archive (`the cover up.zip`) containing a Prefetch file pulled from the workstation and asked to identify the credential-dumping tool executed by the attacker.

**Files:** `the cover up.zip` → `artifacts/MIMIKATZ.EXE-F084BEA4.pf`

**Environment & prerequisites:**

- **OS:** Linux
- **Key tools:** `unzip`, `python3`, `strings`, and the `dissect.util` pure-Python Microsoft XPRESS Huffman (`MAM`) decompression library

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`). This is the detailed technical walkthrough of Challenge 4:

- **Previous:** [[The Foothold — Scheduled Task Persistence]]
- **Next:** [[The Ransom — XOR Decryption]]
- **Related:** [[The Coverup — Prefetch Analysis]] (short writeup)

## Solution

### 1. Extract the Challenge Archive

```bash
$ unzip -o "the cover up.zip"
Archive:  the cover up.zip
   creating: artifacts/
  inflating: artifacts/MIMIKATZ.EXE-F084BEA4.pf
```

The extracted file is `artifacts/MIMIKATZ.EXE-F084BEA4.pf`.

### 2. Analyze the File Format

Inspecting the raw header of `MIMIKATZ.EXE-F084BEA4.pf` via Python:

```python
with open('artifacts/MIMIKATZ.EXE-F084BEA4.pf', 'rb') as f:
    header = f.read(16)
print(header)
# Output: b'MAM\x04bE\x00\x00\xa4\xbb\xc6\xbc\xb7\xcc\xcc\xcc'
```

- Magic bytes **`MAM\x04`** indicate a Windows 10/11 compressed Prefetch file.
- Windows uses the **Microsoft XPRESS Huffman** compression algorithm for MAM files.

### 3. Decompress the MAM Prefetch File

Using Python and the `dissect.util.compression.lzxpress_huffman` library, decompress the payload:

```python
import struct
from dissect.util.compression import lzxpress_huffman

with open('artifacts/MIMIKATZ.EXE-F084BEA4.pf', 'rb') as f:
    data = f.read()

# Header: 4 bytes 'MAM\x04', 4 bytes uncompressed size
uncompressed_size = struct.unpack('<I', data[4:8])[0]
compressed_payload = data[8:]

# Decompress using LZ-Xpress Huffman
decompressed = lzxpress_huffman.decompress(compressed_payload)

with open('decompressed.pf', 'wb') as f:
    f.write(decompressed)

print(f"Decompressed {len(decompressed)} bytes. Header: {decompressed[:8]}")
```

**Output:**

```
Decompressed 17765 bytes. Header: b'\x1f\x00\x00\x00SCCA'
```

The `SCCA` header confirms a valid, uncompressed Windows Prefetch format.

### 4. Extract Forensic Artifacts

Using `strings` or Python to read UTF-16LE strings from `decompressed.pf`:

```bash
$ strings -e l decompressed.pf
```

**Key artifact outputs:**

```text
MIMIKATZ.EXE
\VOLUME{01dc98679b182722-269b4b6f}\USERS\A\APPDATA\LOCAL\TEMP\CTF_CH4_1148861462\MIMIKATZ.EXE
\VOLUME{01dc98679b182722-269b4b6f}\WINDOWS\SYSTEM32\NTDLL.DLL
\VOLUME{01dc98679b182722-269b4b6f}\WINDOWS\SYSTEM32\KERNEL32.DLL
\DEVICE\HARDDISKVOLUME3\USERS\A\APPDATA\LOCAL\TEMP\CTF_CH4_1148861462\MIMIKATZ.EXE
```

**Forensic artifact summary:**

- **Executable file name:** `MIMIKATZ.EXE`
- **Execution path:** `C:\Users\A\AppData\Local\Temp\ctf_ch4_1148861462\MIMIKATZ.EXE`
- **Prefetch hash:** `F084BEA4`
- **Tool type:** Mimikatz (credential dumping utility)

### 5. Flag Construction

Combining the competition's flag wrapper format (`EACAS{...}`) with the identified executable name (`MIMIKATZ.EXE`):

**Flag:** `[REDACTED]`

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Windows Prefetch artifacts (`.pf`)** — located in `C:\Windows\Prefetch`, named `<EXECUTABLE_NAME>-<HASH>.pf`, and persisting evidence of application execution even if the source `.exe` is wiped.
- **MAM compression** — starting with Windows 10, Prefetch files are compressed with XPRESS Huffman (`MAM\x04`); decompression is required before legacy parsers can read the SCCA structure.
- The filename alone (`MIMIKATZ.EXE-F084BEA4.pf`) already identifies the tool — decompression adds the execution path and loaded modules as corroborating evidence.
