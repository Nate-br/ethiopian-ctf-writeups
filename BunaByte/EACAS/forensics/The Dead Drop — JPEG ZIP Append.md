---
title: "The Dead Drop — JPEG ZIP Append"
category: forensics
platform: EACAS
difficulty: Medium
points: 300
solves: 2
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Dead Drop — JPEG ZIP Append

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> During the physical investigation, security found a USB drive hidden under a desk in the server room. The drive contained a single file — what appears to be a corrupted JPEG image labeled `usb_backup.jpg`.
>
> Our initial analysis shows the image is unusually large for a photo of this resolution. We suspect the attacker hid stolen data inside the image file before attempting to smuggle it out of the building.
>
> Extract the hidden data from the image to recover the stolen customer records.

**Files:** `artifacts.zip` → `usb_backup.jpg` (821 bytes, JPEG 1×1 pixel)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Ransom — XOR Decryption]]
- This challenge concludes the campaign — the exfiltrated data was recovered and the incident contained.

## Solution

### 1. Identify the Anomaly

The JPEG is a 1×1 pixel image but 821 bytes — far too large for its resolution. A quick inspection reveals data appended after the JPEG end marker:

```bash
python3 -c "
data = open('usb_backup.jpg','rb').read()
pos = data.rfind(b'\xff\xd9')
print(f'File size: {len(data)} bytes')
print(f'JPEG end (FFD9) at offset: {pos}')
print(f'Extra data after JPEG: {len(data) - pos - 2} bytes')
"
```

```
File size: 821 bytes
JPEG end (FFD9) at offset: 330
Extra data after JPEG: 489 bytes
```

### 2. Extract the Embedded ZIP

The trailing data starts with `PK\x03\x04` — a ZIP archive header:

```python
data = open('usb_backup.jpg','rb').read()
pos = data.find(b'PK\x03\x04')       # offset 332
zip_data = data[pos:]
open('extracted.zip','wb').write(zip_data)
```

### 3. Recover the Stolen Data

```bash
$ unzip extracted.zip
Archive:  extracted.zip
  inflating: customer_records.txt

$ cat customer_records.txt
+--------------------------------------------------------------+
|          EXFILTRATED DATA -- CUSTOMER RECORDS                |
+--------------------------------------------------------------+
|  Source: CBSC-PRIMARY billing database                       |
|  Exfil Date: 2026-06-14 02:30:00 UTC                        |
|  Method: Steganographic concealment in JPEG carrier          |
|                                                              |
|  VERIFICATION TOKEN:                                         |
|  [REDACTED]                                 |
|                                                              |
|  IR team has recovered stolen data. Incident contained.      |
+--------------------------------------------------------------+
|  CUST-00001 | [REDACTED] | Premium 5G  | .50           |
|  CUST-00002 | [REDACTED] | Basic Voice | .00            |
|  [... 5,247,829 more records ...]                            |
+--------------------------------------------------------------+
```

## Flag

```
[REDACTED]
```

The attacker concealed a ZIP archive behind the JPEG's `FFD9` end-of-image marker — a classic steganographic hiding technique. The archive contained 5M+ exfiltrated customer records from the CBSC-PRIMARY billing database.

## Key Takeaways

- Appending a ZIP after the JPEG `FFD9` end-of-image marker is a classic steganographic concealment technique — file-size anomalies are the first clue.
- `rfind(b'\xff\xd9')` locates the true end of the JPEG; `find(b'PK\x03\x04')` locates the embedded archive.
- Always check apparent corruption or size anomalies before assuming a file is simply broken.
