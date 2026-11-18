---
title: "The Ransom 05"
category: forensics
platform: EACAS
difficulty: Hard
points: 300
solves: 0
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Ransom 05

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> We found the attacker's encryption script on the compromised file server. It's the exact tool they used to lock the customer billing database.
>
> The encrypted database file was recovered alongside the script. The encryption key appears to be embedded somewhere in the code but the attacker used obfuscation to hide it.

**Files:** `the ransom 05.zip` → `artifacts/customer_db.enc` (encrypted database, 1,664 bytes), `artifacts/encrypt_db.py` (encryption script, 4,222 bytes)

**Environment & prerequisites:**

- **OS:** Linux
- **Key tools:** `python3`, `hashlib`, `struct`

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Coverup 04]]
- **Next:** [[The Dead Drop — JPEG ZIP Append]]
- **Related:** [[The Ransom — XOR Decryption]]

## Solution

### 1. Extract and Inspect the Challenge Artifacts

```bash
$ unzip -o "the ransom 05.zip"
Archive:  the ransom 05.zip
   creating: artifacts/
  inflating: artifacts/customer_db.enc
  inflating: artifacts/encrypt_db.py
```

The archive provides:
1. `artifacts/encrypt_db.py` — A Python utility claiming to be "TelecomCrypt v2.1 - Database Protection Utility" used by the attacker to encrypt the billing records.
2. `artifacts/customer_db.enc` — The resulting encrypted binary database file.

### 2. Analyze the Encryption Routine (`encrypt_db.py`)

Inspecting `encrypt_db.py` reveals the ransomware structure, key material, and cipher implementation:

#### A. Header Structure
The script prepends a 32-byte header to the encrypted payload:

```python
def _generate_header(original_size):
    header = bytearray()
    header.extend(b"TCDB")                          # Magic bytes (0x00..0x03)
    header.extend(struct.pack(">H", 0x0201))         # Version (0x04..0x05)
    header.extend(struct.pack(">Q", original_size))  # Original size (0x06..0x0D)
    ts = int(datetime.now().timestamp())
    header.extend(struct.pack(">Q", ts))             # Timestamp (0x0E..0x15)
    header.extend(b"\x00" * 10)                      # Reserved (0x16..0x1F)
    return bytes(header)                             # Total = 32 bytes
```

The ciphertext payload begins at byte index `32` (`data[32:]`).

#### B. Key Extraction & Strengthening
The key material is disguised as a list of integers labeled `_SYS_VALIDATION`:

```python
_SYS_VALIDATION = [
    0x54, 0x33, 0x6C, 0x33, 0x63, 0x30, 0x6D,  # "T3l3c0m"
    0x5F, 0x4B, 0x33, 0x79, 0x5F, 0x32, 0x30,  # "_K3y_20"
    0x32, 0x36,                                 # "26"
]
```

Converting these bytes to ASCII yields:
```
T3l3c0m_K3y_2026
```

The key is strengthened using 3 rounds of iterative MD5 hashing with a fixed salt and loop index:

```python
def _derive_session_key(validation_token, rounds):
    raw_key = bytes(validation_token)
    derived = raw_key
    for i in range(rounds):
        h = hashlib.md5()
        h.update(derived)
        h.update(_INTEGRITY_SALT)          # b"cbsc-primary-node-07"
        h.update(struct.pack(">I", i))
        derived = h.digest()
    return derived
```

#### C. The Cipher Implementation
The cipher applies a multi-layer XOR transformation with position-dependent shifts:

```python
for i in range(len(data)):
    k = key[i % key_len]
    shift = (i * 7 + 3) & 0xFF
    result[i] = data[i] ^ k ^ (shift & 0xFF)
```

Because XOR is symmetric and self-inverting:
$$\text{plaintext}[i] = \text{ciphertext}[i] \oplus \text{key}[i \pmod{16}] \oplus ((i \times 7 + 3) \ \& \ \text{0xFF})$$

Data is padded using standard PKCS#7 to 16-byte blocks (`_BLOCK_SIZE = 16`).

### 3. Decrypting the Database

Constructing a solver to reverse the pipeline:

```python
import struct
import hashlib

_SYS_VALIDATION = [
    0x54, 0x33, 0x6C, 0x33, 0x63, 0x30, 0x6D,
    0x5F, 0x4B, 0x33, 0x79, 0x5F, 0x32, 0x30,
    0x32, 0x36
]
_SALT = b"cbsc-primary-node-07"
_ROUNDS = 3

# 1. Derive session key
derived = bytes(_SYS_VALIDATION)
for i in range(_ROUNDS):
    h = hashlib.md5()
    h.update(derived)
    h.update(_SALT)
    h.update(struct.pack(">I", i))
    derived = h.digest()

# 2. Read encrypted file and skip 32-byte header
with open("artifacts/customer_db.enc", "rb") as f:
    data = f.read()

ciphertext = data[32:]

# 3. Apply inverse XOR
plaintext = bytearray(len(ciphertext))
for i in range(len(ciphertext)):
    k = derived[i % len(derived)]
    shift = (i * 7 + 3) & 0xFF
    plaintext[i] = ciphertext[i] ^ k ^ shift

# 4. Remove PKCS#7 padding
padding_len = plaintext[-1]
decrypted_db = bytes(plaintext[:-padding_len]).decode("utf-8")

print(decrypted_db)
```

### 4. Decrypted Output

```text
+--------------------------------------------------------------+
|           TELECOM CORP - CUSTOMER BILLING DATABASE           |
|                    CONFIDENTIAL - INTERNAL                   |
+--------------------------------------------------------------+
|  Database: CBSC-PRIMARY                                      |
|  Server:   billing-db-01.telecom-corp.local                  |
|  Records:  5,247,831 customer accounts                       |
|  Last Backup: 2026-06-13 23:45:00 UTC                        |
+--------------------------------------------------------------+
|                                                              |
|  RECOVERY VERIFICATION TOKEN:                                |
|                                                              |
|  [REDACTED]                                                  |
|                                                              |
|  If you can read this, the database has been successfully    |
|  decrypted. Report this token to the Incident Commander.     |
|                                                              |
+--------------------------------------------------------------+
|  CUST-00001 | Plan: Premium 5G  | Status: Active             |
|  CUST-00002 | Plan: Basic Voice | Status: Active             |
|  CUST-00003 | Plan: Family 10GB | Status: Suspended          |
|  CUST-00004 | Plan: Enterprise  | Status: Active             |
|  CUST-00005 | Plan: Prepaid     | Status: Active             |
|  [... 5,247,826 more records ...]                            |
+--------------------------------------------------------------+
```

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Header Parsing:** When reversing proprietary encrypted database backups or ransomware artifacts, verify if binary headers (e.g., magic bytes `TCDB`, version stamps, size fields) precede the encrypted payload.
- **Obfuscated Byte Arrays:** Hardcoded byte arrays in scripts often represent initial passwords, validation tokens, or salt values.
- **Symmetric XOR Inversion:** Multi-layer deterministic XOR operations (even with index-based shifts `(i * 7 + 3) & 0xFF`) are mathematically reversible with the identical mathematical operation.
