---
title: "The Ransom — XOR Decryption"
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

# The Ransom — XOR Decryption

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> We found the attacker's encryption script on the compromised file server. It's the exact tool they used to lock the customer billing database.
>
> The encrypted database file was recovered alongside the script. The encryption key appears to be embedded somewhere in the code but the attacker used obfuscation to hide it.

**Files:** `artifacts.zip` → `encrypt_db.py` (encryption script), `customer_db.enc` (encrypted database, 1664 bytes)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Coverup — Prefetch Analysis]]
- **Next:** [[The Dead Drop — JPEG ZIP Append]]

## Solution

### 1. Analyze the Encryption Script

The script `encrypt_db.py` implements "TelecomCrypt v2.1" — a custom XOR-based cipher with key derivation.

**Key components:**

| Component | Location | Value |
|---|---|---|
| System Validation Token | Lines 27–30 | `[0x54, 0x33, 0x6C, 0x33, 0x63, 0x30, 0x6D, 0x5F, 0x4B, 0x33, 0x79, 0x5F, 0x32, 0x30, 0x32, 0x36]` |
| Integrity Salt | Line 39 | `b"cbsc-primary-node-07"` |
| Encryption Rounds | Line 33 | `3` |
| Block Size | Line 36 | `16` |

The validation token decodes to ASCII: **`T3l3c0m_K3y_2026`**

### 2. Reverse the Key Derivation

The `_derive_session_key` function applies iterative MD5 hashing:

```python
raw_key = bytes(_SYS_VALIDATION)   # b"T3l3c0m_K3y_2026"
derived = raw_key
for i in range(3):
    h = hashlib.md5()
    h.update(derived)
    h.update(b"cbsc-primary-node-07")
    h.update(struct.pack(">I", i))
    derived = h.digest()
```

Result: **`ae90062283a6d83ff217c1770602a1ed`**

### 3. Reverse the XOR Cipher

The `_apply_cipher` function XORs each byte with both the key byte and a position-dependent shift:

```python
k = session_key[i % 16]
shift = (i * 7 + 3) & 0xFF
plaintext[i] = ciphertext[i] ^ k ^ shift
```

### 4. Parse the File Header

The encrypted file has a 32-byte header:

| Offset | Size | Content | Value |
|---|---|---|---|
| 0 | 4 | Magic | `TCDB` |
| 4 | 2 | Version | `0x0201` |
| 6 | 8 | Original size | `1624` bytes |
| 14 | 8 | Timestamp | Unix epoch |
| 22 | 10 | Reserved | zeros |

### 5. Decrypt

```python
import struct, hashlib

_SYS_VALIDATION = [0x54,0x33,0x6C,0x33,0x63,0x30,0x6D,
                   0x5F,0x4B,0x33,0x79,0x5F,0x32,0x30,0x32,0x36]
_SALT = b"cbsc-primary-node-07"

raw_key = bytes(_SYS_VALIDATION)
derived = raw_key
for i in range(3):
    h = hashlib.md5()
    h.update(derived); h.update(_SALT); h.update(struct.pack(">I", i))
    derived = h.digest()

data = open("customer_db.enc","rb").read()
ciphertext = data[32:]  # skip header

result = bytearray(len(ciphertext))
for i in range(len(ciphertext)):
    k = derived[i % 16]
    shift = (i * 7 + 3) & 0xFF
    result[i] = ciphertext[i] ^ k ^ shift

# Strip PKCS7 padding
pad = result[-1]
plaintext = bytes(result[:-pad])

print(plaintext.decode())
```

**Output:**

```
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
|  [REDACTED]                       |
|                                                              |
+--------------------------------------------------------------+
```

## Flag

```
[REDACTED]
```

The attacker obfuscated the key as a byte array labeled "System Validation Token" and added key-stretching via iterative MD5, but the core cipher was a simple XOR — trivially reversible once the key derivation is understood.

## Key Takeaways

- **Obfuscation ≠ encryption strength**: a key hidden in a byte array with MD5 key-stretching still boils down to XOR — reversible with the same script.
- Custom file formats need their headers parsed and skipped before decryption (magic `TCDB`, version `0x0201`, original size field).
- Position-dependent XOR shifts (`i * 7 + 3`) are deterministic and easily inverted.
