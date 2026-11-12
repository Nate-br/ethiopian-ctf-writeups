---
title: "Double-Dip — AES-CTR Nonce Reuse"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "crypto"
  - "bunabyte"
category: "crypto"
platform: "BunaByte"
---

# CBE CYBER MONTH CTF — Double-Dip (AES-128-CTR Nonce Reuse)

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Double-Dip](../../../pics/double%20dip.png)

**Flag:** `[REDACTED]`

## Scenario

Nexus Bank's notification system encrypts SWIFT-style payment confirmations
with AES-128-CTR. Two confirmations were captured:

- `transfer_almaz.enc` — transfer to Almaz
- `transfer_abebe.enc` — transfer to Abebe (contains the flag)

`bank_log.txt` leaks Almaz's plaintext and notes:

> Notification module v2.1 — **nonce rotation disabled** (ticket #NB-4471)

## Vulnerability

AES-CTR turns a block cipher into a stream cipher: each plaintext byte is
XORed with a keystream byte. The keystream depends on the key, the nonce, and
the counter. Because nonce rotation was disabled, both confirmations reuse the
**same keystream**:

```
C1 = P1 XOR KS
C2 = P2 XOR KS
```

This is a two-time pad. Knowing one plaintext recovers the keystream and thus
the other plaintext:

```
KS = C1 XOR P1
P2 = C2 XOR KS
```

## The second bug: trimmed fixed-width padding

The log line is only 55 bytes:

```
SWIFT: FROM=NEXUSBANK TO=ALMAZ AMT=10000.00 REF=TXN0042
```

but each ciphertext is **79 bytes**. The confirmation is a fixed-width record,
and the log viewer trimmed the trailing spaces. Padding the leaked line with
24 spaces restores the true 79-byte plaintext:

```python
p_almaz = leaked.ljust(len(c_almaz), b" ")
```

That yields the complete keystream for all 79 bytes, so Abebe's confirmation
decrypts in full — no guessing.

## Recovery

```python
C1 = bytes.fromhex(open("transfer_almaz.enc").read().strip())
C2 = bytes.fromhex(open("transfer_abebe.enc").read().strip())
P1 = b"SWIFT: FROM=NEXUSBANK TO=ALMAZ AMT=10000.00 REF=TXN0042"
P1 = P1.ljust(len(C1), b" ")

ks = bytes(a ^ b for a, b in zip(C1, P1))
P2 = bytes(a ^ b for a, b in zip(C2, ks))
```

Recovered confirmation:

```
SWIFT: FROM=NEXUSBANK TO=ABEBE AMT=99999.99 REF=[REDACTED]
```

## Why it happened

- **Nonce reuse** (`nonce rotation disabled`) breaks CTR completely: the same
  keystream encrypts every confirmation, enabling two-time-pad recovery.
- **Fixed-width space padding** meant the trimmed audit-log line still leaked
  the whole plaintext once the padding was restored.
- The two ciphertexts share a 26-byte prefix because the plaintexts are
  identical through `...TO=A`; the first difference is `L` vs `B` at index 26.

## Solution

```bash
python3 -c '
c1 = bytes.fromhex(open("transfer_almaz.enc").read().strip())
c2 = bytes.fromhex(open("transfer_abebe.enc").read().strip())
p1 = b"SWIFT: FROM=NEXUSBANK TO=ALMAZ AMT=10000.00 REF=TXN0042".ljust(len(c1), b" ")
keystream = bytes(a ^ b for a, b in zip(c1, p1))
p2 = bytes(a ^ b for a, b in zip(c2, keystream))
print(p2.decode())
'
```

## Fix

- Generate a fresh, unpredictable nonce/IV for every message; never disable
  nonce rotation.
- Prefer an AEAD construction (AES-GCM / ChaCha20-Poly1305) so misuse and
  tampering are detectable.
- Do not rely on fixed-width padding for confidentiality; use explicit
  length-delimited encoding.
