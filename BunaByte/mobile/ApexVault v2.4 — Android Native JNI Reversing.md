---
title: "ApexVault v2.4 — Android Native JNI Reversing"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "mobile"
  - "bunabyte"
category: "mobile"
platform: "BunaByte"
---

# ApexVault v2.4 — Android CTF Writeup

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![ApexVault v2.4](../../pics/apex.png)

**Flag:** `[REDACTED]`

## Target

- APK: `ApexVault_v2.4.apk`
- Package: `com.apex.vault`
- Version: `2.4.0` (`versionCode 204`)
- SHA-256: `589ba30d9867becb478308e6867143782a818f2d3ecc4df24816612553db3ce5`

## Decoys

Two decoy flags are visible without touching the native code. Both are wrong:

- `[REDACTED]` — Java `DECOY_FLAG`, returned by PIN `12345678`.
- `[REDACTED]` — stored in `resources.arsc`.

The real flag is produced only by `SecurityBridge.verifyAndDecrypt`.

## Java layer

`MainActivity.handleUnlock()`:

1. Requires an 8-character PIN.
2. PIN `12345678` returns the Java decoy.
3. Otherwise loads `assets/vault_payload.bin` and calls:

```java
SecurityBridge.verifyAndDecrypt(payload, "SUPV-8492", pin);
```

`SecurityBridge` loads `libapex_core.so` and declares the native method.

## Native verifier

The relevant function is:

```text
Java_com_apex_vault_SecurityBridge_verifyAndDecrypt
```

It performs these checks:

1. Supervisor ID must equal `SUPV-8492`.
2. PIN length must be 8.
3. Every PIN byte must be `>= '0'` (the UI describes the PIN as 8 digits).
4. The two little-endian 32-bit halves of the PIN, `a` (bytes 0-3) and `b`
   (bytes 4-7), are mixed with a four-round ARX-style chain.

Using `mix(x, c) = (x >> 5) ^ (x << 7) ^ (x * 0x4567 + c)` (all 32-bit):

```text
w1 = a ^ mix(b,  0x9e3779b9)
w2 = b ^ mix(w1, 0x85ebca6b)
w3 = w1 ^ mix(w2, 0xc2b2ae35)   must equal 0x1865e1e0
w4 = w2 ^ mix(w3, 0x27d4eb2f)   must equal 0x1bf35ae3
```

Because `w3` is known, the chain is invertible in reverse:

```text
w2 = C4 ^ mix(C3, 0x27d4eb2f)
w1 = C3 ^ mix(w2, 0xc2b2ae35)
b  = w2 ^ mix(w1, 0x85ebca6b)
a  = w1 ^ mix(b,  0x9e3779b9)
```

This yields `a = 0x31393337` and `b = 0x36343238`, i.e. the PIN:

```text
73918246
```

## Key derivation and decryption

The native code formats:

```text
PIN + ":" + "SUPV-8492" + ":ApexCore2026"
```

and hashes it with SHA-256:

```text
SHA-256("73918246:SUPV-8492:ApexCore2026")
= 62d5b60b5f992c51da4a44013992abc3
  500e5a96be484d782f6c48dead1684f0
```

The 35-byte payload is XORed with this 32-byte digest, repeating the digest
(`key[i & 31]`):

```text
ciphertext:
2097cd656bed1d27e9152e6f08cdddf725622ec9cc7b3b4b5d1f79b0ca49b6c050e3cb

plaintext:
[REDACTED]
```

## Solution

Run the inverse ARX transformation and key derivation directly in Python:

```python
import hashlib

def mix(x, c):
    return ((x >> 5) ^ ((x << 7) & 0xFFFFFFFF) ^ ((x * 0x4567 + c) & 0xFFFFFFFF)) & 0xFFFFFFFF

C3, C4 = 0x1865e1e0, 0x1bf35ae3
w2 = C4 ^ mix(C3, 0x27d4eb2f)
w1 = C3 ^ mix(w2, 0xc2b2ae35)
b = w2 ^ mix(w1, 0x85ebca6b)
a = w1 ^ mix(b, 0x9e3779b9)
pin = a.to_bytes(4, "little").decode() + b.to_bytes(4, "little").decode()

key = hashlib.sha256(f"{pin}:SUPV-8492:ApexCore2026".encode()).digest()
ct = bytes.fromhex("2097cd656bed1d27e9152e6f08cdddf725622ec9cc7b3b4b5d1f79b0ca49b6c050e3cb")
print("Decrypted PIN:", pin)
print("Decrypted Flag:", bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)).decode(errors="replace"))
```
