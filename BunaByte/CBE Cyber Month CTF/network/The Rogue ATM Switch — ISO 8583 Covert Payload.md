---
title: "The Rogue ATM Switch — ISO 8583 Covert Payload"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "network"
  - "bunabyte"
category: "network"
platform: "BunaByte"
---

# The Rogue ATM Switch — ISO 8583 Covert Payload

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![The Rogue ATM Switch](../../../pics/the%20rogues%20atm%20switch.png)

> CBE Cyber Month CTF · **Network Security** · 300 pts · 17 solves · previously filed as *Financial Switch*.

**Flag:** `[REDACTED]`

## Scenario

An ATM terminal (`TERM4092`, `172.28.14.88`) sent anomalous traffic to the
financial switch (`172.28.1.10:5000`). A covert payload was injected through
the ISO 8583 gateway and protected with the terminal's session security.

**Capture:** `financial_switch_dump.pcap` (42 packets)

## Analysis

### 1. Sign-on key material (frames 1–2)

The `0800`/`0810` sign-on exchange carries field 53 twice:

| | value |
|---|---|
| `k1` | `4a1b9e7c528f3104a9d36e2b805c1f47` |
| `k2` | `92f41368b10e77553a98c2ef41187a99` |

Session key:

```
key = k1 XOR k2 = d8ef8d14e3814651934bacc4c14465de
```

> Parsing quirk: in this capture field 53 is encoded with a 3-digit `016`
> length prefix rather than as a fixed 16-byte field. Strip it before using
> the key material.

### 2. Covert field 48 (frame 32)

Frame 32 is a `0210` response. Its field 48 (LLLVAR, length `051`) holds a
proprietary TLV:

- Tag `DF20`
- Length `0x30` = 48 bytes
- Value = AES-128-CBC ciphertext (3 blocks, PKCS#7 padded)

```
f2ada3804c2fa3468619487d038d6809
3af311ef35859821096bcb99b3d74794
3e67de7f3f475339380e00c9271ec68f
```

### 3. CBC IV

The IV is not transmitted separately; it is derived from transaction fields:

```
IV = F37 RRN (883920194810) + last4(F11 STAN = 000109)
   = "8839201948100109"          (16 ASCII bytes)
```

### 4. Decrypt

```
plaintext = AES-128-CBC(key, IV).decrypt(ciphertext)
          = "[REDACTED]"
```

The plaintext is 39 bytes of flag + nine `0x09` PKCS#7 padding bytes = 48.

## Decryption

```bash
echo -n "f2ada3804c2fa3468619487d038d68093af311ef35859821096bcb99b3d747943e67de7f3f475339380e00c9271ec68f" | xxd -r -p | \
  openssl enc -d -aes-128-cbc -K d8ef8d14e3814651934bacc4c14465de -iv $(echo -n "8839201948100109" | xxd -p)
```

The ciphertext and key derived from the ISO 8583 frame and track-2 data decrypt cleanly via standard OpenSSL CLI to yield the plaintext.
