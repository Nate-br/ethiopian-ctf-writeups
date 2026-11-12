---
title: "The Swift Ghost Heist — DNS Tunnel over MT103"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "network"
  - "bunabyte"
category: "network"
platform: "BunaByte"
---

# The Swift Ghost Heist — DNS Tunnel over SWIFT MT103

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![The Swift Ghost Heist](../../../pics/the%20swift%20ghost%20heist.png)

> CBE Cyber Month CTF · **Network Security** · 450 pts · 20 solves · previously filed as *Interbank Clearance*.

**Flag:** `[REDACTED]`

## Scenario

An isolated workstation in an interbank settlement VLAN tunneled an
intercepted SWIFT MT103 instruction out over DNS. External DNS is relayed
through an internal resolver, and the C2 negotiated a session key during
beacon synchronization.

**Capture:** `interbank_clearance.pcapng` (134 packets)

## Analysis

### 1. Session key — C2 sync

A TXT query/response for `c2-sync.session-9941.apex-clearance.net` returns:

```
k=e38b417c802f9d61
```

The key is hex-encoded, i.e. 8 bytes:

```
e3 8b 41 7c 80 2f 9d 61
```

### 2. Tunnel chunks

The exfil stream is 28 DNS **A** queries:

```
<base32-data>.seqNN.apex-clearance.net
```

Chunks `seq00`–`seq27` are Base32 labels (32 bytes each). Base32-decode each
label, sort by sequence number, and concatenate → 559 bytes of ciphertext.

### 3. Decrypt

The ciphertext is XOR-encrypted with the 8-byte session key repeated:

```
plaintext = ciphertext XOR key[i mod 8]
```

Result: a complete SWIFT MT103 message.

## Recovered MT103 (highlights)

```
:20:REF-20261028-GHOST
:32A:261028USD45000000,00
:50K:/US449182390192837465 MERIDIAN GLOBAL TRUST AG
:59:/GB29019283746501928374 SHADOW HOLDINGS INTERNATIONAL LTD
:70:REMITTANCE: [REDACTED]
```

Amount: **USD 45,000,000.00**.

## Decryption Pipeline

Extract the DNS query names with `tshark` and reconstruct the tunnel payload using the XOR key derived from the ICMP handshake:

```bash
tshark -r interbank_clearance.pcapng -Y 'dns.qry.type == 1 && dns.flags.response == 0' -T fields -e dns.qry.name | \
  grep "apex-clearance.net" | sort -u | python3 -c '
import sys, base64

key = bytes.fromhex("e38b417c802f9d61")
chunks = []
for line in sys.stdin:
    parts = line.strip().split(".")
    if len(parts) >= 3 and parts[1].startswith("seq"):
        seq = int(parts[1][3:])
        lbl = parts[0].upper()
        lbl += "=" * ((8 - len(lbl) % 8) % 8)
        chunks.append((seq, base64.b32decode(lbl)))

chunks.sort()
ct = b"".join(c[1] for c in chunks)
print(bytes(b ^ key[i % len(key)] for i, b in enumerate(ct)).decode(errors="replace"))
'
```
