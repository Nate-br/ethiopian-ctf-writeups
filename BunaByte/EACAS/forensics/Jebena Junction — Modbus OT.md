---
title: "Jebena Junction — Modbus OT"
category: forensics
platform: EACAS
difficulty: Medium
points: 250
solves: 3
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# Jebena Junction — Modbus OT

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> The Gera Highland Coffee Cooperative exports some of the finest washed Yirgacheffe lots in the region — but their last shipment to Hamburg was rejected at customs. The beans had spoiled in storage, even though the warehouse's climate control logs showed a steady 19°C and 58% humidity the entire time.
>
> Something doesn't add up. The cooperative's lone IT contractor pulled a capture from the OT network switch the week before the shipment failed...
>
> The warehouse's PLC polls a humidity/temperature RTU over Modbus TCP every few seconds — that's normal, expected traffic. But somewhere in this capture, a host that has no business talking Modbus to that RTU sends it instructions it shouldn't be able to send. Find that host. Find what it wrote. Reconstruct what it was hiding in plain sight.

**Files:** `jebena_junction.pcap` (64 packets, 5.4 KB)

## Solution

### 1. Identify the Traffic

The PCAP contains only Modbus TCP traffic between three hosts:

| Host | Role | Packets |
|---|---|---|
| `10.20.5.21` | PLC (normal polling) | 64 |
| `10.20.5.10` | Temperature/Humidity RTU | 56 |
| `10.20.5.66` | **Rogue host** | **8** |

### 2. Find the Rogue Host

The rogue `10.20.5.66` has only 8 packets — 4 write requests and 4 responses. All writes use **Modbus function code 16** (Write Multiple Registers), starting at reference number 255, writing 4 registers at a time.

This is abnormal — the PLC only reads registers via normal polling; no legitimate device writes to the RTU.

### 3. Extract the Hidden Data

The 16-bit register values, interpreted as big-endian byte pairs, produce ASCII text:

| Write | Register Values | Decoded Bytes |
|---|---|---|
| 1 | `21070, 20558, 18043, 31280` | `R N P N F { z 0` |
| 2 | `29039, 26677, 24437, 13365` | `q o h 5 _ u 4 5` |
| 3 | `24417, 12383, 13416, 26485` | `_ a 0 _ 4 h g u` |
| 4 | `24431, 13162, 13413, 13181` | `_ o 3 j 4 e 3 }` |

Concatenated: **`[REDACTED]`**

### 4. Decode ROT13

Each letter is ROT13-ciphered (a common obfuscation to evade simple `strings` scans):

```
R→E, N→A, P→C, N→A, F→S, z→m, q→d, o→b, h→u, u→h, a→n, g→t, o→b, j→w, e→r
```

Result: **`[REDACTED]`**

Which reads: *"modbus has no auth beware"*

## Flag

```
[REDACTED]
```

The attacker exploited Modbus TCP's complete lack of authentication — any host on the network can write to any register. They wrote ROT13-encoded data into the RTU's registers, hiding the message in plain sight among legitimate SCADA traffic.

## Key Takeaways

- **Modbus TCP has no authentication** — any host on the network can write to any register; function code 16 (Write Multiple Registers) from an unknown host is a red flag in an OT capture.
- ROT13 obfuscation evades naive `strings` scans while remaining trivially reversible.
- 16-bit register values interpreted as big-endian byte pairs decode to ASCII text.
