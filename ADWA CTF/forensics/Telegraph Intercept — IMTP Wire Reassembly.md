---
title: "Telegraph Intercept — IMTP Wire Reassembly"
category: forensics
platform: ADWA CTF
difficulty: Medium
points: 350
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "adwa-ctf"
---

# Telegraph Intercept — IMTP Wire Reassembly

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

> ADWA CTF · **Network Forensics / Wire Analysis** · 350 pts

> On the eve of battle, the copper wire between Sauria and the coast hummed with frantic Italian telegraphs. Tigrayan wiremen tapped the line and recorded the traffic alongside the relay switchboard log. Amidst the garrison chatter, General Baratieri'\''s midnight orders slid across the wire in code. Piece together what was spoken in the dark.

**Flag:** `[REDACTED]`

## Challenge

We are given a network capture (`intercept.pcap`, ~30 KB) recorded from a tapped copper telegraph line on the eve of the Battle of Adwa. The traffic contains command and control chatter, relay heartbeats, position reports, and encrypted telegraph wires sent across the line.

The objective is to isolate General Baratieri's encoded dispatches, determine the cipher key, and reassemble the fragments into the royal token.

## Reconnaissance & Packet Analysis

### 1. Protocol Identification

Inspecting the packet capture with `tshark`:

```bash
tshark -r intercept.pcap -T fields -e tcp.stream -e _ws.col.Protocol -e _ws.col.Info | head -n 25
```

The capture features custom protocol traffic labeled **IMTP/1.0** (Italian Military Telegraph Protocol) running over TCP ports `1896` and `5000`, along with background SMTP and HTTP telemetry:
- `192.168.18.10`: Baratieri Forward HQ (`BARATIERI_FWD`)
- `192.168.18.96`: Sauria Relay Switchboard (`SAURIA_RELAY`)
- `192.168.18.4`: Massawa Coastal Station (`MASSAWA`)
- `192.168.18.1`: Regional Cipher Bureau

### 2. Discovering the Cipher Key

Looking for system configuration messages, TCP Stream 16 reveals a key rotation directive from the Cipher Bureau to the Sauria Relay:

```text
IMTP/1.0 SYSTEM_KEY_ROTATION UNIT=CIPHER_BUREAU KEY_ID=ADWA EPOCH=18960229
IMTP/1.0 SYSTEM_ACK KEY_ROTATION_CONFIRMED
```

The active cryptographic key is identified as:
```text
KEY = b"ADWA"
```

### 3. Locating Encrypted Wire Payloads

Filtering for `ENCRYPTED_TELEGRAM` transactions reveals three legitimate dispatches (`WIRE_9958_*`) alongside failed decoy attempts:

1. **Stream 0 (Frame 93)**:
   ```text
   IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_9958_A DATA=AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0OEQEFABUNAQQeDRN7YXI2ciR8M3BwIWElIidlJHR1MXUkfGd3J04REwADGgQPEG1hcGtkSwMLExh7ZBYlNiUUFQc/IyQtITAzIE4=
   ```
2. **Stream 66 (Frame 149)**:
   ```text
   IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_9958_B DATA=AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0HEwUQDAQKA3thdnhySwYYBRh+dzEpaT4vNSElIiQ0Ix5ycF0=
   ```
3. **Stream 103 (Frame 208)**:
   ```text
   IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_9958_C DATA=AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0HEwUQDAQKA3thd3hySwYYBRh+d3gndGdzcnI2eSUhNnIkOV0AFBAfe2EAGB4PCwMeBAoQAAYBCBYIEB8OFBAIAg4KBA4NDRMAFQ0YD0s=
   ```

## Solution

Decoding the Base64 payloads and decrypting them with repeating XOR against key `ADWA`:

```python
import base64

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

key = b"ADWA"

wires = {
    "A": "AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0OEQEFABUNAQQeDRN7YXI2ciR8M3BwIWElIidlJHR1MXUkfGd3J04REwADGgQPEG1hcGtkSwMLExh7ZBYlNiUUFQc/IyQtITAzIE4=",
    "B": "AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0HEwUQDAQKA3thdnhySwYYBRh+dzEpaT4vNSElIiQ0Ix5ycF0=",
    "C": "AgsZBwgAEg8VDRYNYRASDQQDBQARDHcFCBcHABUHH3tLAgUODH53Ag4JGggSFxYTCAt3AggSHg0EZBEEEwAeDwAKEw5hCRYTFQ0ZCEsQGHthAxIPBBYWDQRkGBMEFwMEYQYWEwAQHgQTDV0HEwUQDAQKA3thd3hySwYYBRh+d3gndGdzcnI2eSUhNnIkOV0AFBAfe2EAGB4PCwMeBAoQAAYBCBYIEB8OFBAIAg4KBA4NDRMAFQ0YD0s="
}

fragments = {}
for wire_id, b64_payload in wires.items():
    raw_cipher = base64.b64decode(b64_payload)
    decrypted = xor_decrypt(raw_cipher, key).decode("latin1")
    print(f"=== WIRE {wire_id} ===")
    print(decrypted)
```

### Decrypted Fragments

The decrypted wire messages form a three-part dispatch from Civil Commissioner Ferdinando Martini to General Baratieri:

- **Wire A (Fragment 1/3)**:
  ```text
  CONFIDENTIAL TELEGRAPH DISPATCH:
  FROM: COMMISSARIO CIVILE FERDINANDO MARTINI
  TO: GENERALE ORESTE BARATIERI
  OPERATIVE_ID: 6a3e8d11e6dcc2e51f4e806f
  FRAGMENT: 1/3
  BODY: [REDACTED PART 1]
  ```

- **Wire B (Fragment 2/3)**:
  ```text
  CONFIDENTIAL TELEGRAPH DISPATCH:
  FROM: COMMISSARIO CIVILE FERDINANDO MARTINI
  TO: GENERALE ORESTE BARATIERI
  FRAGMENT: 2/3
  BODY: [REDACTED PART 2]
  ```

- **Wire C (Fragment 3/3)**:
  ```text
  CONFIDENTIAL TELEGRAPH DISPATCH:
  FROM: COMMISSARIO CIVILE FERDINANDO MARTINI
  TO: GENERALE ORESTE BARATIERI
  FRAGMENT: 3/3
  BODY: [REDACTED PART 3]
  AUTH: DO_NOT_ENGAGE_WITHOUT_CONSOLIDATION
  ```

Concatenating the three fragments sequentially yields the full flag.

## Flag

```
[REDACTED]
```

## Key Takeaways

- Network captures often interleave decoy data and chatter with mission-critical traffic; filtering by sequence IDs or wire numbers isolates genuine payloads.
- Control-plane protocol traffic (such as key exchanges or rotation announcements) can directly reveal cryptographic keys for data-plane dispatches.
- Segmented messages across multiple TCP streams require systematic ordering using metadata headers (e.g., `FRAGMENT: X/Y`).
