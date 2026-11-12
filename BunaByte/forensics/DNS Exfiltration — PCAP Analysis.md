---
title: "DNS Exfiltration — PCAP Analysis"
category: forensics
platform: BunaByte
difficulty: Medium
points: 100
solves: 44
flag: [REDACTED]
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# DNS Exfiltration — PCAP Analysis

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Packet Detective](../../pics/packet%20detective.png)

## Challenge

A packet capture of DNS traffic contains data exfiltrated through base64-encoded subdomains. The goal is to spot the suspicious queries and reconstruct the exfiltrated flag.

**Files:** `capture.zip` → `capture.pcap`

## Solution

### 1. Extract and Identify the Capture

```bash
$ unzip capture.zip
Files: capture.pcap

$ file capture.pcap
capture.pcap: pcap capture file (Ethernet, capture length 65535)
```

### 2. Extract All DNS Queries

```bash
$ tshark -r capture.pcap -Y "dns" -T fields -e frame.number \
    -e dns.qry.name
```

Most queries are normal (google, microsoft, github, etc.), but several go to suspicious analytics/telemetry domains with base64-like subdomains:

```
Frame  13: [REDACTED].data.cdn-analytics.net
Frame  25: aGVsbG8gd29ybGQ.tracker.analytics-cdn.net
Frame  31: [REDACTED].data.cdn-analytics.net
Frame  49: [REDACTED].data.cdn-analytics.net
Frame  58: dGhpcyBpcyBmYWtl.update.telemetry-service.com
Frame  95: bm90IHRoZSBmbGFn.cdn.metrics-collector.io
```

### 3. Identify the Exfil Domain

Three queries go to `data.cdn-analytics.net`:

- `[REDACTED]`
- `[REDACTED]`
- `[REDACTED]`

The other suspicious domains are decoys:

- "hello world" (frame 25)
- "this is fake" (frame 58)
- "not the flag" (frame 95)

### 4. Base64-Decode the Subdomains

Individual decoding:

```
[REDACTED]      -> [REDACTED]        (readable - flag start)
[REDACTED]    -> binary junk    (partial - mid flag)
[REDACTED]      -> binary junk    (partial - end flag)
```

The trick: the subdomains are **fragments of a single base64 string** — they must be concatenated before decoding.

```python
import base64
parts = ['[REDACTED]', '[REDACTED]', '[REDACTED]']
concat = ''.join(parts)
print(base64.b64decode(concat + '==').decode())
```

Output:

```
[REDACTED]
```

### 5. Understanding the Attack

DNS exfiltration hides data in DNS query subdomains:

1. The attacker encodes stolen data as base64.
2. Splits it into chunks that fit in subdomain labels (max 63 chars per label).
3. Queries non-existent subdomains under attacker-controlled domains.
4. The DNS server logs reveal the data.

In this case:

- **Domain:** `data.cdn-analytics.net` (looks like analytics traffic)
- **Protocol:** DNS TXT queries (blends with normal DNS)
- **Encoding:** base64 in subdomain labels
- **Splitting:** 3 fragments that must be joined before decoding

Decoded flag: `[REDACTED]`

- `BB{` = flag format
- `dn5_` = `dns_` in leetspeak
- `3xf1l` = `exfil` in leetspeak
- `_d3t3ct3d}` = `_detected}` in leetspeak

## Flag

```
[REDACTED]
```

## Key Takeaways

- **DNS traffic analysis** — using `tshark` to filter and extract DNS queries from a pcap capture.
- **Exfiltration detection** — identifying suspicious DNS queries that use base64-encoded subdomains to hide data.
- **Domain analysis** — distinguishing normal DNS traffic from attacker-controlled domains used for data exfiltration.
- **Fragment reconstruction** — base64 fragments must be concatenated before decoding, not decoded individually.
- **Decoy recognition** — filtering out intentionally misleading subdomains ("hello world", "this is fake", "not the flag").
