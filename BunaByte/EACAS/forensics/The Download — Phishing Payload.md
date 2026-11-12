---
title: "The Download — Phishing Payload"
category: forensics
platform: EACAS
difficulty: Easy
points: 100
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

# The Download — Phishing Payload

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> After identifying the phishing email from Challenge 1, we know someone clicked the malicious link. Our network monitoring system was recording traffic on the compromised VLAN at the time.
>
> The packet capture shows the exact moment the admin's workstation reached out to the attacker's server and downloaded something. Find the name of the file that was downloaded.

**Files:** `network_capture.pcap` (1,390 bytes, 11 packets)

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`):

- **Previous:** [[The Phish — Email Header Analysis]]
- **Next:** [[The Foothold — Scheduled Task Persistence]]

## Solution

### 1. Analyze the PCAP

A very small capture with a clear sequence of events:

| Time | Source | Dest | Protocol | Details |
|---|---|---|---|---|
| +0s | 192.168.1.50 | Broadcast | ARP | Who has 192.168.1.1? |
| +1s | 192.168.1.1 | 192.168.1.50 | ARP | 192.168.1.1 is here |
| +2s | 192.168.1.50 | 192.168.1.10 | DNS | Query A: `mail.telecom-corp.local` |
| +3s | 192.168.1.50 | 192.168.1.10 | DNS | Query A: **`telecom-update-server.local`** |
| +4s | 192.168.1.10 | 192.168.1.50 | DNS | Response: `telecom-update-server.local` → **10.99.5.105** |
| +5–7s | 192.168.1.50 | 10.99.5.105 | TCP | Three-way handshake (SYN/SYN-ACK/ACK) |
| +8s | 192.168.1.50 | 10.99.5.105 | **HTTP GET** | **`/updates/billing_patch_v2.exe`** |
| +9s | 10.99.5.105 | 192.168.1.50 | **HTTP 200** | **`billing_patch_v2.exe`** (66 bytes) |
| +10s | 192.168.1.50 | 10.99.5.105 | TCP | ACK |

### 2. Identify the Downloaded File

The HTTP response includes:

```
Content-Disposition: attachment; filename="billing_patch_v2.exe"
Content-Type: application/x-msdownload
Content-Length: 66
```

The payload starts with `MZ` — a Windows executable stub, though only 66 bytes (likely a minimal downloader or launcher).

### 3. Attack Chain Context

This challenge fits into the larger DFIR series:

1. **Phishing email** (Challenge 1) — lured admin to click
2. **The Download** — admin's workstation resolves `telecom-update-server.local` → `10.99.5.105`, downloads `billing_patch_v2.exe`
3. **The Foothold** — malware creates `\System_Telemetry_Updater` scheduled task for persistence
4. **The Coverup** — attacker runs Mimikatz for credential theft
5. **The Ransom** — ransomware encrypts `customer_db.enc`
6. **The Dead Drop** — exfiltrated customer data hidden in JPEG

## Flag

```
[REDACTED]
```

The attacker hosted a malicious executable on a domain impersonating a telecom update server, and the admin's workstation downloaded it via HTTP.

## Key Takeaways

- A small pcap can be fully reconstructed by following the packet timeline: DNS resolution → TCP handshake → HTTP GET → 200 response.
- The `Content-Disposition` header names the downloaded file; `Content-Type` and `Content-Length` confirm the executable delivery.
- The payload's `MZ` magic reveals a Windows executable — only 66 bytes, indicating a minimal downloader or launcher.
- An attacker-controlled domain (`telecom-update-server.local`) impersonating a legitimate update server is the campaign's delivery mechanism.
