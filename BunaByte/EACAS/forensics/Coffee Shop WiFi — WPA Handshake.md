---
title: "Coffee Shop WiFi — WPA Handshake"
category: forensics
platform: EACAS
difficulty: Medium
points: 150
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

# Coffee Shop WiFi — WPA Handshake

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> Free WiFi at a tech conference in Addis Ababa was abused by an attacker. The EACA 2026 conference network team noticed unusual login attempts on their guest network and pulled a packet capture during the incident window. Your job: figure out what happened.
>
> The conference organizers set up a guest WiFi network for attendees at EACA 2026 — "EACA2026-Guest." Midway through the event, the network team noticed something strange: repeated connection attempts from a device that didn't belong to any registered attendee.
>
> They captured some traffic during the incident. See if you can recover what happened — and what the attacker found.

**Files:** `Coffeeshop_wifi.zip` → `coffeeshop_wifi.cap`, `coffeeshop_flag.zip` (password-protected), `wordlist.txt`

## Solution

### 1. Analyze the PCAP

The capture contains a full **4-way WPA2 handshake** between an AP and a rogue client:

| Frame | Type | Details |
|---|---|---|
| 1 | Beacon | AP `02:1a:2b:3c:4d:5e` advertising SSID `EACA2026-Guest`, WPA2-PSK/AES |
| 2–3 | Authentication | Open System auth — client `02:9f:8e:7d:6c:5b` to AP |
| 4–5 | Association | Association Request/Response |
| 6 | EAPOL 1 | AP sends ANonce to client |
| 7 | EAPOL 2 | Client responds with SNonce + MIC (`8d7a85e8c33370edf0b266c163aa59a5`) |
| 8 | EAPOL 3 | AP sends GTK |
| 9 | EAPOL 4 | Client acknowledges |

The attacker captured this handshake and cracked the WPA2-PSK passphrase offline.

### 2. Crack the Password-Protected ZIP

The zip `coffeeshop_flag.zip` is password-protected. The provided `wordlist.txt` contains ~500 conference-themed passwords.

```bash
$ while read pwd; do
    unzip -t -P "$pwd" coffeeshop_flag.zip &>/dev/null && echo "FOUND: $pwd" && break
  done < wordlist.txt

FOUND: addis2026
```

### 3. Extract the Flag

```bash
$ unzip -P addis2026 coffeeshop_flag.zip
$ cat flag.txt
Congratulations, you recovered the WiFi handshake and cracked the passphrase.

The conference network "EACA2026-Guest" was using a weak, easily guessable
password — a common mistake even at security-focused events.

[REDACTED]
```

## Flag

```
[REDACTED]
```

*[REDACTED]*

## Key Takeaways

- A captured 4-way WPA2 handshake (EAPOL 1–4 frames) can be cracked offline — the passphrase is the only secret protecting the PSK.
- Weak, guessable guest-network passwords defeat WPA2 even when the handshake exchange itself is sound.
- Password-protected archives are only as strong as their passwords: a ~500-entry themed wordlist cracked this one in seconds.
