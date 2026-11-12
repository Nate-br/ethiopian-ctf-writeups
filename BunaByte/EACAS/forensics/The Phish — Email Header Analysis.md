---
title: "The Phish — Email Header Analysis"
category: forensics
platform: EACAS
difficulty: Easy
points: 100
solves: 5
flag: [REDACTED]
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# The Phish — Email Header Analysis

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> Our email gateway flagged a suspicious message after the breach had already occurred. It was sent to **Ahmad Mansour**, a senior systems administrator with elevated privileges to the billing infrastructure.
>
> The email appeared to come from the internal IT department, urging Ahmad to install a "Critical Server Update" immediately. He clicked the link.
>
> We've extracted the raw email from the gateway logs. Your job: **find the attacker's real IP address** hidden in the email headers.

**Files:** `urgent_update.eml` (5.3 KB), `PLAYER_BRIEFING.html`

## Incident Chain

Part of the EACAS campaign (attacker `10.99.5.105`, `telecom-corp.local`). This challenge is the **first step** of the incident timeline:

- **Next:** [[The Download — Phishing Payload]]

Full sequence: [[The Phish — Email Header Analysis]] → [[The Download — Phishing Payload]] → [[The Foothold — Scheduled Task Persistence]] → [[The Coverup — Prefetch Analysis]] → [[The Ransom — XOR Decryption]] → [[The Dead Drop — JPEG ZIP Append]]

## Solution

### 1. Examine the Email Headers

The `Received` header chain (reading bottom-to-top, oldest-to-newest):

```
Received: from localhost (localhost [127.0.0.1])
    by smtp-relay.telecom-corp.local (Postfix) with ESMTP id ...
    ; Mon, 14 Jun 2026 01:47:20 +0300 (AST)

Received: from smtp-relay.telecom-corp.local (unknown [10.99.5.105])
    by mail-filter.telecom-corp.local (Postfix) with ESMTP id ...
    for <a.mansour@telecom-corp.local>
    (envelope-from it-updates@telecom-corp.local)
    ; Mon, 14 Jun 2026 01:47:21 +0300 (AST)

Received: from mail-filter.telecom-corp.local (mail-filter [192.168.10.30])
    by mail-gw.telecom-corp.local (Postfix) with ESMTP id ...
    ; Mon, 14 Jun 2026 01:47:22 +0300 (AST)

Received: from mail-gw.telecom-corp.local (mail-gw [192.168.10.25])
    by mx-primary.telecom-corp.local (Postfix) with ESMTPS id ...
    ; Mon, 14 Jun 2026 01:47:23 +0300 (AST)
```

### 2. Trace the Origin

The first Received header shows the email was submitted to `smtp-relay` from `localhost [127.0.0.1]` — meaning it was injected directly on the server, not via a remote SMTP connection from a legitimate client.

The **X-Originating-IP** header reveals the actual source:

```
X-Originating-IP: [10.99.5.105]
```

This is consistent with findings from **The Download** challenge, where `10.99.5.105` hosted `telecom-update-server.local` — the attacker's phishing server that delivered `billing_patch_v2.exe`.

### 3. Identify the Deception

The email impersonated the IT department with:

- **From spoof:** "IT Infrastructure Team" <it-updates@telecom-corp.local>
- **Urgency:** "Critical Server Security Patch — Immediate Action Required"
- **Malicious link:** `http://telecom-update-server.local/updates/billing_patch_v2.exe`
- **SPF:** softfail — sending server not authorized
- **DMARC:** fail — authentication failure
- **Content:** convincingly formatted with Microsoft Outlook styling

### 4. Attack Chain Context

This challenge begins the full incident timeline:

1. **The Phish** — Attacker at `10.99.5.105` sends spear-phish to Ahmad Mansour
2. **The Download** — Ahmad clicks link, downloads `billing_patch_v2.exe`
3. **The Foothold** — Malware installs `\System_Telemetry_Updater` scheduled task
4. **The Coverup** — Attacker runs Mimikatz for credential theft
5. **The Ransom** — Billing database encrypted
6. **The Dead Drop** — Customer data exfiltrated

## Flag

```
[REDACTED]
```

The attacker's real IP address (`10.99.5.105`) is hidden in the `X-Originating-IP` header, matching the telecom-update-server infrastructure identified in subsequent challenges.

## Key Takeaways

- **`X-Originating-IP`** reveals the true sending host even when the `From` address and Received chain are spoofed or relayed.
- Read `Received` headers **bottom-to-top** (oldest to newest) to trace the delivery path.
- SPF softfail + DMARC fail plus urgency-themed social engineering are classic spear-phishing indicators.
