---
title: "Find Me? — Maria Telal"
category: forensics
platform: ADWA CTF
difficulty: Easy
points: 400
flag: [REDACTED]
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "adwa-ctf"
---

# Find Me? — Maria Telal

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Find Me?](../../pics/find%20me%3F.png)

## Challenge

> An APT hacker, Maria Telal, announced her big malware development phase. She said she is going to make undetectable malware, which is already on stage 2 of her dev plan. Can you spot her plan and know what she is up to?

## Solution

### 1. Reconnaissance

The challenge description mentions:

- Name: **Maria Telal**
- "apt hacker" (APT = Advanced Persistent Threat)
- Announced a malware development phase
- Currently on **stage 2** of her dev plan
- Challenge title: "Find Me?"

This is primarily an OSINT challenge — find Maria Telal's online presence and discover her "top secret" plan.

### 2. GitHub Search

Searching GitHub for "Maria Telal" reveals a repository:

```
Owner:  ruspaaa
Repo:   maria-telal
URL:    https://github.com/ruspaaa/maria-telal
```

### 3. Repository Contents

The repo contains a single file: **`top-secret-project.txt`**

```
To do list:
- Make undetectable malware
- get ready for stage 2
- step ahead...
- [REDACTED]
```

The to-do list directly references the challenge description ("Make undetectable malware", "get ready for stage 2") and contains the flag in the last item.

## Flag

```
[REDACTED]
```

Decoded: "was making malware for real"

## Key Takeaways

- Challenge titles and descriptions double as OSINT breadcrumbs — "Find Me?", "APT", "stage 2" all point to a public persona.
- Searching GitHub for a persona name can surface repositories that leak plans or flags.
- Read every file in a found repo, including "to-do lists" — flags are often hiding in plain sight.
