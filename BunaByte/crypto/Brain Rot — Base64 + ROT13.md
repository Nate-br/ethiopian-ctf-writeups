---
title: "Brain Rot — Base64 + ROT13"
category: crypto
platform: BunaByte
difficulty: Easy
points: 15
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "crypto"
  - "bunabyte"
---

# Brain Rot — Base64 + ROT13

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Brain Rot](../../pics/brain%20rot.png)

> BunaByte · **Cryptography** · 15 pts · 184 solves · previously filed as *Addis Ababa Stela*.

> An ancient stela cipher found in Addis Ababa: base64 wrapping a Caesar-shifted (ROT13) flag.

**Flag:** `[REDACTED]`

## Challenge

The challenge provides a single encoded string — a cipher text styled as an "ancient stela cipher" from Addis Ababa. Two layers hide the flag: base64 encoding over a ROT13-shifted plaintext.

## Reconnaissance

The given string `[REDACTED]` ends with `=`, which is the padding character for base64 encoding — a strong first signal.

## Solution

1. **Base64 decode**

```bash
echo "[REDACTED]" | base64 -d
```

Result:

```
[REDACTED]
```

This looks like a flag format (`oo{}`) but the inner text is garbled, suggesting a Caesar cipher was applied to the original plaintext before base64 encoding.

2. **Apply ROT13**

ROT13 is a Caesar cipher with shift 13. Applying it to `[REDACTED]`:

```
o → b    o → b    p → c    e → r    l → y
c → p    g → t    0 → 0    _ → _    v → i
5 → 5    _ → _    s → f    h → u    a → n
```

Result:

```
[REDACTED]
```

The restored flag reads "[REDACTED]".

## Flag

```
[REDACTED]
```

## Key Takeaways

- Base64 and ROT13 are often combined in CTF challenges.
- Always try ROT13 on decoded text that looks like it should be a flag but has garbled alphabetic characters.
- ROT13 on base64-encoded data doesn't work well because base64 uses both letters and numbers — decode first, then apply ROT13.
- ROT13 is only one member of the Caesar family; other challenges in this vault (e.g. [[The Ransom — Ransomware Note]]) use different ROT shifts, so brute-forcing all 26 is a good habit.
