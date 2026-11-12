---
title: "The Ransom — Ransomware Note"
category: crypto
platform: —
difficulty: —
points: 60
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "crypto"
  - "bunabyte"
---

# The Ransom — Ransomware Note

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![The Ransom](../../pics/the%20ransom.png)

> A ransomware note left on a victim's desktop by the threat actor "Ph4nt0mCrypt". Hidden within the note is the flag — obfuscated with a Caesar cipher.

**Flag:** `[REDACTED]`

## Challenge

A ZIP archive contains a typical ransomware note. Among the threat-actor drama, the "unique decryption key" is a Caesar-shifted flag. Brute-forcing the shift reveals it.

## Reconnaissance

1. **Extract the ZIP**

```bash
unzip RANSOM_NOTE.zip
```

This yields a single file: `RANSOM_NOTE.txt` (5975 bytes).

2. **Examine the ransom note**

Reading the file reveals a typical ransomware message. The note includes:

- ASCII art banner reading "Ph4nt0mCrypt" and "CRYPT"
- Bitcoin wallet address: `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`
- Contact email: `ph4nt0mcrypt@pr0t0nmail.ch`
- A **"Decryption Key"** used for payment verification

## Solution

1. **Locate the obfuscated key.** On **line 55** of the note, the "unique decryption key" is displayed:

```
[REDACTED]
```

The prefix `[REDACTED]` does not match any standard flag format, suggesting the text has been obfuscated with a substitution cipher.

2. **Apply the Caesar cipher (ROT-8).** Brute-forcing all 26 ROT shifts on the key reveals a readable result at **ROT-8** (shift backwards by 8 positions):

| Shift | Output |
|-------|--------|
| ROT-7 | `[REDACTED]` |
| **ROT-8** | **`[REDACTED]`** |
| ROT-9 | `[REDACTED]` |

ROT-8 cleanly decodes to:

```
[REDACTED]
```

Which reads as **"[REDACTED]"** in leetspeak.

3. **Verify.** No hidden data, trailing spaces, or steganography was found in the file. The ROT-8 shift is the only transformation needed.

## Flag

```
[REDACTED]
```

## Key Takeaways

- Ransomware notes are a rich source of CTF content — wallets, emails, and "decryption keys" are all fair game for hiding data.
- When a flag-like string doesn't match the expected format, brute-force all 26 Caesar shifts (ROT-1 through ROT-25) instead of guessing one.
- The `BB{...}`/`bb{...}` prefix is a reliable anchor: shift until the prefix itself decodes to a known flag format.
- Caesar ciphers appear throughout this vault — compare with [[Addis Ababa Stela — Base64 + ROT13]] (ROT13 over base64).
