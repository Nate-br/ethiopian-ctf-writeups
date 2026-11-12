---
title: "Password Hunter — Strings"
category: reverse
platform: EACAS
difficulty: Easy
points: 50
solves: 2
flag: "[REDACTED]"
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "bunabyte"
---

# Password Hunter — Strings

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> In the depths of a forgotten corporate server, a rogue AI guards its secrets with nothing more than a simple password check. The password is hidden somewhere inside the binary like a digital Easter egg. Your mission: hunt it down using basic terminal sorcery and claim your first victory.

**Files:** `easy1.zip` → `easy1` (ELF 64-bit LSB executable, x86-64, statically linked, not stripped)

## Solution

A single `strings` command reveals everything:

```bash
$ strings easy1 | grep -iE 'flag|password|enter|EACAS'
Enter the password:
[REDACTED]
Correct! The flag is [REDACTED]
Wrong!
```

The password was stored as a plaintext string in the `.rodata` section — fully visible, with no obfuscation at all.

## Verification

```bash
$ echo "[REDACTED]" | ./easy1
Enter the password: Correct! The flag is [REDACTED]

$ echo "wrongpassword" | ./easy1
Enter the password: Wrong!
```

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Always start with `strings`** — plaintext secrets in `.rodata` are the lowest-hanging fruit in reverse engineering.
- **Grep beats eyeballing** — piping `strings` through a targeted `grep -iE` pattern (`flag|password|enter|EACAS`) turns a wall of output into the answer instantly.
- **Static linking doesn't hide anything** — this binary was statically linked, yet the secret sat in plain sight; linking style is irrelevant when the developer never obfuscated the data.
- **Verify the flag by running it** — feeding the recovered value back into the binary confirms the finding end-to-end.

Related: [[Manual Checker — Assembly]] is the `easy2` follow-up in the same EACAS series — the flag there is *not* visible via strings, forcing an assembly-level approach.
