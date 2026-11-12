---
title: "Manual Checker — Assembly"
category: reverse
platform: EACAS
difficulty: Easy
points:
solves:
flag: "[REDACTED]"
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "bunabyte"
---

# Manual Checker — Assembly

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> A paranoid programmer didn't trust library functions. Instead, they built a custom character-by-character flag verifier — slow, stubborn, and full of personality. No obvious strings will save you here. Time to dive into the assembly and outsmart their homemade logic.

**Files:** `easy2.zip` → `easy2` (ELF 64-bit LSB executable, x86-64, statically linked, not stripped)

## Solution

### 1. Initial Recon

```bash
$ file easy2
easy2: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, not stripped

$ strings easy2 | grep -iE 'flag|success|incorrect'
Enter flag:
Success! Flag accepted.
Incorrect.
```

No flag string in `.rodata` — unlike its sibling [[Password Hunter — Strings]], the flag is baked into the code as comparison constants.

### 2. Main Function

The `main` function at `0x401a01`:

- Prints `"Enter flag: "` (string at `0x49d02c`)
- Reads input with `scanf("%99s", buffer)`
- Calls `check(buffer)` at `0x401905`
- Returns `1` → prints `"Success! Flag accepted."` or `0` → prints `"Incorrect."`

### 3. The `check` Function — Custom Character Verifier

The `check` function at `0x401905` implements a **manual character-by-character comparison** — each byte of the input is loaded, compared against a hardcoded hex value, and branches to `0x4019fa` (return 0, failure) if any mismatch is found. If all checks pass, it returns `1` (success).

```asm
check:
  401905:  endbr64
  401909:  push   %rbp
  40190a:  mov    %rsp,%rbp
  40190d:  mov    %rdi,-0x8(%rbp)        ; buffer pointer

  ; Position 0: 'E' = 0x45
  401915:  movzbl (%rax),%eax
  401918:  cmp    $0x45,%al
  40191a:  jne    4019fa                  ; return 0 if mismatch

  ; Position 1: 'A' = 0x41
  401928:  movzbl (%rax),%eax
  40192b:  cmp    $0x41,%al
  40192d:  jne    4019fa

  ; ... repeats for each character ...
```

Each character check follows the same pattern:

1. Load byte from buffer at offset N
2. Compare with a hex constant
3. Jump to failure if not equal

### 4. Extracted Flag Characters

| Position | Hex | ASCII | Position | Hex | ASCII |
|----------|-----|-------|----------|-----|-------|
| 0 | `0x45` | `E` | 7 | `0x33` | `3` |
| 1 | `0x41` | `A` | 8 | `0x6d` | `m` |
| 2 | `0x43` | `C` | 9 | `0x31` | `1` |
| 3 | `0x41` | `A` | 10 | `0x6e` | `n` |
| 4 | `0x53` | `S` | 11 | `0x34` | `4` |
| 5 | `0x7b` | `{` | 12 | `0x6c` | `l` |
| 6 | `0x74` | `t` | 13 | `0x7d` | `}` |

### 5. Verification

```bash
$ echo "[REDACTED]" | ./easy2
Enter flag: Success! Flag accepted.

$ echo "[REDACTED]" | ./easy2
Enter flag: Incorrect.
```

## Flag

```
[REDACTED]
```

*[REDACTED]*

## Key Takeaways

- **Homemade verifiers are just serialized comparisons** — a "custom" check function is often nothing more than repeated `cmp`/`jne` pairs with hardcoded constants.
- **The flag doesn't have to be in `.rodata`** — constants embedded in code are invisible to `strings` but trivially readable in a disassembler.
- **Pattern recognition in assembly** — one repeated check pattern is enough to extract all 14 characters from the hex constants.
- **`endbr64` prologue** — a signature of CET (Control-flow Enforcement Technology); harmless, but worth recognizing so it doesn't confuse the analysis.

Related: [[Password Hunter — Strings]] is the easier `easy1` sibling in the same EACAS series.
