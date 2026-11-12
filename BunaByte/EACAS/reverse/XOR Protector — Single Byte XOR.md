---
title: "XOR Protector — Single Byte XOR"
category: reverse
platform: EACAS
difficulty: Medium
points: 100
solves: 0
flag: "[REDACTED]"
date: 2026-07-20
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "bunabyte"
---

# XOR Protector — Single Byte XOR

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

> In the shadows of the binary, a clever protector encrypted the flag using a single ancient technique — XOR. The data sits quietly in memory, waiting for the right key. Crack the encryption ritual and reveal the hidden message.

**Files:** `medium.zip` → `medium` (ELF 64-bit LSB executable, x86-64, statically linked, not stripped)

## Solution

### 1. Initial Recon

```bash
$ file medium
medium: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, not stripped

$ strings medium | grep -i flag
Correct! The flag is %s

$ nm medium | grep decrypt
0000000000401905 T decrypt
```

The binary has a `decrypt` function and prints `"Correct! The flag is %s"` — likely the success path after the right password.

### 2. Disassemble `decrypt`

```asm
0000000000401905 <decrypt>:
  401905:  endbr64
  401909:  push   %rbp
  40190a:  mov    %rsp,%rbp
  40190d:  mov    %rdi,-0x18(%rbp)    ; buffer pointer
  401911:  mov    %esi,-0x1c(%rbp)    ; length
  401914:  movb   $0x42,-0x5(%rbp)    ; XOR KEY = 0x42 ('B')
  401918:  movl   $0x0,-0x4(%rbp)     ; i = 0
  40191f:  jmp    401947
  401921:  mov    -0x4(%rbp),%eax     ; i
  401924:  movslq %eax,%rdx
  401927:  mov    -0x18(%rbp),%rax    ; buffer
  40192b:  add    %rdx,%rax           ; &buffer[i]
  40192e:  movzbl (%rax),%eax         ; load byte
  401931:  mov    -0x4(%rbp),%edx     ; i
  401934:  movslq %edx,%rcx
  401937:  mov    -0x18(%rbp),%rdx    ; buffer
  40193b:  add    %rcx,%rdx           ; &buffer[i]
  40193e:  xor    -0x5(%rbp),%al      ; XOR with 0x42
  401941:  mov    %al,(%rdx)          ; store back
  401943:  addl   $0x1,-0x4(%rbp)     ; i++
  401947:  mov    -0x4(%rbp),%eax     ; i < len
  40194a:  cmp    -0x1c(%rbp),%eax
  40194d:  jl     401921
  40194f:  nop
  401950:  nop
  401951:  pop    %rbp
  401952:  ret
```

The `decrypt` function iterates over the buffer and XORs each byte with key `0x42`.

### 3. Find the Encrypted Data

In `main`, the encrypted data is loaded as immediate values onto the stack:

```asm
  401971:  movabs $0x723a391103010307,%rax     ; bytes 0-7
  40197b:  movabs $0x2f73311d31731d30,%rdx     ; bytes 8-15
  401993:  movabs $0x3f712e322f7331,%rax       ; bytes 13-20 (+null)
```

Extracted bytes (little-endian):

```
07 03 01 03 11 39 3a 72  30 1d 73 31 1d 31 73 2f
32 2e 71 3f
```

### 4. Decrypt

XOR each byte with `0x42`:

```python
data = bytes([0x07, 0x03, 0x01, 0x03, 0x11, 0x39, 0x3a, 0x72,
              0x30, 0x1d, 0x73, 0x31, 0x1d, 0x31, 0x73, 0x2f,
              0x32, 0x2e, 0x71, 0x3f])
flag = bytes(b ^ 0x42 for b in data)
print(flag.decode())  # [REDACTED]
```

### 5. Verification

```bash
$ ./medium
Enter the password: [REDACTED]
Correct! The flag is [REDACTED]

$ ./medium
Enter the password: wrongpassword
Wrong password.
```

## Flag

```
[REDACTED]
```

*[REDACTED]*

## Key Takeaways

- **Single-byte XOR is trivial to spot** — a loop that loads a byte, XORs with a constant (`xor -0x5(%rbp),%al`), and stores it back is unmistakable in disassembly.
- **The key is often stored right next to the loop** — `movb $0x42,-0x5(%rbp)` initializes the key (`0x42`, `'B'`) immediately before the loop; check the stack frame setup first.
- **Encrypted blobs hide in `movabs` immediates** — big constants loaded onto the stack are little-endian byte arrays; reassemble them in order before decrypting.
- **XOR self-inverts** — the same `decrypt` routine that scrambles the data unscrambles it; the binary doubles as its own oracle.
- **`strings` won't find the flag** — it's not stored as text anywhere; the "Correct! The flag is %s" format string is the only hint.

Related: the exact same key (`0x42`) and technique appear in [[CrackMe2 — ELF Binary]], and [[CrackMe1 — ELF Binary]] uses single-byte XOR with key `0x17`. The same XOR-cipher family is at the heart of [[The Ransom]]'s "TelecomCrypt" script.
