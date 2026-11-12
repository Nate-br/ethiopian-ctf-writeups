---
title: "Adwa CTF — Backward"
category: web
platform: ADWA CTF
difficulty: Hard
points: 200
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "adwa-ctf"
---

# Adwa CTF — Backward

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![ወደ ኋላ (Backward)](../../pics/%E1%8B%88%E1%8B%B0%20%E1%88%80%E1%88%8B.png)

> A "calculator" binary that demands a subscription key before it will evaluate an expression. Solve the calc and the program prints the flag itself.

**Author:** onegash3
**Hint:** *"Your teacher asked you to calculate this: 3 + 4"*

## Challenge

The challenge (ወደ ኋላ 🧑🦯, "Backward") provides a Linux binary named `ifmphuulwdhhguefhdgo`. Although listed under the Web category on ADWA CTF, the solve is pure binary analysis: find the hidden subscription key, unlock the calculator, and enter the expression from the hint.

**Flag:** `[REDACTED]`

## Reconnaissance

Identify the file type:

```bash
file ifmphuulwdhhguefhdgo
```

Expected output:

```
ELF 64-bit LSB executable ... dynamically linked ...
```

This confirms it is a Linux executable program.

## Solution

1. **Run the program**

```bash
chmod +x ifmphuulwdhhguefhdgo
./ifmphuulwdhhguefhdgo
```

Output:

```
Welcome to CxC Calculator!
Enter subscription key to continue:
```

Entering anything (e.g. `test`) yields:

```
Invalid subscription key. Access Denied.
```

2. **Find the subscription key with `strings`**

```bash
strings ifmphuulwdhhguefhdgo
```

Relevant strings from the output:

```
Welcome to CxC Calculator!
Enter subscription key to continue:
%49s
Access Granted! Starting Calculator...
Enter expression (e.g., 4 + 5):
%d %c %d
Result: %d
Error: Divide by zero
Invalid operator
Invalid subscription key. Access Denied.
809-889-345    <--- THIS IS THE KEY!
```

`809-889-345` is the only string that looks like a password or key — the rest are messages and format codes.

3. **Unlock the calculator**

```bash
./ifmphuulwdhhguefhdgo
```

At the `Enter subscription key to continue:` prompt, type `809-889-345` and press Enter:

```
Access Granted! Starting Calculator...
Enter expression (e.g., 4 + 5):
```

4. **Enter the expression from the hint**

The hint says the teacher asked to calculate `3 + 4`. Type exactly — spaces around the `+` are required:

```
3 + 4
```

The program prints:

```
[REDACTED]
```

5. **Submit the flag on the platform**

1. Go to https://adwactf.com
2. Log in to your account
3. Go to Dashboard → Challenges
4. Find challenge "ወደ ኋላ 🧑🦯"
5. Click "Submit Flag"
6. Enter: `[REDACTED]`
7. You get 200 points!

## Flag

```
[REDACTED]
```

## Bonus: How the Flag Was Hidden

The flag was not stored as plain text in the binary. Instead, the author converted each letter of the flag to a byte and XOR'd it with `0x55`:

- `'C'` (letter) = `0x43` (in hex)
- `0x43 XOR 0x55 = 0x16`

So `0x16` was stored in the binary instead of `'C'`. When the program sees a correct `3 + 4` expression, it reverses the XOR for every character:

```
0x16 XOR 0x55 = 0x43 = 'C'
```

**How this was discovered:** disassembling the binary shows:

```bash
objdump -d ifmphuulwdhhguefhdgo
```

In the assembly code there is a loop that runs `0x14` (20) times, reads a byte from memory, XORs it with `0x55`, stores the result in a buffer, and prints it. The encrypted bytes are loaded via `movabs` instructions. Extracting those bytes and XOR'ing them with `0x55` reveals `[REDACTED]`.

## All Commands in One Place

```bash
# 1. Identify file
file ifmphuulwdhhguefhdgo

# 2. Make executable and run
chmod +x ifmphuulwdhhguefhdgo
./ifmphuulwdhhguefhdgo

# 3. Find subscription key
strings ifmphuulwdhhguefhdgo | grep -E '^[0-9-]+$'

# 4. Run with correct key and expression
#    (Type: 809-889-345 , then: 3 + 4)

# 5. Alternative: Extract encrypted data automatically
objdump -d ifmphuulwdhhguefhdgo | grep 'movabs' | python3 -c "
import sys, re
data = b''
for line in sys.stdin:
    m = re.search(r'movabs\s+\$(0x[0-9a-f]+)', line)
    if m:
        val = int(m.group(1), 16)
        data += val.to_bytes((val.bit_length() + 7) // 8, 'little')
flag = bytes(b ^ 0x55 for b in data).rstrip(b'\x00')
print('Flag:', flag.decode())
"
```

## Key Takeaways

- `strings` is the fastest way to spot embedded keys, passwords, and flag fragments in a binary.
- A hardcoded secret in a binary is trivially recoverable; obfuscation such as XOR is only a speed bump.
- When a challenge provides a hint about input, the hint is often the exact input the program expects.
- `objdump -d` plus a small script can automate recovery of XOR-obfuscated data.
- This is a sibling binary challenge to [[Adwa CTF — CrackMe]] — same CTF, same author, same `strings`-first approach.
