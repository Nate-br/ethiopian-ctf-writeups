---
title: "Uncle's Last Byte — PyInstaller"
category: reverse
platform: BunaByte
difficulty: Medium
points: 100
solves: 40
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "bunabyte"
---

# Uncle's Last Byte — PyInstaller

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Uncle's Last Byte](../../pics/uncles%20last%20byte.png)

## Challenge

A stripped ELF binary that turns out to be a PyInstaller-packed Python program. It prints a masked "treasure location" and never reveals the real message — exactly as Uncle's hint warns: don't believe what the program tells you at first glance.

**Files:** `treasure.zip` → `treasure` (ELF 64-bit LSB executable, x86-64, dynamically linked, **stripped**)

## Solution

### 1. Extract and Identify the Binary

```bash
unzip treasure.zip -d treasure
file treasure/treasure
treasure/treasure: ELF 64-bit LSB executable, x86-64, version 1
(SYSV), dynamically linked, stripped
```

The binary is **stripped** (no debug symbols). However, the `strings` output reveals this is a PyInstaller-packed Python executable:

- References to Python modules (base64, hashlib, etc.)
- `"PYZ.pyz"` (Python archive)
- `"treasure.pyc"` (compiled Python bytecode)
- `"libpython3.13.so"` (Python 3.13)

### 2. Extract the PyInstaller Bundle

PyInstaller bundles a Python script into a single executable. The original bytecode can be extracted with pyinstxtractor:

```bash
pip3 install pyinstxtractor-ng
python3 -c "
import pyinstxtractor_ng
import sys
sys.argv = ['pyinstxtractor', 'treasure/treasure']
pyinstxtractor_ng.main()
"
```

This extracts to `treasure_extracted/` with:

- `treasure.pyc` (the main Python script)
- `PYZ.pyz_extracted/` (all imported modules)
- `base_library.zip`
- Various `.so` libraries

### 3. Decompile/Disassemble the Python Bytecode

Since the binary uses Python 3.13, standard decompilers (e.g. uncompyle6) don't support it. Instead, use the `dis` module to disassemble:

```python
import dis, marshal, struct, types
with open('treasure_extracted/treasure.pyc', 'rb') as f:
    f.read(16)  # skip header
    code = marshal.load(f)
dis.dis(code)
```

Or inspect the code constants:

```python
import marshal, struct, types
with open('treasure_extracted/treasure.pyc', 'rb') as f:
    f.read(16)
    code = marshal.load(f)
for c in code.co_consts:
    if isinstance(c, (str, bytes)):
        print(repr(c))
    elif isinstance(c, types.CodeType):
        for cc in c.co_consts:
            if isinstance(cc, (str, bytes)):
                print(f'  {repr(cc)}')
```

### 4. Reconstruct the Python Source Code

From the disassembly, the original source can be reconstructed:

```python
import base64
import hashlib

def decode_message():
    encoded = '[REDACTED]'
    key = hashlib.md5(b's3cr3t_k3y').hexdigest()[:8]

    data = base64.b64decode(encoded).decode('utf-8')
    result = ''
    for i, char in enumerate(data):
        result += chr(ord(char) ^ ord(key[i % len(key)]))
    return result

def main():
    print('The secret treasure is hidden in: **********')
    hidden = decode_message()  # RESULT NEVER PRINTED!

if __name__ == '__main__':
    main()
```

Key observations:

1. The base64 string decodes to: `[REDACTED]`
2. `decode_message()` XORs it with `md5("s3cr3t_k3y")[:8]`
3. `main()` calls `decode_message()` but **does not print** the result
4. The program only prints asterisks: `"**********"`

### 5. Decode the Flag

```bash
python3 -c "
import base64
encoded = '[REDACTED]'
print(base64.b64decode(encoded).decode())
"
[REDACTED]
```

### 6. Understanding the Uncle's Hint

> "If you can uncover the real message hidden inside my last script, the real treasure is yours. Don't believe what program tells you at first glance. Look deeper, kid."

The uncle's warning makes sense:

- The program prints `"**********"` — that's what it "tells you"
- The real treasure is the base64 string inside the code
- The XOR with md5 is a **red herring** — it produces garbage
- The actual flag **is** the base64-decoded value directly

The uncle hid the flag in plain sight as a base64 string, then added a misleading XOR layer that `main()` never even outputs.

## Flag

```
[REDACTED]
```

## Key Takeaways

- **PyInstaller reconnaissance** — spotting the tell-tale strings (`PYZ.pyz`, `.pyc`, `libpython*.so`) identifies a packed Python binary even when stripped; pyinstxtractor recovers the bytecode.
- **Bytecode analysis without a decompiler** — when uncompyle6 and friends don't support the Python version, `marshal` + `dis` still let you read constants and instructions directly.
- **Red herring detection** — the md5-keyed XOR *looks* like the decryption step, but it produces garbage; the real flag is the base64 string itself.
- **Dead code analysis** — `main()` calls `decode_message()` and discards the return value. The result is never printed — a classic "don't believe what the program tells you" scenario, and the same MD5-derived-key + XOR motif seen in [[The Ransom]].

Related: [[CrackMe1 — ELF Binary]] also hides its secret behind a base64 string plus an XOR layer.
