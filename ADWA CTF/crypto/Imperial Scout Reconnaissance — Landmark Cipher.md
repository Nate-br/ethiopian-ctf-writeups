---
title: "Imperial Scout Reconnaissance — Landmark Cipher"
category: crypto
platform: ADWA CTF
difficulty: Medium
points: 300
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "crypto"
  - "adwa-ctf"
---

# Imperial Scout Reconnaissance — Landmark Cipher

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

> ADWA CTF · **Cryptography / Recon** · 300 pts

> Yekatit 1888 (March 1, 1896). The heights of Adwa are shrouded in mist. Emperor Menelik II and Empress Taytu relied on local peasant scouts stationed on the highest basalt peak overlooking the battlefield. An intercepted reconnaissance report from Ras Alula'\''s lookouts has fallen into our hands. Analyze the geographic landmarks, coordinate reports, and historical scout cipher key to decrypt the runner'\''s wire and recover the flag.

**Flag:** `[REDACTED]`

## Challenge

The challenge provides a reconnaissance dispatch text file (`recon_dispatch.txt`) containing intelligence from Ras Alula Engida and Fitawrari Gebeyehu on the night before the Battle of Adwa.

Key excerpts from the dispatch:
- **Observation Redoubt**: Twin-peaked basalt mountain at 2,434 m elevation, coordinates `14.1750° N, 38.8917° E`.
- **Historical Name**: Mount Soloda (`SOLODA`).
- **Enciphered Runner Wire**: `Sr7oFTXM3qru{6-2i-4251w_utBE}bGCFq_7HD{EC`
- **Alphabet**: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}` (length 65)
- **Cipher Key**: Landmark name in uppercase (`SOLODA`).
- **Integrity Checksum (SHA-256)**: `fdc5387f7f3856372555348f0160fef3d738d5e20b10c9cdff58502c9e490105`

## Reconnaissance & Intelligence Analysis

### 1. Landmark & Key Identification

The dispatch explicitly links the scout vantage point to Mount Soloda overlooking Adwa:
```text
TERRAIN INTELLIGENCE & OBSERVATION POST IDENTIFICATION:
- Elevation: 2,434 meters above sea level
- Coordinates: 14.1750° N, 38.8917° E
- Geography: Twin-peaked basalt mountain rising abruptly from the high plateau
- Historical Name: Mount Soloda (Primary Landmark Key: SOLODA)
```

The encryption key is established as:
```text
KEY = "SOLODA"
```

### 2. Cipher Structure & Mechanics

The dispatch defines the alphabet:
```text
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}"
```
Evaluating `len(ALPHABET)` gives **65** characters:
- `A`–`Z`: indices 0–25 (26 characters)
- `a`–`z`: indices 26–51 (26 characters)
- `0`–`9`: indices 52–61 (10 characters)
- `_`: index 62
- `{`: index 63
- `}`: index 64

The ciphertext string contains dashes (`-`) at indices 14 and 17:
```text
Sr7oFTXM3qru{6-2i-4251w_utBE}bGCFq_7HD{EC
```
Because `-` is absent from the 65-character alphabet, standard polyalphabetic convention leaves delimiters intact while the key sequence advances synchronously across every character position.

## Solution

The decryption formula follows the standard Vigenère modular subtraction:
$$P_i = (C_i - K_i) \pmod{65}$$
where non-alphabet characters (`-`) are preserved verbatim, and key index $i$ advances with each character in the transmission.

### Solver Script

```python
import hashlib

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}"
wire = "Sr7oFTXM3qru{6-2i-4251w_utBE}bGCFq_7HD{EC"
key = "SOLODA"
expected_sha = "fdc5387f7f3856372555348f0160fef3d738d5e20b10c9cdff58502c9e490105"

N = len(alphabet)
plaintext = []

for i, ch in enumerate(wire):
    if ch in alphabet:
        k_ch = key[i % len(key)]
        c_val = alphabet.index(ch)
        k_val = alphabet.index(k_ch)
        p_val = (c_val - k_val) % N
        plaintext.append(alphabet[p_val])
    else:
        plaintext.append(ch)

recovered = "".join(plaintext)
calc_sha = hashlib.sha256(recovered.encode()).hexdigest()

assert calc_sha == expected_sha
print(f"Decrypted flag: [REDACTED]")
print(f"Checksum matched: {calc_sha == expected_sha}")
```

Running the script recovers the flag and confirms an exact match with the SHA-256 integrity checksum.

## Flag

```
[REDACTED]
```

## Key Takeaways

- Classical polyalphabetic ciphers (Vigenère) can be generalized to non-standard alphabets incorporating alphanumeric characters and bracket symbols.
- Key index stream alignment across delimiters (such as hyphens) is crucial: testing whether the key counter advances on non-alphabet characters quickly isolates the correct stream phase.
- Provided SHA-256 checksums serve as authoritative validation vectors during automated cryptanalysis.
