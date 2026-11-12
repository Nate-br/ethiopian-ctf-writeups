---
title: "Phishing Invoice — Email + PNG"
category: stego
platform: —
difficulty: —
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "stego"
  - "bunabyte"
---

# Phishing Invoice — Email + PNG

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Phish and Pixels](../../pics/phish%20and%20pixels.png)

> A realistic phishing + steganography chain: a fake invoice email with a suspicious custom header that reveals where the payload is hidden — the LSB of the Blue channel of a PNG disguised as a JPG.

**Flag:** `[REDACTED]`

## Challenge

A ZIP archive (`steg.zip`) contains two files: `email.eml` and `invoice.jpg`. The email is a phishing attempt posing as an overdue invoice; the attached "invoice" hides the flag in its Blue channel LSBs. The custom email header `X-lock-` leaks the hiding location.

## Reconnaissance

1. **Extract and identify the files**

```bash
unzip steg.zip
Files: email.eml, invoice.jpg

file invoice.jpg
invoice.jpg: PNG image data, 784 x 1168, 8-bit/color RGB
```

Key observation: the file is named `invoice.jpg` but is actually a **PNG** file — a common obfuscation technique.

2. **Analyze the email (`email.eml`)**

The email is a phishing attempt posing as an overdue invoice:

```
From: "TechNova Billing" <billing@technova-invoice.com>
Subject: Urgent: Overdue Invoice #INV-74829 - Immediate Payment Required
```

The email body threatens legal action for a $12,450.00 "overdue invoice."

**Suspicious headers found at the bottom of the email:**

```
X-lock-: Ymx1ZWludm9pY2UyMDI2
X-Originating-IP: 185.220.101.2
```

The `X-lock-` header contains a base64-encoded string:

```bash
echo "Ymx1ZWludm9pY2UyMDI2" | base64 -d
```

```
blueinvoice2026
```

This appears to be a password or hint: "blueinvoice2026" — suggesting the data is hidden in the **BLUE channel** of the image.

## Solution

1. **Check for obvious data hiding**

```bash
xxd invoice.jpg | head -5     # PNG header confirmed
xxd invoice.jpg | tail -10    # Ends with IEND marker
```

No extra data appended after the PNG IEND marker.

```bash
strings -n 4 invoice.jpg | tail -30
```

No obvious flag text in the `strings` output.

2. **Extract the LSB steganography**

Since there's no appended data, the flag must be hidden using LSB (least significant bit) steganography. The hint from the email header ("blueinvoice2026") points at the Blue channel. Extract the LSB of each pixel's Blue channel:

```python
from PIL import Image

img = Image.open('invoice.jpg')
pixels = img.load()
width, height = img.size

# Extract LSBs from Blue channel only
bits = []
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y]
        bits.append(b & 1)

# Convert bits to bytes
result = []
for i in range(0, len(bits) // 8 * 8, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    result.append(byte)
extracted = bytes(result)

# Search for flag
text = extracted.decode('ascii', errors='ignore')
idx = text.find('bb{')
if idx >= 0:
    end = text.find('===FLAG_END===', idx)
    print(text[idx:end] if end >= 0 else text[idx:idx+50])
```

Output:

```
[REDACTED]
```

## Flag

```
[REDACTED]
```

## Understanding the Attack Chain

This challenge simulates a realistic phishing + steganography attack:

1. **EMAIL PHISHING** — the email uses urgency ("24 hours or legal action") to pressure the recipient into acting without thinking.
2. **OBFUSCATION** — file extension mismatch (PNG named as `.jpg`) prevents casual inspection.
3. **HIDDEN DATA** — the actual payload is hidden using LSB steganography in the Blue channel of the image.
4. **EMAIL HEADER CLUES** — the custom `X-lock-` header contains a base64 hint ("blueinvoice2026") that reveals where the data is hidden (Blue channel).
5. **FLAG FORMAT** — the flag uses leetspeak: `[REDACTED]`.

## Key Takeaways

- **Email analysis** — inspect email headers for suspicious custom headers (`X-lock-`) that may contain hidden data.
- **File type verification** — always check the actual file type with the `file` command, not just the extension.
- **LSB steganography** — data hidden in the least significant bit of pixel channels is invisible to the naked eye but can be extracted programmatically.
- **Hint correlation** — the base64 in the email header decoded to "blueinvoice2026", directly hinting at the Blue channel as the hiding location.
- Manual LSB extraction is the fallback when a generic tool doesn't flag anything — compare with the automated `zsteg` route in [[Danakil Depression — PNG LSB]].
