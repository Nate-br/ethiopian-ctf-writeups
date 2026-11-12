---
title: "Source Code Treasure"
category: web
platform: BunaByte
difficulty: —
points: 80
solves: 91
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# Source Code Treasure

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Source Code Treasure](../../pics/source%20code%20treassure.png)

> A JavaScript flag hunt: the real flag is split across two JS files, buried among fake flags and obfuscated variable names.

**Target:** `https://c2vjb25kyxj5lwnoywxszw5nzs13zwi.bunabyte.com/`

## Challenge

The page source contains an HTML comment hinting at scripts, and two JavaScript files each hold a piece of the flag. Decoy "fake flags" are scattered through both files to mislead.

## Reconnaissance

**Fetch the page source:**

```bash
curl -s https://c2vjb25kyxj5lwnoywxszw5nzs13zwi.bunabyte.com/
```

Key findings in HTML:

1. HTML comment: "Sometimes scripts speak louder than HTML" → hints to check JavaScript files.

2. Two JS files loaded:

```html
<script src="app.js?v=2"></script>
<script src="utils.js?v=2"></script>
```

## Solution

1. **Analyze app.js**

```bash
curl -s https://c2vjb25kyxj5lwnoywxszw5nzs13zwi.bunabyte.com/app.js?v=2
```

Found in app.js:

```javascript
function _0xdecoyFlag() {
  return "[REDACTED]";  // FAKE FLAG
}

// --- PART 1 (REAL) ---
const _0xabc123 = "[REDACTED]"; // First half of the real flag
// Not everything is in one place
```

Key observations:

- There's a decoy function `_0xdecoyFlag` returning a fake flag.
- PART 1 of the real flag is stored in `_0xabc123`.
- The comment confirms "Not everything is in one place".

2. **Analyze utils.js**

```bash
curl -s https://c2vjb25kyxj5lwnoywxszw5nzs13zwi.bunabyte.com/utils.js?v=2
```

Found in utils.js:

```javascript
// --- PART 2 (REAL) ---
const _0xdef456 = "[REDACTED]";

// Fake flag
const _0xfakeFlag = "[REDACTED]";
```

Key observations:

- PART 2 of the real flag is stored in `_0xdef456`.
- Another fake flag (`_0xfakeFlag`) as a decoy.

3. **Decode the flag parts**

Part 1 (from app.js):

```bash
echo "[REDACTED]" | base64 -d
```

```
[REDACTED]
```

Part 2 (from utils.js):

```bash
echo "[REDACTED]" | base64 -d
```

```
[REDACTED]
```

Combined flag:

```
[REDACTED]
```

4. **Decode the fake flags (decoys)**

```bash
echo "[REDACTED]" | base64 -d
```

```
[REDACTED]
```

This fake flag appears in BOTH files as a decoy to mislead.

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Source code inspection** — always view the page source (Ctrl+U) and check for HTML comments that hint at hidden content.
- **JavaScript analysis** — when comments hint at scripts, check all linked JS files for hidden data.
- **Decoy recognition** — not everything you find is real. The fake flags (`[REDACTED]`) appeared in both files to mislead; the real flag was split across two files.
- **Base64 decoding** — the flag parts were base64-encoded; always try base64 decoding on suspicious strings.
- **Split data** — flags can be split across multiple files:
  - app.js: `[REDACTED]` (`[REDACTED]`)
  - utils.js: `[REDACTED]` (`[REDACTED]`)
- **Obfuscation techniques** — variable names like `_0xabc123`, `_0xdef456` obscure the real data; focus on the values, not the names.
- A related JavaScript base64 hunt is [[NexaCore Source Leak]].
