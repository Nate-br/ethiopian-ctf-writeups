---
title: "Classified Transmission — HTTP Headers"
category: web
platform: BunaByte
difficulty: —
points: 100
solves: 60
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# Classified Transmission — HTTP Headers

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

> A "Classified Transmission" themed page with an empty body — but something lingers in the spaces between. The secret is carried in the envelope, not the letter.

**Target:** `https://1a7f612f0f9949d41ea1cad2ce180846.bunabyte.com/`

## Challenge

The page displays a "Classified Transmission" theme with clues:

- "The page is empty, yet something lingers in the static"
- "Not all secrets are written some are carried in the spaces between"
- "What does the courier hide in the envelope?"

Key hint: *"The courier doesn't just deliver the letter—sometimes the envelope itself contains the secret. What else travels with every message across the wire?"*

This strongly suggests looking at HTTP headers — the "envelope" that carries every web response.

## Reconnaissance

Fetch the page and dump the response headers:

```bash
curl -s -D- https://1a7f612f0f9949d41ea1cad2ce180846.bunabyte.com/
```

Standard headers (not useful):

```
HTTP/2 200
content-type: text/html; charset=utf-8
server: Vercel
x-vercel-cache: HIT
```

**Custom header found:**

```
x-session-flag: [REDACTED]
```

The header name `x-session-flag` is a dead giveaway that this contains the flag.

## Solution

1. **Inspect the HTTP response headers** (see above) — `curl -D-` prints headers, or use browser DevTools (F12 → Network tab).

2. **Decode the flag.** The value `[REDACTED]` is base64-encoded:

```bash
echo "[REDACTED]" | base64 -d
```

Output:

```
[REDACTED]
```

## Flag

```
[REDACTED]
```

## Where to Look for Hidden Data in Web Challenges

1. **HTTP Response Headers** (this challenge)
   - Custom headers like `x-flag`, `x-secret`, `x-session-flag`
   - Standard headers that may contain encoded data

2. **HTML Source Code**
   - HTML comments: `<!-- flag here -->`
   - Hidden elements: `<div style="display:none">`
   - Meta tags

3. **HTTP Cookies**
   - `Set-Cookie` headers
   - Session cookies with encoded values

4. **JavaScript Variables**
   - Global variables in scripts
   - Embedded JSON data

5. **Response Body**
   - Whitespace characters (zero-width spaces)
   - Unicode characters
   - Trailing content after `</html>`

In this case the flag was in a custom HTTP header (`x-session-flag`), encoded in base64. The hints metaphorically described HTTP headers as "the envelope" that carries every message.

## Key Takeaways

- **HTTP header inspection** — always check response headers, especially custom `x-*` ones, when looking for hidden data.
- **Base64 recognition** — many CTF flags are base64-encoded; the character set `[A-Za-z0-9+/=]` is a giveaway.
- **Metaphor interpretation** — "the envelope" = HTTP headers, "the courier" = the HTTP protocol, "spaces between" = the non-visible parts of the response.
- **Tools** — `curl -D-` shows headers; browser DevTools (F12 → Network tab) shows all response headers too.
- This flag was independently recovered during the [[BunaByte Vulnerability Assessment]] (found in the `x-session-flag` response header).
