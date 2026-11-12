---
title: "NexaCore Source Leak"
category: web
platform: BunaByte
difficulty: —
points: 75
solves: 13
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# NexaCore Source Leak

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![NexaCore Source Leak](../../pics/nexacoresource%20leak.png)

> NexaCore Solutions has just launched its new corporate website. Everything looks polished on the surface, but developers sometimes leave secrets behind in client-side assets. Can you uncover the hidden company secret?

**Target:** `https://d2viy2hhbgxlbmdlzm9yaw5zyq.bunabyte.com/`

## Challenge

A standard corporate landing page for "NexaCore Solutions" with sections: Home, About Us, Services, Contact. Nothing interesting in the visible content — the secret lives in a client-side JavaScript asset.

## Reconnaissance

1. **Fetch the target website**

```bash
curl https://d2viy2hhbgxlbmdlzm9yaw5zyq.bunabyte.com/
```

2. **Inspect the HTML source** — two external asset references:

```html
<link rel="stylesheet" href="style.css">
<script src="js/main.js"></script>
```

These are the client-side assets mentioned in the challenge description.

3. **Check style.css** — only standard CSS styling, no secrets:

```bash
curl https://d2viy2hhbgxlbmdlzm9yaw5zyq.bunabyte.com/style.css
```

## Solution

1. **Fetch `js/main.js`**

```bash
curl https://d2viy2hhbgxlbmdlzm9yaw5zyq.bunabyte.com/js/main.js
```

The file contains:

- A `DOMContentLoaded` handler for form submission
- An `initAnalyticsTracker()` function
- A `generateSessionId()` function
- A `trackPageView()` function

2. **Spot the suspicious object.** Inside `trackPageView()`:

```javascript
const _legacyConfig = {
    debugMode: false,
    apiToken: "QkJ7d2FpdF95b3VfZ290X2l0X2h1aH0",
    env: "production"
};
```

The comment `//WHAT A HACKER!!!` above it draws attention. The variable name `_legacyConfig` and the comment "Developer note: Legacy API token configuration. Do not expose in production!" are clearly intentional hints that this is the secret.

3. **Decode the base64 string**

```bash
echo "QkJ7d2FpdF95b3VfZ290X2l0X2h1aH0" | base64 -d
```

Result:

```
[REDACTED]
```

The `BB{}` format confirms it matches the expected flag format for this CTF.

## Flag

```
[REDACTED]
```

## Key Takeaways

- Always inspect all client-side assets loaded by a web page, especially JavaScript files.
- Developers frequently leave hardcoded secrets (API tokens, passwords, flags) in JavaScript files, thinking they are safe because they are not directly visible in the HTML.
- Base64 is not encryption — it is encoding. Never put sensitive data in client-side code, even if base64-encoded.
- The challenge name "Source Leak" hints that the source code (JS files) contains leaked secrets.
- A very similar exercise in hunting base64 blobs inside JS files is [[Source Code Treasure]].
