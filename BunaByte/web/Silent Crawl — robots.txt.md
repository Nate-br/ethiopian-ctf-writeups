---
title: "Silent Crawl — robots.txt"
category: web
platform: BunaByte
difficulty: —
points: 100
solves: 70
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# Silent Crawl — robots.txt

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Silent Crawl](../../pics/silent%20crawl.png)

> Think like a crawler: read the file crawlers read, follow the disallowed paths, and chase the exposed path hint to the flag.

**Target:** `https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/`

## Challenge

The challenge title "Silent Crawl" and description "think like a crawler" are hints to check `robots.txt` — the file crawlers read to learn which paths to ignore.

## Reconnaissance

**Check robots.txt** — every web challenge should start here:

```bash
curl https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/robots.txt
```

Result:

```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /internal/
Disallow: /dev-secret/
```

## Solution

1. **Visit the disallowed paths**

```bash
curl -L https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/admin/
curl -L https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/backup/
curl -L https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/internal/
curl -L https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/dev-secret/
```

(The `-L` flag follows redirects — the paths redirect from `/admin/` to `/admin` without a trailing slash.)

What each path returns:

- `/admin/` → Fake admin login page (not real)
- `/internal/` → "Access Restricted" message
- `/dev-secret/` → 404 NOT_FOUND
- `/backup/` → "Directory Listing Forbidden" page with a SYSTEM NOTE

The `/backup/` page is the important one. It contains a hidden clue:

> "System Note: Warning - Last updated 2026-03-25.
>  Exposed Path: dev-secret/config.json"

2. **Fetch the exposed path**

The backup page reveals that `/dev-secret/config.json` is an exposed path:

```bash
curl https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/dev-secret/config.json
```

Result:

```json
{
  "api_endpoint": "https://api.cloudnova.internal/v1",
  "debug_mode": true,
  "system_status": "operational",
  "auth_token_format": "base64",
  "flag": "[REDACTED]"
}
```

3. **Decode the base64 flag**

The `"auth_token_format": "base64"` field is a hint that the flag field is base64-encoded:

```bash
echo "[REDACTED]" | base64 -d
```

Result:

```
[REDACTED]
```

## Full Solve (All Commands in Order)

```bash
1. curl https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/robots.txt
2. curl -L https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/backup/
   (Look for the "Exposed Path" hint)
3. curl https://zmlyc3qty2hhbgxlbmdllxdlyg.bunabyte.com/dev-secret/config.json
4. echo "[REDACTED]" | base64 -d
5. Flag: [REDACTED]
```

## Flag

```
[REDACTED]
```

## Notes

- No User-Agent spoofing needed — `config.json` was publicly accessible regardless of User-Agent.
- The "think like a crawler" hint was about reading `robots.txt` (the file crawlers use), not about changing your User-Agent.
- The backup page's exposed-path hint was the key clue.
- Flag format: `BB{...}`.

## Key Takeaways

- Always start web challenges with `robots.txt` — disallowed paths often point to admin areas, backups, or internal tooling.
- Not every disallowed path is a dead end; the interesting one may contain a clue pointing to another path.
- JSON config files are a common hiding spot for encoded flags; watch for fields that hint at encoding (`auth_token_format: base64`).
- `curl -L` follows the trailing-slash redirects, so checking both `/path/` and `/path` matters.
