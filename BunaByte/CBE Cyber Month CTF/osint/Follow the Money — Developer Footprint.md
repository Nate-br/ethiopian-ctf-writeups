---
title: "Follow the Money — Developer Footprint"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "osint"
  - "bunabyte"
category: "osint"
platform: "BunaByte"
---

# Follow the Money — Developer Footprint

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Follow the Money](../../../pics/follow%20the%20money.png)

> CBE Cyber Month CTF · **OSINT** · 300 pts · 29 solves · previously filed as *Money Mule*.

**Flag:** `[REDACTED]`

## Scenario

~ETB 500,000 was moved through six personal accounts, consolidated, and wired
out to a shell-company beneficiary, **Acme Global Holdings**. The payment memo
contained no invoice number — only the developer handle **`habtamu-t-dev`**.

## Investigation

The handle resolves to a public GitHub account:

- User: `habtamu-t-dev` ("Habtamu Tesfaye")
- Bio mentions *"Consulting @ Acme Global Holdings LLC"*
- One public repository: `habtamu-t-dev/acme-ledger-tools`
- No gists, no forks, no other repos, no tags

### Recover the deleted secret

```bash
git clone https://github.com/habtamu-t-dev/acme-ledger-tools.git
cd acme-ledger-tools
git log --all --oneline --stat
```

History:

```
54c468b chore: remove committed config, use config.example.ini instead
1ba9c1d temp: add real config for end-of-quarter run (DO NOT PUSH)
d6bf126 initial commit: reconcile tool + example config
09d4239 Initial commit
```

The second commit added a real `config.ini`, which the next commit deleted.
Deleting a file does not remove the blob from git history:

```bash
git show 1ba9c1d:config.ini
```

```ini
[acme]
operating_account = ETB-ACCT-55120-9
statement_author = habtamu-t-dev
quarter = Q3-2024

; Draft quarterly statement header kept here during migration.
; Title:  Acme Global Q3 2024 Draft
; Author: habtamu-t-dev ([REDACTED])
```

**Blob:** `15a2a0f` — introduced in `1ba9c1d`, "removed" in `54c468b`.

## Verification

- `git rev-list --objects --all` enumerates the deleted `config.ini` blob.
- `git fsck --full --unreachable --lost-found` reports nothing dangling — the
  blob is still reachable through commit `1ba9c1d`.
- The only `BB{...}` occurrence in the entire repository/history is the flag.
- No other branches, tags, notes, gists, or repos exist for the account.

## Lesson

Secrets committed to version control remain recoverable forever. Rotate any
credential that ever touched a repository, and scrub history with a tool such
as `git filter-repo` or BFG — a later delete commit is not enough.
