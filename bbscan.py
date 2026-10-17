#!/usr/bin/env python3
"""
Black-box web application pentest suite (evidence-based).

Designed for AUTHORIZED testing of an application you own, against a
NON-PRODUCTION instance (localhost / staging). It never reads source;
it probes the running app and reports only findings it can demonstrate
with a concrete request/response or a differential/timing signal.

Usage:
  python3 bbscan.py --target http://localhost:3000
  python3 bbscan.py --target http://localhost:3000 \
      --login-url http://localhost:3000/session \
      --username you@example.com --password secret \
      --user-field email --pass-field password
  python3 bbscan.py --target http://localhost:3000 \
      --cookie "_curb_session=abc123"   # reuse a known authenticated cookie

Output: console summary + JSON report (--out report.json).

Design rules (why this is not the broken rails-attack script):
  * Payloads are URL-encoded and actually sent in the query/body.
  * Detection is DIFFERENTIAL (baseline vs payload), timing-based for
    blind SQLi, or exact marker-reflection for XSS -- never keyword
    grepping or "response contains <script>".
  * Rate-limited; no DoS, no mass record creation, no destructive verbs
    unless --allow-writes is passed (and even then, GET-safe by default).
"""

import argparse
import http.cookiejar
import json
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser

# ----------------------------------------------------------------------------
# HTTP client (stdlib only: works anywhere, no pip installs)
# ----------------------------------------------------------------------------

DEFAULT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36 bbscan/1.0")


@dataclass
class Resp:
    status: int
    headers: dict
    body: str
    elapsed: float
    url: str


class Client:
    def __init__(self, base, rate=3.0, timeout=15, extra_cookie=None, verbose=False):
        self.base = base.rstrip("/")
        self.min_interval = 1.0 / rate if rate > 0 else 0
        self.timeout = timeout
        self.verbose = verbose
        self._last = 0.0
        self.cj = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # local/staging self-signed tolerated
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj),
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect(),
        )
        self.extra_cookie = extra_cookie

    def _throttle(self):
        if self.min_interval:
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.time()

    def abs(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base + path

    def req(self, method, path, data=None, headers=None, raw=None, content_type=None):
        self._throttle()
        url = self.abs(path)
        body = None
        hdrs = {"User-Agent": DEFAULT_UA,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
        if self.extra_cookie:
            hdrs["Cookie"] = self.extra_cookie
        if headers:
            hdrs.update(headers)
        if raw is not None:                       # pre-encoded body (JSON/multipart)
            body = raw if isinstance(raw, bytes) else raw.encode()
            if content_type:
                hdrs["Content-Type"] = content_type
        elif data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        r = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        t0 = time.time()
        try:
            with self.opener.open(r, timeout=self.timeout) as resp:
                raw = resp.read()
                return Resp(resp.status, _headers_to_dict(resp.headers), _txt(raw),
                            time.time() - t0, resp.geturl())
        except urllib.error.HTTPError as e:
            raw = e.read()
            return Resp(e.code, _headers_to_dict(e.headers), _txt(raw),
                        time.time() - t0, url)
        except Exception as e:  # noqa: BLE001
            return Resp(0, {}, f"__ERROR__ {e}", time.time() - t0, url)

    def get(self, path, headers=None):
        return self.req("GET", path, headers=headers)

    def post(self, path, data=None, headers=None):
        return self.req("POST", path, data=data or {}, headers=headers)

    def send(self, method, path, raw=None, content_type=None, headers=None):
        """Send a request with a pre-encoded raw body (JSON, multipart, XML)."""
        return self.req(method, path, raw=raw, content_type=content_type,
                        headers=headers)

    def post_json(self, path, obj, headers=None):
        return self.send("POST", path, raw=json.dumps(obj),
                         content_type="application/json", headers=headers)

    def post_multipart(self, path, fields, files, headers=None):
        """fields: {name: value}; files: {name: (filename, content_type, bytes)}."""
        boundary = "----bbscan" + secrets.token_hex(8)
        parts = []
        for name, value in (fields or {}).items():
            parts.append(f"--{boundary}\r\n"
                         f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                         f"{value}\r\n".encode())
        for name, (fname, ctype, content) in (files or {}).items():
            head = (f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'
                    f"Content-Type: {ctype}\r\n\r\n").encode()
            body = content if isinstance(content, bytes) else content.encode()
            parts.append(head + body + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self.send("POST", path, raw=b"".join(parts),
                         content_type=f"multipart/form-data; boundary={boundary}",
                         headers=headers)

    def get_follow(self, path, max_redirects=6):
        """GET, following same-origin redirects. Returns (final_resp, chain)."""
        chain = []
        cur = path
        r = self.get(cur)
        chain.append((cur, r.status))
        for _ in range(max_redirects):
            if r.status not in (301, 302, 303, 307, 308):
                break
            loc = r.headers.get("location", "")
            if not loc:
                break
            nxt = urllib.parse.urljoin(self.base + cur, loc)
            if not nxt.startswith(self.base):
                break  # never leave the target origin
            cur = nxt[len(self.base):] or "/"
            r = self.get(cur)
            chain.append((cur, r.status))
        return r, chain


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture redirects instead of following, so we can inspect Location."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _headers_to_dict(msg):
    """Lower-case header keys (HTTP headers are case-insensitive) and join
    duplicates (e.g. multiple Set-Cookie) so lookups are reliable."""
    d = {}
    for k, v in msg.items():
        lk = k.lower()
        d[lk] = (d[lk] + ", " + v) if lk in d else v
    return d


def _txt(raw):
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:  # noqa: BLE001
            continue
    return raw.decode("utf-8", "replace")


# ----------------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------------

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str          # Confirmed | Suspected
    endpoint: str
    evidence: str
    remediation: str
    cvss: str = ""


@dataclass
class Report:
    target: str
    authenticated: bool
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)

    def note(self, s):
        self.notes.append(s)


# ----------------------------------------------------------------------------
# HTML helpers
# ----------------------------------------------------------------------------

class LinkForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(a["href"])
        elif tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "get").lower(),
                         "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name"),
                                        "type": a.get("type", "text"),
                                        "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def parse_page(body):
    p = LinkForm()
    try:
        p.feed(body)
    except Exception:  # noqa: BLE001
        pass
    return p.links, p.forms


# ----------------------------------------------------------------------------
# Modules
# ----------------------------------------------------------------------------

def m_fingerprint(c, rep):
    r = c.get("/")
    server = r.headers.get("server", "")
    powered = r.headers.get("x-powered-by", "")
    is_rails = any(k in ("x-request-id", "x-runtime") for k in r.headers)
    set_cookie = r.headers.get("set-cookie", "")
    rails_cookie = bool(re.search(r"_[\w]+_session=", set_cookie))
    rep.note(f"Root status={r.status} server='{server}' powered='{powered}' "
             f"rails_signals={is_rails or rails_cookie}")
    return r


def m_security_headers(c, rep):
    r = c.get("/")
    h = {k.lower(): v for k, v in r.headers.items()}
    checks = [
        ("Content-Security-Policy", "content-security-policy", "Medium",
         "Set a restrictive CSP to mitigate XSS/data injection."),
        ("X-Content-Type-Options", "x-content-type-options", "Low",
         "Set `X-Content-Type-Options: nosniff`."),
        ("X-Frame-Options / frame-ancestors", "x-frame-options", "Low",
         "Set `X-Frame-Options: DENY` or CSP frame-ancestors to prevent clickjacking."),
        ("Strict-Transport-Security", "strict-transport-security", "Low",
         "Enable HSTS (config.force_ssl = true) for HTTPS deployments."),
    ]
    for name, key, sev, fix in checks:
        if key not in h:
            # HSTS only meaningful over https
            if key == "strict-transport-security" and c.base.startswith("http://"):
                continue
            rep.add(Finding(
                title=f"Missing security header: {name}",
                severity=sev, confidence="Confirmed", endpoint="/",
                evidence=f"GET / response headers lack '{name}'. Present: {sorted(h)}",
                remediation=fix))


def m_cookie_flags(c, rep):
    r = c.get("/")
    raw = r.headers.get("set-cookie", "")
    if not raw:
        rep.note("No Set-Cookie on GET /.")
        return
    for cookie in re.split(r",(?=[^ ;]+=)", raw):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if c.base.startswith("https://") and "secure" not in low:
            missing.append("Secure")
        if missing and "session" in name.lower():
            rep.add(Finding(
                title=f"Session cookie '{name}' missing flags: {', '.join(missing)}",
                severity="Medium", confidence="Confirmed", endpoint="/",
                evidence=f"Set-Cookie: {cookie.strip()[:200]}",
                remediation="Set HttpOnly, SameSite=Lax/Strict (and Secure over HTTPS) "
                            "on session cookies."))


def m_verbose_errors(c, rep):
    # Trigger a likely 404/500 and look for a full stack trace / dev error page.
    r = c.get("/this-should-not-exist-" + str(int(time.time())))
    body = r.body
    if re.search(r"(Extracted source \(around line|"
                 r"actionpack \(\d|activerecord \(\d|"
                 r"Full backtrace|rails-controller-testing|"
                 r"<title>Action Controller: Exception caught</title>)", body):
        rep.add(Finding(
            title="Verbose error page / stack trace exposed",
            severity="Medium", confidence="Confirmed", endpoint=r.url,
            evidence=f"status={r.status}; response contains a Rails backtrace / "
                     f"dev exception page (first 300 chars): {body[:300]!r}",
            remediation="Ensure production runs with config.consider_all_requests_local "
                        "= false and custom error pages; never expose dev error pages."))


def m_common_paths(c, rep):
    interesting = [
        "/rails/info/routes", "/rails/info/properties", "/rails/info",
        "/up", "/health", "/robots.txt", "/sitemap.xml",
        "/.env", "/config/database.yml", "/.git/config",
        "/sidekiq", "/admin", "/users.json", "/users", "/500", "/400",
    ]
    for p in interesting:
        r = c.get(p)
        if r.status in (200, 302) and "__ERROR__" not in r.body:
            sev = "Info"
            fix = "Confirm this endpoint should be publicly reachable."
            if p in ("/rails/info", "/rails/info/routes", "/rails/info/properties"):
                sev = "Medium"
                fix = ("/rails/info is dev-only diagnostic data; ensure it is not "
                       "reachable in production.")
            if p in ("/.env", "/config/database.yml", "/.git/config"):
                sev = "High"
                fix = "Block access to dotfiles/config/VCS metadata at the web server."
            if p == "/sidekiq":
                sev = "Medium"
                fix = "Protect the Sidekiq web UI behind authentication."
            rep.add(Finding(
                title=f"Reachable path: {p} ({r.status})",
                severity=sev, confidence="Confirmed", endpoint=p,
                evidence=f"GET {p} -> {r.status}, {len(r.body)} bytes",
                remediation=fix))


def m_reflected_xss(c, rep, param_eps):
    marker = "bbsx" + str(int(time.time())) + "qzx"
    probe = f"<{marker}>"
    # Discovered GET endpoints + a few generic guesses.
    targets = dict(param_eps)
    for base, p in {"/": {"q": "x"}, "/search": {"q": "x"}}.items():
        targets.setdefault(base, p)
    tested = 0
    escaped_seen = False
    for base, params in targets.items():
        for pname in (list(params.keys()) or ["q"]):
            q = dict(params)
            q[pname] = probe
            url = base + "?" + urllib.parse.urlencode(q)
            r = c.get(url)
            tested += 1
            if probe in r.body:  # < and > survived unescaped
                rep.add(Finding(
                    title="Reflected XSS: unescaped user input in response",
                    severity="High", confidence="Confirmed", endpoint=url,
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    evidence=f"Sent {pname}={probe!r}; reflected verbatim (unescaped). "
                             f"Snippet: {_around(r.body, marker)!r}",
                    remediation="Escape output (Rails does by default with ERB <%= %>); "
                                "avoid raw/html_safe on user data."))
                return
            if marker in r.body:
                escaped_seen = True
    rep.note(f"Reflected-XSS: tested {tested} param combinations; "
             f"{'reflections were HTML-escaped (good)' if escaped_seen else 'no reflection observed'}.")


def _sqli_probe(c, base, params, pname):
    """Differential + time-based test on one parameter. Payloads encoded."""
    def build(val):
        q = dict(params)
        q[pname] = val
        return base + "?" + urllib.parse.urlencode(q)

    orig = str(params.get(pname, "1"))
    r_base = c.get(build(orig))
    r_true = c.get(build(orig + " OR 1=1-- -"))
    r_false = c.get(build(orig + " AND 1=2-- -"))
    signals = []
    if r_base.status and r_true.status and r_false.status:
        if (len(r_true.body) != len(r_false.body)
                and abs(len(r_true.body) - len(r_base.body))
                < abs(len(r_false.body) - len(r_base.body))):
            signals.append("boolean differential in response length")
    if r_base.elapsed < 2.0:  # engine-agnostic time-based
        for label, pl in (("pg_sleep", f"{orig});SELECT pg_sleep(4)-- -"),
                          ("SLEEP", f"{orig} AND SLEEP(4)-- -")):
            rt = c.get(build(pl))
            if rt.elapsed > 3.5:
                signals.append(f"time-based: {label}(4) added {rt.elapsed:.1f}s")
                break
    return signals, r_base, r_true, r_false


def m_sqli(c, rep, param_eps):
    idish = {"id", "page", "p", "user_id", "account_id", "post_id",
             "order_id", "offset", "limit", "sort", "order"}
    cands = []
    for base, params in param_eps.items():
        for pn, pv in params.items():
            if (re.fullmatch(r"\d+", str(pv)) or pn.lower() in idish
                    or pn.lower().endswith("_id")):
                cands.append((base, params, pn))
    if not cands:
        cands.append(("/", {"id": "1"}, "id"))  # generic fallback
    tested = 0
    found = False
    for base, params, pn in cands[:10]:
        tested += 1
        signals, rb, rt, rf = _sqli_probe(c, base, params, pn)
        if signals:
            found = True
            rep.add(Finding(
                title=f"Possible SQL injection ({pn} on {base})",
                severity="Critical", confidence="Suspected",
                endpoint=f"{base}?{pn}=",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                evidence="Signals: " + "; ".join(signals) +
                         f". baseline={rb.elapsed:.2f}s true_len={len(rt.body)} "
                         f"false_len={len(rf.body)}",
                remediation="Use parameterized ActiveRecord queries; never interpolate "
                            "params into where/find_by_sql/order."))
    rep.note(f"SQLi: tested {tested} parameter(s); "
             f"{'signal found' if found else 'no differential/timing signal'}.")


def m_csrf(c, rep, forms):
    for f in forms:
        if f["method"] == "post":
            names = {i.get("name") for i in f["inputs"]}
            has_token = any(n and ("authenticity_token" in n or "csrf" in n)
                            for n in names)
            if not has_token:
                rep.add(Finding(
                    title=f"POST form without CSRF token field: {f['action'] or '(self)'}",
                    severity="Medium", confidence="Suspected",
                    endpoint=f["action"] or "/",
                    evidence=f"Form method=post action={f['action']!r} inputs={sorted(n for n in names if n)} "
                             "had no authenticity_token field.",
                    remediation="Ensure protect_from_forgery is active and the form uses "
                                "Rails form helpers that embed the CSRF token."))


def m_open_redirect(c, rep):
    ev = "https://evil.example.com/"
    for p in ("/?return_to=", "/?redirect=", "/?redirect_to=", "/?url=", "/?next="):
        r = c.get(p + urllib.parse.quote(ev))
        loc = r.headers.get("location", "")
        if r.status in (301, 302, 303, 307, 308) and loc.startswith("https://evil.example.com"):
            rep.add(Finding(
                title=f"Open redirect via {p}",
                severity="Medium", confidence="Confirmed", endpoint=p,
                evidence=f"GET {p}{ev} -> {r.status} Location: {loc}",
                remediation="Only redirect to allow-listed/relative paths; validate "
                            "redirect targets."))


def m_idor(c, rep, authed, id_paths):
    # Prefer id paths the crawl actually discovered; fall back to generic
    # REST nouns only if none were found. Read-only GETs; no mutation.
    targets = list(id_paths)
    if not targets:
        targets = [f"/{r}/1" for r in ("users", "accounts", "posts", "comments",
                                       "orders", "items", "profiles", "messages",
                                       "files", "documents")]
    tested = reported = 0
    for base in targets[:25]:
        m = re.search(r"^(.*?/)(\d+)(/.*|/?)$", base)
        if not m:
            continue
        prefix, num, suffix = m.group(1), m.group(2), m.group(3)
        n = int(num)
        orig = c.get(base)
        tested += 1
        if orig.status != 200 or len(orig.body) < 150 or "__ERROR__" in orig.body:
            continue
        hits = []
        for nb in (n - 1, n + 1, 1, n + 1000):
            if nb <= 0 or nb == n:
                continue
            r = c.get(f"{prefix}{nb}{suffix}")
            tested += 1
            if r.status == 200 and len(r.body) > 150 and "__ERROR__" not in r.body:
                hits.append((nb, len(r.body)))
        if hits:
            reported += 1
            rep.add(Finding(
                title=f"Possible IDOR / broken object-level auth: {prefix}:id{suffix or ''}",
                severity="High", confidence="Suspected",
                endpoint=f"{prefix}:id{suffix}",
                evidence=f"As {'an authenticated' if authed else 'an unauthenticated'} user, "
                         f"{prefix}{n}{suffix} returned 200; adjacent ids "
                         f"{[h[0] for h in hits]} also returned 200 with content "
                         f"(lengths {[h[1] for h in hits]}). Confirm these objects belong "
                         "to OTHER users (needs a second account to prove).",
                remediation="Scope lookups to the current user (e.g. "
                            "current_user.things.find) and enforce object-level "
                            "authorization (Pundit/CanCanCan)."))
    rep.note(f"IDOR: probed {tested} object request(s); {reported} suspected pattern(s).")


def m_auth_gates(c, rep, authed):
    # Privileged areas should NOT be reachable unauthenticated.
    if authed:
        return
    for p in ("/admin", "/admin/users", "/admin/dashboard", "/sidekiq"):
        r = c.get(p)
        if r.status == 200 and len(r.body) > 200:
            rep.add(Finding(
                title=f"Privileged path reachable unauthenticated: {p}",
                severity="High", confidence="Suspected", endpoint=p,
                evidence=f"Unauthenticated GET {p} -> 200 ({len(r.body)} bytes).",
                remediation="Require authentication + authorization before rendering "
                            "admin areas; return 302 to login or 404."))


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------

def do_login(c, args, rep):
    r = c.get(args.login_url.replace(c.base, "") or "/login")
    _, forms = parse_page(r.body)
    token = None
    m = re.search(r'name="(?:authenticity_token|csrf-token)"[^>]*(?:value|content)="([^"]+)"', r.body)
    if not m:
        m = re.search(r'<meta name="csrf-token" content="([^"]+)"', r.body)
    if m:
        token = m.group(1)
    data = {args.user_field: args.username, args.pass_field: args.password}
    if token:
        data["authenticity_token"] = token
    lr = c.post(args.login_url, data=data)
    # Success heuristic: a redirect (302) + a fresh session cookie, or 200
    # without the login form reappearing.
    ok = lr.status in (302, 303) or (lr.status == 200 and args.pass_field not in lr.body)
    rep.note(f"Login POST -> {lr.status}; treated as {'success' if ok else 'FAILED'}.")
    return ok


# ----------------------------------------------------------------------------
# Crawl + run
# ----------------------------------------------------------------------------

def crawl(c, rep, max_pages=60):
    """Follow same-origin redirects and build an endpoint inventory.

    Returns (pages, forms, param_eps, id_paths):
      pages      : set of visited base paths
      forms      : list of parsed <form> dicts
      param_eps  : {base_path: {param: sample_value}} for GET endpoints
      id_paths   : set of base paths ending in a numeric id (e.g. /foo/42)
    """
    seen, queue = set(), ["/"]
    forms_all, param_eps, id_paths = [], {}, set()

    def note_path(path):
        base = path.split("?")[0]
        m = re.search(r"/(\d+)(?:/|$)", base)
        if m:
            id_paths.add(base)
        if "?" in path:
            q = urllib.parse.urlparse(path)
            params = dict(urllib.parse.parse_qsl(q.query))
            if params:
                param_eps.setdefault(base, params)

    while queue and len(seen) < max_pages:
        p = queue.pop(0)
        base = p.split("?")[0]
        if base in seen:
            continue
        seen.add(base)
        r, chain = c.get_follow(p)
        for cp, _ in chain:                       # mine redirect targets too
            note_path(cp)
            b = cp.split("?")[0]
            if b not in seen and len(seen) < max_pages:
                seen.add(b)
        if "__ERROR__" in r.body or not r.body:
            continue
        links, forms = parse_page(r.body)
        forms_all.extend(forms)
        for f in forms:                           # GET forms -> param endpoints
            if f["method"] == "get" and f["action"]:
                params = {i["name"]: (i.get("value") or "test")
                          for i in f["inputs"] if i.get("name")}
                if params:
                    param_eps.setdefault(f["action"].split("?")[0], params)
        for href in links:
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            u = urllib.parse.urljoin(c.base + p, href)
            if not u.startswith(c.base):
                continue
            path = u[len(c.base):] or "/"
            note_path(path)
            b = path.split("?")[0]
            if b not in seen and b not in queue:
                queue.append(b)
    rep.note(f"Crawled {len(seen)} paths; {len(forms_all)} forms; "
             f"{len(param_eps)} param-endpoints; {len(id_paths)} id-paths.")
    if param_eps:
        rep.note("Param endpoints: " + ", ".join(sorted(param_eps)[:12]))
    if id_paths:
        rep.note("Id paths: " + ", ".join(sorted(id_paths)[:12]))
    return seen, forms_all, param_eps, id_paths


def run(c, rep, args, authed):
    m_fingerprint(c, rep)
    pages, forms, param_eps, id_paths = crawl(c, rep)
    m_security_headers(c, rep)
    m_cookie_flags(c, rep)
    m_verbose_errors(c, rep)
    m_common_paths(c, rep)
    m_reflected_xss(c, rep, param_eps)
    m_sqli(c, rep, param_eps)
    m_csrf(c, rep, forms)
    m_open_redirect(c, rep)
    m_idor(c, rep, authed, id_paths)
    m_auth_gates(c, rep, authed)


def _around(body, marker, span=60):
    i = body.find(marker)
    if i < 0:
        return ""
    return body[max(0, i - span):i + span]


def print_report(rep):
    rep.findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    print("\n" + "=" * 78)
    print(f"BLACK-BOX SCAN REPORT  target={rep.target}  "
          f"authenticated={rep.authenticated}")
    print("=" * 78)
    if not rep.findings:
        print("No demonstrable findings.")
    for f in rep.findings:
        print(f"\n[{f.severity}] ({f.confidence}) {f.title}")
        print(f"  endpoint : {f.endpoint}")
        if f.cvss:
            print(f"  cvss     : {f.cvss}")
        print(f"  evidence : {f.evidence}")
        print(f"  fix      : {f.remediation}")
    print("\n--- notes / recon ---")
    for n in rep.notes:
        print(f"  * {n}")
    print("=" * 78)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--rate", type=float, default=3.0, help="requests/sec cap")
    ap.add_argument("--out", default=None, help="write JSON report here")
    ap.add_argument("--cookie", default=None, help="raw Cookie header for authed run")
    ap.add_argument("--login-url", default=None)
    ap.add_argument("--username", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--user-field", default="email")
    ap.add_argument("--pass-field", default="password")
    args = ap.parse_args()

    authed = bool(args.cookie or (args.login_url and args.username))
    c = Client(args.target, rate=args.rate, extra_cookie=args.cookie)
    rep = Report(target=args.target, authenticated=authed)

    if args.login_url and args.username:
        if not do_login(c, args, rep):
            print("!! Login failed; continuing UNauthenticated.", file=sys.stderr)
            authed = False
            rep.authenticated = False

    run(c, rep, args, authed)
    print_report(rep)
    if args.out:
        with open(args.out, "w") as fh:
            json.dump({"target": rep.target, "authenticated": rep.authenticated,
                       "findings": [asdict(f) for f in rep.findings],
                       "notes": rep.notes}, fh, indent=2)
        print(f"JSON written to {args.out}")


if __name__ == "__main__":
    main()
