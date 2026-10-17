#!/usr/bin/env python3
"""
prodscan -- production-readiness black-box security scanner.

A generic, config-driven suite that validates whether a web application is
safe to ship. It probes a RUNNING app only (no source), reports evidence-
backed results, and ends with a GO / NO-GO verdict plus a scorecard.

AUTHORIZED USE ONLY. Point it at a NON-PRODUCTION instance you own.
It is rate-limited and avoids destructive actions and email sending unless
explicitly enabled; it only ever mutates throwaway accounts/objects it
creates itself.

Coverage (each check reports PASS / FAIL / WARN / INFO / SKIP):
  transport & security headers, TLS/HSTS, cookie flags, CORS, clickjacking,
  HTTP methods, verbose errors & debug/dotfile exposure, content discovery,
  info/version disclosure, reflected XSS, stored XSS, SQL injection, SSTI,
  open redirect, host-header injection, CSRF, read & write IDOR across two
  accounts, vertical privilege escalation, format-handler auth bypass, mass
  assignment, file upload, auth user-enumeration, login rate-limiting,
  password policy, session fixation, logout invalidation, password reset.

Usage:
  python3 prodscan.py --config targets/curb.json
  python3 prodscan.py --target http://localhost:3000        # zero-config
  python3 prodscan.py --config targets/curb.json --out-md report.md
"""

import argparse
import json
import re
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict

import bbscan  # reuse the hardened HTTP client / HTML parsing

# --------------------------------------------------------------------------- #
# Result model + report
# --------------------------------------------------------------------------- #

SEV = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
STATUS = ("FAIL", "WARN", "PASS", "INFO", "SKIP")


@dataclass
class Result:
    check: str
    category: str
    status: str          # FAIL | WARN | PASS | INFO | SKIP
    severity: str        # Critical | High | Medium | Low | Info
    title: str
    detail: str = ""
    remediation: str = ""
    confidence: str = "Confirmed"   # Confirmed | Suspected
    endpoint: str = ""


@dataclass
class Report:
    target: str
    results: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add(self, **kw):
        self.results.append(Result(**kw))

    def note(self, s):
        self.notes.append(s)
        print(f"   · {s}")

    # --- verdict -----------------------------------------------------------
    def verdict(self):
        fails = [r for r in self.results if r.status == "FAIL"]
        blockers = [r for r in fails if r.severity in ("Critical", "High")]
        mediums = [r for r in fails if r.severity == "Medium"]
        if blockers:
            return "NO-GO", blockers
        if mediums:
            return "CONDITIONAL", mediums
        return "GO", []

    def summary(self):
        by = {s: 0 for s in STATUS}
        for r in self.results:
            by[r.status] = by.get(r.status, 0) + 1
        return by

    # --- renderers ---------------------------------------------------------
    def to_console(self):
        self.results.sort(key=lambda r: (STATUS.index(r.status)
                                         if r.status in STATUS else 9,
                                         SEV.get(r.severity, 9)))
        print("\n" + "=" * 80)
        print(f"PRODUCTION-READINESS REPORT   {self.target}")
        print("=" * 80)
        verdict, blockers = self.verdict()
        by = self.summary()
        print(f"VERDICT: {verdict}    "
              f"FAIL={by['FAIL']} WARN={by['WARN']} PASS={by['PASS']} "
              f"INFO={by['INFO']} SKIP={by['SKIP']}")
        if blockers:
            print("Blockers:")
            for b in blockers:
                print(f"  - [{b.severity}] {b.title}")
        print("-" * 80)
        for r in self.results:
            if r.status in ("PASS", "SKIP", "INFO"):
                continue
            print(f"\n[{r.status}/{r.severity}] ({r.confidence}) {r.title}")
            print(f"  check    : {r.category}/{r.check}")
            if r.endpoint:
                print(f"  endpoint : {r.endpoint}")
            if r.detail:
                print(f"  evidence : {r.detail}")
            if r.remediation:
                print(f"  fix      : {r.remediation}")
        print("\n--- PASS / INFO / SKIP (condensed) ---")
        for r in self.results:
            if r.status in ("PASS", "INFO", "SKIP"):
                print(f"  {r.status:4} {r.category}/{r.check}: {r.title}")
        if self.notes:
            print("\n--- recon notes ---")
            for n in self.notes:
                print(f"  · {n}")
        print("=" * 80)

    def to_markdown(self):
        verdict, blockers = self.verdict()
        by = self.summary()
        out = [f"# Production-readiness report — {self.target}", "",
               f"**Verdict: {verdict}**  ",
               f"FAIL {by['FAIL']} · WARN {by['WARN']} · PASS {by['PASS']} · "
               f"INFO {by['INFO']} · SKIP {by['SKIP']}", ""]
        if blockers:
            out += ["## Blockers (must fix before production)", ""]
            for b in blockers:
                out.append(f"- **[{b.severity}] {b.title}** — {b.detail}")
            out.append("")
        out += ["## All findings (FAIL / WARN)", "",
                "| Status | Sev | Category | Title | Evidence | Fix |",
                "|---|---|---|---|---|---|"]
        for r in sorted(self.results, key=lambda r: (STATUS.index(r.status)
                        if r.status in STATUS else 9, SEV.get(r.severity, 9))):
            if r.status in ("PASS", "INFO", "SKIP"):
                continue
            esc = lambda s: (s or "").replace("|", "\\|").replace("\n", " ")[:300]
            out.append(f"| {r.status} | {r.severity} | {r.category}/{r.check} "
                       f"| {esc(r.title)} | {esc(r.detail)} | {esc(r.remediation)} |")
        out += ["", "## Passed / informational", ""]
        for r in self.results:
            if r.status in ("PASS", "INFO", "SKIP"):
                out.append(f"- `{r.status}` {r.category}/{r.check}: {r.title}")
        if self.notes:
            out += ["", "## Recon notes", ""] + [f"- {n}" for n in self.notes]
        return "\n".join(out) + "\n"

    def to_json(self):
        v, _ = self.verdict()
        return json.dumps({"target": self.target, "verdict": v,
                           "summary": self.summary(),
                           "results": [asdict(r) for r in self.results],
                           "notes": self.notes}, indent=2)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def meta_token(body):
    m = re.search(r'<meta name="csrf-token" content="([^"]+)"', body or "")
    return m.group(1) if m else None


def form_token(body):
    m = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', body or "")
    return m.group(1) if m else None


THROTTLE_RE = re.compile(r"try again later|too many|rate.?limit|throttl", re.I)

# Known client-side libraries we can fingerprint from asset names / JS content.
# token: substring found in importmap key or asset filename.
# npm: package name to query against the vuln DB (OSV, npm ecosystem).
# vregex: patterns to pull a version out of the fetched JS.
LIB_SIGNATURES = [
    {"token": "turbo", "npm": "@hotwired/turbo",
     "vregex": [r"Turbo[^0-9]{0,25}(\d+\.\d+\.\d+)"]},
    {"token": "stimulus", "npm": "@hotwired/stimulus",
     "vregex": [r"[Ss]timulus[^0-9]{0,25}(\d+\.\d+\.\d+)",
                r"version\s*[:=]\s*[\"'](\d+\.\d+\.\d+)"]},
    {"token": "jquery", "npm": "jquery",
     "vregex": [r"jQuery\s+v?(\d+\.\d+\.\d+)", r"jquery[@/-]v?(\d+\.\d+\.\d+)"]},
    {"token": "bootstrap", "npm": "bootstrap",
     "vregex": [r"Bootstrap\s+v?(\d+\.\d+\.\d+)", r"bootstrap[@/-]v?(\d+\.\d+\.\d+)"]},
    {"token": "lodash", "npm": "lodash",
     "vregex": [r"lodash[@/ ]v?(\d+\.\d+\.\d+)", r"VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)"]},
    {"token": "react-dom", "npm": "react-dom",
     "vregex": [r"react-dom[^0-9]{0,30}(\d+\.\d+\.\d+)"]},
    {"token": "react", "npm": "react",
     "vregex": [r"react\.(?:production|development)[^0-9]{0,30}(\d+\.\d+\.\d+)"]},
    {"token": "vue", "npm": "vue",
     "vregex": [r"Vue[^0-9]{0,20}v?(\d+\.\d+\.\d+)"]},
    {"token": "axios", "npm": "axios",
     "vregex": [r"axios[@/ ]v?(\d+\.\d+\.\d+)"]},
    {"token": "moment", "npm": "moment",
     "vregex": [r"version\s*[:=]\s*[\"'](\d+\.\d+\.\d+)"]},
    {"token": "d3", "npm": "d3", "vregex": [r"d3[^0-9]{0,15}v?(\d+\.\d+\.\d+)"]},
]

GENERIC_VREGEX = [r"[Vv]ersion\s*[:=]\s*[\"'](\d+\.\d+\.\d+)[\"']",
                  r"/\*!?[^*]{0,40}?v(\d+\.\d+\.\d+)"]


def osv_query(name, version, ecosystem="npm", timeout=8):
    """Query OSV.dev for known vulnerabilities in name@version. Returns a list
    of advisory dicts (id/summary/severity), or [] (incl. on any error)."""
    try:
        body = json.dumps({"version": version,
                           "package": {"name": name, "ecosystem": ecosystem}}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        out = []
        for v in data.get("vulns", []):
            sev = ""
            for s in v.get("severity", []):
                sev = s.get("score", "") or sev
            out.append({"id": v.get("id", "?"),
                        "summary": (v.get("summary") or "")[:120],
                        "severity": sev,
                        "aliases": v.get("aliases", [])})
        return out
    except Exception:  # noqa: BLE001  -- offline / API error: no data, not a failure
        return None


def around(body, marker, span=70):
    i = (body or "").find(marker)
    return body[max(0, i - span):i + span] if i >= 0 else ""


def is_local_url(url):
    h = (urllib.parse.urlparse(url).hostname or "").lower()
    return (h in {"localhost", "127.0.0.1", "::1"}
            or h.endswith(".localhost") or h.endswith(".test"))


# PASSIVE profile = read-only checks safe to run against a non-local target:
# no account creation, no payload injection, no mutation, no brute-force.
SAFE_CHECKS = {"check_headers", "check_cookies", "check_cors", "check_methods",
               "check_error_exposure", "check_content_discovery",
               "check_dependencies", "check_csrf"}


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["base_url"].rstrip("/")
        self.rate = cfg.get("rate", 5)
        self.rep = Report(self.base)
        self.csrf_header = cfg.get("auth", {}).get("csrf_header", "X-CSRF-Token")
        self.A = None   # authenticated client (account A)
        self.B = None   # second account (for cross-account tests)
        self.inv = {"pages": set(), "forms": [], "param_eps": {},
                    "id_paths": set(), "json_eps": set()}
        self._cve_specs = []   # populated by check_dependencies for pocgen

    # -- client / auth ------------------------------------------------------
    def client(self):
        return bbscan.Client(self.base, rate=self.rate)

    def authed(self, c):
        chk = self.cfg.get("auth", {}).get("authed_check")
        cands = ([chk] if chk else []) + ["/account", "/dashboard", "/profile",
                                          "/settings", "/me", "/home"]
        for p in cands:
            if not p:
                continue
            r = c.get(p)
            if r.status == 200 and not re.search(r'type="password"', r.body or ""):
                return True
        h = c.get("/").body or ""
        return bool(re.search(r'sign out|log ?out|/sign_out|/session["\']?\s*,?\s*'
                              r'["\']?delete|data-method="delete"', h, re.I))

    def _meta(self, c):
        """A usable global CSRF meta-token from any page (per-form tokens need
        the header path; the meta token works for all authed POSTs)."""
        for p in (self.cfg.get("auth", {}).get("register", {}).get("form_page"),
                  "/account", "/"):
            if not p:
                continue
            t = meta_token(c.get(p).body)
            if t:
                return t
        return None

    def apost(self, c, path, data, token_page=None):
        """Authenticated POST using the CSRF meta-token via header."""
        tok = meta_token(c.get(token_page).body) if token_page else None
        tok = tok or self._meta(c)
        return c.post(path, data=data,
                      headers={self.csrf_header: tok} if tok else None)

    # -- auto-discovery (config-free scanning from just a URL) --------------
    SIGNUP_PATHS = ["/sign_up", "/signup", "/register", "/registration/new",
                    "/registrations/new", "/users/new", "/users/sign_up",
                    "/accounts/new", "/account/new", "/join", "/auth/register",
                    "/users/register", "/signup/new"]
    LOGIN_PATHS = ["/login", "/sign_in", "/signin", "/session/new",
                   "/sessions/new", "/users/sign_in", "/auth/login", "/users/login"]

    def _discover_form(self, paths, kind):
        """Find a signup/login form by probing common paths; map its fields to
        __EMAIL__ / __PASSWORD__ and fill the rest with safe defaults."""
        c = self.client()
        for p in paths:
            r = c.get(p)
            if r.status != 200 or "__ERROR__" in r.body:
                continue
            _, forms = bbscan.parse_page(r.body)
            for f in forms:
                if f["method"] != "post":
                    continue
                inp = f["inputs"]
                if not any(i.get("type") == "password" and i.get("name") for i in inp):
                    continue
                email = next((i.get("name") for i in inp if i.get("name")
                              and re.search(r'email|login|username', i["name"], re.I)), None)
                if not email:
                    continue
                fields = {}
                for i in inp:
                    n, t = i.get("name"), i.get("type", "text")
                    if not n or n == "authenticity_token":
                        continue
                    if t == "password":
                        fields[n] = "__PASSWORD__"
                    elif n == email:
                        fields[n] = "__EMAIL__"
                    elif t == "submit" or re.search(r'commit', n, re.I):
                        fields[n] = i.get("value") or "Submit"
                    elif t in ("hidden", "text", "email", "tel", "number", "textarea", ""):
                        fields[n] = i.get("value") or "Test"
                    elif t == "checkbox":
                        fields[n] = "1"
                return {"form_page": p, "action": f["action"] or p, "fields": fields}
        return None

    def autodiscover_auth(self):
        reg = self._discover_form(self.SIGNUP_PATHS, "register")
        login = self._discover_form(self.LOGIN_PATHS, "login")
        if not (reg and login):
            self.rep.note("Auto-discovery: no signup/login form found — running "
                          "unauthenticated (point at a config for the full suite).")
            return
        self.cfg.setdefault("auth", {})
        self.cfg["auth"].setdefault("csrf_header", "X-CSRF-Token")
        self.cfg["auth"]["register"] = reg
        self.cfg["auth"]["login"] = login
        self.rep.note(f"Auto-discovered auth: signup {reg['action']}, "
                      f"login {login['action']}.")

    def autodiscover_targets(self):
        """From the authenticated crawl, derive owned-object create flows,
        a profile-update form, and a file-upload form."""
        reg_a = self.cfg.get("auth", {}).get("register", {}).get("action")
        login_a = self.cfg.get("auth", {}).get("login", {}).get("action")
        owned, seen = [], set()
        for f in self.inv["forms"]:
            act = f.get("action")
            if (not act or f.get("method") != "post" or act in (reg_a, login_a)
                    or act in seen or "search" in act or "session" in act):
                continue
            if any(i.get("type") == "password" for i in f["inputs"]):
                continue
            if any(i.get("name") == "_method" for i in f["inputs"]):
                continue  # update/delete form, not a create
            textf = next((i.get("name") for i in f["inputs"] if i.get("name")
                          and i.get("type", "text") in ("text", "textarea", "")), None)
            if not textf:
                continue
            seen.add(act)
            fields = {}
            for i in f["inputs"]:
                n, t = i.get("name"), i.get("type", "text")
                if not n or n == "authenticity_token":
                    continue
                fields[n] = ("__MARK__" if n == textf else
                             (i.get("value") or "Create") if (t == "submit" or
                              re.search(r'commit', n, re.I)) else
                             "1" if t == "checkbox" else (i.get("value") or "test"))
            base = act.rstrip("/")
            owned.append({"name": re.sub(r'[^a-z]', '', base.split("/")[-1].lower()) or "obj",
                          "action": act, "token_page": act, "fields": fields,
                          "list_page": act, "id_regex": re.escape(base) + r"/(\d+)",
                          "item_url": base + "/{id}"})
            if len(owned) >= 3:
                break
        if owned:
            self.cfg["owned_objects"] = owned
            o = owned[0]
            sx = {k: ("__PAYLOAD__" if v == "__MARK__" else v) for k, v in o["fields"].items()}
            self.cfg["stored_xss_fields"] = [{"action": o["action"],
                                              "token_page": o["token_page"],
                                              "view": o["list_page"], "fields": sx}]
        # profile-update form (has _method) -> mass assignment
        for f in self.inv["forms"]:
            if f.get("action") and any(i.get("name") == "_method" for i in f["inputs"]):
                bf = {i["name"]: (i.get("value") or "Test") for i in f["inputs"]
                      if i.get("name") and i["name"] not in ("authenticity_token", "_method")
                      and i.get("type") not in ("password", "submit", "file")}
                self.cfg["mass_assignment"] = {"action": f["action"],
                                               "token_page": f["action"], "base_fields": bf}
                break
        # file-upload form
        for f in self.inv["forms"]:
            ff = next((i.get("name") for i in f["inputs"] if i.get("type") == "file"), None)
            if ff and f.get("action"):
                of = {i["name"]: (i.get("value") or "test") for i in f["inputs"]
                      if i.get("name") and i.get("type") in ("text", "hidden", "textarea", "")}
                self.cfg["file_upload"] = {"action": f["action"], "token_page": f["action"],
                                           "file_field": ff, "fields": of}
                break
        found = [k for k in ("owned_objects", "mass_assignment", "file_upload")
                 if self.cfg.get(k)]
        if found:
            self.rep.note("Auto-discovered targets: " + ", ".join(found) + ".")

    def register(self, email, pw):
        reg = self.cfg.get("auth", {}).get("register")
        if not reg:
            return None
        c = self.client()
        tok = form_token(c.get(reg["form_page"]).body)
        data = {}
        for k, v in reg["fields"].items():
            data[k] = (email if v == "__EMAIL__" else
                       pw if v == "__PASSWORD__" else v)
        data.setdefault("authenticity_token", tok or "")
        r = c.post(reg["action"], data=data)
        return c if (r.status in (302, 303) or self.authed(c)) else None

    def login_result(self, c, email, pw):
        """Return ('ok'|'bad'|'throttled', client). Distinguishes a wrong-creds
        failure from IP rate-limiting (302 + 'Try again later' flash, not 429)."""
        lg = self.cfg.get("auth", {}).get("login")
        if not lg:
            return "nocfg", c
        tok = form_token(c.get(lg["form_page"]).body)
        data = {}
        for k, v in lg["fields"].items():
            data[k] = (email if v == "__EMAIL__" else
                       pw if v == "__PASSWORD__" else v)
        data.setdefault("authenticity_token", tok or "")
        r = c.post(lg["action"], data=data)
        if self.authed(c):
            return "ok", c
        flash = c.get(lg["form_page"]).body
        if r.status == 429 or THROTTLE_RE.search(flash or ""):
            return "throttled", c
        return "bad", c

    def login(self, email, pw):
        if not self.cfg.get("auth", {}).get("login"):
            return None
        status, c = self.login_result(self.client(), email, pw)
        return c if status == "ok" else None

    def setup_accounts(self):
        if not self.cfg.get("auth", {}).get("register"):
            self.rep.note("No auth config: running unauthenticated only.")
            return
        ts = int(time.time())
        pwd = "Ps!" + secrets.token_urlsafe(14)
        ea = f"prodscan_a_{ts}@example.com"
        eb = f"prodscan_b_{ts}@example.com"
        self.A = self.register(ea, pwd)
        self.B = self.register(eb, pwd)
        self._creds = {"A": (ea, pwd), "B": (eb, pwd)}
        self.rep.note(f"Accounts: A={'ok' if self.A else 'FAILED'} "
                      f"B={'ok' if self.B else 'FAILED'} (throwaway).")

    # -- mapping ------------------------------------------------------------
    def map_surface(self):
        c = self.A or self.client()
        seen, queue = set(), ["/"]
        maxp = self.cfg.get("max_pages", 80)

        def note(path):
            base = path.split("?")[0]
            if re.search(r"/\d+(?:/|$)", base):
                self.inv["id_paths"].add(base)
            if base.endswith(".json"):
                self.inv["json_eps"].add(base)
            if "?" in path:
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(path).query))
                if q:
                    self.inv["param_eps"].setdefault(base, q)

        while queue and len(seen) < maxp:
            p = queue.pop(0).split("?")[0]
            if p in seen:
                continue
            seen.add(p)
            r, chain = c.get_follow(p)
            for cp, _ in chain:
                note(cp)
            if "__ERROR__" in r.body or not r.body:
                continue
            links, forms = bbscan.parse_page(r.body)
            self.inv["forms"].extend(forms)
            for f in forms:
                if f["method"] == "get" and f["action"]:
                    params = {i["name"]: (i.get("value") or "test")
                              for i in f["inputs"] if i.get("name")}
                    if params:
                        self.inv["param_eps"].setdefault(
                            f["action"].split("?")[0], params)
            for href in links:
                if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                    continue
                u = urllib.parse.urljoin(c.base + p, href)
                if not u.startswith(c.base):
                    continue
                path = u[len(c.base):] or "/"
                note(path)
                b = path.split("?")[0]
                if b not in seen and b not in queue:
                    queue.append(b)
        self.inv["pages"] = seen
        self.rep.note(f"Mapped {len(seen)} paths, {len(self.inv['forms'])} forms, "
                      f"{len(self.inv['param_eps'])} param-endpoints, "
                      f"{len(self.inv['id_paths'])} id-paths, "
                      f"{len(self.inv['json_eps'])} json-endpoints.")

    # ===================================================================== #
    # CHECKS
    # ===================================================================== #

    def check_headers(self):
        r = self.A.get("/") if self.A else self.client().get("/")
        h = r.headers
        https = self.base.startswith("https://")
        reqd = [
            ("content-security-policy", "Medium",
             "No Content-Security-Policy. Add a restrictive CSP (defense-in-depth)."),
            ("x-content-type-options", "Low",
             "Missing X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Low", "Missing Referrer-Policy."),
        ]
        for key, sev, fix in reqd:
            if key in h:
                self.rep.add(check=key, category="headers", status="PASS",
                             severity="Info", title=f"{key} present",
                             detail=h.get(key, "")[:120])
            else:
                self.rep.add(check=key, category="headers", status="FAIL",
                             severity=sev, title=f"Missing header: {key}",
                             endpoint="/", detail=f"Present: {sorted(h)}",
                             remediation=fix)
        # clickjacking
        if "x-frame-options" in h or "frame-ancestors" in h.get(
                "content-security-policy", ""):
            self.rep.add(check="clickjacking", category="headers", status="PASS",
                         severity="Info", title="Framing protection present")
        else:
            self.rep.add(check="clickjacking", category="headers", status="FAIL",
                         severity="Medium", title="No clickjacking protection",
                         endpoint="/", remediation="Set X-Frame-Options: DENY "
                         "or CSP frame-ancestors 'none'.")
        # HSTS (https only)
        if https:
            if "strict-transport-security" in h:
                self.rep.add(check="hsts", category="headers", status="PASS",
                             severity="Info", title="HSTS present")
            else:
                self.rep.add(check="hsts", category="headers", status="FAIL",
                             severity="Medium", title="Missing HSTS over HTTPS",
                             remediation="Set config.force_ssl = true.")
        else:
            self.rep.add(check="tls", category="headers", status="WARN",
                         severity="Low", title="Target is plain HTTP",
                         detail="TLS/HSTS not assessed; production must use HTTPS.",
                         remediation="Serve over HTTPS with HSTS in production.")
        # banner leakage
        for k in ("server", "x-powered-by"):
            if h.get(k):
                self.rep.add(check=f"banner-{k}", category="headers",
                             status="WARN", severity="Low",
                             title=f"Version/banner disclosure: {k}",
                             detail=f"{k}: {h.get(k)}",
                             remediation="Suppress server/framework banners.")

    def check_cookies(self):
        r = self.client().get(self.cfg.get("auth", {}).get("login", {})
                              .get("form_page", "/"))
        # also take a logged-in request to capture session cookie flags
        jar = self.A.cj if self.A else None
        raw = r.headers.get("set-cookie", "")
        https = self.base.startswith("https://")
        checked = False
        for cookie in re.split(r",(?=[^ ;=]+=)", raw):
            if "=" not in cookie:
                continue
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            if "session" not in name.lower() and "csrf" not in name.lower():
                continue
            checked = True
            missing = [flag for flag, tok in
                       (("HttpOnly", "httponly"), ("SameSite", "samesite"))
                       if tok not in low]
            if https and "secure" not in low:
                missing.append("Secure")
            if missing:
                self.rep.add(check="cookie-flags", category="cookies",
                             status="FAIL", severity="Medium",
                             title=f"Cookie '{name}' missing {', '.join(missing)}",
                             detail=cookie.strip()[:160],
                             remediation="Set HttpOnly, SameSite, and Secure "
                             "(HTTPS) on session/CSRF cookies.")
            else:
                self.rep.add(check="cookie-flags", category="cookies",
                             status="PASS", severity="Info",
                             title=f"Cookie '{name}' well-flagged")
        if not checked:
            self.rep.add(check="cookie-flags", category="cookies", status="INFO",
                         severity="Info", title="No session cookie on probed page")

    def check_cors(self):
        evil = "https://evil.example.com"
        r = (self.A or self.client()).get("/")  # with Origin
        r = (self.A or self.client()).req("GET", "/", headers={"Origin": evil})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == evil or acao == "*":
            sev = "High" if (acao == evil and acac.lower() == "true") else "Medium"
            self.rep.add(check="cors", category="cors", status="FAIL", severity=sev,
                         title="Permissive CORS policy", endpoint="/",
                         detail=f"Origin {evil} -> ACAO={acao!r} "
                                f"Allow-Credentials={acac!r}",
                         remediation="Reflect only allow-listed origins; never "
                         "combine ACAO:* or reflected origin with credentials.")
        else:
            self.rep.add(check="cors", category="cors", status="PASS",
                         severity="Info", title="No reflected/permissive CORS",
                         detail=f"ACAO={acao!r}")

    def check_methods(self):
        r = (self.A or self.client()).req("OPTIONS", "/")
        allow = r.headers.get("allow", "")
        if "TRACE" in allow.upper():
            self.rep.add(check="trace", category="methods", status="FAIL",
                         severity="Low", title="HTTP TRACE enabled",
                         detail=f"Allow: {allow}", remediation="Disable TRACE.")
        else:
            self.rep.add(check="methods", category="methods", status="INFO",
                         severity="Info", title="HTTP methods",
                         detail=f"OPTIONS Allow: {allow or '(none)'}")

    def check_error_exposure(self):
        r = (self.A or self.client()).get("/nope-%d" % int(time.time()))
        verbose = bool(re.search(
            r"(Action Controller: Exception caught|Extracted source \(around|"
            r"Full backtrace|activerecord \(\d|actionpack \(\d)", r.body))
        if verbose:
            self.rep.add(check="verbose-errors", category="errors", status="FAIL",
                         severity="Medium", title="Verbose error page exposed",
                         confidence="Confirmed", endpoint=r.url,
                         detail="Rails dev/exception page with backtrace served.",
                         remediation="In production set consider_all_requests_local "
                         "= false and serve generic error pages. (If this run is a "
                         "dev instance, re-verify against production config.)")
        else:
            self.rep.add(check="verbose-errors", category="errors", status="PASS",
                         severity="Info", title="No verbose error page")
        exposed = {
            "/.env": "High", "/.git/config": "High", "/config/database.yml": "High",
            "/config/secrets.yml": "High", "/rails/info/routes": "Medium",
            "/rails/info/properties": "Medium", "/sidekiq": "Medium",
            "/phpinfo.php": "Low", "/server-status": "Medium",
            "/.DS_Store": "Low", "/backup.zip": "Medium", "/db.sqlite3": "High",
        }
        c = self.client()
        for p, sev in exposed.items():
            r = c.get(p)
            if r.status == 200 and "__ERROR__" not in r.body and len(r.body) > 0:
                dev_only = p.startswith("/rails/info")
                self.rep.add(check="exposed-path", category="errors",
                             status="WARN" if dev_only else "FAIL", severity=sev,
                             title=f"Sensitive path reachable: {p}",
                             endpoint=p, detail=f"GET {p} -> 200 ({len(r.body)}B)"
                             + (" [dev-only route]" if dev_only else ""),
                             remediation="Block access to this path at the app/web "
                             "server; never deploy with it reachable.")

    def check_content_discovery(self):
        words = ["admin", "api", "api/v1", "debug", "status", "metrics",
                 "graphql", "swagger", "openapi.json", "robots.txt",
                 "sitemap.xml", "uploads", "download", "export"]
        c = self.client()
        found = []
        for w in words:
            r = c.get("/" + w)
            if r.status in (200, 301, 302) and "__ERROR__" not in r.body:
                found.append(f"/{w}({r.status})")
        self.rep.add(check="content-discovery", category="discovery",
                     status="INFO", severity="Info",
                     title="Reachable common paths",
                     detail=", ".join(found) or "none of the probed words")

    def check_dependencies(self):
        """Fingerprint client-side libraries from the importmap / asset URLs /
        JS content, then (optionally) match versions to known CVEs via OSV."""
        c = self.A or self.client()
        home = c.get_follow("/")[0].body            # follow auth redirect
        if '<script type="importmap"' not in home:  # fall back to public homepage
            home = self.client().get_follow("/")[0].body
        im = re.search(r'<script type="importmap"[^>]*>(.*?)</script>', home, re.S)
        imports = {}
        if im:
            try:
                imports = json.loads(im.group(1)).get("imports", {})
            except Exception:  # noqa: BLE001
                imports = {}
        refs = list(imports.items())
        refs += [(u, u) for u in re.findall(r'<script[^>]+src="([^"]+)"', home)]
        refs += [(u, u) for u in re.findall(r'<link[^>]+href="([^"]+\.js[^"]*)"', home)]

        def lib_name(key, url):
            """Clean name for token matching: importmap key as-is, else the
            filename with its content digest and extension stripped (so a short
            token like 'd3' can't collide with a hex digest in the hash)."""
            if key != url:
                return key.lower()
            base = url.split("?")[0].rsplit("/", 1)[-1]
            base = re.sub(r"-[0-9a-f]{7,}(?=\.)", "", base)   # strip -<digest>
            base = re.sub(r"\.(min\.)?(js|css)$", "", base)
            return base.lower()

        named = [(lib_name(k, u), u) for k, u in refs]
        inventory = []
        for sig in LIB_SIGNATURES:
            url = next((u for name, u in named if sig["token"] in name), None)
            if not url:
                continue
            body = c.get(url).body if url.startswith(("/", "http")) else ""
            version = None
            for pat in sig["vregex"] + GENERIC_VREGEX:
                m = re.search(pat, body)
                if m:
                    version = m.group(1)
                    break
            inventory.append((sig["npm"], version, url))
            if version and self.cfg.get("cve_lookup", True):
                vulns = osv_query(sig["npm"], version)
                if vulns is None:
                    self.rep.note(f"CVE lookup unavailable for {sig['npm']}@{version} "
                                  "(OSV unreachable).")
                elif vulns:
                    ids = ", ".join((v["id"] + (f"[{v['severity']}]" if v["severity"]
                                    else "")) for v in vulns[:6])
                    self.rep.add(check="dependency-cve", category="dependencies",
                                 status="FAIL", severity="High",
                                 title=f"Known-vulnerable library: {sig['npm']}@{version}",
                                 endpoint=url,
                                 detail=f"{len(vulns)} OSV advisory(ies): {ids}",
                                 remediation=f"Upgrade {sig['npm']} past the affected "
                                 "range (see the referenced advisories).")
                    for v in vulns:
                        self._cve_specs.append(
                            {"library": sig["npm"], "version": version,
                             "endpoint": url, "advisory_id": v["id"],
                             "advisory_summary": v["summary"],
                             "aliases": tuple(v.get("aliases", []))})
                else:
                    self.rep.add(check="dependency-cve", category="dependencies",
                                 status="PASS", severity="Info",
                                 title=f"No known CVEs: {sig['npm']}@{version}",
                                 endpoint=url)
        inv = ", ".join(f"{n}@{v or '?'}" for n, v, _ in inventory) or "none recognized"
        self.rep.add(check="inventory", category="dependencies", status="INFO",
                     severity="Info", title=f"Client-side library inventory: {inv}",
                     detail=f"{len(inventory)} fingerprinted; "
                            f"importmap imports={len(imports)}; "
                            f"cve_lookup={'on' if self.cfg.get('cve_lookup', True) else 'off'}")

    def check_reflected_xss(self):
        marker = "pxss" + str(int(time.time()))
        probe = f"<{marker}>"
        targets = dict(self.inv["param_eps"])
        targets.setdefault("/", {"q": "x"})
        targets.setdefault("/search", {"q": "x"})
        c = self.A or self.client()
        tested = found = 0
        for base, params in list(targets.items())[:20]:
            for pn in (list(params.keys()) or ["q"]):
                q = dict(params)
                q[pn] = probe
                url = base + "?" + urllib.parse.urlencode(q)
                r = c.get(url)
                tested += 1
                if probe in r.body:
                    found += 1
                    self.rep.add(check="reflected-xss", category="xss",
                                 status="FAIL", severity="High",
                                 title="Reflected XSS (unescaped reflection)",
                                 endpoint=url,
                                 detail=f"{pn}={probe!r} reflected verbatim: "
                                        f"{around(r.body, marker)!r}",
                                 remediation="Escape output (ERB <%= %> escapes by "
                                 "default); avoid raw/html_safe on user input.")
                    break
            if found:
                break
        if not found:
            self.rep.add(check="reflected-xss", category="xss", status="PASS",
                         severity="Info",
                         title=f"No reflected XSS ({tested} combos; reflections escaped)")

    def check_stored_xss(self):
        """Submit a marker through each POST form, then re-crawl to see if it
        renders unescaped anywhere. Requires auth + writes."""
        if not (self.A and self.cfg.get("allow_writes", True)):
            self.rep.add(check="stored-xss", category="xss", status="SKIP",
                         severity="Info", title="Stored XSS not run (needs auth/writes)")
            return
        flows = self.cfg.get("stored_xss_fields", [])
        if not flows:
            self.rep.add(check="stored-xss", category="xss", status="SKIP",
                         severity="Info",
                         title="Stored XSS skipped (no stored_xss_fields configured)")
            return
        marker = "sxss" + str(int(time.time()))
        probe = f"<b id={marker}>x</b>"
        for fl in flows:
            data = dict(fl.get("fields", {}))
            for k, v in data.items():
                if v == "__PAYLOAD__":
                    data[k] = probe
            self.apost(self.A, fl["action"], data, fl.get("token_page", "/"))
        # re-crawl discovered pages looking for the unescaped marker
        c = self.A
        hit = None
        for p in list(self.inv["pages"])[:60] + [fl.get("view", "/") for fl in flows]:
            r = c.get(p)
            if probe in r.body:
                hit = p
                break
        if hit:
            self.rep.add(check="stored-xss", category="xss", status="FAIL",
                         severity="Critical", title="Stored XSS",
                         endpoint=hit,
                         detail=f"Payload {probe!r} rendered unescaped at {hit}.",
                         remediation="Escape stored content on output; never render "
                         "user input with raw/html_safe.")
        else:
            self.rep.add(check="stored-xss", category="xss", status="PASS",
                         severity="Info",
                         title="No stored XSS in tested fields (payload escaped)")

    def check_sqli(self):
        idish = {"id", "page", "p", "user_id", "sort", "order", "offset", "limit"}
        cands = []
        for base, params in self.inv["param_eps"].items():
            for pn, pv in params.items():
                if (re.fullmatch(r"\d+", str(pv)) or pn.lower() in idish
                        or pn.lower().endswith("_id")):
                    cands.append((base, params, pn))
        if not cands:
            cands = [("/", {"id": "1"}, "id")]
        c = self.A or self.client()
        found = 0
        for base, params, pn in cands[:10]:
            def build(val):
                q = dict(params)
                q[pn] = val
                return base + "?" + urllib.parse.urlencode(q)
            orig = str(params.get(pn, "1"))
            rb = c.get(build(orig))
            rt = c.get(build(orig + " OR 1=1-- -"))
            rf = c.get(build(orig + " AND 1=2-- -"))
            sig = []
            if (rb.status and len(rt.body) != len(rf.body)
                    and abs(len(rt.body) - len(rb.body)) < abs(len(rf.body) - len(rb.body))):
                sig.append("boolean differential")
            if rb.elapsed < 2.0:
                for lbl, pl in (("pg_sleep", f"{orig});SELECT pg_sleep(4)-- -"),
                                ("SLEEP", f"{orig} AND SLEEP(4)-- -")):
                    if c.get(build(pl)).elapsed > 3.5:
                        sig.append(f"time-based {lbl}")
                        break
            if sig:
                found += 1
                self.rep.add(check="sqli", category="injection", status="FAIL",
                             severity="Critical", confidence="Suspected",
                             title=f"Possible SQL injection ({pn} on {base})",
                             endpoint=f"{base}?{pn}=", detail="; ".join(sig),
                             remediation="Use parameterized ActiveRecord queries; "
                             "never interpolate params into SQL / order / find_by_sql.")
        if not found:
            self.rep.add(check="sqli", category="injection", status="PASS",
                         severity="Info",
                         title=f"No SQLi signal ({len(cands[:10])} params tested)")

    def check_ssti(self):
        """Marker-anchored SSTI: only flag when the arithmetic evaluates
        BETWEEN our unique markers, so incidental numbers can't trigger it."""
        targets = dict(self.inv["param_eps"])
        targets.setdefault("/search", {"q": "x"})
        c = self.A or self.client()
        mk = "ss" + str(int(time.time()))
        tested = 0
        for base, params in list(targets.items())[:10]:
            pn = list(params.keys())[0] if params else "q"
            # 1) does this param reflect at all? if not, SSTI here is untestable
            refl = dict(params)
            refl[pn] = mk
            if mk not in c.get(base + "?" + urllib.parse.urlencode(refl)).body:
                continue
            tested += 1
            want = f"{mk}49{mk}"
            for tmpl in (f"{mk}{{{{7*7}}}}{mk}", f"{mk}<%=7*7%>{mk}",
                         f"{mk}#{{7*7}}{mk}", f"{mk}${{7*7}}{mk}"):
                q = dict(params)
                q[pn] = tmpl
                r = c.get(base + "?" + urllib.parse.urlencode(q))
                if want in r.body:
                    self.rep.add(check="ssti", category="injection", status="FAIL",
                                 severity="Critical", confidence="Confirmed",
                                 title="Server-side template injection",
                                 endpoint=base,
                                 detail=f"{tmpl!r} evaluated to {want!r} in response",
                                 remediation="Never render user input as a template.")
                    return
        self.rep.add(check="ssti", category="injection", status="PASS",
                     severity="Info",
                     title=f"No SSTI ({tested} reflected param(s) probed)")

    def check_open_redirect(self):
        ev = "https://evil.example.com/"
        c = self.A or self.client()
        params = ["return_to", "redirect", "redirect_to", "url", "next", "back",
                  "returnurl", "continue", "dest"]
        bases = ["/"] + [p for p in self.inv["param_eps"]]
        for base in bases[:10]:
            for pr in params:
                r = c.get(f"{base}?{pr}=" + urllib.parse.quote(ev))
                loc = r.headers.get("location", "")
                if r.status in (301, 302, 303, 307, 308) and loc.startswith(
                        "https://evil.example.com"):
                    self.rep.add(check="open-redirect", category="injection",
                                 status="FAIL", severity="Medium",
                                 title=f"Open redirect via {pr}",
                                 endpoint=f"{base}?{pr}=", detail=f"-> {loc}",
                                 remediation="Allow-list redirect targets / only "
                                 "permit relative paths.")
                    return
        self.rep.add(check="open-redirect", category="injection", status="PASS",
                     severity="Info", title="No open redirect on common params")

    def check_host_header(self):
        c = self.client()
        r = c.req("GET", "/", headers={"Host": "evil.example.com",
                                       "X-Forwarded-Host": "evil.example.com"})
        loc = r.headers.get("location", "")
        if "evil.example.com" in loc or "evil.example.com" in r.body[:2000]:
            self.rep.add(check="host-header", category="injection", status="FAIL",
                         severity="Medium", title="Host header injection reflected",
                         detail=f"Spoofed Host reflected in {'Location' if loc else 'body'}.",
                         remediation="Pin host via config.hosts / Host Authorization; "
                         "don't build URLs from the request Host.")
        else:
            self.rep.add(check="host-header", category="injection", status="PASS",
                         severity="Info", title="Host header not reflected")

    def check_csrf(self):
        bad = [f for f in self.inv["forms"]
               if f["method"] == "post"
               and not any(n and ("authenticity_token" in n or "csrf" in n)
                           for n in [i.get("name") for i in f["inputs"]])]
        if bad:
            self.rep.add(check="csrf", category="csrf", status="WARN",
                         severity="Medium", confidence="Suspected",
                         title=f"{len(bad)} POST form(s) without a CSRF token field",
                         detail="; ".join(sorted({f['action'] or '(self)'
                                                  for f in bad}))[:200],
                         remediation="Ensure protect_from_forgery is on and forms "
                         "embed the authenticity token.")
        else:
            self.rep.add(check="csrf", category="csrf", status="PASS",
                         severity="Info",
                         title="All discovered POST forms carry a CSRF token")

    # -- access control (needs 2 accounts + owned-object config) -----------
    def _create_owned(self, client, spec, marker):
        data = {}
        for k, v in spec["fields"].items():
            data[k] = marker if v == "__MARK__" else v
        r = self.apost(client, spec["action"], data,
                       spec.get("token_page", spec["action"]))
        loc = r.headers.get("location", "")
        m = re.search(spec["id_regex"], loc)
        if not m:
            lst = client.get(spec["list_page"]).body
            ids = re.findall(spec["id_regex"], lst)
            m = ids[-1] if ids else None
            oid = m
        else:
            oid = m.group(1)
        return oid, r

    def check_access_control(self):
        specs = self.cfg.get("owned_objects", [])
        if not (self.A and self.B and specs):
            self.rep.add(check="idor", category="access-control", status="SKIP",
                         severity="Info",
                         title="IDOR not run (needs 2 accounts + owned_objects config)")
            return
        for spec in specs:
            marker = "own" + str(int(time.time()))
            oid, cr = self._create_owned(self.A, spec, marker)
            if not oid:
                self.rep.add(check="idor", category="access-control", status="WARN",
                             severity="Info", title=f"Could not create {spec['name']} "
                             f"object (status {cr.status}); IDOR not tested",
                             detail=cr.headers.get("location", ""))
                continue
            item = spec["item_url"].format(id=oid)
            a_view = self.A.get(item)
            b_view = self.B.get(item)
            # read IDOR
            if b_view.status == 200 and (marker in b_view.body or
                                         len(b_view.body) > 0.8 * len(a_view.body)
                                         and a_view.status == 200
                                         and marker in a_view.body
                                         and marker in b_view.body):
                self.rep.add(check="idor-read", category="access-control",
                             status="FAIL", severity="High",
                             title=f"Read IDOR on {spec['name']} ({item})",
                             endpoint=item,
                             detail=f"Account B read account A's object "
                                    f"({item}) -> 200 with A's data.",
                             remediation="Scope lookups to current_user; return 404.")
            else:
                self.rep.add(check="idor-read", category="access-control",
                             status="PASS", severity="Info",
                             title=f"Read IDOR safe on {spec['name']}",
                             detail=f"B GET {item} -> {b_view.status} "
                                    f"(A sees it at 200).")
            # write IDOR (edit) -- only if edit fields provided; mutates throwaway obj
            if spec.get("edit_fields"):
                ed = dict(spec["edit_fields"])
                r = self.apost(self.B, item, {**ed, "_method": "patch"},
                               spec.get("token_page", item))
                re_view = self.A.get(item).body
                changed = any(str(v) in re_view for v in ed.values())
                if r.status in (200, 302) and changed:
                    self.rep.add(check="idor-write", category="access-control",
                                 status="FAIL", severity="High",
                                 title=f"Write IDOR on {spec['name']} ({item})",
                                 endpoint=item,
                                 detail="Account B modified account A's object.",
                                 remediation="Enforce object-level authorization on "
                                 "update/destroy, not just read.")
                else:
                    self.rep.add(check="idor-write", category="access-control",
                                 status="PASS", severity="Info",
                                 title=f"Write IDOR safe on {spec['name']}",
                                 detail=f"B PATCH {item} -> {r.status}, no change.")
            # mass assignment of owner field
            if spec.get("owner_field"):
                marker2 = "ma" + str(int(time.time()))
                data = {spec["owner_field"]: "1"}
                for k, v in spec["fields"].items():
                    data[k] = marker2 if v == "__MARK__" else v
                self.apost(self.A, spec["action"], data,
                           spec.get("token_page", spec["action"]))
                in_a = marker2 in self.A.get(spec["list_page"]).body
                self.rep.add(check="mass-assign-owner", category="access-control",
                             status="PASS" if in_a else "FAIL",
                             severity="Info" if in_a else "High",
                             title=f"Owner mass-assignment on {spec['name']}: "
                                   f"{'ignored (safe)' if in_a else 'possible'}",
                             detail=f"Injected {spec['owner_field']}=1; object "
                                    f"{'stayed with A' if in_a else 'left A list'}.",
                             remediation="" if in_a else "Exclude owner/user_id from "
                             "permitted params; set it from current_user server-side.")

    def check_vertical_privesc(self):
        admin_paths = self.cfg.get("admin_paths",
                                   ["/admin", "/admin/users", "/admin/dashboard"])
        if not self.A:
            self.rep.add(check="privesc", category="access-control", status="SKIP",
                         severity="Info", title="Vertical privesc not run (no account)")
            return
        hits = []
        for p in admin_paths:
            r = self.A.get(p)
            if r.status == 200 and len(r.body) > 200:
                hits.append(f"{p}(200)")
        if hits:
            self.rep.add(check="privesc", category="access-control", status="FAIL",
                         severity="High", confidence="Suspected",
                         title="Regular user reached admin path",
                         detail=", ".join(hits),
                         remediation="Require admin authorization on these routes.")
        else:
            self.rep.add(check="privesc", category="access-control", status="PASS",
                         severity="Info", title="Admin paths not reachable as normal user")

    def check_format_bypass(self):
        if not self.inv["id_paths"]:
            self.rep.add(check="format-bypass", category="access-control",
                         status="SKIP", severity="Info",
                         title="Format-handler bypass not run (no id paths)")
            return
        c = self.client()  # unauthenticated
        for base in list(self.inv["id_paths"])[:10]:
            auth_r = (self.A or c).get(base)
            un_html = c.get(base)
            un_json = c.get(base + ".json")
            if (un_html.status in (302, 401, 403) and un_json.status == 200
                    and len(un_json.body) > 50 and "__ERROR__" not in un_json.body):
                self.rep.add(check="format-bypass", category="access-control",
                             status="FAIL", severity="High", confidence="Suspected",
                             title=f"Auth bypass via .json on {base}",
                             endpoint=base + ".json",
                             detail=f"HTML {un_html.status} (gated) but .json 200 "
                                    f"unauthenticated.",
                             remediation="Apply the same authentication/authorization "
                             "to all response formats.")
                return
        self.rep.add(check="format-bypass", category="access-control", status="PASS",
                     severity="Info", title="No .json format auth bypass found")

    def check_mass_assignment(self):
        ma = self.cfg.get("mass_assignment")
        if not (self.A and ma):
            self.rep.add(check="mass-assign", category="mass-assignment",
                         status="SKIP", severity="Info",
                         title="Profile mass-assignment not run (needs config)")
            return
        ts = int(time.time())
        newmail = f"prodscan_ma_{ts}@example.com"
        extra = {"user[email_address]": newmail, "user[admin]": "true",
                 "user[role]": "admin", "user[verified]": "true"}
        data = {**ma.get("base_fields", {}), **extra, "_method": "patch"}
        self.apost(self.A, ma["action"], data, ma.get("token_page", ma["action"]))
        # confirm via the account page itself (no re-login -> throttle-proof)
        after = self.A.get(ma["action"]).body
        changed = newmail in after
        if changed:
            self.rep.add(check="mass-assign", category="mass-assignment",
                         status="FAIL", severity="High",
                         title="Mass assignment: email changed via profile update",
                         endpoint=ma["action"],
                         detail=f"Injected user[email_address]={newmail} is now shown "
                                "on the account page.",
                         remediation="Restrict permitted params; keep email/role/"
                         "admin out of the profile-update permit list.")
            self.apost(self.A, ma["action"], {**ma.get("base_fields", {}),
                       "user[email_address]": self._creds["A"][0], "_method": "patch"},
                       ma.get("token_page", ma["action"]))
        else:
            self.rep.add(check="mass-assign", category="mass-assignment",
                         status="PASS", severity="Info",
                         title="Mass assignment ignored (email/admin/role not applied)",
                         detail="Injected email/admin/role not reflected after update.")

    def check_file_upload(self):
        up = self.cfg.get("file_upload")
        if not (self.A and up):
            self.rep.add(check="file-upload", category="file-upload", status="SKIP",
                         severity="Info", title="File upload not run (needs config)")
            return
        tok = meta_token(self.A.get(up.get("token_page", "/")).body)
        headers = {self.csrf_header: tok} if tok else None
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
               '<script>alert(1)</script></svg>')
        tests = [
            ("evil.svg", "image/svg+xml", svg, "SVG with script (stored-XSS vector)"),
            ("shell.php.png", "image/png", b"\x89PNG\r\n<?php echo 1;?>",
             "double-extension / php content"),
            ("../../evil.png", "image/png", b"\x89PNGxx", "path-traversal filename"),
        ]
        confirmed, inconclusive = [], []
        for fname, ctype, content, label in tests:
            r = self.A.post_multipart(up["action"],
                                      fields=dict(up.get("fields", {}),
                                                  **{"authenticity_token": tok or ""}),
                                      files={up["file_field"]: (fname, ctype, content)},
                                      headers=headers)
            if r.status not in (200, 302):
                continue  # rejected
            # follow the redirect and look for real evidence it was stored
            loc = r.headers.get("location", "")
            path = loc[len(self.base):] if loc.startswith(self.base) else loc
            follow = self.A.get(path) if path else r
            is_login = bool(re.search(r'name="(email_address|password)"', follow.body))
            stored = (follow.status == 200 and not is_login
                      and ("active_storage" in follow.body
                           or fname.split("/")[-1] in follow.body
                           or (up.get("fields") and next(iter(up["fields"].values()))
                               in follow.body)))
            (confirmed if stored else inconclusive).append(f"{label}({r.status})")
        if confirmed:
            self.rep.add(check="file-upload", category="file-upload", status="WARN",
                         severity="Medium", confidence="Suspected",
                         title="Upload stored risky file(s)",
                         endpoint=up["action"], detail="; ".join(confirmed),
                         remediation="Validate content-type AND magic bytes, store "
                         "off web root, randomize filenames, never serve SVG/HTML "
                         "from user content inline.")
        elif inconclusive:
            self.rep.add(check="file-upload", category="file-upload", status="INFO",
                         severity="Info", confidence="Suspected",
                         title="Upload endpoint returned 2xx/3xx but storage unconfirmed",
                         endpoint=up["action"],
                         detail="; ".join(inconclusive) + " — could not confirm the "
                         "file was actually stored/served (verify manually).")
        else:
            self.rep.add(check="file-upload", category="file-upload", status="PASS",
                         severity="Info", title="Upload rejected risky files")

    # -- auth flow tests ----------------------------------------------------
    def check_user_enumeration(self):
        reg = self.cfg.get("auth", {}).get("register")
        if not reg or not self._creds:
            self.rep.add(check="user-enum", category="auth", status="SKIP",
                         severity="Info", title="User-enumeration not run")
            return
        # register with an already-used email (account A's)
        c = self.client()
        tok = form_token(c.get(reg["form_page"]).body)
        data = {}
        for k, v in reg["fields"].items():
            data[k] = (self._creds["A"][0] if v == "__EMAIL__"
                       else "Zz!" + secrets.token_urlsafe(10) if v == "__PASSWORD__"
                       else v)
        data.setdefault("authenticity_token", tok or "")
        r = c.post(reg["action"], data=data)
        leaks = bool(re.search(r"(already (been )?taken|already exists|already "
                               r"registered|email.{0,20}taken)", r.body, re.I))
        if leaks:
            self.rep.add(check="user-enum", category="auth", status="WARN",
                         severity="Low", title="Registration reveals existing emails",
                         detail="Signup with a known email returns an 'already taken' "
                         "message (account enumeration).",
                         remediation="Use a neutral message / email-based confirmation "
                         "to avoid disclosing which emails are registered.")
        else:
            self.rep.add(check="user-enum", category="auth", status="PASS",
                         severity="Info", title="No obvious signup user-enumeration")

    def check_login_rate_limit(self):
        lg = self.cfg.get("auth", {}).get("login")
        if not lg or not self._creds:
            self.rep.add(check="rate-limit", category="auth", status="SKIP",
                         severity="Info", title="Login rate-limit not run")
            return
        c = self.client()
        email = self._creds["A"][0]
        throttled_at = None
        for i in range(14):   # bounded; never a DoS
            tok = form_token(c.get(lg["form_page"]).body)
            data = {}
            for k, v in lg["fields"].items():
                data[k] = (email if v == "__EMAIL__"
                           else f"wrong{i}" if v == "__PASSWORD__" else v)
            data.setdefault("authenticity_token", tok or "")
            r = c.post(lg["action"], data=data)
            flash = c.get(lg["form_page"]).body
            if r.status == 429 or THROTTLE_RE.search(flash or ""):
                throttled_at = i + 1
                break
        if throttled_at:
            self.rep.add(check="rate-limit", category="auth", status="PASS",
                         severity="Info", title="Login rate-limiting present",
                         detail=f"Login throttled after ~{throttled_at} failed "
                                "attempt(s) (429 or 'try again later').")
        else:
            self.rep.add(check="rate-limit", category="auth", status="WARN",
                         severity="Medium", title="No login rate-limiting observed",
                         detail="14 failed logins with no throttle/lockout.",
                         remediation="Add rate limiting / lockout on repeated failed "
                         "logins (e.g. Rails rate_limit or rack-attack).")

    def check_password_policy(self):
        reg = self.cfg.get("auth", {}).get("register")
        if not reg:
            self.rep.add(check="password-policy", category="auth", status="SKIP",
                         severity="Info", title="Password policy not run")
            return
        c = self.client()
        tok = form_token(c.get(reg["form_page"]).body)
        data = {}
        for k, v in reg["fields"].items():
            data[k] = (f"pwpolicy_{int(time.time())}@example.com" if v == "__EMAIL__"
                       else "123" if v == "__PASSWORD__" else v)
        data.setdefault("authenticity_token", tok or "")
        r = c.post(reg["action"], data=data)
        weak_ok = r.status in (302, 303) or self.authed(c)
        self.rep.add(check="password-policy", category="auth",
                     status="WARN" if weak_ok else "PASS",
                     severity="Low" if weak_ok else "Info",
                     title=("Weak password '123' accepted" if weak_ok
                            else "Weak password rejected"),
                     detail=f"register with '123' -> {r.status}",
                     remediation="" if not weak_ok else "Enforce a minimum password "
                     "length/complexity.")

    def check_session_fixation(self):
        lg = self.cfg.get("auth", {}).get("login")
        if not lg or not self._creds:
            self.rep.add(check="session-fixation", category="auth", status="SKIP",
                         severity="Info", title="Session fixation not run")
            return
        c = self.client()
        c.get(lg["form_page"])
        pre = {ck.name: ck.value for ck in c.cj}
        status, _ = self.login_result(c, *self._creds["A"])
        if status == "throttled":
            self.rep.add(check="session-fixation", category="auth", status="SKIP",
                         severity="Info",
                         title="Session fixation not tested (login rate-limited)")
            return
        if status != "ok":
            self.rep.add(check="session-fixation", category="auth", status="SKIP",
                         severity="Info",
                         title=f"Session fixation not tested (login {status})")
            return
        post = {ck.name: ck.value for ck in c.cj}
        rotated = any(pre.get(k) != post.get(k) for k in set(pre) | set(post))
        self.rep.add(check="session-fixation", category="auth",
                     status="PASS" if rotated else "WARN",
                     severity="Info" if rotated else "Medium",
                     title=("Session identifier rotates on login" if rotated
                            else "Session may not rotate on login (fixation risk)"),
                     detail=f"cookies before={list(pre)} after={list(post)}",
                     remediation="" if rotated else "Call reset_session on login.")

    def check_logout_invalidation(self):
        lo = self.cfg.get("auth", {}).get("logout")
        if not (self.A and lo and self._creds):
            self.rep.add(check="logout", category="auth", status="SKIP",
                         severity="Info", title="Logout invalidation not run")
            return
        # fresh session we can safely log out
        status, c = self.login_result(self.client(), *self._creds["B"])
        if status != "ok":
            self.rep.add(check="logout", category="auth", status="SKIP",
                         severity="Info",
                         title=f"Logout not tested (login {status})")
            return
        # capture the session cookie, log out, then replay the old cookie
        old = "; ".join(f"{ck.name}={ck.value}" for ck in c.cj)
        tok = meta_token(c.get(lo.get("token_page", "/")).body)
        c.post(lo["action"], data={"_method": lo.get("method", "delete")},
               headers={self.csrf_header: tok} if tok else None)
        replay = self.client()
        chk = self.cfg.get("auth", {}).get("authed_check", "/")
        r = replay.req("GET", chk, headers={"Cookie": old})
        if r.status == 200:
            self.rep.add(check="logout", category="auth", status="FAIL",
                         severity="Medium", confidence="Suspected",
                         title="Session not invalidated server-side on logout",
                         detail="Old session cookie still authenticated after logout.",
                         remediation="Invalidate the session record on logout, not "
                         "just clear the cookie client-side.")
        else:
            self.rep.add(check="logout", category="auth", status="PASS",
                         severity="Info", title="Logout invalidates the session")

    def check_password_reset(self):
        pr = self.cfg.get("auth", {}).get("password_reset")
        if not pr:
            self.rep.add(check="password-reset", category="auth", status="SKIP",
                         severity="Info", title="Password-reset not run (no config)")
            return
        if not self.cfg.get("allow_email"):
            self.rep.add(check="password-reset", category="auth", status="SKIP",
                         severity="Info",
                         title="Password-reset skipped (sends email; pass allow_email)")
            return
        c = self.client()
        tok = form_token(c.get(pr["form_page"]).body)
        for bad, good in (("nonexistent_%d@example.com" % int(time.time()),
                           self._creds["A"][0]),):
            d1 = {pr["field"]: bad, "authenticity_token": tok or ""}
            d2 = {pr["field"]: good, "authenticity_token": tok or ""}
            r1 = c.post(pr["action"], data=d1)
            r2 = c.post(pr["action"], data=d2)
            same = (r1.status == r2.status and abs(len(r1.body) - len(r2.body)) < 40)
            self.rep.add(check="password-reset", category="auth",
                         status="PASS" if same else "WARN",
                         severity="Info" if same else "Low",
                         title=("Reset response is uniform (no enumeration)" if same
                                else "Reset response differs for known vs unknown email"),
                         detail=f"unknown->{r1.status}/{len(r1.body)}B "
                                f"known->{r2.status}/{len(r2.body)}B",
                         remediation="" if same else "Return an identical response "
                         "regardless of whether the email exists.")

    # ===================================================================== #
    def run(self):
        skip = set(self.cfg.get("skip", []))
        profile = self.cfg.get("profile", "full")
        if not is_local_url(self.base) and profile == "full":
            profile = "safe"
            self.rep.note("Non-local target: forced PASSIVE (read-only) profile "
                          "— no accounts, no payloads, no mutation, no brute-force.")
        self._profile = profile
        print(f"[*] prodscan -> {self.base}  (profile: {profile})")
        probe = self.client().get_follow("/")[0]
        if probe.status == 0 or "__ERROR__" in (probe.body or ""):
            self.rep.add(check="reachability", category="engine", status="FAIL",
                         severity="High", title="Target unreachable — scan aborted",
                         endpoint=self.base,
                         detail=f"Could not fetch {self.base}: {(probe.body or '')[:140]}. "
                                "Check the scheme (http vs https), host, port, and that "
                                "the server is actually running.",
                         remediation="Fix the base URL / start the server, then re-scan "
                                     "(a common mistake is https:// against an http:// server).")
            self.rep.note("Aborted: target unreachable (no response).")
            return self.rep
        if profile == "safe":
            self.rep.note("PASSIVE profile active: transport/headers, cookies, CORS, "
                          "methods, error exposure, content discovery, dependency/CVE "
                          "only.")
        else:
            if not self.cfg.get("auth"):      # URL-only mode: discover the app
                self.autodiscover_auth()
            self.setup_accounts()
        self.map_surface()
        if self._profile == "full" and self.A and not self.cfg.get("owned_objects"):
            self.autodiscover_targets()
        checks = [
            self.check_headers, self.check_cookies, self.check_cors,
            self.check_methods, self.check_error_exposure,
            self.check_content_discovery, self.check_dependencies,
            self.check_reflected_xss,
            self.check_stored_xss, self.check_sqli, self.check_ssti,
            self.check_open_redirect, self.check_host_header, self.check_csrf,
            self.check_access_control, self.check_vertical_privesc,
            self.check_format_bypass, self.check_mass_assignment,
            self.check_file_upload, self.check_user_enumeration,
            self.check_password_policy, self.check_session_fixation,
            self.check_logout_invalidation, self.check_password_reset,
            # brute-force / rate-limit LAST: it trips the login throttle, which
            # would otherwise poison the auth-dependent checks above.
            self.check_login_rate_limit,
        ]
        for chk in checks:
            name = chk.__name__
            if name in skip:
                continue
            if self._profile == "safe" and name not in SAFE_CHECKS:
                continue  # active/intrusive check excluded for non-local targets
            try:
                chk()
            except Exception as e:  # noqa: BLE001  -- a buggy check must not abort the run
                self.rep.add(check=name, category="engine", status="INFO",
                             severity="Info", title=f"{name} errored",
                             detail=repr(e)[:200])
        if self.cfg.get("emit_pocs") and self._cve_specs:
            import pocgen
            outdir = self.cfg.get("poc_dir", "pocs")
            for s in self._cve_specs:
                p, _ = pocgen.emit_poc(pocgen.PocSpec(target=self.base, **s), outdir)
                self.rep.note(f"Throwaway PoC stub written: {p}")
        return self.rep


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", help="JSON target config")
    ap.add_argument("--target", help="base URL (zero-config mode)")
    ap.add_argument("--rate", type=float, default=5)
    ap.add_argument("--out-json")
    ap.add_argument("--out-md")
    ap.add_argument("--no-cve", action="store_true",
                    help="skip the OSV CVE lookup (no external API calls)")
    ap.add_argument("--emit-pocs", action="store_true",
                    help="write a throwaway PoC verifier per CVE finding (pocs/)")
    ap.add_argument("--profile", choices=["full", "safe"], default=None,
                    help="full (local only) or safe/passive; non-local is forced safe")
    args = ap.parse_args()

    if args.config:
        cfg = json.load(open(args.config))
    elif args.target:
        cfg = {"base_url": args.target}
    else:
        ap.error("pass --config or --target")
    cfg.setdefault("rate", args.rate)
    cfg.setdefault("cve_lookup", True)
    if args.no_cve:
        cfg["cve_lookup"] = False
    if args.emit_pocs:
        cfg["emit_pocs"] = True
    if args.profile:
        cfg["profile"] = args.profile

    rep = Scanner(cfg).run()
    rep.to_console()
    if args.out_json:
        open(args.out_json, "w").write(rep.to_json())
        print(f"[+] JSON  -> {args.out_json}")
    if args.out_md:
        open(args.out_md, "w").write(rep.to_markdown())
        print(f"[+] report -> {args.out_md}")


if __name__ == "__main__":
    main()
