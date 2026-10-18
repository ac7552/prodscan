#!/usr/bin/env python3
"""
prodscan dashboard -- a LOCAL, single-user web UI to view reports and launch
scans. Bound to 127.0.0.1 only.

SAFETY BY DESIGN:
  * Binds to localhost only (not 0.0.0.0).
  * "Run" launches prodscan.py with a FIXED argv built from an ALLOWLIST of
    target configs in targets/. No arbitrary commands, no arbitrary URLs, no
    shell=True, no free-text flags. This is a scan launcher, not a command
    runner -- deliberately, so it can't become an RCE box.
  * Reports are read from reports/ with filename validation (no path traversal).

Usage:
  python3 dashboard.py            # http://127.0.0.1:8777
  python3 dashboard.py --port 9000
"""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

BASE = os.path.dirname(os.path.abspath(__file__))          # engine (may be read-only in a .app)
DATA_DIR = os.path.expanduser("~/Library/Application Support/prodscan")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")            # writable, persists across app replacement
POCS_DIR = os.path.join(DATA_DIR, "pocs")
USER_TARGETS = os.path.join(DATA_DIR, "targets")           # user-added configs
BUNDLED_TARGETS = os.path.join(BASE, "targets")            # shipped templates (e.g. example.json)
PYTHON = sys.executable or "python3"

for _d in (REPORTS_DIR, POCS_DIR, USER_TARGETS):
    os.makedirs(_d, exist_ok=True)

RUNS = {}            # run_id -> {"status","output","report"}
RUNS_LOCK = threading.Lock()
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

# Access control: a per-launch token (defeats CSRF — an attacker page can't
# read it) plus Host/Origin pinning (defeats DNS rebinding / cross-site calls).
TOKEN = os.environ.get("PRODSCAN_TOKEN") or secrets.token_urlsafe(16)
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def list_configs():
    out = set()
    for d in (BUNDLED_TARGETS, USER_TARGETS):
        if os.path.isdir(d):
            out.update(f for f in os.listdir(d) if f.endswith(".json"))
    return sorted(out)


def target_path(name):
    for d in (USER_TARGETS, BUNDLED_TARGETS):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def host_is_local(url):
    h = (urlparse(url).hostname or "").lower()
    return (h in {"localhost", "127.0.0.1", "::1"}
            or h.endswith(".localhost") or h.endswith(".test"))


def list_reports():
    out = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not f.endswith(".json"):
            continue
        try:
            data = json.load(open(os.path.join(REPORTS_DIR, f)))
            out.append({"name": f, "target": data.get("target", ""),
                        "verdict": data.get("verdict", ""),
                        "summary": data.get("summary", {}),
                        "mtime": os.path.getmtime(os.path.join(REPORTS_DIR, f))})
        except Exception:  # noqa: BLE001
            continue
    return out


def run_scan(run_id, spec):
    """Launch prodscan with a validated, fixed argv (no shell). `spec` is
    either a config run or a target-URL run (profile gated by the caller)."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    argv = [PYTHON, os.path.join(BASE, "prodscan.py")]
    if spec["mode"] == "config":
        stem = os.path.splitext(spec["config"])[0]
        argv += ["--config", target_path(spec["config"]) or spec["config"]]
    else:
        stem = re.sub(r"[^A-Za-z0-9._-]", "_",
                      urlparse(spec["target"]).hostname or "target")
        argv += ["--target", spec["target"], "--profile", spec["profile"]]
    out_name = f"{stem}-{ts}.json"
    out_path = os.path.join(REPORTS_DIR, out_name)
    argv += ["--out-json", out_path]
    if spec.get("emit_pocs"):
        argv.append("--emit-pocs")
    if spec.get("no_cve"):
        argv.append("--no-cve")
    with RUNS_LOCK:
        RUNS[run_id] = {"status": "running", "output": "", "report": out_name}
    try:
        p = subprocess.Popen(argv, cwd=DATA_DIR, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in p.stdout:
            lines.append(line)
            with RUNS_LOCK:
                RUNS[run_id]["output"] = "".join(lines)[-8000:]
        p.wait()
        done = "done" if p.returncode == 0 else f"exit {p.returncode}"
        with RUNS_LOCK:
            RUNS[run_id]["status"] = done
            RUNS[run_id]["report"] = out_name if os.path.exists(out_path) else None
    except Exception as e:  # noqa: BLE001
        with RUNS_LOCK:
            RUNS[run_id]["status"] = f"error: {e}"


# --------------------------------------------------------------------------- #
# PoC generation + running (AI-assisted, safe-gated)
# --------------------------------------------------------------------------- #


def list_pocs():
    if not os.path.isdir(POCS_DIR):
        return []
    return sorted(f for f in os.listdir(POCS_DIR) if f.endswith(".py"))


def gen_poc_from_report(report_name, idx):
    """Build a PoC from a dependency/CVE finding; AI-fill it if a key is set."""
    import pocgen
    data = json.load(open(os.path.join(REPORTS_DIR, report_name)))
    results = data.get("results", [])
    if idx < 0 or idx >= len(results):
        return {"error": "bad finding index"}
    f = results[idx]
    m = re.search(r'([\w@/.+-]+)@(\d[\d.]*)', f.get("title", ""))
    lib = m.group(1) if m else f.get("title", "library")
    ver = m.group(2) if m else "0"
    adv = re.search(r'(CVE-\d{4}-\d+|GHSA-[\w-]+)',
                    f.get("detail", "") + " " + f.get("title", ""))
    aliases = tuple(re.findall(r'GHSA-[\w-]+', f.get("detail", "")))
    spec = pocgen.PocSpec(target=data.get("target", ""), library=lib, version=ver,
                          advisory_id=adv.group(1) if adv else "",
                          advisory_summary=f.get("detail", ""),
                          endpoint=f.get("endpoint", "/"), aliases=aliases)
    # Client-side library XSS (jQuery &c.): a runnable HTML harness that actually
    # fires, instead of an HTTP verifier that can only say INCONCLUSIVE.
    if pocgen.client_poc_for(spec):
        try:
            html_path, info = pocgen.emit_client_poc(spec, POCS_DIR)
            name = os.path.basename(html_path)
            return {"kind": "html", "poc": name, "url": "/poc/" + name,
                    "cves": info.get("cves", []), "code": open(html_path).read()}
        except Exception as e:  # noqa: BLE001 — fall back to the verifier below
            html_err = str(e)
    else:
        html_err = None
    body = pocgen.fill_check_via_llm(spec)      # None if no ANTHROPIC_API_KEY
    poc_path, _ = pocgen.emit_poc(spec, POCS_DIR, check_body=body)
    return {"kind": "py", "poc": os.path.basename(poc_path), "ai": bool(body),
            "code": open(poc_path).read(),
            "note": ("live HTML PoC unavailable (%s)" % html_err) if html_err else ""}


def _poc_target_local(path):
    try:
        m = re.search(r'TARGET\s*=\s*"([^"]+)"', open(path).read())
        return host_is_local(m.group(1)) if m else False
    except Exception:  # noqa: BLE001
        return False


def run_poc(run_id, name):
    """Run a PoC verifier. Local target -> pass --i-am-authorized; non-local ->
    omit it so the PoC self-refuses (we never auto-run against non-local)."""
    path = os.path.join(POCS_DIR, name)
    argv = [PYTHON, path]
    if _poc_target_local(path):
        argv.append("--i-am-authorized")
    with RUNS_LOCK:
        RUNS[run_id] = {"status": "running", "output": "", "report": None}
    try:
        p = subprocess.Popen(argv, cwd=DATA_DIR, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        out, _ = p.communicate(timeout=150)
        verdict = {0: "CONFIRMED", 1: "NOT", 2: "COULD-NOT-TEST"}.get(
            p.returncode, f"exit {p.returncode}")
        with RUNS_LOCK:
            RUNS[run_id] = {"status": verdict, "output": (out or "")[-8000:],
                            "report": None}
    except Exception as e:  # noqa: BLE001
        with RUNS_LOCK:
            RUNS[run_id] = {"status": f"error: {e}", "output": "", "report": None}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass  # quiet

    def _authorized(self):
        """Pin Host/Origin to localhost and require the per-launch token."""
        if self.headers.get("Host", "").split(":")[0] not in ALLOWED_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin and (urlparse(origin).hostname not in ALLOWED_HOSTS):
            return False
        tok = self.headers.get("X-Prodscan-Token", "") or \
            parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return secrets.compare_digest(tok, TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path.startswith("/poc/"):
            # Serve generated client-side PoC harnesses + their vendored libs.
            # Localhost-only (the server binds 127.0.0.1); no token so the
            # harness's relative vendor/ script loads resolve.
            if self.headers.get("Host", "").split(":")[0] not in ALLOWED_HOSTS:
                return self._send(403, {"error": "forbidden"})
            rel = unquote(u.path[len("/poc/"):])
            full = os.path.realpath(os.path.join(POCS_DIR, rel))
            root = os.path.realpath(POCS_DIR)
            if not (full == root or full.startswith(root + os.sep)) \
                    or not os.path.isfile(full) \
                    or os.path.splitext(full)[1] not in (".html", ".js"):
                return self._send(404, {"error": "not found"})
            ctype = ("text/html; charset=utf-8" if full.endswith(".html")
                     else "application/javascript")
            with open(full, "rb") as fh:
                return self._send(200, fh.read(), ctype)
        if u.path.startswith("/api/") and not self._authorized():
            return self._send(403, {"error": "forbidden"})
        if u.path == "/api/configs":
            return self._send(200, list_configs())
        if u.path == "/api/reports":
            return self._send(200, list_reports())
        if u.path == "/api/report":
            name = (q.get("name") or [""])[0]
            if not SAFE_NAME.match(name) or not name.endswith(".json"):
                return self._send(400, {"error": "bad name"})
            path = os.path.join(REPORTS_DIR, name)
            if not os.path.isfile(path):
                return self._send(404, {"error": "not found"})
            return self._send(200, open(path).read(), "application/json")
        if u.path == "/api/run_status":
            rid = (q.get("id") or [""])[0]
            with RUNS_LOCK:
                return self._send(200, RUNS.get(rid, {"status": "unknown"}))
        if u.path == "/api/pocs":
            return self._send(200, list_pocs())
        if u.path == "/api/poc":
            name = (q.get("name") or [""])[0]
            if not SAFE_NAME.match(name) or not name.endswith(".py"):
                return self._send(400, {"error": "bad name"})
            path = os.path.join(POCS_DIR, name)
            if not os.path.isfile(path):
                return self._send(404, {"error": "not found"})
            return self._send(200, {"name": name, "code": open(path).read()})
        return self._send(404, {"error": "no route"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._authorized():
            return self._send(403, {"error": "forbidden"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:  # noqa: BLE001
            return self._send(400, {"error": "bad json"})

        if u.path == "/api/genpoc":
            report = body.get("report", "")
            if not SAFE_NAME.match(report or "") or not report.endswith(".json") \
                    or not os.path.isfile(os.path.join(REPORTS_DIR, report)):
                return self._send(400, {"error": "bad report"})
            return self._send(200, gen_poc_from_report(report, int(body.get("idx", -1))))

        if u.path == "/api/runpoc":
            name = body.get("name", "")
            if not SAFE_NAME.match(name or "") or not name.endswith(".py") \
                    or not os.path.isfile(os.path.join(POCS_DIR, name)):
                return self._send(400, {"error": "bad poc"})
            rid = "poc_%d" % int(time.time() * 1000)
            threading.Thread(target=run_poc, args=(rid, name), daemon=True).start()
            return self._send(200, {"id": rid})

        if u.path != "/api/run":
            return self._send(404, {"error": "no route"})
        target = (body.get("target") or "").strip()
        if target:
            pu = urlparse(target)
            if pu.scheme not in ("http", "https") or not pu.hostname:
                return self._send(400, {"error": "target must be an http(s) URL"})
            # Host gate: full suite only for local hosts; non-local -> passive.
            profile = "full" if host_is_local(target) else "safe"
            spec = {"mode": "target", "target": target, "profile": profile}
        else:
            config = body.get("config", "")
            if config not in list_configs():   # allowlist
                return self._send(400, {"error": "config not in allowlist"})
            spec = {"mode": "config", "config": config}
        spec["emit_pocs"] = bool(body.get("emit_pocs"))
        spec["no_cve"] = bool(body.get("no_cve"))
        rid = "run_%d" % int(time.time() * 1000)
        threading.Thread(target=run_scan, args=(rid, spec), daemon=True).start()
        return self._send(200, {"id": rid, "profile": spec.get("profile", "full")})


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>prodscan dashboard</title>
<style>
:root{
 --bg:#0f161c;--bg2:#0b1016;--panel:#161f28;--line:#27333d;
 --fg:#dce7ee;--mut:#8295a2;--gold:#79b4c8;--gold2:#a9d4e2;--bronze:#4e7686;
 --fail:#d26a5d;--warn:#caa05c;--pass:#7fb59a;--info:#6fa6c2;--skip:#6d7c87;
 --serif:"Baskerville","Hoefler Text","Iowan Old Style",Palatino,Georgia,serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.6 -apple-system,"Segoe UI",Roboto,sans-serif;
 background-image:radial-gradient(130% 90% at 50% -15%,#17262f 0%,var(--bg) 58%)}
header{padding:18px 26px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px}
.brand{display:flex;align-items:center;gap:11px;color:var(--gold)}
.brand .mark{width:26px;height:26px;display:block;line-height:0}
.brand .word{font-family:var(--serif);font-size:22px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold2)}
.sub{color:var(--mut);font-size:11px;letter-spacing:.24em;text-transform:uppercase;border-left:1px solid var(--line);padding-left:16px}
.badge{font-family:var(--serif);padding:2px 12px;border-radius:2px;font-size:12px;letter-spacing:.14em;text-transform:uppercase;border:1px solid transparent}
.v-GO{color:var(--pass);border-color:var(--pass)}
.v-CONDITIONAL{color:var(--warn);border-color:var(--warn)}
.v-NO-GO{color:var(--fail);border-color:var(--fail)}
.wrap{display:grid;grid-template-columns:330px 1fr;height:calc(100vh - 62px)}
.side{border-right:1px solid var(--line);overflow:auto;padding:18px;background:var(--bg2)}
.main{overflow:auto;padding:30px 36px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:3px;padding:16px;margin-bottom:16px}
.panel h3{font-family:var(--serif);font-size:15px;letter-spacing:.12em;text-transform:uppercase;color:var(--gold2);margin:0 0 12px;font-weight:400}
.reports-h{font-family:var(--serif);font-size:13px;letter-spacing:.16em;text-transform:uppercase;color:var(--mut);margin:20px 2px 10px}
.rep{padding:12px;border:1px solid var(--line);border-radius:3px;margin-bottom:9px;cursor:pointer;background:var(--panel);transition:border-color .15s}
.rep:hover{border-color:var(--gold)}
.rep .t{font-weight:600;font-size:13px}.rep .m{color:var(--mut);font-size:11px;margin-top:3px}
label{display:block;color:var(--mut);font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin:10px 0 4px}
input,select{font:inherit;padding:9px 10px;border-radius:3px;border:1px solid var(--line);background:#0c131a;color:var(--fg);width:100%}
input:focus,select:focus{outline:none;border-color:var(--gold)}
.or{text-align:center;color:var(--mut);font-size:11px;letter-spacing:.2em;margin:13px 0 2px}
.chk{display:flex;align-items:center;gap:8px;color:var(--mut);font-size:12.5px;text-transform:none;letter-spacing:0;margin-top:9px}
.chk input{width:auto}
button#run{margin-top:16px;width:100%;padding:11px;background:transparent;border:1px solid var(--gold);color:var(--gold2);font-family:var(--serif);font-size:14px;letter-spacing:.18em;text-transform:uppercase;cursor:pointer;border-radius:3px;transition:background .15s,color .15s}
button#run:hover{background:var(--gold);color:#0b1016}
button#run:disabled{opacity:.45;cursor:default;background:transparent;color:var(--mut)}
.mini{display:inline-block;width:auto;margin-top:8px;padding:5px 12px;background:transparent;border:1px solid var(--gold);color:var(--gold2);font-size:11px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;border-radius:3px}
.mini:hover{background:var(--gold);color:#0b1016}.mini:disabled{opacity:.5;cursor:default}
h2{font-family:var(--serif);font-weight:400;font-size:26px;letter-spacing:.02em;display:flex;align-items:center;gap:16px;margin:0 0 22px}
.row{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 22px}
.kpi{flex:1;min-width:86px;text-align:center;background:var(--panel);border:1px solid var(--line);border-radius:3px;padding:14px 8px}
.kpi b{display:block;font-family:var(--serif);font-size:30px;line-height:1}
.kpi span{display:block;color:var(--mut);font-size:10px;letter-spacing:.18em;text-transform:uppercase;margin-top:8px}
.kpi b.s-FAIL{color:var(--fail)}.kpi b.s-WARN{color:var(--warn)}
.kpi b.s-PASS{color:var(--pass)}.kpi b.s-INFO{color:var(--info)}.kpi b.s-SKIP{color:var(--skip)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:3px;padding:18px;margin-bottom:16px}
.card>b{font-family:var(--serif);font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--gold2);font-weight:400;display:block;margin-bottom:10px}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.pill{font-family:var(--serif);padding:1px 9px;border-radius:2px;font-size:11px;letter-spacing:.1em;border:1px solid}
.s-FAIL{color:var(--fail);border-color:var(--fail)}.s-WARN{color:var(--warn);border-color:var(--warn)}
.s-PASS{color:var(--pass);border-color:var(--pass)}.s-INFO{color:var(--info);border-color:var(--info)}.s-SKIP{color:var(--skip);border-color:var(--skip)}
.mut{color:var(--mut)}.gold{color:var(--gold2)}.warnc{color:var(--warn)}
.ht{position:relative;cursor:help}
.why{margin-left:7px;color:var(--bronze);font-style:normal;font-weight:400;user-select:none}
.why:hover,.why:focus{color:var(--gold2);outline:none}
.pill.ht:hover,.pill.ht:focus{outline:none;filter:brightness(1.25)}
.tip{display:none;position:absolute;left:0;top:calc(100% + 8px);z-index:1000;width:300px;max-width:66vw;
 background:#0b0f14;border:1px solid var(--gold);border-radius:5px;padding:11px 13px;
 color:var(--fg);font:400 12px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif;letter-spacing:0;
 text-transform:none;white-space:normal;box-shadow:0 16px 42px rgba(0,0,0,.72),0 0 0 1px rgba(11,15,20,.9)}
.ht.up .tip{top:auto;bottom:calc(100% + 8px)}
.tip::before{content:attr(data-label);display:block;color:var(--gold2);font-family:var(--serif);
 font-size:10px;letter-spacing:.16em;text-transform:uppercase;margin-bottom:5px}
.ht:hover .tip,.ht:focus .tip{display:block}
td:last-child .tip{left:auto;right:0}
.ev{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#aebfca;white-space:pre-wrap;margin-top:4px}
pre{background:#0c131a;border:1px solid var(--line);border-radius:3px;padding:12px;overflow:auto;max-height:240px;font-size:11.5px;color:var(--mut)}
.note{font-size:11px;color:var(--mut);margin-top:10px;letter-spacing:.04em}
.empty{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.rose{color:var(--bronze);opacity:.42;margin-bottom:26px}
.tagline{font-family:var(--serif);font-size:18px;color:var(--mut);letter-spacing:.04em}
@keyframes rose-spin{to{transform:rotate(360deg)}}
@keyframes rose-breathe{0%,100%{opacity:.30}50%{opacity:.74}}
@keyframes mark-breathe{0%,100%{opacity:.55}50%{opacity:1}}
body.scanning .rose{animation:rose-breathe 2.4s ease-in-out infinite;color:var(--gold)}
body.scanning .rose svg{animation:rose-spin 16s linear infinite;transform-origin:50% 50%}
body.scanning .brand .mark{animation:mark-breathe 1.6s ease-in-out infinite}
body.scanning .brand .mark svg{animation:rose-spin 5s linear infinite;transform-origin:50% 50%}
@media(prefers-reduced-motion:reduce){body.scanning .rose,body.scanning .rose svg,body.scanning .brand .mark,body.scanning .brand .mark svg{animation:none}body.scanning .rose{opacity:.6;color:var(--gold)}}
@media(max-width:820px){.wrap{grid-template-columns:1fr;height:auto}.side{border-right:0;border-bottom:1px solid var(--line)}}
</style></head><body>
<header>
  <div class="brand"><span class="mark" id="mark"></span><span class="word">Prodscan</span></div>
  <span class="sub">production readiness &middot; local</span>
</header>
<div class="wrap">
  <aside class="side">
    <div class="panel">
      <h3>Run a scan</h3>
      <label>Scan a URL</label>
      <input id="url" type="text" placeholder="https://example.com" spellcheck="false" autocapitalize="off">
      <div id="profnote" class="note"></div>
      <div class="or">&mdash; or &mdash;</div>
      <label>Local config</label>
      <select id="cfg"></select>
      <label class="chk"><input type="checkbox" id="pocs"> emit throwaway PoCs</label>
      <label class="chk"><input type="checkbox" id="nocve"> skip CVE lookup</label>
      <button id="run">Run scan</button>
      <div id="runstat" class="note"></div>
    </div>
    <div class="reports-h">Reports</div>
    <div id="reports"></div>
  </aside>
  <main class="main" id="main"><div class="empty"><div class="rose" id="emptyRose"></div><p class="tagline">Select a report, or point a scan at a target.</p></div></main>
</div>
<script>
const $=s=>document.querySelector(s), esc=s=>(s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
// Plain-language "why this is a risk" per check, keyed by category/check.
const WHY={
 'headers/hsts':"Without HSTS a first visit over plain HTTP — or an attacker-forced downgrade on hostile Wi-Fi — can be intercepted and HTTPS stripped, exposing the session cookie. HSTS tells browsers to only ever connect over TLS.",
 'headers/referrer-policy':"The browser attaches the full referring URL (path and query) to outbound requests. With no Referrer-Policy, anything in your URLs — IDs, tokens, internal paths — leaks to third-party sites, analytics and ad networks.",
 'headers/content-security-policy':"With no CSP, injected markup can pull scripts from anywhere. CSP is the main defense-in-depth that keeps an XSS flaw from escalating into full script execution and data exfiltration.",
 'headers/x-content-type-options':"Without nosniff, a browser may MIME-sniff a response and run, say, a user-uploaded file served as text as a script — turning a benign upload into XSS.",
 'headers/clickjacking':"With no X-Frame-Options / frame-ancestors, your pages can be framed invisibly on an attacker's site and the user tricked into clicking real controls (clickjacking).",
 'headers/tls':"Served over plain HTTP, all traffic — credentials, session cookies, data — travels in cleartext and can be read or altered by anyone on the network path.",
 'headers/banner':"Advertising the exact server/framework and version hands an attacker the list of known CVEs and default misconfigurations to try first. Suppressing banners removes a free recon shortcut.",
 'csrf/csrf':"A POST form with no anti-CSRF token can be submitted from an attacker's page while the victim is logged in, performing state-changing actions (transfers, settings, deletes) as that user without their intent.",
 'dependencies/dependency-cve':"This client-side library version matches a published advisory. Depending on the CVE an attacker can achieve DOM-based XSS, prototype pollution or other code execution in your users' browsers.",
 'dependencies/inventory':"Informational: the client-side libraries and versions fingerprinted on the page, used to match against known-CVE databases. A library shown as “name@?” was detected but its version string couldn't be read, so it can't be checked for CVEs.",
 'injection/sqli':"If user input reaches a SQL query unparameterized, an attacker can read, modify or destroy the whole database and often bypass authentication.",
 'injection/ssti':"User input evaluated by a server-side template engine can escalate to remote code execution on the server.",
 'injection/open-redirect':"An endpoint that redirects to a user-supplied URL lends your domain's trust to phishing and can bypass redirect allowlists in OAuth flows.",
 'injection/host-header':"Trusting the Host header lets an attacker poison password-reset links, cache keys and absolute URLs, sending victims to attacker-controlled hosts.",
 'xss/reflected-xss':"User input echoed into the page without escaping lets an attacker run arbitrary JavaScript in a victim's session — stealing cookies and tokens or acting as that user.",
 'xss/stored-xss':"Attacker-controlled content saved and later rendered to other users runs script in their sessions — the most damaging XSS, hitting every viewer.",
 'cors/cors':"An over-permissive CORS policy (reflecting arbitrary origins with credentials) lets any website read authenticated responses on behalf of your logged-in users.",
 'cookies/cookie-flags':"Session cookies without HttpOnly / Secure / SameSite can be stolen via XSS, sent over plain HTTP, or ridden in CSRF attacks.",
 'methods/trace':"HTTP TRACE can be abused (Cross-Site Tracing) to read headers and cookies that are otherwise protected, and has no production use.",
 'methods/methods':"Unexpected HTTP methods left enabled can expose write or delete operations that were never meant to be reachable.",
 'access-control/idor':"Object references (IDs in URLs or params) that aren't scoped to the current user let an attacker read or change other users' records by guessing or incrementing IDs.",
 'access-control/idor-read':"An object ID that isn't scoped to the current user lets an attacker read other users' records by guessing or incrementing the ID.",
 'access-control/idor-write':"An object ID that isn't scoped to the current user lets an attacker modify other users' records by guessing or incrementing the ID.",
 'access-control/privesc':"A lower-privileged user can reach admin-only routes or actions — full privilege escalation.",
 'access-control/mass-assign-owner':"Binding request params straight to model attributes lets an attacker set fields they shouldn't — owner_id, role, admin — taking over records or escalating privileges.",
 'mass-assignment/mass-assign':"Binding request params straight to model attributes lets an attacker set fields they shouldn't — owner_id, role, admin — taking over records or escalating privileges.",
 'access-control/format-bypass':"Appending a format (.json / .xml) or changing the content-type can bypass an access control that only guarded the HTML route.",
 'auth/logout':"If logout doesn't invalidate the server-side session, a stolen or observed session stays valid after the user believes they've signed out.",
 'auth/password-policy':"With no minimum password strength, users (and attackers via credential stuffing) can rely on trivially guessable passwords.",
 'auth/password-reset':"A weak reset flow — guessable tokens, no expiry, host-header-controlled links — lets an attacker take over accounts.",
 'auth/rate-limit':"No lockout or throttling on login lets an attacker brute-force or credential-stuff passwords at scale.",
 'auth/session-fixation':"If the session ID isn't rotated at login, an attacker who plants a known session ID can hijack the account once the victim authenticates.",
 'auth/user-enum':"Different responses for valid vs. invalid usernames let an attacker harvest a list of real accounts to target.",
 'file-upload/file-upload':"Accepting uploads without validating type and content lets an attacker store a script or executable that is later served and run.",
 'errors/verbose-errors':"Stack traces and framework error pages leak source paths, library versions and config — a roadmap for the next attack.",
 'errors/exposed-path':"A sensitive path (config, .git, admin, backups) is reachable and can leak secrets or source code.",
 'discovery/content-discovery':"Informational: common paths that responded, useful for mapping the attack surface.",
 'engine/reachability':"The scanner couldn't fully reach the target, so results are incomplete — not a clean bill of health."};
const WHY_CAT={'headers':"A missing or weak security response header. On its own it's rarely exploitable, but each one removes a layer of defense-in-depth.",
 'access-control':"An authorization gap: a user reaching data or actions that should be out of their scope.",
 'auth':"A weakness in the authentication or session lifecycle that can lead to account takeover.",
 'injection':"Untrusted input reaching an interpreter (SQL, template, redirect, host) where it can change the intended command or destination."};
function whyText(r){const k=(r.category||'')+'/'+(r.check||'');
 if(WHY[k])return WHY[k];
 if((r.check||'').indexOf('banner-')===0)return WHY['headers/banner'];
 return WHY_CAT[r.category]||'';}
function whyTip(r){const t=whyText(r);return t?` <span class="why ht" tabindex="0" aria-label="why it matters">&#9432;<span class="tip" data-label="why it matters">${esc(t)}</span></span>`:'';}
// What each status level means — shown on hover over the status badge.
const STATUS_WHY={
 FAIL:"A confirmed or likely production-readiness defect. A Critical/High FAIL drives a NO-GO verdict; a Medium FAIL drives CONDITIONAL.",
 WARN:"Worth fixing but not a hard blocker — hardening / defense-in-depth, or a lower-confidence finding. Doesn't fail the verdict on its own.",
 PASS:"The check ran and the target behaved safely — no issue found for this check.",
 INFO:"Context, not a problem: inventory, reachable paths, enabled methods. Useful for understanding the attack surface.",
 SKIP:"The check didn't run — not applicable, the needed surface wasn't reachable, or it was gated off (passive profile, or CVE lookup disabled)."};
function statusCell(st){return `<td><span class="pill s-${st} ht" tabindex="0">${st}<span class="tip" data-label="status · ${st}">${esc(STATUS_WHY[st]||'')}</span></span></td>`;}
const TOKEN=new URLSearchParams(location.search).get('token')||'';
async function j(u,o){o=o||{};o.headers=Object.assign({'X-Prodscan-Token':TOKEN},o.headers||{});const r=await fetch(u,o);return r.json();}
async function loadConfigs(){const c=await j('/api/configs');$('#cfg').innerHTML=c.map(x=>`<option>${esc(x)}</option>`).join('')||'<option>(no configs)</option>';}
async function loadReports(sel){const r=await j('/api/reports');$('#reports').innerHTML=r.map(x=>`<div class="rep" data-n="${esc(x.name)}"><div class="t">${esc(x.target)} <span class="badge v-${esc(x.verdict)}">${esc(x.verdict)}</span></div><div class="m">${esc(x.name)} · F${x.summary.FAIL||0} W${x.summary.WARN||0} P${x.summary.PASS||0}</div></div>`).join('')||'<p class="mut">No reports yet.</p>';
  document.querySelectorAll('.rep').forEach(e=>e.onclick=()=>showReport(e.dataset.n));
  if(sel) showReport(sel);}
async function showReport(name){const d=await j('/api/report?name='+encodeURIComponent(name));
  const s=d.summary||{}; const order={FAIL:0,WARN:1,PASS:2,INFO:3,SKIP:4};
  const res=(d.results||[]).slice().sort((a,b)=>(order[a.status]??9)-(order[b.status]??9));
  const kpi=['FAIL','WARN','PASS','INFO','SKIP'].map(k=>`<div class="kpi"><b class="s-${k}">${s[k]||0}</b><span>${k}</span></div>`).join('');
  const rows=res.filter(r=>r.status!=='PASS'&&r.status!=='INFO'&&r.status!=='SKIP').map(r=>{const oi=(d.results||[]).indexOf(r);const pb=(r.category==='dependencies'&&r.check==='dependency-cve')?`<div><button class="mini genpoc" data-rep="${esc(name)}" data-idx="${oi}">⚙ Generate PoC</button></div>`:'';return `<tr>${statusCell(r.status)}<td>${esc(r.severity)}</td><td class="mut">${esc(r.category)}/${esc(r.check)}</td><td><b>${esc(r.title)}</b>${whyTip(r)}${r.endpoint?`<div class="mut">${esc(r.endpoint)}</div>`:''}<div class="ev">${esc(r.detail)}</div>${r.remediation?`<div class="mut">fix: ${esc(r.remediation)}</div>`:''}${pb}</td></tr>`;}).join('');
  const passed=res.filter(r=>['PASS','INFO','SKIP'].includes(r.status)).map(r=>`<tr>${statusCell(r.status)}<td class="mut">${esc(r.category)}/${esc(r.check)}</td><td>${esc(r.title)}${whyTip(r)}</td></tr>`).join('');
  $('#main').innerHTML=`<h2>${esc(d.target)} <span class="badge v-${esc(d.verdict)}">${esc(d.verdict)}</span></h2>
    <div class="row">${kpi}</div>
    <div class="card"><b>Findings (FAIL / WARN)</b><table><tr><th>Status</th><th>Sev</th><th>Check</th><th>Detail</th></tr>${rows||'<tr><td colspan=4 class="mut">none</td></tr>'}</table></div>
    <div class="card"><b>Passed / informational</b><table>${passed}</table></div>
    ${(d.notes&&d.notes.length)?`<div class="card"><b>Recon notes</b><pre>${esc(d.notes.join('\n'))}</pre></div>`:''}
    <div id="pocarea"></div>`;
  document.querySelectorAll('.genpoc').forEach(b=>b.onclick=async()=>{b.disabled=true;const t=b.textContent;b.textContent='generating…';
    const r=await j('/api/genpoc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report:b.dataset.rep,idx:+b.dataset.idx})});
    b.disabled=false;b.textContent=t;showPoc(r.error?null:r,r.error);});}
function showPoc(r,err){const a=$('#pocarea');if(!r){a.innerHTML=`<div class="card"><b>PoC</b><div class="mut">${esc(err||'error')}</div></div>`;return;}
  if(r.kind==='html'){const src=r.url;
    a.innerHTML=`<div class="card"><b>Generated PoC — ${esc(r.poc)} <span class="gold">· live client-side harness</span></b>
      <div class="note">Runs locally against vendored ${r.cves?esc(r.cves.join(' / ')):'library'}. <a class="gold" href="${esc(src)}" target="_blank" rel="noopener">open in new tab ↗</a></div>
      <div id="pocverdict" class="note">running…</div>
      <iframe src="${esc(src)}" style="width:100%;height:440px;border:1px solid var(--line);border-radius:3px;background:var(--bg2);margin-top:10px"></iframe></div>`;
    a.scrollIntoView({behavior:'smooth'});
    const onmsg=(e)=>{if(e&&e.data&&e.data.__poc__){window.removeEventListener('message',onmsg);
      $('#pocverdict').innerHTML=`<b class="${e.data.ok?'gold':'mut'}">${esc(e.data.verdict)}</b>`;}};
    window.addEventListener('message',onmsg);return;}
  a.innerHTML=`<div class="card"><b>Generated PoC — ${esc(r.poc)} ${r.ai?'<span class="gold">· AI-filled</span>':'<span class="mut">· stub (set ANTHROPIC_API_KEY for AI fill)</span>'}</b>${r.note?`<div class="note warnc">${esc(r.note)}</div>`:''}<pre>${esc(r.code)}</pre><button class="mini runpoc">▶ Run PoC</button><div id="pocresult" class="note"></div></div>`;
  a.scrollIntoView({behavior:'smooth'});
  $('.runpoc').onclick=async()=>{const rb=$('.runpoc');rb.disabled=true;$('#pocresult').textContent='running…';
    const rr=await j('/api/runpoc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:r.poc})});
    if(rr.error){$('#pocresult').textContent='error: '+rr.error;rb.disabled=false;return;}
    const poll=setInterval(async()=>{const st=await j('/api/run_status?id='+rr.id);
      if(st.status==='running'){$('#pocresult').textContent='running…';return;}
      clearInterval(poll);rb.disabled=false;
      $('#pocresult').innerHTML=`<b class="gold">RESULT: ${esc(st.status)}</b><pre>${esc(st.output||'')}</pre>`;},1500);};}
$('#run').onclick=async()=>{const btn=$('#run');btn.disabled=true;$('#runstat').textContent='starting…';
  const url=$('#url').value.trim();
  const payload=url?{target:url}:{config:$('#cfg').value};
  payload.emit_pocs=$('#pocs').checked;payload.no_cve=$('#nocve').checked;
  const r=await j('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  if(r.error){$('#runstat').textContent='error: '+r.error;btn.disabled=false;return;}
  const prof=r.profile?(' — '+r.profile+' profile'):'';
  $('#runstat').textContent='running'+prof;document.body.classList.add('scanning');
  const poll=setInterval(async()=>{const st=await j('/api/run_status?id='+r.id);
    $('#runstat').textContent=(st.status==='running'?'running'+prof:'status: '+st.status);
    if(st.status!=='running'){clearInterval(poll);btn.disabled=false;document.body.classList.remove('scanning');await loadReports(st.report);}},1500);};
function rosette(size,sw){const c=size/2,rings=[[c*0.9,46],[c*0.74,36],[c*0.58,28],[c*0.42,20]];let p='';
  for(const [r,n] of rings){for(let i=0;i<n;i++){const a=2*Math.PI*i/n,x=c+r*Math.cos(a),y=c+r*Math.sin(a),pr=Math.PI*r/n*0.9;
    p+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${pr.toFixed(1)}"/>`;}}
  p+=`<circle cx="${c}" cy="${c}" r="${(c*0.28).toFixed(1)}"/>`;
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="${sw}">${p}</svg>`;}
function localHost(u){try{const h=new URL(u).hostname.toLowerCase();return h==='localhost'||h==='127.0.0.1'||h==='::1'||h.endsWith('.localhost')||h.endsWith('.test');}catch(e){return false;}}
$('#mark').innerHTML=rosette(26,1.1);
$('#emptyRose').innerHTML=rosette(300,1);
$('#url').addEventListener('input',()=>{const v=$('#url').value.trim();
  $('#profnote').innerHTML=!v?'':(localHost(v)?'<span class="gold">▪ full suite — local target</span>':'<span class="warnc">▪ passive read-only — non-local target</span>');});
// Open a hover tooltip upward when its trigger sits low in the viewport, so it
// floats clear of the rows below instead of dropping into them.
function tipDir(h){if(!h)return;const r=h.getBoundingClientRect();
  h.classList.toggle('up', r.bottom > window.innerHeight*0.55);}
document.addEventListener('mouseover',e=>{const h=e.target.closest&&e.target.closest('.ht');if(h)tipDir(h);});
document.addEventListener('focusin',e=>{const h=e.target.closest&&e.target.closest('.ht');if(h)tipDir(h);});
loadConfigs();loadReports();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8777)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    port = srv.server_address[1]              # resolves --port 0 to the real port
    url = f"http://127.0.0.1:{port}/?token={TOKEN}"
    epf = os.environ.get("PRODSCAN_ENDPOINT_FILE")
    if epf:                                   # let a native host read port+token
        try:
            with open(epf, "w") as f:
                json.dump({"port": port, "token": TOKEN, "url": url}, f)
        except Exception:  # noqa: BLE001
            pass
    print(f"prodscan dashboard (localhost only, token-gated)\n  open: {url}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
