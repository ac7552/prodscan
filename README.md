# Prodscan

A black-box **production-readiness security scanner** for web apps, with a native macOS dashboard.
It probes a *running* app (no source needed), checks it across ~30 security categories, fingerprints
client-side libraries and matches them to known CVEs, and can have an AI write a runnable
proof-of-concept verifier for a finding — all behind a strict authorization gate.

It is built for testing apps **you own or are authorized to test**. The full, intrusive suite only ever
runs against a local host; a non-local URL is automatically restricted to passive, read-only checks.

## Quick start

Needs Python 3.8+ (standard library only — no `pip install`). The desktop app additionally needs macOS
and the Xcode Command Line Tools (`swiftc`).

```bash
# 1) scan from the command line
python3 prodscan.py --target http://localhost:3000            # zero-config, auto-profiled
python3 prodscan.py --config targets/example.json --out-md report.md

# 2) run the dashboard (local, token-gated web UI)
python3 dashboard.py                                          # prints a http://127.0.0.1 URL with a token

# 3) build the native macOS app (embeds the dashboard in a WKWebView window)
./build_app.sh
open ProdscanDashboard.app                                    # or move it to /Applications
```

Copy `targets/example.json` to `targets/<yourapp>.json` and adjust the paths/fields to match your app
(discover them black-box — view the signup/login pages and their forms).

## How to use it

1. **Point it at a target.** In the app, type a URL or pick a config. **Local host** (`localhost`,
   `127.0.0.1`, `*.localhost`, `*.test`) runs the **full suite**; any **non-local URL** is forced to a
   **passive, read-only** profile — the UI tells you which before you run.
2. **Run a scan.** Findings come back as **PASS / FAIL / WARN / INFO / SKIP** with evidence and a fix,
   and the run ends on a **GO / CONDITIONAL / NO-GO** verdict.
3. **Review findings.** Each report shows a verdict badge, KPI tiles, the FAIL/WARN table (with the exact
   request/response signal), and the checks that passed.
4. **Generate a PoC.** On a known-vulnerable-library finding, click **Generate PoC**. With
   `ANTHROPIC_API_KEY` set it uses the Anthropic API to write a CVE-specific verifier; otherwise it emits
   a reviewed stub plus a prompt you (or an LLM) can fill.
5. **Run the PoC.** Click **Run PoC** to execute the verifier and see **CONFIRMED / NOT / COULD-NOT-TEST**.
   PoCs are read-only and self-refuse against non-local targets unless you pass `--i-am-authorized`.

## What it checks

- **Transport & headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, banners
- **Cookies** — HttpOnly / SameSite / Secure / `__Host-` prefixes
- **CORS**, clickjacking, HTTP methods (TRACE/OPTIONS)
- **Error & debug exposure** — verbose stack traces, dotfiles, VCS metadata, admin panels, framework info routes
- **Content discovery** — common unlinked paths
- **Injection** — reflected & stored XSS, SQLi (differential + time-based), SSTI, open redirect, host-header
- **Access control** — read & write IDOR across two accounts, vertical privilege escalation, format-handler (.json) auth bypass
- **Mass assignment** — privileged-field and owner-field injection
- **CSRF** — token enforcement on state-changing forms
- **File upload** — risky content-type / double-extension / path-traversal / SVG
- **Auth flows** — user enumeration, login rate-limiting, password policy, session fixation, logout invalidation, password reset
- **Dependencies** — fingerprints JS libraries (importmap / asset URLs / JS content), matches versions to CVEs via [OSV](https://osv.dev)

## Safety model (by design, not by trust)

- **Host gate:** the full intrusive suite — account creation, data mutation, brute-force, payloads — only runs
  against a local host. A non-local target is forced to passive, read-only checks in both the engine and the UI.
- **No DoS:** every request is rate-limited; the brute-force check is bounded.
- **Non-destructive:** it only ever mutates throwaway accounts/objects it creates itself.
- **Dashboard:** binds to `127.0.0.1` only, requires a per-launch access token (defeats CSRF), and pins
  Host/Origin (defeats DNS rebinding). "Run" launches a validated, fixed command — not an arbitrary shell.
- **PoCs:** generated verifiers are read-only and refuse non-local targets without explicit authorization;
  review the generated code before running it.

## Files

| File | What it is |
|---|---|
| `prodscan.py` | the scanner engine + GO/NO-GO reporting |
| `bbscan.py` | the HTTP client (cookies, redirects, multipart, rate-limiting) |
| `pocgen.py` | the AI/throwaway PoC-verifier generator |
| `dashboard.py` | the local, token-gated web UI + run backend |
| `app/main.swift`, `build_app.sh` | the native macOS WKWebView wrapper |
| `targets/example.json` | target config template |

## Disclaimer

For authorized security testing and production-readiness validation only. Do not point it at systems you do
not own or have explicit permission to test. You are responsible for how you use it.
