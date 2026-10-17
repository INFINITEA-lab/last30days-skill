#!/usr/bin/env python3
"""INFINITEA hardening check. Deterministic PASS/FAIL per check; exit 1 on any FAIL.

C6 makes live keyless network calls (HN/Reddit/GitHub); pass --offline to skip it.
"""
from __future__ import annotations

import datetime as dt, json, os, re, runpy, subprocess, sys, tempfile
from pathlib import Path

SKILL = Path(__file__).resolve().parents[2]          # skills/last30days
SCRIPTS = SKILL / "scripts"
REMOVED = ["lib/chrome_cookies.py", "lib/safari_cookies.py", "lib/cookie_extract.py", "lib/agentcookie.py",
           "lib/chrome_cdp.py", "lib/cookie_paths.py", "box_chrome_login.py", "test_device_auth.py"]
MODS = r"(chrome_cookies|safari_cookies|cookie_extract|agentcookie|chrome_cdp|cookie_paths)"
SENSITIVE_PATH = re.compile(r"(Cookies$|cookies\.sqlite|\.binarycookies|Login Data|Keychain|keychain-db|Local State$)")
BAD_EXEC = re.compile(r"(^|/)(security|npx|brew|pbcopy)$")
results: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


# C1 removed modules are gone
missing = [f for f in REMOVED if not (SCRIPTS / f).exists()]
check("C1 cookie/CDP/device-auth modules removed", len(missing) == len(REMOVED), f"{len(missing)}/{len(REMOVED)} absent")

# C2 no static import of removed modules; no live sweet-cookie dynamic import
hits = []
for py in SCRIPTS.rglob("*.py"):
    for i, l in enumerate(py.read_text(errors="ignore").splitlines(), 1):
        s = l.strip()
        if s.startswith("#"):
            continue
        if re.search(rf"^(from\s+\S*\s+import\s+.*\b{MODS}\b|import\s+.*\b{MODS}\b|from\s+\S*\b{MODS}\b\s+import)", s) or \
           re.search(rf"\b{MODS}\.\w+\(", s):
            hits.append(f"{py.relative_to(SKILL)}:{i}")
js = (SCRIPTS / "lib/vendor/bird-search/lib/cookies.js").read_text()
if re.search(r"return\s+import\(\s*'@steipete/sweet-cookie'\s*\)", js):
    hits.append("cookies.js: dynamic import of @steipete/sweet-cookie")
check("C2 no reachable cookie-decrypt import", not hits, ", ".join(hits) or "0 hits")

# Audit hook used by C3/C4: records sensitive opens, forbidden execs, third-party device-flow URLs
events: list[str] = []


def hook(ev, args):
    try:
        if ev == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            p = os.fsdecode(args[0])
            if SENSITIVE_PATH.search(p):
                events.append(f"open {p}")
        elif ev == "subprocess.Popen":
            exe = os.fsdecode(args[0]) if args[0] else ""
            argv0 = os.fsdecode(args[1][0]) if args[1] else ""
            if BAD_EXEC.search(exe) or BAD_EXEC.search(argv0):
                events.append(f"exec {argv0 or exe}")
        elif ev == "urllib.Request" and "scrapecreators.com/v1/github" in str(args[0]):
            events.append(f"url {args[0]}")
    except Exception:
        pass


sys.addaudithook(hook)
sys.path.insert(0, str(SCRIPTS))

# Tripwires for C3/C4: record and block any subprocess, network call, or browser launch, so the
# check is side-effect free even when run against an unhardened (upstream) tree.
import subprocess as _sp, urllib.request as _ur, webbrowser as _wb  # noqa: E402
_real_run = _sp.run


class Tripped(RuntimeError):
    pass


def _trip(kind):
    def f(*a, **k):
        target = a[0] if a else k.get("args") or k.get("url")
        target = getattr(target, "full_url", target)
        events.append(f"{kind} {target if isinstance(target, str) else ' '.join(map(str, target or []))}"[:160])
        raise Tripped(kind)
    return f


def _safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Tripped:
        return "TRIPPED"


def tripwires(on: bool):
    for mod, name, kind in ((_sp, "run", "exec"), (_sp, "Popen", "exec"), (_ur, "urlopen", "net"), (_wb, "open", "browser")):
        if on:
            setattr(mod, f"_orig_{name}", getattr(mod, name))
            setattr(mod, name, _trip(kind))
        else:
            setattr(mod, name, getattr(mod, f"_orig_{name}"))
os.environ.pop("FROM_BROWSER", None)

# C3 env loader with every cookie opt-in set still does no browser reads
tripwires(True)
from lib import env as l30env  # noqa: E402
cfg = {"FROM_BROWSER": "auto", "BROWSER_CONSENT": "true", "AGENTCOOKIE": "on"}
before = len(events)
b = _safe(l30env.cookie_extraction_browsers, dict(cfg))
c = _safe(l30env.extract_browser_credentials, dict(cfg))
_safe(l30env._discover_and_apply_x_credentials, dict(cfg))
xe = _safe(l30env.x_extras_enabled, cfg)
check("C3 env: forced opt-ins yield no browsers/creds/reads",
      b == [] and c == {} and xe is False and len(events) == before,
      f"browsers={b} creds={list(c)} events={events[before:]}")

# C4 setup wizard: consented cookie scan, device flow, auto-installs all inert
from lib import setup_wizard as sw  # noqa: E402
for _n in ("urlopen",):
    if hasattr(sw, _n):
        setattr(sw, _n, _trip("net"))
before = len(events)



r = _safe(sw.run_auto_setup, {}, allow_browser_cookies=True)
r = r if isinstance(r, dict) else {"browser_cookie_scan_attempted": "TRIPPED"}
dev = _safe(sw.run_device_auth)
sf = _safe(sw._start_device_flow) if not sw._existing_scrapecreators_key() else ({"status": "error"}, None)
pub, handle = sf if isinstance(sf, tuple) else ({"status": "TRIPPED"}, "TRIPPED")
check("C4 wizard: no cookie scan, no device flow, no brew/npx",
      r.get("browser_cookie_scan_attempted") is False and not r.get("cookies_found") and dev is None
      and handle is None and pub.get("status") == "error" and len(events) == before
      and r.get("digg_action") != "installed",
      f"scan={r.get('browser_cookie_scan_attempted')} ytdlp={r.get('ytdlp_action')} digg={r.get('digg_action')} "
      f"device={dev} events={events[before:]}")

tripwires(False)

# C5 vendored bird: resolveCredentials never touches browsers
node = os.environ.get("NODE", "node")
probe = ("import('" + (SCRIPTS / "lib/vendor/bird-search/lib/cookies.js").as_uri() + "').then(async m=>{"
         "const r=await m.resolveCredentials({cookieSource:['chrome','safari','firefox']});"
         "console.log(JSON.stringify({src:r.cookies.source,tok:r.cookies.authToken,w:r.warnings}))})")
try:
    out = subprocess.run([node, "-e", probe], capture_output=True, text=True, timeout=30,
                         env={"PATH": os.environ.get("PATH", ""), "HOME": tempfile.mkdtemp()})
    j = json.loads(out.stdout.strip().splitlines()[-1])
    check("C5 bird-search: browser cookie lookup disabled", j["src"] is None and j["tok"] is None,
          f"source={j['src']} warnings={len(j['w'])}")
except Exception as exc:
    check("C5 bird-search: browser cookie lookup disabled", False, f"probe error {exc}")

# C6 keyless live run through the envelope wrapper returns dated, in-window results, no directives
if "--offline" not in sys.argv:
    home = tempfile.mkdtemp()
    p = subprocess.run([sys.executable, str(SCRIPTS / "infinitea/brief.py"), "claude code skills", "--days", "30"],
                       capture_output=True, text=True, timeout=240,
                       env={"PATH": os.environ.get("PATH", ""), "HOME": home, "LANG": "C.UTF-8",
                            "OPENAI_API_KEY": "sk-should-not-pass"})
    txt = p.stdout
    ok_env = txt.startswith('<untrusted_data source="last30days"') and txt.rstrip().endswith("</untrusted_data>")
    body = txt[txt.find("{"):txt.rfind("}") + 1] if ok_env else "{}"
    d = json.loads(body)
    today = dt.date.today()
    dated = [x for x in d.get("results", []) if x.get("published_at")]
    inwin = [x for x in dated if (today - dt.date.fromisoformat(x["published_at"][:10])).days <= 31]
    directives = re.findall(r"LAW \d|STOP and regenerate|SYNTHESIS CONTRACT|PASS-THROUGH FOOTER", body)
    check("C6 keyless envelope run: dated in-window results, no directives",
          ok_env and len(inwin) >= 1 and len(inwin) == len(dated) and not directives,
          f"results={len(d.get('results', []))} dated={len(dated)} in_window={len(inwin)} "
          f"directives={len(directives)} sources={d.get('source_status')}")

# C7 SKILL.md frontmatter validates
t = (SKILL / "SKILL.md").read_text()
m = re.match(r"^---\n(.*?)\n---\n", t, re.S)
fm = dict(re.findall(r"^([a-z_-]+):\s*(.*)$", m.group(1), re.M)) if m else {}
name, desc = fm.get("name", "").strip("\"'"), fm.get("description", "").strip("\"'")
check("C7 SKILL.md frontmatter valid", re.fullmatch(r"[a-z0-9-]{1,64}", name) and 0 < len(desc) <= 1024 and "<" not in desc,
      f"name={name} desc_len={len(desc)}")

for n, ok, det in results:
    print(f"{'PASS' if ok else 'FAIL'}  {n}  [{det}]")
allok = all(ok for _, ok, _ in results)
print("OVERALL", "PASS" if allok else "FAIL")
sys.exit(0 if allok else 1)
