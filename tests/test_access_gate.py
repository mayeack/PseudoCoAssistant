"""Regression tests for the access-key gate (backend/middleware/access_key.py).

Standalone (no pytest), mirroring the other suites:

    venv/bin/python tests/test_access_gate.py

Guards:
  G1  the gate decides on the ROUTED path (scope["path"]), never request.url —
      Starlette rebuilds request.url from the Host header, so a Host like
      "box/health?x=" made request.url.path read "/health" (a public path)
      while the router served a protected route without the key. Starlette
      1.3.1 closes the Host form, but request.url still splits a decoded path
      at a percent-encoded "?" or "#" ("/health%3Fx" reads "/health" while the
      router dispatches "/health?x"), so that form is pinned too
  G2  malformed Host headers are refused with 400; every real host form passes
      (the tunnel hostnames, lab subdomains and localhost health checks)
  G3  the gate still works: 401 without the key, through with Basic auth or the
      session cookie, public paths open, preflights pass to CORS
  G4  the post-login redirect stays on this site ("/\\evil" and control
      characters are refused like "//evil")
  G5  the X-Access-Key header (4.21.0, sent by AI Red Teaming targets to
      /api/chat/completions): the key passes a gated path and anything else is
      401; public paths ignore it; it unlocks what the router actually serves
      and never gets a malformed Host past the 400
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import settings  # noqa: E402
import identity_isolation  # noqa: E402  (no real Duo / CII, whatever .env holds)

identity_isolation.isolate(settings)

KEY = "gate-test-key"
settings.access_key = KEY

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.middleware.access_key import (  # noqa: E402
    ACCESS_KEY_HEADER, AccessKeyMiddleware, COOKIE_NAME, PUBLIC_PATHS, session_token,
)
from backend.routers.auth import _safe_next  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# A minimal app behind the real middleware: one public route, two protected.
app = FastAPI()
app.add_middleware(AccessKeyMiddleware)


@app.get("/health")
def _health():
    return {"status": "ok"}


@app.get("/api/protected")
def _protected():
    return {"protected": True}


# A protected catch-all, the shape an SPA fallback would take. Registered after
# /health so the exact route still wins for "/health" itself.
@app.get("/{page}")
def _page(page: str):
    return {"page": page}


c = TestClient(app)


def get(path, host=None, **kw):
    headers = dict(kw.pop("headers", {}) or {})
    if host is not None:
        headers["host"] = host
    return c.get(path, headers=headers, **kw)


# --- G1: neither a crafted Host nor an encoded ?/# reaches a protected route --
for crafted in ("testserver/health?x=", "testserver/health#", "testserver/login?",
                "evil.example/favicon.ico?"):
    r = get("/api/protected", host=crafted)
    check(f"G1: Host {crafted!r} does not unlock /api/protected",
          r.status_code in (400, 401) and "protected" not in r.text,
          f"got {r.status_code} {r.text[:80]}")
# On Starlette 1.3.1 request.url.path reads "/health" for these while the router
# hands "/health?x" (etc.) to the protected catch-all.
for raw in ("/health%3Fx", "/health%23x", "/login%3Fx", "/favicon.ico%23"):
    r = get(raw)
    check(f"G1: {raw!r} is gated as the route it reaches, not as a public path",
          r.status_code == 401 and "page" not in r.text,
          f"got {r.status_code} {r.text[:80]}")

# --- G2: Host validation -------------------------------------------------------
for good in ("testserver", "localhost", "localhost:8001", "127.0.0.1:8001", "[::1]:8001",
             "pseudocoassistant.com", "pseudocoassistant.com:443",
             "l5-ws1-01.pseudocoassistant.com", "medadvice.yeackbot.com",
             "i-0816ba8fec02ca87e.splunk.show", "host.containers.internal:8001",
             "pseudoco_app:8001"):
    r = get("/health", host=good)
    check(f"G2: valid Host {good!r} is served", r.status_code == 200,
          f"got {r.status_code}")
for bad in ("box/health", "box?x", "box#x", "user@box", "box x", "", "box:80:80"):
    r = get("/health", host=bad)
    check(f"G2: malformed Host {bad!r} -> 400", r.status_code == 400,
          f"got {r.status_code}")

# --- G3: the gate itself -------------------------------------------------------
r = get("/api/protected")
check("G3: no key -> 401", r.status_code == 401, f"got {r.status_code}")
check("G3: API clients get a Basic challenge",
      r.headers.get("www-authenticate", "").lower().startswith("basic"))
r = get("/api/protected", headers={"accept": "text/html"})
check("G3: browsers get the login page link",
      r.status_code == 401 and "/login?next=%2Fapi%2Fprotected" in r.text)
r = get("/api/protected", auth=("x", KEY))
check("G3: Basic auth with the key -> 200", r.status_code == 200, f"got {r.status_code}")
r = get("/api/protected", auth=("x", "wrong"))
check("G3: Basic auth with a wrong key -> 401", r.status_code == 401)
c.cookies.set(COOKIE_NAME, session_token())
r = get("/api/protected")
check("G3: session cookie -> 200", r.status_code == 200, f"got {r.status_code}")
c.cookies.clear()
r = get("/health")
check("G3: public /health needs no key", r.status_code == 200)
check("G3: public paths unchanged", PUBLIC_PATHS == {"/health", "/login", "/favicon.ico"})
r = get("/heal%74h")
check("G3: percent-encoded public path routes and gates the same way",
      r.status_code == 200, f"got {r.status_code}")
r = c.options("/api/protected", headers={"origin": "https://example.com",
                                          "access-control-request-method": "GET"})
check("G3: OPTIONS preflight is not 401'd by the gate", r.status_code != 401,
      f"got {r.status_code}")

# --- G4: post-login redirect target -------------------------------------------
check("G4: local path kept", _safe_next("/app") == "/app")
check("G4: local path with query kept", _safe_next("/settings-ui?tab=hec") == "/settings-ui?tab=hec")
for evil in ("//evil.example", "/\\evil.example", "/\\/evil.example", "https://evil.example",
             "evil.example", "/app\r\nSet-Cookie: x=y", "/app\x00", ""):
    check(f"G4: {evil!r} falls back to the default", _safe_next(evil) == "/app")

# --- G5: the X-Access-Key header ----------------------------------------------
HDR = ACCESS_KEY_HEADER
check("G5: header name unchanged (the red-teaming target config names it)",
      HDR == "X-Access-Key")
r = get("/api/protected", headers={HDR: KEY})
check("G5: valid X-Access-Key -> 200 on a gated path",
      r.status_code == 200 and r.json() == {"protected": True}, f"got {r.status_code}")
r = get("/api/protected", headers={HDR.lower(): KEY})
check("G5: the header name is case-insensitive", r.status_code == 200,
      f"got {r.status_code}")
r = get("/api/protected", headers={HDR: KEY, "authorization": "Bearer unrelated"})
check("G5: an unrelated Bearer Authorization does not void a valid header",
      r.status_code == 200, f"got {r.status_code}")
for wrong in ("wrong", KEY + "x", KEY[:-1], KEY.upper(), ""):
    r = get("/api/protected", headers={HDR: wrong})
    check(f"G5: X-Access-Key {wrong!r} -> 401",
          r.status_code == 401 and "protected" not in r.text, f"got {r.status_code}")
r = get("/api/protected", headers={HDR: b"gate-test-k\xe9y"})
check("G5: a non-ASCII X-Access-Key is refused with 401, not a 500",
      r.status_code == 401, f"got {r.status_code}")
r = get("/api/protected", headers={HDR: "wrong", "accept": "text/html"})
check("G5: a wrong key on a page navigation gets the login link",
      r.status_code == 401 and "/login?next=%2Fapi%2Fprotected" in r.text,
      f"got {r.status_code}")

# Public paths ignore the header: a wrong key never locks them, the right one
# changes nothing.
for label, val in (("wrong", "wrong"), ("valid", KEY)):
    r = get("/health", headers={HDR: val})
    check(f"G5: public /health with a {label} X-Access-Key -> 200",
          r.status_code == 200 and r.json() == {"status": "ok"}, f"got {r.status_code}")
r = c.options("/api/protected", headers={HDR: "wrong", "origin": "https://example.com",
                                          "access-control-request-method": "POST"})
check("G5: a preflight carrying a wrong key is not 401'd", r.status_code != 401,
      f"got {r.status_code}")

# Routed path: the header unlocks what the router serves, and each path is
# gated like the route it reaches ("/api/prot%65cted" is /api/protected,
# "/health%3Fx" is the catch-all, never the public /health). Real hosts are
# gated rather than 400'd, and no key gets a malformed Host past the 400.
r = get("/api/prot%65cted")
check("G5: percent-encoded protected path without a key -> 401",
      r.status_code == 401 and "protected" not in r.text, f"got {r.status_code}")
r = get("/api/prot%65cted", headers={HDR: KEY})
check("G5: percent-encoded protected path with X-Access-Key -> 200",
      r.status_code == 200 and r.json() == {"protected": True}, f"got {r.status_code}")
r = get("/health%3Fx", headers={HDR: "wrong"})
check("G5: '/health%3Fx' with a wrong key -> 401 (not the public /health)",
      r.status_code == 401 and "page" not in r.text, f"got {r.status_code}")
r = get("/health%3Fx", headers={HDR: KEY})
check("G5: '/health%3Fx' with X-Access-Key reaches the route it routes to",
      r.status_code == 200 and r.json() == {"page": "health?x"},
      f"got {r.status_code} {r.text[:80]}")
for tunnel in ("pseudocoassistant.com", "l5-ws1-01.pseudocoassistant.com", "localhost:8001"):
    r = get("/api/protected", host=tunnel)
    check(f"G5: Host {tunnel!r} without a key -> 401 (gated, not 400)",
          r.status_code == 401, f"got {r.status_code}")
    r = get("/api/protected", host=tunnel, headers={HDR: KEY})
    check(f"G5: Host {tunnel!r} with X-Access-Key -> 200", r.status_code == 200,
          f"got {r.status_code}")
for crafted in ("testserver/health?x=", "evil.example/favicon.ico?", "user@box"):
    for label, val in (("valid", KEY), ("wrong", "wrong")):
        r = get("/api/protected", host=crafted, headers={HDR: val})
        check(f"G5: Host {crafted!r} with a {label} X-Access-Key -> 400",
              r.status_code == 400 and "protected" not in r.text,
              f"got {r.status_code} {r.text[:80]}")

# --- G6: review fixes in 4.21.1 ------------------------------------------------
import base64  # noqa: E402
import logging  # noqa: E402

from starlette.requests import Request as _Req  # noqa: E402

from backend.middleware import settings_gate  # noqa: E402
from backend.middleware.access_key import _host_is_valid, keys_match  # noqa: E402
from backend.middleware.request_logging import RequestLoggingMiddleware  # noqa: E402


def _host_req(host: bytes):
    return _Req({"type": "http", "method": "GET", "path": "/health",
                 "headers": [(b"host", host)]})


# Optional whitespace around the Host value (RFC 9112) is not "malformed":
# uvicorn's httptools parser keeps trailing spaces and tabs.
for host in (b"localhost:8001 ", b"localhost:8001\t", b"pseudocoassistant.com  "):
    check(f"G6: Host {host!r} with trailing whitespace is valid", _host_is_valid(_host_req(host)))
for host in (b"box/health?x= ", b"user@box\t"):
    check(f"G6: malformed Host {host!r} is still refused after the strip",
          not _host_is_valid(_host_req(host)))

# A non-ASCII secret is a wrong secret, never a TypeError (a 500).
check("G6: keys_match('café', key) is False", keys_match("café", KEY) is False)
check("G6: keys_match(key, key) is True", keys_match(KEY, KEY) is True)
check("G6: settings code_is_valid('café') is False", settings_gate.code_is_valid("café") is False)
basic = "Basic " + base64.b64encode("x:café".encode("utf-8")).decode("ascii")
r = get("/api/protected", headers={"Authorization": basic})
check("G6: a non-ASCII Basic password -> 401, not 500", r.status_code == 401, f"got {r.status_code}")
bad_cookie = f"{COOKIE_NAME}=caf".encode("ascii") + b"\xc3\xa9"
r = get("/api/protected", headers={"cookie": bad_cookie})
check("G6: a non-ASCII cookie -> 401, not 500", r.status_code == 401, f"got {r.status_code}")
r = get("/api/protected", headers={"cookie": bad_cookie, HDR: KEY})
check("G6: a valid X-Access-Key beside a non-ASCII cookie -> 200", r.status_code == 200,
      f"got {r.status_code}")

# The request log names the path percent-encoded, so an encoded CR/LF cannot
# start a forged line in the plain-text log.
log_app = FastAPI()
log_app.add_middleware(RequestLoggingMiddleware)


@log_app.get("/{p}")
def _logged(p: str):
    return {"p": p}


_lines = []


class _Capture(logging.Handler):
    def emit(self, record):
        _lines.append(record.getMessage())


_cap = _Capture()
_log = logging.getLogger("backend.middleware.request_logging")
_log.addHandler(_cap)
_old_level = _log.level
_log.setLevel(logging.INFO)
TestClient(log_app).get("/x%0D%0A2026-11-05 18:00:00,000 - backend.routers.auth - WARNING - FORGED")
_log.removeHandler(_cap)
_log.setLevel(_old_level)
check("G6: an encoded CR/LF in the path stays on one log line",
      bool(_lines) and all("\r" not in m and "\n" not in m for m in _lines), repr(_lines))
check("G6: the logged path is percent-encoded", any("%0D%0A" in m for m in _lines), repr(_lines))

print()
if _failures:
    print(f"FAILED {len(_failures)} check(s): {', '.join(_failures)}")
    sys.exit(1)
print("All access-gate checks passed.")
