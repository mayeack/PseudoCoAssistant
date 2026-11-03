"""Regression tests for the access-key gate (backend/middleware/access_key.py).

Standalone (no pytest), mirroring the other suites:

    venv/bin/python tests/test_access_gate.py

Guards:
  G1  the gate decides on the ROUTED path (scope["path"]), never request.url —
      Starlette rebuilds request.url from the Host header, so a Host like
      "box/health?x=" made request.url.path read "/health" (a public path)
      while the router served a protected route without the key
  G2  malformed Host headers are refused with 400; every real host form passes
  G3  the gate still works: 401 without the key, through with Basic auth or the
      session cookie, public paths open, preflights pass to CORS
  G4  the post-login redirect stays on this site ("/\\evil" and control
      characters are refused like "//evil")
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import settings  # noqa: E402

KEY = "gate-test-key"
settings.access_key = KEY

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.middleware.access_key import (  # noqa: E402
    AccessKeyMiddleware, COOKIE_NAME, PUBLIC_PATHS, session_token,
)
from backend.routers.auth import _safe_next  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# A minimal app behind the real middleware: one public route, one protected.
app = FastAPI()
app.add_middleware(AccessKeyMiddleware)


@app.get("/health")
def _health():
    return {"status": "ok"}


@app.get("/api/protected")
def _protected():
    return {"protected": True}


c = TestClient(app)


def get(path, host=None, **kw):
    headers = dict(kw.pop("headers", {}) or {})
    if host is not None:
        headers["host"] = host
    return c.get(path, headers=headers, **kw)


# --- G1: a crafted Host header must not reach a protected route ---------------
for crafted in ("testserver/health?x=", "testserver/health#", "testserver/login?",
                "evil.example/favicon.ico?"):
    r = get("/api/protected", host=crafted)
    check(f"G1: Host {crafted!r} does not unlock /api/protected",
          r.status_code in (400, 401) and "protected" not in r.text,
          f"got {r.status_code} {r.text[:80]}")

# --- G2: Host validation -------------------------------------------------------
for good in ("testserver", "localhost:8001", "127.0.0.1:8001", "[::1]:8001",
             "medadvice.yeackbot.com", "i-0816ba8fec02ca87e.splunk.show",
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

print()
if _failures:
    print(f"FAILED {len(_failures)} check(s): {', '.join(_failures)}")
    sys.exit(1)
print("All access-gate checks passed.")
