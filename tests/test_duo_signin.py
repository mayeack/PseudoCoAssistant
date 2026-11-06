#!/usr/bin/env python3
"""Lab 5 Duo Universal Prompt sign-in (4.22.0, plan 12.1 / PR-2): the
duo_universal wrapper, the sign-in routes, the state and identity cookies, the
redaction of Duo's one-time code, and the frontend hooks.

Covers: the health check (once, at startup, off the event loop, cached for the
duo_signin gate); the canonical-host redirect; the allowlist; the per-username
rate limit; state mismatch / expiry / single use; the username taken only from
the pending state, and Duo's preferred_username matching it; every Duo refusal
mapped to a fixed error code (no traceback even with DEBUG on); an http base
URL turning the gate off; /login unchanged; sign-out (and GET /logout); the
callback code kept out of spans (run.sh) and the uvicorn access log; and the
real duo_universal.Client driven end to end against a fake Duo endpoint.

Side-effect-safe: a temp SQLite database and log directory, the LLM boundary
stubbed, HEC and Agent Observability off, and no network call to Duo or
anything else (a fake client, or the real SDK with its HTTP call replaced).

    .venv/bin/python tests/test_duo_signin.py      # exit 0 = pass
"""
import inspect
import json
import logging
import logging.config
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: E402,F401  (loads .env, CA bundle)
from backend.config import settings  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="pseudoco-duo-signin-test-")
settings.database_url = f"sqlite:///{os.path.join(_TMP, 'signin.db')}"
settings.debug = False
KEY = "duo-signin-test-access-key"
settings.access_key = KEY
settings.prewarm_llm = False
settings.hec_host = ""
for _rate in ("pii_injection_rate", "toxic_injection_rate", "hallucination_injection_rate",
              "authority_injection_rate"):
    setattr(settings, _rate, 0.0)

BASE = "https://testserver"
CLIENT_ID = "DIABCDEFGHIJKLMNOPQR"                       # 20 characters, as Duo issues them
CLIENT_SECRET = "Zx9Lq2Vw7Rt4Yp1Ks8Hd3Fg6Jm0Nb5Cv2Xa7Qe4Tu"[:40]   # 40 characters, as Duo issues them
API_HOST = "api-test0000.duosecurity.com"
ALLOWED = "nina.osei, Avery.Kim,victim.user"


def _configure(**overrides) -> None:
    values = dict(duo_enabled=True, duo_client_id=CLIENT_ID, duo_client_secret=CLIENT_SECRET,
                  duo_api_host=API_HOST, public_base_url=BASE, identity_allowed_users=ALLOWED)
    values.update(overrides)
    for k, v in values.items():
        setattr(settings, k, v)


_configure()

import backend.agents.llm as llm  # noqa: E402
from backend.agents.llm import NormalizedLLMResponse  # noqa: E402


def _fake_llm(*_a, **_k):
    return NormalizedLLMResponse(id="test-id", content="LOW\nAssessment: test. Guidance: rest, fluids.",
                                 model="test-model", input_tokens=5, output_tokens=7, stop_reason="end_turn")


llm.invoke_agent = _fake_llm
llm.invoke_chat = _fake_llm

import jwt  # noqa: E402
from duo_universal import client as duo_sdk  # noqa: E402
from duo_universal.client import DuoException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend import host_capabilities  # noqa: E402
from backend.database import db as dbmod  # noqa: E402
from backend.logging import log_handlers  # noqa: E402
from backend.logging.governance_logger import governance_logger  # noqa: E402
from backend.main import app  # noqa: E402
from backend.middleware import access_key as access_mw  # noqa: E402
from backend.middleware import identity as idmw  # noqa: E402
from backend.models.db_models import IdentitySession  # noqa: E402
from backend.routers import identity_auth  # noqa: E402
from backend.services import identity_signin as signin  # noqa: E402
from backend.services import identity_store as store  # noqa: E402

governance_logger.set_logs_directory(os.path.join(_TMP, "logs"))
H = {"X-Access-Key": KEY}
COOKIE = idmw.COOKIE_NAME
STATE_COOKIE = identity_auth.STATE_COOKIE
_fails = 0
# Every Duo code a test sends; none may ever reach a log, an event or the page.
_CODES_SENT = set()


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


# --- capture every BUILT event (after create_audit_log / create_governance_log) ---
_built = []
_orig_write_log = governance_logger._write_log


def _capture_write_log(log_data, log_type):
    _built.append((log_type, dict(log_data)))
    return _orig_write_log(log_data, log_type)


governance_logger._write_log = _capture_write_log


def _audits(action=None):
    return [e for t, e in _built if t == "audit" and (action is None or e.get("action") == action)]


# --------------------------------------------------------------------------- the fake Duo client
def good_answer(code, username, nonce):
    return {
        "preferred_username": username,
        "nonce": nonce,
        "auth_result": {"result": "allow", "status": "allow", "status_msg": "Login Successful"},
        "auth_context": {"txid": "4a1b2c3d-0000-4000-8000-000000000001", "result": "success",
                         "access_device": {"ip": "203.0.113.50", "location": {"city": "Austin"}}},
    }


class FakeDuo:
    """Stands in for duo_universal.Client; records what the app asked of it."""

    instances = []
    issued = []
    exchanges = []
    health_calls = []
    health_mode = "ok"            # "ok", "hang", or an exception instance to raise
    answer = staticmethod(good_answer)

    def __init__(self, *, client_id, client_secret, host, redirect_uri, duo_certs=None):
        self.client_id, self.client_secret, self.host, self.redirect_uri = (
            client_id, client_secret, host, redirect_uri)
        self.duo_certs = duo_certs
        FakeDuo.instances.append(self)

    def health_check(self):
        FakeDuo.health_calls.append(threading.current_thread())
        mode = FakeDuo.health_mode
        if mode == "hang":
            time.sleep(1.5)
        elif isinstance(mode, BaseException):
            raise mode
        return {"stat": "OK", "response": {"timestamp": 1}}

    def create_auth_url(self, username, state, nonce=None):
        FakeDuo.issued.append({"username": username, "state": state, "nonce": nonce})
        return f"https://{self.host}/oauth/v1/authorize?response_type=code&client_id={self.client_id}&request=x"

    def exchange_authorization_code_for_2fa_result(self, code, username, nonce=None):
        FakeDuo.exchanges.append({"code": code, "username": username, "nonce": nonce,
                                  "thread": threading.current_thread()})
        return FakeDuo.answer(code, username, nonce)


def _reset_fake() -> None:
    FakeDuo.instances.clear(); FakeDuo.issued.clear(); FakeDuo.exchanges.clear()
    FakeDuo.health_calls.clear()
    FakeDuo.health_mode = "ok"
    FakeDuo.answer = staticmethod(good_answer)


def _open_gate() -> None:
    """Healthy Duo, recorded the way the startup check records it."""
    host_capabilities.record_duo_health(True)


def _close_gate(detail: str = "HTTP 503") -> None:
    """Duo down long enough to close the gate: one failed check never does,
    it takes DUO_HEALTH_FAILURES_TO_CLOSE in a row."""
    for _ in range(host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE):
        host_capabilities.record_duo_health(False, detail)


# --------------------------------------------------------------------------- request helpers
def client(base_url: str = BASE) -> TestClient:
    return TestClient(app, base_url=base_url)


def start(c, username, headers=None):
    return c.post("/auth/duo/start", data={"username": username}, headers={**H, **(headers or {})},
                  follow_redirects=False)


def callback(c, state, code="CODE-0001", extra="", headers=None):
    _CODES_SENT.add(code)
    return c.get(f"/auth/duo/callback?duo_code={code}&state={state}{extra}", headers={**H, **(headers or {})},
                 follow_redirects=False)


def sign_in(c, username="nina.osei", code="CODE-0001"):
    r1 = start(c, username)
    state = FakeDuo.issued[-1]["state"] if FakeDuo.issued else ""
    return r1, callback(c, state, code), state


def raw_cookies(response):
    return [v.decode() for k, v in response.headers.raw if k.lower() == b"set-cookie"]


def cookie_header(response, name):
    return next((h for h in raw_cookies(response) if h.startswith(name + "=")), "")


def attrs(header):
    return [a.strip().lower() for a in header.split(";")]


def location(response):
    return response.headers.get("location", "")


def rows(username=None):
    db = dbmod.SessionLocal()
    try:
        q = db.query(IdentitySession)
        if username:
            q = q.filter(IdentitySession.username == username)
        return q.all()
    finally:
        db.close()


def _wipe_sessions() -> None:
    """Start a test from no identity sessions (earlier tests' rows would skew counts)."""
    with dbmod.get_db_context() as db:
        db.query(IdentitySession).delete(synchronize_session=False)
    store.clear_cache()


def _set_pending_age(state: str, seconds: float) -> None:
    key = signin._state_key(state)
    with signin._lock:
        p = signin._pending[key]
        signin._pending[key] = signin.PendingSignin(p.username, p.nonce, p.created - seconds, p.client_address)


# --------------------------------------------------------------------------- health check + gate
def test_startup_health_check(c: TestClient) -> None:
    print("health check: once, at startup, off the event loop, cached for the gate")
    deadline = time.monotonic() + 3.0
    while not signin.gate().get("enabled") and time.monotonic() < deadline:
        time.sleep(0.02)
    check("startup ran Duo's health check exactly once", len(FakeDuo.health_calls) == 1,
          str(len(FakeDuo.health_calls)))
    check("...on a worker thread (not the main thread, not the event loop)",
          FakeDuo.health_calls and FakeDuo.health_calls[0].name == "duo-call"
          and FakeDuo.health_calls[0] is not threading.main_thread(),
          str([t.name for t in FakeDuo.health_calls]))
    check("its result opened the duo_signin gate", signin.gate() == {"enabled": True, "reason": ""},
          str(signin.gate()))
    info = c.get("/api/server-info", headers=H).json()
    check("GET /api/server-info: gated.duo_signin enabled", info["gated"]["duo_signin"]["enabled"] is True)
    inst = FakeDuo.instances[-1]
    check("the client is built from .env settings: id, secret, API host",
          (inst.client_id, inst.client_secret, inst.host) == (CLIENT_ID, CLIENT_SECRET, API_HOST))
    check("...and the CA bundle setting (duo_certs: REQUESTS_CA_BUNDLE's file, else None = Duo's pinning)",
          inst.duo_certs == signin.duo_ca_bundle(), str(inst.duo_certs))
    check("redirect_uri = PUBLIC_BASE_URL + /auth/duo/callback, and nothing else",
          inst.redirect_uri == "https://testserver/auth/duo/callback", inst.redirect_uri)
    for _ in range(3):
        c.get("/login/duo", headers=H)
        c.get("/api/server-info", headers=H)
    check("requests never re-run the health check (the gate reads the cached result)",
          len(FakeDuo.health_calls) == 1, str(len(FakeDuo.health_calls)))
    check("server-info never shows the Web SDK secret", CLIENT_SECRET not in json.dumps(info))


def test_health_check_outcomes() -> None:
    print("health check: failures close the gate with a sanitized reason")
    saved = (signin.HEALTH_TIMEOUT_S,)
    try:
        for exc, expect in (
            (DuoException({"stat": "FAIL", "code": 40002, "message": "invalid_client",
                           "message_detail": f"bad assertion for {CLIENT_SECRET}"}), "Duo answered 40002 invalid_client"),
            (DuoException(ConnectionError(f"https://{API_HOST}/oauth/v1/health_check unreachable")), "ConnectionError"),
            (DuoException(duo_sdk.ERR_CLIENT_SECRET), duo_sdk.ERR_CLIENT_SECRET),
            (DuoException(f"something with {CLIENT_SECRET} in it"), "DuoException"),
        ):
            host_capabilities.reset_duo_health()
            FakeDuo.health_mode = exc
            ok = signin.run_health_check()
            reason = signin.gate()["reason"]
            check(f"failed check -> gate closed: {expect!r}",
                  ok is False and reason == f"Duo health check failed: {expect}", reason)
            check("...and the reason carries no secret, URL or response body",
                  CLIENT_SECRET not in reason and "https://" not in reason and "message_detail" not in reason)
        host_capabilities.reset_duo_health()
        signin.HEALTH_TIMEOUT_S = 0.3
        FakeDuo.health_mode = "hang"
        t0 = time.monotonic()
        ok = signin.run_health_check()
        took = time.monotonic() - t0
        check("a hung Duo: the check gives up at its deadline and the gate stays closed",
              ok is False and took < 1.2 and signin.gate()["reason"].startswith("Duo health check failed: no answer"),
              f"{took:.2f}s {signin.gate()}")

        def _no_sdk(**_kw):
            raise ImportError("No module named 'duo_universal'")

        host_capabilities.reset_duo_health()
        signin.set_client_factory(_no_sdk)
        signin.run_health_check()
        check("duo_universal missing -> the gate says so",
              "duo_universal is not installed" in signin.gate()["reason"], signin.gate()["reason"])
    finally:
        signin.HEALTH_TIMEOUT_S = saved[0]
        signin.set_client_factory(FakeDuo)
        FakeDuo.health_mode = "ok"
        time.sleep(1.3)                          # let the hung fake finish (it holds one call slot)
        host_capabilities.reset_duo_health()
        _open_gate()

    before = len(FakeDuo.instances)
    _configure(duo_enabled=False)
    try:
        check("DUO_ENABLED off: start_health_check does nothing and builds no client",
              signin.start_health_check() is None and len(FakeDuo.instances) == before)
        _configure(public_base_url="http://testserver")
        check("an http PUBLIC_BASE_URL: no health check either",
              signin.start_health_check() is None and len(FakeDuo.instances) == before)
    finally:
        _configure()


# --------------------------------------------------------------------------- /login/duo
def test_login_page() -> None:
    print("GET /login/duo: canonical host, gate rendered server-side, self-contained page")
    c = client()
    r = c.get("/login/duo", headers=H)
    check("canonical host: 200, no-store", r.status_code == 200 and r.headers.get("cache-control") == "no-store")
    check("the gate is open: Continue enabled", 'data-gate="enabled"' in r.text
          and re.search(r'id="continueBtn"[^>]*\sdisabled', r.text) is None)
    check("no placeholder left unrendered", re.search(r"__[A-Z][A-Z_]*__", r.text) is None,
          str(re.findall(r"__[A-Z][A-Z_]*__", r.text)))
    check("an anonymous browser: neither signed in nor holding a revoked session",
          'data-signed-in-as=""' in r.text and 'data-revoked-as=""' in r.text)

    other = client("https://198.51.100.20:8001")
    r = other.get("/login/duo?error=state_mismatch&expired=1&junk=%3Cscript%3E&error2=x", headers=H,
                  follow_redirects=False)
    check("another host: 303 to the canonical PUBLIC_BASE_URL host first, known flags only",
          r.status_code == 303 and location(r) == "https://testserver/login/duo?error=state_mismatch&expired=1",
          location(r))
    r = other.get("/login/duo?error=%3Cscript%3E", headers=H, follow_redirects=False)
    check("an unknown error code is not carried over", location(r) == "https://testserver/login/duo", location(r))
    r = other.post("/auth/duo/start", data={"username": "nina.osei"}, headers=H, follow_redirects=False)
    check("POST /auth/duo/start on another host: back to the canonical sign-in page, no state",
          r.status_code == 303 and location(r) == "https://testserver/login/duo"
          and not cookie_header(r, STATE_COOKIE), location(r))

    _close_gate("HTTP <b>503</b>")
    try:
        r = c.get("/login/duo", headers=H)
        check("gate closed: Continue disabled, the reason as its tooltip (escaped)",
              'data-gate="disabled"' in r.text and re.search(r'id="continueBtn"[^>]*\sdisabled', r.text)
              and "Duo health check failed: HTTP &lt;b&gt;503&lt;/b&gt;" in r.text and "<b>503" not in r.text)
    finally:
        _open_gate()

    _configure(public_base_url="http://testserver")
    try:
        r = c.get("/login/duo", headers=H, follow_redirects=False)
        check("an http PUBLIC_BASE_URL turns the gate off (no redirect, button disabled, reason shown)",
              r.status_code == 200 and 'data-gate="disabled"' in r.text and "PUBLIC_BASE_URL must be https://" in r.text)
    finally:
        _configure()

    page = (ROOT / "frontend" / "login-duo.html").read_text()
    check("login-duo.html is self-contained (no external stylesheet, script, font or image)",
          re.search(r'(src|href)="https?://', page) is None and "@import" not in page
          and "url(" not in page and "<link" not in page)
    check("login-duo.html never writes HTML from the URL (textContent only)", "innerHTML" not in page)
    keys = set(re.findall(r"^\s+([a-z_]+): \"", page.split("const MESSAGES = {", 1)[1].split("};", 1)[0], re.M))
    check("one fixed message per error code, no more, no fewer", keys == set(signin.ERROR_CODES),
          str(sorted(keys ^ set(signin.ERROR_CODES))))
    check("the form posts the username to /auth/duo/start",
          'action="/auth/duo/start"' in page and 'name="username"' in page)
    foot = page[page.index('<div class="foot">'):page.index("</main>")]
    check("the foot: a plain /app link, plus a sign-out form that continues to /app",
          '<a href="/app" class="continue">Continue without signing in</a>' in foot
          and re.search(r'<form method="POST" action="/auth/identity/logout" class="continue">\s*'
                        r'<input type="hidden" name="next" value="/app">', foot) is not None)
    check("...swapped by the server-rendered data-revoked-as alone (CSS, no script needed)",
          ".foot form.continue{display:none" in page
          and '#signin:not([data-revoked-as=""]) .foot a.continue{display:none}' in page
          and '#signin:not([data-revoked-as=""]) .foot form.continue{display:inline}' in page)
    script = page[page.index("<script>"):]
    check("a revoked session gets its own message with the Sign out form (the ?revoked=1 notice steps aside)",
          "const revokedAs = root.dataset.revokedAs;" in script
          and "if (flag === 'revoked' && revokedAs) continue;" in script
          and re.search(r"\} else if \(revokedAs\) \{\s*document\.getElementById\('signedInText'\)\.textContent = "
                        r"'Your verified session as ' \+ revokedAs[^;]*;\s*"
                        r"document\.getElementById\('signedInMsg'\)\.classList\.add\('show'\);", script) is not None)
    msg = page[page.index('id="signedInMsg"'):page.index('action="/auth/duo/start"')]
    check("...and that message box holds the Sign out form", 'action="/auth/identity/logout"' in msg
          and ">Sign out</button>" in msg)
    check("the page needs the room key like every other route (no PUBLIC_PATHS change)",
          access_mw.PUBLIC_PATHS == {"/health", "/login", "/favicon.ico"}
          and c.get("/login/duo", headers={"Accept": "text/html"}).status_code == 401)
    for path, method in (("/auth/duo/start", "post"), ("/auth/duo/callback", "get"),
                         ("/api/identity/me", "get"), ("/auth/identity/logout", "post")):
        check(f"{method.upper()} {path} without the room key -> 401",
              getattr(c, method)(path, follow_redirects=False).status_code == 401)


def test_login_unchanged() -> None:
    print("/login (the room key's own sign-in) is unchanged")
    c = client()
    r = c.get("/login")
    check("GET /login serves login.html as before, without a key",
          r.status_code == 200 and r.text == (ROOT / "frontend" / "login.html").read_text())
    r = c.post("/login", data={"access_code": KEY, "next": "/app"}, follow_redirects=False)
    check("POST /login with the key: 303 + md_access cookie",
          r.status_code == 303 and location(r) == "/app" and cookie_header(r, "md_access"))
    r = c.post("/login", data={"access_code": "wrong", "next": "/app"}, follow_redirects=False)
    check("POST /login with a wrong key: 303 /login?error=1", location(r).startswith("/login?error=1"))


# --------------------------------------------------------------------------- POST /auth/duo/start
def test_start() -> None:
    print("POST /auth/duo/start: allowlist, normalization, state cookie, Duo-only redirect")
    signin.reset()
    c = client()
    n_issued, n_fail = len(FakeDuo.issued), len(_audits("identity_signin_failure"))
    r = start(c, "mallory")
    fails = _audits("identity_signin_failure")
    check("not on IDENTITY_ALLOWED_USERS -> 303 /login/duo?error=not_allowed",
          r.status_code == 303 and location(r) == "/login/duo?error=not_allowed", location(r))
    check("...no Duo prompt URL built and no state cookie",
          len(FakeDuo.issued) == n_issued and not cookie_header(r, STATE_COOKIE))
    check("...one identity_signin_failure event (user, src, reason only)",
          len(fails) == n_fail + 1 and fails[-1].get("user") == "mallory" and fails[-1].get("src") == "testclient"
          and fails[-1].get("details") == {"reason": "not_allowed"}, str(fails[-1:])[:300])
    r = start(c, "bad name!")
    check("a malformed username -> error=invalid_username", location(r) == "/login/duo?error=invalid_username")
    r = start(c, "")
    check("an empty username -> error=invalid_username", location(r) == "/login/duo?error=invalid_username")

    r = start(c, "  Avery.Kim ")
    issued = FakeDuo.issued[-1]
    check("the username is normalized (stripped, lowercased) and matched against the allowlist",
          r.status_code == 303 and issued["username"] == "avery.kim", str(issued))
    check("303 to Duo's prompt on DUO_API_HOST", location(r).startswith(f"https://{API_HOST}/oauth/v1/authorize?"),
          location(r))
    sc = cookie_header(r, STATE_COOKIE)
    a = attrs(sc)
    check("state cookie: __Secure- name, the state, Secure, HttpOnly, SameSite=lax, Path=/auth/duo/, 5 min",
          sc.startswith(f"{STATE_COOKIE}={issued['state']};") and "secure" in a and "httponly" in a
          and "samesite=lax" in a and "path=/auth/duo/" in a and "max-age=300" in a
          and not any(x.startswith("domain") for x in a), sc)
    check("state and nonce are fresh random values Duo accepts (16..1024 characters)",
          16 <= len(issued["state"]) <= 1024 and 16 < len(issued["nonce"] or "") < 1024
          and issued["state"] != issued["nonce"])
    check("the redirect is no-store / no-referrer",
          r.headers.get("cache-control") == "no-store" and r.headers.get("referrer-policy") == "no-referrer")
    r2 = start(client(), "avery.kim", headers={"Host": "testserver", "X-Forwarded-Host": "evil.example"})
    check("the redirect URI never follows the request (X-Forwarded-Host ignored)",
          FakeDuo.instances[-1].redirect_uri == "https://testserver/auth/duo/callback"
          and location(r2).startswith(f"https://{API_HOST}/"))

    for origin in ("https://evil.example", "null"):
        r = start(client(), "nina.osei", headers={"Origin": origin})
        check(f"cross-site POST (Origin {origin}) -> error=bad_origin, no state",
              location(r) == "/login/duo?error=bad_origin" and not cookie_header(r, STATE_COOKIE), location(r))
    r = start(client(), "nina.osei", headers={"Origin": "https://testserver"})
    check("same-origin POST (Origin = PUBLIC_BASE_URL) goes through",
          location(r).startswith(f"https://{API_HOST}/"))

    def _bad_url(**kw):
        fake = FakeDuo(**kw)
        fake.create_auth_url = lambda *a, **k: "https://evil.example/phish"
        return fake

    signin.set_client_factory(_bad_url)
    try:
        r = start(client(), "nina.osei")
        check("a prompt URL off DUO_API_HOST is refused (error=failed), never followed",
              location(r) == "/login/duo?error=failed" and not cookie_header(r, STATE_COOKIE), location(r))
    finally:
        signin.set_client_factory(FakeDuo)

    host_capabilities.reset_duo_health()
    try:
        n_fail = len(_audits("identity_signin_failure"))
        r = start(client(), "nina.osei")
        check("gate closed (health check not passed) -> error=unavailable, no audit event (inert)",
              location(r) == "/login/duo?error=unavailable" and len(_audits("identity_signin_failure")) == n_fail)
    finally:
        _open_gate()
    _configure(duo_enabled=False)
    try:
        n_inst = len(FakeDuo.instances)
        r = start(client(), "nina.osei")
        check("DUO_ENABLED off -> error=unavailable and no Duo client touched",
              location(r) == "/login/duo?error=unavailable" and len(FakeDuo.instances) == n_inst)
    finally:
        _configure()


def test_disabled_persona_refused() -> None:
    print("POST /auth/duo/start refuses a persona Duo reports disabled (read-only Admin API, cached)")
    import httpx
    from backend.services import identity_lookup

    calls = []

    def duo(request):
        calls.append(request)
        name = dict(httpx.QueryParams(request.url.query)).get("username")
        status = "disabled" if name == "victim.user" else "active"
        return httpx.Response(200, json={"stat": "OK", "response": [
            {"username": name, "status": status, "email": f"{name}@pseudocoassistant.com"}]})

    saved = (settings.duo_admin_ikey, settings.duo_admin_skey)
    settings.duo_admin_ikey, settings.duo_admin_skey = "DIWJ8X6AEYOR5OMC6TQ1", "s" * 40
    identity_lookup.set_transport(httpx.MockTransport(duo))
    signin.reset()
    try:
        c = client()
        n_issued = len(FakeDuo.issued)
        r = start(c, "victim.user")
        fails = _audits("identity_signin_failure")
        check("a Duo-disabled persona -> 303 /login/duo?error=duo_denied, no prompt URL built",
              location(r) == "/login/duo?error=duo_denied" and len(FakeDuo.issued) == n_issued, location(r))
        check("...one identity_signin_failure (reason duo_denied), and only a GET to Duo",
              fails[-1].get("user") == "victim.user" and fails[-1].get("details") == {"reason": "duo_denied"}
              and calls and all(q.method == "GET" and q.url.path == "/admin/v1/users" for q in calls))
        r = start(c, "nina.osei")
        check("an active persona still goes to Duo's prompt", location(r).startswith(f"https://{API_HOST}/"))
    finally:
        settings.duo_admin_ikey, settings.duo_admin_skey = saved
        identity_lookup.set_transport(None)
        signin.reset()


def test_rate_limit() -> None:
    print("rate limit: per username (never per IP), first refusal audited once per window")
    signin.reset()
    saved = signin.RATE_LIMIT_STARTS
    signin.RATE_LIMIT_STARTS = 3
    try:
        c = client()
        codes = [location(start(c, "victim.user")) for _ in range(3)]
        check("within the budget: every start reaches Duo", all(x.startswith(f"https://{API_HOST}/") for x in codes))
        n_fail = len(_audits("identity_signin_failure"))
        r4, r5 = start(c, "victim.user"), start(c, "Victim.User")
        check("over the budget -> error=rate_limited (case-insensitive key)",
              location(r4) == location(r5) == "/login/duo?error=rate_limited", f"{location(r4)} {location(r5)}")
        new = _audits("identity_signin_failure")[n_fail:]
        check("only the first refusal in the window writes an audit event",
              len(new) == 1 and new[0].get("details") == {"reason": "rate_limited"} and new[0].get("user") == "victim.user",
              str(new)[:300])
        check("another username from the same IP is unaffected",
              location(start(c, "nina.osei")).startswith(f"https://{API_HOST}/"))
        check("the default budget fits a room signing in as one persona (>= 30 per 5 min)",
              saved >= 30 and signin.RATE_LIMIT_WINDOW_S == 300.0)
    finally:
        signin.RATE_LIMIT_STARTS = saved
        signin.reset()


# --------------------------------------------------------------------------- GET /auth/duo/callback
def test_callback_success() -> None:
    print("GET /auth/duo/callback: a good sign-in")
    signin.reset()
    _wipe_sessions()
    c = client()
    n_ok = len(_audits("identity_signin_success"))
    r1, r, state = sign_in(c, "nina.osei", code="CODE-OK-0001")
    ex = FakeDuo.exchanges[-1]
    check("303 to /app?signin=ok", r.status_code == 303 and location(r) == "/app?signin=ok", location(r))
    check("the exchange got Duo's code, the PENDING username and the pending nonce",
          ex["code"] == "CODE-OK-0001" and ex["username"] == "nina.osei"
          and ex["nonce"] == FakeDuo.issued[-1]["nonce"], str(ex))
    check("the exchange ran on a bounded worker thread, not the request's",
          ex["thread"].name == "duo-call")
    ic = cookie_header(r, COOKIE)
    a = attrs(ic)
    check("identity cookie: __Host- name, Secure, HttpOnly, SameSite=lax, Path=/, TTL, no Domain",
          ic.startswith(f"{COOKIE}=") and "secure" in a and "httponly" in a and "samesite=lax" in a
          and "path=/" in a and f"max-age={store.ttl_minutes() * 60}" in a
          and not any(x.startswith("domain") for x in a), ic)
    sc = cookie_header(r, STATE_COOKIE)
    check("the state cookie is deleted (single use), with its own path",
          "max-age=0" in attrs(sc) and "path=/auth/duo/" in attrs(sc) and "secure" in attrs(sc), sc)
    sess = rows("nina.osei")
    check("one identity session row: username, Duo txid, client address; the cookie only as its hash",
          len(sess) == 1 and sess[0].duo_txid == "4a1b2c3d-0000-4000-8000-000000000001"
          and sess[0].client_address == "testclient"
          and sess[0].token_hash == store.hash_token(ic.split(";")[0].split("=", 1)[1]), str(sess))
    ok = _audits("identity_signin_success")
    check("identity_signin_success: user, src, and only Duo's txid in details (no location or Duo-seen IP)",
          len(ok) == n_ok + 1 and ok[-1].get("user") == "nina.osei" and ok[-1].get("src") == "testclient"
          and ok[-1].get("details") == {"duo_txid": "4a1b2c3d-0000-4000-8000-000000000001"}
          and "Austin" not in json.dumps(ok[-1]) and "203.0.113.50" not in json.dumps(ok[-1]), str(ok[-1:])[:300])

    me = c.get("/api/identity/me", headers=H)
    body = me.json()
    check("GET /api/identity/me: signed in as nina.osei (source duo, times), no-store",
          me.status_code == 200 and body.get("signed_in") is True and body.get("username") == "nina.osei"
          and body.get("source") == "duo" and body.get("expires_at") and me.headers.get("cache-control") == "no-store",
          str(body))
    token = ic.split(";")[0].split("=", 1)[1]
    check("...never the cookie or its hash", token not in me.text and store.hash_token(token) not in me.text)
    page = c.get("/login/duo", headers=H)
    check("the sign-in page knows who is signed in (and holds no revoked session)",
          'data-signed-in-as="nina.osei"' in page.text and 'data-revoked-as=""' in page.text)

    sid = c.post("/api/chat/session/new", headers=H).json()["session_id"]
    r = c.post("/api/chat/message", headers=H,
               json={"session_id": sid, "message": "mild sore throat", "disclaimer_accepted": True})
    gov = [e for t, e in _built if t == "governance" and e.get("session_id") == sid]
    check("a chat turn after a real sign-in carries the username as enduser_id, verified",
          r.status_code == 200 and gov and all(e.get("enduser_id") == "nina.osei"
                                               and e.get("identity_verified") is True for e in gov),
          str([(e.get("enduser_id"), e.get("identity_verified")) for e in gov])[:200])

    # Signing in again (as someone else) replaces the cookie and ends the session behind the old one.
    r1, r, _ = sign_in(c, "avery.kim", code="CODE-OK-0002")
    check("signing in again ends the previous session", location(r) == "/app?signin=ok"
          and rows("nina.osei") == [] and len(rows("avery.kim")) == 1)
    check("...and /api/identity/me now names the new user",
          c.get("/api/identity/me", headers=H).json().get("username") == "avery.kim")


def test_callback_refusals() -> None:
    print("GET /auth/duo/callback: every refusal is a fixed code, never a session")
    signin.reset()
    _wipe_sessions()

    # state mismatch: this browser's cookie holds S1, the callback names S2 (another pending sign-in)
    a, b = client(), client()
    start(a, "nina.osei"); s1 = FakeDuo.issued[-1]["state"]
    start(b, "avery.kim"); s2 = FakeDuo.issued[-1]["state"]
    n_ex = len(FakeDuo.exchanges)
    r = callback(a, s2, code="CODE-MISMATCH-1")
    check("state != this browser's state cookie -> error=state_mismatch, no exchange, no session",
          location(r) == "/login/duo?error=state_mismatch" and len(FakeDuo.exchanges) == n_ex
          and not cookie_header(r, COOKIE) and rows("avery.kim") == [], location(r))
    check("...the other browser's sign-in is left intact",
          location(callback(b, s2, code="CODE-MISMATCH-2")) == "/app?signin=ok")
    r = callback(client(), s1, code="CODE-NOCOOKIE")
    check("no state cookie at all -> error=state_mismatch", location(r) == "/login/duo?error=state_mismatch")

    # single use: replaying a finished sign-in, even with its cookie
    c = client()
    _, ok, st = sign_in(c, "victim.user", code="CODE-REPLAY-1")
    r = callback(client(), st, code="CODE-REPLAY-2", headers={"Cookie": f"{STATE_COOKIE}={st}"})
    check("a used state (replayed with its cookie) -> error=state_expired",
          location(ok) == "/app?signin=ok" and location(r) == "/login/duo?error=state_expired", location(r))

    # expired: older than 5 minutes
    c = client()
    start(c, "nina.osei"); st = FakeDuo.issued[-1]["state"]
    _set_pending_age(st, signin.STATE_TTL_S + 1)
    r = callback(c, st, code="CODE-OLD")
    fails = _audits("identity_signin_failure")
    check("a state older than 5 minutes -> error=state_expired, audited with the pending username",
          location(r) == "/login/duo?error=state_expired" and fails[-1].get("user") == "nina.osei"
          and fails[-1].get("details") == {"reason": "state_expired"}, str(fails[-1:])[:200])

    # the username comes only from the pending state
    c = client()
    start(c, "nina.osei"); st = FakeDuo.issued[-1]["state"]
    r = callback(c, st, code="CODE-QUERYUSER", extra="&username=victim.user&duo_uname=victim.user")
    check("username/duo_uname in the query are ignored: the session is the pending user's",
          location(r) == "/app?signin=ok" and FakeDuo.exchanges[-1]["username"] == "nina.osei"
          and c.get("/api/identity/me", headers=H).json().get("username") == "nina.osei")

    def refused(answer=None, extra="", expect=None, label="", username="nina.osei"):
        cc = client()
        start(cc, username)
        stt = FakeDuo.issued[-1]["state"]
        if answer is not None:
            FakeDuo.answer = staticmethod(answer)
        try:
            n_rows = len(rows())
            rr = callback(cc, stt, code=f"CODE-{expect.upper()}", extra=extra)
        finally:
            FakeDuo.answer = staticmethod(good_answer)
        last = _audits("identity_signin_failure")[-1]
        check(f"{label} -> error={expect}, no session, audited",
              location(rr) == f"/login/duo?error={expect}" and not cookie_header(rr, COOKIE)
              and len(rows()) == n_rows and last.get("details") == {"reason": expect}
              and last.get("user") == username and "max-age=0" in attrs(cookie_header(rr, STATE_COOKIE)),
              f"{location(rr)} {last}")

    def _raise(exc):
        def answer(*_a):
            raise exc
        return answer

    refused(lambda code, user, nonce: dict(good_answer(code, user, nonce), preferred_username="victim.user"),
            expect="username_mismatch", label="Duo signed in a different user (preferred_username)")
    refused(lambda code, user, nonce: dict(good_answer(code, user, nonce), nonce="x" * 40),
            expect="nonce_mismatch", label="the id token's nonce is not the pending one")
    refused(lambda code, user, nonce: dict(good_answer(code, user, nonce),
                                           auth_result={"result": "deny", "status": "deny"}),
            expect="duo_denied", label="auth_result is not allow")
    refused(expect="duo_denied", extra="&error=access_denied&error_description=Denied",
            label="Duo redirected with an error")
    refused(_raise(DuoException({"error": "invalid_grant", "error_description": "code expired"})),
            expect="duo_refused", label="Duo's token endpoint refused the code")
    refused(_raise(DuoException(jwt.InvalidSignatureError("bad"))), expect="duo_refused",
            label="the id token did not verify")
    refused(_raise(DuoException(duo_sdk.requests.ConnectionError("down"))), expect="duo_unavailable",
            label="Duo unreachable")
    refused(_raise(ValueError("Expecting value: line 1 column 1 (char 0)")), expect="duo_unavailable",
            label="a non-JSON error page in front of Duo")
    refused(_raise(DuoException(duo_sdk.ERR_USERNAME)), expect="username_mismatch",
            label="the SDK's own username check")
    refused(_raise(DuoException(duo_sdk.ERR_NONCE)), expect="nonce_mismatch", label="the SDK's own nonce check")

    c = client()
    start(c, "nina.osei"); st = FakeDuo.issued[-1]["state"]
    r = c.get(f"/auth/duo/callback?state={st}", headers=H, follow_redirects=False)
    check("no duo_code -> error=missing_code", location(r) == "/login/duo?error=missing_code", location(r))

    # DEBUG on: an unexpected exception still maps to error=failed, never a traceback page.
    app.debug = True
    try:
        refused(_raise(RuntimeError("boom")), expect="failed", label="an unexpected error with DEBUG on")
    finally:
        app.debug = False

    # a hung Duo: bounded wait
    saved = signin.DUO_CALL_TIMEOUT_S
    signin.DUO_CALL_TIMEOUT_S = 0.3
    try:
        t0 = time.monotonic()
        refused(lambda *a: (time.sleep(1.2), good_answer(*a))[1], expect="duo_unavailable",
                label="Duo hangs on the code exchange")
        check("...answered at the deadline, not when Duo gives up", time.monotonic() - t0 < 1.1)
    finally:
        signin.DUO_CALL_TIMEOUT_S = saved
        time.sleep(1.0)

    # allowlist changed between start and callback
    c = client()
    start(c, "victim.user"); st = FakeDuo.issued[-1]["state"]
    _configure(identity_allowed_users="nina.osei")
    try:
        r = callback(c, st, code="CODE-NOTALLOWED")
        check("re-checked at the callback: no longer allowed -> error=not_allowed",
              location(r) == "/login/duo?error=not_allowed", location(r))
    finally:
        _configure()

    # The duo_signin gate closing between start and callback no longer refuses
    # the callback: test_callback_not_gated.


def test_routes_off_event_loop() -> None:
    print("store / Duo routes are plain def routes (threadpool), never on the event loop")
    for fn in (identity_auth.duo_start, identity_auth.duo_callback, identity_auth.identity_logout,
               identity_auth.identity_me, identity_auth.login_duo_page):
        check(f"{fn.__name__} is a plain def", not inspect.iscoroutinefunction(fn))


# --------------------------------------------------------------------------- sign-out
def test_sign_out() -> None:
    print("sign-out: POST /auth/identity/logout and GET /logout end the session")
    signin.reset()
    _wipe_sessions()
    c = client()
    sign_in(c, "nina.osei", code="CODE-OUT-1")
    r = c.post("/auth/identity/logout", headers={**H, "Origin": "https://evil.example"}, follow_redirects=False)
    check("a cross-site sign-out is refused (403), the session stays",
          r.status_code == 403 and len(rows("nina.osei")) == 1)
    r = c.post("/auth/identity/logout", headers=H, follow_redirects=False)
    dc = cookie_header(r, COOKIE)
    check("POST /auth/identity/logout: 303 /login/duo?signed_out=1, row deleted, cookie deleted (__Host- attrs)",
          r.status_code == 303 and location(r) == "/login/duo?signed_out=1" and rows("nina.osei") == []
          and "max-age=0" in attrs(dc) and "secure" in attrs(dc) and "path=/" in attrs(dc), f"{location(r)} {dc}")
    check("...and the browser is anonymous again", c.get("/api/identity/me", headers=H).json() == {"signed_in": False})

    # a revoked tombstone: every request answers identity_session_revoked until sign-out
    page_h = {**H, "Accept": "text/html,application/xhtml+xml"}

    def revoked_browser(code):
        cc = client()
        sign_in(cc, "victim.user", code=code)
        store.revoke(rows("victim.user")[0].id, reason="duo_disabled")
        return cc

    c = revoked_browser("CODE-OUT-2")
    r = c.get("/api/identity/me", headers=H)
    check("revoked: GET /api/identity/me (the 10 s poll) reaches the tombstone: whose session ended and why",
          r.status_code == 200 and r.json() == {"signed_in": False, "revoked": True, "username": "victim.user",
                                                "revoked_reason": "duo_disabled", "can_unblock": True}, r.text)
    r = c.get("/api/server-info", headers=H)
    check("...while any other request answers 403 identity_session_revoked (the banner's trigger)",
          r.status_code == 403 and r.json() == {"detail": "identity_session_revoked"}, r.text)
    r = c.get("/app", headers=page_h, follow_redirects=False)
    check("revoked: loading the app (a reload, a new tab) goes to /login/duo?revoked=1",
          r.status_code == 303 and location(r) == "/login/duo?revoked=1", location(r))
    page = c.get("/login/duo?revoked=1", headers=page_h)
    check("revoked: the sign-in page still loads, with its gate rendered", page.status_code == 200
          and 'data-gate="enabled"' in page.text)
    check("revoked: the page names the ended session and is not signed in as it",
          'data-revoked-as="victim.user"' in page.text and 'data-signed-in-as=""' in page.text)
    check("...so it offers a way out: the Sign out form and the sign-out-and-continue form",
          page.text.count('action="/auth/identity/logout"') == 2 and 'name="next" value="/app"' in page.text)
    check("...while every other request is still refused (the page attributes nothing)",
          c.get("/api/identity/me", headers=H).json().get("signed_in") is False
          and c.post("/api/chat/session/new", headers=H).status_code == 403)
    check("...and the page offers Unblock me for it (a form to /api/identity/unblock, next=/app)",
          'action="/api/identity/unblock"' in page.text)
    _close_gate()
    try:
        page = c.get("/login/duo?revoked=1", headers=page_h)
        check("revoked with Duo sign-in closed: Continue with Duo disabled, the way out still offered",
              re.search(r'id="continueBtn"[^>]*\sdisabled', page.text) is not None
              and 'data-revoked-as="victim.user"' in page.text
              and re.search(r'class="link"[^>]*\sdisabled', page.text) is None)
    finally:
        _open_gate()
    r = c.post("/auth/identity/logout", headers={**H, "Origin": "https://evil.example"},
               data={"next": "/app"}, follow_redirects=False)
    check("a cross-site sign-and-continue is refused (403), the tombstone stays",
          r.status_code == 403 and len(rows("victim.user")) == 1)

    # way out 1: the message's Sign out -> the sign-in page, signed out
    r = c.post("/auth/identity/logout", headers=H, follow_redirects=False)
    check("revoked: Sign out clears the tombstone", location(r) == "/login/duo?signed_out=1"
          and rows("victim.user") == [] and c.get("/api/identity/me", headers=H).json() == {"signed_in": False})
    page = c.get("/login/duo?signed_out=1", headers=page_h)
    check("...the sign-in page no longer holds a revoked session (the plain /app link is back)",
          'data-revoked-as=""' in page.text and 'data-signed-in-as=""' in page.text)
    r = c.get("/app", headers=page_h, follow_redirects=False)
    check("...and the app loads again, anonymous", r.status_code == 200 and 'id="identityBanner"' in r.text,
          f"{r.status_code} {location(r)}")

    # way out 2: "Continue without signing in" -> signed out, straight to /app
    c = revoked_browser("CODE-OUT-2B")
    r = c.post("/auth/identity/logout", headers=page_h, data={"next": "/app"}, follow_redirects=False)
    dc = cookie_header(r, COOKIE)
    check("revoked: Continue without signing in = sign out, 303 /app, tombstone gone, cookie deleted",
          r.status_code == 303 and location(r) == "/app" and rows("victim.user") == []
          and "max-age=0" in attrs(dc) and "secure" in attrs(dc) and "path=/" in attrs(dc)
          and r.headers.get("cache-control") == "no-store", f"{location(r)} {dc}")
    r = c.get("/app", headers=page_h, follow_redirects=False)
    check("...and /app then loads (no bounce back to the sign-in page)",
          r.status_code == 200 and c.get("/api/identity/me", headers=H).json() == {"signed_in": False},
          f"{r.status_code} {location(r)}")

    # next is honoured only when it is exactly /app
    for i, bad in enumerate(("https://evil.example/", "//evil.example/app", "/app/../settings-ui", "/settings-ui",
                             "/app?x=1", "/APP", " /app", "")):
        c = revoked_browser(f"CODE-OUT-NEXT-{i}")
        r = c.post("/auth/identity/logout", headers=H, data={"next": bad}, follow_redirects=False)
        check(f"next={bad!r}: ignored, the sign-in page as usual (tombstone still ended)",
              location(r) == "/login/duo?signed_out=1" and rows("victim.user") == [], location(r))

    # GET /logout (the room-key sign-out) ends the identity session too
    c = client()
    sign_in(c, "avery.kim", code="CODE-OUT-3")
    r = c.get("/logout", headers=H, follow_redirects=False)
    check("GET /logout: room cookie and identity cookie deleted, identity row gone",
          location(r) == "/login" and "max-age=0" in attrs(cookie_header(r, "md_access"))
          and "max-age=0" in attrs(cookie_header(r, COOKIE)) and rows("avery.kim") == [], str(raw_cookies(r)))
    r = client().get("/logout", headers=H, follow_redirects=False)
    check("GET /logout without an identity cookie: unchanged (no identity cookie header)",
          location(r) == "/login" and not cookie_header(r, COOKIE))


# --------------------------------------------------------------------------- the code stays out of telemetry and logs
def _run_sh_block() -> str:
    """run.sh's exclusion lines: inside the opentelemetry-instrument branch,
    before its exec. Empty when they are missing (the checks then fail)."""
    text = (ROOT / "run.sh").read_text()
    try:
        otel = text[text.index("if grep -q '^OTEL_EXPORTER_OTLP_ENDPOINT=."):text.index("exec opentelemetry-instrument")]
        start_ = otel.index('    export OTEL_PYTHON_EXCLUDED_URLS=')
        return otel[start_:otel.index("    fi\n", start_) + len("    fi\n")]
    except ValueError:
        return ""


def test_redaction() -> None:
    print("Duo's one-time code: no span (run.sh), redacted in the uvicorn access log")
    block = _run_sh_block()
    check("run.sh: inside the opentelemetry-instrument branch, before exec, the callback path is excluded",
          "auth/duo/callback" in block)
    script = block + '\nprintf "%s|%s" "${OTEL_PYTHON_EXCLUDED_URLS-}" "${OTEL_PYTHON_FASTAPI_EXCLUDED_URLS-UNSET}"\n'

    def run(env):
        base = {k: v for k, v in os.environ.items() if not k.startswith("OTEL_PYTHON_")}
        out = subprocess.run(["bash", "-c", script], env={**base, **env}, capture_output=True, text=True, timeout=10)
        return out.stdout

    check("nothing set in .env -> OTEL_PYTHON_EXCLUDED_URLS=auth/duo/callback",
          run({}) == "auth/duo/callback|UNSET", run({}))
    check("appended to what .env set (the runbook's /health regex kept)",
          run({"OTEL_PYTHON_EXCLUDED_URLS": "^(https?://)?[^/]+/health$"})
          == "^(https?://)?[^/]+/health$,auth/duo/callback|UNSET")
    check("a FastAPI-specific list (which wins over the generic one) gets the path too",
          run({"OTEL_PYTHON_FASTAPI_EXCLUDED_URLS": "health"}) == "auth/duo/callback|health,auth/duo/callback")

    value = "^(https?://)?[^/]+/health$,auth/duo/callback"
    probe = (
        "from opentelemetry.instrumentation import fastapi as f\n"
        "u = f._excluded_urls_from_env\n"
        "print(u.url_disabled('https://l5.pseudocoassistant.com/auth/duo/callback?duo_code=x&state=y'),"
        " u.url_disabled('https://l5.pseudocoassistant.com/app'),"
        " u.url_disabled('https://l5.pseudocoassistant.com/health'))\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("OTEL_PYTHON_")}
    out = subprocess.run([sys.executable, "-c", probe], env={**env, "OTEL_PYTHON_EXCLUDED_URLS": value},
                         capture_output=True, text=True, timeout=60, cwd=_TMP)
    check("the FastAPI instrumentation reads that list: callback excluded, /app traced, /health still excluded",
          out.stdout.strip() == "True False True", out.stdout + out.stderr[-300:])

    access = logging.getLogger("uvicorn.access")
    check("the redaction filter is on uvicorn's access logger after the app is imported",
          any(isinstance(f, log_handlers.DuoCallbackRedactionFilter) for f in access.filters))
    import uvicorn.config

    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)   # what uvicorn.run does at start
    check("...and survives uvicorn's logging dictConfig",
          any(isinstance(f, log_handlers.DuoCallbackRedactionFilter) for f in access.filters))
    log_handlers.install_access_log_redaction()
    check("installing it again does not stack filters",
          sum(isinstance(f, log_handlers.DuoCallbackRedactionFilter) for f in access.filters) == 1)
    lines = []

    class _Grab(logging.Handler):
        def emit(self, record):
            lines.append(self.format(record))

    grab = _Grab()
    access.addHandler(grab)
    prev = access.level
    access.setLevel(logging.INFO)
    try:
        secret = "CODE-ACCESSLOG-SECRET"
        _CODES_SENT.add(secret)
        # Exactly uvicorn's call (protocols/http/h11_impl.py).
        access.info('%s - "%s %s HTTP/%s" %d', "198.51.100.7:5000", "GET",
                    f"/auth/duo/callback?duo_code={secret}&state=abc", "1.1", 303)
        access.info('%s - "%s %s HTTP/%s" %d', "198.51.100.7:5000", "GET", "/app?signin=ok", "1.1", 200)
    finally:
        access.removeHandler(grab)
        access.setLevel(prev)
    check("the callback line keeps its path, its query is [redacted]",
          lines and 'GET /auth/duo/callback?[redacted] HTTP/1.1" 303' in lines[0] and secret not in lines[0],
          str(lines[:1]))
    check("other paths are logged as before", len(lines) == 2 and "/app?signin=ok" in lines[1])
    check("redact_callback_query on a free-form message",
          log_handlers.redact_callback_query("x https://h/auth/duo/callback?duo_code=1&state=2 y")
          == "x https://h/auth/duo/callback?[redacted] y")


# --------------------------------------------------------------------------- the real SDK, no network
class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.content = json.dumps(payload).encode()

    def json(self):
        return self._payload


def test_real_sdk() -> None:
    print("the real duo_universal.Client end to end, its HTTP call replaced by a fake Duo")
    signin.reset()
    calls, box = [], {"secret": CLIENT_SECRET, "claims": {}}

    def fake_post(url, data=None, params=None, headers=None, verify=None, proxies=None, timeout=None):
        calls.append({"url": url, "data": data, "params": params, "verify": verify, "timeout": timeout})
        if url == f"https://{API_HOST}/oauth/v1/health_check":
            jwt.decode(data["client_assertion"], CLIENT_SECRET, algorithms=["HS512"], audience=url)
            return _Resp(200, {"stat": "OK", "response": {"timestamp": int(time.time())}})
        if url == f"https://{API_HOST}/oauth/v1/token":
            now = int(time.time())
            claims = {"iss": url, "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                      "preferred_username": "nina.osei", "nonce": box["nonce"],
                      "auth_result": {"result": "allow", "status": "allow", "status_msg": "Login Successful"},
                      "auth_context": {"txid": "5b2c3d4e-0000-4000-8000-000000000002"}}
            claims.update(box["claims"])
            return _Resp(200, {"id_token": jwt.encode(claims, box["secret"], algorithm="HS512"),
                               "access_token": "a", "expires_in": 300, "token_type": "Bearer"})
        return _Resp(404, {"stat": "FAIL", "code": 40400, "message": "Not found"})

    def begin_flow(c):
        r = start(c, "Nina.Osei")
        q = parse_qs(urlsplit(location(r)).query)
        req = jwt.decode(q["request"][0], CLIENT_SECRET, algorithms=["HS512"], audience=f"https://{API_HOST}")
        box["nonce"] = q["nonce"][0]
        return r, q, req

    real_requests = duo_sdk.requests
    duo_sdk.requests = SimpleNamespace(post=fake_post)
    signin.set_client_factory(None)
    try:
        host_capabilities.reset_duo_health()
        check("the health check through the real SDK passes and opens the gate",
              signin.run_health_check() is True and signin.gate()["enabled"] is True, str(signin.gate()))
        trust = signin.duo_ca_bundle() or duo_sdk.DEFAULT_CA_CERT_PATH
        check("...TLS checked against REQUESTS_CA_BUNDLE when it names a file, else Duo's pinned bundle",
              bool(calls) and calls[-1]["verify"] == trust, str(calls[-1:])[:300])
        check("...with a timeout on the SDK's HTTP call (the SDK sets none and takes none)",
              bool(calls) and calls[-1]["timeout"] == signin.DUO_HTTP_TIMEOUT
              and isinstance(duo_sdk.requests, signin._TimedRequests), str(calls[-1:])[:300])
        c = client()
        r, q, req = begin_flow(c)
        check("the prompt URL is Duo's authorize endpoint for this client",
              location(r).startswith(f"https://{API_HOST}/oauth/v1/authorize?") and q["client_id"] == [CLIENT_ID])
        check("its signed request: redirect_uri from PUBLIC_BASE_URL, the normalized username, our state",
              req["redirect_uri"] == "https://testserver/auth/duo/callback" and req["duo_uname"] == "nina.osei"
              and cookie_header(r, STATE_COOKIE).startswith(f"{STATE_COOKIE}={req['state']};"), str(req))
        r = callback(c, req["state"], code="REALSDK-CODE-1")
        tok = [x for x in calls if x["url"].endswith("/oauth/v1/token")][-1]
        check("the exchange posts Duo's code with the same redirect_uri, the same TLS trust, a timeout",
              tok["params"]["code"] == "REALSDK-CODE-1"
              and tok["params"]["redirect_uri"] == "https://testserver/auth/duo/callback"
              and tok["verify"] == trust and tok["timeout"] == signin.DUO_HTTP_TIMEOUT,
              str(tok["params"])[:200])
        check("Duo's signed token (allow, our nonce, our user) signs the browser in",
              location(r) == "/app?signin=ok" and c.get("/api/identity/me", headers=H).json().get("username") == "nina.osei"
              and rows("nina.osei")[0].duo_txid == "5b2c3d4e-0000-4000-8000-000000000002", location(r))

        for label, change, expect in (
            ("a token for another user", {"claims": {"preferred_username": "victim.user"}}, "username_mismatch"),
            ("a token with another nonce", {"claims": {"nonce": "n" * 40}}, "nonce_mismatch"),
            ("a token not signed with the Web SDK secret", {"secret": "W" * 40}, "duo_refused"),
            ("an expired token", {"claims": {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 3700}},
             "duo_refused"),
            ("a deny result", {"claims": {"auth_result": {"result": "deny", "status": "deny"}}}, "duo_denied"),
        ):
            box.update(secret=CLIENT_SECRET, claims={})
            box.update(change)
            cc = client()
            _, _, req = begin_flow(cc)
            rr = callback(cc, req["state"], code="REALSDK-CODE-2")
            check(f"real SDK, {label} -> error={expect}", location(rr) == f"/login/duo?error={expect}"
                  and not cookie_header(rr, COOKIE), location(rr))
        box.update(secret=CLIENT_SECRET, claims={})
    finally:
        duo_sdk.requests = real_requests
        signin.set_client_factory(FakeDuo)
        host_capabilities.reset_duo_health()
        _open_gate()


# --------------------------------------------------------------------------- frontend hooks
def test_frontend() -> None:
    print("frontend: identity badge, #identityBanner, the single fetch wrapper, cache-buster")
    page = client().get("/app", headers=H).text
    js = (ROOT / "frontend" / "js" / "chat.js").read_text()
    row = page[page.index('id="appSubtitle"'):page.index('id="sessionId"')]
    check("the identity badge sits in the Session ID row, hidden by default",
          re.search(r'<span id="identityBadge" class="hidden[ "]', row) is not None)
    badge = page[page.index('id="identityBadge"'):page.index('id="identitySignin"')]
    check("...the persona in neutral colours, a trust pill, and a Sign out form",
          'id="identityUser"' in badge and "text-gray-700" in badge and 'id="identityTrust"' in badge
          and 'action="/auth/identity/logout"' in badge)
    check("#identityBanner sits beside #emergencyBanner, hidden by default",
          re.search(r'<div id="identityBanner" class="hidden ', page) is not None
          and 0 < page.index('id="emergencyBanner"') - page.index('id="identityBanner"') < 4000)
    check("chat.js cache-buster bumped to v=38", "/static/js/chat.js?v=38" in page)
    check("chat.js: exactly ONE fetch wrapper, around window.fetch",
          js.count("window.fetch =") == 1 and "const _pageFetch = window.fetch.bind(window);" in js
          and js.count("_pageFetch(") == 1)
    check("...which raises the banner on identity_session_revoked (and _expired) from any request",
          "detail === 'identity_session_revoked') showIdentityBanner('revoked')" in js
          and "detail === 'identity_session_expired') showIdentityBanner('expired')" in js)
    refresh = re.search(r"function refreshIndicators\(\) \{(.*?)\n\}", js, re.S).group(1)
    check("refreshIdentity runs on the existing 10 s poll (refreshIndicators)",
          "refreshIdentity()" in refresh and "setInterval(refreshIndicators, 10000)" in js)
    consume = re.search(r"function consumeSigninRedirect\(\) \{(.*?)\n\}", js, re.S).group(1)
    check("a successful sign-in clears medadvice_session_id and the recent sessions list",
          "localStorage.removeItem('medadvice_session_id')" in consume
          and "localStorage.removeItem(RECENT_SESSIONS_KEY)" in consume
          and "params.get('signin') !== 'ok'" in consume and "history.replaceState" in consume)
    check("...first thing on page load", re.search(
        r"DOMContentLoaded', function\(\) \{\s*(//[^\n]*\n\s*)*consumeSigninRedirect\(\);", js) is not None)
    check("the Sign in link follows gated.duo_signin; pill colours only via classList",
          "gateFor('duo_signin')" in js and "rounded-full bg-" not in js)
    check("the callback lands where chat.js looks", identity_auth.SIGNED_IN_REDIRECT == "/app?signin=ok")


# --------------------------------------------------------------------------- nothing leaked
_root_lines = []


class _RootGrab(logging.Handler):
    """Every app log line. Not httpx's: that is this test's own TestClient
    logging the URLs it requests, which no app process does for inbound ones."""

    def emit(self, record):
        if record.name.startswith("httpx"):
            return
        try:
            _root_lines.append(record.getMessage())
        except Exception:  # noqa: BLE001
            pass


logging.getLogger().addHandler(_RootGrab(level=logging.DEBUG))


def test_no_leaks() -> None:
    print("no Duo code or Web SDK secret in any log line, log file or built event")
    blob = json.dumps([e for _, e in _built], default=str)
    files = "".join(p.read_text(errors="ignore") for p in Path(_TMP, "logs").glob("*") if p.is_file())
    lines = "\n".join(_root_lines)
    leaked = sorted(code for code in _CODES_SENT if code in blob or code in files or code in lines)
    check(f"none of the {len(_CODES_SENT)} Duo codes sent appears anywhere", not leaked, str(leaked))
    check("the Web SDK secret appears nowhere",
          CLIENT_SECRET not in blob and CLIENT_SECRET not in files and CLIENT_SECRET not in lines)


# --------------------------------------------------------------------------- stage-review fixes
class _LocalDuo(BaseHTTPRequestHandler):
    """A fake Duo on 127.0.0.1 (plain http; the SDK's endpoint templates are
    pointed at it). Answers the health check and the token exchange the way
    Duo does, sets a load-balancer cookie, and echoes /echo for httpx."""

    nonce = ""
    seen_tokens = []

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", f"duo_lb={LB_COOKIE}; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parts = urlsplit(self.path)
        self.rfile.read(int(self.headers.get("content-length") or 0))
        host = self.headers.get("host")
        if parts.path == "/oauth/v1/health_check":
            return self._send(200, {"stat": "OK", "response": {"timestamp": int(time.time())}})
        if parts.path == "/oauth/v1/token":
            q = parse_qs(parts.query)
            endpoint = f"http://{host}/oauth/v1/token"
            jwt.decode(q["client_assertion"][0], CLIENT_SECRET, algorithms=["HS512"], audience=endpoint)
            _LocalDuo.seen_tokens.append(q["code"][0])
            now = int(time.time())
            claims = {"iss": endpoint, "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                      "preferred_username": "nina.osei", "nonce": _LocalDuo.nonce,
                      "auth_result": {"result": "allow", "status": "allow"},
                      "auth_context": {"txid": "6c3d4e5f-0000-4000-8000-000000000003"}}
            return self._send(200, {"id_token": jwt.encode(claims, CLIENT_SECRET, algorithm="HS512"),
                                    "access_token": "ACCESS-TOKEN-FROM-DUO-1234", "expires_in": 300})
        return self._send(404, {"stat": "FAIL", "code": 40400})

    def do_GET(self):
        return self._send(200, {"ok": True, "access_token": "ECHO-ACCESS-TOKEN-5678"})

    def log_message(self, *_a):
        pass


LB_COOKIE = "LBCOOKIE-SECRET-VALUE-9012"


class _Capture(logging.Handler):
    """Every formatted line, as the app's own log handler would write it."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        self.lines = []

    def emit(self, record):
        self.lines.append((record.name, self.format(record)))


def test_debug_log_redaction() -> None:
    print("LOG_LEVEL=DEBUG: no Duo code, assertion, cookie, token or secret in any log line")
    from backend.logging import redaction

    check("the redacting log record factory is installed at app import (setup_logging)", redaction.installed())
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalDuo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    cap = _Capture()
    root = logging.getLogger()
    saved_level = root.level
    saved_templates = (duo_sdk.OAUTH_V1_TOKEN_ENDPOINT, duo_sdk.OAUTH_V1_HEALTH_CHECK_ENDPOINT)
    saved_env = {k: os.environ.get(k) for k in ("NO_PROXY", "no_proxy")}
    code = "LOCALDUO-CODE-4c1f9a"
    _CODES_SENT.add(code)
    root.addHandler(cap)
    root.setLevel(logging.DEBUG)
    duo_sdk.OAUTH_V1_TOKEN_ENDPOINT = "http://{}/oauth/v1/token"
    duo_sdk.OAUTH_V1_HEALTH_CHECK_ENDPOINT = "http://{}/oauth/v1/health_check"
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    _configure(duo_api_host=f"127.0.0.1:{port}")
    signin.set_client_factory(None)
    signin.reset()
    try:
        host_capabilities.reset_duo_health()
        check("the real SDK's health check, through real requests/urllib3, passes",
              signin.run_health_check() is True, str(signin.gate()))
        c = client()
        r = start(c, "nina.osei")
        q = parse_qs(urlsplit(location(r)).query)
        _LocalDuo.nonce = q["nonce"][0]
        state = jwt.decode(q["request"][0], CLIENT_SECRET, algorithms=["HS512"],
                           audience=f"https://127.0.0.1:{port}")["state"]
        r = callback(c, state, code=code)
        check("a sign-in through the real SDK and urllib3 succeeds with redaction on",
              location(r) == "/app?signin=ok" and _LocalDuo.seen_tokens[-1:] == [code], location(r))

        import httpx

        with httpx.Client(timeout=5) as hc:
            hc.get(f"http://127.0.0.1:{port}/echo?access_token=QUERY-TOKEN-3456&username=nina.osei",
                   headers={"Authorization": "Bearer BEARER-TOKEN-7890abcdef"})
    finally:
        root.removeHandler(cap)
        root.setLevel(saved_level)
        duo_sdk.OAUTH_V1_TOKEN_ENDPOINT, duo_sdk.OAUTH_V1_HEALTH_CHECK_ENDPOINT = saved_templates
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        server.shutdown()
        _configure()
        signin.set_client_factory(FakeDuo)
        signin.reset()
        host_capabilities.reset_duo_health()
        _open_gate()

    text = "\n".join(line for _, line in cap.lines)
    token_lines = [line for name, line in cap.lines
                   if name.startswith("urllib3") and "/oauth/v1/token?" in line]
    check("urllib3 did log the token request line at DEBUG (the path the finding was about)",
          len(token_lines) == 1, str(len(token_lines)))
    check("...with code and client_assertion kept as keys, their values [REDACTED]",
          bool(token_lines) and "code=[REDACTED]" in token_lines[0]
          and "client_assertion=[REDACTED]" in token_lines[0], (token_lines or [""])[0][:300])
    leaks = {name: value for name, value in (
        ("the Duo code", code), ("a JWT (client_assertion / id_token)", "eyJ"),
        ("the Web SDK secret", CLIENT_SECRET), ("Duo's cookie", LB_COOKIE),
        ("the query token", "QUERY-TOKEN-3456"), ("the bearer token", "BEARER-TOKEN-7890abcdef"),
        ("the echoed token", "ECHO-ACCESS-TOKEN-5678")) if value in text}
    check("none of them in any captured line", not leaks, str(sorted(leaks)))
    check("httpcore's DEBUG response headers were logged, the Set-Cookie value [REDACTED]",
          any(n.startswith("httpcore") and "(b'Set-Cookie', b'[REDACTED]')" in l for n, l in cap.lines))
    check("httpx's request line keeps the URL, its query values [REDACTED]",
          any(n == "httpx" and "/echo?access_token=[REDACTED]&username=[REDACTED]" in l for n, l in cap.lines))


class _Records(logging.Handler):
    """Every record object, for formatters that read ``record.args``."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def test_redaction_rules() -> None:
    print("redaction: child loggers, tracebacks, other loggers by pattern and configured secret, structure kept")
    from uvicorn.logging import AccessFormatter

    from backend.logging import redaction

    cap = _Capture()
    recs = _Records()
    root = logging.getLogger()
    root.addHandler(cap)
    saved_level = root.level
    root.setLevel(logging.DEBUG)
    _CODES_SENT.update({"ACCESS-ARG-CODE-3", "SPLIT-CODE-4"})
    try:
        child = logging.getLogger("urllib3.brand_new_child_" + str(os.getpid()))
        child.debug('%s "%s %s"', "https://h:443", "POST", "/oauth/v1/token?code=CHILD-CODE-1&state=s")
        try:
            raise ValueError("Max retries exceeded with url: /oauth/v1/token?code=TRACE-CODE-2&client_assertion=x")
        except ValueError:
            logging.getLogger("requests.adapters").exception("connection failed")
        access = logging.getLogger("uvicorn.access")
        saved_access = (access.level, access.propagate)
        access.setLevel(logging.INFO)
        access.propagate = False         # as uvicorn configures it: its own handler only
        access.addHandler(cap)
        access.addHandler(recs)
        try:
            access.info('%s - "%s %s HTTP/%s" %d', "198.51.100.7:5000", "GET",
                        f"/app?x={CLIENT_SECRET}&code=ACCESS-ARG-CODE-3&signin=ok", "1.1", 200)
        finally:
            access.removeHandler(cap)
            access.removeHandler(recs)
            access.setLevel(saved_access[0])
            access.propagate = saved_access[1]
        other = logging.getLogger("some.other.module")
        other.info("plain %s, status_code=%d, ?k=v, exit code=1 state=open", "words", 200)
        # A credential the format string and its argument only make up together.
        other.warning("redirected to /auth/duo/callback?duo_code=%s", "SPLIT-CODE-4")
    finally:
        root.removeHandler(cap)
        root.setLevel(saved_level)
    text = "\n".join(line for _, line in cap.lines)
    check("a child logger created after install is redacted too (filters on 'urllib3' alone would miss it)",
          "CHILD-CODE-1" not in text and "code=[REDACTED]" in text)
    check("a traceback logged with exc_info is redacted", "TRACE-CODE-2" not in text
          and any("Max retries exceeded" in l and "code=[REDACTED]" in l for _, l in cap.lines))
    acc = [l for n, l in cap.lines if n == "uvicorn.access"]
    check("another logger: the configured secret and the code= value go, other parameters stay "
          "(uvicorn's access log)",
          len(acc) == 1 and CLIENT_SECRET not in acc[0] and "ACCESS-ARG-CODE-3" not in acc[0]
          and 'GET /app?x=[REDACTED]&code=[REDACTED]&signin=ok HTTP/1.1" 200' in acc[0], str(acc)[:300])
    fmt = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
    line = fmt.format(recs.records[0]) if len(recs.records) == 1 else ""
    check("...its argument tuple is kept, so uvicorn's own AccessFormatter still formats it",
          isinstance(recs.records[0].args, tuple) and len(recs.records[0].args) == 5
          and line == '198.51.100.7:5000 - "GET /app?x=[REDACTED]&code=[REDACTED]&signin=ok HTTP/1.1" 200 OK',
          line)
    check("...a code split across the format string and its argument is redacted too",
          "SPLIT-CODE-4" not in text and any(l.endswith("/auth/duo/callback?duo_code=[REDACTED]")
                                             for _, l in cap.lines))
    check("...and ordinary lines elsewhere are left alone (code= / state= outside a query are text)",
          any(l.endswith("plain words, status_code=200, ?k=v, exit code=1 state=open") for _, l in cap.lines))
    for raw, want in (
        ("POST /x?grant_type=authorization_code&code=A1&client_assertion=eyJa.eyJb.c HTTP/1.1",
         "POST /x?grant_type=[REDACTED]&code=[REDACTED]&client_assertion=[REDACTED] HTTP/1.1"),
        ("[(b'Set-Cookie', b'sid=1; Path=/'), (b'Content-Type', b'text/plain')]",
         "[(b'Set-Cookie', b'[REDACTED]'), (b'Content-Type', b'text/plain')]"),
        ("{'Authorization': 'Bearer abcdefgh', 'Accept': '*/*'}", "{'Authorization': '[REDACTED]', 'Accept': '*/*'}"),
        ('{"access_token": "t0k3n-abc", "expires_in": 3600, "code": 40002}',
         '{"access_token": "[REDACTED]", "expires_in": 3600, "code": 40002}'),
        ("Cookie: a=b; c=d", "Cookie: [REDACTED]"),
        ("client_secret=abc123xyz status_code=401 response_type=code", "client_secret=[REDACTED] status_code=401 response_type=code"),
    ):
        got = redaction.redact(raw)
        check(f"redact: {raw[:48]!r}", got == want and redaction.redact(got) == got, got)


def test_rate_limit_order_and_eviction() -> None:
    print("rate limit: the allowlist first; the per-username table evicts one name at a time (LRU)")
    signin.reset()
    saved = (signin.RATE_LIMIT_STARTS, signin._RATE_KEYS_MAX)
    signin.RATE_LIMIT_STARTS = 2
    try:
        c = client()
        for _ in range(2):
            start(c, "victim.user")
        check("victim.user has spent its budget", location(start(c, "victim.user")) == "/login/duo?error=rate_limited")
        r = start(c, "not.on.the.list")
        check("a name not on the allowlist -> not_allowed, and it takes no rate slot",
              location(r) == "/login/duo?error=not_allowed" and "not.on.the.list" not in signin._starts,
              str(list(signin._starts)))
        for i in range(signin._RATE_KEYS_MAX + 50):        # the flood that used to wipe the table
            try:
                signin.begin(f"made.up.{i}")
            except signin.SigninError:
                pass
        check("a flood of made-up names never reaches the table, so victim.user's spent budget stands",
              list(signin._starts) == ["victim.user"]
              and location(start(c, "victim.user")) == "/login/duo?error=rate_limited", str(list(signin._starts))[:200])

        signin.reset()
        signin._RATE_KEYS_MAX = 2
        start(c, "nina.osei"); start(c, "avery.kim"); start(c, "nina.osei")   # nina used last
        start(c, "victim.user")                                              # table full: one goes
        check("a full table evicts the least recently used name only, never all of them",
              list(signin._starts) == ["nina.osei", "victim.user"]
              and len(signin._starts["nina.osei"]) == 2, str({k: len(v) for k, v in signin._starts.items()}))
    finally:
        signin.RATE_LIMIT_STARTS, signin._RATE_KEYS_MAX = saved
        signin.reset()


def test_hung_call_releases_slot() -> None:
    print("a Duo call that never returns gives its slot back at its deadline")
    release = threading.Event()
    errors = []
    saved_hook = threading.excepthook
    threading.excepthook = lambda args: errors.append(args.exc_value)

    def hang(*_a):
        release.wait(10)
        return "late"

    try:
        outcomes = []
        for _ in range(signin._DUO_CALL_SLOTS + 2):
            try:
                signin._bounded(hang, timeout=0.15)
            except signin._DuoTimeout:
                outcomes.append("timeout")
        check(f"{signin._DUO_CALL_SLOTS + 2} hung calls each answer at the deadline",
              outcomes == ["timeout"] * (signin._DUO_CALL_SLOTS + 2), str(outcomes))
        t0 = time.monotonic()
        value = signin._bounded(lambda: "answered", timeout=1.0)
        check("...and a call after them still gets a slot at once (none is held by a hung call)",
              value == "answered" and time.monotonic() - t0 < 0.5, f"{time.monotonic() - t0:.2f}s")
        check("every slot is free while the hung calls are still running",
              signin._duo_slots._value == signin._DUO_CALL_SLOTS, str(signin._duo_slots._value))
        busy = threading.Lock()
        try:
            signin._bounded(hang, timeout=0.15, exclusive=busy)
        except signin._DuoTimeout:
            pass
        t0 = time.monotonic()
        try:
            signin._bounded(lambda: "x", timeout=1.0, exclusive=busy)
            second = "ran"
        except signin._DuoBusy:
            second = "busy"
        check("an exclusive call still running: the next one is refused at once, not stacked",
              second == "busy" and time.monotonic() - t0 < 0.1, second)
        release.set()
        deadline = time.monotonic() + 3
        while busy.locked() and time.monotonic() < deadline:
            time.sleep(0.02)
        check("...and runs again once the hung call has ended", signin._bounded(lambda: "x", timeout=1.0,
                                                                                exclusive=busy) == "x")
        time.sleep(0.1)
        check("a hung call ending later releases nothing twice (no over-release, no thread error)",
              not errors and signin._duo_slots._value == signin._DUO_CALL_SLOTS,
              f"{errors!r} {signin._duo_slots._value}")
    finally:
        release.set()
        threading.excepthook = saved_hook

    saved = signin.HEALTH_TIMEOUT_S
    signin.HEALTH_TIMEOUT_S = 0.2
    FakeDuo.health_mode = "hang"
    host_capabilities.reset_duo_health()      # a gate that never opened shows its latest failure
    try:
        n = len(FakeDuo.health_calls)
        first = signin.run_health_check()
        second = signin.run_health_check()
        check("a health check behind one still waiting for Duo starts no second call",
              first is False and second is False and len(FakeDuo.health_calls) == n + 1
              and signin.gate()["reason"] == "Duo health check failed: the previous health check is "
                                            "still waiting for Duo", signin.gate()["reason"])
    finally:
        signin.HEALTH_TIMEOUT_S = saved
        FakeDuo.health_mode = "ok"
        time.sleep(1.5)                       # the hung fake sleeps 1.5 s
        check("...and once it has ended, the next check runs and passes", signin.run_health_check() is True)
        _open_gate()


def test_health_timer() -> None:
    print("the duo_signin gate re-checks Duo's health on a timer, off the event loop")
    check("the app's shutdown stopped the checker it started", signin._health_thread is None)
    saved = (signin.HEALTH_INTERVAL_S, signin.HEALTH_RETRY_S)
    signin.HEALTH_INTERVAL_S, signin.HEALTH_RETRY_S = 0.2, 0.1
    host_capabilities.reset_duo_health()
    FakeDuo.health_calls.clear()

    def wait_for(pred, timeout=3.0):
        deadline = time.monotonic() + timeout
        while not pred() and time.monotonic() < deadline:
            time.sleep(0.02)
        return pred()

    try:
        t = signin.start_health_check()
        check("it runs on a daemon thread named duo-health-check",
              t is not None and t.daemon and t.name == "duo-health-check" and t is not threading.main_thread())
        check("...and checks again and again (not once at startup)", wait_for(lambda: len(FakeDuo.health_calls) >= 3),
              str(len(FakeDuo.health_calls)))
        check("each check is a bounded duo-call thread", all(x.name == "duo-call" for x in FakeDuo.health_calls))
        check("start again: the running checker is returned, not a second one", signin.start_health_check() is t)
        check("...and its first passing check opened the gate", wait_for(lambda: signin.gate()["enabled"]))
        n_ok = len(FakeDuo.health_calls)
        FakeDuo.health_mode = DuoException({"stat": "FAIL", "code": 40301, "message": "access_denied"})
        closed = wait_for(lambda: not signin.gate()["enabled"])
        failed = len(FakeDuo.health_calls) - n_ok
        check("Duo starts failing: the timer closes the gate only after 3 failed checks in a row, not on the first",
              closed and failed >= host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE
              and "40301" in signin.gate()["reason"], f"{failed} failed checks, {signin.gate()}")
        FakeDuo.health_mode = "ok"
        check("Duo recovers: a retry reopens it", wait_for(lambda: signin.gate()["enabled"]), str(signin.gate()))
        signin.stop_health_check()
        check("stop: the checker ends", not t.is_alive())
        n = len(FakeDuo.health_calls)
        time.sleep(0.5)
        check("...and checks no more", len(FakeDuo.health_calls) == n)
    finally:
        signin.stop_health_check()
        signin.HEALTH_INTERVAL_S, signin.HEALTH_RETRY_S = saved
        FakeDuo.health_mode = "ok"
        host_capabilities.reset_duo_health()
        _open_gate()


def test_ca_bundle() -> None:
    print("Duo's TLS: the repo's CA bundle when one is configured, else duo_universal's pinning")
    names = ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
    saved = {k: os.environ.get(k) for k in names}
    bundle = os.path.join(_TMP, "corp-ca-bundle.pem")
    Path(bundle).write_text("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")

    def env(**values):
        for k in names:
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in values.items() if v is not None})

    try:
        env(REQUESTS_CA_BUNDLE=bundle)
        check("REQUESTS_CA_BUNDLE names a file -> Duo is verified against it", signin.duo_ca_bundle() == bundle)
        real = signin._default_client_factory(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, host=API_HOST,
                                              redirect_uri="https://testserver/auth/duo/callback",
                                              duo_certs=signin.duo_ca_bundle())
        check("...the real SDK client verifies with that bundle (TLS on, pinning off)",
              real._duo_certs == bundle and not real._disable_ca_pinning)
        signin.set_client_factory(FakeDuo)
        signin._client()
        check("...and the app's client is built with it (duo_certs)", FakeDuo.instances[-1].duo_certs == bundle)
        env(CURL_CA_BUNDLE=bundle)
        check("CURL_CA_BUNDLE counts too (requests' own order)", signin.duo_ca_bundle() == bundle)
        env()
        check("no bundle configured -> None", signin.duo_ca_bundle() is None)
        signin._client()
        check("...the app's client is rebuilt for it, with duo_certs=None", FakeDuo.instances[-1].duo_certs is None)
        real = signin._default_client_factory(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, host=API_HOST,
                                              redirect_uri="https://testserver/auth/duo/callback", duo_certs=None)
        check("...and the real SDK keeps Duo's pinned bundle", real._duo_certs == duo_sdk.DEFAULT_CA_CERT_PATH)
        env(REQUESTS_CA_BUNDLE=os.path.join(_TMP, "missing.pem"))
        check("a bundle path that is not a file -> pinning kept", signin.duo_ca_bundle() is None)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        signin.set_client_factory(FakeDuo)


def test_server_info_identity_session() -> None:
    print("GET /api/server-info: identity_session says whether THIS browser holds a verified session")
    _wipe_sessions()
    c = client()
    r = c.get("/api/server-info", headers=H)
    check("anonymous: identity_session false, and the answer is never cached",
          r.json().get("identity_session") is False and "no-store" in r.headers.get("cache-control", ""))
    sign_in(c, "nina.osei", code="CODE-SRVINFO-1")
    check("signed in: identity_session true", c.get("/api/server-info", headers=H).json().get("identity_session") is True)
    _configure(duo_enabled=False)
    try:
        check("DUO_ENABLED off: false even with the cookie (the middleware does not read it)",
              c.get("/api/server-info", headers=H).json().get("identity_session") is False)
    finally:
        _configure()


# Loads the real chat.js with a stub DOM and fetch, runs refreshIndicators()
# per scenario, and prints how many GET /api/identity/me each one sent.
_POLL_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
const scenarios = JSON.parse(process.argv[3]);
function run(sc) {
  const requests = [];
  const ctx = {
    console: { log() {}, warn() {}, error() {}, debug() {} },
    fetch: async (input) => {
      const url = String(input);
      requests.push(url);
      const body = url.startsWith('/api/server-info') ? sc.server_info
                 : url.startsWith('/api/identity/me') ? (sc.me || { signed_in: false }) : {};
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body),
               headers: { get: (k) => (k.toLowerCase() === 'content-type' ? 'application/json' : null) },
               clone() { return this; } };
    },
    document: { addEventListener() {}, getElementById: () => null, querySelectorAll: () => [],
                querySelector: () => null, hidden: false,
                documentElement: { classList: { toggle() {}, add() {}, remove() {} } } },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    history: { replaceState() {} },
    location: { search: '', pathname: '/app', hash: '', href: '' },
    setInterval: () => 1, clearInterval() {}, setTimeout: () => 1, clearTimeout() {},
    URLSearchParams,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(src, ctx, { filename: 'chat.js' });
  return { ctx, requests };
}
(async () => {
  const out = {};
  for (const [name, sc] of Object.entries(scenarios)) {
    const { ctx, requests } = run(sc);
    for (let i = 0; i < (sc.polls || 3); i++) {
      vm.runInContext('refreshIndicators()', ctx);
      for (let j = 0; j < 20; j++) await new Promise((r) => setImmediate(r));
    }
    out[name] = { me: requests.filter((u) => u.startsWith('/api/identity/me')).length,
                  info: requests.filter((u) => u.startsWith('/api/server-info')).length };
  }
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(2); });
"""


def test_identity_poll_inert() -> None:
    print("chat.js: GET /api/identity/me only while gated.duo_signin is open or a session exists")
    js = (ROOT / "frontend" / "js" / "chat.js").read_text()
    refresh = re.search(r"function refreshIndicators\(\) \{(.*?)\n\}", js, re.S).group(1)
    check("refreshIndicators asks identityPollWanted() before refreshIdentity()",
          "if (identityPollWanted()) refreshIdentity();" in refresh)
    check("server-info's identity_session is kept with the gates",
          "identity_session: data.identity_session === true" in js)
    node = shutil.which("node")
    if not node:
        print("  SKIP  node is not installed: the behavioural poll check did not run")
        return
    harness = Path(_TMP, "poll_harness.js")
    harness.write_text(_POLL_HARNESS)
    off = {"enabled": False, "reason": "Duo sign-in is off (DUO_ENABLED is not true)."}
    down = {"enabled": False, "reason": "Duo health check failed: ConnectionError"}
    scenarios = {
        "duo_off": {"server_info": {"gated": {"duo_signin": off}, "identity_session": False}},
        "no_field": {"server_info": {"gated": {}}},
        "gate_open": {"server_info": {"gated": {"duo_signin": {"enabled": True, "reason": ""}},
                                      "identity_session": False}},
        "down_with_session": {"server_info": {"gated": {"duo_signin": down}, "identity_session": True},
                              "me": {"signed_in": True, "username": "nina.osei"}},
        "down_no_session": {"server_info": {"gated": {"duo_signin": down}, "identity_session": False}},
    }
    out = subprocess.run([node, str(harness), str(ROOT / "frontend" / "js" / "chat.js"), json.dumps(scenarios)],
                         capture_output=True, text=True, timeout=60)
    try:
        counts = json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        check("the chat.js poll harness ran", False, (out.stdout + out.stderr)[-400:])
        return
    check("Duo off (Labs 0-4): three polls, server-info only, no /api/identity/me",
          counts["duo_off"] == {"me": 0, "info": 3} and counts["no_field"]["me"] == 0, str(counts))
    check("the gate open: polled", counts["gate_open"]["me"] == 3, str(counts["gate_open"]))
    check("Duo down but this browser signed in: polled", counts["down_with_session"]["me"] == 3,
          str(counts["down_with_session"]))
    check("Duo down, no session: not polled", counts["down_no_session"]["me"] == 0, str(counts["down_no_session"]))


# Loads the real chat.js with stub #identitySignin / #identityBadge elements,
# runs refreshIndicators() once per server-info answer in `polls`, and prints
# whether the "Sign in with Duo" link was shown after each poll, and whether it
# was EVER shown (a flash in between counts). `me` is the /api/identity/me
# answer, or a list of them (one per poll): a body (200), {status, body},
# 'pending' (never answers) or 'throw' (a network error).
_LINK_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
const scenarios = JSON.parse(process.argv[3]);
function el(initial) {
  const s = new Set(initial || []);
  const e = { title: '', textContent: '', dataset: {}, ever: false };
  const seen = () => { if (!s.has('hidden')) e.ever = true; };
  e.classList = { add: (...c) => { c.forEach((x) => s.add(x)); seen(); },
                  remove: (...c) => { c.forEach((x) => s.delete(x)); seen(); },
                  toggle: (c, force) => { const on = force === undefined ? !s.has(c) : !!force;
                                          if (on) s.add(c); else s.delete(c); seen(); return on; },
                  contains: (c) => s.has(c) };
  return e;
}
function respond(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body),
           headers: { get: (k) => (k.toLowerCase() === 'content-type' ? 'application/json' : null) },
           clone() { return this; } };
}
(async () => {
  const out = {};
  for (const [name, sc] of Object.entries(scenarios)) {
    const elements = { identitySignin: el(['hidden']), identityBadge: el(['hidden']) };
    let poll = 0;
    const requests = [];
    const ctx = {
      console: { log() {}, warn() {}, error() {}, debug() {} },
      fetch: async (input) => {
        const url = String(input);
        requests.push(url);
        if (url.startsWith('/api/server-info')) return respond(200, sc.polls[Math.min(poll, sc.polls.length - 1)]);
        if (!url.startsWith('/api/identity/me')) return respond(200, {});
        const me = sc.me || { signed_in: false };
        const answer = Array.isArray(me) ? me[Math.min(poll, me.length - 1)] : me;
        if (answer === 'pending') return new Promise(() => {});
        if (answer === 'throw') throw new TypeError('Failed to fetch');
        return answer.status ? respond(answer.status, answer.body || {}) : respond(200, answer);
      },
      document: { addEventListener() {}, getElementById: (id) => elements[id] || null, querySelectorAll: () => [],
                  querySelector: () => null, hidden: false,
                  documentElement: { classList: { toggle() {}, add() {}, remove() {} } } },
      localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
      history: { replaceState() {} },
      location: { search: '', pathname: '/app', hash: '', href: '' },
      setInterval: () => 1, clearInterval() {}, setTimeout: () => 1, clearTimeout() {},
      URLSearchParams,
    };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: 'chat.js' });
    const shown = [];
    for (poll = 0; poll < sc.polls.length; poll++) {
      vm.runInContext('refreshIndicators()', ctx);
      for (let j = 0; j < 20; j++) await new Promise((r) => setImmediate(r));
      shown.push(!elements.identitySignin.classList.contains('hidden'));
    }
    out[name] = { shown, ever: elements.identitySignin.ever,
                  me: requests.filter((u) => u.startsWith('/api/identity/me')).length };
  }
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(2); });
"""


def test_signin_link_follows_gate() -> None:
    print("chat.js: the Sign in with Duo link follows every server-info poll, and never flashes for a signed-in user")
    js = (ROOT / "frontend" / "js" / "chat.js").read_text()
    info = re.search(r"async function refreshServerInfo\(\) \{(.*?)\n\}", js, re.S).group(1)
    check("refreshServerInfo re-evaluates the link (renderSigninLink) on every answer",
          "renderSigninLink();" in info)
    link = re.search(r"function renderSigninLink\(\) \{(.*?)\n\}", js, re.S).group(1)
    check("...and shows it only on a signed-out answer from the server (_identityAnswer), unknown at first",
          "_identityAnswer !== 'signed_out'" in link and "let _identityAnswer = null;" in js)
    node = shutil.which("node")
    if not node:
        print("  SKIP  node is not installed: the behavioural link check did not run")
        return
    harness = Path(_TMP, "link_harness.js")
    harness.write_text(_LINK_HARNESS)
    up = {"enabled": True, "reason": ""}
    down = {"enabled": False, "reason": "Duo health check failed: ConnectionError"}
    off = {"enabled": False, "reason": "Duo sign-in is off (DUO_ENABLED is not true)."}

    def si(gate, session=False):
        return {"gated": {"duo_signin": gate}, "identity_session": session}

    scenarios = {
        "gate_closes": {"polls": [si(up), si(down), si(down)]},
        "gate_reopens": {"polls": [si(down), si(up)]},
        "signed_in": {"polls": [si(up, True), si(down, True)], "me": {"signed_in": True, "username": "nina.osei"}},
        "duo_off": {"polls": [si(off), si(off)]},
        "first_me_pending_signed_in": {"polls": [si(up, True)], "me": "pending"},
        "first_me_pending_signed_out": {"polls": [si(up)], "me": "pending"},
        "me_errors": {"polls": [si(up)] * 5,
                      "me": [{"signed_in": False}, {"status": 502, "body": {"detail": "Bad Gateway"}}, "throw",
                             {"status": 401, "body": {"detail": "identity_session_expired"}},
                             {"status": 403, "body": {"detail": "identity_session_revoked"}}]},
        "server_info_signed_in": {"polls": [si(up), si(up, True)], "me": [{"signed_in": False}, "pending"]},
    }
    out = subprocess.run([node, str(harness), str(ROOT / "frontend" / "js" / "chat.js"), json.dumps(scenarios)],
                         capture_output=True, text=True, timeout=60)
    try:
        got = json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        check("the chat.js link harness ran", False, (out.stdout + out.stderr)[-400:])
        return
    check("the gate closes, no session: the link goes on the very next poll, and stays gone",
          got["gate_closes"]["shown"] == [True, False, False], str(got["gate_closes"]))
    check("the gate reopens: the link comes back", got["gate_reopens"]["shown"] == [False, True],
          str(got["gate_reopens"]))
    check("signed in: never the link (the badge instead), gate open or closed, not even for a moment",
          got["signed_in"]["shown"] == [False, False] and not got["signed_in"]["ever"], str(got["signed_in"]))
    check("the first /me still pending: no link, whatever server-info says (signed in or not)",
          got["first_me_pending_signed_in"] == {"shown": [False], "ever": False, "me": 1}
          and got["first_me_pending_signed_out"] == {"shown": [False], "ever": False, "me": 1},
          f"{got['first_me_pending_signed_in']} {got['first_me_pending_signed_out']}")
    check("/me errors: a 502 or a network error hides the link, a 401 or 403 (signed out) shows it",
          got["me_errors"]["shown"] == [True, False, False, True, True], str(got["me_errors"]))
    check("server-info's identity_session says signed in: the link goes before /me answers",
          got["server_info_signed_in"]["shown"] == [True, False], str(got["server_info_signed_in"]))
    check("Duo off: never the link, and no /api/identity/me", got["duo_off"] == {"shown": [False, False], "ever": False, "me": 0},
          str(got["duo_off"]))


def test_redaction_by_pattern_only() -> None:
    print("redaction by pattern only: no request registers a string, so no input can blank a username")
    from backend.logging import redaction

    check("redaction has no run-time registration (register / forget_registered / _registered)",
          not any(hasattr(redaction, n) for n in ("register", "forget_registered", "_registered")))
    sources = [(ROOT / p).read_text() for p in ("backend/services/identity_signin.py",
                                                "backend/services/identity_store.py",
                                                "backend/services/identity_lookup.py")]
    check("...and nothing calls it (the Duo code, the identity cookie, the CII token)",
          not any("redaction.register" in s for s in sources))
    from backend.middleware import access_key as ak_mw
    from backend.middleware import settings_gate as sg_mw

    check("APP_COOKIES is exactly this app's cookie names",
          set(redaction.APP_COOKIES) == {ak_mw.COOKIE_NAME, sg_mw.COOKIE_NAME, idmw.COOKIE_NAME, STATE_COOKIE})
    check("ACCESS_KEY is one of the configured secrets", "access_key" in redaction.SECRET_SETTINGS)

    def refuse(*_a):
        raise DuoException({"error": "invalid_grant", "error_description": "code expired"})

    signin.reset()
    _open_gate()
    cap = _Capture()
    root = logging.getLogger()
    root.addHandler(cap)
    saved_level = root.level
    root.setLevel(logging.DEBUG)
    before = redaction._secrets
    try:
        c = client()
        start(c, "nina.osei")
        st = FakeDuo.issued[-1]["state"]
        # The attack the old design allowed: Duo's code is the caller's input, and
        # arriving at the callback registered it. Another persona's name as the code.
        FakeDuo.answer = staticmethod(refuse)
        r = c.get(f"/auth/duo/callback?duo_code=victim.user&state={st}", headers=H, follow_redirects=False)
        FakeDuo.answer = staticmethod(good_answer)
        logging.getLogger("backend.agents.graph").info("identity verdict for %s: allow", "victim.user")
        logging.getLogger("backend.routers.identity_auth").info("Duo sign-in for %s (session %s)",
                                                                "victim.user", "ref-1")
    finally:
        FakeDuo.answer = staticmethod(good_answer)
        root.removeHandler(cap)
        root.setLevel(saved_level)
    lines = [l for _, l in cap.lines]
    check("the made-up code was exchanged and refused (a fixed error)",
          location(r) == "/login/duo?error=duo_refused" and FakeDuo.exchanges[-1]["code"] == "victim.user",
          location(r))
    check("...and left the redaction state untouched (the same compiled secrets)", redaction._secrets is before)
    check("a username sent as Duo's code is NOT blanked from other loggers' lines",
          any(l.endswith("identity verdict for victim.user: allow") for l in lines), str(lines[-3:])[:300])
    check("...nor from the identity modules' own lines",
          any(l.endswith("Duo sign-in for victim.user (session ref-1)") for l in lines), str(lines[-3:])[:300])
    check("the code in its own context (duo_code= in the request line) is still redacted, by pattern",
          any(n == "httpx" and "/auth/duo/callback?duo_code=[REDACTED]&state=[REDACTED]" in l for n, l in cap.lines)
          and not any("duo_code=victim.user" in l for l in lines))


def test_redaction_bounded_and_safe() -> None:
    print("redaction: compiled once per configuration, nothing grows, no lock in the record factory")
    from backend.logging import redaction

    compiles = []
    real_compile = redaction._compile_secrets

    def counting(values):
        compiles.append(len(values))
        return real_compile(values)

    cap = _Capture()
    root = logging.getLogger()
    root.addHandler(cap)
    saved_level = root.level
    root.setLevel(logging.DEBUG)
    saved_skey = settings.duo_admin_skey
    new_skey = "DUO-ADMIN-SKEY-ROTATED-0123456789abcdef"
    _CODES_SENT.update({"NESTED-CODE-5", "OUTER-CODE-6"})
    redaction._compile_secrets = counting
    try:
        redaction.secrets_pattern()
        before = redaction._secrets
        compiles.clear()
        for i in range(300):
            logging.getLogger("urllib3.connectionpool").debug("GET /x?code=BOUND-%d&state=s", i)
            logging.getLogger("backend.agents.graph").info("turn %d for %s", i, "nina.osei")
        signin.reset()
        _open_gate()
        for i in range(20):
            sign_in(client(), "avery.kim", code=f"CODE-BOUND-{i:04d}")
        check("600 records and 20 sign-ins: nothing compiled, the same secrets pattern kept",
              compiles == [] and redaction._secrets is before, f"{len(compiles)} compiles")
        pattern = before[1]
        alternatives = pattern.pattern.count("|") + 1 if pattern is not None else 0
        check("that pattern is the configured secrets only (at most 3 forms of each setting)",
              0 < alternatives <= 3 * len(redaction.SECRET_SETTINGS), str(alternatives))
        settings.duo_admin_skey = new_skey
        for i in range(50):
            logging.getLogger("some.other.module").info("rotated %s", new_skey if i == 49 else "x")
        check("a configuration change compiles it once more, and the new secret is redacted from then on",
              len(compiles) == 1 and any(l.endswith("rotated [REDACTED]") for _, l in cap.lines)
              and not any(new_skey in l for _, l in cap.lines), f"{len(compiles)} compiles")

        # No lock in the record factory: a log call made while install() holds
        # its lock, or from inside a record being redacted, never waits.
        held, release, done = threading.Event(), threading.Event(), threading.Event()

        def holder():
            with redaction._install_lock:
                held.set()
                release.wait(5)

        class Chatty:
            def __str__(self):
                logging.getLogger("urllib3.nested").warning("nested ?code=%s", "NESTED-CODE-5")
                return "chatty ?code=OUTER-CODE-6"

        def log_it():
            logging.getLogger("requests.outer").warning("outer %s", Chatty())
            done.set()

        threading.Thread(target=holder, daemon=True).start()
        held.wait(2)
        threading.Thread(target=log_it, daemon=True).start()
        finished = done.wait(3)
        release.set()
        check("a log call while install() holds its lock, made from inside a record being redacted, finishes",
              finished)
        with redaction._install_lock:
            redaction.install()           # re-entrant: install() from under its own lock returns
        check("install()'s lock is re-entrant, and install() stays idempotent",
              isinstance(redaction._install_lock, type(threading.RLock())) and redaction.installed()
              and not getattr(redaction._install_lock, "_is_owned", lambda: False)())
    finally:
        redaction._compile_secrets = real_compile
        settings.duo_admin_skey = saved_skey
        root.removeHandler(cap)
        root.setLevel(saved_level)
    text = "\n".join(l for _, l in cap.lines)
    check("...and both the nested and the outer record are redacted",
          "NESTED-CODE-5" not in text and "OUTER-CODE-6" not in text
          and any(l.endswith("nested ?code=[REDACTED]") for _, l in cap.lines)
          and any(l.endswith("outer chatty ?code=[REDACTED]") for _, l in cap.lines))


_MB = 1 << 20
_BUDGET_PER_MB = 0.050          # seconds per MB of input, for any one rule


def _timed_sub(pattern, text: str) -> float:
    started = time.perf_counter()
    pattern.sub("X", text)
    return time.perf_counter() - started


def test_redaction_linear_time() -> None:
    print("redaction: every rule and the secrets pattern stay linear on 1 MB adversarial inputs (<= 50 ms per MB)")
    from urllib.parse import quote

    from backend.logging import redaction

    secrets = redaction.secrets_pattern()
    check("the configured secrets are compiled (the Web SDK secret, ACCESS_KEY)", secrets is not None)
    patterns = list(dict.fromkeys([p for p, _ in redaction._FULL + redaction._COMMON] + [secrets]))
    # Repeated to 1 MB each: the shapes the finding named, runs of token
    # characters, and near misses of every rule (a name with no value, a
    # value with no end, a secret one character short).
    units = ["eyJ", "-eyJ", "eyJ-", ".eyJ", "eyJ.", "eyJaaaa.", "eyJaaaa.aaaa", "a=", "%3D", "Bearer ", "bearer\t",
             "Basic ", "a", "A9_-", "-", "_", ".", "=", "?", "&", "?a=", "'", '"', "\\", "\\'", "'a", "'c", '"x',
             " ", "\t", "\n", "\na", " c", ";", "%", "?code", "&code=", "?client_", "'Cookie': ", "'Cookie': '",
             '"access_token":"', "\nAuthorization", "\nSet-Cookie:", " md_access", " md_access=", " client_secret",
             " code=", "(b'Set-Cookie', b", "Bearer abc ", CLIENT_SECRET[:-1], KEY[:-1], quote(KEY + "/")[:-1]]
    slow = []
    for pattern in patterns:
        for unit in units:
            text = (unit * (_MB // len(unit) + 1))[:_MB]
            # 64 KB first: a super-linear rule fails here in seconds instead
            # of running for minutes on the full megabyte.
            if _timed_sub(pattern, text[:64 * 1024]) > _BUDGET_PER_MB:
                slow.append((pattern.pattern[:60], unit, "64 KB over the 1 MB budget"))
                continue
            # The best of three: only a slow run is measured again (noise).
            took = _timed_sub(pattern, text)
            for _ in range(2):
                if took <= _BUDGET_PER_MB:
                    break
                took = min(took, _timed_sub(pattern, text))
            if took > _BUDGET_PER_MB:
                slow.append((pattern.pattern[:60], unit, f"{took * 1000:.0f} ms"))
    check(f"{len(patterns)} patterns x {len(units)} inputs of 1 MB: each within {_BUDGET_PER_MB * 1000:.0f} ms",
          not slow and len(patterns) >= 14, str(slow[:5]))

    jwt = r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}+\.[A-Za-z0-9_-]{4,}+\.[A-Za-z0-9_-]*+"
    check("the JWT rule starts only where a run of base64url characters starts, each segment one possessive class",
          any(p.pattern == jwt for p, _ in redaction._COMMON))
    check("...and still takes a JWT after '=', a space or a quote, never one glued to a longer token",
          redaction.redact_common("t=eyJhbGci.eyJzdWIi.c2ln 'eyJhbGci.eyJzdWIi.c2ln' x-eyJhbGci.eyJzdWIi.c2ln")
          == "t=[REDACTED] '[REDACTED]' x-eyJhbGci.eyJzdWIi.c2ln")
    check("the docstring's linear-time claim names this test",
          "test_redaction_linear_time" in (redaction.__doc__ or ""))


def test_redaction_cap() -> None:
    print("redaction: a text over 64 KB is cut first, with a marker, and the cut never keeps half a credential")
    from backend.logging import redaction

    cap = redaction.MAX_SCAN_CHARS
    marker = re.compile(r" \[TRUNCATED: (\d+) more characters\]$")
    check("MAX_SCAN_CHARS is 64 KB", cap == 64 * 1024)
    started = time.perf_counter()
    out = redaction.redact("-eyJ" * (_MB // 4))
    took = time.perf_counter() - started
    check("1 MB of '-eyJ' (one token) through the full treatment: fast, and only the marker is kept",
          took < 0.5 and out == redaction.TRUNCATED_MARKER.format(_MB), f"{took:.3f} s, {out[:80]!r}")
    head = "x" * (cap - 25) + " "
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuaW5hLm9zZWkifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
    for name, text, gone in (
        ("a JWT", head + jwt + " tail ", "eyJ"),
        ("the Web SDK secret", head + "secret=" + CLIENT_SECRET + " tail ", CLIENT_SECRET[:12]),
        ("a quoted cookie value", "x" * (cap - 60) + " {'Cookie': 'sid=SID-VALUE-1; other=" + "z" * 70000 + "'} ",
         "SID-VALUE-1"),
    ):
        text += "y" * 100000
        got = redaction.redact_common(text)
        m = marker.search(got)
        check(f"{name} split by the cut: none of it kept, the marker counts what went",
              gone not in got and got.startswith("x" * 1000) and m is not None
              and len(text) - cap < int(m.group(1)) < len(text) - cap + 200
              and len(got) <= cap + len(redaction.TRUNCATED_MARKER) + 10, got[-120:])
    check("a text under the cap is untouched by it",
          redaction.redact_common("Cookie: a=b; " + "y" * 1000) == "Cookie: [REDACTED]")

    lines = _Capture()
    root = logging.getLogger()
    root.addHandler(lines)
    saved_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        started = time.perf_counter()
        logging.getLogger("backend.routers.chat").info("chat message: %s", "-eyJ " * (_MB // 5))
        took = time.perf_counter() - started
    finally:
        root.removeHandler(lines)
        root.setLevel(saved_level)
    line = lines.lines[-1][1] if lines.lines else ""
    m = marker.search(line)
    check("a 1 MB chat message logged by any module: logged at once, cut to 64 KB and marked",
          took < 1.0 and "chat message: -eyJ -eyJ" in line and m is not None and len(line) < cap + 200,
          f"{took:.3f} s, {len(line)} chars")


def test_health_gate_three_failures() -> None:
    print("the duo_signin gate closes only after 3 failed health checks in a row")
    failing = DuoException({"stat": "FAIL", "code": 40301, "message": "access_denied"})
    closed_reason = "Duo health check failed: Duo answered 40301 access_denied"
    signin.reset()
    host_capabilities.reset_duo_health()
    c = client()
    try:
        check("DUO_HEALTH_FAILURES_TO_CLOSE is 3", host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE == 3)
        FakeDuo.health_mode = "ok"
        check("a passing check opens the gate", signin.run_health_check() is True and signin.gate()["enabled"])
        FakeDuo.health_mode = failing
        first = signin.run_health_check()
        check("one failed check (a blip on the timer) leaves it open",
              first is False and signin.gate() == {"enabled": True, "reason": ""}, str(signin.gate()))
        r = start(c, "nina.osei")
        check("...so a sign-in still starts", location(r).startswith(f"https://{API_HOST}/"), location(r))
        second = signin.run_health_check()
        check("two in a row: still open, and /api/server-info agrees",
              second is False and signin.gate()["enabled"] is True
              and c.get("/api/server-info", headers=H).json()["gated"]["duo_signin"]["enabled"] is True,
              str(signin.gate()))
        third = signin.run_health_check()
        check("the third in a row closes it, with Duo's sanitized reason",
              third is False and signin.gate() == {"enabled": False, "reason": closed_reason}, str(signin.gate()))
        check("...and /api/server-info says so at once",
              c.get("/api/server-info", headers=H).json()["gated"]["duo_signin"]["enabled"] is False)
        check("closed: POST /auth/duo/start -> error=unavailable",
              location(start(c, "nina.osei")) == "/login/duo?error=unavailable")
        FakeDuo.health_mode = "ok"
        check("a passing check reopens it", signin.run_health_check() is True and signin.gate()["enabled"])
        for mode in (failing, failing, "ok", failing, failing):
            FakeDuo.health_mode = mode
            signin.run_health_check()
        check("only failures in a row count: fail, fail, pass, fail, fail leaves it open",
              signin.gate()["enabled"] is True, str(signin.gate()))
        host_capabilities.reset_duo_health()
        signin.run_health_check()
        check("a gate that never opened stays closed on its first failure, with that reason",
              signin.gate() == {"enabled": False, "reason": closed_reason}, str(signin.gate()))
    finally:
        FakeDuo.health_mode = "ok"
        host_capabilities.reset_duo_health()
        _open_gate()
        signin.reset()


def test_callback_not_gated() -> None:
    print("GET /auth/duo/callback finishes a started sign-in even if the duo_signin gate closed meanwhile")
    signin.reset()
    _wipe_sessions()
    _open_gate()
    close_gate = _close_gate

    def duo_down(*_a):
        raise DuoException(duo_sdk.requests.ConnectionError("down"))

    try:
        c = client()
        start(c, "nina.osei")
        st = FakeDuo.issued[-1]["state"]
        close_gate()
        check("the gate closed after the sign-in started", signin.gate()["enabled"] is False)
        n_ex = len(FakeDuo.exchanges)
        r = callback(c, st, code="CODE-GATE-CLOSED-1")
        check("the callback still exchanges the code and signs the user in",
              location(r) == "/app?signin=ok" and len(FakeDuo.exchanges) == n_ex + 1
              and len(rows("nina.osei")) == 1, location(r))
        check("...while a new start is refused (error=unavailable)",
              location(start(client(), "avery.kim")) == "/login/duo?error=unavailable")

        _open_gate()
        c = client()
        start(c, "avery.kim")
        st = FakeDuo.issued[-1]["state"]
        close_gate()
        FakeDuo.answer = staticmethod(duo_down)
        try:
            r = callback(c, st, code="CODE-GATE-CLOSED-2")
        finally:
            FakeDuo.answer = staticmethod(good_answer)
        last = _audits("identity_signin_failure")[-1]
        check("...and a Duo failure there maps to the fixed error, audited (error=duo_unavailable)",
              location(r) == "/login/duo?error=duo_unavailable" and last.get("details") == {"reason": "duo_unavailable"}
              and last.get("user") == "avery.kim" and rows("avery.kim") == [], f"{location(r)} {last}")

        _open_gate()
        c = client()
        start(c, "victim.user")
        st = FakeDuo.issued[-1]["state"]
        _configure(duo_enabled=False)
        n_ex, n_fail = len(FakeDuo.exchanges), len(_audits("identity_signin_failure"))
        r = callback(c, st, code="CODE-DUO-OFF")
        check("Duo sign-in switched off (DUO_ENABLED): the callback is refused (unavailable), "
              "no exchange, no audit event",
              location(r) == "/login/duo?error=unavailable" and len(FakeDuo.exchanges) == n_ex
              and len(_audits("identity_signin_failure")) == n_fail, location(r))
    finally:
        _configure()
        FakeDuo.answer = staticmethod(good_answer)
        host_capabilities.reset_duo_health()
        _open_gate()
        signin.reset()


def main() -> int:
    check("temp DB in use (never the app's medadvice.db)", _TMP in str(dbmod.engine.url), str(dbmod.engine.url))
    dbmod.init_db()
    _reset_fake()
    host_capabilities.reset_duo_health()
    signin.set_client_factory(FakeDuo)
    signin.reset()
    try:
        with TestClient(app, base_url=BASE) as c:
            governance_logger.set_logs_directory(os.path.join(_TMP, "logs"))
            test_startup_health_check(c)
        test_health_check_outcomes()
        test_login_page()
        test_login_unchanged()
        test_start()
        test_disabled_persona_refused()
        test_rate_limit()
        test_callback_success()
        test_callback_refusals()
        test_routes_off_event_loop()
        test_sign_out()
        test_redaction()
        test_real_sdk()
        test_frontend()
        test_debug_log_redaction()
        test_redaction_rules()
        test_rate_limit_order_and_eviction()
        test_hung_call_releases_slot()
        test_health_timer()
        test_ca_bundle()
        test_server_info_identity_session()
        test_identity_poll_inert()
        test_signin_link_follows_gate()
        test_redaction_by_pattern_only()
        test_redaction_bounded_and_safe()
        test_redaction_linear_time()
        test_redaction_cap()
        test_health_gate_three_failures()
        test_callback_not_gated()
        test_no_leaks()
    finally:
        signin.stop_health_check()
        signin.set_client_factory(None)
        signin.reset()
        host_capabilities.reset_duo_health()
        settings.duo_enabled = False
        dbmod.engine.dispose()
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
