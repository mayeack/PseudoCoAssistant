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

    def __init__(self, *, client_id, client_secret, host, redirect_uri):
        self.client_id, self.client_secret, self.host, self.redirect_uri = (
            client_id, client_secret, host, redirect_uri)
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
    check("no placeholder left unrendered", "__DUO_SIGNIN" not in r.text and "__SIGNED_IN_AS__" not in r.text)

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

    host_capabilities.record_duo_health(False, "HTTP <b>503</b>")
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
    check("the sign-in page knows who is signed in", 'data-signed-in-as="nina.osei"' in page.text)

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

    # gate closed between start and callback
    c = client()
    start(c, "nina.osei"); st = FakeDuo.issued[-1]["state"]
    host_capabilities.record_duo_health(False, "HTTP 503")
    try:
        r = callback(c, st, code="CODE-GATE")
        check("gate closed at the callback -> error=unavailable", location(r) == "/login/duo?error=unavailable")
    finally:
        _open_gate()


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
    c = client()
    sign_in(c, "victim.user", code="CODE-OUT-2")
    ref = rows("victim.user")[0].id
    store.revoke(ref, reason="duo_disabled")
    r = c.get("/api/identity/me", headers=H)
    check("revoked: GET /api/identity/me (the 10 s poll) answers 403 identity_session_revoked",
          r.status_code == 403 and r.json() == {"detail": "identity_session_revoked"}, r.text)
    page = c.get("/login/duo", headers={**H, "Accept": "text/html"})
    check("revoked: the sign-in page still loads, with its gate rendered", page.status_code == 200
          and 'data-gate="enabled"' in page.text)
    r = c.post("/auth/identity/logout", headers=H, follow_redirects=False)
    check("revoked: signing out clears the tombstone", location(r) == "/login/duo?signed_out=1"
          and rows("victim.user") == [] and c.get("/api/identity/me", headers=H).json() == {"signed_in": False})

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

    def fake_post(url, data=None, params=None, headers=None, verify=None, proxies=None):
        calls.append({"url": url, "data": data, "params": params, "verify": verify})
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
        check("...with Duo's CA bundle pinned (the SDK's own ca_certs.pem)",
              bool(calls) and calls[-1]["verify"] == duo_sdk.DEFAULT_CA_CERT_PATH, str(calls[-1:]))
        c = client()
        r, q, req = begin_flow(c)
        check("the prompt URL is Duo's authorize endpoint for this client",
              location(r).startswith(f"https://{API_HOST}/oauth/v1/authorize?") and q["client_id"] == [CLIENT_ID])
        check("its signed request: redirect_uri from PUBLIC_BASE_URL, the normalized username, our state",
              req["redirect_uri"] == "https://testserver/auth/duo/callback" and req["duo_uname"] == "nina.osei"
              and cookie_header(r, STATE_COOKIE).startswith(f"{STATE_COOKIE}={req['state']};"), str(req))
        r = callback(c, req["state"], code="REALSDK-CODE-1")
        tok = [x for x in calls if x["url"].endswith("/oauth/v1/token")][-1]
        check("the exchange posts Duo's code with the same redirect_uri, CA pinned",
              tok["params"]["code"] == "REALSDK-CODE-1"
              and tok["params"]["redirect_uri"] == "https://testserver/auth/duo/callback"
              and tok["verify"] == duo_sdk.DEFAULT_CA_CERT_PATH, str(tok["params"])[:200])
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
          and 0 < page.index('id="emergencyBanner"') - page.index('id="identityBanner"') < 2000)
    check("chat.js cache-buster bumped to v=34", "/static/js/chat.js?v=34" in page)
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
        test_rate_limit()
        test_callback_success()
        test_callback_refusals()
        test_routes_off_event_loop()
        test_sign_out()
        test_redaction()
        test_real_sdk()
        test_frontend()
        test_no_leaks()
    finally:
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
