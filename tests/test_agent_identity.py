#!/usr/bin/env python3
"""The app's Duo Agent Directory token (4.24.0, plan 12.4):
backend/services/agent_identity.py.

Covers:
- inert unless configured: no thread starts and nothing is sent;
- the request: client_secret_basic, the client-credentials form and the scope;
- the cache and the timing (refresh before expiry, backoff after a failure,
  Duo's Retry-After);
- the fixed-vocabulary failures, with nothing raised;
- the redaction of the client secret and the token;
- the refresher thread (daemon, idempotent, stoppable, never blocking
  startup);
- the startup and shutdown wiring;
- the .env-only rule (no Settings-API field);
- the test isolation that keeps every suite off the real Duo.

No network: every request goes to an ``httpx.MockTransport``.

    .venv/bin/python tests/test_agent_identity.py      # exit 0 = pass
"""
import base64
import logging
import os
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import httpx  # noqa: E402

import backend.config  # noqa: E402,F401  (loads .env, CA bundle)
from backend.config import Settings, settings  # noqa: E402

settings.debug = False
import identity_isolation  # noqa: E402  (no real Duo / CII, whatever .env holds)

identity_isolation.isolate(settings)

from backend.logging import redaction  # noqa: E402
from backend.services import agent_identity as ai  # noqa: E402

TOKEN_URL = "https://sso-test0000.sso.duosecurity.com/oauth2/DIAGENTAPPTEST000000/token"
CLIENT_ID = "afe005f942e243228d0681938f774a00"           # 32 hex, as Duo issues them
CLIENT_SECRET = "AgentClientSecretTestValue0123456789abcd"  # 40 characters
ACCESS = ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZmUwMDVmOTQyZTI0MzIyOGQwNjgxOTM4Zjc3NGEwMCJ9"
          ".c2lnbmF0dXJlLXRlc3QtdmFsdWUtMDEyMzQ1Njc4OWFiY2RlZg")
SCOPE = "pseudoco:tools"

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


def _configure(on: bool = True, **overrides) -> None:
    values = dict(duo_enabled=on, duo_agent_client_id=CLIENT_ID if on else "",
                  duo_agent_client_secret=CLIENT_SECRET if on else "",
                  duo_agent_token_url=TOKEN_URL if on else "", duo_agent_scope=SCOPE if on else "")
    values.update(overrides)
    for k, v in values.items():
        setattr(settings, k, v)


class Duo:
    """A fake token endpoint: records each request and answers with
    ``self.reply`` (a Response, or an exception to raise)."""

    def __init__(self) -> None:
        self.requests = []
        self.reply = None
        self.seen = threading.Event()

    def ok(self, **body) -> httpx.Response:
        doc = {"access_token": ACCESS, "token_type": "Bearer", "expires_in": 3600, "scope": SCOPE}
        doc.update(body)
        return httpx.Response(200, json={k: v for k, v in doc.items() if v is not None})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.seen.set()
        reply = self.reply if self.reply is not None else self.ok()
        if isinstance(reply, BaseException):
            raise reply
        return reply


def _install(duo: Duo) -> None:
    ai.set_transport(httpx.MockTransport(duo))


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def text(self) -> str:
        return "\n".join(r.getMessage() for r in self.records)


# --------------------------------------------------------------------------- inert
def test_inert() -> None:
    print("inert unless DUO_ENABLED with the client ID, the secret and an https token URL")
    d = Settings.model_fields
    check("defaults: every DUO_AGENT_* key empty", all(d[k].default == "" for k in (
        "duo_agent_client_id", "duo_agent_client_secret", "duo_agent_token_url", "duo_agent_scope")))
    duo = Duo()
    _install(duo)
    cases = {
        "DUO_ENABLED off": dict(duo_enabled=False),
        "no client ID": dict(duo_agent_client_id=""),
        "no client secret": dict(duo_agent_client_secret=""),
        "no token URL": dict(duo_agent_token_url=""),
        "http token URL": dict(duo_agent_token_url=TOKEN_URL.replace("https://", "http://")),
        "token URL with no host": dict(duo_agent_token_url="https:///oauth2/x/token"),
    }
    for name, override in cases.items():
        _configure(True, **override)
        ok, wait = ai.request_token()
        check(f"{name}: not configured, start() starts nothing, request_token() sends nothing",
              not ai.configured() and ai.start() is None and ok is False and not duo.requests)
        check(f"{name}: status says not_configured", ai.status()["state"] == ai.NOT_CONFIGURED)
    check("scope is optional", (_configure(True, duo_agent_scope=""), ai.configured())[1])
    _configure(False)


# --------------------------------------------------------------------------- one request
def test_request() -> None:
    print("one client-credentials request: Basic auth, the form, the scope")
    duo = Duo()
    _install(duo)
    _configure(True)
    check("before any request: state pending, no token", ai.status()["state"] == ai.PENDING and ai.token() is None)
    ok, wait = ai.request_token()
    check("200 -> ok, next request 300 s before the 3600 s expiry", ok and wait == 3300.0, f"{ok} {wait}")
    check("exactly one request", len(duo.requests) == 1, str(len(duo.requests)))
    req = duo.requests[0]
    check("POST to DUO_AGENT_TOKEN_URL", req.method == "POST" and str(req.url) == TOKEN_URL, str(req.url))
    expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    check("client_secret_basic: HTTP Basic with the client ID and secret",
          req.headers.get("authorization") == expected)
    form = parse_qs(req.content.decode())
    check("form: grant_type=client_credentials and scope=DUO_AGENT_SCOPE, nothing else",
          form == {"grant_type": ["client_credentials"], "scope": [SCOPE]}, str(form))
    check("the secret is not in the body", CLIENT_SECRET not in req.content.decode())
    check("form-encoded", req.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"))
    check("its own User-Agent", req.headers.get("user-agent") == ai.USER_AGENT)
    check("token() returns it", ai.token() == ACCESS)
    st = ai.status()
    check("status: ok, an expiry, no error, one request",
          st["state"] == ai.OK and st["expires_at"] and st["last_error"] is None and st["requests"] == 1, str(st))
    check("status never carries the token or the secret",
          ACCESS not in str(st) and CLIENT_SECRET not in str(st))

    duo.requests.clear()
    _configure(True, duo_agent_scope="")
    ai.request_token()
    form = parse_qs(duo.requests[0].content.decode())
    check("no DUO_AGENT_SCOPE -> no scope parameter", form == {"grant_type": ["client_credentials"]}, str(form))
    _configure(False)


# --------------------------------------------------------------------------- timing
def test_timing() -> None:
    print("lifetimes, refresh margin, backoff and Retry-After")
    check("3600 s token -> refresh after 3300 s", ai.refresh_after_s(3600) == 3300)
    check("short token -> refresh at half its life, never sooner than 30 s",
          ai.refresh_after_s(400) == 200 and ai.refresh_after_s(60) == 30)
    check("backoff doubles from 60 s", [ai.retry_after_failure_s(n) for n in (1, 2, 3, 4)] == [60, 120, 240, 480])
    check("backoff stops at an hour", ai.retry_after_failure_s(30) == 3600)
    check("a longer Retry-After wins, up to the hour",
          ai.retry_after_failure_s(1, 900) == 900 and ai.retry_after_failure_s(1, 10 ** 6) == 3600)
    check("a shorter Retry-After does not shorten the backoff", ai.retry_after_failure_s(3, 5) == 240)

    duo = Duo()
    _install(duo)
    _configure(True)
    for expires_in, lifetime in ((None, 3600.0), (10, 60.0), (10 ** 9, 86400.0), ("junk", 3600.0)):
        ai.reset()
        duo.reply = duo.ok(expires_in=expires_in)
        ok, wait = ai.request_token()
        check(f"expires_in={expires_in!r} -> lifetime {lifetime:.0f} s", ok and wait == ai.refresh_after_s(lifetime),
              f"{ok} {wait}")

    # Validity follows the monotonic clock: handed out until just before expiry.
    ai.reset()
    duo.reply = None
    base = [1000.0]
    real = ai._monotonic
    ai._monotonic = lambda: base[0]
    try:
        ai.request_token()
        base[0] += 3300
        check("still handed out at the refresh point (overlap)", ai.token() == ACCESS)
        base[0] += 300 - ai.EXPIRY_SKEW_S + 1
        check("not handed out in its last 30 s", ai.token() is None)
        check("status: unavailable once the token lapsed", ai.status()["state"] == ai.UNAVAILABLE)
    finally:
        ai._monotonic = real
    _configure(False)


# --------------------------------------------------------------------------- failures
def test_failures() -> None:
    print("failures: fixed codes, backoff, never raises, the last good token kept until it lapses")
    duo = Duo()
    _install(duo)
    _configure(True)
    cases = [
        (httpx.Response(401, json={"error": "invalid_client", "detail": CLIENT_SECRET}), "http_401", 60),
        (httpx.Response(400, text="bad"), "http_400", 120),
        (httpx.Response(429, headers={"Retry-After": "900"}), "http_429", 900),
        (httpx.Response(302, headers={"Location": "https://elsewhere.example/steal"}), "http_302", 480),
        (httpx.Response(200, text="not json"), "bad_response", 960),
        (httpx.Response(200, json={"token_type": "Bearer"}), "bad_response", 1920),
        (httpx.Response(200, json={"access_token": ACCESS, "token_type": "mac"}), "bad_response", 3600),
        (httpx.ConnectError("refused"), "connect_error", 3600),
        (httpx.ReadTimeout("slow"), "timeout", 3600),
    ]
    for reply, code, wait in cases:
        duo.reply = reply
        try:
            ok, got = ai.request_token()
        except Exception as exc:  # noqa: BLE001
            check(f"{code}: never raises", False, repr(exc))
            continue
        st = ai.status()
        check(f"{code}: (False, {wait} s), last_error {code}",
              ok is False and got == wait and st["last_error"] == code, f"{ok} {got} {st}")
    check("a redirect is not followed (one request per attempt)",
          all(r.url.host == "sso-test0000.sso.duosecurity.com" for r in duo.requests))
    check("failures count up, state unavailable",
          ai.status()["failures"] == len(cases) and ai.status()["state"] == ai.UNAVAILABLE)
    duo.reply = None
    ok, wait = ai.request_token()
    st = ai.status()
    check("a success resets the failures and the error",
          ok and wait == 3300 and st["failures"] == 0 and st["last_error"] is None, str(st))
    duo.reply = httpx.Response(503)
    ai.request_token()
    check("a failed refresh keeps the still-valid token", ai.token() == ACCESS and ai.status()["state"] == ai.OK)
    _configure(False)


# --------------------------------------------------------------------------- redaction
def test_redaction() -> None:
    print("the secret and the token never reach a log record")
    check("DUO_AGENT_CLIENT_SECRET is a configured secret", "duo_agent_client_secret" in redaction.SECRET_SETTINGS)
    check("agent_identity's logger gets the full redaction", redaction.is_redacted_logger(ai.logger.name))
    redaction.install()
    _configure(True)
    check("redact() drops the configured secret", CLIENT_SECRET not in redaction.redact(f"x {CLIENT_SECRET} y"))
    check("redact_common() drops it too (every logger)",
          CLIENT_SECRET not in redaction.redact_common(f"x {CLIENT_SECRET} y"))
    check("and drops the token (JWT)", ACCESS not in redaction.redact_common(f"token {ACCESS}"))
    cap = _Capture()
    ai.logger.addHandler(cap)
    old_level = ai.logger.level
    ai.logger.setLevel(logging.DEBUG)
    try:
        duo = Duo()
        _install(duo)
        _configure(True)
        ai.request_token()
        ai.request_token()
        duo.reply = httpx.Response(401, json={"error": "invalid_client", "secret": CLIENT_SECRET})
        ai.request_token()
        duo.reply = None
        ai.request_token()
        text = cap.text()
        check("a first token is logged at INFO with its expiry",
              any(r.levelno == logging.INFO and "Duo agent token obtained" in r.getMessage() for r in cap.records))
        check("a routine refresh is DEBUG only",
              [r.levelno for r in cap.records if "obtained" in r.getMessage()][1] == logging.DEBUG)
        check("a failure is a WARNING with its code", "failed (http_401, 1 in a row)" in text, text)
        check("a recovery is INFO again",
              [r.levelno for r in cap.records if "obtained" in r.getMessage()][-1] == logging.INFO)
        check("no record has the token, the secret or the token URL",
              ACCESS not in text and CLIENT_SECRET not in text and TOKEN_URL not in text, text)
    finally:
        ai.logger.removeHandler(cap)
        ai.logger.setLevel(old_level)
    _configure(False)


# --------------------------------------------------------------------------- refresher
def test_refresher() -> None:
    print("the refresher: a daemon thread, idempotent, stoppable, never blocking startup")
    duo = Duo()
    gate = threading.Event()

    def slow(request: httpx.Request) -> httpx.Response:
        gate.wait(5)
        return duo(request)

    ai.set_transport(httpx.MockTransport(slow))
    _configure(True)
    t0 = time.monotonic()
    thread = ai.start()
    took = time.monotonic() - t0
    check("start() returns at once even while Duo is slow", took < 0.5, f"{took:.3f} s")
    check("a daemon thread named duo-agent-token",
          thread is not None and thread.daemon and thread.name == "duo-agent-token")
    check("start() again returns the running thread", ai.start() is thread)
    gate.set()
    check("it asks for a token right away", duo.seen.wait(3))
    deadline = time.monotonic() + 3
    while ai.token() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    check("and keeps it", ai.token() == ACCESS)
    ai.stop()
    check("stop() ends the thread", not thread.is_alive())
    check("one request for one token (the next waits for the refresh point)", len(duo.requests) == 1,
          str(len(duo.requests)))

    _configure(False)
    check("not configured -> start() returns None", ai.start() is None)


# --------------------------------------------------------------------------- wiring + .env only
def test_wiring() -> None:
    print("startup / shutdown wiring, .env only, isolation")
    main_src = (ROOT / "backend" / "main.py").read_text()
    start_at = main_src.find("async def startup_event")
    stop_at = main_src.find("async def shutdown_event")
    check("startup starts the refresher", "agent_identity.start()" in main_src[start_at:stop_at])
    check("shutdown stops it off the event loop",
          "asyncio.to_thread(agent_identity.stop)" in main_src[stop_at:])

    from backend import settings_store
    attrs, envs = set(), set()
    for group in (settings_store._PROVIDER_FIELDS, settings_store._INTEGRATION_FIELDS):
        for specs in group.values():
            for f in specs:
                attrs.add(f.settings_attr or "")
                envs.add((f.env or "").upper())
    keys = {"duo_agent_client_id", "duo_agent_client_secret", "duo_agent_token_url", "duo_agent_scope"}
    check("no DUO_AGENT_* key is a Settings-API field (secrets stay in .env)",
          not (attrs & keys) and not (envs & {k.upper() for k in keys}))

    env_example = (ROOT / ".env.example").read_text()
    for key in sorted(keys):
        check(f".env.example documents {key.upper()} (commented)", f"\n# {key.upper()}=" in env_example)
    run_all = (ROOT / "tests" / "run_all.sh").read_text()
    check("run_all.sh blanks every DUO_AGENT_* key and runs this suite",
          all(f"{k.upper()}=" in run_all for k in keys) and "tests/test_agent_identity.py" in run_all)

    _configure(True)
    identity_isolation.isolate(settings)
    check("isolate() blanks the DUO_AGENT_* keys", not ai.configured()
          and all(getattr(settings, k) == "" for k in keys))
    check("child_env() blanks them for a child process",
          all(identity_isolation.child_env().get(k.upper()) == "" for k in keys))
    before = len(identity_isolation.requests_refused())
    _configure(True)
    identity_isolation.restore()
    ai.request_token()
    refused = identity_isolation.requests_refused()
    check("isolation routes the token request to the refusing transport",
          len(refused) == before + 1 and refused[-1].startswith("POST sso-test0000"), str(refused[before:]))
    identity_isolation.isolate(settings)


def main() -> int:
    try:
        test_inert()
        test_request()
        test_timing()
        test_failures()
        test_redaction()
        test_refresher()
        test_wiring()
    finally:
        ai.stop()
        identity_isolation.isolate(settings)
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
