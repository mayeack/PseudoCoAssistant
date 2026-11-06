#!/usr/bin/env python3
"""Lab 5 identity groundwork (4.22.0): config, session store, the identity
middleware, chat threading, the evidence fields and the identity audit events.

Inert unless configured: with DUO_ENABLED off nothing changes (the cookie is not
even read). With it on, a signed-in turn carries the verified username as
enduser_id plus identity_verified / identity_source on every governance event,
the conversation is owned by that user, and identity only ever comes from the
middleware -- never from a request body or from enduser_id.

Side-effect-safe: a temp SQLite database and log directory, the LLM boundary
stubbed, HEC and Agent Observability off, and no Duo / Identity Intelligence
call anywhere (sessions are created through the store, as the sign-in route
will). Run standalone:

    .venv/bin/python tests/test_identity_sessions.py      # exit 0 = pass
"""
import asyncio
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: E402,F401  (loads .env, CA bundle)
from backend.config import Settings, settings  # noqa: E402

# A throwaway database and log directory, set BEFORE the engine is built.
_TMP = tempfile.mkdtemp(prefix="pseudoco-identity-test-")
settings.database_url = f"sqlite:///{os.path.join(_TMP, 'identity.db')}"
settings.debug = False
KEY = "identity-test-access-key"
settings.access_key = KEY
settings.prewarm_llm = False
settings.duo_enabled = False
settings.hec_host = ""
for _rate in ("pii_injection_rate", "toxic_injection_rate", "hallucination_injection_rate",
              "authority_injection_rate"):
    setattr(settings, _rate, 0.0)

import backend.agents.llm as llm  # noqa: E402
from backend.agents.llm import NormalizedLLMResponse  # noqa: E402


def _fake_llm(*_a, **_k):
    return NormalizedLLMResponse(id="test-id", content="LOW\nAssessment: test. Guidance: rest, fluids.",
                                 model="test-model", input_tokens=5, output_tokens=7, stop_reason="end_turn")


llm.invoke_agent = _fake_llm
llm.invoke_chat = _fake_llm

from fastapi.testclient import TestClient  # noqa: E402

from backend.agents import graph  # noqa: E402
from backend.agents import state as state_mod  # noqa: E402
from backend.database import db as dbmod  # noqa: E402
from backend.logging import identity_audit  # noqa: E402
from backend.logging.governance_logger import governance_logger  # noqa: E402
from backend.main import app  # noqa: E402
from backend.middleware import identity as idmw  # noqa: E402
from backend.models.db_models import AuditLog, Conversation, IdentitySession  # noqa: E402
from backend.models.schemas import ChatCompletionRequest, ChatRequest  # noqa: E402
from backend.routers import chat as chat_router  # noqa: E402
from backend.services import identity_store as store  # noqa: E402
from backend.services.enduser_pool import ENDUSER_IDS  # noqa: E402
from backend.services.recommendation_engine import RecommendationEngine  # noqa: E402
from backend.telemetry import otel  # noqa: E402

governance_logger.set_logs_directory(os.path.join(_TMP, "logs"))
COOKIE = idmw.COOKIE_NAME
H = {"X-Access-Key": KEY}
_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


def ck(token: str, **extra) -> dict:
    return {**H, "Cookie": f"{COOKIE}={token}", **extra}


# --- capture every BUILT event (after create_governance_log / create_audit_log) ---
_built = []
_orig_write_log = governance_logger._write_log


def _capture_write_log(log_data, log_type):
    _built.append((log_type, dict(log_data)))
    return _orig_write_log(log_data, log_type)


governance_logger._write_log = _capture_write_log


def _events(log_type, **match):
    return [e for t, e in _built if t == log_type and all(e.get(k) == v for k, v in match.items())]


# The identity keys of the 12.1 config table (no broker keys).
IDENTITY_SETTINGS = {
    "public_base_url", "duo_enabled", "duo_client_id", "duo_client_secret", "duo_api_host",
    "duo_admin_ikey", "duo_admin_skey", "cii_client_id", "cii_client_secret", "cii_token_url",
    "cii_api_url", "identity_allowed_users", "identity_session_ttl_minutes",
    "identity_status_ttl_seconds", "identity_fail_open",
}


# --------------------------------------------------------------------------- config
def test_config() -> None:
    print("config (12.1 table), inert defaults, .env-only")
    fields = set(Settings.model_fields)
    check("every 12.1 key is a setting (plus HEC_HOST)", (IDENTITY_SETTINGS | {"hec_host"}) <= fields,
          str(sorted((IDENTITY_SETTINGS | {"hec_host"}) - fields)))
    check("no identity-broker keys", not any(f.startswith("identity_broker") or f == "identity_instance_id"
                                             for f in fields))
    d = Settings.model_fields
    check("inert defaults: DUO_ENABLED off, every key empty",
          d["duo_enabled"].default is False and d["hec_host"].default == "" and all(
              d[k].default == "" for k in IDENTITY_SETTINGS
              if k not in ("duo_enabled", "identity_session_ttl_minutes", "identity_status_ttl_seconds",
                           "identity_fail_open")))
    check("TTL 720 min, status cache 10 s, fail open (A3)",
          (d["identity_session_ttl_minutes"].default, d["identity_status_ttl_seconds"].default,
           d["identity_fail_open"].default) == (720, 10, True))
    env_example = (ROOT / ".env.example").read_text()
    for key in sorted(IDENTITY_SETTINGS | {"hec_host"}):
        check(f".env.example documents {key.upper()} (commented)",
              re.search(rf"^# {key.upper()}=", env_example, re.M) is not None)
    version = re.search(r"^APP_VERSION=(\S+)", env_example, re.M)
    check("app_version and APP_VERSION move together (4.22.0)",
          version is not None and version.group(1) == Settings.model_fields["app_version"].default == "4.22.0",
          f"{version.group(1) if version else None} vs {Settings.model_fields['app_version'].default}")

    from backend import settings_store
    attrs, envs = set(), set()
    for group in (settings_store._PROVIDER_FIELDS, settings_store._INTEGRATION_FIELDS):
        for specs in group.values():
            for f in specs:
                attrs.add(f.settings_attr or "")
                envs.add((f.env or "").upper())
    check("no identity key is a Settings-API field (secrets stay in .env)",
          not (attrs & (IDENTITY_SETTINGS | {"hec_host"}))
          and not (envs & {k.upper() for k in IDENTITY_SETTINGS | {"hec_host"}}),
          str(sorted(attrs & IDENTITY_SETTINGS)))

    s = Settings(public_base_url="https://L5-WS-3.PseudoCoAssistant.com/", identity_allowed_users=" Nina.Osei, avery.kim ,,")
    check("duo_redirect_uri = normalized PUBLIC_BASE_URL + /auth/duo/callback",
          s.duo_redirect_uri == "https://l5-ws-3.pseudocoassistant.com/auth/duo/callback", s.duo_redirect_uri)
    check("IDENTITY_ALLOWED_USERS parsed lowercased",
          s.identity_allowed_users_set == frozenset({"nina.osei", "avery.kim"}), str(s.identity_allowed_users_set))
    for url in ("http://l5.pseudocoassistant.com", "https://203.0.113.7", "https://[::1]", "https://127.1",
                "https://u:p@l5.pseudocoassistant.com", "https://l5.pseudocoassistant.com/app",
                "https://l5.pseudocoassistant.com/?next=x", "https://l5.pseudocoassistant.com.", ""):
        bad = Settings(public_base_url=url)
        check(f"not https on a DNS name -> no redirect URI: {url!r}",
              bad.public_base_url_is_https is False and bad.duo_redirect_uri == "")
    check("an explicit port is kept", Settings(public_base_url="https://dev.pseudocoassistant.com:8443")
          .duo_redirect_uri == "https://dev.pseudocoassistant.com:8443/auth/duo/callback")


def test_request_contract() -> None:
    print("identity is never a request field; the turn signatures accept it")
    for model in (ChatRequest, ChatCompletionRequest):
        names = set(model.model_fields)
        check(f"{model.__name__}: no identity_session / enduser_id / identity* field",
              not any(n == "enduser_id" or n.startswith("identity") for n in names), str(sorted(names)))
    snap = store.IdentitySnapshot(session_ref="r", username="nina.osei", created_at=datetime(2026, 1, 1),
                                  expires_at=datetime(2026, 1, 2))
    kw = chat_router._turn_kwargs(ChatRequest(session_id="s", message="m"), {"messages": [], "enduser_id": "x"},
                                  "198.51.100.4", identity=snap)
    check("_turn_kwargs carries the verified identity as identity_session",
          (kw.get("identity_session") or {}).get("username") == "nina.osei")
    check("_turn_kwargs: anonymous -> identity_session None",
          chat_router._turn_kwargs(ChatRequest(session_id="s", message="m"), {"messages": []},
                                   None).get("identity_session", "missing") is None)
    for fn in (graph.run_turn, graph._build_turn_state, RecommendationEngine.process_message):
        params = set(inspect.signature(fn).parameters)
        check(f"{fn.__qualname__} accepts every key the router passes (no silent legacy fallback)",
              set(kw) <= params, str(sorted(set(kw) - params)))
    check("build_initial_state takes identity_session",
          "identity_session" in inspect.signature(state_mod.build_initial_state).parameters)
    declared = state_mod.PseudoCoAssistantState.__annotations__
    check("state declares identity_session and identity_risk (LangGraph drops undeclared keys)",
          {"identity_session", "identity_risk"} <= set(declared))
    st = state_mod.build_initial_state(session_id="s", user_message="m", conversation_history=[],
                                       enduser_id="victim", identity_session=snap.to_state())
    check("a verified identity session names the end user (enduser_id = username)",
          st["enduser_id"] == "nina.osei", st["enduser_id"])
    check("governance overrides: identity_verified/identity_source on a verified turn",
          state_mod.governance_identity_overrides(dict(st, workflow_name="w"))
          == {"workflow_name": "w", "identity_verified": True, "identity_source": "duo"})
    anon = state_mod.build_initial_state(session_id="s", user_message="m", conversation_history=[],
                                         enduser_id="victim")
    check("anonymous turn: enduser_id as passed, no identity keys in the overrides",
          anon["enduser_id"] == "victim" and anon["identity_session"] is None
          and "identity_verified" not in state_mod.governance_identity_overrides(anon))
    check("a session without a username is not an identity",
          state_mod.identity_governance_fields({"source": "duo"}) == {}
          and state_mod.identity_governance_fields("nina.osei") == {})


# --------------------------------------------------------------------------- store
def _db():
    return dbmod.SessionLocal()


def _set_expiry(ref: str, when: datetime) -> None:
    with dbmod.get_db_context() as db:
        db.query(IdentitySession).filter(IdentitySession.id == ref).update({IdentitySession.expires_at: when})
    store.clear_cache()


def test_store() -> None:
    print("session store")
    store._last_purge = time.monotonic()        # no background purge during the suite
    token, snap = store.create("  Nina.Osei ", client_address="203.0.113.7", user_agent="UA/1",
                               duo_txid="1b2c3d4e-0000-4000-8000-000000000001")
    check("token: 32 random bytes, base64url", store.is_token_shaped(token) and len(token) == 43)
    db = _db()
    try:
        row = db.query(IdentitySession).filter(IdentitySession.id == snap.session_ref).first()
        values = [str(getattr(row, c.name)) for c in IdentitySession.__table__.columns]
    finally:
        db.close()
    check("only the sha256 of the cookie is stored", row.token_hash == store.hash_token(token)
          and not any(token in v for v in values))
    check("the public reference is not derived from the token",
          snap.session_ref != row.token_hash and snap.session_ref not in token)
    check("username normalized, TTL from settings, client/agent/txid recorded",
          row.username == "nina.osei" and abs((row.expires_at - row.created_at) - timedelta(minutes=720))
          < timedelta(seconds=1) and row.client_address == "203.0.113.7" and row.user_agent == "UA/1"
          and row.duo_txid.startswith("1b2c3d4e"))
    try:
        snap.username = "x"  # type: ignore[misc]
        frozen = False
    except FrozenInstanceError:
        frozen = True
    check("the snapshot is frozen", frozen)
    check("the snapshot never carries the token", token not in repr(snap) and token not in json.dumps(snap.to_state()))

    res = store.lookup(token)
    check("lookup: valid", res.valid and res.identity.username == "nina.osei")
    check("lookup: garbage and unknown cookies are unknown",
          store.lookup("not-a-token").status == store.UNKNOWN
          and store.lookup(store.new_token()).status == store.UNKNOWN and store.lookup(None).status == store.UNKNOWN)

    # 5 s cache: a second lookup within the TTL never queries the database.
    queries = {"n": 0}
    real_session_local = store.SessionLocal

    def _counting():
        queries["n"] += 1
        return real_session_local()

    store.SessionLocal = _counting
    try:
        store.clear_cache()
        store.lookup(token)
        store.lookup(token)
        store.lookup(token)
    finally:
        store.SessionLocal = real_session_local
    check("lookup: one query per cache TTL", queries["n"] == 1, str(queries))

    # throttled touch
    store.clear_cache()
    t0 = datetime.utcnow() + timedelta(minutes=1)
    store.lookup(token, now=t0)
    store.lookup(token, now=t0 + timedelta(seconds=5))
    db = _db()
    try:
        seen = db.query(IdentitySession).filter(IdentitySession.id == snap.session_ref).first().last_seen_at
    finally:
        db.close()
    check("touch: last-seen recorded, at most once per interval", seen == t0, f"{seen} vs {t0}")

    # expiry wins, on the clock, even from the cache
    check("lookup: expired once past expires_at (cached facts, live clock)",
          store.lookup(token, now=snap.expires_at + timedelta(seconds=1)).status == store.EXPIRED)

    # revoke: tombstone + audit event + cache dropped at once
    store.lookup(token)                                  # warm the cache
    before = len(_events("audit", action=identity_audit.SESSION_REVOKED))
    check("revoke: True the first time", store.revoke(snap.session_ref, reason="duo_disabled"))
    check("revoke: visible immediately (cache dropped)", store.lookup(token).status == store.REVOKED)
    check("revoke: a tombstone keeps answering revoked",
          store.lookup(token).status == store.REVOKED and store.lookup(token).revoked_reason == "duo_disabled")
    check("revoke: second call is a no-op (no second event)", store.revoke(snap.session_ref, reason="x") is False)
    revoked = _events("audit", action=identity_audit.SESSION_REVOKED)
    check("revoke writes exactly one identity_session_revoked event", len(revoked) == before + 1)
    if revoked:
        ev = revoked[-1]
        check("revoked event: user=username, src=sign-in address, actor=system, synthetic session_id",
              ev.get("user") == "nina.osei" and ev.get("src") == "203.0.113.7" and ev.get("actor") == "system"
              and ev.get("session_id") == f"identity-{snap.session_ref}", str(ev))
        check("revoked event: details carry the reason code only",
              ev.get("details") == {"reason": "duo_disabled"}, str(ev.get("details")))

    # end (sign-out) and purge
    t2, s2 = store.create("avery.kim")
    check("end: deletes the session behind the cookie", store.end(t2) and store.lookup(t2).status == store.UNKNOWN)
    t3, s3 = store.create("omar.k")
    t4, s4 = store.create("live.user")
    _set_expiry(s3.session_ref, datetime.utcnow() - timedelta(minutes=1))
    _set_expiry(snap.session_ref, datetime.utcnow() - timedelta(minutes=1))   # the tombstone above
    n = store.purge()
    check("purge: deletes expired rows (tombstones included), keeps live ones",
          n == 2 and store.lookup(t3).status == store.UNKNOWN and store.lookup(token).status == store.UNKNOWN
          and store.lookup(t4).valid, f"purged {n}")
    try:
        store.create("   ")
        rejected = False
    except ValueError:
        rejected = True
    check("create refuses an empty username", rejected)


# --------------------------------------------------------------------------- cookie helper
def test_cookie_helper() -> None:
    print("one cookie helper: Secure; HttpOnly; SameSite=Lax; Path=/")
    from starlette.responses import Response

    r = Response()
    idmw.set_identity_cookie(r, "tok", max_age=60)
    idmw.delete_identity_cookie(r)
    raw = [v.decode() for k, v in r.raw_headers if k == b"set-cookie"]
    check("two raw Set-Cookie headers", len(raw) == 2, str(raw))
    for label, header in zip(("set", "delete"), raw):
        attrs = [a.strip().lower() for a in header.split(";")]
        check(f"{label}: __Host- name, Secure, HttpOnly, SameSite=lax, Path=/, no Domain",
              header.startswith(f"{COOKIE}=") and "secure" in attrs and "httponly" in attrs
              and "samesite=lax" in attrs and "path=/" in attrs and not any(a.startswith("domain") for a in attrs),
              header)
    check("delete: Max-Age=0", "max-age=0" in raw[1].lower(), raw[1])
    check("deletion_header() is what delete_identity_cookie writes",
          idmw.deletion_header()[1].decode().split(";")[0] == raw[1].split(";")[0])
    check("the cookie name follows the naming rule", COOKIE == "__Host-pseudoco_assistant_identity")


# --------------------------------------------------------------------------- middleware (raw ASGI)
async def _echo(scope, receive, send):
    ident = (scope.get("state") or {}).get("identity")
    body = json.dumps({"identity": getattr(ident, "username", None),
                       "kind": type(ident).__name__ if ident is not None else None}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


async def _call(app_, path, *, cookie=None, accept="application/json", state=None):
    headers = [(b"accept", accept.encode())]
    if cookie is not None:
        headers.append((b"cookie", f"other=1; {COOKIE}={cookie}".encode()))
    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": headers, "state": dict(state or {}), "client": ("198.51.100.9", 5000)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app_(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    hdrs = {}
    for k, v in start["headers"]:
        hdrs.setdefault(k.decode().lower(), []).append(v.decode())
    return start["status"], hdrs, body


def test_middleware() -> None:
    print("identity middleware (pure ASGI)")
    mw = idmw.IdentityMiddleware(_echo)
    run = asyncio.run
    good, gsnap = store.create("nina.osei", client_address="203.0.113.7")
    old, osnap = store.create("avery.kim")
    _set_expiry(osnap.session_ref, datetime.utcnow() - timedelta(minutes=1))
    gone, rsnap = store.create("victim.user")
    store.revoke(rsnap.session_ref, reason="duo_disabled")

    settings.duo_enabled = False
    st, _, body = run(_call(mw, "/api/x", cookie=good))
    check("DUO_ENABLED off: a valid cookie is ignored (inert)", st == 200 and json.loads(body)["identity"] is None)
    st, _, _ = run(_call(mw, "/api/x", cookie=old))
    check("DUO_ENABLED off: an expired cookie is not refused", st == 200)
    st, _, body = run(_call(mw, "/api/x", state={"identity": "spoofed"}))
    check("an upstream state.identity is always dropped", json.loads(body)["identity"] is None)

    settings.duo_enabled = True
    try:
        st, hdrs, body = run(_call(mw, "/api/x"))
        check("no cookie: untouched", st == 200 and json.loads(body)["identity"] is None and "set-cookie" not in hdrs)
        st, hdrs, body = run(_call(mw, "/api/x", cookie=good))
        out = json.loads(body)
        check("valid cookie: state.identity is the frozen snapshot",
              st == 200 and out == {"identity": "nina.osei", "kind": "IdentitySnapshot"}, str(out))

        for label, cookie in (("expired", old), ("unknown", store.new_token()), ("garbage", "x" * 10)):
            st, hdrs, body = run(_call(mw, "/api/x", cookie=cookie))
            check(f"{label} (API): 401 identity_session_expired + cookie deleted, no Basic challenge",
                  st == 401 and json.loads(body) == {"detail": "identity_session_expired"}
                  and any(v.startswith(f'{COOKIE}=""') and "Max-Age=0" in v for v in hdrs.get("set-cookie", []))
                  and "www-authenticate" not in hdrs, f"{st} {hdrs}")
        st, hdrs, _ = run(_call(mw, "/app", cookie=old, accept="text/html,application/xhtml+xml"))
        check("expired (browser page): 303 to /login/duo?expired=1 + cookie deleted",
              st == 303 and hdrs.get("location") == ["/login/duo?expired=1"] and "set-cookie" in hdrs, str(hdrs))

        for _ in range(2):
            st, hdrs, body = run(_call(mw, "/api/x", cookie=gone))
            check("revoked (API): 403 identity_session_revoked, cookie kept (tombstone), no Basic challenge",
                  st == 403 and json.loads(body) == {"detail": "identity_session_revoked"}
                  and "set-cookie" not in hdrs and "www-authenticate" not in hdrs, f"{st} {hdrs}")
        st, hdrs, _ = run(_call(mw, "/app", cookie=gone, accept="text/html"))
        check("revoked (browser page): 303 to /login/duo?revoked=1",
              st == 303 and hdrs.get("location") == ["/login/duo?revoked=1"], str(hdrs))

        for path in ("/login/duo", "/auth/duo/callback", "/auth/duo/start", "/auth/identity/logout", "/logout",
                     "/static/js/chat.js", "/health", "/login", "/favicon.ico"):
            codes = [run(_call(mw, path, cookie=c, accept=a))[0]
                     for c in (old, gone) for a in ("application/json", "text/html")]
            check(f"exempt from the refusal: {path}", codes == [200, 200, 200, 200], str(codes))
        st, _, body = run(_call(mw, "/login/duo", cookie=good))
        check("an exempt sign-in path still sees a valid identity", json.loads(body)["identity"] == "nina.osei")
    finally:
        settings.duo_enabled = False


def test_off_event_loop() -> None:
    print("store calls run off the event loop: a hung lookup delays nobody else")
    good, _ = store.create("nina.osei")
    other, _ = store.create("avery.kim")
    hung, _ = store.create("slow.user")
    real_lookup = store.lookup
    threads = []

    def _slow(token, **kw):
        threads.append(threading.current_thread())
        if token == hung:
            time.sleep(1.5)
        return real_lookup(token, **kw)

    async def scenario():
        mw = idmw.IdentityMiddleware(_echo)
        loop_thread = threading.current_thread()
        slow = asyncio.create_task(_call(mw, "/api/x", cookie=hung))
        await asyncio.sleep(0.1)
        t0 = time.monotonic()
        health = await _call(mw, "/health")
        t_health = time.monotonic() - t0
        t0 = time.monotonic()
        peer = await _call(mw, "/api/x", cookie=other)
        t_peer = time.monotonic() - t0
        still_hung = not slow.done()
        await slow
        return loop_thread, health, t_health, peer, t_peer, still_hung, slow.result()

    settings.duo_enabled = True
    store.lookup = _slow
    try:
        loop_thread, health, t_health, peer, t_peer, still_hung, slow = asyncio.run(scenario())
    finally:
        store.lookup = real_lookup
        settings.duo_enabled = False
    check("/health answered while another request's lookup hangs", health[0] == 200 and t_health < 0.5,
          f"{t_health:.2f}s")
    check("another session answered while the lookup hangs",
          peer[0] == 200 and json.loads(peer[2])["identity"] == "avery.kim" and t_peer < 0.5, f"{t_peer:.2f}s")
    check("the hung request was still in flight meanwhile, then completed",
          still_hung and slow[0] == 200 and json.loads(slow[2])["identity"] == "slow.user")
    check("every lookup ran on a worker thread, never the event loop thread",
          threads and all(t is not loop_thread for t in threads))


# --------------------------------------------------------------------------- the app, end to end
def _sse_final(text: str) -> dict:
    frames = [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]
    return next((f for f in frames if f.get("event") == "final"), {})


def test_app(c: TestClient) -> None:
    print("the app: middleware order, inertness, chat threading at all three endpoints")
    order = [m.cls.__name__ for m in app.user_middleware]
    check("RequestLogging -> AccessKey -> Identity -> ChatBodyLimit -> CORS",
          order == ["RequestLoggingMiddleware", "AccessKeyMiddleware", "IdentityMiddleware",
                    "ChatBodyLimitMiddleware", "CORSMiddleware"], str(order))

    spans = []
    real_span = otel.workflow_span

    def _span(**kw):
        spans.append(kw)
        return real_span(**kw)

    otel.workflow_span = _span
    nina, nsnap = store.create("Nina.Osei", client_address="203.0.113.7")
    avery, _ = store.create("avery.kim")
    try:
        # ---- inert: DUO_ENABLED off ----
        settings.duo_enabled = False
        sid = str(uuid.uuid4())
        r = c.post("/api/chat/message", headers=ck(nina),
                   json={"session_id": sid, "message": "mild sore throat", "disclaimer_accepted": True})
        last = (_events("governance", session_id=sid) or [{}])[-1]
        check("off: a signed-in cookie changes nothing (pool enduser_id, no identity keys)",
              r.status_code == 200 and last.get("enduser_id") in ENDUSER_IDS
              and "identity_verified" not in last and "identity_source" not in last, str(last)[:300])
        check("off: an expired cookie is not refused",
              c.get("/api/chat/disclaimer", headers=ck(store.new_token())).status_code == 200)

        settings.duo_enabled = True
        # ---- refusals through the real stack ----
        r = c.get("/api/chat/disclaimer", headers=ck(store.new_token()))
        check("on: unknown cookie -> 401 identity_session_expired, no WWW-Authenticate",
              r.status_code == 401 and r.json() == {"detail": "identity_session_expired"}
              and "www-authenticate" not in r.headers, f"{r.status_code} {r.text[:120]}")
        r = c.get("/app", headers=ck(store.new_token(), accept="text/html"), follow_redirects=False)
        check("on: browser page with an unknown cookie -> 303 /login/duo?expired=1",
              r.status_code == 303 and r.headers.get("location") == "/login/duo?expired=1", str(r.headers))
        check("on: the room-key gate still answers first (no key -> 401 Basic)",
              c.get("/api/chat/disclaimer", headers={"Cookie": f"{COOKIE}={nina}"}).status_code == 401)
        check("on: /health is untouched", c.get("/health", headers={"Cookie": f"{COOKIE}={nina}"}).status_code == 200)

        # ---- /message, signed in ----
        sid = str(uuid.uuid4())
        spans.clear()
        r = c.post("/api/chat/message", headers=ck(nina),
                   json={"session_id": sid, "message": "mild sore throat", "disclaimer_accepted": True})
        evs = _events("governance", session_id=sid)
        last = evs[-1] if evs else {}
        check("/message signed in -> 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
        check("built governance event: enduser_id/user = the verified username",
              last.get("enduser_id") == "nina.osei" and last.get("user") == "nina.osei", str(last)[:300])
        check("built governance event: identity_verified=True, identity_source=duo",
              last.get("identity_verified") is True and last.get("identity_source") == "duo")
        check("every governance event of the turn carries the identity fields",
              evs and all(e.get("identity_verified") is True for e in evs))
        check("workflow span gets enduser.id + client.address (run_turn)",
              spans and spans[-1].get("enduser_id") == "nina.osei" and spans[-1].get("client_address") == "testclient",
              str(spans[-1:]))
        db = _db()
        try:
            conv = db.query(Conversation).filter(Conversation.session_id == sid).first()
            audit = db.query(AuditLog).filter(AuditLog.session_id == sid, AuditLog.action == "session_started").first()
        finally:
            db.close()
        check("the owner is recorded in conversation_metadata",
              (conv.conversation_metadata or {}).get("identity_owner") == "nina.osei", str(conv.conversation_metadata))
        check("AuditLog.enduser_id filled (session_started)", audit is not None and audit.enduser_id == "nina.osei")

        # ---- ownership: 409 to anyone else, 404 on read ----
        body = {"session_id": sid, "message": "another question", "disclaimer_accepted": True}
        check("another identity -> 409 (/message)",
              c.post("/api/chat/message", headers=ck(avery), json=body).status_code == 409)
        check("another identity -> 409 (/message/stream, before any SSE frame)",
              c.post("/api/chat/message/stream", headers=ck(avery), json=body).status_code == 409)
        check("anonymous -> 409 on an owned conversation", c.post("/api/chat/message", headers=H, json=body).status_code == 409)
        check("GET session: owner 200", c.get(f"/api/chat/session/{sid}", headers=ck(nina)).status_code == 200)
        check("GET session: another identity 404", c.get(f"/api/chat/session/{sid}", headers=ck(avery)).status_code == 404)
        check("GET session: anonymous 404", c.get(f"/api/chat/session/{sid}", headers=H).status_code == 404)
        chat_router.sessions.pop(sid, None)                      # evicted: the DB owner still rules
        check("after eviction: another identity still 409 (owner read from the database)",
              c.post("/api/chat/message", headers=ck(avery), json=body).status_code == 409)
        check("after eviction: GET still 404 to another identity",
              c.get(f"/api/chat/session/{sid}", headers=ck(avery)).status_code == 404)
        r = c.post("/api/chat/message", headers=ck(nina), json=body)
        resumed = (_events("governance", session_id=sid) or [{}])[-1]
        check("after eviction: the owner resumes, enduser_id = username",
              r.status_code == 200 and resumed.get("enduser_id") == "nina.osei")

        # ---- /message/stream, signed in ----
        sid2 = str(uuid.uuid4())
        spans.clear()
        r = c.post("/api/chat/message/stream", headers=ck(nina),
                   json={"session_id": sid2, "message": "mild headache", "disclaimer_accepted": True})
        last = (_events("governance", session_id=sid2) or [{}])[-1]
        check("/message/stream signed in -> final frame", r.status_code == 200 and _sse_final(r.text).get("message"))
        check("/message/stream: the built event carries the verified identity",
              last.get("enduser_id") == "nina.osei" and last.get("identity_verified") is True)
        check("workflow span gets enduser.id + client.address (run_turn_stream)",
              spans and spans[-1].get("enduser_id") == "nina.osei" and spans[-1].get("client_address") == "testclient")

        # ---- /completions, signed in ----
        seen = []
        real_dispatch = chat_router._dispatch_chat_turn

        def _dispatch(**kw):
            seen.append(kw)
            return real_dispatch(**kw)

        chat_router._dispatch_chat_turn = _dispatch
        try:
            r = c.post("/api/chat/completions", headers=ck(nina),
                       json={"messages": [{"role": "user", "content": "mild cough"}],
                             "identity_session": {"username": "victim.user"}, "enduser_id": "victim.user"})
        finally:
            chat_router._dispatch_chat_turn = real_dispatch
        sid3 = (r.json().get("pseudoco_assistant_turn") or {}).get("session_id") if r.status_code == 200 else None
        last = (_events("governance", session_id=sid3) or [{}])[-1]
        check("/completions signed in -> 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
        check("/completions: the turn gets the middleware's identity, not the body's",
              seen and (seen[-1].get("identity_session") or {}).get("username") == "nina.osei"
              and seen[-1].get("enduser_id") == "nina.osei", str(seen[-1:])[:300])
        check("/completions: built event carries the verified identity",
              last.get("enduser_id") == "nina.osei" and last.get("identity_source") == "duo")
        check("/completions: the new conversation is owned by the signed-in user",
              c.get(f"/api/chat/session/{sid3}", headers=ck(avery)).status_code == 404)

        # ---- anonymous turns, and body injection ----
        sid4 = str(uuid.uuid4())
        r = c.post("/api/chat/message", headers=H,
                   json={"session_id": sid4, "message": "mild sore throat", "disclaimer_accepted": True,
                         "identity_session": {"username": "victim.user", "source": "duo"},
                         "enduser_id": "victim.user"})
        last = (_events("governance", session_id=sid4) or [{}])[-1]
        check("anonymous: body identity_session / enduser_id are ignored",
              r.status_code == 200 and last.get("enduser_id") in ENDUSER_IDS
              and "identity_verified" not in last and "identity_source" not in last, str(last)[:300])
        r = c.post("/api/chat/message", headers=ck(avery),
                   json={"session_id": sid4, "message": "follow up", "disclaimer_accepted": True})
        last = (_events("governance", session_id=sid4) or [{}])[-1]
        check("an unowned conversation is claimed by the signed-in user who resumes it",
              r.status_code == 200 and last.get("enduser_id") == "avery.kim"
              and c.get(f"/api/chat/session/{sid4}", headers=H).status_code == 404)

        # ---- revocation through the real stack ----
        store.revoke(nsnap.session_ref, reason="duo_disabled")
        for _ in range(2):
            r = c.post("/api/chat/message", headers=ck(nina),
                       json={"session_id": str(uuid.uuid4()), "message": "hi", "disclaimer_accepted": True})
            check("revoked: every request answers 403 identity_session_revoked",
                  r.status_code == 403 and r.json() == {"detail": "identity_session_revoked"}, r.text[:120])
        check("revoked: /login (room-key form) still renders", c.get("/login", headers=ck(nina)).status_code == 200)
        db = _db()
        try:
            row = db.query(AuditLog).filter(AuditLog.action == "identity_session_revoked",
                                            AuditLog.session_id == f"identity-{nsnap.session_ref}").first()
        finally:
            db.close()
        check("identity_session_revoked lands in audit_logs with enduser_id",
              row is not None and row.enduser_id == "nina.osei" and row.ip_address == "203.0.113.7")
    finally:
        otel.workflow_span = real_span
        settings.duo_enabled = False


# --------------------------------------------------------------------------- audit helpers
def test_audit_events() -> None:
    print("identity audit events (built)")
    before = len(_built)
    identity_audit.log_signin_success(username="Nina.Osei", client_address="203.0.113.7", session_ref="abc123",
                                      duo_txid="0f1e2d3c-1111-4222-8333-444455556666", trust_level="neutral")
    identity_audit.log_signin_failure(username="Bad\x00User\nname", client_address="198.51.100.9",
                                      reason="not on the allowlist!", duo_txid="<script>")
    new = [e for t, e in _built[before:] if t == "audit"]
    check("two audit events built", len(new) == 2, str(len(new)))
    if len(new) == 2:
        ok, bad = new
        check("success: action, actor=user, user=username, src=client IP",
              ok["action"] == "identity_signin_success" and ok["actor"] == "user" and ok["user"] == "nina.osei"
              and ok["src"] == "203.0.113.7" and ok["ip_address"] == "203.0.113.7", str(ok))
        check("success: details are the Duo txid and trust only",
              ok["details"] == {"duo_txid": "0f1e2d3c-1111-4222-8333-444455556666", "trust_level": "NEUTRAL"},
              str(ok["details"]))
        check("success: synthetic non-null session_id from the session reference", ok["session_id"] == "identity-abc123")
        check("failure: the typed username is cleaned (control characters dropped, lowercased)",
              bad["user"] == "badusername", repr(bad.get("user")))
        check("failure: reason code sanitized, malformed txid dropped",
              bad["details"] == {"reason": "other"}, str(bad["details"]))
        check("failure: a fresh synthetic session_id",
              re.fullmatch(r"identity-[0-9a-f]{32}", bad["session_id"]) is not None, bad["session_id"])
        check("details never carry a location / device / Duo-seen IP",
              all(set(e["details"]) <= identity_audit.DETAIL_KEYS for e in new))
    try:
        identity_audit.log_identity_event("identity_whatever", username="x", client_address=None)
        refused = False
    except ValueError:
        refused = True
    check("only the three identity actions are accepted", refused)


def test_hec_and_ao() -> None:
    print("HEC envelope and Agent Observability metadata")
    from backend.hec.config import HECConfig, effective_host
    from backend.hec.forwarder import HECForwarder

    audit = (_events("audit", action="identity_signin_success") or [{}])[-1]
    fwd = HECForwarder(HECConfig(id="t", name="t", url="https://localhost:8088"), "tok")
    env = fwd._build_event("audit", audit)
    check("user / enduser_id are never promoted to indexed HEC fields",
          env["fields"] == {"log_type": "audit"} and env["event"].get("user") == "nina.osei", str(env["fields"]))
    check("HEC host: medadvice by default", env["host"] == "medadvice")
    settings.hec_host = "l5-ws-3"
    try:
        check("HEC_HOST stamps every destination's events",
              HECForwarder(HECConfig(id="t", host="custom-host", url="https://localhost:8088"), "t")
              ._build_event("audit", audit)["host"] == "l5-ws-3")
    finally:
        settings.hec_host = ""
    check("HEC_HOST empty keeps a destination's own host", effective_host("custom-host") == "custom-host"
          and effective_host("") == "medadvice")

    import backend.agent_observability as ao

    class _Rec:
        def __init__(self):
            self.calls = []

        def start_trace(self, **k):
            self.calls.append(("start_trace", k))
            return object()

        def __getattr__(self, name):
            return lambda **k: self.calls.append((name, k))

    gov = (_events("governance", identity_source="duo") or [{}])[-1]
    rec = _Rec()
    ao._build_turn(rec, gov)
    wf = next((k for n, k in rec.calls if n == "add_workflow_span"), {})
    meta = wf.get("metadata") or {}
    check("Agent Observability span metadata carries identity_verified / identity_source",
          meta.get("identity_verified") is True and meta.get("identity_source") == "duo"
          and meta.get("enduser_id") == gov.get("enduser_id") and bool(gov.get("enduser_id")), str(meta)[:300])
    anon = next((e for t, e in reversed(_built) if t == "governance" and e.get("operation_name") == "chat"
                 and "identity_source" not in e), {})
    rec = _Rec()
    ao._build_turn(rec, anon)
    meta = next((k for n, k in rec.calls if n == "add_workflow_span"), {}).get("metadata") or {}
    check("an anonymous turn adds no identity keys to the span metadata",
          bool(anon) and "identity_verified" not in meta and "identity_source" not in meta)


def test_legacy_engine() -> None:
    print("legacy engine: the same identity evidence (the agentic path's fallback)")
    snap = store.IdentitySnapshot(session_ref="legacy-ref", username="nina.osei", created_at=datetime(2026, 1, 1),
                                  expires_at=datetime(2026, 1, 2))
    sid = f"legacy-{uuid.uuid4().hex[:8]}"
    # A policy-blocked turn: logged before any model call, so nothing is stubbed.
    RecommendationEngine().process_message(session_id=sid, user_message="I want to end my life",
                                           conversation_history=[], enduser_id="victim.user",
                                           identity_session=snap.to_state())
    last = (_events("governance", session_id=sid) or [{}])[-1]
    check("legacy: the verified username is the end user, with identity_verified / identity_source",
          last.get("policy_blocked") is True and last.get("enduser_id") == "nina.osei"
          and last.get("identity_verified") is True and last.get("identity_source") == "duo", str(last)[:300])
    sid = f"legacy-{uuid.uuid4().hex[:8]}"
    RecommendationEngine().process_message(session_id=sid, user_message="I want to end my life",
                                           conversation_history=[], enduser_id="t.nguyen")
    last = (_events("governance", session_id=sid) or [{}])[-1]
    check("legacy: an anonymous turn is unchanged (no identity keys)",
          last.get("enduser_id") == "t.nguyen" and "identity_verified" not in last)


def main() -> int:
    check("temp DB in use (never the app's medadvice.db)", _TMP in str(dbmod.engine.url), str(dbmod.engine.url))
    dbmod.init_db()                        # the temp database's tables
    test_config()
    test_request_contract()
    test_store()
    test_cookie_helper()
    test_middleware()
    test_off_event_loop()
    with TestClient(app) as c:
        # Startup re-points the governance JSONL at the configured directory.
        governance_logger.set_logs_directory(os.path.join(_TMP, "logs"))
        test_app(c)
    test_audit_events()
    test_hec_and_ao()
    test_legacy_engine()
    dbmod.engine.dispose()
    shutil.rmtree(_TMP, ignore_errors=True)
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
