#!/usr/bin/env python3
"""Lab 5 Identity Risk Gate and Duo-driven revocation (plan 12.1, PR-3).

Covers the status lookup (Duo Admin API request signing, the CII OAuth token
and GraphQL query, caching, sanitized failures, CII still asked with the
remembered Duo email while Duo is down, "no such user" as an answer), the pure
decide(), the identity_risk node in both engines, the revocation pull in the
identity middleware, Unblock me (POST /api/identity/unblock and /reblock, the
audit events, identity_override on later events, and that only an override
which brought a Duo-revoked session back holds it open), the identity store's
cache generation, and the rules: no Demo Controls card, no request field, no
network call to Duo or CII except through the fakes below.

Side-effect-safe: a temp SQLite database and log directory, the LLM stubbed,
HEC and Agent Observability off, and every Duo / CII request answered by an
httpx.MockTransport. Run standalone:

    .venv/bin/python tests/test_identity_gate.py      # exit 0 = pass
"""
import base64
import copy
import inspect
import json
import os
import shutil
import sys
import tempfile
import urllib.parse
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: E402,F401  (loads .env, CA bundle)
from backend.config import settings  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="pseudoco-identity-gate-test-")
settings.database_url = f"sqlite:///{os.path.join(_TMP, 'gate.db')}"
settings.debug = False
KEY = "identity-gate-test-access-key"
settings.access_key = KEY
settings.prewarm_llm = False
settings.hec_host = ""
for _rate in ("pii_injection_rate", "toxic_injection_rate", "hallucination_injection_rate",
              "authority_injection_rate"):
    setattr(settings, _rate, 0.0)

IKEY = "DIWJ8X6AEYOR5OMC6TQ1"
SKEY = "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"
DUO_HOST = "api-test0001.duosecurity.com"
CII_TOKEN_URL = "https://auth.cii.example/oauth2/token"
CII_API_URL = "https://api.cii.example/graphql"
CII_SECRET = "cii-secret-value-0001"


def _configure(on: bool = True) -> None:
    settings.duo_enabled = on
    settings.duo_admin_ikey, settings.duo_admin_skey, settings.duo_api_host = (IKEY, SKEY, DUO_HOST) if on else ("", "", "")
    settings.cii_client_id = "cii-client" if on else ""
    settings.cii_client_secret = CII_SECRET if on else ""
    settings.cii_token_url = CII_TOKEN_URL if on else ""
    settings.cii_api_url = CII_API_URL if on else ""
    settings.identity_fail_open = True
    settings.identity_status_ttl_seconds = 10


_configure(False)
import identity_isolation  # noqa: E402  (no real Duo / CII, whatever .env holds)

identity_isolation.isolate(settings)

import backend.agents.llm as llm  # noqa: E402
from backend.agents.llm import NormalizedLLMResponse  # noqa: E402

_LLM_CALLS = []


def _fake_llm(*_a, **_k):
    _LLM_CALLS.append(_k.get("agent_name"))
    return NormalizedLLMResponse(id="test-id", content="LOW\nAssessment: test. Guidance: rest, fluids.",
                                 model="test-model", input_tokens=5, output_tokens=7, stop_reason="end_turn")


llm.invoke_agent = _fake_llm
llm.invoke_chat = _fake_llm

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend import settings_store  # noqa: E402
from backend.agents import graph  # noqa: E402
from backend.agents.blueprints import guardrails  # noqa: E402
from backend.database import db as dbmod  # noqa: E402
from backend.logging import identity_audit  # noqa: E402
from backend.logging.governance_logger import governance_logger  # noqa: E402
from backend.main import app  # noqa: E402
from backend.middleware import identity as idmw  # noqa: E402
from backend.models.schemas import ChatCompletionRequest, ChatRequest  # noqa: E402
from backend.services import identity_gate as gate  # noqa: E402
from backend.services import identity_lookup as lookup  # noqa: E402
from backend.services import identity_store as store  # noqa: E402
from backend.services.recommendation_engine import RecommendationEngine  # noqa: E402

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


# Every BUILT event (after create_governance_log / create_audit_log).
_built = []
_orig_write_log = governance_logger._write_log


def _capture_write_log(log_data, log_type):
    _built.append((log_type, dict(log_data)))
    return _orig_write_log(log_data, log_type)


governance_logger._write_log = _capture_write_log


def _events(log_type, **match):
    return [e for t, e in _built if t == log_type and all(e.get(k) == v for k, v in match.items())]


def _audits(action):
    return [e for t, e in _built if t == "audit" and e.get("action") == action]


def _revoked(user):
    return [e for e in _audits("identity_session_revoked") if e.get("user") == user]


# --------------------------------------------------------------------------- fake Duo + CII
class FakeServices:
    """Answers the Duo Admin API and the CII token + GraphQL endpoints. Checks
    every Duo signature the way Duo would, and records every request."""

    def __init__(self):
        self.requests = []
        self.duo = {}          # username -> {"status", "email"}
        self.cii = {}          # login (email) -> {"levelOfTrust", "failingChecks"}
        self.tokens_issued = 0
        self.valid_tokens = set()
        self.fail = None       # None | "duo_500" | "duo_connect" | "duo_timeout" | "cii_500" | "cii_401_once"
        self.bad_signatures = 0
        self.cii_body = None   # a GraphQL answer to send (HTTP 200) instead of the user's record

    def set_user(self, username, status="active", trust="TRUSTED", failing=()):
        email = f"{username}@pseudocoassistant.com"
        self.duo[username] = {"status": status, "email": email}
        self.cii[email] = {"levelOfTrust": trust, "failingChecks": list(failing)}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host == DUO_HOST:
            return self._duo(request)
        if str(request.url) == CII_TOKEN_URL:
            return self._token(request)
        if str(request.url) == CII_API_URL:
            return self._graphql(request)
        return httpx.Response(404, json={"error": "unknown host"})

    def _duo(self, request):
        if self.fail == "duo_connect":
            raise httpx.ConnectError("refused", request=request)
        if self.fail == "duo_timeout":
            raise httpx.ReadTimeout("slow", request=request)
        if self.fail == "duo_500":
            return httpx.Response(500, text=f"<html>error at {request.url} key {IKEY}</html>")
        params = dict(urllib.parse.parse_qsl(request.url.query.decode()))
        auth = lookup.duo_sign(IKEY, SKEY, request.method, DUO_HOST, request.url.path,
                               {k: [v] for k, v in params.items()}, request.headers.get("date", ""))
        if request.method != "GET" or request.headers.get("authorization") != auth:
            self.bad_signatures += 1
            return httpx.Response(401, json={"stat": "FAIL", "code": 40103, "message": "Invalid signature"})
        user = self.duo.get(params.get("username", ""))
        users = [] if user is None else [{"user_id": "DU1", "username": params["username"],
                                          "status": user["status"], "email": user["email"]}]
        return httpx.Response(200, json={"stat": "OK", "response": users})

    def _token(self, request):
        body = json.loads(request.content or b"{}")
        if body != {"client_id": "cii-client", "client_secret": CII_SECRET, "grant_type": "client_credentials"}:
            return httpx.Response(401, json={"error": "invalid_client"})
        self.tokens_issued += 1
        token = f"tok-{self.tokens_issued}"
        self.valid_tokens.add(token)
        return httpx.Response(200, json={"access_token": token, "token_type": "Bearer", "expires_in": 36000})

    def _graphql(self, request):
        if self.fail == "cii_500":
            return httpx.Response(500, text="boom")
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if self.fail == "cii_401_once":
            self.fail = None
            self.valid_tokens.discard(token)
        if token not in self.valid_tokens:
            return httpx.Response(401, json={"message": "Unauthorized"})
        body = json.loads(request.content)
        if body.get("query") != lookup.CII_END_USER_QUERY:
            return httpx.Response(400, json={"errors": [{"message": "unexpected query"}]})
        if self.cii_body is not None:
            return httpx.Response(200, json=self.cii_body)
        login = body.get("variables", {}).get("login")
        user = self.cii.get(login)
        if user is None:
            # The published schema's answer for a user CII has no record of
            # (GetEndUserOutput! with null details), the same as the Mac's
            # tests/lab5_fakes.FakeCII; the other "no such user" shapes are in
            # tests/fixtures/cii_end_user_answers.json.
            return httpx.Response(200, json={"data": {"getEndUser": {"endUserDetails": None,
                                                                     "providerEndUserDetails": []}}})
        return httpx.Response(200, json={"data": {"getEndUser": {"endUserDetails": {
            "login": login, "status": "ACTIVE", "failingChecks": user["failingChecks"],
            "endUserTrustScore": {"levelOfTrust": user["levelOfTrust"], "lastUpdated": "2026-11-05T09:00:00Z"}}}}})

    def count(self, *, host=None, url=None):
        return sum(1 for r in self.requests
                   if (host is None or r.url.host == host) and (url is None or str(r.url) == url))


FAKE = FakeServices()


def _fresh_fake() -> FakeServices:
    global FAKE
    FAKE = FakeServices()
    lookup.set_transport(httpx.MockTransport(FAKE))
    return FAKE


# --------------------------------------------------------------------------- signing
def test_signer() -> None:
    print("Duo Admin API request signing (known answers from duo_client 5.7.0, signature v5)")
    date = "Tue, 21 Aug 2012 17:29:18 -0000"
    vectors = [
        ("api-xxxxxxxx.duosecurity.com", {"username": ["nina.osei"]},
         "RElXSjhYNkFFWU9SNU9NQzZUUTE6YjA2ZGY4OWQ2YTNiNGVlNDhiNThjYjg1ZmU5MjI2ZDBmZDk3YjhkNDRmN2MxMjRmODcxNjMwMDFhNDQxNGI3M2EzMTZhN2Q1MzJhY2IwNTAzOTQ4NjExNmUyNzU1MTQyZTRjOTRiMDU2NmVmOThiYjhiNDgwNmNlZGYwMzBkNzE="),
        ("API-XXXXXXXX.DuoSecurity.com", {"username": ["facilitator@pseudocoassistant.com"]},
         "RElXSjhYNkFFWU9SNU9NQzZUUTE6YjBkOTg1ODNiMzdjOTdhZDc5OWQxZjZlZTgzYzBiNWJmNjgyNGExYTU5YWM4MDkzYWQxNGQ0NWQ2OTVmYzNmN2U2MmMxMDViYjY2ZWM5NTVkYjMyNWU2MTY3ODM2ZjJlZTJhMGFiNzJiZDBmMWIzNmMxM2U4YzI3YmEwMjQwNjM="),
        ("api-xxxxxxxx.duosecurity.com", {"username": ["j d+x~y"], "limit": ["1"]},
         "RElXSjhYNkFFWU9SNU9NQzZUUTE6ZGZlMDdkNjAxYTYwMzM3NGMxMDI0N2ZjNmRkZDk5NjYzZTYwNDhhMzUzNGU5YWFlNDQyNDUyZmY0OTA5ZTU4ZmNhMzY3NjhkMDRlYzkzZjY2YWM3ODc0MWFlZjY2ZDU1YTE4ZjA2NWM2NzI2ZjY3YTBmMzdhNDFkY2E3ZTJmMmI="),
    ]
    for host, params, expected in vectors:
        got = lookup.duo_sign(IKEY, SKEY, "GET", host, "/admin/v1/users", params, date)
        check(f"signature matches duo_client for {params}", got == "Basic " + expected, got)
    canon = lookup.duo_canonicalize("get", "API-X.duosecurity.com", "/admin/v1/users",
                                    {"username": ["j d+x~y"], "limit": "1"}, date)
    lines = canon.split("\n")
    check("canonical request: date, METHOD, host (lowercase), path, sorted RFC 3986 params, two SHA-512s",
          lines[:5] == [date, "GET", "api-x.duosecurity.com", "/admin/v1/users", "limit=1&username=j%20d%2Bx~y"]
          and len(lines) == 7 and all(len(x) == 128 for x in lines[5:]), canon)
    user, _, sig = base64.b64decode(lookup.duo_sign(IKEY, SKEY, "GET", DUO_HOST, "/p", {}, date)[6:]).decode().partition(":")
    check("Basic auth: the integration key as user, a 128-hex HMAC-SHA512 as password",
          user == IKEY and len(sig) == 128 and all(c in "0123456789abcdef" for c in sig))


# --------------------------------------------------------------------------- lookup
def test_lookup() -> None:
    print("status lookup: Duo + CII through the fakes, cached, never raises, sanitized")
    _configure(False)
    fake = _fresh_fake()
    st = lookup.lookup("nina.osei")
    check("inert unless configured: no request, both sources not_configured, unavailable",
          fake.requests == [] and st["sources"] == {"duo": "not_configured", "cii": "not_configured"}
          and st["available"] is False, str(st))
    check("bounded: 3 s connect, 5 s read",
          lookup.TIMEOUT.connect == 3.0 and lookup.TIMEOUT.read == 5.0)

    _configure(True)
    fake = _fresh_fake()
    fake.set_user("nina.osei", trust="QUESTIONABLE")
    fake.set_user("avery.kim", status="locked out", trust="UNTRUSTED", failing=["MFA Flood", "Impossible Travel"])
    st = lookup.lookup("Nina.Osei ")
    check("Duo status, CII trust level and failing checks, both sources ok",
          st["duo_status"] == "active" and st["trust_level"] == "QUESTIONABLE" and st["failing_checks"] == []
          and st["available"] is True and st["sources"] == {"duo": "ok", "cii": "ok"} and st["as_of"], str(st))
    duo_req = next(r for r in fake.requests if r.url.host == DUO_HOST)
    check("Duo: GET /admin/v1/users?username= over https, Date header, signature accepted",
          duo_req.method == "GET" and duo_req.url.scheme == "https" and duo_req.url.path == "/admin/v1/users"
          and dict(urllib.parse.parse_qsl(duo_req.url.query.decode())) == {"username": "nina.osei"}
          and duo_req.headers.get("date") and fake.bad_signatures == 0)
    gql = next(r for r in fake.requests if str(r.url) == CII_API_URL)
    check("CII: the one GraphQL query, the Duo email as login, a Bearer token",
          json.loads(gql.content) == {"query": lookup.CII_END_USER_QUERY,
                                      "variables": {"login": "nina.osei@pseudocoassistant.com"}}
          and gql.headers.get("authorization") == "Bearer tok-1")
    check("the query asks getEndUser for failingChecks and endUserTrustScore.levelOfTrust",
          all(t in lookup.CII_END_USER_QUERY for t in ("getEndUser(login: $login)", "failingChecks",
                                                        "endUserTrustScore", "levelOfTrust")))
    n = len(fake.requests)
    lookup.lookup("nina.osei")
    check("cached: a second lookup inside IDENTITY_STATUS_TTL_SECONDS sends nothing", len(fake.requests) == n)
    st = lookup.lookup("avery.kim")
    check("Duo's 'locked out' normalizes to locked_out; checks come through",
          st["duo_status"] == "locked_out" and st["trust_level"] == "UNTRUSTED"
          and st["failing_checks"] == ["MFA Flood", "Impossible Travel"], str(st))
    check("the CII token is fetched once and reused (client credentials in the JSON body)",
          fake.tokens_issued == 1 and fake.count(url=CII_TOKEN_URL) == 1)
    lookup.clear_cache()                 # drops the answers and the token
    before, queries = fake.tokens_issued, fake.count(url=CII_API_URL)
    fake.fail = "cii_401_once"
    st = lookup.lookup("nina.osei")
    check("a 401 from the API refreshes the token once and retries",
          st["available"] is True and fake.tokens_issued == before + 2
          and fake.count(url=CII_API_URL) == queries + 2, f"{st} {fake.tokens_issued - before}")

    lookup.clear_cache()
    n = fake.count(url=CII_API_URL)
    st = lookup.lookup("ghost.user")
    check("a user Duo does not know: duo not_found; with no CII login to ask, CII says so (never not_found)",
          st["sources"] == {"duo": "not_found", "cii": "unavailable"} and st["errors"] == {"cii": "no_login"}
          and st["available"] is False and fake.count(url=CII_API_URL) == n, str(st))
    fake.duo["mail.only"] = {"status": "active", "email": "mail.only@pseudocoassistant.com"}
    st = lookup.lookup("mail.only")
    v = gate.decide(st)
    check("a user CII does not know (a new account): cii not_found is an answer, not an outage: check ok, allowed",
          st["sources"] == {"duo": "ok", "cii": "not_found"} and st["available"] is True
          and v["check"] == "ok" and v["verdict"] == "allow" and v["trust_level"] is None, f"{st} {v}")

    check("Duo's email is remembered beyond the answer cache (clear_cache keeps it)",
          lookup.remembered_email("Nina.Osei") == "nina.osei@pseudocoassistant.com")
    for mode, code in (("duo_500", "http_500"), ("duo_connect", "connect_error"), ("duo_timeout", "timeout")):
        lookup.clear_cache()
        fake.fail = mode
        queries = fake.count(url=CII_API_URL)
        try:
            st = lookup.lookup("nina.osei")
            raised = False
        except Exception:  # noqa: BLE001
            raised, st = True, {}
        text = json.dumps(st)
        check(f"Duo {mode}: no exception, unavailable with a fixed code, nothing leaked",
              not raised and st.get("sources", {}).get("duo") == "unavailable" and st.get("errors", {}).get("duo") == code
              and DUO_HOST not in text and IKEY not in text and SKEY not in text and "<html>" not in text, text)
        check(f"Duo {mode}: CII is still asked, with the email Duo last gave",
              st.get("sources", {}).get("cii") == "ok" and st.get("trust_level") == "QUESTIONABLE"
              and fake.count(url=CII_API_URL) == queries + 1, text)
    lookup.clear_cache()
    fake.fail = "duo_500"
    st = lookup.lookup("avery.kim")
    v = gate.decide(st)
    check("Duo down: a CII block still holds (UNTRUSTED, failing checks), check unavailable",
          st["sources"] == {"duo": "unavailable", "cii": "ok"} and v["verdict"] == "block"
          and v["reasons"] == ["trust_untrusted", "mfa_flood", "impossible_travel"] and v["check"] == "unavailable",
          f"{st} {v}")
    lookup.forget_emails()
    lookup.clear_cache()
    queries = fake.count(url=CII_API_URL)
    st = lookup.lookup("nina.osei")
    check("Duo down and no email known yet: CII is not asked, and the answer says so (no_login)",
          st["sources"] == {"duo": "unavailable", "cii": "unavailable"}
          and st["errors"] == {"duo": "http_500", "cii": "no_login"} and fake.count(url=CII_API_URL) == queries,
          str(st))
    fake.fail = None
    lookup.clear_cache()
    lookup.lookup("nina.osei")
    fake.duo["nina.osei"]["email"] = ""
    lookup.clear_cache()
    st = lookup.lookup("nina.osei")
    check("a Duo answer without an email forgets the remembered one (no CII login to ask)",
          lookup.remembered_email("nina.osei") is None and st["errors"] == {"cii": "no_login"}, str(st))
    fake.duo["nina.osei"]["email"] = "nina.osei@pseudocoassistant.com"
    lookup.clear_cache()
    lookup.lookup("nina.osei")
    fake = _fresh_fake()
    check("set_transport (a fresh fake) forgets the remembered emails", lookup.remembered_email("nina.osei") is None)
    fake.set_user("nina.osei", trust="QUESTIONABLE")
    lookup.clear_cache()
    n = len(fake.requests)
    lookup.lookup("nina.osei")
    lookup.lookup("nina.osei")
    check("a failure is cached too, and so is the recovery (one Duo call per window)",
          fake.count(host=DUO_HOST) - sum(1 for r in fake.requests[:n] if r.url.host == DUO_HOST) == 1)

    settings.cii_token_url = "http://auth.cii.example/oauth2/token"
    check("CII over plain http is never configured (no secret over http)", not lookup.cii_configured())
    settings.cii_token_url = CII_TOKEN_URL
    settings.duo_api_host = "evil.example/x?"
    check("a malformed DUO_API_HOST is never configured", not lookup.duo_configured())
    settings.duo_api_host = DUO_HOST


# --------------------------------------------------------------------------- decide
def _status(**over):
    base = {"duo_status": "active", "trust_level": "TRUSTED", "failing_checks": [], "as_of": "t",
            "available": True, "sources": {"duo": "ok", "cii": "ok"}}
    base.update(over)
    return base


def test_cii_not_found_is_an_answer_only_by_its_shape() -> None:
    print("CII 'no such user': read from the answer's shape alone; no error is ever one, whatever it says")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("avery.kim", trust="UNTRUSTED", failing=["MFA Flood", "Impossible Travel"])
    table = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())
    check("the shared answer table has every kind of answer",
          {c["expect"] for c in table["cases"]} == {"found", "not_found", "unavailable"})
    for case in table["cases"]:
        name, body, expect = case["name"], case["body"], case["expect"]
        fake.cii_body = body
        lookup.clear_cache()
        st = lookup.lookup("avery.kim")
        closed = gate.decide(st, fail_open=False)
        opened = gate.decide(st, fail_open=True)
        if expect == "unavailable":
            check(f"{name}: CII unavailable, never not_found, and never a clean check",
                  st["sources"] == {"duo": "ok", "cii": "unavailable"} and st["available"] is False
                  and closed["check"] == "unavailable" and opened["check"] == "unavailable", f"{st} {closed}")
            check(f"{name}: what it did say is kept (trust {case.get('trust')}, failing {case.get('failing', [])})",
                  st["trust_level"] == case.get("trust")
                  and sorted(st["failing_checks"]) == sorted(case.get("failing", [])), str(st))
            if case.get("reasons"):
                check(f"{name}: a block resting on what was learned blocks under fail-open and fail-closed alike",
                      closed["verdict"] == opened["verdict"] == "block"
                      and closed["reasons"] == opened["reasons"] == case["reasons"]
                      and not gate.unverified_only(opened), f"{opened} {closed}")
            else:
                check(f"{name}: nothing against the user: fail-closed blocks as not verifiable, fail-open allows",
                      closed["verdict"] == "block" and closed["reasons"] == ["identity_unavailable"]
                      and opened["verdict"] == "allow" and opened["reasons"] == [], f"{opened} {closed}")
        elif expect == "not_found":
            check(f"{name}: CII's 'no such user', an answer (check ok)",
                  st["sources"] == {"duo": "ok", "cii": "not_found"} and st["available"] is True
                  and closed["check"] == "ok" and closed["verdict"] == "allow", f"{st} {closed}")
        else:
            check(f"{name}: read as the user's details",
                  st["sources"] == {"duo": "ok", "cii": "ok"} and st["available"] is True
                  and st["trust_level"] == case["trust"]
                  and sorted(st["failing_checks"]) == sorted(case["failing"]), str(st))
    # No error is ever "no such user", whatever it says: every message of the
    # shared table, in every shape such an error takes, is unavailable.
    shapes = table["error_messages"]["shapes"]
    check("the shared table tries each message with data null and the error on getEndUser too (the shape the "
          "published schema gives an error there: GetEndUserOutput! is non-null)",
          any(s["data"] is None and s["path"] == ["getEndUser"] for s in shapes), str(shapes))
    misread = []
    for message in table["error_messages"]["messages"]:
        for shape in shapes:
            fake.cii_body = _error_answer(shape, message)
            lookup.clear_cache()
            st = lookup.lookup("avery.kim")
            closed = gate.decide(st, fail_open=False)
            opened = gate.decide(st, fail_open=True)
            if (st["sources"]["cii"] != "unavailable" or closed["reasons"] != ["identity_unavailable"]
                    or opened["check"] != "unavailable"):
                misread.append(f"{message!r} {shape['where']}: {st['sources']['cii']}, {closed['verdict']}")
    check(f"every error message of the shared table, in each of its {len(shapes)} shapes (on getEndUser, on "
          "endUserDetails, on getEndUser with data null, with no path): unavailable, never 'no such user' "
          "(fail-closed blocks it as not verifiable, fail-open says unavailable)", not misread, "; ".join(misread))
    fake.cii_body = None
    lookup.clear_cache()


def _error_answer(shape, message):
    """A getEndUser answer carrying one code-less error with this message, in
    one of the shared table's shapes (``error_messages.shapes``)."""
    error = {"message": message, **({"path": shape["path"]} if shape["path"] else {})}
    return {"data": copy.deepcopy(shape["data"]), "errors": [error]}


def _box_victim_row(fake, body=None):
    """lab5-setup status's victim row for avery.kim, from the box's own
    VICTIM_CHECK_SCRIPT run here against the fakes (``body``: a CII answer to
    send instead of the user's record)."""
    import contextlib
    import io
    from types import SimpleNamespace

    if str(ROOT / "deploy" / "lab5") not in sys.path:
        sys.path.insert(0, str(ROOT / "deploy" / "lab5"))
    import lab5_setup  # noqa: E402  (imports cleanly without paramiko / PyYAML / duo_client)

    fake.cii_body = body
    lookup.clear_cache()
    cwd, argv = os.getcwd(), list(sys.argv)
    out = io.StringIO()
    sys.argv = ["-", str(ROOT), "avery.kim"]
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(lab5_setup.VICTIM_CHECK_SCRIPT, "<victim-check>", "exec"), {"__name__": "__main__"})
    finally:
        sys.argv = argv
        os.chdir(cwd)
    printed = out.getvalue()
    rem = SimpleNamespace(run=lambda argv, stdin=None, timeout=60.0: SimpleNamespace(rc=0, out=printed, err=""))
    return lab5_setup.victim_blocked(SimpleNamespace(ws=SimpleNamespace(victim="avery.kim")),
                                     SimpleNamespace(checkout=str(ROOT)), rem)


def test_victim_self_check_on_a_partial_answer() -> None:
    print("lab5-setup status: the box's own victim check (VICTIM_CHECK_SCRIPT) blocks on what a partial answer said")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("avery.kim", trust="NEUTRAL")
    table = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())
    for name, verdict, needles in (
            ("details present, but failingChecks failed and came back null (an untrusted user)", "OK",
             ["blocks avery.kim: trust_untrusted", "cii graphql_error"]),
            ("details present, the trust score failed, two blocking checks known", "OK",
             ["blocks avery.kim: mfa_flood, impossible_travel"]),
            ("details present, a neutral user whose failingChecks failed (never a clean check)", "FAIL",
             ["cannot verify avery.kim (cii graphql_error)", "spikes S5/S6"])):
        body = next(c["body"] for c in table["cases"] if c["name"] == name)
        status, detail = _box_victim_row(fake, body)
        check(f"{name}: the box's victim row is {verdict}, and never sends the facilitator to the Keychain",
              status == verdict and all(n in detail for n in needles) and "pseudoco-lab5-cii-" not in detail,
              f"{status}: {detail}")
    fake.cii_body = None
    lookup.clear_cache()


def test_victim_self_check_on_a_refused_client() -> None:
    print("lab5-setup status: an error on getEndUser is 'cannot verify', never 'not in CII yet', whatever it says")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("avery.kim", trust="NEUTRAL")
    shapes = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())[
        "error_messages"]["shapes"]
    # Each once read as CII's "no such user" through the wording rule (a scope,
    # a role, a quoted word or another principal taken for the user or its
    # login), so the row said WARN "trust no record in CII yet". Each is tried
    # in every shape of the shared table, data null on getEndUser included.
    for message in ("No user (or group) permission granted to this API client",
                    "No user 'read' scope granted to this API client",
                    "Required scope user:read.all not found in access token",
                    "Permission read:user not found for this API client",
                    "Role end-user does not exist",
                    "No user for abc123XYZ@clients",
                    "User abc123XYZ@clients not found",
                    "End user avery.kim@pseudocoassistant.com not found"):
        for shape in shapes:
            where = shape["where"]
            status, detail = _box_victim_row(fake, _error_answer(shape, message))
            check(f"{message!r} {where}: the box's victim row is FAIL (cannot verify), never WARN 'no record in CII'",
                  status == "FAIL" and "cannot verify avery.kim (cii graphql_error)" in detail
                  and "no record in CII" not in detail, f"{status}: {detail}")
            # The row carries only the code, so its advice is the facilitator's
            # only pointer: a refused client is the API client's role or scopes
            # (its token was issued), never only "the query does not match".
            check(f"{message!r} {where}: the row's advice names the API client's role or scopes and the Mac's "
                  "self-check (which prints CII's message), and never says the query alone is at fault",
                  all(n in detail for n in ("the CII API client's role or scopes", "persona_activity.py selfcheck",
                                            "spikes S5/S6"))
                  and "query does not match the tenant" not in detail and "pseudoco-lab5-cii-" not in detail,
                  detail)
    fake.cii_body = None
    lookup.clear_cache()


def test_victim_self_check_on_a_lockout() -> None:
    print("lab5-setup status: a Duo lockout alone never makes the box's victim row OK (Duo unlocks it on its own)")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("avery.kim", status="locked out", trust="NEUTRAL")
    settings.cii_client_secret = "a-secret-cii-refuses"
    try:
        status, detail = _box_victim_row(fake)
        check("locked out while CII refuses the box's API client: FAIL, the block lasts only as long as the lockout",
              status == "FAIL" and all(n in detail for n in (
                  "cannot verify avery.kim (cii token_http_401)", "only while Duo's lockout lasts",
                  "about 15 minutes", "IDENTITY_FAIL_OPEN", "pseudoco-lab5-cii-")), f"{status}: {detail}")
        fake.set_user("avery.kim", status="active", trust="NEUTRAL")
        status, detail = _box_victim_row(fake)
        check("the same box once Duo unlocks the account: FAIL, and the gate lets the victim chat",
              status == "FAIL" and "cannot verify avery.kim (cii token_http_401)" in detail
              and "lockout" not in detail
              and gate.decide(lookup.lookup("avery.kim"), fail_open=True)["verdict"] == "allow",
              f"{status}: {detail}")
    finally:
        _configure(True)
    fake.set_user("avery.kim", status="locked out", trust="NEUTRAL")
    status, detail = _box_victim_row(fake)
    check("locked out, both sources answer, nothing against it in CII yet: WARN, not OK (the lockout reverts)",
          status == "WARN" and all(n in detail for n in (
              "blocks avery.kim (duo_locked_out) only while Duo's lockout lasts", "; then it would let it chat",
              "trust NEUTRAL", "T-0")), f"{status}: {detail}")
    fake.set_user("avery.kim", status="locked out", trust="UNTRUSTED", failing=["MFA Flood"])
    status, detail = _box_victim_row(fake)
    check("locked out after the takeover, CII failing MFA Flood: OK, the CII block holds when Duo unlocks it",
          status == "OK" and "blocks avery.kim: duo_locked_out, trust_untrusted, mfa_flood" in detail,
          f"{status}: {detail}")
    lookup.clear_cache()


def test_decide() -> None:
    print("decide(): pure, block rules, fail open")
    cases = [
        ("active + TRUSTED", _status(), "allow", []),
        ("QUESTIONABLE is allowed (the badge shows it)", _status(trust_level="QUESTIONABLE"), "allow", []),
        ("bypass status is not a block reason", _status(duo_status="bypass"), "allow", []),
        ("Duo disabled", _status(duo_status="disabled"), "block", ["duo_disabled"]),
        ("Duo locked out", _status(duo_status="locked_out"), "block", ["duo_locked_out"]),
        ("Duo pending deletion", _status(duo_status="pending_deletion"), "block", ["duo_pending_deletion"]),
        ("no such Duo user", _status(duo_status=None, sources={"duo": "not_found", "cii": "ok"}, available=False),
         "block", ["duo_user_not_found"]),
        ("UNTRUSTED", _status(trust_level="untrusted"), "block", ["trust_untrusted"]),
        ("failing MFA Flood (any spelling)", _status(failing_checks=["MFA_FLOOD"]), "block", ["mfa_flood"]),
        ("failing Impossible Travel", _status(failing_checks=["Impossible Travel", "Users Sharing Authenticators"]),
         "block", ["impossible_travel"]),
        ("another failing check alone is not a block", _status(failing_checks=["A Bypass Code Was Used"]), "allow", []),
    ]
    for name, st, verdict, reasons in cases:
        v = gate.decide(st)
        check(f"{name}: {verdict}", v["verdict"] == verdict and v["reasons"] == reasons, str(v))
    down = _status(duo_status=None, trust_level=None, available=False,
                   sources={"duo": "unavailable", "cii": "unavailable"})
    v = gate.decide(down, fail_open=True)
    check("unavailable + IDENTITY_FAIL_OPEN: allow, check unavailable",
          v["verdict"] == "allow" and v["check"] == "unavailable" and v["reasons"] == [], str(v))
    v = gate.decide(down, fail_open=False)
    check("unavailable, fail closed: block as not verifiable (neutral)",
          v["verdict"] == "block" and v["reasons"] == ["identity_unavailable"] and gate.unverified_only(v), str(v))
    v = gate.decide(_status(duo_status="disabled", trust_level=None, available=False,
                            sources={"duo": "ok", "cii": "unavailable"}), fail_open=True)
    check("what IS known wins: Duo disabled blocks while CII is down",
          v["verdict"] == "block" and v["reasons"] == ["duo_disabled"] and v["check"] == "unavailable", str(v))
    check("decide() never raises on garbage", gate.decide(None)["verdict"] == "allow"
          and gate.decide({"failing_checks": "x", "sources": 3})["verdict"] == "allow")
    check("reasons in words for the banner",
          gate.reasons_text({"reasons": ["duo_locked_out", "mfa_flood"]})
          == "your Duo account is locked out and your account is failing the MFA Flood check")


# --------------------------------------------------------------------------- the turn, both engines
_SESSION = {"session_ref": "ref-gate", "username": "avery.kim", "source": "duo",
            "signed_in_at": "2026-11-05T10:00:00", "expires_at": "2026-11-05T22:00:00"}
_BLOCK_KEYS = ("guardrail_ids", "policy_blocked", "safety_categories", "severity", "enduser_id",
               "identity_verified", "identity_risk", "identity_check", "identity_risk_reasons",
               "identity_duo_status", "identity_trust_level", "identity_failing_checks", "usage_total_tokens")


def _turn_events(run):
    start = len(_built)
    result = run()
    return result, [e for t, e in _built[start:] if t == "governance"]


def test_engines() -> None:
    print("the gate in both engines: same block, same evidence; fail open; Unblock me")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("avery.kim", status="locked out", trust="UNTRUSTED", failing=["MFA Flood"])
    fake.set_user("nina.osei", trust="QUESTIONABLE")
    common = dict(session_id="gate-turn", user_message="mild sore throat", conversation_history=[],
                  theme="medadvice", enduser_id="t.nguyen", internal_policy_review=True)
    del _LLM_CALLS[:]
    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session=dict(_SESSION)))
    agentic = evs[-1] if evs else {}
    check("agentic: refused before any model, attributed to Cisco Identity Intelligence",
          res.get("policy_blocked") is True and _LLM_CALLS == []
          and agentic.get("guardrail_ids") == ["cisco_identity_intelligence"]
          and "POLICY BLOCKED (Cisco Identity Intelligence)" in agentic.get("response_text", ""), str(agentic)[:300])
    check("the banner says why, in words, and never claims a screened document",
          "locked out" in res["message"] and "MFA Flood" in res["message"]
          and "screened together" not in res["message"], res["message"])
    res2, evs2 = _turn_events(lambda: RecommendationEngine().process_message(**common,
                                                                              identity_session=dict(_SESSION)))
    legacy = evs2[-1] if evs2 else {}
    check("legacy engine: the same block function, before its policy check",
          res2.get("policy_blocked") is True and legacy.get("guardrail_ids") == ["cisco_identity_intelligence"]
          and _LLM_CALLS == [])
    check("both engines log the same block evidence",
          {k: agentic.get(k) for k in _BLOCK_KEYS} == {k: legacy.get(k) for k in _BLOCK_KEYS},
          f"{ {k: agentic.get(k) for k in _BLOCK_KEYS} } != { {k: legacy.get(k) for k in _BLOCK_KEYS} }")
    check("the block event: compromised_identity, HIGH, zero tokens, the verified user, no escalation",
          agentic.get("safety_categories") == ["compromised_identity"] and agentic.get("severity") == "HIGH"
          and agentic.get("usage_total_tokens") == 0 and agentic.get("enduser_id") == "avery.kim"
          and agentic.get("identity_duo_status") == "locked_out" and not _events("escalations", session_id="gate-turn")
          and agentic.get("prompt_category") == "compromised_identity"
          and agentic.get("business_outcome") == "blocked_compromised_identity", str(agentic)[:400])

    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session={**_SESSION, "override": True}))
    check("Unblock me: the turn goes on; every event carries the real verdict and identity_override",
          res.get("policy_blocked") is not True and _LLM_CALLS and evs
          and all(e.get("identity_override") is True and e.get("identity_risk") == "block" for e in evs),
          str([(e.get("identity_override"), e.get("identity_risk")) for e in evs]))
    legacy_common = {**common, "user_message": "I want to end my life", "session_id": "gate-turn-legacy"}
    res, evs = _turn_events(lambda: RecommendationEngine().process_message(
        **legacy_common, identity_session={**_SESSION, "override": True}))
    esc = _events("escalation", session_id="gate-turn-legacy")
    check("...in the legacy engine too: past the gate to its policy check, override + verdict on every event",
          evs and evs[-1].get("guardrail_ids") == ["policy_block"] and esc
          and all(e.get("identity_override") is True and e.get("identity_risk") == "block" for e in evs + esc),
          str([(e.get("guardrail_ids"), e.get("identity_override")) for e in evs + esc]))

    nina = {**_SESSION, "username": "nina.osei"}
    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session=nina))
    check("a QUESTIONABLE user is allowed; the verdict rides on the turn's events",
          res.get("policy_blocked") is not True and evs and evs[-1].get("identity_risk") == "allow"
          and evs[-1].get("identity_trust_level") == "QUESTIONABLE" and evs[-1].get("identity_check") == "ok")
    lookup.clear_cache()
    fake.fail = "duo_500"
    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session=nina))
    check("A3 fail open: Duo down, the turn is allowed with identity_check=unavailable",
          res.get("policy_blocked") is not True and evs and evs[-1].get("identity_check") == "unavailable"
          and evs[-1].get("identity_risk") == "allow", str(evs[-1:])[:300])
    settings.identity_fail_open = False
    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session=nina))
    check("IDENTITY_FAIL_OPEN off: refused with the neutral 'could not be verified' banner",
          res.get("policy_blocked") is True and "could not be verified" in res["message"]
          and evs and evs[-1].get("safety_categories") == ["identity_unverified"]
          and evs[-1].get("severity") == "MEDIUM", str(evs[-1:])[:300])
    settings.identity_fail_open = True
    del _LLM_CALLS[:]
    res, evs = _turn_events(lambda: graph.run_turn(**common, identity_session=dict(_SESSION)))
    check("Duo down, fail open: the victim's CII block still refuses the turn (claim 2 holds)",
          res.get("policy_blocked") is True and _LLM_CALLS == [] and evs
          and evs[-1].get("guardrail_ids") == ["cisco_identity_intelligence"]
          and evs[-1].get("identity_risk_reasons") == ["trust_untrusted", "mfa_flood"]
          and evs[-1].get("identity_check") == "unavailable" and not evs[-1].get("identity_duo_status"),
          str(evs[-1:])[:400])
    fake.fail = None
    lookup.clear_cache()
    n = len(fake.requests)
    res, evs = _turn_events(lambda: graph.run_turn(**common))
    check("anonymous: nothing looked up, no identity key on any event",
          len(fake.requests) == n and evs and not any(k.startswith("identity") for e in evs for k in e))
    check("no audit event from any turn (the gate has no side effects)",
          not any(t == "audit" and str(e.get("session_id", "")).startswith("gate-turn") for t, e in _built))


# --------------------------------------------------------------------------- the store
def test_store_generation() -> None:
    print("identity store: a lookup racing a revoke never re-caches the pre-revoke row")
    token, snap = store.create("race.user")
    store.clear_cache()
    real = store._row_facts
    fired = []

    def racing(row):
        facts = real(row)
        if not fired:
            fired.append(True)
            store.revoke(snap.session_ref, reason="duo_disabled", actor="duo")   # clears the cache meanwhile
        return facts

    store._row_facts = racing
    try:
        first = store.lookup(token)
    finally:
        store._row_facts = real
    cached = store.hash_token(token) in store._cache
    second = store.lookup(token)
    check("the racing lookup answers what it read, but does not cache it",
          first.status == store.VALID and not cached, f"{first.status} cached={cached} fired={fired}")
    check("the next lookup sees the revoke at once (not after the 5 s cache)", second.status == store.REVOKED,
          second.status)
    store.clear_cache()
    gen = store._generation
    store.clear_cache()
    store._cache_put("h", None, gen)
    check("_cache_put drops a value read under an older generation", "h" not in store._cache)


def test_store_override() -> None:
    print("identity store: what an Unblock me override holds open")
    token, snap = store.create("override.user")
    ref = snap.session_ref
    s = store.unblock(ref)
    check("unblock of a live session: override on, nothing cleared, holds no revocation open",
          s.overridden and s.unblock_cleared is None and not s.holds_open("duo_disabled"))
    check("revoke: True, and it ends the override (a revocation ends the session)",
          store.revoke(ref, reason="duo_disabled", actor="duo")
          and store.get(ref).unblocked_at is None and store.get(ref).unblock_cleared is None)
    s = store.unblock(ref)
    check("unblock of the tombstone: valid again, holding open exactly the revocation it cleared",
          store.lookup(token).status == store.VALID and s.unblock_cleared == "duo_disabled"
          and s.holds_open("duo_disabled") and not s.holds_open("other"))
    s = store.unblock(ref)
    check("unblock again keeps what it holds open", s.holds_open("duo_disabled"))
    check("rearm: forgets the cleared revocation once, keeps the override",
          store.rearm(ref) is True and store.rearm(ref) is False
          and store.get(ref).overridden and store.get(ref).unblock_cleared is None)
    store.revoke(ref, reason="duo_disabled", actor="duo")
    store.unblock(ref)
    s = store.reblock(ref)
    check("reblock clears the override and what it held open",
          not s.overridden and s.unblock_cleared is None and store.get(ref).unblock_cleared is None)
    store.end(token)


# --------------------------------------------------------------------------- the app
def _chat(c, token, sid, text="mild sore throat"):
    return c.post("/api/chat/message", headers=ck(token),
                  json={"session_id": sid, "message": text, "disclaimer_accepted": True})


def test_app(c: TestClient) -> None:
    print("revocation pull, /api/identity/me, Unblock me (the app, through the fakes)")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("victim.user", status="active", trust="UNTRUSTED", failing=["MFA Flood", "Impossible Travel"])
    fake.set_user("nina.osei", trust="QUESTIONABLE")
    token, snap = store.create("victim.user", client_address="203.0.113.9")
    me = c.get("/api/identity/me", headers=ck(token)).json()
    check("/api/identity/me: the verdict, trust and checks for the badge and banner",
          me.get("signed_in") is True and me.get("verdict") == "block" and me.get("trust_level") == "UNTRUSTED"
          and me.get("failing_checks") == ["MFA Flood", "Impossible Travel"] and me.get("override") is False
          and me.get("identity_check") == "ok" and "MFA Flood" in me.get("reasons_text", ""), str(me))
    sid = str(uuid.uuid4())
    r = _chat(c, token, sid)
    ev = (_events("governance", session_id=sid) or [{}])[-1]
    check("a chat turn of the at-risk identity is refused by the gate (not revoked: Duo says active)",
          r.status_code == 200 and ev.get("guardrail_ids") == ["cisco_identity_intelligence"]
          and store.lookup(token).status == store.VALID, f"{r.status_code} {ev.get('guardrail_ids')}")
    check("the session is not revoked by a gate block (no identity_session_revoked)",
          not _revoked("victim.user"))

    # A4: Duo disables the account -> the next request revokes the session.
    fake.duo["victim.user"]["status"] = "disabled"
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    check("Duo disabled: the next request answers 403 identity_session_revoked",
          r.status_code == 403 and r.json() == {"detail": "identity_session_revoked"}, r.text)
    rev = _revoked("victim.user")
    check("...and wrote identity_session_revoked (reason duo_disabled, actor duo, the user)",
          len(rev) == 1 and rev[0].get("details") == {"reason": "duo_disabled"} and rev[0].get("actor") == "duo"
          and rev[0].get("user") == "victim.user", str(rev)[:300])
    r = c.get("/app", headers={**ck(token), "Accept": "text/html"}, follow_redirects=False)
    check("a page load goes to the sign-in page", r.status_code == 303
          and r.headers.get("location") == "/login/duo?revoked=1")
    me = c.get("/api/identity/me", headers=ck(token))
    check("/api/identity/me reaches the tombstone with its identity (carry-over a)",
          me.status_code == 200 and me.json() == {"signed_in": False, "revoked": True, "username": "victim.user",
                                                  "revoked_reason": "duo_disabled", "can_unblock": True}, me.text)
    check("...as identity_revoked only: a chat turn is still refused",
          _chat(c, token, str(uuid.uuid4())).status_code == 403)

    # Unblock me, from the tombstone.
    n = len(fake.requests)
    r = c.post("/api/identity/unblock", headers=ck(token, Origin="https://evil.example"))
    check("a cross-site Unblock me is refused", r.status_code == 403 and store.lookup(token).status == store.REVOKED)
    r = c.post("/api/identity/unblock", headers=ck(token))
    check("POST /api/identity/unblock: 200, override on, the tombstone cleared",
          r.status_code == 200 and r.json() == {"ok": True, "username": "victim.user", "override": True}
          and store.lookup(token).status == store.VALID, r.text)
    check("...without one request to Duo or Identity Intelligence", len(fake.requests) == n)
    ub = _audits("identity_unblocked")
    check("identity_unblocked: who overrode, and the revocation it cleared",
          len(ub) == 1 and ub[0].get("user") == "victim.user"
          and ub[0].get("details") == {"reason": "unblock_me", "cleared": "duo_disabled"}, str(ub)[:300])
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    check("Duo still says disabled, but an unblocked session is not revoked again",
          r.status_code == 200 and len(_revoked("victim.user")) == 1 and fake.duo["victim.user"]["status"] == "disabled")
    sid = str(uuid.uuid4())
    r = _chat(c, token, sid)
    evs = _events("governance", session_id=sid)
    check("the turn goes on; every event: the real verdict (block) plus identity_override=true",
          r.status_code == 200 and evs and evs[-1].get("guardrail_ids") != ["cisco_identity_intelligence"]
          and all(e.get("identity_override") is True and e.get("identity_risk") == "block"
                  and e.get("identity_duo_status") == "disabled" for e in evs), str([e.get("identity_risk") for e in evs]))
    me = c.get("/api/identity/me", headers=ck(token)).json()
    check("/api/identity/me says override on (the banner's toggle)", me.get("override") is True
          and me.get("unblocked_at"))
    r = c.post("/api/identity/unblock", headers=ck(token))
    check("Unblock me again: no second audit event", r.status_code == 200 and len(_audits("identity_unblocked")) == 1)

    # Reblock: the next request is gated (and revoked) again.
    r = c.post("/api/identity/reblock", headers=ck(token))
    rb = _audits("identity_reblocked")
    check("POST /api/identity/reblock: override off, identity_reblocked written",
          r.status_code == 200 and r.json().get("override") is False and len(rb) == 1
          and rb[0].get("details") == {"reason": "reblock"}, r.text)
    r = c.get("/api/server-info", headers=ck(token))
    check("...and Duo still disabled revokes the session again on the next request",
          r.status_code == 403 and len(_revoked("victim.user")) == 2)
    r = c.post("/api/identity/reblock", headers=ck(token))
    check("reblock on a tombstone: reachable, nothing to clear, no event",
          r.status_code == 200 and len(_audits("identity_reblocked")) == 1)

    # The sign-in page's form: Unblock me, then straight to /app.
    r = c.post("/api/identity/unblock", headers={**ck(token), "Accept": "text/html"}, data={"next": "/app"},
               follow_redirects=False)
    check("the sign-in page's Unblock me form: 303 /app, session back",
          r.status_code == 303 and r.headers.get("location") == "/app" and store.lookup(token).status == store.VALID)
    for bad in ("https://evil.example/", "/settings-ui", "//evil.example"):
        r = c.post("/api/identity/unblock", headers=ck(token), data={"next": bad}, follow_redirects=False)
        check(f"next={bad!r} is ignored (JSON, no redirect)", r.status_code == 200 and "location" not in r.headers)

    check("no session: 401 identity_not_signed_in",
          c.post("/api/identity/unblock", headers=H).json() == {"detail": "identity_not_signed_in"})
    settings.duo_enabled = False
    check("DUO_ENABLED off: the routes are 404", c.post("/api/identity/unblock", headers=ck(token)).status_code == 404
          and c.post("/api/identity/reblock", headers=ck(token)).status_code == 404)
    settings.duo_enabled = True

    # Locked out only blocks turns; it never revokes.
    fake.set_user("locked.user", status="locked out", trust="TRUSTED")
    t2, _ = store.create("locked.user")
    lookup.clear_cache()
    before = len(_audits("identity_session_revoked"))
    r = c.get("/api/server-info", headers=ck(t2))
    check("locked out: requests go on, the session is not revoked",
          r.status_code == 200 and store.lookup(t2).status == store.VALID
          and len(_audits("identity_session_revoked")) == before)
    # The pull is cached: a burst of requests is one Duo call.
    lookup.clear_cache()
    n = fake.count(host=DUO_HOST)
    for _ in range(4):
        c.get("/api/server-info", headers=ck(t2))
    check("the revocation pull is cached (10 s): four requests, one Duo call", fake.count(host=DUO_HOST) - n == 1)
    # Duo down: no revocation, no failure.
    lookup.clear_cache()
    fake.fail = "duo_connect"
    r = c.get("/api/server-info", headers=ck(t2))
    check("Duo unreachable: the request goes on, nothing revoked", r.status_code == 200
          and store.lookup(t2).status == store.VALID)
    fake.fail = None


def _unblocked(user):
    return [e for e in _audits("identity_unblocked") if e.get("user") == user]


def test_override_and_pull(c: TestClient) -> None:
    print("Unblock me never stops a Duo disable from ending the session (12.1, claim 4)")
    _configure(True)
    fake = _fresh_fake()
    fake.set_user("gate.victim", status="active", trust="UNTRUSTED", failing=["MFA Flood", "Impossible Travel"])
    fake.set_user("early.user", trust="QUESTIONABLE")
    fake.duo["new.account"] = {"status": "active", "email": "new.account@pseudocoassistant.com"}

    # 1. IDENTITY AT RISK before any turn; the attendee turns Unblock me on.
    token, snap = store.create("gate.victim")
    me = c.get("/api/identity/me", headers=ck(token)).json()
    check("the /me poll reports the gate block before any turn (the banner offers Unblock me)",
          me.get("verdict") == "block" and me.get("override") is False, str(me))
    r = c.post("/api/identity/unblock", headers=ck(token))
    ub = _unblocked("gate.victim")
    check("Unblock me for a gate block: on, nothing cleared",
          r.status_code == 200 and r.json().get("override") is True and len(ub) == 1
          and ub[0].get("details") == {"reason": "unblock_me"}, str(ub)[:300])
    sid = str(uuid.uuid4())
    check("...and the turn goes on", _chat(c, token, sid).status_code == 200
          and (_events("governance", session_id=sid) or [{}])[-1].get("identity_override") is True)

    # 2. The response agent disables the account in Duo: the session ends anyway.
    fake.duo["gate.victim"]["status"] = "disabled"
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    rev = _revoked("gate.victim")
    check("Duo disables the account: the overridden session is revoked on its next request",
          r.status_code == 403 and r.json() == {"detail": "identity_session_revoked"}
          and store.lookup(token).status == store.REVOKED and len(rev) == 1
          and rev[0].get("details") == {"reason": "duo_disabled"} and rev[0].get("actor") == "duo", r.text)
    check("...the revocation ended the override",
          store.get(snap.session_ref).unblocked_at is None and store.get(snap.session_ref).unblock_cleared is None)
    me = c.get("/api/identity/me", headers=ck(token)).json()
    check("...and the /me poll shows SESSION ENDED (the tombstone)",
          me.get("revoked") is True and me.get("revoked_reason") == "duo_disabled", str(me))

    # 3. Unblock me brings it back, and that one holds while Duo keeps it disabled.
    r = c.post("/api/identity/unblock", headers=ck(token))
    ub = _unblocked("gate.victim")
    check("Unblock me again: the session is back, and the event says what it cleared",
          r.status_code == 200 and store.lookup(token).status == store.VALID and len(ub) == 2
          and ub[1].get("details") == {"reason": "unblock_me", "cleared": "duo_disabled"}, str(ub)[-1:])
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    sid = str(uuid.uuid4())
    r2 = _chat(c, token, sid)
    evs = _events("governance", session_id=sid)
    check("...not revoked again while Duo keeps the account disabled; turns carry the override and the real status",
          r.status_code == 200 and r2.status_code == 200 and len(_revoked("gate.victim")) == 1 and evs
          and all(e.get("identity_override") is True and e.get("identity_duo_status") == "disabled" for e in evs))

    # 4. Duo enables the account again: a new disable ends the session again.
    fake.duo["gate.victim"]["status"] = "active"
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    check("Duo enables the account again: the revocation Unblock me cleared is forgotten, the override stays",
          r.status_code == 200 and store.get(snap.session_ref).unblock_cleared is None
          and store.get(snap.session_ref).overridden)
    fake.duo["gate.victim"]["status"] = "disabled"
    lookup.clear_cache()
    r = c.get("/api/server-info", headers=ck(token))
    check("...so a second Duo disable ends the session again", r.status_code == 403
          and len(_revoked("gate.victim")) == 2)
    lookup.clear_cache()
    fake.fail = "duo_connect"
    c.post("/api/identity/unblock", headers=ck(token))
    r = c.get("/api/server-info", headers=ck(token))
    check("Duo unreachable: a held-open session stays, and nothing is forgotten",
          r.status_code == 200 and store.get(snap.session_ref).unblock_cleared == "duo_disabled")
    fake.fail = None

    # 5. A pre-emptive Unblock me (nothing blocked) holds nothing open either.
    t2, s2 = store.create("early.user")
    me = c.get("/api/identity/me", headers=ck(t2)).json()
    r = c.post("/api/identity/unblock", headers=ck(t2))
    fake.duo["early.user"]["status"] = "disabled"
    lookup.clear_cache()
    r2 = c.get("/api/server-info", headers=ck(t2))
    check("a pre-emptive Unblock me (verdict allow) does not stop a Duo disable from ending the session",
          me.get("verdict") == "allow" and r.status_code == 200 and r2.status_code == 403
          and len(_revoked("early.user")) == 1, f"{me.get('verdict')} {r.status_code} {r2.status_code}")

    # A user CII has no record of yet (a new participant account) is checked, not "unavailable".
    t3, _ = store.create("new.account")
    me = c.get("/api/identity/me", headers=ck(t3)).json()
    check("a user CII does not know yet: /me says identity_check ok, allowed, no trust level (no 'unavailable' badge)",
          me.get("identity_check") == "ok" and me.get("verdict") == "allow" and me.get("trust_level") is None, str(me))
    for t in (token, t2, t3):
        store.end(t)


# --------------------------------------------------------------------------- the rules
def test_rules() -> None:
    print("rules: shared chain, no toggle or request field, .env-only, UI, docs, suite registration")
    check("identity_risk is PRE_NODES[1], after attachment_intake and before policy, and may end the turn",
          guardrails.PRE_NODES[:3] == ["attachment_intake", "identity_risk", "policy"]
          and "identity_risk" in guardrails._MAY_TERMINATE
          and guardrails._NODE_FNS["identity_risk"].__name__ == "identity_risk_node")
    words = ("override", "unblock", "identity")
    fields = set(ChatRequest.model_fields) | set(ChatCompletionRequest.model_fields)
    check("no ChatRequest / ChatCompletionRequest field for identity or Unblock me",
          not [f for f in fields if any(w in f for w in words)], str(sorted(fields)))
    keys = [c.get("key", "") for c in settings_store.DEMO_CONTROLS]
    check("no Demo Controls card for it (registry)", not [k for k in keys if any(w in k for w in words)], str(keys))
    creds = json.dumps({k: [getattr(f, "name", str(f)) for f in v] for k, v in settings_store._INTEGRATION_FIELDS.items()},
                       default=str).lower()
    check("no Duo / CII key in settings_store (anyone with the room key can rewrite those)",
          not any(w in creds for w in ("duo_admin", "cii_", "identity_fail_open")))
    check("the override is a run_turn parameter of the session only (identity_session), never its own",
          "identity_override" not in inspect.signature(graph.run_turn).parameters
          and "identity_session" in inspect.signature(graph.run_turn).parameters)
    check("identity audit actions include identity_unblocked and identity_reblocked",
          {"identity_unblocked", "identity_reblocked"} <= identity_audit.ACTIONS)
    from backend import agent_observability as ao
    check("Agent Observability metadata keys carry the verdict and the override",
          {"identity_risk", "identity_check", "identity_override", "identity_trust_level"} <= set(ao._GOVERNANCE_KEYS))
    check("the middleware lets a tombstone reach exactly /me, /unblock and /reblock",
          idmw.TOMBSTONE_PATHS == {"/api/identity/me", "/api/identity/unblock", "/api/identity/reblock"})

    js = (ROOT / "frontend" / "js" / "chat.js").read_text()
    page = (ROOT / "frontend" / "index.html").read_text()
    login = (ROOT / "frontend" / "login-duo.html").read_text()
    check("UI: the identity_risk stage label, hidden on anonymous turns",
          "identity_risk: 'Verifying your identity (Cisco Identity Intelligence)…'" in js
          and "event.node === 'identity_risk' && !_identity" in js)
    banner = page[page.index('id="identityBanner"'):page.index('id="emergencyBanner"')]
    drawer = page[page.index('id="settingsDrawer"'):page.index('id="drawerToggle"')]
    check("UI: the Unblock me toggle sits in #identityBanner (never the Demo Controls drawer), green accent",
          'id="identityUnblockToggle"' in banner and "peer-checked:bg-green-600" in banner
          and "identityUnblockToggle" not in drawer and "unblock" not in drawer.lower())
    check("UI: the toggle calls /api/identity/unblock and /reblock; chat.js?v=40",
          "'/api/identity/unblock' : '/api/identity/reblock'" in js and "/static/js/chat.js?v=40" in page)
    banners = _banner_for({
        "fail_closed": {"signed_in": True, "username": "nina.osei", "verdict": "block", "identity_check": "unavailable",
                        "reasons": ["identity_unavailable"], "reasons_text": "your identity could not be verified"},
        "at_risk": {"signed_in": True, "username": "avery.kim", "verdict": "block", "identity_check": "ok",
                    "reasons": ["mfa_flood"], "reasons_text": "your account is failing the MFA Flood check"},
        "fail_open": {"signed_in": True, "username": "nina.osei", "verdict": "allow", "identity_check": "unavailable",
                      "reasons": []},
        "fail_closed_cii_trusted": {"signed_in": True, "username": "nina.osei", "verdict": "block",
                                    "identity_check": "unavailable", "trust_level": "TRUSTED",
                                    "reasons": ["identity_unavailable"],
                                    "reasons_text": "your identity could not be verified"},
        "fail_closed_unblocked": {"signed_in": True, "username": "nina.osei", "verdict": "block", "override": True,
                                  "identity_check": "unavailable", "reasons": ["identity_unavailable"]},
    })
    if banners is not None:
        closed, risk = banners.get("fail_closed") or {}, banners.get("at_risk") or {}
        check("UI: a fail-closed block's banner is neutral (IDENTITY NOT VERIFIED), never 'reports a risk'",
              closed.get("kind") == "unverified" and closed.get("title") == "IDENTITY NOT VERIFIED"
              and "reports a risk" not in closed.get("text", "") and "could not be verified" in closed.get("text", "")
              and closed.get("unblock") is True, str(closed))
        check("UI: a block with a real reason keeps the at-risk banner",
              risk.get("kind") == "blocked" and risk.get("title") == "IDENTITY AT RISK"
              and "MFA Flood" in risk.get("text", ""), str(risk))
        pills = {k: (banners.get(k) or {}).get("pill") or {} for k in
                 ("fail_closed", "fail_open", "fail_closed_cii_trusted", "fail_closed_unblocked")}
        check("UI: fail-closed, the trust pill's tooltip says messages are refused, as the banner does (never 'not "
              "held up')", pills["fail_closed"].get("text") == "STATUS UNAVAILABLE"
              and "refused" in pills["fail_closed"].get("title", "")
              and "not held up" not in pills["fail_closed"].get("title", ""), str(pills["fail_closed"]))
        check("UI: fail-open, the same pill says messages are not held up (no banner)",
              "not held up" in pills["fail_open"].get("title", "") and not (banners.get("fail_open") or {}).get("shown"),
              str(banners.get("fail_open")))
        check("UI: fail-closed with CII still answering: its trust level shows, and its tooltip says why messages "
              "are refused", pills["fail_closed_cii_trusted"].get("text") == "TRUSTED"
              and "refused" in pills["fail_closed_cii_trusted"].get("title", ""), str(pills["fail_closed_cii_trusted"]))
        check("UI: Unblock me on: messages go through, and the pill says they are not held up",
              "not held up" in pills["fail_closed_unblocked"].get("title", ""), str(pills["fail_closed_unblocked"]))
    check("UI: the sign-in page offers Unblock me for a revoked session",
          'action="/api/identity/unblock"' in login and 'form.unblock' in login)
    claude = (ROOT / "CLAUDE.md").read_text()
    check("CLAUDE.md: 'Identity sign-in' and 'Identity Risk Gate' sections",
          "## Identity sign-in" in claude and "## Identity Risk Gate" in claude)
    from backend.agents.nodes import identity as identity_node
    gate_rules = claude.split("## Identity Risk Gate", 1)[-1].split("\n## ", 1)[0]
    check("CLAUDE.md states both block events the node writes: compromised_identity / HIGH, and the neutral "
          "fail-closed identity_unverified / MEDIUM",
          f'"{identity_node.SAFETY_CATEGORY}"' in gate_rules and f'"{identity_node.UNVERIFIED_CATEGORY}"' in gate_rules
          and "severity HIGH" in gate_rules and "severity MEDIUM" in gate_rules, gate_rules[-900:])
    check("docs/identity.md and its .html rendering exist",
          (ROOT / "docs" / "identity.md").exists() and (ROOT / "docs" / "identity.html").exists())
    check("tests/run_all.sh runs this suite", "tests/test_identity_gate.py" in (ROOT / "tests" / "run_all.sh").read_text())


# Loads the real chat.js with a stub DOM and runs renderIdentity() on each
# /api/identity/me answer; prints the banner each one raised.
_BANNER_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
const answers = JSON.parse(process.argv[3]);
const out = {};
for (const [name, me] of Object.entries(answers)) {
  const els = {};
  const el = (id) => els[id] || (els[id] = {
    id, textContent: '', title: '', checked: false, disabled: false, dataset: {},
    _cls: new Set(['hidden']),
    classList: { add(...c) { c.forEach((x) => this._o._cls.add(x)); }, remove(...c) { c.forEach((x) => this._o._cls.delete(x)); },
                 toggle(c, on) { if (on === undefined ? !this._o._cls.has(c) : on) this._o._cls.add(c); else this._o._cls.delete(c); },
                 contains(c) { return this._o._cls.has(c); } },
  });
  const ctx = {
    console: { log() {}, warn() {}, error() {}, debug() {} },
    fetch: async () => ({ ok: true, status: 200, json: async () => ({}), headers: { get: () => null } }),
    document: { addEventListener() {}, getElementById: (id) => { const e = el(id); e.classList._o = e; return e; },
                querySelectorAll: () => [], querySelector: () => null, hidden: false,
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
  ctx.__me = me;
  vm.runInContext('renderIdentity(__me)', ctx);
  const banner = els.identityBanner || { dataset: {}, _cls: new Set(['hidden']) };
  const pill = els.identityTrust || { _cls: new Set(['hidden']) };
  out[name] = { kind: banner.dataset.kind || null, shown: !banner._cls.has('hidden'),
                title: (els.identityBannerTitle || {}).textContent, text: (els.identityBannerText || {}).textContent,
                unblock: els.identityBannerUnblock ? !els.identityBannerUnblock._cls.has('hidden') : null,
                pill: pill._cls.has('hidden') ? null : { text: pill.textContent, title: pill.title } };
}
console.log(JSON.stringify(out));
"""


def _banner_for(answers):
    """The banner chat.js raises for each /api/identity/me answer, or None (and
    a SKIP line) without node."""
    import subprocess

    node = shutil.which("node")
    if not node:
        print("  SKIP  node is not installed: the behavioural banner check did not run")
        return None
    harness = Path(_TMP, "banner_harness.js")
    harness.write_text(_BANNER_HARNESS)
    run = subprocess.run([node, str(harness), str(ROOT / "frontend" / "js" / "chat.js"), json.dumps(answers)],
                         capture_output=True, text=True, timeout=60)
    try:
        return json.loads(run.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        check("UI: the banner harness ran", False, (run.stderr or run.stdout)[-400:])
        return {}


def main() -> int:
    check("temp DB in use (never the app's medadvice.db)", _TMP in str(dbmod.engine.url), str(dbmod.engine.url))
    dbmod.init_db()
    try:
        test_signer()
        test_lookup()
        test_cii_not_found_is_an_answer_only_by_its_shape()
        test_victim_self_check_on_a_partial_answer()
        test_victim_self_check_on_a_refused_client()
        test_victim_self_check_on_a_lockout()
        test_decide()
        test_engines()
        test_store_generation()
        with TestClient(app) as c:
            governance_logger.set_logs_directory(os.path.join(_TMP, "logs"))
            test_app(c)
            test_override_and_pull(c)
        test_store_override()
        test_rules()
        refused = identity_isolation.requests_refused()
        check("no identity request reached a real Duo or CII (each was refused and recorded)", not refused, str(refused))
    finally:
        lookup.set_transport(None)
        _configure(False)
        dbmod.engine.dispose()
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
