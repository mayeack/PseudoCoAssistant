"""Duo and Cisco Identity Intelligence status lookups (Lab 5, plan 12.1).

The Identity Risk Gate (``identity_gate.decide``) and the revocation pull in
the identity middleware ask this module about a signed-in username. There is
no identity broker: the app calls both services itself, read-only.

- **Duo Admin API** (application "PseudoCo Lab: Status", *Grant read resource*
  only): ``GET /admin/v1/users?username=`` for the account's status (active,
  bypass, disabled, locked out, pending deletion) and its email. Requests are
  signed by ``duo_sign``: Duo's HMAC-SHA512 request signing (signature version
  5, the default of the official ``duo_client``; tests/test_identity_gate.py
  pins known answers produced by ``duo_client`` 5.7.0).
- **Cisco Identity Intelligence** (an API client's four "Copy all" values): an
  OAuth client-credentials token from ``CII_TOKEN_URL`` (cached until shortly
  before it expires, about 10 h), then ``CII_END_USER_QUERY`` against the
  GraphQL API at ``CII_API_URL`` for the user's level of trust and current
  failing checks. CII's login is the user's email, so the Duo answer's email
  is the CII login (a username that is already an email is used as is).
  The last email Duo gave for each username is kept beyond the cache
  (``remembered_email``; it does not change), so CII is still asked while
  Duo cannot answer: once Duo has answered for a user since the app
  started, a Duo outage or throttle never hides that user's CII block.
  Before that (a fresh start, or Status keys Duo refuses) no email is known
  and CII is not asked (``no_login``).

Rules:

- **Never raises.** Every failure is a result with ``state`` "unavailable" and
  a short, fixed-vocabulary ``error`` (an exception class, an HTTP status, a
  Duo stat code); never a URL, key, token or response body.
- **Bounded:** 3 s to connect, 5 s per read, and callers run it off the event
  loop (the middleware uses ``run_in_threadpool``; chat turns already run in
  the threadpool; the routes that call it are plain ``def``).
- **Cached** per username and source for ``IDENTITY_STATUS_TTL_SECONDS``
  (10 s), failures included, so a down service costs one slow request per
  user per window; concurrent callers share one fetch.
- **Inert unless configured:** with a source's keys empty nothing is sent to
  it (``state`` "not_configured"). Secrets go only over https.

``lookup(username)`` returns ``{duo_status, trust_level, failing_checks,
as_of, available, sources}``; ``available`` is True only when both sources
answered about this user, where "no such user" (``not_found``) is an answer:
a user CII has no record of yet (a new participant account) is not an
outage. ``sources`` says what each one actually answered; a source that could
not be asked (no CII login known) is ``unavailable`` (error ``no_login``),
never ``not_found``. CII's "no such user" is read from the answer's shape,
never from the wording of just any error (``_cii_not_found``): a failure
taken for one would make the check "ok" and let the turn through even with
``IDENTITY_FAIL_OPEN`` off.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import logging
import re
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_S = 3.0
READ_TIMEOUT_S = 5.0
TIMEOUT = httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S)
USER_AGENT = "pseudoco-assistant-identity-lookup"

#: Source states.
OK, UNAVAILABLE, NOT_CONFIGURED, NOT_FOUND = "ok", "unavailable", "not_configured", "not_found"
#: States in which a source answered about the user ("no such user" included).
ANSWERED = frozenset({OK, NOT_FOUND})
#: The CII error when no login is known to ask it with (Duo gave no email).
NO_LOGIN = "no_login"

DUO_USERS_PATH = "/admin/v1/users"
#: Duo account statuses, normalized (Duo writes "locked out", "pending deletion").
DUO_STATUSES = frozenset({"active", "bypass", "disabled", "locked_out", "pending_deletion"})
#: CII levels of trust (``LevelOfTrust``).
TRUST_LEVELS = frozenset({"TRUSTED", "FAVORABLE", "NEUTRAL", "QUESTIONABLE", "UNTRUSTED", "UNKNOWN"})

#: The one GraphQL query this app sends to Cisco Identity Intelligence. Kept in
#: one place so it is easy to correct against the live schema (docs.oort.io
#: Public API: ``getEndUser(login)`` -> ``endUserDetails`` with
#: ``failingChecks`` and ``endUserTrustScore.levelOfTrust``).
CII_END_USER_QUERY = (
    "query PseudoCoAssistantEndUser($login: String!) {"
    " getEndUser(login: $login) {"
    " endUserDetails { login status failingChecks endUserTrustScore { levelOfTrust lastUpdated } }"
    " } }"
)
#: Refresh the CII token this long before the server says it expires.
TOKEN_REFRESH_MARGIN_S = 300.0
#: The token's life when the token endpoint does not say (CII documents 10 h).
TOKEN_DEFAULT_LIFETIME_S = 10 * 3600.0

#: GraphQL error codes (``extensions.code``, or AppSync's ``errorType``) that
#: may sit on CII's "no such user" error, compared upper-cased with everything
#: but letters and digits removed (``NOT_FOUND``, ``NotFound``, ``not-found``
#: all read NOTFOUND). Any other code is not that answer.
CII_NOT_FOUND_CODES = frozenset({"NOTFOUND", "USERNOTFOUND", "ENDUSERNOTFOUND"})
#: The wording of a "no such user" error: a sentence about the user itself (an
#: end user, or its record, account, profile or details, with its login quoted
#: or as an address if any) that is not found or does not exist, or "no such
#: user", or "no user" at the end of a sentence or before "found", "with" or a
#: login. Anything else between "user" and the verb ("user pool", "user
#: permission", "scope user.read", "no user permissions") is not the user.
#: Checked only on an error that sits on ``getEndUser`` or its
#: ``endUserDetails`` (``_CII_NOT_FOUND_PATHS``, see ``_cii_not_found``).
#: ``deploy/lab5/lab5_cii.py`` holds the same pattern (test_identity_personas pins it).
_CII_USER_NOT_FOUND_RE = re.compile(
    # A sentence whose subject is the user itself: "<end> user [record|account|...] [with login] [<login>]
    # [is|was|has] not (been) found / does not exist".
    r"\b(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?"
    r"(?:\s+(?:with|for|having|by)\s+(?:login|email|username|id))?"
    r"(?:(?:\s*:\s*|\s+)(?:\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|`[^`\n]{1,200}`|\([^()\n]{1,200}\)"
    r"|[^\s\"'`()]{0,200}[@.][^\s\"'`()]{0,200}))?"
    r"(?:\s*:\s*|\s+)(?:(?:is|was|has|had)\s+)?(?:not\s+(?:been\s+)?found"
    r"|(?:(?:does|did)\s+not|doesn't|didn't|not)\s+exist|(?:could|can)\s*not\s+be\s+found|can't\s+be\s+found)\b"
    # "No such user", or "no user" at the end of a sentence or before "found", "with", a login.
    r"|\bno\s+(?:such\s+)?(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?"
    r"(?:\s*(?:$|[.:;,!])|\s+(?:found|exists?|with|matching|named)\b|\s+(?:for|by)\s+(?:login|email|username|id)\b"
    r"|\s+(?:\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|`[^`\n]{1,200}`|\([^()\n]{1,200}\)"
    r"|[^\s\"'`()]{0,200}[@.][^\s\"'`()]{0,200}))",
    re.IGNORECASE)

_CACHE_MAX = 2048
_FAILING_CHECKS_MAX = 32
_CHECK_NAME_MAX = 80
_HOST_RE = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
_EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
_SAFE_CHECK_RE = re.compile(r"[^A-Za-z0-9 _.:/()&'-]")


# --------------------------------------------------------------------------- Duo request signing
def duo_canon_params(params: Mapping[str, Any]) -> str:
    """Duo's canonical parameter string: RFC 3986-encoded (``~`` unescaped,
    space as ``%20``), sorted by key and then value, ``k=v`` joined by ``&``."""
    args: List[str] = []
    for key, vals in sorted((urllib.parse.quote(str(k), "~"), v) for k, v in params.items()):
        values = vals if isinstance(vals, (list, tuple)) else [vals]
        for val in sorted(urllib.parse.quote(str(v), "~") for v in values):
            args.append(f"{key}={val}")
    return "&".join(args)


def duo_canonicalize(method: str, host: str, path: str, params: Mapping[str, Any], date: str,
                     body: str = "") -> str:
    """The signature-version-5 canonical request: date, method, host, path,
    params, then the SHA-512 of the body and of the (here: no) ``X-Duo-*``
    headers."""
    empty_headers = hashlib.sha512(b"").hexdigest()
    return "\n".join([
        date,
        method.upper(),
        host.lower(),
        path,
        duo_canon_params(params),
        hashlib.sha512(body.encode("utf-8")).hexdigest(),
        empty_headers,
    ])


def duo_sign(ikey: str, skey: str, method: str, host: str, path: str, params: Mapping[str, Any],
             date: str, body: str = "") -> str:
    """The ``Authorization`` header for one Duo Admin API request: HTTP Basic,
    the integration key as user and the HMAC-SHA512 hex of the canonical
    request (keyed by the secret key) as password."""
    canonical = duo_canonicalize(method, host, path, params, date, body)
    signature = hmac.new(skey.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha512).hexdigest()
    return "Basic " + base64.b64encode(f"{ikey}:{signature}".encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------- configuration
def _s(name: str) -> str:
    return str(getattr(settings, name, "") or "").strip()


def _https_url(value: str) -> str:
    """``value`` when it is an https URL with a host, else ``""`` (no secret
    ever goes over http)."""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    return value if parts.scheme.lower() == "https" and parts.hostname else ""


def duo_api_host() -> str:
    host = _s("duo_api_host").lower()
    return host if _HOST_RE.fullmatch(host) else ""


def duo_configured() -> bool:
    """DUO_ENABLED with the read-only Admin API keys and a valid API host."""
    return bool(getattr(settings, "duo_enabled", False) and _s("duo_admin_ikey")
                and _s("duo_admin_skey") and duo_api_host())


def cii_configured() -> bool:
    """DUO_ENABLED with the CII API client's four values (https URLs)."""
    return bool(getattr(settings, "duo_enabled", False) and _s("cii_client_id")
                and _s("cii_client_secret") and _https_url(_s("cii_token_url"))
                and _https_url(_s("cii_api_url")))


def ttl_seconds() -> float:
    """``IDENTITY_STATUS_TTL_SECONDS``, clamped to 1 s .. 5 min."""
    try:
        value = float(getattr(settings, "identity_status_ttl_seconds", 10))
    except (TypeError, ValueError):
        value = 10.0
    return max(1.0, min(300.0, value))


# --------------------------------------------------------------------------- HTTP client
_client_lock = threading.Lock()
_transport: Optional[httpx.BaseTransport] = None
_http: Optional[httpx.Client] = None


def set_transport(transport: Optional[httpx.BaseTransport] = None) -> None:
    """Route every lookup through ``transport`` (tests pass an
    ``httpx.MockTransport``); ``None`` restores the network. Drops the client,
    the caches, the CII token and the remembered emails."""
    global _transport, _http
    with _client_lock:
        _transport = transport
        if _http is not None:
            try:
                _http.close()
            except Exception:  # noqa: BLE001
                pass
        _http = None
    clear_cache()
    forget_emails()


def _client() -> httpx.Client:
    global _http
    with _client_lock:
        if _http is None:
            _http = httpx.Client(timeout=TIMEOUT, transport=_transport, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT})
        return _http


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connect_error"
    return type(exc).__name__


# --------------------------------------------------------------------------- cache
class _Cache:
    """A small TTL cache with one fetch in flight per key. ``clear`` bumps a
    generation, so a fetch that started before it never stores its answer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._inflight: Dict[str, threading.Lock] = {}
        self._generation = 0

    def get(self, key: str, fetch: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        ttl = ttl_seconds()
        with self._lock:
            hit = self._data.get(key)
            if hit is not None and time.monotonic() - hit[0] < ttl:
                return hit[1]
            gate = self._inflight.setdefault(key, threading.Lock())
        # One fetch per key; the others wait for it (each fetch is bounded by
        # the HTTP timeouts, and so is this wait).
        if not gate.acquire(timeout=4 * (CONNECT_TIMEOUT_S + READ_TIMEOUT_S)):
            return _unavailable("busy")
        try:
            with self._lock:
                hit = self._data.get(key)
                if hit is not None and time.monotonic() - hit[0] < ttl:
                    return hit[1]
                generation = self._generation
            value = fetch()
            with self._lock:
                if generation == self._generation:
                    if len(self._data) >= _CACHE_MAX:
                        self._data.clear()
                    self._data[key] = (time.monotonic(), value)
            return value
        finally:
            gate.release()
            with self._lock:
                if len(self._inflight) > _CACHE_MAX:
                    self._inflight = {k: v for k, v in self._inflight.items() if v.locked()}

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._generation += 1


_duo_cache = _Cache()
_cii_cache = _Cache()
_token_lock = threading.Lock()
_token: Optional[Tuple[str, float]] = None      # (access token, monotonic expiry)

# username -> the email of Duo's last successful answer about it: CII's login.
# Not an answer cache (no TTL): an email does not change with the account's
# status, and keeping it lets CII be asked while Duo cannot answer. Updated by
# every Duo read that succeeds (sign-in start, the pull, the gate, /me).
_EMAILS_MAX = 4096
_emails_lock = threading.Lock()
_emails: Dict[str, str] = {}


def clear_cache() -> None:
    """Forget every cached answer and the CII token (tests, configuration
    change). The remembered emails stay (``forget_emails``)."""
    global _token
    _duo_cache.clear()
    _cii_cache.clear()
    with _token_lock:
        _token = None


def forget_emails() -> None:
    """Forget every remembered email (tests; ``set_transport`` does this)."""
    with _emails_lock:
        _emails.clear()


def remembered_email(username: Any) -> Optional[str]:
    """The email Duo last gave for ``username``, or None."""
    with _emails_lock:
        return _emails.get(_normalize_username(username))


def _remember_email(username: str, answer: Mapping[str, Any]) -> None:
    """Keep the email of a successful Duo answer; an answer without one
    forgets it (Duo no longer has an email on file). Failures change nothing."""
    if answer.get("state") != OK:
        return
    mail = answer.get("email")
    with _emails_lock:
        if isinstance(mail, str) and mail:
            if username not in _emails and len(_emails) >= _EMAILS_MAX:
                _emails.clear()
            _emails[username] = mail
        else:
            _emails.pop(username, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _unavailable(error: str) -> Dict[str, Any]:
    return {"state": UNAVAILABLE, "error": error, "fetched_at": _now_iso()}


def _normalize_username(username: Any) -> str:
    return str(username or "").strip().lower()


# --------------------------------------------------------------------------- Duo
def normalize_duo_status(value: Any) -> Optional[str]:
    status = re.sub(r"\s+", "_", str(value or "").strip().lower())
    return status if status in DUO_STATUSES else ("other" if status else None)


def _duo_fetch(username: str) -> Dict[str, Any]:
    host = duo_api_host()
    params = {"username": [username]}
    date = email.utils.formatdate()
    auth = duo_sign(_s("duo_admin_ikey"), _s("duo_admin_skey"), "GET", host, DUO_USERS_PATH, params, date)
    url = f"https://{host}{DUO_USERS_PATH}?{urllib.parse.urlencode({'username': username})}"
    try:
        response = _client().get(url, headers={"Date": date, "Authorization": auth})
    except Exception as exc:  # noqa: BLE001 - never raises
        return _unavailable(_error_code(exc))
    if response.status_code != 200:
        return _unavailable(f"http_{response.status_code}")
    try:
        body = response.json()
    except ValueError:
        return _unavailable("bad_response")
    if not isinstance(body, dict) or body.get("stat") != "OK":
        code = body.get("code") if isinstance(body, dict) else None
        return _unavailable(f"stat_{code}" if isinstance(code, int) else "stat_fail")
    users = body.get("response")
    if not isinstance(users, list):
        return _unavailable("bad_response")
    users = [u for u in users if isinstance(u, dict)]
    match = next((u for u in users if _normalize_username(u.get("username")) == username),
                 users[0] if len(users) == 1 else None)
    if match is None:
        return {"state": NOT_FOUND, "duo_status": None, "fetched_at": _now_iso()}
    mail = str(match.get("email") or "").strip()
    return {"state": OK, "duo_status": normalize_duo_status(match.get("status")),
            "email": mail if _EMAIL_RE.fullmatch(mail) else None, "fetched_at": _now_iso()}


def duo_user(username: Any) -> Dict[str, Any]:
    """The Duo half of a lookup: ``{state, duo_status, [email], [error], fetched_at}``.
    Cached; never raises; no request unless the Admin API keys are set."""
    name = _normalize_username(username)
    if not duo_configured():
        return {"state": NOT_CONFIGURED, "duo_status": None, "fetched_at": _now_iso()}
    if not name:
        return {"state": NOT_FOUND, "duo_status": None, "fetched_at": _now_iso()}

    def fetch() -> Dict[str, Any]:
        try:
            result = _duo_fetch(name)
        except Exception as exc:  # noqa: BLE001
            result = _unavailable(_error_code(exc))
        if result["state"] == UNAVAILABLE:
            logger.warning("Duo status lookup unavailable (%s)", result.get("error"))
        _remember_email(name, result)
        return result

    return _duo_cache.get(name, fetch)


# --------------------------------------------------------------------------- Cisco Identity Intelligence
def _cii_access_token(*, refresh: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """``(token, None)`` or ``(None, error)``. Cached until shortly before it expires."""
    global _token
    with _token_lock:
        if not refresh and _token is not None and time.monotonic() < _token[1]:
            return _token[0], None
        body = {"client_id": _s("cii_client_id"), "client_secret": _s("cii_client_secret"),
                "grant_type": "client_credentials"}
        try:
            response = _client().post(_s("cii_token_url"), json=body)
        except Exception as exc:  # noqa: BLE001
            return None, "token_" + _error_code(exc)
        if response.status_code != 200:
            return None, f"token_http_{response.status_code}"
        try:
            data = response.json()
        except ValueError:
            return None, "token_bad_response"
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            return None, "token_bad_response"
        # A credential: never logged, and backend/logging/redaction.py drops it
        # by pattern where it travels (Authorization: Bearer, access_token, a JWT).
        try:
            lifetime = float(data.get("expires_in") or TOKEN_DEFAULT_LIFETIME_S)
        except (TypeError, ValueError):
            lifetime = TOKEN_DEFAULT_LIFETIME_S
        usable = lifetime - TOKEN_REFRESH_MARGIN_S if lifetime > 2 * TOKEN_REFRESH_MARGIN_S else lifetime / 2
        _token = (token, time.monotonic() + max(1.0, usable))
        return token, None


def _sanitize_checks(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value[:_FAILING_CHECKS_MAX]:
        if isinstance(item, str):
            text = _SAFE_CHECK_RE.sub("", item).strip()[:_CHECK_NAME_MAX]
            if text and text not in out:
                out.append(text)
    return out


def _cii_query(login: str, token: str) -> Tuple[Optional[httpx.Response], Optional[str]]:
    try:
        response = _client().post(_s("cii_api_url"), headers={"Authorization": f"Bearer {token}"},
                                  json={"query": CII_END_USER_QUERY, "variables": {"login": login}})
    except Exception as exc:  # noqa: BLE001
        return None, _error_code(exc)
    return response, None


def _error_code_of(error: Mapping[str, Any]) -> str:
    extensions = error.get("extensions") if isinstance(error.get("extensions"), Mapping) else {}
    code = extensions.get("code") or extensions.get("errorType") or error.get("errorType") or ""
    return re.sub(r"[^A-Z0-9]+", "", str(code).upper())


#: Where a CII "no such user" error may sit: on ``getEndUser`` itself, or on
#: its ``endUserDetails`` (the published ``GetEndUserOutput!`` keeps the
#: wrapper and nulls the details).
_CII_NOT_FOUND_PATHS = (["getEndUser"], ["getEndUser", "endUserDetails"])


def _cii_not_found(body: Any) -> bool:
    """Whether a GraphQL answer is CII's own "no such user".

    The user's details must stop at one of three places, and nowhere deeper:
    ``data`` is null (a non-null field failed and GraphQL nulled its parent),
    ``getEndUser`` is null, or ``getEndUser`` is an object whose
    ``endUserDetails`` is present and null. The last is the published schema's
    answer for a user CII has no record of yet (``GetEndUserOutput!`` with a
    nullable ``endUserDetails``). With no error, a null ``getEndUser`` or null
    details is the answer; a null ``data`` is not. With errors, every one must
    sit on ``getEndUser`` or its ``endUserDetails`` (``_CII_NOT_FOUND_PATHS``),
    at or below where the details stop, say that the user was not found
    (``_CII_USER_NOT_FOUND_RE``), and carry no code or one of
    ``CII_NOT_FOUND_CODES``. Anything else is not an answer: a request-level
    error (no ``data``: a query the schema rejects), an error at another path
    or none (a deeper partial failure, a tenant or permission problem), or
    other wording.

    ``deploy/lab5/lab5_cii.py`` applies the same rule on the Mac;
    ``tests/fixtures/cii_end_user_answers.json`` holds the cases both must
    read the same way."""
    if not isinstance(body, Mapping) or "data" not in body:
        return False
    data, errors = body.get("data"), body.get("errors")
    if data is None:
        stop = 0
    elif isinstance(data, Mapping) and "getEndUser" in data:
        end_user = data.get("getEndUser")
        if end_user is None:
            stop = 1
        elif (isinstance(end_user, Mapping) and "endUserDetails" in end_user
              and end_user.get("endUserDetails") is None):
            stop = 2
        else:
            return False
    else:
        return False
    if not errors:
        return stop > 0
    if not isinstance(errors, list):
        return False
    for error in errors:
        if not isinstance(error, Mapping):
            return False
        path = error.get("path")
        if path not in _CII_NOT_FOUND_PATHS or len(path) < stop:
            return False
        if not _CII_USER_NOT_FOUND_RE.search(str(error.get("message") or "")[:1000]):
            return False
        code = _error_code_of(error)
        if code and code not in CII_NOT_FOUND_CODES:
            return False
    return True


def _cii_details(details: Mapping[str, Any]) -> Dict[str, Any]:
    """The level of trust and the failing checks an ``endUserDetails`` holds."""
    score = details.get("endUserTrustScore") if isinstance(details.get("endUserTrustScore"), Mapping) else {}
    level = str(score.get("levelOfTrust") or "").strip().upper() or None
    return {"trust_level": level if level in TRUST_LEVELS or level is None else "OTHER",
            "failing_checks": _sanitize_checks(details.get("failingChecks"))}


def _cii_parse(body: Any) -> Dict[str, Any]:
    """One GraphQL answer to ``{state, trust_level, failing_checks, [error], fetched_at}``.

    CII's "no such user" (``_cii_not_found``) is ``not_found``. Details with no
    error are ``ok``. Any other answer that carries errors is ``unavailable``,
    details or not: a partial answer (say, ``failingChecks`` failed and came
    back null) would otherwise read as a user with no failing checks. What a
    partial answer did say is kept, though: GraphQL nulls only the fields that
    failed, so a level of trust or failing checks in its details are CII's
    own, and the gate blocks on them (a block resting on what was learned
    still blocks) while the check stays ``unavailable``. Anything else is
    ``unavailable`` with nothing learned."""
    if _cii_not_found(body):
        return {"state": NOT_FOUND, "trust_level": None, "failing_checks": [], "fetched_at": _now_iso()}
    if not isinstance(body, Mapping):
        return _unavailable("bad_response")
    data = body.get("data")
    end_user = data.get("getEndUser") if isinstance(data, Mapping) else None
    details = end_user.get("endUserDetails") if isinstance(end_user, Mapping) else None
    learned = _cii_details(details) if isinstance(details, Mapping) else {}
    if body.get("errors"):
        return {**_unavailable("graphql_error"), "trust_level": None, "failing_checks": [], **learned}
    if not learned:
        return _unavailable("bad_response")
    return {"state": OK, **learned, "fetched_at": _now_iso()}


def _cii_fetch(login: str) -> Dict[str, Any]:
    token, error = _cii_access_token()
    if token is None:
        return _unavailable(error or "token_error")
    response, error = _cii_query(login, token)
    if response is not None and response.status_code == 401:
        # The cached token was revoked or expired early: one fresh token, one retry.
        token, error = _cii_access_token(refresh=True)
        if token is None:
            return _unavailable(error or "token_error")
        response, error = _cii_query(login, token)
    if response is None:
        return _unavailable(error or "error")
    if response.status_code != 200:
        return _unavailable(f"http_{response.status_code}")
    try:
        body = response.json()
    except ValueError:
        return _unavailable("bad_response")
    return _cii_parse(body)


def cii_login(username: str, duo_answer: Optional[Mapping[str, Any]] = None) -> Optional[str]:
    """The CII login for a user: the email Duo has on file (this answer's;
    when Duo could not answer now, the email of its last answer), else the
    username when it is an email already."""
    answer = duo_answer or {}
    mail = answer.get("email")
    if not (isinstance(mail, str) and _EMAIL_RE.fullmatch(mail)) and answer.get("state") != OK:
        mail = remembered_email(username)
    if isinstance(mail, str) and _EMAIL_RE.fullmatch(mail):
        return mail.lower()
    return username if _EMAIL_RE.fullmatch(username or "") else None


def cii_user(login: Optional[str]) -> Dict[str, Any]:
    """The CII half of a lookup: ``{state, trust_level, failing_checks, [error], fetched_at}``.
    Cached per login; never raises; no request unless the API client is set.
    Without a login nothing is asked, and the answer says so: ``unavailable``
    with error ``no_login`` (never ``not_found``, which is CII's own answer)."""
    if not cii_configured():
        return {"state": NOT_CONFIGURED, "trust_level": None, "failing_checks": [], "fetched_at": _now_iso()}
    if not login:
        return {**_unavailable(NO_LOGIN), "trust_level": None, "failing_checks": []}

    def fetch() -> Dict[str, Any]:
        try:
            result = _cii_fetch(login)
        except Exception as exc:  # noqa: BLE001
            result = _unavailable(_error_code(exc))
        if result["state"] == UNAVAILABLE:
            logger.warning("Identity Intelligence lookup unavailable (%s)", result.get("error"))
        return result

    return _cii_cache.get(login.lower(), fetch)


# --------------------------------------------------------------------------- the lookup
def lookup(username: Any) -> Dict[str, Any]:
    """Everything the gate needs about one username. Never raises."""
    name = _normalize_username(username)
    try:
        duo = duo_user(name)
        cii = cii_user(cii_login(name, duo))
    except Exception as exc:  # noqa: BLE001 - belt and braces: never raises
        duo = cii = _unavailable(_error_code(exc))
    times = [t for t in (duo.get("fetched_at"), cii.get("fetched_at")) if t]
    return {
        "duo_status": duo.get("duo_status"),
        "trust_level": cii.get("trust_level"),
        "failing_checks": list(cii.get("failing_checks") or []),
        "as_of": min(times) if times else _now_iso(),
        "available": duo.get("state") in ANSWERED and cii.get("state") in ANSWERED,
        "sources": {"duo": duo.get("state"), "cii": cii.get("state")},
        "errors": {k: v.get("error") for k, v in (("duo", duo), ("cii", cii)) if v.get("error")},
    }
