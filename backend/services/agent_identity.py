"""The app's own identity in Duo's Agent Directory (Lab 5, plan 12.4).

PseudoCo Assistant is registered in Duo's Agent Directory as the custom agent
"PseudoCo Assistant". A confidential client of a Duo OAuth 2.1 / OIDC
application ("PseudoCo Assistant Agent API") is bound to it by the agent's
client registration rules. Each time that client authenticates, Duo binds it
to the agent and records the agent instance as seen. A client-credentials
grant has no user and no device, so Duo shows both as "Unknown". Cisco
Identity Intelligence collects the Agent Directory from Duo. It lists the
agent as an *Agentic App* non-human identity, last seen at the latest token,
and lists the client as a *Confidential Client* (verified 2026-11-18).

This module asks for that token on a daemon thread: once at startup, and
again shortly before each token expires. It keeps the current token for
``token()``.

**The token authorizes nothing yet.** No gateway checks it and no tool call
presents it. It shows that the app authenticates to Duo as its agent. Never
describe it as Duo governing the agent's tool calls.

Rules (CLAUDE.md "Identity sign-in"):

- **Inert unless configured.** The keys are ``DUO_ENABLED``,
  ``DUO_AGENT_CLIENT_ID``, ``DUO_AGENT_CLIENT_SECRET`` and an https
  ``DUO_AGENT_TOKEN_URL``. With any missing, no thread starts, no client is
  built and nothing is sent. Labs 0-4 are unchanged.
- **The keys are set in .env only**, never through ``settings_store`` or
  ``_INTEGRATION_FIELDS``. ``DUO_AGENT_CLIENT_SECRET`` is on
  ``redaction.SECRET_SETTINGS``. The access token is never logged, and the
  redactor drops it by pattern (a bearer token, ``access_token``, a JWT).
  This module's logger is one of ``redaction.REDACTED_LOGGERS``.
- **Never on the event loop.** Requests run on the daemon thread.
  ``token()`` and ``status()`` only read the cache.
- **Bounded.** 3 s to connect and 5 s per read. Redirects are not followed.
  Secrets go only over https. TLS uses the CA bundle that ``backend.config``
  sets (``SSL_CERT_FILE``), like ``identity_lookup``.
- **Never raises.** A failure is a short code from a fixed vocabulary: an
  exception class, ``http_<status>`` or ``bad_response``. It never contains a
  URL, a secret or a response body.
- **One request per token.** The next request goes ``REFRESH_MARGIN_S``
  before the token expires. After a failure, the wait doubles from
  ``RETRY_MIN_S`` up to ``RETRY_MAX_S``. When Duo's ``Retry-After`` is longer,
  that is used, up to the same maximum. Nothing else ever asks for a token:
  not a request, a turn or a restart beyond the first.

The client authenticates with HTTP Basic (``client_secret_basic``) and sends
``grant_type=client_credentials``, plus ``scope=DUO_AGENT_SCOPE`` when that is
set.
"""
from __future__ import annotations

import email.utils
import logging
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_S = 3.0
READ_TIMEOUT_S = 5.0
TIMEOUT = httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S)
USER_AGENT = "pseudoco-assistant-agent-identity"

#: Ask for the next token this long before the current one expires.
REFRESH_MARGIN_S = 300.0
#: ``token()`` stops handing out a token this long before it expires.
EXPIRY_SKEW_S = 30.0
#: A token's life when Duo's answer does not say. Duo's say 3600 s, and the
#: client's Access Token Lifetime sets it.
DEFAULT_LIFETIME_S = 3600.0
#: Lifetimes outside this range are clamped. The ceiling keeps a bad answer
#: from parking the refresher for days.
MIN_LIFETIME_S = 60.0
MAX_LIFETIME_S = 86400.0
#: Never ask again sooner than this after a token was issued.
MIN_REFRESH_S = 30.0
#: After a failure, wait this long, doubling with each failure in a row, up
#: to the maximum. Duo's Retry-After is used when it is longer.
RETRY_MIN_S = 60.0
RETRY_MAX_S = 3600.0

#: ``status()["state"]`` values.
NOT_CONFIGURED, PENDING, OK, UNAVAILABLE = "not_configured", "pending", "ok", "unavailable"

# Clocks, replaceable by tests: monotonic for validity and waits, wall time for
# the timestamps ``status()`` reports.
_monotonic = time.monotonic
_wall = time.time


# --------------------------------------------------------------------------- configuration
def _s(name: str) -> str:
    return str(getattr(settings, name, "") or "").strip()


def _https_url(value: str) -> str:
    """``value`` when it is an https URL with a host, else ``""``. No secret
    ever goes over http."""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    return value if parts.scheme.lower() == "https" and parts.hostname else ""


def configured() -> bool:
    """True when ``DUO_ENABLED`` is on and the client ID, the client secret and
    an https token URL are all set."""
    return bool(getattr(settings, "duo_enabled", False) and _s("duo_agent_client_id")
                and _s("duo_agent_client_secret") and _https_url(_s("duo_agent_token_url")))


# --------------------------------------------------------------------------- HTTP client
_client_lock = threading.Lock()
_transport: Optional[httpx.BaseTransport] = None
_http: Optional[httpx.Client] = None


def _client() -> httpx.Client:
    global _http
    with _client_lock:
        if _http is None:
            _http = httpx.Client(timeout=TIMEOUT, transport=_transport, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        return _http


def set_transport(transport: Optional[httpx.BaseTransport] = None) -> None:
    """Send every token request through ``transport``. Tests pass an
    ``httpx.MockTransport``, and ``None`` restores the network. Also drops the
    client and the cached token."""
    global _transport, _http
    with _client_lock:
        _transport = transport
        if _http is not None:
            try:
                _http.close()
            except Exception:  # noqa: BLE001
                pass
        _http = None
    reset()


# --------------------------------------------------------------------------- state
_state_lock = threading.Lock()
_token: Optional[str] = None
_valid_until = 0.0          # monotonic: the token is handed out until then
_expires_at: Optional[float] = None    # wall clock, for status()
_obtained_at: Optional[float] = None   # wall clock, for status()
_last_error: Optional[str] = None
_failures = 0               # failed requests in a row
_requests = 0               # requests sent since start (or reset)


def reset() -> None:
    """Forget the token and every counter (tests, ``set_transport``)."""
    global _token, _valid_until, _expires_at, _obtained_at, _last_error, _failures, _requests
    with _state_lock:
        _token, _valid_until, _expires_at, _obtained_at = None, 0.0, None, None
        _last_error, _failures, _requests = None, 0, 0


def token() -> Optional[str]:
    """The current access token, or None when none is valid. Reads the cache
    only and never sends a request."""
    with _state_lock:
        return _token if _token is not None and _monotonic() < _valid_until else None


def _iso(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def status() -> Dict[str, Any]:
    """What the refresher knows, without the token. Returns ``configured``,
    ``state`` (not_configured / pending / ok / unavailable), ``obtained_at``,
    ``expires_at``, ``last_error``, ``failures`` and ``requests``."""
    with _state_lock:
        valid = _token is not None and _monotonic() < _valid_until
        if not configured():
            state = NOT_CONFIGURED
        elif valid:
            state = OK
        elif _requests == 0:
            state = PENDING
        else:
            state = UNAVAILABLE
        return {"configured": configured(), "state": state, "obtained_at": _iso(_obtained_at),
                "expires_at": _iso(_expires_at) if valid else None, "last_error": _last_error,
                "failures": _failures, "requests": _requests}


# --------------------------------------------------------------------------- one request
def _error_code(exc: BaseException) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connect_error"
    return type(exc).__name__


def _retry_after_s(response: Optional[httpx.Response]) -> float:
    """Duo's ``Retry-After`` in seconds (a number or an HTTP date), or 0."""
    if response is None:
        return 0.0
    raw = str(response.headers.get("retry-after") or "").strip()
    if raw.isdigit():
        return float(raw)
    if raw:
        try:
            return max(0.0, email.utils.parsedate_to_datetime(raw).timestamp() - _wall())
        except (TypeError, ValueError, IndexError, OverflowError):
            return 0.0
    return 0.0


def _lifetime_s(data: Dict[str, Any]) -> float:
    try:
        lifetime = float(data.get("expires_in") or DEFAULT_LIFETIME_S)
    except (TypeError, ValueError):
        lifetime = DEFAULT_LIFETIME_S
    return max(MIN_LIFETIME_S, min(MAX_LIFETIME_S, lifetime))


def refresh_after_s(lifetime: float) -> float:
    """How long after a token is issued the next one is asked for."""
    if lifetime > 2 * REFRESH_MARGIN_S:
        return max(MIN_REFRESH_S, lifetime - REFRESH_MARGIN_S)
    return max(MIN_REFRESH_S, lifetime / 2)


def retry_after_failure_s(failures: int, retry_after: float = 0.0) -> float:
    """How long to wait after the ``failures``-th failure in a row."""
    backoff = RETRY_MIN_S * (2 ** max(0, min(failures - 1, 16)))
    return min(RETRY_MAX_S, max(backoff, retry_after))


def _failed(error: str, response: Optional[httpx.Response] = None) -> Tuple[bool, float]:
    global _last_error, _failures
    with _state_lock:
        _last_error, _failures = error, _failures + 1
        failures = _failures
    wait = retry_after_failure_s(failures, _retry_after_s(response))
    logger.warning("Duo agent token request failed (%s, %d in a row); next try in %.0f s",
                   error, failures, wait)
    return False, wait


def request_token() -> Tuple[bool, float]:
    """Ask Duo for one client-credentials token and keep it. Returns
    ``(ok, seconds until the next request)``. Never raises, and sends nothing
    unless ``configured()``."""
    global _token, _valid_until, _expires_at, _obtained_at, _last_error, _failures, _requests
    if not configured():
        return False, RETRY_MAX_S
    form = {"grant_type": "client_credentials"}
    scope = _s("duo_agent_scope")
    if scope:
        form["scope"] = scope
    with _state_lock:
        _requests += 1
    try:
        response = _client().post(_s("duo_agent_token_url"), data=form,
                                  auth=(_s("duo_agent_client_id"), _s("duo_agent_client_secret")))
    except Exception as exc:  # noqa: BLE001 - a failed request is a status, never a crash
        return _failed(_error_code(exc))
    if response.status_code != 200:
        return _failed(f"http_{response.status_code}", response)
    try:
        data = response.json()
    except ValueError:
        return _failed("bad_response")
    access = data.get("access_token") if isinstance(data, dict) else None
    kind = str(data.get("token_type") or "bearer").lower() if isinstance(data, dict) else ""
    if not isinstance(access, str) or not access or kind != "bearer":
        return _failed("bad_response")
    lifetime = _lifetime_s(data)
    now_mono, now_wall = _monotonic(), _wall()
    with _state_lock:
        recovered = _failures > 0 or _obtained_at is None
        _token = access
        # Handed out until just before it expires. The next one is asked for
        # REFRESH_MARGIN_S before that, so the two overlap.
        _valid_until = now_mono + max(1.0, lifetime - min(EXPIRY_SKEW_S, lifetime / 4))
        _expires_at, _obtained_at = now_wall + lifetime, now_wall
        _last_error, _failures = None, 0
    (logger.info if recovered else logger.debug)(
        "Duo agent token obtained (expires %s); Duo records the PseudoCo Assistant agent as seen",
        _iso(now_wall + lifetime))
    return True, refresh_after_s(lifetime)


# --------------------------------------------------------------------------- refresher
_run_lock = threading.Lock()
_stop: Optional[threading.Event] = None
_thread: Optional[threading.Thread] = None


def _loop(stop: threading.Event) -> None:
    """Ask now, then again whenever ``request_token`` says, until stopped or no
    longer configured."""
    while not stop.is_set() and configured():
        _ok, wait = request_token()
        if stop.wait(wait):
            return


def start() -> Optional[threading.Thread]:
    """Start the refresher on a daemon thread (at startup, never on the event
    loop). Idempotent: a running refresher is returned as it is. Does nothing
    unless ``configured()``."""
    global _thread, _stop
    if not configured():
        return None
    with _run_lock:
        if _thread is not None and _thread.is_alive():
            return _thread
        stop = threading.Event()
        thread = threading.Thread(target=_loop, args=(stop,), name="duo-agent-token", daemon=True)
        _stop, _thread = stop, thread
        thread.start()
        return thread


def stop(timeout: float = 2.0) -> None:
    """Stop the refresher (at shutdown, and in tests). A request already in
    flight runs to its own timeout. The loop just does not go round again."""
    global _thread, _stop
    with _run_lock:
        thread, event = _thread, _stop
        _thread = _stop = None
    if event is not None:
        event.set()
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout)
