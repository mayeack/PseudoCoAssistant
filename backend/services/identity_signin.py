"""Duo Universal Prompt sign-in (Lab 5): the app's only Duo Web SDK caller.

Wraps ``duo_universal.Client`` (pinned in requirements.txt) for the Web SDK
application "PseudoCo Lab: Sign-in". There is no identity broker (plan 12.1):
the instance holds the Web SDK keys in ``.env`` for the workshop's lifetime and
talks to Duo itself. backend/routers/identity_auth.py is the only caller.

The flow, and the rules that keep it honest:

- ``begin(username)`` normalizes the username, rate-limits it **per username**
  (never per IP: a room signs in from behind one NAT), checks it against
  ``IDENTITY_ALLOWED_USERS``, and returns Duo's prompt URL plus a fresh state.
  The state and an OIDC nonce are kept here for 5 minutes, single use, with
  the username they were issued for. The route binds the state to a cookie.
- ``complete(...)`` requires the callback's state to equal the cookie's
  (``compare_digest``), takes the pending entry (single use), and exchanges
  Duo's code. **The username comes only from that pending entry**, never from
  the query, and Duo's answer must say ``allow`` with a ``preferred_username``
  equal to it (the SDK checks that and the nonce; so do we). Then it creates
  the identity session and writes ``identity_signin_success``.
- The redirect URI is ``settings.duo_redirect_uri`` (``PUBLIC_BASE_URL`` +
  ``/auth/duo/callback``) and nothing else, never the request's Host header.
- Every failure is a ``SigninError`` carrying one fixed code from
  ``ERROR_CODES``; the sign-in page has one message per code and never shows
  anything Duo or the request said.
- Duo is called off the event loop and with a deadline: the SDK sets no
  timeout on its HTTP calls, so each one runs on a daemon thread that the
  caller waits on for at most ``DUO_CALL_TIMEOUT_S`` (at most
  ``_DUO_CALL_SLOTS`` at once). A hung Duo answers ``duo_unavailable``; it never
  holds a request, or the process at shutdown, hostage.
- ``run_health_check`` calls Duo's health check once at startup
  (``start_health_check``, a daemon thread) and records the result for the
  ``duo_signin`` host gate (``host_capabilities.record_duo_health``). The
  gate, and so every sign-in route, stays closed until it has passed.

Inert unless configured: nothing here runs, and ``duo_universal`` is not even
imported, unless ``DUO_ENABLED`` is on with the Web SDK keys and an https
``PUBLIC_BASE_URL``.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, Optional, Tuple

from backend.config import settings
from backend.services import identity_store

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- error codes
# Fixed codes; frontend/login-duo.html has one message for each
# (tests/test_duo_signin.py pins the two lists together). They double as the
# ``reason`` of the identity_signin_failure audit event.
UNAVAILABLE = "unavailable"            # the duo_signin gate is closed
BAD_ORIGIN = "bad_origin"              # a cross-site POST
INVALID_USERNAME = "invalid_username"
NOT_ALLOWED = "not_allowed"            # not on IDENTITY_ALLOWED_USERS
RATE_LIMITED = "rate_limited"
STATE_MISMATCH = "state_mismatch"      # callback state != this browser's state cookie
STATE_EXPIRED = "state_expired"        # unknown, already used, or older than 5 minutes
NONCE_MISMATCH = "nonce_mismatch"
MISSING_CODE = "missing_code"
DUO_DENIED = "duo_denied"              # Duo's result is not "allow", or Duo returned an error
DUO_REFUSED = "duo_refused"            # Duo refused the code exchange, or its token did not verify
DUO_UNAVAILABLE = "duo_unavailable"    # Duo could not be reached in time
USERNAME_MISMATCH = "username_mismatch"
FAILED = "failed"                      # anything else
ERROR_CODES = frozenset({
    UNAVAILABLE, BAD_ORIGIN, INVALID_USERNAME, NOT_ALLOWED, RATE_LIMITED, STATE_MISMATCH,
    STATE_EXPIRED, NONCE_MISMATCH, MISSING_CODE, DUO_DENIED, DUO_REFUSED, DUO_UNAVAILABLE,
    USERNAME_MISMATCH, FAILED,
})


class SigninError(Exception):
    """A refused sign-in. ``code`` is one of ``ERROR_CODES``; ``username`` is the
    normalized username the attempt was for, when known (for the audit event).
    ``audit`` is False when the failure must not write an audit event (the
    gate is closed, or a rate-limited name was already recorded this window)."""

    def __init__(self, code: str, username: Optional[str] = None, *, audit: bool = True) -> None:
        super().__init__(code)
        self.code = code if code in ERROR_CODES else FAILED
        self.username = username or None
        self.audit = audit


# --------------------------------------------------------------------------- limits
#: The pending state lives this long (Duo's own JWT expiry is 5 minutes too).
STATE_TTL_S = 300.0
#: Sign-in starts per username per window. Per username, never per IP: a room
#: signs in from behind one NAT, so a per-IP budget would lock the whole room
#: out. 30 in 5 minutes lets a room of about 30 start one sign-in each as one
#: shared persona; a script hammering one name is stopped.
RATE_LIMIT_STARTS = 30
RATE_LIMIT_WINDOW_S = 300.0
#: Deadline for one Duo call (the code exchange) and for the startup health check.
DUO_CALL_TIMEOUT_S = 10.0
HEALTH_TIMEOUT_S = 15.0
_DUO_CALL_SLOTS = 4
_PENDING_MAX = 1024
_RATE_KEYS_MAX = 4096
_USERNAME_MAX = 128
# A Duo username after normalization (identity_store.normalize_username).
_USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._@+-]{0,127}")
# Duo's authorization code: opaque, but bounded and printable.
_CODE_RE = re.compile(r"[A-Za-z0-9_.~+/=-]{1,1024}")
# A short, fixed-vocabulary text safe to show in the gate's reason.
_SAFE_TEXT = re.compile(r"[A-Za-z0-9 _.,'()-]{1,80}")

_lock = threading.Lock()
_duo_slots = threading.BoundedSemaphore(_DUO_CALL_SLOTS)


@dataclass(frozen=True)
class PendingSignin:
    """One started sign-in, keyed by the sha256 of its state."""

    username: str
    nonce: str
    created: float                 # time.monotonic()
    client_address: Optional[str] = None


_pending: "OrderedDict[str, PendingSignin]" = OrderedDict()
_starts: Dict[str, Deque[float]] = {}
_rate_refusal_logged: Dict[str, float] = {}


# --------------------------------------------------------------------------- the Duo client
def _default_client_factory(*, client_id: str, client_secret: str, host: str, redirect_uri: str) -> Any:
    from duo_universal import Client  # lazy: never imported unless Duo sign-in is configured

    return Client(client_id, client_secret, host, redirect_uri)


_client_factory: Callable[..., Any] = _default_client_factory
_client_cache: Optional[Tuple[tuple, Any]] = None


def set_client_factory(factory: Optional[Callable[..., Any]] = None) -> None:
    """Replace how the Duo client is built (tests pass a fake). ``None``
    restores ``duo_universal.Client``. Drops the cached client."""
    global _client_factory, _client_cache
    with _lock:
        _client_factory = factory or _default_client_factory
        _client_cache = None


def _client() -> Any:
    """The Duo client for the current settings (built once per configuration).
    The redirect URI is ``settings.duo_redirect_uri`` and nothing else."""
    global _client_cache
    key = (settings.duo_client_id, settings.duo_client_secret, settings.duo_api_host,
           settings.duo_redirect_uri)
    with _lock:
        if _client_cache is not None and _client_cache[0] == key:
            return _client_cache[1]
        factory = _client_factory
    client = factory(client_id=key[0], client_secret=key[1], host=key[2], redirect_uri=key[3])
    with _lock:
        _client_cache = (key, client)
    return client


def configured() -> bool:
    """DUO_ENABLED with the Web SDK keys and an https PUBLIC_BASE_URL: the
    settings half of the duo_signin gate (the health check is the other)."""
    return bool(getattr(settings, "duo_enabled", False)
                and all(str(getattr(settings, k, "") or "").strip()
                        for k in ("duo_client_id", "duo_client_secret", "duo_api_host"))
                and settings.duo_redirect_uri)


def gate() -> Dict[str, Any]:
    """The ``duo_signin`` host gate, the single rule every route reads."""
    from backend import host_capabilities

    return host_capabilities.duo_signin_gate(settings)


class _DuoTimeout(Exception):
    """A Duo call did not answer within its deadline."""


def _bounded(fn: Callable[..., Any], *args: Any, timeout: float) -> Any:
    """Run one Duo call on a daemon thread and wait at most ``timeout`` for it.

    The SDK sets no timeout on its HTTP calls, so the call itself cannot be
    cancelled: a hung one keeps its slot until its socket gives up, and is
    simply not waited for. Daemon threads never block process exit. One
    deadline covers both the wait for a free slot and the call itself."""
    deadline = time.monotonic() + timeout
    if not _duo_slots.acquire(timeout=timeout):
        raise _DuoTimeout()
    box: Dict[str, Any] = {}
    done = threading.Event()

    def _run() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = exc
        finally:
            _duo_slots.release()
            done.set()

    try:
        threading.Thread(target=_run, name="duo-call", daemon=True).start()
    except BaseException:
        _duo_slots.release()
        raise
    if not done.wait(max(0.0, deadline - time.monotonic())):
        raise _DuoTimeout()
    if "error" in box:
        raise box["error"]
    return box["value"]


def _sdk_messages() -> frozenset:
    """The SDK's own fixed error strings (safe to show)."""
    try:
        from duo_universal import client as duo_client_module
    except Exception:  # noqa: BLE001
        return frozenset()
    return frozenset(v for k, v in vars(duo_client_module).items()
                     if k.startswith("ERR_") and isinstance(v, str))


def describe_failure(exc: BaseException) -> str:
    """A short description of a Duo failure that is safe to show as the gate's
    reason: an error class, Duo's numeric code and fixed message, or one of the
    SDK's fixed strings. Never a URL, key, header or response body."""
    inner = exc.args[0] if getattr(exc, "args", None) else None
    if isinstance(inner, dict):
        parts = []
        code = inner.get("code")
        if isinstance(code, int) or (isinstance(code, str) and code.isdigit()):
            parts.append(str(code))
        message = inner.get("message") or inner.get("error")
        if isinstance(message, str) and _SAFE_TEXT.fullmatch(message):
            parts.append(message)
        return "Duo answered " + " ".join(parts) if parts else "Duo refused the request"
    if isinstance(inner, BaseException):
        return type(inner).__name__
    if isinstance(inner, str) and inner in _sdk_messages():
        return inner
    return type(exc).__name__


# --------------------------------------------------------------------------- health check
def run_health_check() -> bool:
    """Call Duo's health check (bounded) and record the result for the
    ``duo_signin`` gate. Never raises. Returns whether it passed."""
    from backend import host_capabilities

    try:
        _bounded(_client().health_check, timeout=HEALTH_TIMEOUT_S)
    except _DuoTimeout:
        host_capabilities.record_duo_health(False, f"no answer within {HEALTH_TIMEOUT_S:.0f} s")
        return False
    except ImportError:
        host_capabilities.record_duo_health(
            False, "duo_universal is not installed (pip install -r requirements.txt)")
        return False
    except Exception as exc:  # noqa: BLE001 - a failed check closes the gate, never the app
        detail = describe_failure(exc)
        logger.warning("Duo health check failed: %s", detail)
        host_capabilities.record_duo_health(False, detail)
        return False
    logger.info("Duo health check passed; Duo sign-in is available")
    host_capabilities.record_duo_health(True)
    return True


def start_health_check() -> Optional[threading.Thread]:
    """Run the health check once, on a daemon thread (startup; never the event
    loop). Does nothing, and builds no client, unless Duo sign-in is
    configured: the gate's earlier reasons already explain why it is closed."""
    if not configured():
        return None
    thread = threading.Thread(target=run_health_check, name="duo-health-check", daemon=True)
    thread.start()
    return thread


# --------------------------------------------------------------------------- state + rate limit
def _state_key(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _remember(state: str, pending: PendingSignin) -> None:
    now = time.monotonic()
    with _lock:
        for key in [k for k, p in _pending.items() if now - p.created > STATE_TTL_S]:
            del _pending[key]
        while len(_pending) >= _PENDING_MAX:
            _pending.popitem(last=False)
        _pending[_state_key(state)] = pending


def _take(state: str) -> Optional[PendingSignin]:
    """Remove and return the pending sign-in for a state (single use)."""
    with _lock:
        return _pending.pop(_state_key(state), None)


def _take_rate_slot(username: str) -> Tuple[bool, bool]:
    """``(allowed, audit)``: whether this start fits the username's budget, and
    whether a refusal should be audited (only the first in each window)."""
    now = time.monotonic()
    with _lock:
        starts = _starts.get(username)
        if starts is None:
            if len(_starts) >= _RATE_KEYS_MAX:
                _starts.clear()
                _rate_refusal_logged.clear()
            starts = _starts[username] = deque()
        while starts and now - starts[0] > RATE_LIMIT_WINDOW_S:
            starts.popleft()
        if len(starts) < RATE_LIMIT_STARTS:
            starts.append(now)
            return True, True
        logged = _rate_refusal_logged.get(username)
        first = logged is None or now - logged > RATE_LIMIT_WINDOW_S
        if first:
            _rate_refusal_logged[username] = now
        return False, first


def reset() -> None:
    """Forget pending sign-ins and rate-limit history (tests)."""
    with _lock:
        _pending.clear()
        _starts.clear()
        _rate_refusal_logged.clear()


# --------------------------------------------------------------------------- the flow
def begin(username: Any, *, client_address: Optional[str] = None) -> Tuple[str, str]:
    """Start a sign-in. Returns ``(Duo prompt URL, state)``; the caller binds
    the state to this browser with the state cookie. Raises ``SigninError``."""
    name = identity_store.normalize_username(username)[:_USERNAME_MAX + 1]
    if not gate().get("enabled"):
        raise SigninError(UNAVAILABLE, audit=False)
    if not _USERNAME_RE.fullmatch(name):
        raise SigninError(INVALID_USERNAME, name)
    allowed, audit = _take_rate_slot(name)
    if not allowed:
        raise SigninError(RATE_LIMITED, name, audit=audit)
    if name not in settings.identity_allowed_users_set:
        raise SigninError(NOT_ALLOWED, name)
    # A persona Duo reports disabled is refused here (Duo would refuse it at
    # the prompt too). Only with the read-only Admin API keys; cached, and an
    # unanswered lookup refuses nothing.
    from backend.services import identity_lookup

    if identity_lookup.duo_configured() and identity_lookup.duo_user(name).get("duo_status") == "disabled":
        raise SigninError(DUO_DENIED, name)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    try:
        url = _client().create_auth_url(name, state, nonce=nonce)
    except ImportError:
        raise SigninError(UNAVAILABLE, name) from None
    except Exception:  # noqa: BLE001
        logger.warning("Duo prompt URL could not be built", exc_info=True)
        raise SigninError(FAILED, name) from None
    # The only place a sign-in redirect may go: this instance's Duo API host.
    if not isinstance(url, str) or not url.startswith(f"https://{settings.duo_api_host}/"):
        logger.warning("Duo prompt URL is not on DUO_API_HOST; refused")
        raise SigninError(FAILED, name)
    _remember(state, PendingSignin(username=name, nonce=nonce, created=time.monotonic(),
                                   client_address=client_address))
    return url, state


def _exchange_error_code(exc: BaseException) -> str:
    """Map an exception from the SDK's code exchange to a fixed code."""
    if isinstance(exc, ImportError):
        return UNAVAILABLE
    inner = exc.args[0] if getattr(exc, "args", None) else None
    try:
        from duo_universal import client as sdk
    except Exception:  # noqa: BLE001
        sdk = None
    if sdk is not None and isinstance(inner, str):
        if inner == getattr(sdk, "ERR_USERNAME", None):
            return USERNAME_MISMATCH
        if inner == getattr(sdk, "ERR_NONCE", None):
            return NONCE_MISMATCH
        if inner == getattr(sdk, "ERR_CODE", None):
            return MISSING_CODE
    if isinstance(inner, dict):
        return DUO_REFUSED              # Duo's token endpoint said no (expired / used code, ...)
    try:
        import requests

        if isinstance(inner, requests.RequestException) or isinstance(exc, requests.RequestException):
            return DUO_UNAVAILABLE
    except Exception:  # noqa: BLE001
        pass
    if isinstance(inner, BaseException):
        return DUO_REFUSED              # the id_token did not verify (signature, audience, expiry)
    if isinstance(exc, ValueError):
        return DUO_UNAVAILABLE          # a non-JSON error page in front of Duo
    return FAILED


def complete(
    *,
    state: Optional[str],
    state_cookie: Optional[str],
    duo_code: Optional[str],
    duo_error: Optional[str] = None,
    client_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[str, identity_store.IdentitySnapshot]:
    """Finish a sign-in from Duo's redirect: ``(identity cookie value, snapshot)``.

    Raises ``SigninError``. The username is the pending entry's, never anything
    in the callback's query."""
    if not gate().get("enabled"):
        raise SigninError(UNAVAILABLE, audit=False)
    if not state or not state_cookie or not secrets.compare_digest(
            state.encode("utf-8"), state_cookie.encode("utf-8")):
        # Not this browser's sign-in: the pending entry (if any) is left for the
        # browser that holds the matching cookie.
        raise SigninError(STATE_MISMATCH)
    pending = _take(state)
    if pending is None:
        raise SigninError(STATE_EXPIRED)
    name = pending.username
    if time.monotonic() - pending.created > STATE_TTL_S:
        raise SigninError(STATE_EXPIRED, name)
    if duo_error:
        raise SigninError(DUO_DENIED, name)
    if not duo_code or not _CODE_RE.fullmatch(duo_code):
        raise SigninError(MISSING_CODE, name)
    try:
        token = _bounded(_client().exchange_authorization_code_for_2fa_result, duo_code, name,
                         pending.nonce, timeout=DUO_CALL_TIMEOUT_S)
    except _DuoTimeout:
        raise SigninError(DUO_UNAVAILABLE, name) from None
    except Exception as exc:  # noqa: BLE001 - every failure maps to a fixed code
        code = _exchange_error_code(exc)
        logger.warning("Duo code exchange failed (%s): %s", code, describe_failure(exc))
        raise SigninError(code, name) from None
    if not isinstance(token, dict):
        raise SigninError(DUO_REFUSED, name)
    result = token.get("auth_result") if isinstance(token.get("auth_result"), dict) else {}
    if result.get("result") != "allow":
        raise SigninError(DUO_DENIED, name)
    preferred = identity_store.normalize_username(token.get("preferred_username"))
    if not preferred or not secrets.compare_digest(preferred.encode("utf-8"), name.encode("utf-8")):
        raise SigninError(USERNAME_MISMATCH, name)
    nonce = token.get("nonce")
    if not isinstance(nonce, str) or not secrets.compare_digest(nonce.encode("utf-8"),
                                                                pending.nonce.encode("utf-8")):
        raise SigninError(NONCE_MISMATCH, name)
    if name not in settings.identity_allowed_users_set:
        raise SigninError(NOT_ALLOWED, name)
    context = token.get("auth_context") if isinstance(token.get("auth_context"), dict) else {}
    txid = context.get("txid")
    txid = txid if isinstance(txid, str) and re.fullmatch(r"[A-Za-z0-9-]{1,64}", txid) else None
    cookie_token, snapshot = identity_store.create(
        name, client_address=client_address, user_agent=user_agent, duo_txid=txid)
    from backend.logging import identity_audit

    identity_audit.log_signin_success(username=name, client_address=client_address,
                                      session_ref=snapshot.session_ref, duo_txid=txid)
    return cookie_token, snapshot


def record_failure(err: SigninError, *, client_address: Optional[str]) -> None:
    """Write the ``identity_signin_failure`` audit event for a refused sign-in
    (unless the error says not to). Never raises."""
    if not err.audit:
        return
    from backend.logging import identity_audit

    identity_audit.log_signin_failure(username=err.username, client_address=client_address,
                                      reason=err.code)
