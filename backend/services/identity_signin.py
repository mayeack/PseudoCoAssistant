"""Duo Universal Prompt sign-in (Lab 5): the app's only Duo Web SDK caller.

Wraps ``duo_universal.Client`` (pinned in requirements.txt) for the Web SDK
application "PseudoCo Lab: Sign-in". There is no identity broker (plan 12.1):
the instance holds the Web SDK keys in ``.env`` for the workshop's lifetime and
talks to Duo itself. backend/routers/identity_auth.py is the only caller.

The flow, and the rules that keep it honest:

- ``begin(username)`` normalizes the username, checks it against
  ``IDENTITY_ALLOWED_USERS``, then rate-limits it **per username** (never per
  IP: a room signs in from behind one NAT), and returns Duo's prompt URL plus
  a fresh state. The allowlist comes first, so a name that is not on it never
  takes a rate slot, and the per-username table (bounded, least recently used
  evicted first) only ever holds allowlisted names: no flood of made-up names
  can push a real user's spent budget out of it.
  The state and an OIDC nonce are kept here for 5 minutes, single use, with
  the username they were issued for. The route binds the state to a cookie.
- ``complete(...)`` requires the callback's state to equal the cookie's
  (``compare_digest``), takes the pending entry (single use), and exchanges
  Duo's code. **The username comes only from that pending entry**, never from
  the query, and Duo's answer must say ``allow`` with a ``preferred_username``
  equal to it (the SDK checks that and the nonce; so do we). Then it creates
  the identity session and writes ``identity_signin_success``. It does not
  read the ``duo_signin`` gate: a sign-in that is already at Duo finishes
  even if the gate closed meanwhile (the exchange is attempted, and a Duo
  failure is a fixed code). Only ``begin()`` (``POST /auth/duo/start``) and
  the sign-in link depend on the gate; ``complete()`` needs only Duo sign-in
  to be configured (``configured()``).
- The redirect URI is ``settings.duo_redirect_uri`` (``PUBLIC_BASE_URL`` +
  ``/auth/duo/callback``) and nothing else, never the request's Host header.
- Every failure is a ``SigninError`` carrying one fixed code from
  ``ERROR_CODES``; the sign-in page has one message per code and never shows
  anything Duo or the request said.
- Duo is called off the event loop and with a deadline. duo_universal 2.3.1
  sets no timeout on its HTTP calls and takes none (``Client()`` has no such
  parameter; it calls ``requests.post`` with only ``verify=`` and
  ``proxies=``), so two things bound a call. Its HTTP requests get
  ``DUO_HTTP_TIMEOUT`` (connect, read) through ``_TimedRequests``, the
  ``requests`` its module sees. And each call runs on a daemon thread that the
  caller waits on for at most ``DUO_CALL_TIMEOUT_S`` (at most
  ``_DUO_CALL_SLOTS`` at once): at that deadline the caller gives the slot
  back, whether or not the call ever returns, and the call is abandoned on its
  thread. A hung Duo answers ``duo_unavailable``; it never holds a request, a
  slot, or the process at shutdown, hostage.
- TLS to Duo: with a CA bundle configured the way every other outbound client
  reads it (``REQUESTS_CA_BUNDLE``, else ``CURL_CA_BUNDLE``, naming a file;
  ``backend.config`` points it at the checkout's ``ca-bundle.pem``), Duo is
  verified against that bundle, which is what a TLS-inspecting proxy needs.
  With none, duo_universal's own pinned bundle is kept (``duo_ca_bundle``).
- ``start_health_check`` runs Duo's health check on a daemon thread, at
  startup and then every ``HEALTH_INTERVAL_S`` (every ``HEALTH_RETRY_S`` while
  it fails), and records each result for the ``duo_signin`` host gate
  (``host_capabilities.record_duo_health``). The gate opens on a passing
  check and closes only after ``host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE``
  (3) failed checks in a row, so one failed check on the timer never closes
  it. A check never starts while the previous one is still waiting for Duo.
- Nothing secret reaches a log: ``backend.logging.redaction`` redacts by
  pattern (credential query parameters such as ``duo_code`` and
  ``client_assertion``, credential headers, JWTs) and the configured
  secrets, in every record of every logger, and every query value in the
  HTTP clients' and the Duo SDK's (urllib3 logs the token request's query
  string, with the code and the ``client_assertion`` JWT, at DEBUG). Nothing
  here registers a value with it: no request can make the logs drop a string.

Inert unless configured: nothing here runs, and ``duo_universal`` is not even
imported, unless ``DUO_ENABLED`` is on with the Web SDK keys and an https
``PUBLIC_BASE_URL``.
"""
from __future__ import annotations

import hashlib
import logging
import os
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
UNAVAILABLE = "unavailable"            # start: the duo_signin gate is closed; callback: Duo sign-in is off
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
#: Deadline for one Duo call (the code exchange) and for one health check.
DUO_CALL_TIMEOUT_S = 10.0
HEALTH_TIMEOUT_S = 15.0
#: (connect, read) timeout on every HTTP request the Duo SDK makes.
DUO_HTTP_TIMEOUT: Tuple[float, float] = (5.0, 10.0)
#: Re-check Duo's health this often while it passes, and this often while it fails.
HEALTH_INTERVAL_S = 300.0
HEALTH_RETRY_S = 60.0
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
# Per-username rate state, least recently used first (evicted one at a time).
_starts: "OrderedDict[str, Deque[float]]" = OrderedDict()
_rate_refusal_logged: "OrderedDict[str, float]" = OrderedDict()


# --------------------------------------------------------------------------- the Duo client
def duo_ca_bundle() -> Optional[str]:
    """The CA bundle Duo's TLS is verified against, or None to keep
    duo_universal's own pinned bundle.

    The same setting every other outbound client reads (requests' own order):
    ``REQUESTS_CA_BUNDLE``, else ``CURL_CA_BUNDLE``; ``backend.config`` points
    both at the checkout's ``ca-bundle.pem`` when it exists. Only a path to an
    existing file counts: with none, Duo stays pinned."""
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        path = (os.environ.get(name) or "").strip()
        if path:
            return path if os.path.isfile(path) else None
    return None


def duo_tls_trust() -> str:
    """What Duo's certificate is checked against, for logs and the docs."""
    return "the configured CA bundle" if duo_ca_bundle() else "duo_universal's pinned CA bundle"


class _TimedRequests:
    """``requests`` as duo_universal's module sees it: everything passes
    through, and ``post`` gets ``timeout=DUO_HTTP_TIMEOUT`` unless the call
    sets one. The SDK sets none and takes none, so this is the only way to put
    a timeout on its sockets; the bounded wait in ``_bounded`` stays as well."""

    def __init__(self, module: Any) -> None:
        self._module = module

    def post(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("timeout", DUO_HTTP_TIMEOUT)
        return self._module.post(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._module, name)


_sdk_patch_lock = threading.Lock()


def _install_sdk_timeout() -> None:
    """Give duo_universal's HTTP calls a timeout (idempotent)."""
    from duo_universal import client as sdk

    with _sdk_patch_lock:
        if not isinstance(sdk.requests, _TimedRequests):
            sdk.requests = _TimedRequests(sdk.requests)


def _default_client_factory(*, client_id: str, client_secret: str, host: str, redirect_uri: str,
                            duo_certs: Optional[str] = None) -> Any:
    from duo_universal import Client  # lazy: never imported unless Duo sign-in is configured

    _install_sdk_timeout()
    # duo_certs=None keeps the SDK's pinned bundle; a path verifies against it.
    return Client(client_id, client_secret, host, redirect_uri, duo_certs=duo_certs)


_client_factory: Callable[..., Any] = _default_client_factory
_client_cache: Optional[Tuple[tuple, Any]] = None


def set_client_factory(factory: Optional[Callable[..., Any]] = None) -> None:
    """Replace how the Duo client is built (tests pass a fake). ``None``
    restores ``duo_universal.Client``. Drops the cached client. The factory is
    called with ``client_id``, ``client_secret``, ``host``, ``redirect_uri``
    and ``duo_certs`` (``duo_ca_bundle()``)."""
    global _client_factory, _client_cache
    with _lock:
        _client_factory = factory or _default_client_factory
        _client_cache = None


def _client() -> Any:
    """The Duo client for the current settings (built once per configuration).
    The redirect URI is ``settings.duo_redirect_uri`` and nothing else."""
    global _client_cache
    key = (settings.duo_client_id, settings.duo_client_secret, settings.duo_api_host,
           settings.duo_redirect_uri, duo_ca_bundle())
    with _lock:
        if _client_cache is not None and _client_cache[0] == key:
            return _client_cache[1]
        factory = _client_factory
    client = factory(client_id=key[0], client_secret=key[1], host=key[2], redirect_uri=key[3],
                     duo_certs=key[4])
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
    """The ``duo_signin`` host gate: the single rule ``begin()`` (``POST
    /auth/duo/start``), the sign-in page's button and the chat page's
    "Sign in with Duo" link read. The callback does not (``complete()``)."""
    from backend import host_capabilities

    return host_capabilities.duo_signin_gate(settings)


class _DuoTimeout(Exception):
    """A Duo call did not answer within its deadline."""


class _DuoBusy(_DuoTimeout):
    """The previous call of this kind is still waiting for Duo; none started."""


def _release_once(release: Callable[[], None]) -> Callable[[], bool]:
    """``release`` wrapped so that only its first call does anything."""
    lock = threading.Lock()
    done = [False]

    def once() -> bool:
        with lock:
            if done[0]:
                return False
            done[0] = True
        release()
        return True

    return once


def _bounded(fn: Callable[..., Any], *args: Any, timeout: float,
             exclusive: Optional[threading.Lock] = None) -> Any:
    """Run one Duo call on a daemon thread and wait at most ``timeout`` for it.

    One deadline covers both the wait for a free slot and the call itself. A
    Python thread cannot be cancelled, so a call that overruns is abandoned on
    its (daemon) thread, and its slot is given back right there at the
    deadline: whichever comes first, the call ending or the deadline, releases
    the slot, exactly once. So a call that never returns holds no slot past
    its deadline, and daemon threads never block process exit. The SDK's
    sockets have ``DUO_HTTP_TIMEOUT`` too, so an abandoned call does end.

    ``exclusive``: a lock held for as long as the call runs (past an
    abandonment too). When it is already held, nothing starts and
    ``_DuoBusy`` is raised: the periodic health check never stacks a second
    call behind one that is still waiting for Duo."""
    deadline = time.monotonic() + timeout
    if exclusive is not None and not exclusive.acquire(blocking=False):
        raise _DuoBusy()
    if not _duo_slots.acquire(timeout=timeout):
        if exclusive is not None:
            exclusive.release()
        raise _DuoTimeout()
    give_back = _release_once(_duo_slots.release)
    box: Dict[str, Any] = {}
    done = threading.Event()

    def _run() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = exc
        finally:
            give_back()
            if exclusive is not None:
                exclusive.release()
            done.set()

    try:
        threading.Thread(target=_run, name="duo-call", daemon=True).start()
    except BaseException:
        give_back()
        if exclusive is not None:
            exclusive.release()
        raise
    if not done.wait(max(0.0, deadline - time.monotonic())):
        give_back()          # the slot comes back now; the call is abandoned on its thread
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
# Held while a health-check call is running (past its deadline too), so the
# timer never starts a second call while one is still waiting for Duo.
_health_call = threading.Lock()
# The running checker and its own stop event (a new pair per start, so a
# checker that is still finishing a call after a stop never runs on).
_health_stop: Optional[threading.Event] = None
_health_thread: Optional[threading.Thread] = None


def run_health_check() -> bool:
    """Call Duo's health check (bounded) and record the result for the
    ``duo_signin`` gate, which closes only after
    ``host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE`` failures in a row.
    Never raises. Returns whether it passed."""
    from backend import host_capabilities

    try:
        _bounded(_client().health_check, timeout=HEALTH_TIMEOUT_S, exclusive=_health_call)
    except _DuoBusy:
        detail = "the previous health check is still waiting for Duo"
    except _DuoTimeout:
        detail = f"no answer within {HEALTH_TIMEOUT_S:.0f} s"
    except ImportError:
        detail = "duo_universal is not installed (pip install -r requirements.txt)"
    except Exception as exc:  # noqa: BLE001 - a failed check counts toward closing the gate, never the app
        detail = describe_failure(exc)
    else:
        if not host_capabilities.duo_signin_gate().get("enabled"):
            logger.info("Duo health check passed (TLS checked against %s); Duo sign-in is available",
                        duo_tls_trust())
        host_capabilities.record_duo_health(True)
        return True
    failures = host_capabilities.record_duo_health(False, detail)
    logger.warning("Duo health check failed (%d in a row; Duo sign-in closes at %d): %s",
                   failures, host_capabilities.DUO_HEALTH_FAILURES_TO_CLOSE, detail)
    return False


def _health_loop(stop: threading.Event) -> None:
    """Check now, then every ``HEALTH_INTERVAL_S`` while it passes and every
    ``HEALTH_RETRY_S`` while it fails, until stopped or no longer configured."""
    while not stop.is_set() and configured():
        passed = run_health_check()
        if stop.wait(HEALTH_INTERVAL_S if passed else HEALTH_RETRY_S):
            return


def start_health_check() -> Optional[threading.Thread]:
    """Start the periodic health check on a daemon thread (startup; never the
    event loop). Idempotent: a running checker is returned as is. Does
    nothing, and builds no client, unless Duo sign-in is configured: the
    gate's earlier reasons already explain why it is closed."""
    global _health_thread, _health_stop
    if not configured():
        return None
    with _lock:
        if _health_thread is not None and _health_thread.is_alive():
            return _health_thread
        stop = threading.Event()
        thread = threading.Thread(target=_health_loop, args=(stop,), name="duo-health-check", daemon=True)
        _health_stop, _health_thread = stop, thread
        thread.start()
        return thread


def stop_health_check(timeout: float = 2.0) -> None:
    """Stop the periodic health check (shutdown, tests). A check in flight is
    left to its deadline; the loop just does not go round again."""
    global _health_thread, _health_stop
    with _lock:
        thread, stop = _health_thread, _health_stop
        _health_thread = _health_stop = None
    if stop is not None:
        stop.set()
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout)


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
    whether a refusal should be audited (only the first in each window).

    Called only for allowlisted names. Both tables are bounded by
    ``_RATE_KEYS_MAX`` and evict the least recently used name, one at a time:
    never all at once, so filling the table cannot reset anyone's budget."""
    now = time.monotonic()
    with _lock:
        starts = _starts.get(username)
        if starts is None:
            while len(_starts) >= _RATE_KEYS_MAX:
                _starts.popitem(last=False)
            starts = _starts[username] = deque()
        else:
            _starts.move_to_end(username)
        while starts and now - starts[0] > RATE_LIMIT_WINDOW_S:
            starts.popleft()
        if len(starts) < RATE_LIMIT_STARTS:
            starts.append(now)
            return True, True
        logged = _rate_refusal_logged.get(username)
        first = logged is None or now - logged > RATE_LIMIT_WINDOW_S
        if first:
            _rate_refusal_logged[username] = now
            _rate_refusal_logged.move_to_end(username)
            while len(_rate_refusal_logged) > _RATE_KEYS_MAX:
                _rate_refusal_logged.popitem(last=False)
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
    # The allowlist first: a name that is not on it never takes a rate slot.
    if name not in settings.identity_allowed_users_set:
        raise SigninError(NOT_ALLOWED, name)
    allowed, audit = _take_rate_slot(name)
    if not allowed:
        raise SigninError(RATE_LIMITED, name, audit=audit)
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
    in the callback's query.

    Not gated: a sign-in started while the ``duo_signin`` gate was open
    finishes here even if the gate has closed since. The code exchange is
    attempted and a Duo failure maps to a fixed code (``duo_unavailable``,
    ``duo_refused``, ...). Only Duo sign-in being off (``configured()``)
    refuses it up front, unaudited, so Labs 0-4 never write an identity event."""
    if not configured():
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
    # The code is a credential until it is exchanged. It is never logged here,
    # and backend.logging.redaction drops it by pattern wherever it travels as
    # duo_code= / code= (never by registering it: the code is the caller's
    # input, and registering it would let a caller blank any string out of
    # every later log line).
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
