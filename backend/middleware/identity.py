"""Identity middleware (Lab 5): resolve the Duo sign-in cookie on every request.

Pure ASGI rather than ``BaseHTTPMiddleware``, because it sits on the SSE path
(``/api/chat/message/stream``) and must not buffer or wrap streaming bodies.
Registered INSIDE the access-key gate (backend/main.py), so the room key is
still the outer trust boundary and an unauthenticated caller gets its 401 first:

    RequestLogging -> AccessKey -> Identity -> ChatBodyLimit -> CORS -> app

Behaviour, only while ``DUO_ENABLED`` is on (off, the cookie is not even read):

- no cookie: the request passes untouched (anonymous, as in Labs 0-4);
- a valid session: ``request.state.identity`` is set to a frozen
  ``IdentitySnapshot`` (never the cookie or its hash);
- expired, or a cookie the store does not know: the cookie is deleted and the
  request answered 401 ``identity_session_expired`` (API) or 303 to
  ``/login/duo?expired=1`` (a browser page);
- revoked: the session is a tombstone, and every request answers 403
  ``identity_session_revoked`` (API) or 303 to ``/login/duo?revoked=1``, cookie
  kept, until the user signs in again, signs out, or turns Unblock me on;
- the revocation pull (plan 12.1, A4): on a valid session's request, Duo's
  status for the user (``identity_lookup.duo_user``, 10 s cache, off the event
  loop) is checked, and ``disabled`` revokes the session there and then (a
  tombstone and an ``identity_session_revoked`` audit event), Unblock me or
  not: a disabled account ends the session, and Unblock me can bring it back.
  Only a session Unblock me brought back from that revocation is left alone,
  while Duo keeps the account disabled (``holds_open``; once Duo enables it
  again, ``identity_store.rearm``). Locked out only blocks turns (the gate),
  and nothing happens without the Admin API keys or when Duo cannot be
  reached;
- no response here ever carries ``WWW-Authenticate: Basic`` (that would pop the
  browser's Basic-auth dialog over the room-key gate's).

Three identity API paths reach a tombstone too (``TOMBSTONE_PATHS``:
``GET /api/identity/me``, ``POST /api/identity/unblock`` and
``POST /api/identity/reblock``), again only as ``identity_revoked``: the chat
page's banner learns whose session ended and why, and Unblock me can bring it
back. Without that, a revoked session could never be unblocked.

The sign-in, sign-out and public paths are never refused (``REDIRECT_EXEMPT``),
or an expired or revoked cookie would loop between the two gates. Static assets
and the health check are not even looked up. On those paths a revoked cookie's
session goes on ``request.state.identity_revoked`` (``revoked_identity``),
never on ``request.state.identity``: it is not an identity, and only the sign-in
page reads it, to say whose session ended and to offer Sign out. Without that,
a browser holding a tombstone would land on a sign-in page with no way out but
a Duo sign-in, which Duo refuses once it has disabled the account.

Store calls run in the threadpool: the app is one uvicorn process, so a slow
lookup on the event loop would stall every other request, SSE streams included.

The cookie is set and deleted only through ``set_identity_cookie`` /
``delete_identity_cookie`` (``Secure; HttpOnly; SameSite=Lax; Path=/``). A
browser refuses a ``__Host-`` cookie, including its deletion, without
``Secure`` and ``Path=/`` (and with a ``Domain``), and a deletion it refused
would leave a redirect loop.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, List, Optional, Tuple

from starlette.concurrency import run_in_threadpool
from starlette.requests import cookie_parser
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.config import settings
from backend.middleware.access_key import PUBLIC_PATHS
from backend.services import identity_lookup, identity_store

#: The identity cookie. ``__Host-``: Secure, Path=/, no Domain, host-only.
COOKIE_NAME = "__Host-pseudoco_assistant_identity"
_COOKIE_ATTRS = {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}

EXPIRED_DETAIL = "identity_session_expired"
REVOKED_DETAIL = "identity_session_revoked"
LOGIN_PATH = "/login/duo"

#: ``request.state`` keys only this middleware sets (both dropped on entry).
#: ``identity`` is the verified identity; ``identity_revoked`` is a tombstone's
#: session, set only on the paths a revoked cookie is let through to.
STATE_IDENTITY = "identity"
STATE_REVOKED = "identity_revoked"

# Never refused for an expired / revoked cookie: the sign-in and sign-out
# routes, plus everything the room-key gate itself serves without a key
# (/login, /favicon.ico, /health), which would otherwise bounce between gates.
REDIRECT_EXEMPT_PATHS = frozenset({LOGIN_PATH, "/auth/identity/logout", "/logout"} | set(PUBLIC_PATHS))
REDIRECT_EXEMPT_PREFIXES: Tuple[str, ...] = ("/auth/duo/", "/static/")
# Reached by a revoked session (as ``identity_revoked``, never as an identity):
# the banner's status poll and the Unblock me toggle.
TOMBSTONE_PATHS = frozenset({"/api/identity/me", "/api/identity/unblock", "/api/identity/reblock"})
#: The revocation reason of a session Duo disabled.
DUO_DISABLED_REASON = "duo_disabled"
# Not even looked up: no identity is ever needed to serve these.
PASSTHROUGH_PATHS = frozenset({"/health", "/favicon.ico"})
PASSTHROUGH_PREFIXES: Tuple[str, ...] = ("/static/",)


# --------------------------------------------------------------------------- cookie helper
def set_identity_cookie(response: Response, token: str, *, max_age: Optional[int] = None) -> None:
    """Set the identity cookie on a response (the one place it is set)."""
    if max_age is None:
        max_age = identity_store.ttl_minutes() * 60
    response.set_cookie(COOKIE_NAME, token, max_age=max_age, **_COOKIE_ATTRS)


def delete_identity_cookie(response: Response) -> None:
    """Delete the identity cookie, with the attributes a ``__Host-`` cookie needs."""
    response.delete_cookie(COOKIE_NAME, **_COOKIE_ATTRS)


def deletion_header() -> Tuple[bytes, bytes]:
    """The raw ``Set-Cookie`` header ``delete_identity_cookie`` writes."""
    probe = Response()
    delete_identity_cookie(probe)
    return next((k, v) for k, v in probe.raw_headers if k == b"set-cookie")


# --------------------------------------------------------------------------- request helpers
def _state_snapshot(request: Any, key: str) -> Optional[identity_store.IdentitySnapshot]:
    state = getattr(request, "state", None)
    value = getattr(state, key, None) if state is not None else None
    return value if isinstance(value, identity_store.IdentitySnapshot) else None


def current_identity(request: Any) -> Optional[identity_store.IdentitySnapshot]:
    """The request's verified identity, or None. Only the middleware sets it,
    and only a real snapshot counts."""
    return _state_snapshot(request, STATE_IDENTITY)


def revoked_identity(request: Any) -> Optional[identity_store.IdentitySnapshot]:
    """The revoked session (tombstone) behind this browser's cookie, or None.

    Set only on the paths a revoked cookie is let through to (``REDIRECT_EXEMPT``:
    the sign-in and sign-out routes); everywhere else that cookie is refused.
    Never a verified identity: nothing may attribute a turn, own a conversation
    or pass it to the chain. The sign-in page reads it to offer Sign out."""
    return _state_snapshot(request, STATE_REVOKED)


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers") or ():
        if key == name:
            return value.decode("latin-1")
    return ""


def _identity_cookie(scope: Scope) -> str:
    raw = _header(scope, b"cookie")
    return cookie_parser(raw).get(COOKIE_NAME, "") if raw else ""


def _wants_html(scope: Scope) -> bool:
    return "text/html" in _header(scope, b"accept")


def _in(path: str, paths: Iterable[str], prefixes: Tuple[str, ...]) -> bool:
    return path in paths or path.startswith(prefixes)


async def _respond(send: Send, status: int, headers: List[Tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-length", str(len(body)).encode("ascii")),
                            (b"cache-control", b"no-store"), *headers]})
    await send({"type": "http.response.body", "body": body})


async def _refuse(scope: Scope, send: Send, detail: str, *, status: int, delete_cookie: bool) -> None:
    headers: List[Tuple[bytes, bytes]] = [deletion_header()] if delete_cookie else []
    if _wants_html(scope):
        flag = "expired" if detail == EXPIRED_DETAIL else "revoked"
        headers.append((b"location", f"{LOGIN_PATH}?{flag}=1".encode("ascii")))
        await _respond(send, 303, headers, b"")
        return
    headers.append((b"content-type", b"application/json"))
    await _respond(send, status, headers, json.dumps({"detail": detail}).encode("utf-8"))


# --------------------------------------------------------------------------- revocation pull
def pull_revocation(identity: Optional[identity_store.IdentitySnapshot]) -> bool:
    """Revoke a valid session whose Duo account is now ``disabled`` (A4).

    Blocking (a cached Duo Admin API read), so the middleware runs it in the
    threadpool. Returns True when it revoked. Never raises: a lookup that
    cannot answer leaves the session as it is (the gate decides turns).

    An Unblock me override does not stop it (plan 12.1: a disabled account
    ends the session, and Unblock me brings it back), unless the override is
    what brought this session back from a Duo disable (``holds_open``). That
    session stays while Duo keeps the account disabled; once Duo answers that
    the account is enabled again, ``identity_store.rearm`` forgets the
    revocation it cleared, so a new disable ends the session again."""
    if identity is None or not identity_lookup.duo_configured():
        return False
    try:
        answer = identity_lookup.duo_user(identity.username)
        disabled = answer.get("duo_status") == "disabled"
        if identity.holds_open(DUO_DISABLED_REASON):
            if answer.get("state") == identity_lookup.OK and not disabled:
                identity_store.rearm(identity.session_ref)
            return False
        if not disabled:
            return False
        identity_store.revoke(identity.session_ref, reason=DUO_DISABLED_REASON, actor="duo")
        return True
    except Exception:  # noqa: BLE001 - a failed pull never fails the request
        return False


# --------------------------------------------------------------------------- middleware
class IdentityMiddleware:
    """Resolve the identity cookie; see the module docstring."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = scope.get("state")
        if isinstance(state, dict):
            # Only this middleware may set these; drop anything already there.
            state.pop(STATE_IDENTITY, None)
            state.pop(STATE_REVOKED, None)
        path = scope.get("path") or ""
        if not getattr(settings, "duo_enabled", False) or _in(path, PASSTHROUGH_PATHS, PASSTHROUGH_PREFIXES):
            await self.app(scope, receive, send)
            return
        token = _identity_cookie(scope)
        if not token:
            await self.app(scope, receive, send)
            return

        result = await run_in_threadpool(identity_store.lookup, token)
        if result.valid and await run_in_threadpool(pull_revocation, result.identity):
            result = identity_store.LookupResult(identity_store.REVOKED, result.identity, DUO_DISABLED_REASON)
        if result.valid:
            scope.setdefault("state", {})[STATE_IDENTITY] = result.identity
            await self.app(scope, receive, send)
            return
        if (path in TOMBSTONE_PATHS and result.status == identity_store.REVOKED
                and result.identity is not None):
            scope.setdefault("state", {})[STATE_REVOKED] = result.identity
            await self.app(scope, receive, send)
            return
        if _in(path, REDIRECT_EXEMPT_PATHS, REDIRECT_EXEMPT_PREFIXES):
            if result.status == identity_store.REVOKED and result.identity is not None:
                # Not an identity: the sign-in page's way out of the tombstone.
                scope.setdefault("state", {})[STATE_REVOKED] = result.identity
            await self.app(scope, receive, send)
            return
        if result.status == identity_store.REVOKED:
            await _refuse(scope, send, REVOKED_DETAIL, status=403, delete_cookie=False)
        else:   # expired, or unknown to the store: either way, sign in again
            await _refuse(scope, send, EXPIRED_DETAIL, status=401, delete_cookie=True)
