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
  kept, until the user signs in again or signs out;
- no response here ever carries ``WWW-Authenticate: Basic`` (that would pop the
  browser's Basic-auth dialog over the room-key gate's).

The sign-in, sign-out and public paths are never refused (``REDIRECT_EXEMPT``),
or an expired or revoked cookie would loop between the two gates. Static assets
and the health check are not even looked up.

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
from backend.services import identity_store

#: The identity cookie. ``__Host-``: Secure, Path=/, no Domain, host-only.
COOKIE_NAME = "__Host-pseudoco_assistant_identity"
_COOKIE_ATTRS = {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}

EXPIRED_DETAIL = "identity_session_expired"
REVOKED_DETAIL = "identity_session_revoked"
LOGIN_PATH = "/login/duo"

# Never refused for an expired / revoked cookie: the sign-in and sign-out
# routes, plus everything the room-key gate itself serves without a key
# (/login, /favicon.ico, /health), which would otherwise bounce between gates.
REDIRECT_EXEMPT_PATHS = frozenset({LOGIN_PATH, "/auth/identity/logout", "/logout"} | set(PUBLIC_PATHS))
REDIRECT_EXEMPT_PREFIXES: Tuple[str, ...] = ("/auth/duo/", "/static/")
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
def current_identity(request: Any) -> Optional[identity_store.IdentitySnapshot]:
    """The request's verified identity, or None. Only the middleware sets it,
    and only a real snapshot counts."""
    state = getattr(request, "state", None)
    identity = getattr(state, "identity", None) if state is not None else None
    return identity if isinstance(identity, identity_store.IdentitySnapshot) else None


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
            # Only this middleware may set it; drop anything already there.
            state.pop("identity", None)
        path = scope.get("path") or ""
        if not getattr(settings, "duo_enabled", False) or _in(path, PASSTHROUGH_PATHS, PASSTHROUGH_PREFIXES):
            await self.app(scope, receive, send)
            return
        token = _identity_cookie(scope)
        if not token:
            await self.app(scope, receive, send)
            return

        result = await run_in_threadpool(identity_store.lookup, token)
        if result.valid:
            scope.setdefault("state", {})["identity"] = result.identity
            await self.app(scope, receive, send)
            return
        if _in(path, REDIRECT_EXEMPT_PATHS, REDIRECT_EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return
        if result.status == identity_store.REVOKED:
            await _refuse(scope, send, REVOKED_DETAIL, status=403, delete_cookie=False)
        else:   # expired, or unknown to the store: either way, sign in again
            await _refuse(scope, send, EXPIRED_DETAIL, status=401, delete_cookie=True)
