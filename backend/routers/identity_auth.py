"""Duo Universal Prompt sign-in routes (Lab 5, plan 12.1).

Every route stays behind the room access key (no ``PUBLIC_PATHS`` change): the
key is still the outer trust boundary, and Duo's redirect back to the callback
is a top-level navigation that carries the room-key cookie (``SameSite=Lax``).
The identity middleware never refuses these paths for an expired or revoked
identity cookie (``REDIRECT_EXEMPT``), so a user can always sign in again.

- ``GET /login/duo`` - the sign-in page (frontend/login-duo.html). It first
  redirects to the canonical ``PUBLIC_BASE_URL`` host: the state cookie, Duo's
  redirect and the identity cookie all live on that one host. The Continue
  button greys out from the ``duo_signin`` gate, rendered into the page here
  (a page fetch of ``/api/server-info`` would be refused for a revoked cookie).
  So is the browser's session: signed in as whom, or a revoked tombstone. A
  tombstone sends every other page here (``?revoked=1``), and Duo refuses to
  sign a disabled account in again, so for one the page names the ended
  session, offers Sign out, and turns "Continue without signing in" into a
  sign-out that continues to ``/app`` (a plain link there would come straight
  back).
- ``POST /auth/duo/start`` - username in, 303 to Duo's prompt out, with the
  single-use state bound to this browser by a ``Secure; HttpOnly;
  SameSite=Lax; Path=/auth/duo/`` cookie.
- ``GET /auth/duo/callback`` - Duo's redirect. The state must equal the
  cookie's; the username is the pending sign-in's, never the query's. Sets the
  identity cookie and goes to ``/app?signin=ok``. Every failure is a 303 to
  ``/login/duo?error=<fixed code>``; no exception reaches the error page, so
  ``DEBUG=True`` never renders a traceback here. The query (Duo's ``duo_code``)
  is kept out of telemetry and logs: ``run.sh`` appends this path to
  ``OTEL_PYTHON_EXCLUDED_URLS`` and the uvicorn access log redacts its query
  (``log_handlers.install_access_log_redaction``).
- ``POST /auth/identity/logout`` - ends the identity session (tombstone
  included), deletes the cookie and goes to ``/login/duo?signed_out=1``, or to
  ``/app`` when the form's ``next`` is exactly ``/app`` (never another target).
  ``GET /logout`` (the room-key sign-out) ends it too.
- ``GET /api/identity/me`` - who this browser is signed in as, the Unblock me
  override, and the latest Duo / Identity Intelligence status and gate verdict.
  A plain ``def`` route, so it runs in the threadpool; the chat page polls it
  every 10 s. A revoked session reaches it as a tombstone (``revoked: true``);
  an expired one answers the middleware's 401.
- ``POST /api/identity/unblock`` / ``POST /api/identity/reblock`` - Unblock me
  on and off (plan 12.1). They reach a revoked session too; never Duo or CII.

Routes that touch the store or Duo are plain ``def`` routes, so they run in the
threadpool, never on the event loop.
"""
from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from backend.config import settings
from backend.middleware.identity import (
    COOKIE_NAME,
    LOGIN_PATH,
    current_identity,
    delete_identity_cookie,
    revoked_identity,
    set_identity_cookie,
)
from backend.services import identity_gate, identity_lookup, identity_signin, identity_store
from backend.services.identity_signin import SigninError

logger = logging.getLogger(__name__)
router = APIRouter()

_LOGIN_DUO_HTML = Path(__file__).parent.parent.parent / "frontend" / "login-duo.html"

#: The state cookie: binds a started sign-in to the browser that started it.
#: ``__Secure-`` (Secure required) rather than ``__Host-``, which would force
#: ``Path=/``; the path keeps it off every request but the two sign-in routes.
STATE_COOKIE = "__Secure-pseudoco_assistant_duo_state"
STATE_COOKIE_PATH = "/auth/duo/"
_STATE_COOKIE_ATTRS = {"path": STATE_COOKIE_PATH, "secure": True, "httponly": True, "samesite": "lax"}

CALLBACK_PATH = "/auth/duo/callback"
SIGNED_IN_REDIRECT = "/app?signin=ok"
#: The one place sign-out may continue to besides the sign-in page (the
#: sign-in page's "Continue without signing in" for a revoked session). The
#: form's ``next`` must equal it exactly; any other value is ignored.
SIGNED_OUT_CONTINUE = "/app"
#: Notices the sign-in page shows besides an error code (?expired=1 etc.).
NOTICE_FLAGS = ("expired", "revoked", "signed_out")
_NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


# --------------------------------------------------------------------------- helpers
def _client_address(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _host(netloc: str) -> str:
    """``host[:port]`` lowercased, without a default https port."""
    value = (netloc or "").strip().lower()
    return value[:-4] if value.endswith(":443") else value


def _canonical_host() -> str:
    return _host(urlsplit(settings.public_base_origin).netloc) if settings.public_base_origin else ""


def _canonical_redirect(request: Request) -> Optional[str]:
    """The canonical sign-in page URL when this request reached another host
    (an IP, http://localhost, a second tunnel name), else None. The target is
    always ``PUBLIC_BASE_URL``; the request's Host is only compared, never used."""
    canonical = _canonical_host()
    if not (getattr(settings, "duo_enabled", False) and canonical):
        return None
    if _host(request.headers.get("host", "")) == canonical:
        return None
    query: Dict[str, str] = {}
    error = request.query_params.get("error")
    if error in identity_signin.ERROR_CODES:
        query["error"] = error
    for flag in NOTICE_FLAGS:
        if request.query_params.get(flag) == "1":
            query[flag] = "1"
    return settings.public_base_origin + LOGIN_PATH + (f"?{urlencode(query)}" if query else "")


def _cross_site(request: Request) -> bool:
    """True for a POST another site's page sent (an ``Origin`` that is neither
    this instance's canonical host nor the host the request was sent to). A
    missing ``Origin`` passes: browsers send it on every cross-site POST."""
    origin = request.headers.get("origin")
    if not origin:
        return False
    if origin.strip().lower() == "null":
        return True
    allowed = {h for h in (_canonical_host(), _host(request.headers.get("host", ""))) if h}
    return _host(urlsplit(origin.strip()).netloc) not in allowed


def _to_login(*, error: Optional[str] = None, notice: Optional[str] = None,
              clear_state: bool = False) -> RedirectResponse:
    query = {}
    if error:
        query["error"] = error if error in identity_signin.ERROR_CODES else identity_signin.FAILED
    if notice in NOTICE_FLAGS:
        query[notice] = "1"
    response = RedirectResponse(LOGIN_PATH + (f"?{urlencode(query)}" if query else ""),
                                status_code=303, headers=_NO_STORE)
    if clear_state:
        delete_state_cookie(response)
    return response


def set_state_cookie(response, state: str) -> None:
    response.set_cookie(STATE_COOKIE, state, max_age=int(identity_signin.STATE_TTL_S), **_STATE_COOKIE_ATTRS)


def delete_state_cookie(response) -> None:
    response.delete_cookie(STATE_COOKIE, **_STATE_COOKIE_ATTRS)


def _render_login(request: Request) -> str:
    gate = identity_signin.gate()
    identity = current_identity(request)
    revoked = revoked_identity(request) if identity is None else None
    text = _LOGIN_DUO_HTML.read_text() if _LOGIN_DUO_HTML.exists() else "<h1>Sign-in page not found</h1>"
    enabled = bool(gate.get("enabled"))
    values = {
        "__DUO_SIGNIN_STATE__": "enabled" if enabled else "disabled",
        "__DUO_SIGNIN_DISABLED__": "" if enabled else "disabled",
        "__DUO_SIGNIN_REASON__": html.escape(gate.get("reason") or "", quote=True),
        "__SIGNED_IN_AS__": html.escape(identity.username if identity is not None else "", quote=True),
        "__REVOKED_AS__": html.escape(revoked.username if revoked is not None else "", quote=True),
    }
    for placeholder, value in values.items():
        text = text.replace(placeholder, value)
    return text


# --------------------------------------------------------------------------- routes
@router.get(LOGIN_PATH, response_class=HTMLResponse)
def login_duo_page(request: Request):
    """The Duo sign-in page, on the canonical host."""
    target = _canonical_redirect(request)
    if target:
        return RedirectResponse(target, status_code=303, headers=_NO_STORE)
    return HTMLResponse(_render_login(request), headers=_NO_STORE)


@router.post("/auth/duo/start")
def duo_start(request: Request, username: str = Form("")):
    """Start a Duo sign-in for one username; 303 to Duo's Universal Prompt."""
    target = _canonical_redirect(request)
    if target:
        return RedirectResponse(target, status_code=303, headers=_NO_STORE)
    client = _client_address(request)
    try:
        if _cross_site(request):
            raise SigninError(identity_signin.BAD_ORIGIN,
                              identity_store.normalize_username(username)[:129] or None)
        url, state = identity_signin.begin(username, client_address=client)
    except SigninError as err:
        identity_signin.record_failure(err, client_address=client)
        return _to_login(error=err.code)
    except Exception as exc:  # noqa: BLE001 - never a traceback page
        logger.warning("Duo sign-in start failed (%s)", type(exc).__name__)
        return _to_login(error=identity_signin.FAILED)
    response = RedirectResponse(url, status_code=303, headers=_NO_STORE)
    set_state_cookie(response, state)
    return response


@router.get(CALLBACK_PATH)
def duo_callback(request: Request):
    """Duo's redirect after the Universal Prompt: exchange the code, sign in."""
    client = _client_address(request)
    query = request.query_params
    try:
        token, snapshot = identity_signin.complete(
            state=query.get("state"),
            state_cookie=request.cookies.get(STATE_COOKIE),
            duo_code=query.get("duo_code"),
            duo_error=query.get("error"),
            client_address=client,
            user_agent=request.headers.get("user-agent"),
        )
    except SigninError as err:
        identity_signin.record_failure(err, client_address=client)
        return _to_login(error=err.code, clear_state=True)
    except Exception as exc:  # noqa: BLE001 - never a traceback page
        logger.warning("Duo sign-in callback failed (%s)", type(exc).__name__)
        return _to_login(error=identity_signin.FAILED, clear_state=True)
    previous = request.cookies.get(COOKIE_NAME)
    if previous:
        try:   # the cookie is about to be replaced: end the session (or tombstone) behind it
            identity_store.end(previous)
        except Exception:  # noqa: BLE001
            logger.debug("previous identity session could not be ended", exc_info=True)
    logger.info("Duo sign-in for %s (session %s)", snapshot.username, snapshot.session_ref)
    response = RedirectResponse(SIGNED_IN_REDIRECT, status_code=303, headers=_NO_STORE)
    set_identity_cookie(response, token)
    delete_state_cookie(response)
    return response


@router.post("/auth/identity/logout")
def identity_logout(request: Request, next_path: str = Form("", alias="next")):
    """Sign out of the identity session (a revoked tombstone included). Goes to
    the sign-in page, or to ``/app`` when ``next`` is exactly that."""
    if _cross_site(request):
        return JSONResponse({"detail": "cross-site sign-out refused"}, status_code=403, headers=_NO_STORE)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        try:
            identity_store.end(token)
        except Exception:  # noqa: BLE001 - sign-out never fails; the cookie goes regardless
            logger.warning("identity session could not be ended at sign-out", exc_info=True)
    if next_path == SIGNED_OUT_CONTINUE:
        response = RedirectResponse(SIGNED_OUT_CONTINUE, status_code=303, headers=_NO_STORE)
    else:
        response = _to_login(notice="signed_out")
    delete_identity_cookie(response)
    return response


@router.get("/api/identity/me")
def identity_me(request: Request):
    """The verified identity of this browser, or ``{"signed_in": false}``.
    Never the cookie or anything derived from it.

    Signed in, it also carries what the badge and banner show: the Unblock me
    ``override``, the latest Duo status / CII trust level / failing checks
    (``identity_lookup``, cached; ``identity_check`` "unavailable" when either
    could not answer) and the gate's ``verdict`` for the next turn. A revoked
    session (the middleware lets it reach this path only as a tombstone)
    answers ``{"signed_in": false, "revoked": true, "username", "revoked_reason"}``
    so the banner can say whose session ended and offer Unblock me."""
    identity = current_identity(request)
    headers = {"Cache-Control": "no-store"}
    if identity is None:
        revoked = revoked_identity(request)
        if revoked is not None:
            result = identity_store.status(revoked.session_ref)
            return JSONResponse({
                "signed_in": False, "revoked": True, "username": revoked.username,
                "revoked_reason": result.revoked_reason if result is not None else None,
                "can_unblock": True,
            }, headers=headers)
        return JSONResponse({"signed_in": False}, headers=headers)
    status = identity_lookup.lookup(identity.username)
    verdict = identity_gate.decide(status, fail_open=bool(getattr(settings, "identity_fail_open", True)))
    return JSONResponse({
        "signed_in": True,
        "username": identity.username,
        "source": identity.source,
        "signed_in_at": identity.created_at.isoformat(),
        "expires_at": identity.expires_at.isoformat(),
        "override": identity.overridden,
        "unblocked_at": identity.unblocked_at.isoformat() if identity.unblocked_at else None,
        "duo_status": verdict["duo_status"],
        "trust_level": verdict["trust_level"],
        "failing_checks": verdict["failing_checks"],
        "identity_check": verdict["check"],
        "verdict": verdict["verdict"],
        "reasons": verdict["reasons"],
        "reasons_text": identity_gate.reasons_text(verdict),
    }, headers=headers)


def _override_identity(request: Request):
    """The session Unblock me acts on: the verified one, or a tombstone."""
    return current_identity(request) or revoked_identity(request)


def _override_response(snapshot, *, next_path: str) -> object:
    if next_path == SIGNED_OUT_CONTINUE:
        return RedirectResponse(SIGNED_OUT_CONTINUE, status_code=303, headers=_NO_STORE)
    return JSONResponse({"ok": True, "username": snapshot.username, "override": snapshot.overridden},
                        headers=_NO_STORE)


def _override_refusal(request: Request) -> Optional[JSONResponse]:
    if not getattr(settings, "duo_enabled", False):
        return JSONResponse({"detail": "Not Found"}, status_code=404, headers=_NO_STORE)
    if _cross_site(request):
        return JSONResponse({"detail": "cross-site request refused"}, status_code=403, headers=_NO_STORE)
    if _override_identity(request) is None:
        return JSONResponse({"detail": "identity_not_signed_in"}, status_code=401, headers=_NO_STORE)
    return None


@router.post("/api/identity/unblock")
def identity_unblock(request: Request, next_path: str = Form("", alias="next")):
    """Unblock me (plan 12.1): let this identity session's turns through the
    Identity Risk Gate, and bring a revoked session back. Every later event
    of the session carries ``identity_override=true`` beside the real verdict;
    writes ``identity_unblocked``. Never touches Duo or Identity Intelligence:
    a disabled account stays disabled. Only bringing a Duo-revoked session back
    keeps the revocation pull off it; an override turned on before Duo
    disables the account does not, so that disable still ends the session
    (and this brings it back). Answers JSON, or 303 ``/app`` for the sign-in
    page's form (``next=/app``, nothing else)."""
    refusal = _override_refusal(request)
    if refusal is not None:
        return refusal
    snapshot = identity_store.unblock(_override_identity(request).session_ref,
                                      client_address=_client_address(request))
    if snapshot is None:
        return JSONResponse({"detail": "identity_session_expired"}, status_code=401, headers=_NO_STORE)
    logger.info("Unblock me on for %s (session %s)", snapshot.username, snapshot.session_ref)
    return _override_response(snapshot, next_path=next_path)


@router.post("/api/identity/reblock")
def identity_reblock(request: Request, next_path: str = Form("", alias="next")):
    """Unblock me off: the next turn is gated again (and a Duo-disabled
    account's session is revoked again on its next request). Writes
    ``identity_reblocked`` when the override was on."""
    refusal = _override_refusal(request)
    if refusal is not None:
        return refusal
    snapshot = identity_store.reblock(_override_identity(request).session_ref,
                                      client_address=_client_address(request))
    if snapshot is None:
        return JSONResponse({"detail": "identity_session_expired"}, status_code=401, headers=_NO_STORE)
    logger.info("Unblock me off for %s (session %s)", snapshot.username, snapshot.session_ref)
    return _override_response(snapshot, next_path=next_path)
