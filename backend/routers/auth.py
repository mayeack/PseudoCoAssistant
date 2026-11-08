import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from backend.config import settings
from backend.middleware.access_key import COOKIE_NAME, keys_match, session_token
from backend.middleware import identity as identity_mw
from backend.middleware import settings_gate
from backend.services import identity_store

logger = logging.getLogger(__name__)
router = APIRouter()

_FRONTEND = Path(__file__).parent.parent.parent / "frontend"
_LOGIN_HTML = _FRONTEND / "login.html"
_SETTINGS_LOGIN_HTML = _FRONTEND / "settings-login.html"
_COOKIE_MAX_AGE = 60 * 60 * 12  # 12 hours


def _safe_next(next_path: str, default: str = "/app") -> str:
    """Only redirect to local paths — blocks open-redirect to other sites.

    Browsers read a backslash as a slash, so "/\\evil.example" is the same
    protocol-relative URL as "//evil.example"; control characters are refused
    for the same reason.
    """
    if (next_path and next_path.startswith("/") and not next_path.startswith("//")
            and "\\" not in next_path
            and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in next_path)):
        return next_path
    return default


@router.get("/login", response_class=HTMLResponse)
async def login_page():
    if _LOGIN_HTML.exists():
        return _LOGIN_HTML.read_text()
    return "<h1>Login page not found</h1>"


@router.post("/login")
async def login_submit(
    access_code: str = Form(""),
    next_path: str = Form("/app", alias="next"),
):
    target = _safe_next(next_path)
    if settings.access_key and keys_match(access_code, settings.access_key):
        response = RedirectResponse(url=target, status_code=303)
        response.set_cookie(
            COOKIE_NAME,
            session_token(),
            max_age=_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response
    logger.warning("Failed login attempt")
    return RedirectResponse(
        url=f"/login?error=1&next={quote(target, safe='')}", status_code=303
    )


#: ``Sec-Fetch-Site`` values of a navigation this origin (or the user, from the
#: address bar or a bookmark) started. Empty: a browser that sends no
#: Fetch Metadata.
_OWN_NAVIGATION = frozenset({"", "same-origin", "none"})


@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    # Lab 5: signing out of the room also ends the Duo identity session, if
    # this browser has one (a revoked tombstone included), but only on a
    # navigation the browser says this origin or the user started. A link on
    # another site (another lab instance included: same-site, not
    # same-origin) still signs the browser out of the room key, as it always
    # did, and leaves the identity session and any tombstone alone: POST
    # /auth/identity/logout refuses a cross-site sign-out for the same reason.
    # The store call is blocking database work, so it runs in the threadpool.
    token = request.cookies.get(identity_mw.COOKIE_NAME)
    own = request.headers.get("sec-fetch-site", "").strip().lower() in _OWN_NAVIGATION
    if token and own:
        try:
            await run_in_threadpool(identity_store.end, token)
        except Exception:  # noqa: BLE001 - sign-out never fails; the cookie goes regardless
            logger.warning("identity session could not be ended at /logout", exc_info=True)
        identity_mw.delete_identity_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Settings gate — a SECOND code, in front of /settings-ui only. Stacked on top
# of the app gate above (a visitor still needs the app's ACCESS_KEY to get
# here), so unlocking the app never unlocks Settings. See
# backend/middleware/settings_gate.py for why the code is hardcoded.
# ---------------------------------------------------------------------------

@router.get("/settings-login", response_class=HTMLResponse)
async def settings_login_page():
    if _SETTINGS_LOGIN_HTML.exists():
        return _SETTINGS_LOGIN_HTML.read_text()
    return "<h1>Settings login page not found</h1>"


@router.post("/settings-login")
async def settings_login_submit(
    access_code: str = Form(""),
    next_path: str = Form("/settings-ui", alias="next"),
):
    target = _safe_next(next_path, default="/settings-ui")
    if settings_gate.code_is_valid(access_code):
        response = RedirectResponse(url=target, status_code=303)
        response.set_cookie(
            settings_gate.COOKIE_NAME,
            settings_gate.session_token(),
            max_age=settings_gate.COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response
    logger.warning("Failed settings-login attempt")
    return RedirectResponse(
        url=f"/settings-login?error=1&next={quote(target, safe='')}", status_code=303
    )


@router.get("/settings-logout")
async def settings_logout():
    """Re-lock Settings without dropping the app session."""
    response = RedirectResponse(url="/app", status_code=303)
    response.delete_cookie(settings_gate.COOKIE_NAME, path="/")
    return response
