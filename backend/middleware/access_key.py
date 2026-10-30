import base64
import binascii
import hashlib
import re
import secrets
import logging
from urllib.parse import quote

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, HTMLResponse, PlainTextResponse

from backend.config import settings

logger = logging.getLogger(__name__)

# Cookie set after a successful POST /login.
COOKIE_NAME = "md_access"

# Reachable without the key: the health check and the login page itself
# (otherwise an unauthenticated user could never reach the form to log in).
PUBLIC_PATHS = {"/health", "/login", "/favicon.ico"}

# What a real client puts in Host: a DNS name, IPv4 or [IPv6] literal, optional
# :port. Anything else ("box/health?x=", spaces, "@") is refused with a 400.
_VALID_HOST = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::[0-9]{1,5})?$")


def routed_path(request: Request) -> str:
    """The path the router will dispatch this request to.

    Never decide access on ``request.url.path``: Starlette rebuilds
    ``request.url`` from the Host header plus the path and re-parses it, so a
    crafted Host can make ``request.url.path`` read ``/health`` while the
    router serves a protected route. ``scope["path"]`` is what routing uses.
    """
    return request.scope.get("path") or "/"


def _host_is_valid(request: Request) -> bool:
    host = request.headers.get("host")
    return host is None or bool(_VALID_HOST.match(host))


def session_token() -> str:
    """Opaque cookie value derived from the access key.

    Storing the hash (not the raw key) keeps the secret itself out of the
    browser, while remaining stateless — no server-side session store needed.
    """
    return hashlib.sha256(settings.access_key.encode("utf-8")).hexdigest()


def _has_valid_cookie(request: Request) -> bool:
    cookie = request.cookies.get(COOKIE_NAME, "")
    return bool(cookie) and secrets.compare_digest(cookie, session_token())


def _has_valid_basic_auth(request: Request) -> bool:
    scheme, _, credentials = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(credentials).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    _, _, password = decoded.partition(":")
    return secrets.compare_digest(password, settings.access_key)


class AccessKeyMiddleware(BaseHTTPMiddleware):
    """Gate every request behind a single shared access key.

    Two accepted ways to present it:
      * Browser  -> log in at /login, which sets an HttpOnly session cookie.
      * API/curl -> HTTP Basic Auth  (curl -u x:$ACCESS_KEY ...).
    No-op when settings.access_key is empty (local development).
    """

    async def dispatch(self, request: Request, call_next):
        # A malformed Host header is never a real client, and it is the lever
        # for confusing request.url with the routed path (see routed_path).
        if not _host_is_valid(request):
            logger.warning(
                "Rejected request with malformed Host header",
                extra={"path": routed_path(request),
                       "client": request.client.host if request.client else None},
            )
            return PlainTextResponse("Bad Request", status_code=400)

        path = routed_path(request)

        # CORS preflights pass through. This middleware is added last, so it
        # wraps CORSMiddleware and sees the request first; a preflight carries
        # neither cookie nor Authorization header, so gating OPTIONS 401'd every
        # preflight before CORS could answer it. A preflight discloses nothing
        # and authorizes nothing — the actual request behind it is still gated.
        if (not settings.access_key
                or request.method == "OPTIONS"
                or path in PUBLIC_PATHS
                or _has_valid_cookie(request)
                or _has_valid_basic_auth(request)):
            return await call_next(request)

        logger.warning(
            "Rejected unauthenticated request",
            extra={"path": path,
                   "client": request.client.host if request.client else None},
        )

        # Top-level browser navigation gets a friendly page that links to the
        # login form; API clients (fetch/curl) get JSON + a Basic Auth challenge.
        if "text/html" in request.headers.get("accept", ""):
            login_url = "/login?next=" + quote(path, safe="")
            return HTMLResponse(
                _UNAUTHORIZED_HTML.replace("__LOGIN_URL__", login_url),
                status_code=401,
            )
        return JSONResponse(
            {"detail": "Access key required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="PseudoCo Assistant"'},
        )


# Standalone 401 page (no external assets). __LOGIN_URL__ is substituted per
# request so "Enter access code" returns the user to the page they wanted.
_UNAUTHORIZED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access required · PseudoCo Assistant</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#7c3aed;--primary-hover:#6d28d9;--ink:#0f172a;--muted:#64748b;--bg1:#f5f3ff;--bg2:#ede9fe;}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
      font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      background:radial-gradient(1200px 600px at 50% -10%,var(--bg1),var(--bg2));color:var(--ink);}
    .card{width:100%;max-width:420px;background:#fff;border:1px solid #e5e7eb;border-radius:20px;
      box-shadow:0 20px 40px -12px rgba(15,23,42,.18),0 2px 6px rgba(15,23,42,.06);
      padding:40px 34px;text-align:center;animation:rise .4s cubic-bezier(.2,.8,.2,1);}
    @keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
    .badge{width:62px;height:62px;margin:0 auto 22px;border-radius:17px;
      background:linear-gradient(135deg,#ede9fe,#f5f3ff);display:flex;align-items:center;justify-content:center;
      color:var(--primary);box-shadow:inset 0 0 0 1px rgba(124,58,237,.15)}
    .badge svg{width:29px;height:29px}
    h1{font-size:22px;margin:0 0 9px;letter-spacing:-.02em}
    p{margin:0 auto 28px;color:var(--muted);font-size:15px;line-height:1.55;max-width:300px}
    a.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;
      padding:13px 18px;font-size:15px;font-weight:600;color:#fff;background:var(--primary);
      border-radius:12px;text-decoration:none;transition:background .15s}
    a.btn:hover{background:var(--primary-hover)}
    .foot{margin-top:24px;color:#94a3b8;font-size:12px}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none"><rect x="4" y="10" width="16" height="11" rx="2.5" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
    </div>
    <h1>Access required</h1>
    <p>This page is private. Enter your access code to continue to PseudoCo Assistant.</p>
    <a class="btn" href="__LOGIN_URL__">
      Enter access code
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </a>
    <div class="foot">PseudoCo Assistant · Authorized access only</div>
  </div>
</body>
</html>"""
