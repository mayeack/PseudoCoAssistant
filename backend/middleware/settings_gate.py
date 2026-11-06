"""Second access gate, in front of the Settings page.

The app-wide `ACCESS_KEY` (`backend/middleware/access_key.py`) lets an audience
into the demo. This code keeps that same audience out of `/settings-ui`, where
the provider / HEC / guardrail credentials are edited — a deliberately separate
secret, so handing the demo key to a room does not hand over the settings page.

Hardcoded on purpose. Unlike `ACCESS_KEY`, which is per-deployment and comes
from `.env`, this value is the same on every box, so there is nothing to
provision on a new EC2 replica. It is a demo speed bump, not a security
boundary: the `/api/settings*` and `/api/hec/*` endpoints the page drives stay
reachable with the app access key alone (the chat UI needs some of them), so
the gate is on the page, not the API.
"""
import hashlib
import secrets

from fastapi import Request

# The settings access code. Intentionally in source, not in .env — see above.
SETTINGS_ACCESS_CODE = "OneCisco2027"

# Cookie set after a successful POST /settings-login. Separate from the app
# gate's `md_access`, so unlocking one never unlocks the other.
COOKIE_NAME = "md_settings"
COOKIE_MAX_AGE = 60 * 60 * 12  # 12 hours, matching the app gate's session


def session_token() -> str:
    """Opaque cookie value derived from the code, so the browser never holds it."""
    return hashlib.sha256(SETTINGS_ACCESS_CODE.encode("utf-8")).hexdigest()


def has_settings_access(request: Request) -> bool:
    cookie = request.cookies.get(COOKIE_NAME, "")
    return bool(cookie) and secrets.compare_digest(
        cookie.encode("utf-8"), session_token().encode("utf-8"))


def code_is_valid(code: str) -> bool:
    # Bytes, not str: compare_digest raises TypeError on non-ASCII text (a 500).
    return secrets.compare_digest(code.encode("utf-8"), SETTINGS_ACCESS_CODE.encode("utf-8"))
