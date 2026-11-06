"""Duo Admin API and Auth API calls for the Lab 5 tools on the facilitator's Mac.

Two Duo applications are used from the Mac, never from a box (plan 4.2, 12.4):

* **PseudoCo Provisioner** (Admin API, Grant resource read + write): the
  persona cast, the participant accounts, their groups and HOTP tokens, and
  the room personas' bypass codes for the handout (plan 4.3).
* **PseudoCo VPN** (Auth API): the persona sign-ins (baseline, takeover,
  replay) and the self-check's preauth.

Every call goes through a ``transport`` with duo_client's
``json_api_call(method, path, params)`` / ``json_paging_api_call(...)``
signatures. The real one is ``duo_client.Admin`` / ``duo_client.Auth``
(imported lazily, deploy/lab5/requirements.txt); the tests pass a fake. The
methods below call the documented endpoints directly instead of duo_client's
helpers, because those helpers leave out parameters Lab 5 needs (``hostname``
on ``/auth/v2/auth``) and must never send one it forbids
(``client_supports_verified_push``, plan 4.5).

Secrets (skeys, HOTP secrets, passcodes) only ever travel as signed request
parameters: duo_client puts POST parameters in the request body, and nothing
secret is sent with GET.

Every call raises ``DuoError`` and nothing else (``_Api``): a refusal from Duo,
and any answer that never arrived or cannot be read, so each caller's
per-card and per-account handling sees one error type.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import re
import secrets
import struct
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import quote_plus

from lab5_common import Keychain, Lab5Error

# Keychain items (service names) for the two Mac-side Duo apps. The API
# hostname is the same on every Duo application page of the tenant; the
# Web SDK item from lab5-setup is accepted when the shared one is missing.
PROVISIONER_ITEMS = {"ikey": "pseudoco-lab5-duo-provisioner-ikey",
                     "skey": "pseudoco-lab5-duo-provisioner-skey"}
VPN_ITEMS = {"ikey": "pseudoco-lab5-duo-vpn-ikey",
             "skey": "pseudoco-lab5-duo-vpn-skey"}
API_HOST_ITEM = "pseudoco-lab5-duo-api-host"
API_HOST_FALLBACK_ITEM = "pseudoco-lab5-duo-websdk-api-host"

_HOST_RE = re.compile(r"^api-[a-z0-9]+(?:\.[a-z0-9-]+)+$")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_BYPASS_CODE_RE = re.compile(r"^[0-9]{6,20}$")
BYPASS_PER_REQUEST = 10      # Duo creates at most 10 bypass codes per call
BYPASS_LIMIT = 100           # Duo's object limit: bypass codes per user


class DuoError(Lab5Error):
    """A Duo API refusal or transport failure. ``status`` is the HTTP status
    and ``code`` Duo's error code (40003: a group with that name exists)."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


# --------------------------------------------------------------------------- HOTP
SECRET_ENCODINGS = ("hex", "base32")


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP (HMAC-SHA1, dynamic truncation)."""
    if counter < 0:
        raise ValueError("HOTP counter must be >= 0")
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def new_hotp_secret() -> bytes:
    """160 bits, the RFC 4226 recommendation."""
    return secrets.token_bytes(20)


def encode_secret(secret: bytes, encoding: str) -> str:
    """How the secret is sent to Duo (``POST /admin/v1/tokens`` ``secret``)
    and kept in the Keychain. Duo's API page does not say; spike S7 settles
    hex vs base32, and personas.yaml ``hotp.secret_encoding`` follows it."""
    if encoding == "hex":
        return secret.hex()
    if encoding == "base32":
        return base64.b32encode(secret).decode().rstrip("=")
    raise Lab5Error(f"unknown HOTP secret encoding {encoding!r} (use hex or base32)")


def decode_secret(text: str, encoding: str) -> bytes:
    try:
        if encoding == "hex":
            return bytes.fromhex(text)
        if encoding == "base32":
            return base64.b32decode(text.upper() + "=" * (-len(text) % 8))
    except ValueError:
        raise Lab5Error("a Keychain HOTP secret is not valid for its encoding")
    raise Lab5Error(f"unknown HOTP secret encoding {encoding!r} (use hex or base32)")


def wrong_passcode(secret: bytes, counter: int, rng: Callable[[int], int] = secrets.randbelow,
                   window: int = 200) -> str:
    """A 6-digit code that is NOT any valid code near the counter, so a
    deliberate failure can never be accepted by Duo's look-ahead."""
    valid = {hotp(secret, c) for c in range(max(0, counter - window), counter + window)}
    while True:
        code = str(rng(10 ** 6)).zfill(6)
        if code not in valid:
            return code


# --------------------------------------------------------------------------- transport
def duo_transport(kind: str, ikey: str, skey: str, host: str) -> Any:
    """A real duo_client client: ``kind`` is "admin" or "auth"."""
    try:
        import duo_client  # lazy: deploy/lab5/requirements.txt
    except ImportError:
        raise Lab5Error("duo_client is not installed for this Python. One-time setup: "
                        "~/.pseudoco-lab5/venv/bin/pip install -r deploy/lab5/requirements.txt")
    cls = duo_client.Admin if kind == "admin" else duo_client.Auth
    return cls(ikey=ikey, skey=skey, host=host, timeout=20)


def api_host(keychain: Keychain) -> str:
    host = (keychain.get(API_HOST_ITEM, secret=False) or keychain.get(API_HOST_FALLBACK_ITEM, secret=False) or "")
    host = host.strip().lower()
    if not host:
        raise Lab5Error(f"Keychain item '{API_HOST_ITEM}' (the Duo API hostname, api-XXXXXXXX.duosecurity.com) "
                        f"is missing. Add it with: security add-generic-password -s {API_HOST_ITEM} -a \"$USER\" -w")
    if not _HOST_RE.match(host):
        raise Lab5Error(f"the Duo API hostname in the Keychain does not look like api-XXXXXXXX.duosecurity.com")
    return host


def admin_panel_url(host: str, user_id: str = "") -> str:
    """api-XXXX.duosecurity.com -> https://admin-XXXX.duosecurity.com[/users/<id>]."""
    panel = "admin-" + host[len("api-"):] if host.startswith("api-") else host
    return f"https://{panel}" + (f"/users/{quote_plus(user_id)}" if user_id else "")


# What a duo_client call raises when no usable answer comes back, besides the
# RuntimeError that carries Duo's own refusal: the socket, TLS and timeout
# errors (OSError; ssl.SSLError and socket.timeout are OSErrors), an HTTP
# exchange cut off or garbled on the way (http.client.HTTPException:
# IncompleteRead, BadStatusLine, RemoteDisconnected), and a body that is not the
# JSON Duo documents (ValueError: JSONDecodeError, UnicodeDecodeError; KeyError,
# TypeError and AttributeError from its parser). Each becomes a DuoError.
TRANSPORT_ERRORS = (OSError, http.client.HTTPException, ValueError, KeyError, TypeError, AttributeError)


class _Api:
    def __init__(self, transport: Any, host: str = "") -> None:
        self.transport = transport
        self.host = host

    def call(self, method: str, path: str, params: Optional[Dict[str, str]] = None) -> Any:
        try:
            return self.transport.json_api_call(method, path, dict(params or {}))
        except RuntimeError as exc:
            raise self._error(method, path, exc)
        except TRANSPORT_ERRORS as exc:
            raise self._transport_error(method, path, exc)

    def page(self, path: str, params: Optional[Dict[str, str]] = None) -> List[Any]:
        try:
            return list(self.transport.json_paging_api_call("GET", path, dict(params or {})))
        except RuntimeError as exc:
            raise self._error("GET", path, exc)
        except TRANSPORT_ERRORS as exc:
            raise self._transport_error("GET", path, exc)

    @staticmethod
    def _transport_error(method: str, path: str, exc: Exception) -> DuoError:
        """Only the exception's type is reported: an unfinished answer to a
        create may hold what it created (a bypass code, say)."""
        if isinstance(exc, OSError):
            return DuoError(f"Duo {method} {path}: cannot reach Duo ({type(exc).__name__})")
        return DuoError(f"Duo {method} {path}: Duo's answer was cut off or unreadable ({type(exc).__name__}), so "
                        "whether the call took effect is unknown")

    @staticmethod
    def _error(method: str, path: str, exc: RuntimeError) -> DuoError:
        status = getattr(exc, "status", None)
        code = None
        data = getattr(exc, "data", None)
        try:
            body = data if isinstance(data, dict) else json.loads(
                data.decode() if isinstance(data, bytes) else (data or "{}"))
            code = int(body.get("code")) if body.get("code") is not None else None
        except (ValueError, AttributeError, TypeError):
            pass
        text = str(exc)
        if status == 200 or text.startswith(("Received bad response", "Received error response")):
            # duo_client puts the whole body of an unreadable 200 answer in its message; it may hold what
            # the call created, so it is never repeated
            text = "Duo's answer was not the JSON it documents, so whether the call took effect is unknown"
        return DuoError(f"Duo {method} {path}: {text[:200]}", status=status, code=code)


def _id(value: Any) -> str:
    text = str(value or "")
    if not _ID_RE.match(text):
        raise DuoError(f"unexpected Duo object id {text[:20]!r}")
    return quote_plus(text)


class AdminAPI(_Api):
    """The Admin API endpoints the Provisioner app is used for."""

    # users
    def user_by_name(self, username: str) -> Optional[Dict[str, Any]]:
        found = self.call("GET", "/admin/v1/users", {"username": username})
        return found[0] if found else None

    def users(self) -> List[Dict[str, Any]]:
        return self.page("/admin/v1/users")

    def create_user(self, username: str, email: str, realname: str, notes: str,
                    firstname: str = "", lastname: str = "") -> Dict[str, Any]:
        params = {"username": username, "email": email, "realname": realname, "notes": notes,
                  "status": "active"}
        if firstname:
            params["firstname"] = firstname
        if lastname:
            params["lastname"] = lastname
        return self.call("POST", "/admin/v1/users", params)

    def set_status(self, user_id: str, status: str) -> Dict[str, Any]:
        if status not in ("active", "disabled"):
            raise DuoError(f"refusing to set user status {status!r}: only active or disabled")
        return self.call("POST", f"/admin/v1/users/{_id(user_id)}", {"status": status})

    def delete_user(self, user_id: str) -> None:
        self.call("DELETE", f"/admin/v1/users/{_id(user_id)}")

    # groups
    def groups(self) -> List[Dict[str, Any]]:
        return self.page("/admin/v1/groups")

    def group_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        matches = [g for g in self.groups() if g.get("name") == name]
        if len(matches) > 1:
            raise DuoError(f"several Duo groups are named {name!r}; keep one")
        return matches[0] if matches else None

    def create_group(self, name: str, desc: str) -> Dict[str, Any]:
        return self.call("POST", "/admin/v1/groups", {"name": name, "desc": desc})

    def user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        """``GET /admin/v1/users/{id}/groups`` (paged; *Grant resource - Read*):
        the user's groups as group objects, each with ``group_id``, ``name``
        and ``status`` (read it with group_status())."""
        return self.page(f"/admin/v1/users/{_id(user_id)}/groups")

    def add_user_group(self, user_id: str, group_id: str) -> None:
        self.call("POST", f"/admin/v1/users/{_id(user_id)}/groups", {"group_id": str(group_id)})

    # hardware tokens
    def create_hotp_token(self, serial: str, secret_text: str, counter: int = 0) -> Dict[str, Any]:
        return self.call("POST", "/admin/v1/tokens",
                         {"type": "h6", "serial": serial, "secret": secret_text, "counter": str(int(counter))})

    def token_by_serial(self, serial: str) -> Optional[Dict[str, Any]]:
        found = self.call("GET", "/admin/v1/tokens", {"type": "h6", "serial": serial})
        return found[0] if found else None

    def attach_token(self, user_id: str, token_id: str) -> None:
        self.call("POST", f"/admin/v1/users/{_id(user_id)}/tokens", {"token_id": str(token_id)})

    def user_tokens(self, user_id: str) -> List[Dict[str, Any]]:
        return self.page(f"/admin/v1/users/{_id(user_id)}/tokens")

    def delete_token(self, token_id: str) -> None:
        self.call("DELETE", f"/admin/v1/tokens/{_id(token_id)}")

    def resync_token(self, token_id: str, codes: Iterable[str]) -> None:
        code1, code2, code3 = list(codes)
        self.call("POST", f"/admin/v1/tokens/{_id(token_id)}/resync",
                  {"code1": code1, "code2": code2, "code3": code3})

    # bypass codes: the room personas' handout codes (plan 4.3), never a participant's
    def create_bypass_codes(self, user_id: str, count: int, reuse_count: int, valid_secs: int) -> List[str]:
        """``POST /admin/v1/users/{id}/bypass_codes``, always with
        ``preserve_existing=true``: Duo's default clears every code the user
        already has, and a trusted persona carries other boxes' and other
        rooms' codes. Duo's defaults for the other two, ``reuse_count`` 0
        (unlimited) and ``valid_secs`` 0 (never expires), are refused.

        Returns the codes. The response is the only place they ever appear,
        and it carries no id for them; no error message here repeats one."""
        count, reuse_count, valid_secs = int(count), int(reuse_count), int(valid_secs)
        if not 1 <= count <= BYPASS_PER_REQUEST:
            raise DuoError(f"refusing to create {count} bypass codes in one call: Duo creates 1 to "
                           f"{BYPASS_PER_REQUEST}")
        if reuse_count < 1:
            raise DuoError("refusing bypass codes without a use limit (reuse_count 0 is unlimited in Duo)")
        if valid_secs < 1:
            raise DuoError("refusing bypass codes that never expire (valid_secs 0 in Duo)")
        result = self.call("POST", f"/admin/v1/users/{_id(user_id)}/bypass_codes",
                           {"count": str(count), "reuse_count": str(reuse_count), "valid_secs": str(valid_secs),
                            "preserve_existing": "true"})
        codes = result if isinstance(result, list) else []
        if len(codes) != count or not all(isinstance(c, str) and _BYPASS_CODE_RE.match(c) for c in codes):
            raise DuoError(f"Duo POST /admin/v1/users/{{id}}/bypass_codes: expected {count} numeric code(s) back")
        return list(codes)

    def user_bypass_codes(self, user_id: str) -> List[Dict[str, Any]]:
        """The user's bypass codes as metadata only (``bypass_code_id``,
        ``created``, ``expiration``, ``reuse_count``, ``admin_email``): Duo never
        returns a code's value after creating it."""
        return self.page(f"/admin/v1/users/{_id(user_id)}/bypass_codes")

    def delete_bypass_code(self, code_id: str) -> bool:
        """``DELETE /admin/v1/bypass_codes/{bypass_code_id}`` (no parameters,
        *Grant resource - Write*). True when Duo deleted it, False when Duo has
        no such code (404: used up, expired or deleted already)."""
        try:
            self.call("DELETE", f"/admin/v1/bypass_codes/{_id(code_id)}")
        except DuoError as exc:
            if exc.status == 404:
                return False
            raise
        return True


class AuthAPI(_Api):
    """The Auth API endpoints the PseudoCo VPN app is used for. Every sign-in
    carries ``ipaddr`` and ``hostname``; ``client_supports_verified_push`` is
    never sent (plan 4.5)."""

    def check(self) -> Dict[str, Any]:
        return self.call("GET", "/auth/v2/check")

    def preauth(self, username: str, ipaddr: str, hostname: str) -> Dict[str, Any]:
        return self.call("POST", "/auth/v2/preauth", {"username": username, "ipaddr": ipaddr, "hostname": hostname})

    def auth_passcode(self, username: str, passcode: str, ipaddr: str, hostname: str) -> Dict[str, Any]:
        return self.call("POST", "/auth/v2/auth", {"username": username, "factor": "passcode", "passcode": passcode,
                                                   "ipaddr": ipaddr, "hostname": hostname, "async": "0"})

    def auth_push_async(self, username: str, ipaddr: str, hostname: str, text: str = "") -> str:
        params = {"username": username, "factor": "push", "device": "auto", "ipaddr": ipaddr,
                  "hostname": hostname, "async": "1"}
        if text:
            params["type"] = text
        return str(self.call("POST", "/auth/v2/auth", params).get("txid") or "")

    def auth_status(self, txid: str) -> Dict[str, Any]:
        return self.call("GET", "/auth/v2/auth_status", {"txid": txid})


def admin_api(keychain: Keychain, transport_factory: Callable[..., Any] = duo_transport,
              items: Optional[Dict[str, str]] = None) -> AdminAPI:
    items = items or PROVISIONER_ITEMS
    ikey = keychain.require(items["ikey"], "Duo Admin API app PseudoCo Provisioner: integration key")
    skey = keychain.require(items["skey"], "Duo Admin API app PseudoCo Provisioner: secret key")
    host = api_host(keychain)
    return AdminAPI(transport_factory("admin", ikey, skey, host), host)


def auth_api(keychain: Keychain, transport_factory: Callable[..., Any] = duo_transport,
             items: Optional[Dict[str, str]] = None) -> AuthAPI:
    items = items or VPN_ITEMS
    ikey = keychain.require(items["ikey"], "Duo Auth API app PseudoCo VPN: integration key")
    skey = keychain.require(items["skey"], "Duo Auth API app PseudoCo VPN: secret key")
    host = api_host(keychain)
    return AuthAPI(transport_factory("auth", ikey, skey, host), host)


def group_names(user: Dict[str, Any]) -> List[str]:
    return [str(g.get("name") or "") for g in (user.get("groups") or [])]


def group_status(group: Dict[str, Any]) -> str:
    """A group object's ``status``, lower-cased; empty when Duo sent none.
    The Admin API documents "Active" (members complete secondary
    authentication), "Bypass" (members skip it) and "Disabled" (members
    cannot authenticate), while its example responses write "active"."""
    return str(group.get("status") or "").strip().lower()


def assigned_elsewhere(token: Dict[str, Any], user_id: str = "") -> bool:
    """Is this token assigned to some user other than ``user_id``? A token
    found by serial is only ever deleted when it is not."""
    return any(str(u.get("user_id")) != str(user_id) for u in (token.get("users") or []))
