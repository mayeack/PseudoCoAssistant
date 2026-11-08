"""Read-only Cisco Identity Intelligence (CII) API client for the persona self-check.

Uses the CII API client in the Mac's Keychain (items ``pseudoco-lab5-cii-*``,
the "Copy all" values), which never leaves the Mac: an OAuth
client-credentials token (JSON body ``client_id``, ``client_secret``,
``grant_type``; it lasts 24 h and is cached here for the run) and one GraphQL
query,
``getEndUser(login)``, whose ``levelOfTrust`` and current ``failingChecks``
are all the self-check reads (plan 4.5, 12.4). CII's login is the email.
CII gives each API client only ``TOKENS_PER_HOUR`` tokens a clock hour (spike
S16), so the boxes never get the client: ``lab5-setup`` mints one token here
(``CIIClient.mint``) and pushes it to every box as CII_ACCESS_TOKEN, and the
gate on the box asks CII with it until it expires.

The shape is the published schema's (docs.oort.io Public API), the same one
the app's gate asks (``backend/services/identity_lookup.CII_END_USER_QUERY``;
tests/test_identity_personas.py pins the two together):
``getEndUser(login: String!): GetEndUserOutput!``, whose ``endUserDetails``
carries ``failingChecks`` and ``endUserTrustScore { levelOfTrust }``. A user
CII has no record of yet reads the way the gate reads it (``not_found``): an
answer with no error at all whose ``getEndUser`` is null or holds a present,
null ``endUserDetails``, or CII's own error for a login it has no record of,
matched exactly (``UNKNOWN_LOGIN_ANSWER``, the live API's answer captured on
2026-11-06). Any other answer that carries an error is a failed query, never
"not in CII yet", whatever the error says, what code it carries or what its
details hold: reading a missing user from the words of a message, or from a
code such as ``USER_NOT_FOUND``, is a guess that a permission or scope error
can pass.
``tests/fixtures/cii_end_user_answers.json`` holds the cases the two must read
the same way. Spikes S5/S6 confirm the shape on the tenant; personas.yaml ``cii.end_user_query``
overrides the query, and an override must keep that shape, which is what the
parser reads. Values are parsed defensively: a trust level may come back as a
string or as an object, and a failing check as a name or as an object.
"""
from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from lab5_common import Keychain, Lab5Error

CII_ITEMS = {"client_id": "pseudoco-lab5-cii-client-id", "client_secret": "pseudoco-lab5-cii-client-secret",
             "token_url": "pseudoco-lab5-cii-token-url", "api_url": "pseudoco-lab5-cii-api-url"}

# CII's token endpoint gives each API client this many tokens a clock hour
# (spike S16, 2026-11-07: HTTP 429, x-ratelimit-limit 6, reset on the hour).
# A token lasts 24 h, and minting one does not end the earlier ones.
TOKENS_PER_HOUR = 6
END_USER_QUERY = ("query Lab5EndUser($login: String!) { getEndUser(login: $login) "
                  "{ endUserDetails { login status failingChecks endUserTrustScore { levelOfTrust lastUpdated } } } }")

# CII's LevelOfTrust, best first; "Neutral or better" (plan 4.6) is GOOD_TRUST.
TRUST_LEVELS = ("TRUSTED", "FAVORABLE", "NEUTRAL", "QUESTIONABLE", "UNTRUSTED", "UNKNOWN")
GOOD_TRUST = ("TRUSTED", "FAVORABLE", "NEUTRAL")

Transport = Callable[[str, str, Dict[str, str], Optional[bytes], float], Tuple[int, bytes]]


def jwt_expiry(token: Optional[str]) -> Optional[float]:
    """The ``exp`` claim of a JWT, in seconds since the epoch, read without
    checking the signature (the same reading as the app's
    ``identity_lookup.jwt_expiry``). None for a token that is not a JWT or has
    no ``exp``."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError, binascii.Error):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _trust(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("level") or value.get("name") or value.get("value")
    text = str(value or "").strip().upper().replace(" ", "_")
    return text or "UNKNOWN"


def _check_name(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("name") or value.get("checkId") or value.get("id") or value.get("title")
    return str(value or "").strip()


#: CII's own answer for a login it has no record of (the gate's
#: ``identity_lookup.CII_UNKNOWN_LOGIN_ANSWER``; tests/test_identity_personas.py
#: pins the two equal): matched exactly, each error's ``locations`` aside.
UNKNOWN_LOGIN_ANSWER = {"data": None, "errors": [{"path": ["getEndUser"], "data": None,
                                                  "errorType": "404", "message": "Not Found"}]}


def unknown_login(doc: Any) -> bool:
    """Is this answer, exactly, CII's error for a login it has no record of
    (``UNKNOWN_LOGIN_ANSWER``), each error's ``locations`` aside? The gate's
    ``identity_lookup._cii_unknown_login``."""
    if not isinstance(doc, dict) or not isinstance(doc.get("errors"), list):
        return False
    errors = [{k: v for k, v in e.items() if k != "locations"} if isinstance(e, dict) else e
              for e in doc["errors"]]
    return {**doc, "errors": errors} == UNKNOWN_LOGIN_ANSWER


def not_found(doc: Any) -> bool:
    """Is this GraphQL answer CII's "no such user"? The gate's rule
    (``identity_lookup._cii_not_found``): CII's error for a login it has no
    record of, matched exactly (``unknown_login``), or an answer with ``data``
    and no error at all, whose ``getEndUser`` is null or holds a present, null
    ``endUserDetails``. Any other answer with an error never is, whatever it
    says or what code it carries.
    No error at all is ``errors`` absent, null or an empty list; any other
    value carries one, a falsy one (``{}``, ``""``, 0, false) included, here
    and in ``parse_end_user``. tests/test_identity_personas.py pins this code
    to the gate's copy and pins the path to it: after the one exact answer,
    its errors guard turns away every answer that carries an error before
    anything else reads it,
    ``parse_end_user``'s first statement (under this rule) is the only
    ``found: False`` the Mac's tools write and nothing else returns before
    its errors guard, and CIIClient hands it the transport's answer
    untouched. It also sends every error the table holds and every failed
    request through CIIClient.end_user and the self-check's row."""
    if unknown_login(doc):
        return True
    if not isinstance(doc, dict) or doc.get("errors") not in (None, []) or "data" not in doc:
        return False
    data = doc.get("data")
    if not isinstance(data, dict) or "getEndUser" not in data:
        return False
    user = data.get("getEndUser")
    if user is None:
        return True
    return isinstance(user, dict) and "endUserDetails" in user and user.get("endUserDetails") is None


def parse_end_user(doc: Any) -> Dict[str, Any]:
    """One getEndUser answer to ``{"trust", "failing_checks", "found"}``. CII's
    "no such user" (``not_found``: an answer with no error at all) is
    ``found: False``. Every answer that carries an error raises, whatever it
    says, what code it carries or where it sits, and so does one without
    details: a partial or misshapen answer is a failed query, never a user
    with no failing checks and never "not in CII yet"."""
    if not_found(doc):
        return {"trust": "UNKNOWN", "failing_checks": [], "found": False}
    errors = doc.get("errors") if isinstance(doc, dict) else None
    if errors not in (None, []):
        first = errors[0] if isinstance(errors, list) and errors else errors
        message = str(first.get("message") if isinstance(first, dict) else first)[:200]
        raise Lab5Error(f"CII query failed ({message}). Apart from CII's own answer for a login it has no record "
                        "of, an error is never read as \"not in CII yet\": check the API client and "
                        "cii.end_user_query in scripts/identity/personas.yaml")
    data = doc.get("data") if isinstance(doc, dict) else None
    user = data.get("getEndUser") if isinstance(data, dict) else None
    details = user.get("endUserDetails") if isinstance(user, dict) else None
    if not isinstance(details, dict):
        raise Lab5Error("CII answered getEndUser in a shape the self-check cannot read (no endUserDetails); "
                        "spikes S5/S6 pin the query: set cii.end_user_query in scripts/identity/personas.yaml")
    score = details.get("endUserTrustScore")
    level = score.get("levelOfTrust") if isinstance(score, dict) else score
    checks = details.get("failingChecks") or []
    if not isinstance(checks, list):
        checks = [checks]
    return {"trust": _trust(level),
            "failing_checks": sorted({_check_name(c) for c in checks if _check_name(c)}),
            "found": True}


class CIIClient:
    def __init__(self, client_id: str, client_secret: str, token_url: str, api_url: str,
                 transport: Transport, query: str = END_USER_QUERY, clock: Callable[[], float] = time.time) -> None:
        for url, what in ((token_url, "token URL"), (api_url, "API URL")):
            if not url.lower().startswith("https://"):
                raise Lab5Error(f"the CII {what} in the Keychain must be an https URL")
        self._id, self._secret = client_id, client_secret
        self.token_url, self.api_url = token_url, api_url
        self._transport, self.query, self._clock = transport, query or END_USER_QUERY, clock
        self._token: Optional[str] = None
        self._expires = 0.0

    def _post(self, url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        body = json.dumps(payload).encode()
        try:
            status, data = self._transport("POST", url, dict(headers, **{"Content-Type": "application/json",
                                                                          "Accept": "application/json"}),
                                           body, 20.0)
        except Lab5Error as exc:
            raise Lab5Error(f"CII: cannot reach {url.split('/')[2]} ({exc})")
        if status == 429 and url == self.token_url:
            raise Lab5Error(f"CII: {url.split('/')[2]} answered HTTP 429: this API client's tokens for the hour are "
                            f"used up (CII gives each client {TOKENS_PER_HOUR} an hour); they come back on the hour")
        if status != 200:
            raise Lab5Error(f"CII: {url.split('/')[2]} answered HTTP {status}")
        try:
            return json.loads(data or b"{}")
        except ValueError:
            raise Lab5Error("CII: the answer was not JSON")

    def mint(self) -> Tuple[str, float]:
        """A new access token and when it expires (seconds since the epoch):
        one of this API client's ``TOKENS_PER_HOUR``. ``lab5-setup`` pushes it
        to the boxes (CII_ACCESS_TOKEN), so they never mint their own."""
        doc = self._post(self.token_url, {"client_id": self._id, "client_secret": self._secret,
                                          "grant_type": "client_credentials"}, {})
        token = str(doc.get("access_token") or "")
        if not token:
            raise Lab5Error("CII: the token endpoint returned no access_token")
        try:
            lifetime = float(doc.get("expires_in") or 36000)
        except (TypeError, ValueError):
            lifetime = 36000.0
        return token, jwt_expiry(token) or (self._clock() + lifetime)

    def token(self) -> str:
        if self._token and self._clock() < self._expires:
            return self._token
        token, expires = self.mint()
        self._token = token
        self._expires = max(self._clock() + 60.0, expires - 300.0)
        return token

    def end_user(self, login: str) -> Dict[str, Any]:
        """``{"trust": "NEUTRAL", "failing_checks": [...], "found": bool}`` (``parse_end_user``)."""
        doc = self._post(self.api_url, {"query": self.query, "variables": {"login": login}},
                         {"Authorization": f"Bearer {self.token()}"})
        return parse_end_user(doc)


def cii_client(keychain: Keychain, transport: Transport, query: str = "") -> CIIClient:
    return CIIClient(
        keychain.require(CII_ITEMS["client_id"], "CII API client: client ID"),
        keychain.require(CII_ITEMS["client_secret"], "CII API client: client secret"),
        keychain.require(CII_ITEMS["token_url"], "CII API client: token URL", secret=False),
        keychain.require(CII_ITEMS["api_url"], "CII API client: API URL", secret=False),
        transport, query=query)


def failing(checks: List[str], wanted: str) -> bool:
    """Does any failing check name contain ``wanted`` (case and spacing
    ignored)? Check IDs are pinned by spike S6; names are matched loosely."""
    key = wanted.lower().replace(" ", "").replace("_", "").replace("-", "")
    return any(key in c.lower().replace(" ", "").replace("_", "").replace("-", "") for c in checks)
