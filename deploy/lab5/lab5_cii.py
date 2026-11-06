"""Read-only Cisco Identity Intelligence (CII) API client for the persona self-check.

Uses the same CII API client the boxes use for the gate (Keychain items
``pseudoco-lab5-cii-*``, the "Copy all" values): an OAuth client-credentials
token (JSON body ``client_id``, ``client_secret``, ``grant_type``; it lasts
about 10 h and is cached here for the run) and one GraphQL query,
``getEndUser(login)``, whose ``levelOfTrust`` and current ``failingChecks``
are all the self-check reads (plan 4.5, 12.4). CII's login is the email.

The shape is the published schema's (docs.oort.io Public API), the same one
the app's gate asks (``backend/services/identity_lookup.CII_END_USER_QUERY``;
tests/test_identity_personas.py pins the two together):
``getEndUser(login: String!): GetEndUserOutput!``, whose ``endUserDetails``
carries ``failingChecks`` and ``endUserTrustScore { levelOfTrust }``. A user
CII has no record of yet reads the way the gate reads it (``not_found``): an
answer with no error at all whose ``getEndUser`` is null or holds a present,
null ``endUserDetails``. Any answer that carries an error is a failed query,
never "not in CII yet", whatever the error says or its details hold: reading
a missing user from the words of a message is a guess that a permission or
scope error can pass. If spikes S5/S6 show CII answers an unknown login with
an error, that exact answer is added to both copies and the shared table.
``tests/fixtures/cii_end_user_answers.json`` holds the cases the two must read
the same way. Spikes S5/S6 confirm the shape on the tenant; personas.yaml ``cii.end_user_query``
overrides the query, and an override must keep that shape, which is what the
parser reads. Values are parsed defensively: a trust level may come back as a
string or as an object, and a failing check as a name or as an object.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from lab5_common import Keychain, Lab5Error

CII_ITEMS = {"client_id": "pseudoco-lab5-cii-client-id", "client_secret": "pseudoco-lab5-cii-client-secret",
             "token_url": "pseudoco-lab5-cii-token-url", "api_url": "pseudoco-lab5-cii-api-url"}

END_USER_QUERY = ("query Lab5EndUser($login: String!) { getEndUser(login: $login) "
                  "{ endUserDetails { login status failingChecks endUserTrustScore { levelOfTrust lastUpdated } } } }")

# CII's LevelOfTrust, best first; "Neutral or better" (plan 4.6) is GOOD_TRUST.
TRUST_LEVELS = ("TRUSTED", "FAVORABLE", "NEUTRAL", "QUESTIONABLE", "UNTRUSTED", "UNKNOWN")
GOOD_TRUST = ("TRUSTED", "FAVORABLE", "NEUTRAL")

Transport = Callable[[str, str, Dict[str, str], Optional[bytes], float], Tuple[int, bytes]]


def _trust(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("level") or value.get("name") or value.get("value")
    text = str(value or "").strip().upper().replace(" ", "_")
    return text or "UNKNOWN"


def _check_name(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("name") or value.get("checkId") or value.get("id") or value.get("title")
    return str(value or "").strip()


def not_found(doc: Any) -> bool:
    """Is this GraphQL answer CII's "no such user"? The gate's rule
    (``identity_lookup._cii_not_found``): an answer with ``data`` and no error
    at all, whose ``getEndUser`` is null or holds a present, null
    ``endUserDetails``. An answer with any error never is, whatever it says."""
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
    "no such user" is ``found: False``. Any other answer with errors, or one
    without details, raises: a partial or misshapen answer is a failed query,
    never a user with no failing checks."""
    if not_found(doc):
        return {"trust": "UNKNOWN", "failing_checks": [], "found": False}
    errors = doc.get("errors") if isinstance(doc, dict) else None
    if errors not in (None, []):
        first = errors[0] if isinstance(errors, list) and errors else errors
        message = str(first.get("message") if isinstance(first, dict) else first)[:200]
        raise Lab5Error(f"CII query failed ({message}). An error is never read as \"not in CII yet\": if CII "
                        "answers a login it has no record of this way, spikes S5/S6 pin that answer; otherwise "
                        "check the API client and cii.end_user_query in scripts/identity/personas.yaml")
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
        if status != 200:
            raise Lab5Error(f"CII: {url.split('/')[2]} answered HTTP {status}")
        try:
            return json.loads(data or b"{}")
        except ValueError:
            raise Lab5Error("CII: the answer was not JSON")

    def token(self) -> str:
        if self._token and self._clock() < self._expires:
            return self._token
        doc = self._post(self.token_url, {"client_id": self._id, "client_secret": self._secret,
                                          "grant_type": "client_credentials"}, {})
        token = str(doc.get("access_token") or "")
        if not token:
            raise Lab5Error("CII: the token endpoint returned no access_token")
        self._token = token
        self._expires = self._clock() + max(60.0, float(doc.get("expires_in") or 36000) - 300.0)
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
