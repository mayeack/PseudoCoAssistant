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
CII has no record of yet reads the way the gate reads it (``not_found``): the
details stop at a present, null ``endUserDetails``, at ``getEndUser`` or at
``data``. With no error, a null ``getEndUser`` or null details is the answer
(a null ``data`` is not). With errors, every one sits on ``getEndUser`` or
``endUserDetails``, at or below where the details stop, says the user was not
found (``_USER_NOT_FOUND_RE``, on its first ``MESSAGE_SCAN_MAX`` characters),
and carries no code other than ``NOT_FOUND_CODES`` (``extensions.code``,
``extensions.errorType``, AppSync's ``errorType``). Any other answer with an error is a failed query, never
"not in CII yet", whatever its details say.
``tests/fixtures/cii_end_user_answers.json`` holds the cases the two must read
the same way. Spikes S5/S6 confirm the shape on the tenant; personas.yaml ``cii.end_user_query``
overrides the query, and an override must keep that shape, which is what the
parser reads. Values are parsed defensively: a trust level may come back as a
string or as an object, and a failing check as a name or as an object.
"""
from __future__ import annotations

import json
import re
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

# CII's "no such user" (the gate's rule: backend/services/identity_lookup._cii_not_found).
NOT_FOUND_PATHS = (["getEndUser"], ["getEndUser", "endUserDetails"])
NOT_FOUND_CODES = frozenset({"NOTFOUND", "USERNOTFOUND", "ENDUSERNOTFOUND"})
MESSAGE_SCAN_MAX = 1000
_USER_NOT_FOUND_RE = re.compile(
    # A sentence whose subject is the user itself: "<end> user [record|account|...] [with login] [<login>]
    # [is|was|has] not (been) found / does not exist".
    r"\b(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?"
    r"(?:\s+(?:with|for|having|by)\s+(?:login|email|username|id))?"
    r"(?:(?:\s*:\s*|\s+)(?:\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|`[^`\n]{1,200}`|\([^()\n]{1,200}\)"
    r"|[^\s\"'`()]{0,200}[@.](?=\w)[^\s\"'`()]{0,200}))?"
    r"(?:\s*:\s*|\s+)(?:(?:is|was|has|had)\s+)?(?:not\s+(?:been\s+)?found"
    r"|(?:(?:does|did)\s+not|doesn't|didn't|not)\s+exist|(?:could|can)\s*not\s+be\s+found|can't\s+be\s+found)\b"
    # "No such user" at the end of a sentence (a mark before a space or the end), or before a colon.
    r"|\bno\s+such\s+(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?"
    r"\s*(?:$|[.;!?](?=\s|$)|:(?=\s|$))"
    # "No user" as the whole message.
    r"|^\s*no\s+(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?\s*[.!]?\s*$"
    # "No [such] user" found / exists, or before a login: "with login" (email, ...), quoted, an address.
    r"|\bno\s+(?:such\s+)?(?:end[ _-]?)?user(?:\s+(?:record|account|profile|entry|details))?"
    r"(?:\s+(?:found|exists?)\b"
    r"|\s+(?:with|for|by|matching|named)\s+(?:login|email|username|id)\b"
    r"|(?:\s*:\s*|\s+)(?:(?:with|matching|named)\s+)?(?:\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|`[^`\n]{1,200}`"
    r"|\([^()\n]{1,200}\)|[^\s\"'`()@]{1,200}@(?=\w)[^\s\"'`()]{0,200}))",
    re.IGNORECASE)

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


def _error_codes(error: Dict[str, Any]) -> List[str]:
    """Every code a GraphQL error carries, normalized (the gate's
    ``_cii_error_codes``)."""
    extensions = error.get("extensions") if isinstance(error.get("extensions"), dict) else {}
    codes = (extensions.get("code"), extensions.get("errorType"), error.get("errorType"))
    return [re.sub(r"[^A-Z0-9]+", "", str(code).upper()) for code in codes if code]


def not_found(doc: Any) -> bool:
    """Is this GraphQL answer CII's "no such user"? The same rule as the gate's
    ``_cii_not_found``: the details stop at ``data``, ``getEndUser`` or a present,
    null ``endUserDetails``; with no error a null ``getEndUser`` or null details
    is the answer; every error sits on ``getEndUser`` or ``endUserDetails``, at or
    below where the details stop, says the user was not found, and carries no
    code but a not-found one."""
    if not isinstance(doc, dict) or "data" not in doc:
        return False
    data, errors = doc.get("data"), doc.get("errors")
    if data is None:
        stop = 0
    elif isinstance(data, dict) and "getEndUser" in data:
        user = data.get("getEndUser")
        if user is None:
            stop = 1
        elif isinstance(user, dict) and "endUserDetails" in user and user.get("endUserDetails") is None:
            stop = 2
        else:
            return False
    else:
        return False
    if not errors:
        return stop > 0
    if not isinstance(errors, list):
        return False
    for error in errors:
        if not isinstance(error, dict):
            return False
        path = error.get("path")
        if path not in NOT_FOUND_PATHS or len(path) < stop:
            return False
        if not _USER_NOT_FOUND_RE.search(str(error.get("message") or "")[:MESSAGE_SCAN_MAX]):
            return False
        if any(code not in NOT_FOUND_CODES for code in _error_codes(error)):
            return False
    return True


def parse_end_user(doc: Any) -> Dict[str, Any]:
    """One getEndUser answer to ``{"trust", "failing_checks", "found"}``. CII's
    "no such user" is ``found: False``. Any other answer with errors, or one
    without details, raises: a partial or misshapen answer is a failed query,
    never a user with no failing checks."""
    if not_found(doc):
        return {"trust": "UNKNOWN", "failing_checks": [], "found": False}
    errors = doc.get("errors") if isinstance(doc, dict) else None
    if errors:
        first = errors[0] if isinstance(errors, list) and errors else errors
        message = str(first.get("message") if isinstance(first, dict) else first)[:200]
        raise Lab5Error(f"CII query failed ({message}); spikes S5/S6 pin the query: "
                        "set cii.end_user_query in scripts/identity/personas.yaml")
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
