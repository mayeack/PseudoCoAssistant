"""The Identity Risk Gate's decision (Lab 5, plan 12.1 and PR-3): pure, no I/O.

``decide(status)`` turns one ``identity_lookup.lookup`` answer into the turn's
verdict. **Block** when any of these is known:

- the Duo account is disabled, locked out or pending deletion, or Duo has no
  such user;
- Cisco Identity Intelligence rates the user ``UNTRUSTED``;
- the user currently fails CII's **MFA Flood** or **Impossible Travel** check.
  CII's API lists only *current* ``failingChecks``; a failure stays current for
  7 days after its last observation. Trusted personas are kept out of false
  blocks by their CII exclusions, not by anything here.

**Allow** otherwise (a ``QUESTIONABLE`` user is allowed; the badge shows it).

**Unavailable** (either source could not answer about the user): the verdict
says ``check: "unavailable"``. With ``IDENTITY_FAIL_OPEN`` (the default, A3)
the turn is allowed; with it off the turn is blocked as not verifiable. A block
that rests on what *was* learned wins over either: a disabled Duo account is
a block even while CII is down, and a CII block holds while Duo is down (the
lookup asks CII with the email Duo last gave). "No such user" is an answer,
not an outage: a user CII has no record of yet is checked (``ok``) and,
with nothing against it, allowed.

The verdict is data for the node, the governance events and the badge. The
override (Unblock me) is applied by the caller, never here, so every event
can carry the real verdict next to ``identity_override``.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping

ALLOW, BLOCK = "allow", "block"
CHECK_OK, CHECK_UNAVAILABLE = "ok", "unavailable"

#: Duo account statuses that block a turn, with their reason codes.
BLOCKING_DUO_STATUSES = {
    "disabled": "duo_disabled",
    "locked_out": "duo_locked_out",
    "pending_deletion": "duo_pending_deletion",
}
DUO_NOT_FOUND = "duo_user_not_found"
TRUST_UNTRUSTED = "trust_untrusted"
IDENTITY_UNAVAILABLE = "identity_unavailable"
#: CII checks that block, matched on the check name with everything but
#: letters and digits removed ("MFA Flood", "mfa_flood", "MFA-FLOOD" all match).
BLOCKING_CHECKS = (("mfaflood", "mfa_flood"), ("impossibletravel", "impossible_travel"))

#: Every reason code, with the words the block banner uses for it.
REASON_TEXT = {
    "duo_disabled": "your Duo account is disabled",
    "duo_locked_out": "your Duo account is locked out",
    "duo_pending_deletion": "your Duo account is pending deletion",
    DUO_NOT_FOUND: "Duo has no such account",
    TRUST_UNTRUSTED: "your trust level is Untrusted",
    "mfa_flood": "your account is failing the MFA Flood check",
    "impossible_travel": "your account is failing the Impossible Travel check",
    IDENTITY_UNAVAILABLE: "your identity could not be verified",
}


def _checks(value: Any) -> List[str]:
    return [str(c) for c in value if isinstance(c, str)] if isinstance(value, (list, tuple)) else []


def decide(status: Mapping[str, Any], *, fail_open: bool = True) -> Dict[str, Any]:
    """The verdict for one lookup answer (``identity_lookup.lookup``)."""
    status = status if isinstance(status, Mapping) else {}
    sources = status.get("sources") if isinstance(status.get("sources"), Mapping) else {}
    duo_status = status.get("duo_status") or None
    trust_level = str(status.get("trust_level") or "").upper() or None
    failing = _checks(status.get("failing_checks"))

    reasons: List[str] = []
    if duo_status in BLOCKING_DUO_STATUSES:
        reasons.append(BLOCKING_DUO_STATUSES[duo_status])
    elif sources.get("duo") == "not_found":
        reasons.append(DUO_NOT_FOUND)
    if trust_level == "UNTRUSTED":
        reasons.append(TRUST_UNTRUSTED)
    for check in failing:
        flat = re.sub(r"[^a-z0-9]", "", check.lower())
        for needle, reason in BLOCKING_CHECKS:
            if needle in flat and reason not in reasons:
                reasons.append(reason)

    available = bool(status.get("available"))
    if reasons:
        verdict = BLOCK
    elif not available and not fail_open:
        verdict, reasons = BLOCK, [IDENTITY_UNAVAILABLE]
    else:
        verdict = ALLOW
    return {
        "verdict": verdict,
        "reasons": reasons,
        "check": CHECK_OK if available else CHECK_UNAVAILABLE,
        "duo_status": duo_status,
        "trust_level": trust_level,
        "failing_checks": failing,
        "as_of": status.get("as_of"),
    }


def unverified_only(verdict: Mapping[str, Any]) -> bool:
    """True for a fail-closed block: nothing bad is known, the identity just
    could not be verified (its banner and category are neutral)."""
    return list(verdict.get("reasons") or []) == [IDENTITY_UNAVAILABLE]


def reasons_text(verdict: Mapping[str, Any]) -> str:
    """The block reasons in words, joined ('' without reasons)."""
    words = [REASON_TEXT.get(r, r.replace("_", " ")) for r in verdict.get("reasons") or []]
    if len(words) > 1:
        return ", ".join(words[:-1]) + " and " + words[-1]
    return words[0] if words else ""
