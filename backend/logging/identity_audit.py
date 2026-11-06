"""Identity audit events (Lab 5): sign-in success and failure, session revocation.

Written through ``governance_logger.log_audit`` like every other audit event, so
they reach the JSONL file, SQLite (``audit_logs``, with ``enduser_id``) and every
HEC destination as ``log_type=audit``:

- ``user`` is the username and ``src`` the client IP: ``create_audit_log`` copies
  them from ``enduser_id`` / ``ip_address`` (``log_schemas.cim_identity``);
- ``details`` carries Duo's transaction id and the trust level only, plus a
  fixed reason code on a failure or a revocation. Never the location, device or
  IP that Duo saw;
- ``session_id`` is synthetic and never null (the ``audit_logs`` column is NOT
  NULL, and these events belong to no chat session): ``identity-<session ref>``
  for a session's events, a fresh ``identity-<random>`` for a failed sign-in;
- ``user`` / ``enduser_id`` stay in the event body only. The HEC forwarder never
  promotes them to indexed fields (that double-counted every ``stats ... by``).

Every value that reaches an event is shape-checked here, because a sign-in
failure carries whatever username was typed.
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SIGNIN_SUCCESS = "identity_signin_success"
SIGNIN_FAILURE = "identity_signin_failure"
SESSION_REVOKED = "identity_session_revoked"
ACTIONS = frozenset({SIGNIN_SUCCESS, SIGNIN_FAILURE, SESSION_REVOKED})

#: The only keys an identity audit event's ``details`` may carry.
DETAIL_KEYS = frozenset({"duo_txid", "trust_level", "reason"})

_REASON_RE = re.compile(r"[a-z0-9_]{1,64}")
_TXID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_TRUST_RE = re.compile(r"[A-Za-z_]{1,32}")
_USERNAME_MAX = 128


def audit_session_id(session_ref: Optional[str] = None) -> str:
    """The synthetic, non-null ``session_id`` of an identity audit event."""
    ref = str(session_ref or "").strip()
    return f"identity-{ref if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', ref) else uuid.uuid4().hex}"


def _username(value: Any) -> Optional[str]:
    """Lowercased, control characters removed, bounded; None when empty."""
    text = "".join(ch for ch in str(value or "") if ch.isprintable()).strip().lower()
    return text[:_USERNAME_MAX] or None


def build_details(*, duo_txid: Any = None, trust_level: Any = None, reason: Any = None) -> Dict[str, str]:
    """``details`` for an identity event: only well-formed values of DETAIL_KEYS."""
    details: Dict[str, str] = {}
    if duo_txid and _TXID_RE.fullmatch(str(duo_txid)):
        details["duo_txid"] = str(duo_txid)
    if trust_level and _TRUST_RE.fullmatch(str(trust_level)):
        details["trust_level"] = str(trust_level).upper()
    if reason:
        details["reason"] = str(reason) if _REASON_RE.fullmatch(str(reason)) else "other"
    return details


def log_identity_event(
    action: str,
    *,
    username: Any,
    client_address: Optional[str],
    session_ref: Optional[str] = None,
    actor: str = "user",
    duo_txid: Any = None,
    trust_level: Any = None,
    reason: Any = None,
    request_id: Optional[str] = None,
) -> bool:
    """Write one identity audit event. Returns False when logging failed: an
    audit write never breaks a sign-in or a request."""
    if action not in ACTIONS:
        raise ValueError(f"not an identity audit action: {action!r}")
    from backend.logging.governance_logger import governance_logger

    try:
        governance_logger.log_audit(
            session_id=audit_session_id(session_ref),
            request_id=request_id or str(uuid.uuid4()),
            action=action,
            actor=actor,
            details=build_details(duo_txid=duo_txid, trust_level=trust_level, reason=reason),
            ip_address=client_address or None,
            enduser_id=_username(username),
        )
    except Exception:  # noqa: BLE001
        logger.warning("identity audit event %s could not be logged", action, exc_info=True)
        return False
    return True


def log_signin_success(*, username: Any, client_address: Optional[str], session_ref: str,
                       duo_txid: Any = None, trust_level: Any = None,
                       request_id: Optional[str] = None) -> bool:
    return log_identity_event(SIGNIN_SUCCESS, username=username, client_address=client_address,
                              session_ref=session_ref, duo_txid=duo_txid, trust_level=trust_level,
                              request_id=request_id)


def log_signin_failure(*, username: Any, client_address: Optional[str], reason: str,
                       duo_txid: Any = None, request_id: Optional[str] = None) -> bool:
    return log_identity_event(SIGNIN_FAILURE, username=username, client_address=client_address,
                              reason=reason, duo_txid=duo_txid, request_id=request_id)


def log_session_revoked(*, username: Any, client_address: Optional[str], session_ref: str,
                        reason: str, actor: str = "system",
                        request_id: Optional[str] = None) -> bool:
    return log_identity_event(SESSION_REVOKED, username=username, client_address=client_address,
                              session_ref=session_ref, actor=actor, reason=reason,
                              request_id=request_id)
