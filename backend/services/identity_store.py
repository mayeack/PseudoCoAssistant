"""Identity sessions: the server-side half of a Duo sign-in (Lab 5).

A signed-in browser holds one opaque cookie (``__Host-pseudoco_assistant_identity``,
backend/middleware/identity.py). Everything behind it lives here:

- The cookie value is 32 random bytes (``secrets.token_urlsafe``). Only its
  sha256 is stored (``identity_sessions.token_hash``), so reading the table or
  a backup never yields a usable cookie. The public reference used in logs and
  audit events is the row ``id``, a separate random value.
- ``lookup`` answers valid / expired / revoked / unknown from a 5 s cache, so the
  middleware does not query SQLite on every poll and SSE request. Expiry is
  checked against the clock on every call, cached or not; ``revoke`` and ``end``
  drop the cache at once.
- ``touch`` records last-seen at most once a minute per session.
- A revoked session is kept as a tombstone until it would have expired, so every
  request on it answers ``identity_session_revoked`` until the user signs in
  again (a new cookie) or signs out (``end``). ``revoke`` writes the
  ``identity_session_revoked`` audit event.
- ``purge`` deletes rows past their expiry (run from ``create``, throttled).
- ``unblock`` / ``reblock`` set and clear the session's Unblock me override
  (``unblocked_at``; plan 12.1). ``unblock`` also clears a tombstone and
  records the revocation reason it cleared (``unblock_cleared``): only an
  override that brought the session back from a Duo disable keeps the
  revocation pull off it (``IdentitySnapshot.holds_open``), and ``rearm``
  drops that once Duo has enabled the account again. A revocation ends the
  override (it ends the session). ``unblock`` / ``reblock`` each write their
  audit event (``identity_unblocked`` / ``identity_reblocked``) and none of
  these ever talks to Duo or Cisco Identity Intelligence.
- Every write drops the lookup cache, and a lookup that read the database
  before such a drop never stores its (stale) row: the cache has a generation.

Every function does blocking database work, so callers on the event loop run it
in the threadpool (the middleware uses ``run_in_threadpool``). Nothing here
talks to Duo or Cisco Identity Intelligence.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from backend.config import settings
from backend.database.db import SessionLocal, get_db_context
from backend.models.db_models import IdentitySession

logger = logging.getLogger(__name__)

#: Where an identity came from. The only source today: the Duo Universal Prompt.
SOURCE_DUO = "duo"

#: lookup() statuses.
VALID, EXPIRED, REVOKED, UNKNOWN = "valid", "expired", "revoked", "unknown"

LOOKUP_CACHE_TTL_S = 5.0
TOUCH_INTERVAL_S = 60.0
PURGE_INTERVAL_S = 600.0
_CACHE_MAX = 4096
_TOKEN_BYTES = 32
# token_urlsafe(32) is 43 characters of base64url; anything else is not ours.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_USERNAME_MAX = 128
_USER_AGENT_MAX = 512
_TTL_MINUTES_MAX = 7 * 24 * 60

_lock = threading.Lock()
# token_hash -> (fetched at, monotonic; row facts, or None for "no such token")
_cache: Dict[str, Tuple[float, Optional["_Row"]]] = {}
_touched: Dict[str, float] = {}
# Bumped by clear_cache(): a lookup that read the database under an older
# generation does not cache what it read (a revoke between the read and the
# put would otherwise be undone for LOOKUP_CACHE_TTL_S).
_generation = 0
_last_purge = 0.0


def _utcnow() -> datetime:
    """Naive UTC, the form every timestamp in this database uses."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class IdentitySnapshot:
    """What a request learns about its verified identity (``request.state.identity``).

    Frozen, and never carries the cookie or its hash."""

    session_ref: str
    username: str
    created_at: datetime
    expires_at: datetime
    source: str = SOURCE_DUO
    duo_txid: Optional[str] = None
    client_address: Optional[str] = None
    #: Set while Unblock me overrides the Identity Risk Gate for this session.
    unblocked_at: Optional[datetime] = None
    #: The revocation reason that override cleared (Unblock me turned on for a
    #: revoked session), or None (turned on for a gate block, or pre-emptively).
    unblock_cleared: Optional[str] = None

    @property
    def overridden(self) -> bool:
        return self.unblocked_at is not None

    def holds_open(self, reason: str) -> bool:
        """True while Unblock me holds this session open past a revocation for
        ``reason``: the override brought the session back from exactly that.
        An override turned on for a gate block (or before any block) holds
        nothing open, so a Duo disable still ends the session."""
        return self.overridden and self.unblock_cleared == reason

    def to_state(self) -> Dict[str, Any]:
        """The turn-state form (``identity_session``): what the chain and the
        governance evidence need, as plain data. ``override`` only while
        Unblock me is on."""
        state = {
            "session_ref": self.session_ref,
            "username": self.username,
            "source": self.source,
            "signed_in_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        if self.overridden:
            state["override"] = True
        return state


@dataclass(frozen=True)
class _Row:
    snapshot: IdentitySnapshot
    revoked_at: Optional[datetime]
    revoked_reason: Optional[str]


@dataclass(frozen=True)
class LookupResult:
    """``status`` is one of VALID / EXPIRED / REVOKED / UNKNOWN. ``identity`` is
    the session's snapshot whenever the row exists; only a VALID one may be
    attached to a request."""

    status: str
    identity: Optional[IdentitySnapshot] = None
    revoked_reason: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.status == VALID


# --------------------------------------------------------------------------- helpers
def new_token() -> str:
    """A fresh cookie value: 32 random bytes, base64url (43 characters)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """The stored form of a cookie value."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_token_shaped(token: Any) -> bool:
    """True for a value ``new_token`` could have produced. Anything else is
    answered as an unknown session without touching the database."""
    return isinstance(token, str) and _TOKEN_RE.fullmatch(token) is not None


def normalize_username(username: Any) -> str:
    """Stripped and lowercased. Duo usernames compare case-insensitively, and
    ownership checks compare these strings exactly."""
    return str(username or "").strip().lower()


def ttl_minutes() -> int:
    """``IDENTITY_SESSION_TTL_MINUTES``, clamped to 1 minute .. 7 days."""
    try:
        value = int(getattr(settings, "identity_session_ttl_minutes", 720))
    except (TypeError, ValueError):
        value = 720
    return max(1, min(_TTL_MINUTES_MAX, value))


def _row_facts(row: IdentitySession) -> _Row:
    return _Row(
        snapshot=IdentitySnapshot(
            session_ref=row.id,
            username=row.username,
            created_at=row.created_at,
            expires_at=row.expires_at,
            duo_txid=row.duo_txid,
            client_address=row.client_address,
            unblocked_at=getattr(row, "unblocked_at", None),
            unblock_cleared=getattr(row, "unblock_cleared", None),
        ),
        revoked_at=row.revoked_at,
        revoked_reason=row.revoked_reason,
    )


def _cache_put(token_hash: str, facts: Optional[_Row], generation: Optional[int] = None) -> None:
    """Cache one lookup. With ``generation`` (the value read before the
    database query), nothing is stored when ``clear_cache`` ran since."""
    with _lock:
        if generation is not None and generation != _generation:
            return
        if len(_cache) >= _CACHE_MAX:
            _cache.clear()
        _cache[token_hash] = (time.monotonic(), facts)


def clear_cache() -> None:
    """Forget every cached lookup (revocation, sign-out, tests)."""
    global _generation
    with _lock:
        _cache.clear()
        _touched.clear()
        _generation += 1


# --------------------------------------------------------------------------- API
def create(
    username: str,
    *,
    client_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    duo_txid: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Tuple[str, IdentitySnapshot]:
    """Start a session for an already-verified username.

    Returns ``(cookie value, snapshot)``. The cookie value is returned exactly
    once and never stored; set it with ``middleware.identity.set_identity_cookie``.
    Raises ValueError for an empty or over-long username."""
    name = normalize_username(username)
    if not name or len(name) > _USERNAME_MAX:
        raise ValueError("username must be 1-128 characters")
    now = now or _utcnow()
    token = new_token()
    token_hash = hash_token(token)
    row = IdentitySession(
        id=uuid.uuid4().hex,
        token_hash=token_hash,
        username=name,
        created_at=now,
        expires_at=now + timedelta(minutes=ttl_minutes()),
        last_seen_at=now,
        client_address=client_address,
        user_agent=(user_agent or None) and str(user_agent)[:_USER_AGENT_MAX],
        duo_txid=duo_txid,
    )
    with get_db_context() as db:
        db.add(row)
        db.flush()
        facts = _row_facts(row)
    _cache_put(token_hash, facts)
    with _lock:
        _touched[token_hash] = time.monotonic()
    _maybe_purge(now)
    return token, facts.snapshot


def lookup(token: Optional[str], *, now: Optional[datetime] = None) -> LookupResult:
    """Classify a cookie value. Expiry wins over revocation: a tombstone lasts
    until the session would have expired anyway. A valid session is touched
    (last-seen) at most once per ``TOUCH_INTERVAL_S``."""
    if not is_token_shaped(token):
        return LookupResult(UNKNOWN)
    token_hash = hash_token(token)
    now = now or _utcnow()
    with _lock:
        hit = _cache.get(token_hash)
        generation = _generation
    if hit is not None and time.monotonic() - hit[0] < LOOKUP_CACHE_TTL_S:
        facts = hit[1]
    else:
        db = SessionLocal()
        try:
            row = db.query(IdentitySession).filter(IdentitySession.token_hash == token_hash).first()
            facts = _row_facts(row) if row is not None else None
        finally:
            db.close()
        _cache_put(token_hash, facts, generation)
    if facts is None:
        return LookupResult(UNKNOWN)
    if now >= facts.snapshot.expires_at:
        return LookupResult(EXPIRED, facts.snapshot)
    if facts.revoked_at is not None:
        return LookupResult(REVOKED, facts.snapshot, facts.revoked_reason)
    _maybe_touch(token_hash, facts.snapshot.session_ref, now)
    return LookupResult(VALID, facts.snapshot)


def _maybe_touch(token_hash: str, session_ref: str, now: datetime) -> None:
    mono = time.monotonic()
    with _lock:
        last = _touched.get(token_hash)
        if last is not None and mono - last < TOUCH_INTERVAL_S:
            return
        if len(_touched) >= _CACHE_MAX:
            _touched.clear()
        _touched[token_hash] = mono
    try:
        with get_db_context() as db:
            db.query(IdentitySession).filter(IdentitySession.id == session_ref).update(
                {IdentitySession.last_seen_at: now}, synchronize_session=False)
    except Exception:  # noqa: BLE001 - last-seen is bookkeeping, never a request failure
        logger.debug("identity session touch failed", exc_info=True)


def get(session_ref: str) -> Optional[IdentitySnapshot]:
    """The snapshot of a session by its public reference (any status)."""
    db = SessionLocal()
    try:
        row = db.query(IdentitySession).filter(IdentitySession.id == session_ref).first()
        return _row_facts(row).snapshot if row is not None else None
    finally:
        db.close()


def revoke(session_ref: str, *, reason: str, actor: str = "system",
           now: Optional[datetime] = None) -> bool:
    """Revoke a session, keeping it as a tombstone, and write the
    ``identity_session_revoked`` audit event. Returns False when the session
    does not exist or was already revoked (no second event).

    A revocation ends the session, so it ends its Unblock me override too:
    Unblock me can then bring the session back (``unblock``), which records
    that it cleared this revocation."""
    now = now or _utcnow()
    with get_db_context() as db:
        row = db.query(IdentitySession).filter(IdentitySession.id == session_ref).first()
        if row is None or row.revoked_at is not None:
            return False
        row.revoked_at = now
        row.revoked_reason = reason
        row.unblocked_at = None
        row.unblock_cleared = None
        snapshot = _row_facts(row).snapshot
    clear_cache()
    from backend.logging import identity_audit

    identity_audit.log_session_revoked(
        username=snapshot.username,
        client_address=snapshot.client_address,
        session_ref=snapshot.session_ref,
        reason=reason,
        actor=actor,
    )
    return True


def unblock(session_ref: str, *, client_address: Optional[str] = None,
            now: Optional[datetime] = None) -> Optional[IdentitySnapshot]:
    """Unblock me (plan 12.1): override the Identity Risk Gate for this session
    and clear its tombstone, if any. Writes ``identity_unblocked`` when that
    changed anything. Returns the session's snapshot, or None when it does not
    exist or has expired. Never talks to Duo or Identity Intelligence: the
    account itself stays as Duo has it.

    Clearing a tombstone records its revocation reason (``unblock_cleared``,
    and ``details.cleared`` on the event). Only that keeps the Duo revocation
    pull off the session (``IdentitySnapshot.holds_open``): an override turned
    on for a live session, blocked by the gate or not, does not, so a later
    Duo disable still ends the session and this can bring it back."""
    now = now or _utcnow()
    with get_db_context() as db:
        row = db.query(IdentitySession).filter(IdentitySession.id == session_ref).first()
        if row is None or row.expires_at <= now:
            return None
        cleared = row.revoked_reason if row.revoked_at is not None else None
        changed = row.unblocked_at is None or row.revoked_at is not None
        if changed:
            row.unblocked_at = row.unblocked_at or now
            if cleared:
                row.unblock_cleared = cleared
            row.revoked_at = None
            row.revoked_reason = None
        snapshot = _row_facts(row).snapshot
    clear_cache()
    if changed:
        from backend.logging import identity_audit

        identity_audit.log_unblocked(username=snapshot.username,
                                     client_address=client_address or snapshot.client_address,
                                     session_ref=snapshot.session_ref, cleared=cleared)
    return snapshot


def reblock(session_ref: str, *, client_address: Optional[str] = None,
            now: Optional[datetime] = None) -> Optional[IdentitySnapshot]:
    """Turn Unblock me off: the next turn is gated again (and the Duo
    revocation pull applies again). Writes ``identity_reblocked`` when the
    override was on. Returns the snapshot, or None when the session does not
    exist or has expired."""
    now = now or _utcnow()
    with get_db_context() as db:
        row = db.query(IdentitySession).filter(IdentitySession.id == session_ref).first()
        if row is None or row.expires_at <= now:
            return None
        changed = row.unblocked_at is not None
        row.unblocked_at = None
        row.unblock_cleared = None
        snapshot = _row_facts(row).snapshot
    clear_cache()
    if changed:
        from backend.logging import identity_audit

        identity_audit.log_reblocked(username=snapshot.username,
                                     client_address=client_address or snapshot.client_address,
                                     session_ref=snapshot.session_ref)
    return snapshot


def rearm(session_ref: str) -> bool:
    """Duo reports the account enabled again: the revocation this session's
    Unblock me cleared is over, so forget it (``unblock_cleared``) and a new
    Duo disable ends the session again. The override itself stays on (the
    gate keeps recording it). Returns True when it changed anything; no audit
    event (the override did not change), and nothing is sent to Duo."""
    with get_db_context() as db:
        changed = db.query(IdentitySession).filter(
            IdentitySession.id == session_ref,
            IdentitySession.unblock_cleared.isnot(None)).update(
            {IdentitySession.unblock_cleared: None}, synchronize_session=False)
    if changed:
        clear_cache()
    return bool(changed)


def status(session_ref: str) -> Optional[LookupResult]:
    """The session's current state by its public reference (no cache)."""
    db = SessionLocal()
    try:
        row = db.query(IdentitySession).filter(IdentitySession.id == session_ref).first()
        facts = _row_facts(row) if row is not None else None
    finally:
        db.close()
    if facts is None:
        return None
    if _utcnow() >= facts.snapshot.expires_at:
        return LookupResult(EXPIRED, facts.snapshot)
    if facts.revoked_at is not None:
        return LookupResult(REVOKED, facts.snapshot, facts.revoked_reason)
    return LookupResult(VALID, facts.snapshot)


def end(token: Optional[str]) -> bool:
    """Sign-out: delete the session behind a cookie value. Returns whether one
    existed. The caller also deletes the cookie."""
    if not is_token_shaped(token):
        return False
    token_hash = hash_token(token)
    with get_db_context() as db:
        deleted = db.query(IdentitySession).filter(
            IdentitySession.token_hash == token_hash).delete(synchronize_session=False)
    clear_cache()
    return bool(deleted)


def purge(*, now: Optional[datetime] = None) -> int:
    """Delete every session past its expiry (tombstones included). Returns the count."""
    now = now or _utcnow()
    with get_db_context() as db:
        deleted = db.query(IdentitySession).filter(
            IdentitySession.expires_at <= now).delete(synchronize_session=False)
    if deleted:
        clear_cache()
    return int(deleted or 0)


def _maybe_purge(now: datetime) -> None:
    global _last_purge
    mono = time.monotonic()
    with _lock:
        if mono - _last_purge < PURGE_INTERVAL_S:
            return
        _last_purge = mono
    try:
        purge(now=now)
    except Exception:  # noqa: BLE001 - housekeeping, never a sign-in failure
        logger.warning("identity session purge failed", exc_info=True)
