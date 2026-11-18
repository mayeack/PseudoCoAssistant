"""PatchBot persistence: estates, Change Board records and the activity feed.

Thin SQLAlchemy helpers over the three PatchBot tables. Every function opens
its own short session (``get_db_context`` commits or rolls back), so callers on
the event loop wrap them in ``run_in_threadpool``. A per-owner lock serializes
read-modify-write of one estate document.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.database.db import get_db_context
from backend.models.db_models import PatchbotActivity, PatchbotChange, PatchbotEstate
from backend.patchbot import estate as est

_locks: Dict[str, threading.RLock] = {}
_locks_guard = threading.Lock()
_change_guard = threading.Lock()


def owner_lock(owner: str) -> threading.RLock:
    with _locks_guard:
        lock = _locks.get(owner)
        if lock is None:
            lock = _locks[owner] = threading.RLock()
        return lock


# --------------------------------------------------------------------------- estates

def load_estate(owner: str) -> Dict[str, Any]:
    """The owner's estate, seeded on first use."""
    with get_db_context() as db:
        row = db.get(PatchbotEstate, owner)
        if row is None:
            state = est.seed_state()
            db.add(PatchbotEstate(owner=owner, state=state))
            return state
        state = est.ensure_schema(row.state)
        if state is not row.state:
            row.state = state
        return state


def save_estate(owner: str, state: Dict[str, Any]) -> None:
    with get_db_context() as db:
        row = db.get(PatchbotEstate, owner)
        if row is None:
            db.add(PatchbotEstate(owner=owner, state=state))
        else:
            row.state = state
            row.updated_at = datetime.utcnow()


def reset_estate(owner: str) -> Dict[str, Any]:
    state = est.seed_state()
    save_estate(owner, state)
    with get_db_context() as db:
        db.query(PatchbotActivity).filter(PatchbotActivity.owner == owner).delete()
        db.query(PatchbotChange).filter(PatchbotChange.owner == owner,
                                        PatchbotChange.status.in_(("draft", "awaiting_approval"))) \
            .update({"status": "withdrawn"}, synchronize_session=False)
    return state


# --------------------------------------------------------------------------- activity

def add_activity(owner: str, kind: str, text: str, *, actor: Optional[str] = None,
                 actor_type: str = "agent", finding_id: Optional[str] = None,
                 data: Optional[Dict[str, Any]] = None) -> None:
    with get_db_context() as db:
        db.add(PatchbotActivity(owner=owner, kind=kind, text=text[:1000], actor=actor,
                                actor_type=actor_type, finding_id=finding_id, data=data or {}))


def list_activity(owner: str, *, finding_id: Optional[str] = None, limit: int = 60) -> List[Dict[str, Any]]:
    with get_db_context() as db:
        q = db.query(PatchbotActivity).filter(PatchbotActivity.owner == owner)
        if finding_id:
            q = q.filter(PatchbotActivity.finding_id == finding_id)
        rows = q.order_by(PatchbotActivity.created_at.desc(), PatchbotActivity.id.desc()).limit(limit).all()
        return [{"id": r.id, "kind": r.kind, "text": r.text, "actor": r.actor, "actor_type": r.actor_type,
                 "finding_id": r.finding_id, "data": r.data or {},
                 "at": r.created_at.replace(microsecond=0).isoformat() + "Z"} for r in rows]


# --------------------------------------------------------------------------- changes

def _change_dict(r: PatchbotChange) -> Dict[str, Any]:
    iso = lambda d: (d.replace(microsecond=0).isoformat() + "Z") if d else None  # noqa: E731
    return {"id": r.id, "owner": r.owner, "requested_by": r.requested_by, "requester_role": r.requester_role,
            "status": r.status, "cve": r.cve, "finding_id": r.finding_id, "servers": list(r.servers or []),
            "environment": r.environment, "window_start": iso(r.window_start), "window_end": iso(r.window_end),
            "plan": r.plan, "priority": r.priority, "investigation_id": r.investigation_id,
            "approver": r.approver, "approver_role": r.approver_role, "decided_at": iso(r.decided_at),
            "decision_note": r.decision_note, "created_at": iso(r.created_at), "updated_at": iso(r.updated_at)}


def create_change(**fields: Any) -> Dict[str, Any]:
    with _change_guard:
        with get_db_context() as db:
            n = db.query(PatchbotChange).count()
            change_id = f"CHG-{1001 + n}"
            while db.get(PatchbotChange, change_id) is not None:
                n += 1
                change_id = f"CHG-{1001 + n}"
            row = PatchbotChange(id=change_id, **fields)
            db.add(row)
            db.flush()
            return _change_dict(row)


def get_change(change_id: str) -> Optional[Dict[str, Any]]:
    with get_db_context() as db:
        row = db.get(PatchbotChange, change_id)
        return _change_dict(row) if row else None


def update_change(change_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    with get_db_context() as db:
        row = db.get(PatchbotChange, change_id)
        if row is None:
            return None
        for k, v in fields.items():
            setattr(row, k, v)
        row.updated_at = datetime.utcnow()
        db.flush()
        return _change_dict(row)


def list_changes(*, owner: Optional[str] = None, statuses: Optional[List[str]] = None,
                 limit: int = 100) -> List[Dict[str, Any]]:
    with get_db_context() as db:
        q = db.query(PatchbotChange)
        if owner:
            q = q.filter(PatchbotChange.owner == owner)
        if statuses:
            q = q.filter(PatchbotChange.status.in_(statuses))
        return [_change_dict(r) for r in q.order_by(PatchbotChange.created_at.desc()).limit(limit).all()]


def open_change_for(owner: str, cve: str, environment: str = "production") -> Optional[Dict[str, Any]]:
    """The newest change for this CVE that is not finished."""
    for c in list_changes(owner=owner, statuses=["draft", "awaiting_approval", "approved"]):
        if c["cve"] == cve and c["environment"] == environment:
            return c
    return None
