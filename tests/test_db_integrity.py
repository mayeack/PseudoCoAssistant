"""Persistence and concurrency integrity of the SQLite path.

Covers the three data-loss defects found by the ultracode review:

  F20  StaticPool handed the SAME sqlite3 connection to every Session, so
       concurrent event-loop and threadpool writers interleaved transactions on
       one connection and could commit or roll back each other's work.
  F25  Conversation.messages is a plain JSON column (no MutableList). Resuming a
       conversation from the DB stored the ORM-loaded list BY REFERENCE and
       mutated it in place, so SQLAlchemy compared the attribute against itself,
       saw no change, and omitted it from the UPDATE — losing that turn.
  F27  EscalationRules.should_escalate accumulated onto shared instance state,
       so concurrent turns could clobber each other's escalation reasons.

Standalone (no pytest required), mirroring tests/test_tool_guard.py:
    venv/bin/python tests/test_db_integrity.py

Side-effect-safe: every check runs against a temp SQLite file, never the app's
medadvice.db. DATABASE_URL is redirected BEFORE backend.database.db is imported.
"""
import os
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.config  # noqa: F401  (sets SSL_CERT_FILE / loads .env)

# Point the engine at a throwaway database before it is constructed at import.
_tmpdir = tempfile.mkdtemp(prefix="pseudoco-assistant-dbtest-")
_dbfile = os.path.join(_tmpdir, "integrity.db")
from backend.config import settings  # noqa: E402

settings.database_url = f"sqlite:///{_dbfile}"

from backend.database import db as dbmod  # noqa: E402
from backend.models.db_models import Base, Conversation  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


check("temp DB in use (never the app's medadvice.db)",
      _dbfile in str(dbmod.engine.url), str(dbmod.engine.url))
Base.metadata.create_all(bind=dbmod.engine)

# 1. The file-backed SQLite engine must NOT share one connection -------------
# StaticPool returns the same DBAPI connection to every checkout; the default
# pool gives each Session its own. Two concurrently-open sessions are the test.
s1, s2 = dbmod.SessionLocal(), dbmod.SessionLocal()
try:
    c1 = s1.connection().connection.dbapi_connection
    c2 = s2.connection().connection.dbapi_connection
    check("file-backed sqlite: concurrent sessions get distinct connections",
          c1 is not c2, f"{c1!r} vs {c2!r}")
finally:
    s1.close()
    s2.close()

# In-memory SQLite must still share, or each connection is a new empty DB.
_saved_url = settings.database_url
settings.database_url = "sqlite:///:memory:"
try:
    mem_engine = dbmod.create_db_engine()
    from sqlalchemy.pool import StaticPool

    check("in-memory sqlite: still StaticPool (shared connection)",
          isinstance(mem_engine.pool, StaticPool), type(mem_engine.pool).__name__)
finally:
    settings.database_url = _saved_url

# 2. A concurrent writer must not lose rows under interleaved commits --------
# Each thread opens its own session (as the governance writer does via
# get_db_context) and commits its own row. With one shared connection these
# commits interleave and rows can be lost or error out.
WRITERS, PER_WRITER = 8, 5
errors = []


def _writer(n):
    for i in range(PER_WRITER):
        try:
            with dbmod.get_db_context() as s:
                s.add(Conversation(session_id=f"w{n}-msg{i}", messages=[],
                                   disclaimer_accepted=True, escalated=False))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"w{n}-{i}: {exc}")


threads = [threading.Thread(target=_writer, args=(n,)) for n in range(WRITERS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

check("concurrent writers: no exceptions", not errors, "; ".join(errors[:3]))
with dbmod.get_db_context() as s:
    written = s.query(Conversation).filter(
        Conversation.session_id.like("w%-msg%")).count()
check("concurrent writers: every row persisted",
      written == WRITERS * PER_WRITER, f"{written} of {WRITERS * PER_WRITER}")

# 3. In-place JSON mutation is invisible to SQLAlchemy (the F25 mechanism) ---
# Demonstrates WHY _prepare_session must copy: with a plain JSON column and no
# MutableList, mutating the loaded list in place and assigning it back compares
# the attribute against itself, so `messages` is omitted from the UPDATE.
# (The end-to-end guard for the real chat path is the resume-after-restart check
# in tests/test_api.py — this one pins the ORM behavior the fix depends on.)
with dbmod.get_db_context() as s:
    s.add(Conversation(session_id="alias-me",
                       messages=[{"role": "user", "content": "first"}],
                       disclaimer_accepted=True, escalated=False))

with dbmod.get_db_context() as s:
    row = s.query(Conversation).filter(Conversation.session_id == "alias-me").first()
    aliased = row.messages          # BY REFERENCE — the old _prepare_session
    aliased.append({"role": "assistant", "content": "second"})
    row.messages = aliased          # same object back in — no detectable change

with dbmod.get_db_context() as s:
    row = s.query(Conversation).filter(Conversation.session_id == "alias-me").first()
    aliased_len = len(row.messages or [])

# Now the copying pattern the fix uses, on a fresh row.
with dbmod.get_db_context() as s:
    s.add(Conversation(session_id="copy-me",
                       messages=[{"role": "user", "content": "first"}],
                       disclaimer_accepted=True, escalated=False))

with dbmod.get_db_context() as s:
    row = s.query(Conversation).filter(Conversation.session_id == "copy-me").first()
    copied = list(row.messages or [])            # COPY — the fixed load
    copied.append({"role": "assistant", "content": "second"})
    same = s.query(Conversation).filter(Conversation.session_id == "copy-me").first()
    check("copy: identity map returns the same instance (bug precondition)",
          same is row)
    same.messages = list(copied)                 # distinct object

with dbmod.get_db_context() as s:
    row = s.query(Conversation).filter(Conversation.session_id == "copy-me").first()
    msgs = row.messages or []
    check("copy: appended turn was persisted", len(msgs) == 2, f"len={len(msgs)}")
    check("copy: both messages present in order",
          [m.get("content") for m in msgs] == ["first", "second"],
          str([m.get("content") for m in msgs]))
    check("copy pattern persists where the alias pattern did not",
          len(msgs) > aliased_len, f"copy={len(msgs)} alias={aliased_len}")

# 4. EscalationRules must not return shared instance state (F27) -------------
# The contamination mechanism: `self.escalation_reasons = []` REBINDS, so a turn
# already inside should_escalate keeps appending through self.* and lands its
# reasons in the newer turn's list — then returns that same object. The
# invariant that makes it impossible is simply that the returned list is not the
# instance attribute. Asserting the invariant is deterministic; asserting the
# race is not.
from backend.models.schemas import SeverityLevel  # noqa: E402
from backend.services.escalation_rules import EscalationRules  # noqa: E402

shared = EscalationRules()   # the singleton pattern both call sites use
_, reasons_a = shared.should_escalate(
    conversation_history=[{"role": "user", "content": "I have chest pain"}],
    severity=SeverityLevel.EMERGENCY, user_input="I have chest pain", ai_confidence=0.9,
)
check("escalation: returned list is NOT shared instance state",
      reasons_a is not shared.escalation_reasons)
check("escalation: emergency turn reports its own reasons",
      any("Emergency" in r or "severity" in r for r in reasons_a), str(reasons_a))

_, reasons_b = shared.should_escalate(
    conversation_history=[{"role": "user", "content": "my wifi is slow"}],
    severity=SeverityLevel.LOW, user_input="my wifi is slow", ai_confidence=0.9,
)
check("escalation: a later turn returns a distinct list", reasons_a is not reasons_b)
check("escalation: benign turn inherits nothing", reasons_b == [], str(reasons_b))
check("escalation: earlier result survives the later turn untouched",
      any("Emergency" in r or "severity" in r for r in reasons_a), str(reasons_a))

# Concurrency smoke: many turns through the one shared instance, each keeping
# its own verdict.
_conc = {}


def _turn(tag, user_input, severity):
    _, rs = shared.should_escalate(
        conversation_history=[{"role": "user", "content": user_input}],
        severity=severity, user_input=user_input, ai_confidence=0.9,
    )
    _conc[tag] = rs


_ts = []
for i in range(6):
    emergency = i % 2 == 0
    _ts.append(threading.Thread(target=_turn, args=(
        f"t{i}",
        "I have chest pain" if emergency else "my wifi is slow",
        SeverityLevel.EMERGENCY if emergency else SeverityLevel.LOW,
    )))
for t in _ts:
    t.start()
for t in _ts:
    t.join()
check("escalation: concurrent benign turns stay empty",
      all(_conc[f"t{i}"] == [] for i in range(6) if i % 2),
      str({k: v for k, v in _conc.items() if v}))

# 5. Governance JSONL writes are serialized across threads (F29) -------------
# Concurrent writers used to be able to interleave halves of two JSON objects,
# corrupting the file Splunk ingests. Every line must still parse.
import json as _json  # noqa: E402

from backend.logging.log_handlers import GovernanceFileHandler  # noqa: E402

_logdir = tempfile.mkdtemp(prefix="pseudoco-assistant-logtest-")
_handler = GovernanceFileHandler(logs_dir=_logdir)
_big = "x" * 20000          # well past one atomic write


def _spam(n):
    for i in range(15):
        _handler.write_governance_log(
            {"event_id": f"e{n}-{i}", "who": n, "seq": i, "payload": _big}
        )


_ts = [threading.Thread(target=_spam, args=(n,)) for n in range(8)]
for t in _ts:
    t.start()
for t in _ts:
    t.join()

_gov = Path(_logdir) / "ai_governance.json"
_lines = [l for l in _gov.read_text().splitlines() if l.strip()]
_bad = []
for l in _lines:
    try:
        _json.loads(l)
    except ValueError as exc:
        _bad.append(str(exc)[:60])
check("jsonl: every concurrently-written line parses", not _bad,
      f"{len(_bad)} corrupt of {len(_lines)}: {_bad[:2]}")
check("jsonl: no events lost", len(_lines) == 8 * 15, f"{len(_lines)} of {8 * 15}")

# 6. setup_logging is idempotent — no duplicate console handlers (F57) -------
import logging as _logging  # noqa: E402

from backend.logging.log_handlers import setup_logging  # noqa: E402

setup_logging()
_first = len(_logging.getLogger("governance").handlers)
setup_logging()
setup_logging()
_after = len(_logging.getLogger("governance").handlers)
check("logging: repeated setup_logging adds no extra handlers",
      _after == _first, f"{_first} -> {_after}")

# 7. appointments (docs/scheduling.md): the table comes from create_all (no
#    migration) and concurrent bookings through the store all persist.
from datetime import datetime as _dt  # noqa: E402
from sqlalchemy import inspect as _sa_inspect  # noqa: E402

from backend.services.scheduling import store as _appt_store  # noqa: E402

check("appointments: table created by create_all", "appointments" in set(_sa_inspect(dbmod.engine).get_table_names()))
_appt_errs = []


def _book_one(i):
    try:
        _appt_store.book(client_id="c-integrity", session_id=f"s{i}", theme="medadvice", name=f"n{i}",
                         provider_label="Clinician follow-up visit", start_utc=_dt(2030, 1, 1, 12, i),
                         duration_minutes=20, timezone_name="UTC")
    except Exception as exc:  # noqa: BLE001
        _appt_errs.append(str(exc)[:80])


_bts = [threading.Thread(target=_book_one, args=(i,)) for i in range(8)]
for t in _bts:
    t.start()
for t in _bts:
    t.join()
check("appointments: concurrent bookings raise nothing", not _appt_errs, str(_appt_errs[:2]))
check("appointments: every concurrent booking persisted",
      len(_appt_store.list_all(client_id="c-integrity", status="all", limit=100)) == 8)
check("appointments: cancel then upcoming excludes it",
      (lambda rows: _appt_store.cancel(rows[0]["id"]) is not None
       and len(_appt_store.list_upcoming("c-integrity", now_utc=_dt(2029, 1, 1))) == 7)(
          _appt_store.list_all(client_id="c-integrity", limit=100)))

# 8. Lab 5 identity: identity_sessions comes from create_all; audit_logs gains
#    enduser_id, and reconcile_schema (bare columns only) is followed by
#    ensure_indexes, so an existing database gets the column AND its index.
from sqlalchemy import create_engine as _create_engine  # noqa: E402
from sqlalchemy import text as _text  # noqa: E402

_insp = _sa_inspect(dbmod.engine)
check("identity: identity_sessions created by create_all", "identity_sessions" in set(_insp.get_table_names()))
check("identity: identity_sessions stores the token hash, never a token column",
      {"token_hash", "username", "expires_at", "revoked_at", "revoked_reason", "duo_txid", "user_agent",
       "client_address", "last_seen_at"} <= {c["name"] for c in _insp.get_columns("identity_sessions")}
      and not any(c["name"] == "token" for c in _insp.get_columns("identity_sessions")))
check("identity: a fresh audit_logs has enduser_id + ix_audit_logs_enduser_id",
      "enduser_id" in {c["name"] for c in _insp.get_columns("audit_logs")}
      and "ix_audit_logs_enduser_id" in {i["name"] for i in _insp.get_indexes("audit_logs")})

_old_file = os.path.join(_tmpdir, "pre-4.22.db")
_old = _create_engine(f"sqlite:///{_old_file}")
with _old.begin() as _conn:   # the pre-4.22 shape: no enduser_id
    _conn.execute(_text(
        "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, audit_id VARCHAR NOT NULL, session_id VARCHAR NOT NULL, "
        "request_id VARCHAR NOT NULL, timestamp DATETIME NOT NULL, action VARCHAR NOT NULL, actor VARCHAR NOT NULL, "
        "details JSON NOT NULL, ip_address VARCHAR)"))
_added = dbmod.reconcile_schema(_old)
check("identity: reconcile_schema adds audit_logs.enduser_id to an existing database",
      ("audit_logs", "enduser_id") in _added, str(_added))
check("identity: ensure_indexes creates its index there",
      dbmod.ensure_indexes(_old) == ["ix_audit_logs_enduser_id"]
      and "ix_audit_logs_enduser_id" in {i["name"] for i in _sa_inspect(_old).get_indexes("audit_logs")})
check("identity: ensure_indexes is idempotent", dbmod.ensure_indexes(_old) == ["ix_audit_logs_enduser_id"])
_old.dispose()

from backend.logging.governance_logger import governance_logger as _gl  # noqa: E402
from backend.logging.log_schemas import create_audit_log as _cal  # noqa: E402
from backend.models.db_models import AuditLog as _AuditLog  # noqa: E402

_gl._write_audit_to_db(_cal(audit_id="aud-identity-1", session_id="identity-ref1", request_id="r1",
                            action="identity_signin_success", actor="user", details={"duo_txid": "t1"},
                            ip_address="203.0.113.7", enduser_id="nina.osei"))
with dbmod.get_db_context() as s:
    _row = s.query(_AuditLog).filter(_AuditLog.audit_id == "aud-identity-1").first()
    check("identity: _write_audit_to_db maps enduser_id (and keeps ip_address)",
          _row is not None and _row.enduser_id == "nina.osei" and _row.ip_address == "203.0.113.7")

# Cleanup: drop the temp database entirely.
dbmod.engine.dispose()
try:
    os.remove(_dbfile)
    os.remove(_old_file)
    os.rmdir(_tmpdir)
except OSError:
    pass

print()
if _failures:
    print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
    sys.exit(1)
print("All DB-integrity checks passed.")
