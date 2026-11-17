"""Appointment scheduling regression suite (docs/scheduling.md).

Covers the deterministic service (slots, labels, intent parsing, the offer
policy, the appointment store) and the two pipeline nodes
(``scheduling_intake`` / ``scheduling``) in both Multi-Agent modes.

Standalone (no pytest required):
    venv/bin/python tests/test_scheduling.py

Side-effect-safe: the store runs against a temp SQLite file (DATABASE_URL is
redirected BEFORE backend.database.db is imported, as test_db_integrity.py
does); the LLM boundary and the governance logger are stubbed.
"""
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
# Survives backend.config's .env load (which only sets keys not already present).
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: F401,E402  (sets SSL_CERT_FILE / loads .env)
from backend.config import settings  # noqa: E402

_tmpdir = tempfile.mkdtemp(prefix="pseudoco-assistant-schedtest-")
settings.database_url = f"sqlite:///{os.path.join(_tmpdir, 'sched.db')}"
settings.prewarm_llm = False
settings.scheduling_default_timezone = "America/New_York"

from backend.database import db as dbmod  # noqa: E402
from backend.models.db_models import Base  # noqa: E402

Base.metadata.create_all(bind=dbmod.engine)

from backend.agents.themes import THEMES  # noqa: E402
from backend.services import scheduling as sched  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


check("temp DB in use (never the app's medadvice.db)", _tmpdir in str(dbmod.engine.url), str(dbmod.engine.url))
check("appointments table exists after create_all",
      "appointments" in Base.metadata.tables and dbmod.engine.dialect.has_table(dbmod.engine.connect(), "appointments"))

# --- per-theme profiles ---------------------------------------------------------
for key, theme in THEMES.items():
    check(f"{key}: has a scheduling profile", isinstance(theme.scheduling, sched.SchedulingProfile))
    check(f"{key}: offer copy renders without stray placeholders", "{" not in theme.scheduling.render("offer"))
    check(f"{key}: confirmation copy renders",
          "{" not in theme.scheduling.render("confirmed", label="Mon Sep 7, 8:00 AM", name="Alex"))
    ask = theme.scheduling.render("ask_name", label="Mon Sep 7, 8:00 AM")
    check(f"{key}: the name question names the held time and asks for a name",
          "{" not in ask and "Mon Sep 7, 8:00 AM" in ask and "name" in ask.lower(), ask)
check("medadvice never offers on an EMERGENCY first answer",
      "EMERGENCY" in THEMES["medadvice"].scheduling.first_offer_excludes)
check("telecom books 2-hour arrival windows", THEMES["telecomchatbot"].scheduling.window_minutes == 120)
check("profiles differ per theme (verticalized)",
      len({t.scheduling.provider_label for t in THEMES.values()}) == len(THEMES))

# --- slots (fixed clock) ---------------------------------------------------------
med = THEMES["medadvice"].scheduling
TZ = "America/New_York"
NOW = datetime(2026, 9, 4, 20, 30)  # Fri 2026-09-04 16:30 EDT; lead 2h is past closing
slots = sched.suggest_slots(med, now_utc=NOW, tz=TZ)
check("3 slots per page", len(slots) == 3, str(len(slots)))
check("rolls past the weekend to Monday's opening", slots[0].label == "Mon Sep 7, 8:00 AM", slots[0].label)
check("slot_id is the UTC start", slots[0].slot_id == "20260907T1200Z", slots[0].slot_id)
check("20-minute steps", slots[1].time == "8:20 AM" and slots[2].time == "8:40 AM", f"{slots[1].time}/{slots[2].time}")
page2 = sched.suggest_slots(med, now_utc=NOW, tz=TZ, page=1)
check("page 1 continues where page 0 stopped", page2[0].time == "9:00 AM", page2[0].time)
check("resolve_slot round-trips a suggested id",
      sched.resolve_slot(med, slots[0].slot_id, now_utc=NOW, tz=TZ).label == slots[0].label)
check("resolve_slot rejects the past", sched.resolve_slot(med, "20200101T1200Z", now_utc=NOW) is None)
check("resolve_slot rejects garbage", sched.resolve_slot(med, "not-a-slot", now_utc=NOW) is None)
same = sched.suggest_slots(med, now_utc=datetime(2026, 9, 7, 13, 0), tz=TZ)  # Mon 9:00 EDT
check("same-day slots start after the lead time", same[0].label == "Mon Sep 7, 11:00 AM", same[0].label)
dst = sched.suggest_slots(med, now_utc=datetime(2026, 10, 30, 12, 0), tz=TZ, page=20)
check("slots across the DST change still render", len(dst) == 3 and all(s.label for s in dst))
tel = THEMES["telecomchatbot"].scheduling
win = sched.suggest_slots(tel, now_utc=NOW, tz=TZ)
check("telecom offers Saturday arrival windows", win[0].label == "Sat Sep 5, 8:00 AM–10:00 AM", win[0].label)
check("windows step by the window length", win[1].time == "10:00 AM", win[1].time)
check("labels fall back to the configured zone", sched.label_for(med, datetime(2026, 9, 7, 13, 0)) == "Mon Sep 7, 9:00 AM")
check("unknown tz falls back to the configured zone", sched.resolve_tz("Not/AZone").key == "America/New_York")
check("is_valid_tz", sched.is_valid_tz("Europe/London") and not sched.is_valid_tz("nope"))

# --- offer policy -----------------------------------------------------------------
def offer(profile=med, **kw):
    base = dict(severity="LOW", first_answer=True, declined=False, has_upcoming=False)
    base.update(kw)
    return sched.should_offer(profile, **base)


check("first answer at LOW offers", offer() == "offer")
check("first answer EMERGENCY (medadvice) does not offer", offer(severity="EMERGENCY") == "none")
check("later LOW answer does not re-offer", offer(first_answer=False) == "none")
check("later HIGH answer re-offers", offer(first_answer=False, severity="HIGH") == "offer")
check("declined: no re-offer", offer(first_answer=False, severity="HIGH", declined=True) == "none")
check("already booked: first answer says so", offer(has_upcoming=True) == "already_booked")
check("already booked: later answers stay quiet", offer(first_answer=False, severity="HIGH", has_upcoming=True) == "none")
check("severity enum accepted", offer(severity=__import__("backend.models.schemas", fromlist=["SeverityLevel"]).SeverityLevel.EMERGENCY) == "none")
check("telecom re-offers only from HIGH", offer(tel, first_answer=False, severity="MEDIUM") == "none"
      and offer(tel, first_answer=False, severity="HIGH") == "offer")

# --- intent parsing ---------------------------------------------------------------
sd = [s.as_dict() for s in slots]
offered = {"state": "offered", "page": 0, "slots": sd, "pending": None, "appointments": []}
P = sched.parse_action
check("typed ordinal picks the second slot", P("the second one please", offered, []) == {"action": "book", "slot_id": slots[1].slot_id})
check("typed time picks the slot", (P("8:40 works", offered, []) or {}).get("slot_id") == slots[2].slot_id)
check("typed am time picks the slot", (P("book 8am", offered, []) or {}).get("slot_id") == slots[0].slot_id)
check("'more times' pages forward", P("can you show me other times?", offered, []) == {"action": "more_times", "page": 1})
check("decline after an offer", P("no thanks", offered, []) == {"action": "decline"})
check("accept after an offer", P("yes please", offered, []) == {"action": "accept", "page": 0})
check("unrelated text while offering is not scheduling", P("my throat still hurts", offered, []) is None)
# A named day is BINDING — "Saturday at 8am" must never book Friday/Monday 8:00 AM.
check("a named day we didn't offer never matches", P("Can you do Saturday at 8am?", offered, []) ==
      {"action": "clarify_slot", "pref": {"weekday": 5, "minute_of_day": 480}})
check("the offered day + its time matches exactly",
      (P("Monday at 8am works", offered, []) or {}).get("slot_id") == slots[0].slot_id)
check("a day with several offered slots is ambiguous -> clarify",
      (P("how about Monday?", offered, []) or {}).get("action") == "clarify_slot")
check("a time we didn't offer -> clarify, never the nearest",
      (P("can you do 3pm?", offered, []) or {}).get("action") == "clarify_slot")
check("match_slot refuses a day we didn't offer", sched.match_slot("Saturday at 8am", sd) is None)
check("match_slot still takes an exact offered time", sched.match_slot("8:20", sd)["slot_id"] == slots[1].slot_id)
# The preference parser: a bare number is not a time.
pt = sched.parse_time_preference
check("preference: day + time", pt("Can you do Saturday at 8am?").as_dict() == {"weekday": 5, "minute_of_day": 480})
check("preference: day only", pt("how about tuesday").as_dict() == {"weekday": 1, "minute_of_day": None})
check("preference: time only", pt("does 2:30 pm work").as_dict() == {"weekday": None, "minute_of_day": 870})
check("preference: 'at 3' means the afternoon", pt("at 3").minute_of_day == 15 * 60)
check("preference: a bare count is not a time", pt("it's been 2 days now").expressed is False)
check("preference: no day/time expressed", pt("my throat still hurts").expressed is False)
check("preference label reads back", pt("Saturday at 8am").label == "Saturday at 8:00 AM")
# Best-guess candidates for what they asked for.
sat = sched.TimePreference(weekday=5, minute_of_day=480)
med_cands = sched.slots_for_preference(med, sat, now_utc=NOW, tz=TZ)
check("medadvice doesn't book Saturday -> nearest bookable times instead",
      all(s.weekday != 5 for s in med_cands) and med_cands[0].label == slots[0].label, str(med_cands[0].label))
tax_cands = sched.slots_for_preference(THEMES["taxadvice"].scheduling, sat, now_utc=NOW, tz=TZ)
check("taxadvice books Saturday -> Saturday candidates", all(s.weekday == 5 for s in tax_cands) and len(tax_cands) == 3,
      str([s.label for s in tax_cands]))
check("business-days label", sched.business_days_label(med) == "Monday to Friday"
      and sched.business_days_label(THEMES["taxadvice"].scheduling) == "Monday to Saturday")

checked = {"state": "check_resolved", "page": 0, "slots": [], "pending": None, "appointments": []}
check("'no' to the resolved check -> not_resolved", P("No, not really", checked, []) == {"action": "not_resolved", "page": 0})
check("'still' to the resolved check -> not_resolved", P("still hurts", checked, []) == {"action": "not_resolved", "page": 0})
check("'yes' to the resolved check -> resolved", P("Yes, that helped, thanks", checked, []) == {"action": "resolved"})
check("a new question after the check is not scheduling", P("What about my headache?", checked, []) is None)
pending_name = {"state": "awaiting_name", "page": 0, "slots": [], "appointments": [],
                "pending": {"awaiting": "name", "slot_id": slots[0].slot_id}}
check("bare name while awaiting one", P("Alex Rivera", pending_name, []) == {"action": "book", "slot_id": slots[0].slot_id, "name": "Alex Rivera"})
check("'my name is' prefix stripped", (P("my name is Sam Lee.", pending_name, []) or {}).get("name") == "Sam Lee")
check("a question while awaiting a name is not a name", P("what does that cost?", pending_name, []) is None)
check("decline while awaiting a name", P("no thanks", pending_name, []) == {"action": "decline"})
check("list intent", P("what's on my schedule?", None, []) == {"action": "list"})
check("list intent (upcoming)", P("do I have any upcoming appointments", None, []) == {"action": "list"})
check("book intent from scratch", P("can you schedule an appointment for me", None, []) == {"action": "accept", "page": 0})
appt = {"id": "A1", "day": "Mon Sep 7", "time": "8:00 AM"}
check("cancel targets the only upcoming", P("please cancel my appointment", None, [appt]) == {"action": "cancel", "appointment_id": "A1"})
check("reschedule targets the only upcoming", P("I need to reschedule", None, [appt]) == {"action": "reschedule", "appointment_id": "A1"})
two = [appt, {"id": "A2", "day": "Tue Sep 8", "time": "9:00 AM"}]
check("cancel with two picks by weekday", (P("cancel the tuesday one", None, two) or {}).get("appointment_id") == "A2")
check("cancel with two and no hint has no target", P("cancel", None, two) == {"action": "cancel", "appointment_id": None})
resched = {"state": "rescheduling", "page": 0, "slots": sd, "appointments": [],
           "pending": {"awaiting": "slot", "reschedule_id": "A1"}}
check("slot pick while rescheduling", P("the first one", resched, [appt]) == {"action": "reschedule", "appointment_id": "A1", "slot_id": slots[0].slot_id})
check("more times while rescheduling keeps the target",
      P("show me more times", resched, [appt]) == {"action": "more_times", "page": 1, "appointment_id": "A1"})
check("a plain question is not scheduling", P("I have a mild sore throat", None, []) is None)
check("empty text is not scheduling", P("   ", offered, []) is None)

# --- store (temp DB) --------------------------------------------------------------
S = sched.store
a = S.book(client_id="c-test", session_id="s1", theme="medadvice", name="Alex",
           provider_label=med.provider_label, start_utc=slots[0].start_utc, duration_minutes=20,
           timezone_name=TZ, notes={"request_id": "r1"})
check("book returns the row", a["status"] == "scheduled" and bool(a["id"]) and a["notes"] == {"request_id": "r1"})
check("get finds it", (S.get(a["id"]) or {}).get("id") == a["id"])
check("upcoming lists it", [x["id"] for x in S.list_upcoming("c-test", now_utc=NOW)] == [a["id"]])
check("upcoming is per client", S.list_upcoming("someone-else", now_utc=NOW) == [])
check("latest_name remembers the name", S.latest_name("c-test") == "Alex")
check("describe adds the local label", sched.describe(a, med, tz=TZ)["label"] == slots[0].label)
r = S.reschedule(a["id"], start_utc=slots[2].start_utc, client_id="c-test", timezone_name=TZ)
check("reschedule moves it and records the old time",
      r["start_utc"] == slots[2].start_utc.isoformat() and r["notes"]["rescheduled_from"] == slots[0].start_utc.isoformat())
check("reschedule refuses another client's id", S.reschedule(a["id"], start_utc=slots[1].start_utc, client_id="x") is None)
c = S.cancel(a["id"], client_id="c-test")
check("cancel flips the status", (c or {}).get("status") == "cancelled")
check("cancelled rows leave upcoming", S.list_upcoming("c-test", now_utc=NOW) == [])
check("list_all(all) still shows it", len(S.list_all(client_id="c-test", status="all")) == 1)
check("list_all(scheduled) hides it", S.list_all(client_id="c-test") == [])
check("cancel unknown id -> None", S.cancel("nope") is None)
check("delete_for_client cleans up", S.delete_for_client("c-test") == 1)

# --- nodes (added with backend/agents/nodes/scheduling.py) ------------------------
try:
    from tests._scheduling_nodes_checks import run as _run_node_checks  # type: ignore
except ImportError:
    _run_node_checks = None
if _run_node_checks is not None:
    _run_node_checks(check, sched, THEMES, slots, NOW, TZ)

print()
if _failures:
    print(f"RESULT: {len(_failures)} failed")
    for f in _failures:
        print(f"  - {f}")
    sys.exit(1)
print("RESULT: ok")
