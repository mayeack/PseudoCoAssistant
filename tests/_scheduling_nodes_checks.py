"""Node-level checks for tests/test_scheduling.py (imported by it — not a suite).

Drives ``scheduling_intake_node`` / ``scheduling_node`` directly with synthetic
states in both Multi-Agent modes: an in-memory store stands in for SQLite, the
LLM boundary and the governance tool-call logger are stubbed, the clock is fixed.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List

from backend.agents.llm import NormalizedLLMResponse
from backend.agents.nodes import scheduling as node_mod
from backend.models.schemas import SeverityLevel


class FakeStore:
    def __init__(self, fail=False):
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.calls: List[str] = []
        self.fail = fail
        self._n = 0

    def _check(self):
        if self.fail:
            raise RuntimeError("db down")

    def list_upcoming(self, client_id, *, theme=None, now_utc=None):
        self._check()
        return [dict(r) for r in self.rows.values()
                if r["client_id"] == client_id and r["status"] == "scheduled" and (theme is None or r["theme"] == theme)]

    def latest_name(self, client_id):
        self._check()
        names = [r["name"] for r in self.rows.values() if r["client_id"] == client_id and r["name"]]
        return names[-1] if names else None

    def book(self, *, client_id, session_id, theme, name, provider_label, start_utc, duration_minutes,
             timezone_name, notes=None):
        self._check()
        self._n += 1
        row = {"id": f"A{self._n}", "client_id": client_id, "session_id": session_id, "theme": theme, "name": name,
               "provider_label": provider_label, "start_utc": start_utc.isoformat(),
               "end_utc": (start_utc + timedelta(minutes=duration_minutes)).isoformat(),
               "duration_minutes": duration_minutes, "timezone": timezone_name, "status": "scheduled",
               "created_at": "2026-09-04T20:30:00", "updated_at": None, "notes": dict(notes or {})}
        self.rows[row["id"]] = row
        self.calls.append("book")
        return dict(row)

    def cancel(self, appointment_id, *, client_id=None):
        self._check()
        row = self.rows.get(appointment_id)
        if row is None or (client_id and row["client_id"] != client_id):
            return None
        row["status"] = "cancelled"
        self.calls.append("cancel")
        return dict(row)

    def reschedule(self, appointment_id, *, start_utc, client_id=None, timezone_name=None):
        self._check()
        row = self.rows.get(appointment_id)
        if row is None or (client_id and row["client_id"] != client_id):
            return None
        row["notes"] = {"rescheduled_from": row["start_utc"]}
        row["start_utc"] = start_utc.isoformat()
        self.calls.append("reschedule")
        return dict(row)


def run(check, sched, THEMES, slots, NOW, TZ):
    llm_calls: List[str] = []
    tool_calls: List[Dict[str, Any]] = []

    def fake_invoke(settings_, *, agent_name, system, messages, max_tokens=2048, temperature=0.7,
                    fallback_model=None, model_override=None, **_kw):
        llm_calls.append(agent_name)
        return NormalizedLLMResponse(id="r", content="Sure — here's what I set up for you.", model="fake-model",
                                     input_tokens=7, output_tokens=3, stop_reason="end_turn")

    orig_invoke, orig_now, orig_store = node_mod.invoke_agent, node_mod._now, node_mod.store
    orig_tool_call = node_mod.governance_logger.log_tool_call
    node_mod.invoke_agent = fake_invoke
    node_mod._now = lambda: NOW
    node_mod.governance_logger.log_tool_call = lambda **kw: tool_calls.append(kw)
    fake = FakeStore()
    node_mod.store = fake

    def base_state(**over):
        s = {
            "session_id": "S-sched", "request_id": "R-sched", "trace_id": "T-sched", "theme": "medadvice",
            "user_message": "I have a mild sore throat.", "conversation_history": [],
            "final_message": "**Assessment:**\nLikely a mild viral sore throat.", "severity": SeverityLevel.LOW,
            "confidence": 0.9, "start_time": 0.0, "enduser_id": "eu-1", "client_id": "c1", "client_tz": TZ,
            "llm_input_tokens": 10, "llm_output_tokens": 5,
            "agent_trace": [{"name": "medadvice_domain_agent", "role": "synthesizer"}],
        }
        s.update(over)
        return s

    def turn(**over):
        s = base_state(**over)
        s.update(node_mod.scheduling_intake_node(s))
        return s, node_mod.scheduling_node(s)

    def assistant(meta, content="ok", mtype="recommendation"):
        return {"role": "assistant", "content": content, "type": mtype, "metadata": {"scheduling": meta}}

    try:
        # --- intake -----------------------------------------------------------
        out = node_mod.scheduling_intake_node(base_state(client_id=None))
        check("intake: no client_id -> inert", out["scheduling_context"] == {"enabled": False} and out["scheduling_directive"] == "")
        s, out = turn()
        ctx = s["scheduling_context"]
        check("intake: answer turn has no action and no directive", ctx["action"] is None and s["scheduling_directive"] == "")
        check("intake: first answer detected", ctx["first_answer"] is True)

        # --- offer (single-agent) --------------------------------------------------
        med = THEMES["medadvice"].scheduling
        p = out["scheduling"]
        check("check: answer turn asks whether it resolved the concern (Yes/No chips, own bubble)",
              p["state"] == "check_resolved" and [c["action"] for c in p["actions"]] == ["resolved", "not_resolved"]
              and p["message"] == med.render("check") and p["slots"] == [])
        check("check: the answer itself is left untouched", "final_message" not in out)
        check("check: single-agent mode has no agent trace / LLM call", "agent_trace" not in out and llm_calls == [])
        _, out = turn(severity=SeverityLevel.EMERGENCY)
        check("check: medadvice EMERGENCY answer gets no follow-up", out == {})
        hist = [{"role": "user", "content": "q"}, assistant({"state": "check_resolved"}, "Did this resolve…?"), {"role": "user", "content": "still sore"}]
        _, out = turn(conversation_history=hist)
        check("check: later LOW answer does not re-ask", out == {})
        _, out = turn(conversation_history=hist, severity=SeverityLevel.HIGH)
        check("check: later HIGH answer re-asks", out.get("scheduling", {}).get("state") == "check_resolved")
        hist_declined = hist + [assistant({"state": "declined"}, "No problem."), {"role": "user", "content": "more"}]
        _, out = turn(conversation_history=hist_declined, severity=SeverityLevel.HIGH)
        check("check: declined earlier -> no re-ask", out == {})
        # "No" -> the offer with slots; "Yes" -> a warm close, no offer.
        _, out = turn(scheduling_action={"action": "not_resolved", "page": 0}, user_message="No, I still have concerns")
        p = out["scheduling"]
        check("offer after No: state offered with 3 slot chips + More times + No thanks",
              p["state"] == "offered" and [c["action"] for c in p["actions"]] == ["book", "book", "book", "more_times", "decline"])
        check("offer after No: the reply IS the offer copy", out["final_message"] == med.render("offer"))
        check("offer after No: slots are Monday's opening (fixed clock)", p["slots"][0]["label"] == slots[0].label, p["slots"][0]["label"])
        check("offer after No: more_available", p["more_available"] is True)
        _, out = turn(scheduling_action={"action": "resolved", "page": 0}, user_message="Yes, that resolved it")
        check("Yes: closes without an offer", out["scheduling"]["state"] == "resolved" and out["scheduling"]["actions"] == []
              and out["final_message"] == med.render("resolved"))

        # --- offer (multi-agent) ---------------------------------------------------
        _, out = turn(multi_agent_mode=True)
        check("MA check: fixed copy in its own bubble, no agent call",
              llm_calls == [] and out["scheduling"]["message"] == med.render("check") and "final_message" not in out
              and "agent_trace" not in out)
        check("MA check: chips still deterministic", [c["action"] for c in out["scheduling"]["actions"]] == ["resolved", "not_resolved"])
        _, out = turn(multi_agent_mode=True, scheduling_action={"action": "not_resolved", "page": 0},
                      user_message="No, I still have concerns")
        check("MA offer after No: the scheduling agent phrases it",
              llm_calls == ["medadvice_scheduling_agent"] and out["final_message"] == "Sure — here's what I set up for you.")
        check("MA offer: agent_trace ends with the scheduling agent",
              out["agent_trace"][-1]["name"] == "medadvice_scheduling_agent" and out["agent_trace"][-1]["role"] == "scheduling")
        check("MA offer: tokens summed onto the turn", out["llm_input_tokens"] == 17 and out["llm_output_tokens"] == 8)
        check("MA offer: chips still deterministic", [c["action"] for c in out["scheduling"]["actions"]][:3] == ["book"] * 3)

        # --- directives --------------------------------------------------------
        s = base_state(user_message="what's on my schedule?")
        s.update(node_mod.scheduling_intake_node(s))
        check("directive: single-agent intent turn gets the full context", "SCHEDULING CONTEXT" in s["scheduling_directive"])
        s = base_state(user_message="what's on my schedule?", multi_agent_mode=True)
        s.update(node_mod.scheduling_intake_node(s))
        check("directive: Multi-Agent intent turn gets the hand-off", "SCHEDULING HAND-OFF" in s["scheduling_directive"])

        # --- book flow ----------------------------------------------------------
        offered_meta = {"state": "offered", "page": 0, "slots": [x.as_dict() for x in slots], "pending": None, "appointments": []}
        hist = [{"role": "user", "content": "sore throat"}, assistant(offered_meta), {"role": "user", "content": "the second one"}]
        s, out = turn(conversation_history=hist, user_message="the second one", final_message="Certainly.")
        check("book: typed ordinal resolved from the prior offer", s["scheduling_context"]["action"] == {"action": "book", "slot_id": slots[1].slot_id})
        p = out["scheduling"]
        check("book: name unknown -> awaiting_name with the slot pending",
              p["state"] == "awaiting_name" and p["pending"] == {"awaiting": "name", "slot_id": slots[1].slot_id} and fake.calls == [])
        check("book: single-agent appends the ask-name copy when the model omitted it",
              med.render("ask_name", label=slots[1].label) in out["final_message"], out["final_message"])
        # The reported turn (2026-11-17): a slot chip on a browser with no saved
        # name. The domain agent was never told the time, wrote "click the
        # button above", and the "name" in its text passed the check.
        chip = {"action": "book", "slot_id": slots[1].slot_id, "page": 0}
        chip_hist = [{"role": "user", "content": "Schedule an appointment for me"}, assistant(offered_meta)]
        s = base_state(scheduling_action=chip, conversation_history=chip_hist,
                       user_message=f"Book {slots[1].label}")
        s.update(node_mod.scheduling_intake_node(s))
        d = s["scheduling_directive"]
        check("name step: the directive names the picked time", f"picked: {slots[1].label}" in d, d)
        check("name step: the directive says it is held, not booked, and that the user types the name",
              "NOT booked" in d and "no button" in d, d)
        bad = ("Book your appointment by clicking the button above.\n"
               "Please provide the name you'd like to use for this booking.")
        _, out = turn(scheduling_action=chip, conversation_history=chip_hist,
                      user_message=f"Book {slots[1].label}", final_message=bad)
        check("name step: a reply without the held time is replaced by the copy",
              out.get("final_message") == med.render("ask_name", label=slots[1].label)
              and out["scheduling"]["state"] == "awaiting_name" and fake.calls == [], str(out.get("final_message")))
        good = f"I'm holding {slots[1].label} for your follow-up visit. What name should I put it under?"
        _, out = turn(scheduling_action=chip, conversation_history=chip_hist,
                      user_message=f"Book {slots[1].label}", final_message=good)
        check("name step: a reply that says the time and asks for the name is kept", "final_message" not in out,
              str(out.get("final_message")))
        _, out = turn(scheduling_action=chip, conversation_history=chip_hist, multi_agent_mode=True,
                      user_message=f"Book {slots[1].label}", final_message="Acknowledged.")
        check("name step (Multi-Agent): wording without the held time falls back to the copy",
              out["final_message"] == med.render("ask_name", label=slots[1].label)
              and out["agent_trace"][-1]["name"] == "medadvice_scheduling_agent", str(out.get("final_message")))
        # The reported bug: "Saturday at 8am" against Friday/Monday slots used to
        # book the matching clock time on the WRONG day. Now it asks.
        s, out = turn(conversation_history=[{"role": "user", "content": "q"}, assistant(offered_meta),
                                            {"role": "user", "content": "Can you do Saturday at 8am?"}],
                      user_message="Can you do Saturday at 8am?", final_message="Sure.")
        q = out["scheduling"]
        check("intent: a day we don't book asks instead of booking",
              q["state"] == "clarify_slot" and fake.calls == [] and all(c["action"] != "book" or c["slot_id"] for c in q["actions"]))
        check("intent: it says why Saturday isn't available and names the booking days",
              "Saturday" in out["final_message"] and "Monday to Friday" in out["final_message"], out["final_message"])
        check("intent: it offers the closest bookable times as buttons",
              [c["action"] for c in q["actions"]] == ["book", "book", "book", "more_times", "decline"]
              and all("Sat" not in c["text"] for c in q["actions"][:3]), str([c["text"] for c in q["actions"]]))
        check("intent: picking one of those buttons books it",
              turn(scheduling_action={"action": "book", "slot_id": q["slots"][0]["slot_id"], "page": 0},
                   conversation_history=[assistant(q)])[1]["scheduling"]["state"] in ("booked", "awaiting_name"))

        hist2 = hist + [assistant(p, "What name?"), {"role": "user", "content": "Alex Rivera"}]
        s, out = turn(conversation_history=hist2, user_message="Alex Rivera", final_message="Booked.")
        p = out["scheduling"]
        check("book: bare name completes the booking", p["state"] == "booked" and fake.calls == ["book"] and p["appointment"]["name"] == "Alex Rivera")
        check("book: label is the chosen slot", p["appointment"]["label"] == slots[1].label, p["appointment"]["label"])
        check("book: schedule_appointment tool call logged with identity",
              tool_calls and tool_calls[-1]["tool_name"] == "schedule_appointment" and tool_calls[-1]["agent_surface"] == "scheduling"
              and tool_calls[-1]["tool_decision"] == "allow")
        check("book: confirmation appended (label missing from model text)", slots[1].label in out["final_message"])
        s, out = turn(scheduling_action={"action": "book", "slot_id": slots[2].slot_id, "page": 0},
                      final_message=f"Done — you're booked for {slots[2].label}.")
        check("book: chip action wins and the remembered name is reused", out["scheduling"]["state"] == "booked" and out["scheduling"]["appointment"]["name"] == "Alex Rivera")
        check("book: no duplicate confirmation when the model already said it", "final_message" not in out)
        _, out = turn(scheduling_action={"action": "book", "slot_id": "20200101T1200Z", "page": 0})
        check("book: stale slot id -> re-present slots", out["scheduling"]["state"] == "choosing" and med.render("slot_unavailable") in out["final_message"])

        # --- list / cancel / reschedule ---------------------------------------------
        _, out = turn(user_message="what's on my schedule?", final_message="Here you go.")
        p = out["scheduling"]
        check("list: both appointments with Reschedule/Cancel chips",
              p["state"] == "listed" and len(p["appointments"]) == 2 and [c["action"] for c in p["actions"]] == ["reschedule", "cancel"] * 2)
        check("list: labels in the text", slots[1].label in out["final_message"] and slots[2].label in out["final_message"])
        _, out = turn(scheduling_action={"action": "cancel", "appointment_id": "A1", "page": 0})
        check("cancel: chip cancels and logs", out["scheduling"]["state"] == "cancelled" and fake.rows["A1"]["status"] == "cancelled"
              and tool_calls[-1]["tool_name"] == "cancel_appointment")
        _, out = turn(scheduling_action={"action": "reschedule", "appointment_id": "A2", "page": 0}, multi_agent_mode=True)
        p = out["scheduling"]
        check("reschedule: no slot yet -> slots with the target pending",
              p["state"] == "rescheduling" and p["pending"] == {"awaiting": "slot", "reschedule_id": "A2"}
              and all(c["appointment_id"] == "A2" for c in p["actions"] if c["action"] == "reschedule"))
        _, out = turn(scheduling_action={"action": "reschedule", "appointment_id": "A2", "slot_id": slots[0].slot_id, "page": 0})
        check("reschedule: with a slot moves it and logs", out["scheduling"]["state"] == "rescheduled"
              and fake.rows["A2"]["start_utc"] == slots[0].start_utc.isoformat() and tool_calls[-1]["tool_name"] == "reschedule_appointment")
        _, out = turn(user_message="cancel", final_message="Which?")
        check("cancel: single upcoming targeted by typed text", out["scheduling"]["state"] == "cancelled" and fake.rows["A2"]["status"] == "cancelled")
        _, out = turn(scheduling_action={"action": "cancel", "page": 0})
        check("cancel: nothing scheduled -> none_scheduled copy", out["scheduling"]["state"] == "listed" and med.render("none_scheduled") in out["final_message"])
        _, out = turn(scheduling_action={"action": "decline", "page": 0})
        check("decline: recorded", out["scheduling"]["state"] == "declined")
        _, out = turn(scheduling_action={"action": "more_times", "page": 1})
        check("more_times: page 1 slots", out["scheduling"]["page"] == 1 and out["scheduling"]["slots"][0]["time"] == "9:00 AM")

        # already booked on a first answer
        fake.book(client_id="c1", session_id="S", theme="medadvice", name="Alex Rivera", provider_label="x",
                  start_utc=slots[0].start_utc, duration_minutes=20, timezone_name=TZ)
        _, out = turn()
        check("already booked: first answer says so in its own bubble, answer untouched",
              out["scheduling"]["state"] == "already_booked" and slots[0].label in out["scheduling"]["message"]
              and "final_message" not in out)

        # --- degradation ---------------------------------------------------------
        node_mod.store = FakeStore(fail=True)
        s, out = turn(user_message="what's on my schedule?")
        check("store down: intake degrades (store_ok False) and the turn survives", s["scheduling_context"]["store_ok"] is False
              and out["scheduling"]["state"] == "unavailable" and med.render("unavailable") in out["final_message"])
        node_mod.store = fake

        # --- shared-chain touches -----------------------------------------------
        from backend.agents.nodes.safety import safety_node
        from backend.agents.nodes.clarify import intake_node
        from backend.agents.blueprints.pseudoco_multi_agent import _route_after_intake
        from backend.agents.blueprints.nvidia_virtual_assistant import make_primary_assistant
        intent_state = base_state(user_message="I want to see a doctor, please cancel my appointment",
                                  scheduling_context={"enabled": True, "action": {"action": "cancel"}})
        check("safety: scheduling-intent turn does not escalate", safety_node(intent_state) == {"should_escalate": False, "escalation_reasons": []})
        check("clarify: scheduling-intent turn asks nothing", intake_node(intent_state) == {})
        check("core: scheduling-intent turn skips the specialists (Multi-Agent on)",
              _route_after_intake(dict(intent_state, multi_agent_mode=True)) == "synthesizer")
        pa = make_primary_assistant(THEMES["medadvice"])(dict(intent_state, multi_agent_mode=True))
        check("nvidia core: scheduling-intent turn routes to no sub-assistant without a model call",
              pa["selected_specialists"] == [] and pa["blueprint_route"]["mode"] == "scheduling")
    finally:
        node_mod.invoke_agent = orig_invoke
        node_mod._now = orig_now
        node_mod.store = orig_store
        node_mod.governance_logger.log_tool_call = orig_tool_call
