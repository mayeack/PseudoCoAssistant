"""Appointment scheduling nodes (docs/scheduling.md).

Two nodes in the SHARED guardrail chain (blueprints/guardrails.py), so both
blueprints get scheduling by construction:

- ``scheduling_intake_node`` — last PRE node. Deterministic, no LLM, never
  ``terminal``: resolves the client, parses the turn's scheduling action (a
  chip's structured action wins over typed text), loads the client's
  appointments, generates candidate slots, and writes the prompt directive the
  domain agent receives (``scheduling_directive``).
- ``scheduling_node`` — POST node between ``injection`` and ``compliance``, so
  its text is part of the logged ``response_text`` and still passes
  ``agent_control -> nemo_output_rails -> response_defense``. It executes the
  action (book / cancel / reschedule / list / page slots), decides whether to
  offer on an answer turn, appends the deterministic scheduling copy to
  ``final_message`` and leaves the structured payload (``scheduling``) the
  router returns and persists as ``metadata.scheduling``.

Multi-Agent Mode ON: the POST node runs as the ``{theme}_scheduling_agent`` —
its own AgentInvocation span, an LLM call for the conversational wording (the
internal model, short output), an ``agent_trace`` entry, tokens summed onto the
turn — and executes bookings under that span. OFF: no separate agent; the
domain agent wrote the scheduling reply itself from the full directive, and
this node only executes the action and attaches the payload (appending copy
only when the model omitted the key fact).

Never raises: an exception escaping a node replaces the whole turn with the
generic safety warning (graph.py), so every store call degrades to
``state="unavailable"`` instead.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.agents.llm import ChatModelError, invoke_agent
from backend.agents.nodes.agent_common import request_model, trace_entry
from backend.agents.state import governance_identity_overrides
from backend.agents.themes import get_theme
from backend.agents.token_usage import TokenTally
from backend.config import settings
from backend.logging.governance_logger import governance_logger
from backend.services import scheduling as svc
from backend.services.scheduling import (
    TOOL_CANCEL,
    TOOL_RESCHEDULE,
    TOOL_SCHEDULE,
    SchedulingProfile,
)
from backend.telemetry import otel

logger = logging.getLogger(__name__)

AGENT_SURFACE = "scheduling"
_SCHEDULING_AGENT_MAX_TOKENS = 160

# The store is looked up through the module so a test can swap it
# (``nodes.scheduling.store = Fake()``) without touching the service.
store = svc.store


def _now() -> datetime:
    return datetime.utcnow()


# --------------------------------------------------------------------------- helpers
def _last_scheduling_meta(history: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """``metadata.scheduling`` of the most recent assistant message (the current
    user message is already appended to the history, so walk backwards)."""
    for msg in reversed(history or []):
        role = getattr(msg.get("role"), "value", msg.get("role"))
        if role == "assistant":
            meta = msg.get("metadata") or {}
            sched = meta.get("scheduling") if isinstance(meta, dict) else None
            return sched if isinstance(sched, dict) else None
    return None


def _session_scheduling_history(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What the session already did: whether an answer was given, an offer made,
    a decline recorded, a booking made — all read from persisted metadata so it
    survives restarts and Show Recent reloads."""
    answered = offered = declined = booked = False
    for msg in history or []:
        role = getattr(msg.get("role"), "value", msg.get("role"))
        if role != "assistant":
            continue
        mtype = getattr(msg.get("type"), "value", msg.get("type"))
        if mtype in ("recommendation", "escalation"):
            answered = True
        meta = msg.get("metadata") or {}
        sched = meta.get("scheduling") if isinstance(meta, dict) else None
        if not isinstance(sched, dict):
            continue
        state = sched.get("state")
        if state in ("check_resolved", "offered", "choosing", "awaiting_name", "already_booked"):
            offered = True
        if state == "declined":
            declined = True
        if state in ("booked", "rescheduled"):
            booked = True
    return {"answered": answered, "offered": offered, "declined": declined, "booked": booked}


def _action_chip(action: str, text: str, **extra: Any) -> Dict[str, Any]:
    chip = {"action": action, "text": text}
    chip.update({k: v for k, v in extra.items() if v is not None})
    return chip


def _slot_chips(slots: List[Dict[str, Any]], *, page: int, reschedule_id: Optional[str] = None,
                decline: bool = True) -> List[Dict[str, Any]]:
    chips = []
    for s in slots:
        if reschedule_id:
            chips.append(_action_chip("reschedule", s["label"], slot_id=s["slot_id"], appointment_id=reschedule_id))
        else:
            chips.append(_action_chip("book", s["label"], slot_id=s["slot_id"]))
    chips.append(_action_chip("more_times", "More times", page=page + 1, appointment_id=reschedule_id))
    if decline:
        chips.append(_action_chip("decline", "No thanks"))
    return chips


def _appointment_chips(appointments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chips = []
    for a in appointments:
        chips.append(_action_chip("reschedule", f"Reschedule {a['label']}", appointment_id=a["id"]))
        chips.append(_action_chip("cancel", f"Cancel {a['label']}", appointment_id=a["id"]))
    return chips


def _payload(profile: SchedulingProfile, theme: str, state_name: str, **fields: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "state": state_name,
        "theme": theme,
        "appointment_noun": profile.appointment_noun,
        "page": 0,
        "more_available": False,
        "slots": [],
        "pending": None,
        "appointments": [],
        "appointment": None,
        "actions": [],
        # Answer-turn scheduling copy the UI shows as its OWN assistant bubble
        # (with the chips under it) — the resolved check, the already-booked
        # note. Scheduling text is never appended to the answer itself.
        "message": None,
    }
    payload.update(fields)
    return payload


def _describe_all(appointments: List[Dict[str, Any]], profile: SchedulingProfile, tz: Optional[str]) -> List[Dict[str, Any]]:
    return [svc.describe(a, profile, tz) for a in appointments]


# --------------------------------------------------------------------------- directive
def build_scheduling_directive(profile: SchedulingProfile, ctx: Dict[str, Any], *, multi_agent: bool) -> str:
    """Prompt tail for the domain agent on a scheduling-intent turn.

    Single-agent: the FULL picture, because that one agent writes the whole
    reply. Multi-Agent: a hand-off, because the scheduling agent follows it.
    Answer turns (no intent) get nothing: the offer is deterministic copy.
    """
    action = (ctx.get("action") or {}).get("action")
    if not action:
        return ""
    if multi_agent:
        return (
            "\n\n--- SCHEDULING HAND-OFF ---\n"
            f"The user's latest message is about scheduling {profile.a_noun} "
            f"(request: {action}). A dedicated scheduling agent handles it right after you. "
            "Reply with ONE brief sentence acknowledging the request inside your normal "
            "answer format; do not propose, confirm or list any times or appointments."
        )
    lines = [
        "\n\n--- SCHEDULING CONTEXT ---",
        f"You also handle appointments. The user's latest message is a scheduling request ({action}) "
        f"for {profile.a_noun} with {profile.provider_noun}. Respond to it briefly inside your normal "
        "answer format (a sentence or two in the main answer field); keep any domain advice to one "
        "sentence. Never invent times or appointments: use only the facts below. The exact options "
        "are shown to the user as buttons, so do not enumerate them.",
    ]
    slots = ctx.get("slots") or []
    if slots:
        lines.append("Times being offered: " + "; ".join(s["label"] for s in slots) + ".")
    upcoming = ctx.get("upcoming") or []
    if upcoming:
        lines.append("Their scheduled " + profile.noun_plural + ": "
                     + "; ".join(f"{a['label']} ({a.get('name') or 'no name'})" for a in upcoming) + ".")
    else:
        lines.append(f"They have no {profile.noun_plural} scheduled.")
    chosen = ctx.get("chosen_label")
    if chosen:
        lines.append(f"The time the user picked: {chosen}.")
    if action == "book" and not ctx.get("name_known") and not (ctx.get("action") or {}).get("name"):
        # A chip click lands here on a browser that has never booked: nothing
        # is booked yet. Without the time and the "not booked" fact the model
        # used to invent a "click the button above" step that does not exist.
        lines.append(
            (f"{chosen} is held but NOT booked yet" if chosen else "The booking is not made yet")
            + ": a name is needed first. Say the time and ask what name to put it under. "
            "There is no button for this step: the user types the name."
        )
    if ctx.get("pending"):
        lines.append(f"Pending step: {ctx['pending']}.")
    return "\n".join(lines)


def build_scheduling_agent_prompt(profile: SchedulingProfile, theme_label: str, outcome: Dict[str, Any]) -> str:
    """System prompt for the ``{theme}_scheduling_agent`` (Multi-Agent Mode)."""
    facts = outcome.get("facts") or []
    return (
        f"You are the scheduling agent on the {theme_label} assistant team. You book "
        f"{profile.noun_plural} with {profile.provider_noun}. Write ONE or TWO short, warm "
        "sentences to the user that convey exactly the outcome below — nothing else. "
        "Do not list times or add options: they are shown as buttons. Do not invent details. "
        "No greetings, no sign-off, no markdown.\n\n"
        f"Outcome: {outcome.get('summary', '')}\n"
        + ("Facts: " + " ".join(facts) + "\n" if facts else "")
    )


# --------------------------------------------------------------------------- PRE node
def scheduling_intake_node(state: Dict[str, Any]) -> Dict[str, Any]:
    client_id = state.get("client_id")
    if not client_id:
        return {"scheduling_context": {"enabled": False}, "scheduling_directive": ""}

    theme_key = state.get("theme") or "medadvice"
    theme_config = get_theme(theme_key)
    profile = theme_config.scheduling
    tz = state.get("client_tz") if svc.is_valid_tz(state.get("client_tz")) else None
    history = state.get("conversation_history", []) or []
    last_meta = _last_scheduling_meta(history)
    now = _now()

    try:
        upcoming_raw = store.list_upcoming(client_id, theme=theme_key, now_utc=now)
        name_known = bool(store.latest_name(client_id))
        store_ok = True
    except Exception:  # noqa: BLE001 - degrade, never fail the turn
        logger.exception("scheduling intake: store unavailable")
        upcoming_raw, name_known, store_ok = [], False, False
    upcoming = _describe_all(upcoming_raw, profile, tz)

    action = state.get("scheduling_action")
    if isinstance(action, dict) and action.get("action"):
        action = dict(action)
    else:
        action = svc.parse_action(state.get("user_message", ""), last_meta, upcoming)

    page = int((action or {}).get("page") or 0)
    slots: List[Dict[str, Any]] = []
    if action and action.get("action") in ("accept", "more_times", "choose_slot") or (
        action and action.get("action") == "reschedule" and not action.get("slot_id")
    ):
        slots = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=page)]
    # The slot a chip (or a typed pick) chose, so the domain agent can name it.
    chosen_label = None
    if action and action.get("action") in ("book", "reschedule") and action.get("slot_id"):
        chosen = svc.resolve_slot(profile, action.get("slot_id"), now_utc=now, tz=tz)
        chosen_label = chosen.label if chosen else None

    hist = _session_scheduling_history(history)
    ctx = {
        "enabled": True,
        "store_ok": store_ok,
        "client_id": client_id,
        "tz": tz,
        "action": action,
        "page": page,
        "slots": slots,
        "chosen_label": chosen_label,
        "upcoming": upcoming,
        "pending": (last_meta or {}).get("pending"),
        "last_state": (last_meta or {}).get("state"),
        "last_slots": list((last_meta or {}).get("slots") or []),
        "name_known": name_known,
        "first_answer": not hist["answered"],
        "offered_before": hist["offered"],
        "declined": hist["declined"],
    }
    directive = build_scheduling_directive(profile, ctx, multi_agent=state.get("multi_agent_mode") is True)
    return {"scheduling_context": ctx, "scheduling_directive": directive}


# --------------------------------------------------------------------------- mutations
def _record_mutation(state: Dict[str, Any], tool_name: str, arguments: Dict[str, Any],
                     appointment: Optional[Dict[str, Any]]) -> None:
    """execute_tool span + tool_call governance event for a booking mutation —
    the tool-guard shape (routers/toolguard.py), so it lands in the governance
    UI, SQLite and Splunk like an OpenClaw tool call."""
    call_id = (appointment or {}).get("id")
    with otel.tool_span(tool_name, tool_call_id=call_id, agent_surface=AGENT_SURFACE) as span:
        otel.record_tool_result(span, decision="allow")
    try:
        governance_logger.log_tool_call(
            session_id=state["session_id"],
            request_id=state["request_id"],
            tool_name=tool_name,
            tool_decision="allow",
            tool_call_id=call_id,
            tool_arguments=str(arguments),
            agent_surface=AGENT_SURFACE,
            enduser_id=state.get("enduser_id"),
            **governance_identity_overrides(state),
        )
    except Exception:  # noqa: BLE001 - logging must never break the turn
        logger.exception("scheduling: tool_call governance logging failed")


def _execute(state: Dict[str, Any], profile: SchedulingProfile, theme_key: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Run the turn's scheduling action (or the offer policy) and return the
    outcome: the payload plus the deterministic copy and facts for the agent."""
    client_id = ctx["client_id"]
    tz = ctx.get("tz")
    now = _now()
    action = ctx.get("action") or {}
    kind = action.get("action")
    upcoming = ctx.get("upcoming") or []
    page = int(ctx.get("page") or 0)

    def present(slots: List[Dict[str, Any]], *, state_name: str, text: str, pending=None,
                reschedule_id: Optional[str] = None, page_no: int = page) -> Dict[str, Any]:
        more = bool(svc.suggest_slots(profile, now_utc=now, tz=tz, page=page_no + 1))
        return {
            "payload": _payload(profile, theme_key, state_name, page=page_no, slots=slots, more_available=more,
                                pending=pending, appointments=upcoming,
                                actions=_slot_chips(slots, page=page_no, reschedule_id=reschedule_id,
                                                    decline=reschedule_id is None)),
            "text": text,
            "summary": text,
            "facts": [f"Options offered: {', '.join(s['label'] for s in slots)}."] if slots else [],
        }

    if not kind:
        verdict = svc.should_offer(profile, severity=state.get("severity"), first_answer=ctx.get("first_answer", True),
                                   declined=ctx.get("declined", False), has_upcoming=bool(upcoming))
        if verdict == "offer":
            # Not the offer yet: first ask, in a separate bubble, whether the
            # answer resolved the concern. The offer follows a "no".
            text = profile.render("check")
            return {"payload": _payload(profile, theme_key, "check_resolved", appointments=upcoming, message=text,
                                        actions=[_action_chip("resolved", profile.render("check_yes")),
                                                 _action_chip("not_resolved", profile.render("check_no"))]),
                    "text": text, "summary": text,
                    "facts": ["Ask ONLY whether the answer resolved their concern (yes/no buttons are shown); "
                              "do not mention appointments or times yet."]}
        if verdict == "already_booked":
            label = upcoming[0]["label"]
            text = profile.render("already_booked", label=label)
            return {"payload": _payload(profile, theme_key, "already_booked", appointments=upcoming,
                                        actions=_appointment_chips(upcoming)),
                    "text": text, "summary": text, "facts": []}
        return {"payload": None, "text": "", "summary": "", "facts": []}

    if kind == "not_resolved":
        slots = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=0)]
        out = present(slots, state_name="offered", text=profile.render("offer"), page_no=0)
        out["facts"].append("The user said the concern is NOT resolved; invite them to book.")
        return out

    if kind == "resolved":
        text = profile.render("resolved")
        return {"payload": _payload(profile, theme_key, "resolved", appointments=upcoming),
                "text": text, "summary": "The user said the concern is resolved; close warmly, no offer.",
                "facts": [f"They can schedule {profile.a_noun} anytime by asking."]}

    if kind == "clarify_slot":
        # The user named a day/time we could not resolve to exactly one offered
        # slot ("Saturday at 8am" against Friday slots). Never guess: show what
        # they most likely meant as buttons and let them pick.
        pref = svc.preference_from_dict(action.get("pref"))
        pending_prev = ctx.get("pending") or {}
        reschedule_id = action.get("appointment_id") or (
            pending_prev.get("reschedule_id") if pending_prev.get("awaiting") == "slot" else None)
        cands = [s.as_dict() for s in svc.slots_for_preference(profile, pref, now_utc=now, tz=tz)]
        if not cands:
            cands = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=0)]
        day_bookable = pref.weekday is None or pref.weekday in profile.business_days
        if day_bookable:
            text = profile.render("clarify_slot", asked=pref.label)
        else:
            text = profile.render("day_unavailable", day=svc.weekday_label(pref.weekday),
                                  days=svc.business_days_label(profile))
        out = present(cands, state_name="clarify_slot", text=text, page_no=0,
                      pending={"awaiting": "slot", "reschedule_id": reschedule_id} if reschedule_id else None,
                      reschedule_id=reschedule_id)
        out["facts"].append(
            f"They asked for {pref.label}." + ("" if day_bookable else
            f" {profile.noun_plural.capitalize()} are only booked {svc.business_days_label(profile)}, "
            f"so {svc.weekday_label(pref.weekday)} is not available — say so and offer the closest times."))
        return out

    if kind in ("accept", "more_times", "choose_slot"):
        slots = ctx.get("slots") or []
        pending_prev = ctx.get("pending") or {}
        reschedule_id = action.get("appointment_id") or (
            pending_prev.get("reschedule_id") if pending_prev.get("awaiting") == "slot" else None)
        if not slots:
            slots = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=page)]
        pending = {"awaiting": "slot", "reschedule_id": reschedule_id} if reschedule_id else None
        return present(slots, state_name="rescheduling" if reschedule_id else "choosing",
                       text=profile.render("choose"), pending=pending, reschedule_id=reschedule_id)

    if kind == "decline":
        text = profile.render("declined")
        return {"payload": _payload(profile, theme_key, "declined", appointments=upcoming),
                "text": text, "summary": text, "facts": []}

    if kind == "list":
        if not upcoming:
            text = profile.render("none_scheduled")
            slots = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=0)]
            out = present(slots, state_name="choosing", text=text + " " + profile.render("choose"), page_no=0)
            out["payload"]["state"] = "listed"
            out["summary"] = text
            return out
        text = profile.render("listed") + "\n" + "\n".join(
            f"• {a['label']} — {a.get('provider_label') or profile.provider_label}"
            + (f" (under {a['name']})" if a.get("name") else "") for a in upcoming)
        return {"payload": _payload(profile, theme_key, "listed", appointments=upcoming,
                                    actions=_appointment_chips(upcoming)),
                "text": text, "summary": f"They have {len(upcoming)} scheduled: "
                + "; ".join(a["label"] for a in upcoming) + ".", "facts": []}

    if kind == "book":
        slot = svc.resolve_slot(profile, action.get("slot_id"), now_utc=now, tz=tz)
        if slot is None:
            slots = [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=0)]
            return present(slots, state_name="choosing", text=profile.render("slot_unavailable"), page_no=0)
        name = (action.get("name") or "").strip() or None
        if not name:
            try:
                name = store.latest_name(client_id)
            except Exception:  # noqa: BLE001
                name = None
        if not name:
            text = profile.render("ask_name", label=slot.label)
            return {"payload": _payload(profile, theme_key, "awaiting_name", slots=[slot.as_dict()],
                                        pending={"awaiting": "name", "slot_id": slot.slot_id},
                                        appointments=upcoming, actions=[_action_chip("decline", "Never mind")]),
                    "text": text,
                    "summary": f"{slot.label} is held but NOT booked yet; ask what name to put it under.",
                    "facts": [f"Chosen time: {slot.label}. Say this time.",
                              "The user types the name; there is no button for it."]}
        appt = store.book(client_id=client_id, session_id=state["session_id"], theme=theme_key, name=name,
                          provider_label=profile.provider_label, start_utc=slot.start_utc,
                          duration_minutes=profile.duration_minutes, timezone_name=tz,
                          notes={"request_id": state.get("request_id"), "enduser_id": state.get("enduser_id")})
        appt = svc.describe(appt, profile, tz)
        _record_mutation(state, TOOL_SCHEDULE, {"slot_id": slot.slot_id, "name": name, "theme": theme_key}, appt)
        text = profile.render("confirmed", label=appt["label"], name=name)
        return {"payload": _payload(profile, theme_key, "booked", appointment=appt, appointments=upcoming + [appt],
                                    actions=_appointment_chips([appt])),
                "text": text, "summary": f"Booked {appt['label']} under {name}.",
                "facts": [f"Booked: {appt['label']}, {profile.appointment_noun} with {profile.provider_noun}, under {name}."]}

    if kind in ("cancel", "reschedule"):
        target_id = action.get("appointment_id")
        target = next((a for a in upcoming if a["id"] == target_id), None) if target_id else None
        if target is None and len(upcoming) == 1 and not target_id:
            target = upcoming[0]
        if target is None:
            if not upcoming:
                text = profile.render("none_scheduled")
                return {"payload": _payload(profile, theme_key, "listed"), "text": text, "summary": text, "facts": []}
            text = profile.render("which_one")
            return {"payload": _payload(profile, theme_key, "listed", appointments=upcoming,
                                        actions=_appointment_chips(upcoming)),
                    "text": text, "summary": text, "facts": []}
        if kind == "cancel":
            done = store.cancel(target["id"], client_id=client_id)
            if done is None:
                text = profile.render("unavailable")
                return {"payload": _payload(profile, theme_key, "unavailable"), "text": text, "summary": text, "facts": []}
            done = svc.describe(done, profile, tz)
            _record_mutation(state, TOOL_CANCEL, {"appointment_id": target["id"]}, done)
            text = profile.render("cancelled", label=done["label"])
            remaining = [a for a in upcoming if a["id"] != target["id"]]
            return {"payload": _payload(profile, theme_key, "cancelled", appointment=done, appointments=remaining),
                    "text": text, "summary": f"Cancelled {done['label']}.", "facts": [f"Cancelled: {done['label']}."]}
        # reschedule
        slot = svc.resolve_slot(profile, action.get("slot_id"), now_utc=now, tz=tz)
        if slot is None:
            slots = ctx.get("slots") or [s.as_dict() for s in svc.suggest_slots(profile, now_utc=now, tz=tz, page=page)]
            return present(slots, state_name="rescheduling", text=profile.render("choose"),
                           pending={"awaiting": "slot", "reschedule_id": target["id"]}, reschedule_id=target["id"])
        moved = store.reschedule(target["id"], start_utc=slot.start_utc, client_id=client_id, timezone_name=tz)
        if moved is None:
            text = profile.render("unavailable")
            return {"payload": _payload(profile, theme_key, "unavailable"), "text": text, "summary": text, "facts": []}
        moved = svc.describe(moved, profile, tz)
        _record_mutation(state, TOOL_RESCHEDULE, {"appointment_id": target["id"], "slot_id": slot.slot_id}, moved)
        text = profile.render("rescheduled", label=moved["label"])
        others = [a for a in upcoming if a["id"] != target["id"]]
        return {"payload": _payload(profile, theme_key, "rescheduled", appointment=moved, appointments=others + [moved],
                                    actions=_appointment_chips([moved])),
                "text": text, "summary": f"Moved to {moved['label']}.", "facts": [f"New time: {moved['label']}."]}

    return {"payload": None, "text": "", "summary": "", "facts": []}


# --------------------------------------------------------------------------- POST node
def scheduling_node(state: Dict[str, Any]) -> Dict[str, Any]:
    ctx = state.get("scheduling_context") or {}
    if not ctx.get("enabled"):
        return {}
    theme_key = state.get("theme") or "medadvice"
    theme_config = get_theme(theme_key)
    profile = theme_config.scheduling
    multi_agent = state.get("multi_agent_mode") is True
    intent_turn = bool((ctx.get("action") or {}).get("action"))
    final_message = state.get("final_message", "") or ""

    if not ctx.get("store_ok", True) and intent_turn:
        text = profile.render("unavailable")
        return {"final_message": f"{final_message.rstrip()}\n\n{text}" if final_message else text,
                "scheduling": _payload(profile, theme_key, "unavailable")}

    try:
        outcome = _execute(state, profile, theme_key, ctx)
    except Exception:  # noqa: BLE001 - never fail the whole turn on a scheduling error
        logger.exception("scheduling: action failed")
        text = profile.render("unavailable")
        return {"final_message": f"{final_message.rstrip()}\n\n{text}" if final_message else text,
                "scheduling": _payload(profile, theme_key, "unavailable")}

    payload = outcome.get("payload")
    if payload is None:
        return {}
    text = outcome.get("text") or ""
    updates: Dict[str, Any] = {"scheduling": payload}
    # The "did this resolve your concern?" check rides in payload["message"]: the
    # UI shows it as its own bubble under the untouched answer. It is fixed copy
    # in BOTH modes — a yes/no prompt must not depend on a model's phrasing (a
    # local model turned it into a statement) — so no scheduling-agent call here;
    # the agent phrases what follows a "no".
    if payload.get("state") == "check_resolved":
        payload["message"] = text
        return updates

    if multi_agent:
        # The scheduling agent phrases the outcome (offer included); the
        # template is the fallback when the model errors or returns nothing.
        agent_name = f"{theme_key}_scheduling_agent"
        provider = settings.ai_provider
        model_override = settings.ollama_model_internal if provider == "ollama" else None
        system_prompt = build_scheduling_agent_prompt(profile, theme_config.label, outcome)
        messages = [{"role": "user", "content": state.get("user_message", "") or "(no message)"}]
        trace = list(state.get("agent_trace", []))
        agent_start = time.perf_counter()
        with otel.agent_span(agent_name, theme=theme_key):
            try:
                with otel.llm_span(request_model=request_model(provider, model_override), provider=provider) as llm_sp:
                    response = invoke_agent(
                        settings, agent_name=agent_name, system=system_prompt, messages=messages,
                        max_tokens=_SCHEDULING_AGENT_MAX_TOKENS, temperature=0.4, model_override=model_override,
                    )
                    otel.record_llm_result(
                        llm_sp, response_id=response.id, response_model=response.model,
                        input_tokens=response.input_tokens, output_tokens=response.output_tokens,
                        output_tokens_cached=response.output_tokens_cached,
                        output_tokens_uncached=response.output_tokens_uncached,
                        finish_reason=response.stop_reason,
                    )
            except ChatModelError as exc:
                logger.warning("scheduling agent '%s' failed: %s", agent_name, exc)
                trace.append(trace_entry(name=agent_name, role="scheduling", status="error",
                                         duration_ms=round((time.perf_counter() - agent_start) * 1000, 1)))
                response = None
        if response is not None:
            wording = (response.content or "").strip()
            if wording and payload["state"] == "awaiting_name" and not _model_covers_outcome(payload, wording):
                # The name step must say the held time and ask for the name
                # (the agent is told not to list times); keep the template
                # when its wording drops either.
                wording = ""
            if wording:
                # Keep the deterministic facts line for listings (the agent is
                # told not to enumerate); prepend its wording otherwise.
                text = wording if payload["state"] != "listed" else f"{wording}\n{text}"
            trace.append(trace_entry(name=agent_name, role="scheduling", response=response,
                                     duration_ms=round((time.perf_counter() - agent_start) * 1000, 1)))
            updates.update(TokenTally(state).add(response).updates())
        updates["agent_trace"] = trace
        if intent_turn:
            # An intent turn IS the scheduling reply: the scheduling agent's
            # wording replaces the domain agent's text (a local model tends to
            # re-answer the domain question despite the hand-off).
            updates["final_message"] = text
        else:
            # Answer-turn copy (already booked) is its OWN bubble, never text
            # inside the answer.
            payload["message"] = text
        return updates

    # Single-agent mode: on an intent turn the domain agent was directed to write
    # the scheduling reply itself. Keep its text when it actually covers the
    # outcome; otherwise (it re-answered the domain question instead) the
    # deterministic copy IS the reply, so nothing is said twice or off-topic.
    if intent_turn:
        if not _model_covers_outcome(payload, final_message):
            updates["final_message"] = text
        return updates
    # Answer-turn copy (already booked) is its OWN bubble, never text inside
    # the answer.
    payload["message"] = text
    return updates


def _model_covers_outcome(payload: Dict[str, Any], text: str) -> bool:
    """Did the domain agent's reply actually address the scheduling outcome?"""
    low = (text or "").lower()
    state_name = payload.get("state")
    appt = payload.get("appointment") or {}
    if state_name in ("booked", "rescheduled", "cancelled"):
        return bool(appt.get("label")) and appt["label"] in text
    if state_name == "awaiting_name":
        # It must ask for the name AND say which time is held. "name" alone
        # passed a reply that told the user to "click the button above" and
        # never said the time was held, not booked.
        held = [s.get("label") for s in payload.get("slots") or [] if s.get("label")]
        return "name" in low and bool(held) and all(label in text for label in held)
    if state_name == "listed":
        labels = [a.get("label") for a in payload.get("appointments") or [] if a.get("label")]
        return bool(labels) and all(label in text for label in labels)
    if state_name in ("choosing", "rescheduling", "clarify_slot"):
        # Only an actual offered time counts. A bare mention of "time" used to
        # pass here, which let a re-answered domain question stand in for the
        # question we needed to ask.
        return any(s.get("label") in text for s in payload.get("slots") or [])
    return False
