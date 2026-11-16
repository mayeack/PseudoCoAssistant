#!/usr/bin/env python3
"""Regression: the Prompt Injection Spray's turn driver (backend/routers/spray.py).

A Lab 5 rehearsal on 2026-11-12 found two defects in ``_drive_campaign``:

1. **Allowed turns reached the model with no prompt.** The driver passed the
   session's history from BEFORE the turn. The chat router passes
   ``session["messages"]``, which already ends with the typed message
   (``_prepare_session``), and the answering agent builds the model's messages
   from ``conversation_history`` alone (``nodes/synthesizer.py``). So every turn
   the screens let through went to the model with nothing to answer:
   governance showed ``input_messages=[]`` (or only earlier turns), about 1
   input token and an unrelated answer. Blocked turns looked right, because
   the screens read the typed prompt.
2. **The tally dropped the turn in flight at a stop.** A stop (manual, or the
   auto-stop at ``duration_s``) cancelled the driver while ``run_turn`` was
   still finishing in its worker thread. The thread wrote the turn's
   governance events, but the driver never reached ``record_turn``, so
   ``/api/spray/status`` reported one turn fewer than Splunk.

No real AI Defense or model traffic. The driver checks stub ``run_turn``. The
one real-graph check stubs the LLM boundary and every guardrail client, and
captures the governance logger, so nothing reaches the database, HEC or
Agent Observability.

Run:  venv/bin/python tests/test_spray_driver.py    # exit 0 = pass
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
# Survives backend.config's .env load (which only sets keys not already present).
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: E402,F401
from backend.config import settings  # noqa: E402

settings.prewarm_llm = False
settings.mcp_tool_thrash_enabled = False
for _rate in ("pii_injection_rate", "toxic_injection_rate", "hallucination_injection_rate",
              "authority_injection_rate"):
    setattr(settings, _rate, 0.0)
import identity_isolation  # noqa: E402  (no real Duo / CII, whatever .env holds)

identity_isolation.isolate(settings)

from backend.agents.nodes.shared import build_llm_messages  # noqa: E402
from backend.routers import spray  # noqa: E402
from backend.spray_campaign import SprayCampaign, app_for_theme, spray_campaign  # noqa: E402

# The driver logs every start and stop at WARNING; the checks say what matters.
for _name in ("backend.routers.spray", "backend.spray_campaign"):
    logging.getLogger(_name).setLevel(logging.ERROR)

_APP = app_for_theme("medadvice")
_failures: List[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def _turn(session: str, prompt: str, *, actor: str = "t.nguyen",
          technique: str = "subtle_probe") -> spray._Turn:
    return spray._Turn(actor=actor, session_id=session, prompt=prompt, technique=technique, app=_APP)


def _user(text: str) -> Dict[str, str]:
    return {"role": "user", "content": text}


@contextmanager
def _driver(plan_for: Callable[[spray.SprayStart], List[spray._Turn]], run_turn=None, gap: float = 0.0):
    """Drive a fixed plan, ``gap`` seconds between turns; ``run_turn`` replaces
    the real graph when given."""
    saved = (spray._build_plan, spray._gap_seconds, spray.run_turn)
    spray._build_plan = lambda body, rng: list(plan_for(body))
    spray._gap_seconds = lambda *a, **k: gap
    if run_turn is not None:
        spray.run_turn = run_turn
    try:
        yield
    finally:
        spray._build_plan, spray._gap_seconds, spray.run_turn = saved


@contextmanager
def _quiet(name: str):
    """Hide a logger's expected traceback for the length of one check."""
    log = logging.getLogger(name)
    level = log.level
    log.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        log.setLevel(level)


class _RunTurn:
    """A ``run_turn`` stub that records what each turn was given.

    ``blocked`` prompts come back policy-blocked, ``fail`` prompts raise, and a
    ``gated`` prompt waits in its worker thread until ``release`` is set, so a
    check can stop the campaign while that turn is in flight.
    """

    def __init__(self, *, blocked=(), fail=(), gated=()):
        self.blocked, self.fail, self.gated = set(blocked), set(fail), set(gated)
        self.calls: List[Dict[str, Any]] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, **kw):
        prompt = kw["user_message"]
        with self._lock:
            self.calls.append({"user_message": prompt, "session_id": kw["session_id"],
                               "conversation_history": [dict(m) for m in kw["conversation_history"]]})
        if prompt in self.gated:
            self.entered.set()
            if not self.release.wait(10):
                raise RuntimeError(f"{prompt!r} was never released")
        if prompt in self.fail:
            raise RuntimeError(f"boom: {prompt}")
        return {"message": f"reply to {prompt}", "policy_blocked": prompt in self.blocked}

    def prompts(self) -> List[str]:
        return [c["user_message"] for c in self.calls]


async def _until(cond: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


def _drive_once(plan: List[spray._Turn], run_turn=None) -> Dict[str, Any]:
    """Run one whole campaign over ``plan``; returns its final status."""
    with _driver(lambda body: plan, run_turn=run_turn):
        spray_campaign.start(actor="t.nguyen", duration_s=60, intensity=len(plan), secondary_actors=0)
        asyncio.run(spray._drive_campaign(spray.SprayStart(), random.Random(7)))
        status = spray_campaign.status()
        spray_campaign.stop()
    return status


# --------------------------------------------------------------------------- defect 1: the prompt


def test_turn_carries_prompt() -> None:
    print("== every turn reaches the graph with its prompt as the last user message ==")
    a1, a2, a3 = "first step", "second step", "third step"
    b1 = "a one-off probe"
    plan = [_turn("spray-a", a1, technique="multi_turn_escalation"), _turn("spray-b", b1),
            _turn("spray-a", a2, technique="multi_turn_escalation"),
            _turn("spray-a", a3, technique="multi_turn_escalation")]
    stub = _RunTurn(blocked={a2})
    status = _drive_once(plan, stub)
    seen = {c["user_message"]: c["conversation_history"] for c in stub.calls}

    check("all four planned turns ran, in order", stub.prompts() == [a1, b1, a2, a3], str(stub.prompts()))
    for call in stub.calls:
        prompt, history = call["user_message"], call["conversation_history"]
        check(f"{prompt!r}: conversation_history ends with the prompt",
              bool(history) and history[-1] == _user(prompt), str(history))
        # What the answering agent sends the model (nodes/synthesizer.py).
        messages = build_llm_messages(history)
        check(f"{prompt!r}: the model's messages end with the prompt",
              bool(messages) and messages[-1] == _user(prompt), str(messages))
        roles = [m["role"] for m in history]
        check(f"{prompt!r}: user and assistant alternate (no doubled user turn)",
              all(r1 != r2 for r1, r2 in zip(roles, roles[1:])), str(roles))
    check("a session's first turn carries its prompt alone (it used to carry nothing)",
          seen[a1] == [_user(a1)] and seen[b1] == [_user(b1)], f"{seen[a1]} {seen[b1]}")
    check("a later step carries the earlier exchanges, a blocked one included, and its prompt once",
          seen[a3] == [_user(a1), {"role": "assistant", "content": f"reply to {a1}"},
                       _user(a2), {"role": "assistant", "content": f"reply to {a2}"},
                       _user(a3)], str(seen[a3]))
    check("the tally counts every turn with its verdict",
          (status["turns_sent"], status["blocked"], status["allowed"], status["errors"]) == (4, 1, 3, 0),
          str(status))


def test_failed_turn_leaves_no_half_exchange() -> None:
    print("== a failed turn leaves the session's history whole ==")
    c1, c2 = "this turn fails", "this turn follows it"
    stub = _RunTurn(fail={c1})
    with _quiet("backend.routers.spray"):
        status = _drive_once([_turn("spray-c", c1), _turn("spray-c", c2)], stub)
    follow = stub.calls[1]["conversation_history"] if len(stub.calls) > 1 else None
    check("the campaign goes on after a failed turn", stub.prompts() == [c1, c2], str(stub.prompts()))
    check("the next step carries its own prompt only, no dangling user turn",
          follow == [_user(c2)], str(follow))
    check("the failure is tallied as an error",
          (status["turns_sent"], status["errors"], status["allowed"]) == (2, 1, 1), str(status))


def test_model_sees_prompt_through_real_graph() -> None:
    print("== the real graph: the model and governance get the prompt ==")
    from backend.agents.llm import NormalizedLLMResponse
    from backend.agents.nodes import agent_control as ac_mod
    from backend.agents.nodes import defense as def_mod
    from backend.agents.nodes import nemo_rails as nr_mod
    from backend.logging.governance_logger import governance_logger
    from backend.services.ai_defense import InspectionResult
    from backend.services.spray_corpus import SUBTLE_PROMPTS

    # The allowed cohort: the turns that lost their prompt.
    p1, p2 = SUBTLE_PROMPTS[0], SUBTLE_PROMPTS[2]
    llm_calls: List[tuple] = []
    screened: List[str] = []
    events: List[Dict[str, Any]] = []

    def fake_llm(_settings, *, agent_name, system, messages, **_kw):
        llm_calls.append((agent_name, [dict(m) for m in messages or []]))
        return NormalizedLLMResponse(id="r", content="LOW\nAssessment: test. Guidance: rest, fluids.",
                                     model="fake-model", input_tokens=10, output_tokens=5,
                                     stop_reason="end_turn")

    def screen(text, **_kw):
        screened.append(text)
        return InspectionResult(is_safe=True)

    def record(kind):
        return lambda **kw: events.append(dict(kw, _kind=kind))

    patches = [
        (def_mod, "ai_defense_client", SimpleNamespace(
            is_configured=True, inspect_prompt=screen,
            inspect_response=lambda *a, **k: InspectionResult(is_safe=True))),
        # Off whatever the checkout's .env says: these must never be reached.
        (ac_mod, "agent_control_client", SimpleNamespace(is_configured=False, stages=[])),
        (nr_mod, "nemo_guardrails_client", SimpleNamespace(is_configured=False)),
        (governance_logger, "log_request", lambda **kw: None),
    ]
    patches += [(governance_logger, name, record(name))
                for name in ("log_response", "log_error", "log_escalation", "log_decision",
                             "log_tool_call", "log_audit")]
    patches += [(mod, attr, fake_llm)
                for name, mod in list(sys.modules.items()) if name.startswith("backend.agents")
                for attr in ("invoke_agent", "invoke_chat") if hasattr(mod, attr)]
    saved = [(obj, attr, getattr(obj, attr)) for obj, attr, _ in patches]
    try:
        for obj, attr, value in patches:
            setattr(obj, attr, value)
        status = _drive_once([_turn("spray-real", p1), _turn("spray-real", p2)])  # the real run_turn
    finally:
        for obj, attr, value in reversed(saved):
            setattr(obj, attr, value)

    answers = [messages for name, messages in llm_calls if name.endswith("_domain_agent")]
    check("the answering agent ran once per turn", len(answers) == 2, str([n for n, _ in llm_calls]))
    if len(answers) == 2:
        check("turn 1: the model is asked the prompt (it was asked nothing)",
              answers[0] == [_user(p1)], str(answers[0]))
        check("turn 2: the model gets turn 1's exchange, then the prompt",
              len(answers[1]) == 3 and answers[1][0] == _user(p1) and answers[1][1]["role"] == "assistant"
              and bool(answers[1][1]["content"]) and answers[1][2] == _user(p2), str(answers[1]))
    responses = [e for e in events if e["_kind"] == "log_response"]
    check("governance input_messages end with the prompt (was [] on a session's first turn)",
          [(r.get("input_messages") or [None])[-1] for r in responses] == [_user(p1), _user(p2)],
          str([r.get("input_messages") for r in responses]))
    check("AI Defense screened each typed prompt once", screened == [p1, p2], str(screened))
    check("both turns were allowed and tallied",
          (status["turns_sent"], status["allowed"]) == (2, 2), str(status))


# --------------------------------------------------------------------------- defect 2: the tally


def test_campaign_scoping() -> None:
    print("== the tally belongs to one campaign ==")
    camp = SprayCampaign()
    camp.start(actor="t.nguyen", duration_s=60, intensity=1, secondary_actors=0)
    first = camp.campaign_id
    camp.stop()
    counted = camp.record_turn(campaign_id=first, session_id="s", technique="x", app_name="a", blocked=True)
    check("a stopped campaign still counts its own late turn",
          counted and (camp.turns_sent, camp.blocked) == (1, 1), f"{counted} {camp.status()}")
    camp.start(actor="t.nguyen", duration_s=60, intensity=1, secondary_actors=0)
    counted = camp.record_turn(campaign_id=first, session_id="s", technique="x", app_name="a", blocked=True)
    check("a replaced campaign's late turn is not counted in the new one",
          not counted and camp.turns_sent == 0, f"{counted} {camp.status()}")
    check("is_active(campaign_id) answers for that campaign only",
          camp.is_active() and camp.is_active(camp.campaign_id) and not camp.is_active(first))


def test_stop_mid_turn() -> None:
    print("== /stop mid-turn: the turn is still tallied, and no other starts ==")
    t1, t2, t3 = "turn one", "turn two, in flight at the stop", "turn three"
    stub = _RunTurn(gated={t2}, blocked={t2})

    async def scenario():
        await spray.start_spray(spray.SprayStart(actor="t.nguyen", duration_s=60, intensity=3,
                                                 secondary_actors=0))
        in_flight = await _until(stub.entered.is_set)
        at_stop = await spray.stop_spray()
        stub.release.set()
        landed = await _until(lambda: not spray._status()["driver_running"])
        return in_flight, at_stop, landed, spray._status()

    with _driver(lambda body: [_turn("spray-s", t1), _turn("spray-s", t2), _turn("spray-s", t3)], stub):
        in_flight, at_stop, landed, final = asyncio.run(scenario())
    check("turn two was in flight when the stop came", in_flight)
    check("the stop ends the campaign", at_stop["active"] is False, str(at_stop))
    check("the stop reports the driver running while turn two lands",
          at_stop["driver_running"] is True and at_stop["turns_sent"] == 1, str(at_stop))
    check("the driver exits once turn two has landed", landed)
    check("turn two is tallied with its verdict (status used to show one turn fewer than Splunk)",
          (final["turns_sent"], final["blocked"], final["allowed"]) == (2, 1, 1), str(final))
    check("no turn starts after the stop", stub.prompts() == [t1, t2], str(stub.prompts()))


def test_stop_between_turns() -> None:
    print("== /stop between turns: the campaign ends at once ==")
    t1, t2 = "turn one", "turn two, never sent"
    stub = _RunTurn()

    async def scenario():
        await spray.start_spray(spray.SprayStart(actor="t.nguyen", duration_s=60, intensity=2,
                                                 secondary_actors=0))
        tallied = await _until(lambda: spray_campaign.status()["turns_sent"] == 1)
        await asyncio.sleep(0.05)  # the driver is now waiting out the gap
        at_stop = await spray.stop_spray()
        await asyncio.sleep(0.05)
        return tallied, at_stop, spray._status()

    # A 30 s gap: the driver idles between the turns for the whole check.
    with _driver(lambda body: [_turn("spray-g", t1), _turn("spray-g", t2)], stub, gap=30.0):
        tallied, at_stop, after = asyncio.run(scenario())
    check("turn one was tallied before the stop", tallied)
    check("the stop reports the driver gone (nothing was in flight)",
          at_stop["active"] is False and at_stop["driver_running"] is False, str(at_stop))
    check("the tally is final at the stop",
          at_stop["turns_sent"] == 1 and after["turns_sent"] == 1, f"{at_stop} {after}")
    check("no turn starts after the stop", stub.prompts() == [t1], str(stub.prompts()))


def test_auto_stop_mid_turn() -> None:
    print("== the auto-stop mid-turn: the turn is still tallied ==")
    t1, t2, t3 = "turn one", "turn two, in flight at the expiry", "turn three"
    stub = _RunTurn(gated={t2})

    async def scenario():
        # The expiry task start_spray schedules, firing after 1 s. That is below
        # SprayStart's 10 s floor, so the body is built without validation.
        body = spray.SprayStart.model_construct(actor="t.nguyen", duration_s=1, intensity=3,
                                                secondary_actors=0, theme=None, drive_turns=True)
        await spray.start_spray(body)
        in_flight = await _until(stub.entered.is_set)
        expired = await _until(lambda: spray._expiry_task is not None and spray._expiry_task.done())
        at_expiry = spray._status()
        stub.release.set()
        landed = await _until(lambda: not spray._status()["driver_running"])
        return in_flight, expired, at_expiry, landed, spray._status()

    with _driver(lambda body: [_turn("spray-x", t1), _turn("spray-x", t2), _turn("spray-x", t3)], stub):
        in_flight, expired, at_expiry, landed, final = asyncio.run(scenario())
    check("turn two was in flight when the campaign expired", in_flight)
    check("the auto-stop ran and ended the campaign", expired and at_expiry["active"] is False, str(at_expiry))
    check("the driver is still running while turn two lands", at_expiry["driver_running"] is True,
          str(at_expiry))
    check("the driver exits once turn two has landed", landed)
    check("turn two is tallied (the live run showed 3 against 4 and 5 against 6)",
          (final["turns_sent"], final["allowed"]) == (2, 2), str(final))
    check("no turn starts after the auto-stop", stub.prompts() == [t1, t2], str(stub.prompts()))


def test_restart_mid_turn() -> None:
    print("== a new campaign started mid-turn never inherits the old one's turns ==")
    a1, a2 = "old campaign, in flight", "old campaign, never sent"
    b1, b2 = "new campaign, one", "new campaign, two"
    plans = {"old.actor": [_turn("spray-old", a1, actor="old.actor"), _turn("spray-old", a2, actor="old.actor")],
             "new.actor": [_turn("spray-new", b1, actor="new.actor"), _turn("spray-new", b2, actor="new.actor")]}
    stub = _RunTurn(gated={a1})

    async def scenario():
        await spray.start_spray(spray.SprayStart(actor="old.actor", duration_s=60, intensity=2,
                                                 secondary_actors=0))
        old_driver = spray._driver_task
        in_flight = await _until(stub.entered.is_set)
        new = await spray.start_spray(spray.SprayStart(actor="new.actor", duration_s=60, intensity=2,
                                                       secondary_actors=0))
        new_done = await _until(lambda: len(stub.calls) >= 3 and spray._driver_task.done())
        stub.release.set()
        old_done = await _until(old_driver.done)
        final = spray._status()
        await spray.stop_spray()
        return in_flight, new, new_done, old_done, final

    with _driver(lambda body: plans[body.actor], stub):
        in_flight, new, new_done, old_done, final = asyncio.run(scenario())
    check("the old campaign's turn was in flight at the restart", in_flight)
    check("the new campaign ran its own plan meanwhile", new_done, str(stub.prompts()))
    check("the old driver exits once its turn lands", old_done)
    check("the old campaign's late turn is not counted in the new campaign",
          final["campaign_id"] == new["campaign_id"] and (final["turns_sent"], final["allowed"]) == (2, 2),
          str(final))
    check("the old campaign never sends another turn", stub.prompts() == [a1, b1, b2], str(stub.prompts()))


def main() -> int:
    for fn in (test_turn_carries_prompt, test_failed_turn_leaves_no_half_exchange,
               test_model_sees_prompt_through_real_graph, test_campaign_scoping, test_stop_mid_turn,
               test_stop_between_turns, test_auto_stop_mid_turn, test_restart_mid_turn):
        fn()
    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
        return 1
    print("All spray-driver checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
