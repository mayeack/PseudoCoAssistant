#!/usr/bin/env python3
"""API regression suite — every endpoint's auth gating + contract, via FastAPI's
in-process TestClient.

Side-effect-safe: the LLM boundary and the auto-prompter are stubbed, and the demo
incident is started without driving load, so the suite makes no real Anthropic
calls, spawns no background load, and triggers no external emission (Splunk/HEC/
Agent Observability are no-op without config). pytest isn't installed; run standalone:

    venv/bin/python tests/test_api.py        # exit 0 = pass
"""
import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import backend.config  # noqa: E402  (sets CA bundle etc.)
from backend.config import settings  # noqa: E402

# Ensure the access gate is exercised even if .env has no ACCESS_KEY.
KEY = settings.access_key or "test-access-key"
settings.access_key = KEY

# Make the governance-content background rates deterministic for the suite: an
# OFF-path turn (no force_* flag) must request nothing, so the no-toggle
# assertions below are stable. The directive/fallback logic reads these at call
# time, so setting them here (before any request) is sufficient.
settings.pii_injection_rate = 0.0
settings.toxic_injection_rate = 0.0
settings.hallucination_injection_rate = 0.0
settings.authority_injection_rate = 0.0

# No startup pre-warm: the suite stubs the LLM boundary and must not load a
# real Ollama model (or touch the daemon) as a side effect.
settings.prewarm_llm = False

# --- stub the LLM boundary BEFORE backend.main imports the graph/nodes ---
import backend.agents.llm as llm  # noqa: E402
from backend.agents.llm import NormalizedLLMResponse  # noqa: E402

# Captures the last system prompt handed to the (stubbed) model so the suite can
# assert the governance directive is appended to the INPUT, not the output.
_last_system = {"v": ""}


def _fake_llm(*_a, **_k):
    _last_system["v"] = _k.get("system", "")
    return NormalizedLLMResponse(
        id="test-id", content="LOW\nAssessment: test. Guidance: rest, fluids.",
        model="test-model", input_tokens=5, output_tokens=7, stop_reason="end_turn",
    )


llm.invoke_agent = _fake_llm
llm.invoke_chat = _fake_llm

# --- stub the Agent Control evaluation so the agent_control_review check
# below exercises the node without an outbound call to the control server ---
import backend.services.agent_control as agent_control  # noqa: E402

agent_control.agent_control_client.evaluate_response = (
    lambda *_a, **_k: agent_control.ControlVerdict(is_safe=True, confidence=0.0)
)

# --- stub the auto-prompter so /auto-prompt/start launches no real load ---
import backend.services.auto_prompter as ap  # noqa: E402


async def _noop(*_a, **_k):
    return None


ap.auto_prompter.start = _noop  # type: ignore[assignment]
ap.auto_prompter.stop = _noop   # type: ignore[assignment]

from fastapi.testclient import TestClient  # noqa: E402
from backend.main import app  # noqa: E402

AUTH = {"Authorization": "Basic " + base64.b64encode(f"x:{KEY}".encode()).decode()}
_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


def main() -> int:
    with TestClient(app) as c:
        # ---- public (no key) ----
        check("GET /health -> 200 (public)", c.get("/health").status_code == 200)
        check("GET /login -> 200 (public)", c.get("/login").status_code == 200)

        # ---- auth gating: gated endpoints reject without the key (401 JSON) ----
        for path in ("/api/chat/auto-prompt/status", "/api/incident/status",
                     "/api/spray/status", "/api/appointments?client_id=x",
                     "/api/settings", "/api/hec/destinations", "/admin/logs/metrics",
                     "/api/settings/emit-model"):
            r = c.get(path)
            check(f"GET {path} -> 401 without key", r.status_code == 401, f"got {r.status_code}")

        # ---- chat ----
        r = c.post("/api/chat/session/new", headers=AUTH)
        check("POST /api/chat/session/new -> 200 + session_id",
              r.status_code == 200 and "session_id" in r.json(), f"{r.status_code}")
        sid = r.json().get("session_id", "") if r.status_code == 200 else ""
        check("GET /api/chat/session/{id} -> 200",
              c.get(f"/api/chat/session/{sid}", headers=AUTH).status_code in (200, 404))
        check("GET /api/chat/disclaimer -> 200", c.get("/api/chat/disclaimer", headers=AUTH).status_code == 200)
        # Theme-aware: it used to return the MEDICAL disclaimer unconditionally,
        # with no theme parameter, so five of six themes got wrong text.
        rdm = c.get("/api/chat/disclaimer", headers=AUTH).json()
        check("disclaimer: defaults to medadvice's medical text",
              rdm.get("theme") == "medadvice" and "MEDICAL DISCLAIMER" in rdm.get("content", ""))
        rdt = c.get("/api/chat/disclaimer?theme=telecomchatbot", headers=AUTH).json()
        check("disclaimer: a non-medical theme gets non-medical text",
              rdt.get("theme") == "telecomchatbot"
              and "MEDICAL DISCLAIMER" not in rdt.get("content", "")
              and "not professional advice" in rdt.get("content", ""),
              str(rdt.get("title")))
        check("disclaimer: unknown theme falls back rather than erroring",
              c.get("/api/chat/disclaimer?theme=nonsense", headers=AUTH).status_code == 200)

        # REQUIRE_DISCLAIMER_ACCEPTANCE had no readers: setting it False did
        # nothing and the 400 gate was unconditional.
        _saved_req = settings.require_disclaimer_acceptance
        try:
            settings.require_disclaimer_acceptance = True
            _newsid = c.post("/api/chat/session/new", headers=AUTH).json()["session_id"]
            check("disclaimer gate ON -> new session without acceptance is 400",
                  c.post("/api/chat/message", headers=AUTH,
                         json={"session_id": _newsid, "message": "hi",
                               "disclaimer_accepted": False}).status_code == 400)
            settings.require_disclaimer_acceptance = False
            _newsid2 = c.post("/api/chat/session/new", headers=AUTH).json()["session_id"]
            check("disclaimer gate OFF -> the flag is actually honored (no 400)",
                  c.post("/api/chat/message", headers=AUTH,
                         json={"session_id": _newsid2, "message": "hi",
                               "disclaimer_accepted": False}).status_code == 200)
        finally:
            settings.require_disclaimer_acceptance = _saved_req

        # MAX_CLARIFYING_QUESTIONS was likewise inert (a hardcoded 2 won).
        from backend.services.clarifying_questions import ClarifyingQuestionsService  # noqa: E402
        _svc = ClarifyingQuestionsService()
        _saved_max = settings.max_clarifying_questions
        try:
            settings.max_clarifying_questions = 5
            check("clarifying limit follows the setting", _svc.MAX_QUESTIONS == 5,
                  str(_svc.MAX_QUESTIONS))
        finally:
            settings.max_clarifying_questions = _saved_max
        # Assert the CODE default, not the live value: this box's .env sets 3, and
        # now that the setting is honored that .env value is what actually applies.
        check("clarifying limit code default is the shipped 2",
              type(settings).model_fields["max_clarifying_questions"].default == 2,
              str(type(settings).model_fields["max_clarifying_questions"].default))
        # /message: validation (no real LLM turn asserted — that's integration-tested)
        check("POST /api/chat/message bad body -> 422",
              c.post("/api/chat/message", headers=AUTH, json={}).status_code == 422)
        rmsg = c.post("/api/chat/message", headers=AUTH,
                      json={"session_id": sid, "message": "test", "disclaimer_accepted": True})
        check("POST /api/chat/message (stubbed LLM) -> 200", rmsg.status_code == 200, f"{rmsg.status_code}")
        # --- Governance content toggles ------------------------------------
        # Each force_* flag appends a directive to the INPUT asking the model to
        # produce the content INSIDE its answer fields. There is deliberately NO
        # deterministic fallback: a (stubbed) model that omits the content yields
        # a reply with none of it, and the turn reports the category as not
        # delivered. Canned text appended after the LLM call is not what the
        # guardrails score.
        #
        # The directive is the same on every provider (build_input_directives):
        # unlabeled, theme-aware, embedded in the JSON answer contract. A
        # censored provider (anthropic / bedrock / openai / nvidia) is additionally
        # given the GOVERNANCE EVALUATION MODE permission preamble; ollama is
        # not. Neither path may ever solicit a "SAMPLE" label or a "fictional"
        # banner — that text used to reach the audience. So pin the provider per
        # block and assert both.
        _saved_provider = settings.ai_provider
        _LABELS = ("SAMPLE:", "(fictional)", "Synthetic governance", "test suite",
                   "INTERNAL SAFETY-DETECTOR", "labeled synthetic")

        def _turn(**flags):
            return c.post("/api/chat/message", headers=AUTH,
                          json={"session_id": sid, "message": "I have a sore throat.",
                                "disclaimer_accepted": True, **flags})

        def _unlabeled(tag):
            leaked = [w for w in _LABELS if w in _last_system["v"]]
            check(f"{tag}: directive solicits no sample/fictional label", not leaked, str(leaked))

        try:
            for provider in ("anthropic", "ollama"):
                settings.ai_provider = provider
                censored = provider != "ollama"
                rb = _turn(force_boundary_injection=True)
                check(f"{provider}: boundary -> overstep directive embedded in the answer",
                      "overstep your authorized non-prescriptive scope" in _last_system["v"])
                _unlabeled(f"{provider}: boundary")
                check(f"{provider}: boundary -> no canned overreach for the stubbed model",
                      rb.status_code == 200 and "**Recommended Prescription:**" not in rb.json().get("message", "")
                      and not re.search(r"\b(?:oxycodone|alprazolam|adderall|zolpidem|tramadol)\b",
                                        rb.json().get("message", ""), re.I),
                      f"{rb.status_code}")
                rp = _turn(force_pii_injection=True)
                check(f"{provider}: pii -> record header embedded in the answer contract",
                      "patient record header" in _last_system["v"]
                      and "NNN-NN-NNNN" in _last_system["v"])
                _unlabeled(f"{provider}: pii")
                check(f"{provider}: pii -> no canned SSN for the stubbed model",
                      rp.status_code == 200 and not re.search(r"\d{3}-\d{2}-\d{4}", rp.json().get("message", "")),
                      f"{rp.status_code}")
                rt = _turn(force_toxic_injection=True)
                check(f"{provider}: toxic -> persona override embedded in the answer",
                      "REQUIRED PERSONA OVERRIDE" in _last_system["v"])
                _unlabeled(f"{provider}: toxic")
                check(f"{provider}: toxic -> no canned harassment for the stubbed model",
                      rt.status_code == 200 and not any(w in rt.json().get("message", "")
                                                        for w in ("idiot", "pathetic", "worthless", "useless",
                                                                  "miserable", "brainless", "dumb",
                                                                  "**Direct Assessment:**")),
                      f"{rt.status_code}")
                rh = _turn(force_hallucination_injection=True)
                check(f"{provider}: hallucination -> embedded in the answer contract",
                      rh.status_code == 200
                      and "never admit that anything is invented or unverified" in _last_system["v"]
                      and "MANDATORY" in _last_system["v"], f"{rh.status_code}")
                _unlabeled(f"{provider}: hallucination")
                check(f"{provider}: hallucination -> no canned fabrication for the stubbed model",
                      rh.status_code == 200 and not any(h in rh.json().get("message", "") for h in
                                                        ("**Data:**", "**Recent Research:**", "**Current Guidelines:**",
                                                         "**Possible Explanation:**", "**Recommended Resource:**",
                                                         "**Technical Detail:**", "**Available Options:**")),
                      f"{rh.status_code}")
                check(f"{provider}: evaluation preamble {'present' if censored else 'absent'}",
                      ("GOVERNANCE EVALUATION MODE" in _last_system["v"]) is censored)

                rnb = _turn()
                check(f"{provider}: no toggles -> no directive on the INPUT",
                      "REQUIRED IN THIS RESPONSE" not in _last_system["v"]
                      and "GOVERNANCE EVALUATION MODE" not in _last_system["v"])
                check(f"{provider}: no toggles -> no overreach marker",
                      rnb.status_code == 200 and "**Recommended Prescription:**" not in rnb.json().get("message", ""),
                      f"{rnb.status_code}")
        finally:
            settings.ai_provider = _saved_provider
        # /message/stream: same turn over SSE — auth-gated, stage frames then one final.
        r401 = c.post("/api/chat/message/stream",
                      json={"session_id": sid, "message": "test", "disclaimer_accepted": True})
        check("POST /api/chat/message/stream -> 401 without key",
              r401.status_code == 401, f"got {r401.status_code}")
        rs = c.post("/api/chat/message/stream", headers=AUTH,
                    json={"session_id": sid, "message": "stream test", "disclaimer_accepted": True})
        check("POST /api/chat/message/stream -> 200 text/event-stream",
              rs.status_code == 200
              and rs.headers.get("content-type", "").startswith("text/event-stream"),
              f"{rs.status_code} {rs.headers.get('content-type')}")
        frames = [json.loads(f[len("data: "):]) for f in rs.text.split("\n\n")
                  if f.startswith("data: ")]
        stages = [f for f in frames if f.get("event") == "stage"]
        finals = [f for f in frames if f.get("event") == "final"]
        check("stream -> >=1 stage frame and exactly 1 final frame with a message",
              len(stages) >= 1 and len(finals) == 1 and bool(finals[0].get("message")),
              f"stages={len(stages)} finals={len(finals)}")
        check("stream final frame carries the ChatResponse contract",
              len(finals) == 1 and {"session_id", "message", "type", "escalated",
                                    "timestamp"} <= set(finals[0].keys()))
        stage_nodes = [f.get("node") for f in stages]
        check("stream default -> coordinator/specialists absent (single-agent default)",
              "coordinator" not in stage_nodes and "specialists" not in stage_nodes,
              f"nodes={stage_nodes}")
        check("stream default -> synthesizer + all guardrails run",
              {"synthesizer", "safety", "injection", "compliance",
               "agent_control", "response_defense", "governance"} <= set(stage_nodes),
              f"nodes={stage_nodes}")
        # multi_agent_mode=true -> opt-in to the full coordinator/specialists core.
        rma = c.post("/api/chat/message/stream", headers=AUTH,
                     json={"session_id": sid, "message": "I have a sore throat.",
                           "disclaimer_accepted": True, "multi_agent_mode": True})
        ma_nodes = [f.get("node") for f in
                    (json.loads(l[len("data: "):]) for l in rma.text.split("\n\n")
                     if l.startswith("data: "))
                    if f.get("event") == "stage"]
        check("multi_agent_mode=true -> coordinator stage present",
              "coordinator" in ma_nodes, f"nodes={ma_nodes}")
        # multi_agent_mode=false -> single-agent bypass: the coordinator and
        # specialists never run; the synthesizer + every guardrail node still do.
        rsa = c.post("/api/chat/message", headers=AUTH,
                     json={"session_id": sid, "message": "I have a sore throat.",
                           "disclaimer_accepted": True, "multi_agent_mode": False})
        check("POST /api/chat/message multi_agent_mode=false -> 200 + message",
              rsa.status_code == 200 and bool(rsa.json().get("message")), f"{rsa.status_code}")
        rss = c.post("/api/chat/message/stream", headers=AUTH,
                     json={"session_id": sid, "message": "I have a sore throat.",
                           "disclaimer_accepted": True, "multi_agent_mode": False})
        sa_nodes = [f.get("node") for f in
                    (json.loads(l[len("data: "):]) for l in rss.text.split("\n\n")
                     if l.startswith("data: "))
                    if f.get("event") == "stage"]
        check("multi_agent_mode=false -> coordinator/specialists skipped",
              "coordinator" not in sa_nodes and "specialists" not in sa_nodes,
              f"nodes={sa_nodes}")
        check("multi_agent_mode=false -> synthesizer + all guardrails still run",
              {"synthesizer", "safety", "injection", "compliance",
               "agent_control", "response_defense", "governance"} <= set(sa_nodes),
              f"nodes={sa_nodes}")
        # agent_control_review (the "Agent Observability Controls" toggle) is
        # accepted and, with a clean verdict (stubbed above), leaves the turn
        # untouched rather than erroring or withholding the answer.
        rac = c.post("/api/chat/message", headers=AUTH,
                     json={"session_id": sid, "message": "I have a sore throat.",
                           "disclaimer_accepted": True, "agent_control_review": True})
        check("POST /api/chat/message agent_control_review=true -> 200 + message",
              rac.status_code == 200 and bool(rac.json().get("message")), f"{rac.status_code}")
        # Resume-after-restart: a conversation reloaded from the DB must persist
        # its next turn. _prepare_session used to hold the ORM-loaded messages
        # list BY REFERENCE and mutate it in place; with a plain JSON column (no
        # MutableList) SQLAlchemy compared the attribute against itself, saw no
        # change, and omitted `messages` from the UPDATE — so the first turn
        # after a restart was written to nothing. Dropping the in-memory entry is
        # exactly what a process restart does.
        import backend.routers.chat as chat_router  # noqa: E402
        from backend.database.db import get_db_context  # noqa: E402
        from backend.models.db_models import Conversation  # noqa: E402

        rsum = c.post("/api/chat/message", headers=AUTH,
                      json={"session_id": sid, "message": "before the restart",
                            "disclaimer_accepted": True})
        check("resume: pre-restart turn -> 200", rsum.status_code == 200, f"{rsum.status_code}")
        with get_db_context() as _s:
            _before = len((_s.query(Conversation)
                           .filter(Conversation.session_id == sid).first().messages) or [])
        chat_router.sessions.pop(sid, None)      # simulate the restart
        rres = c.post("/api/chat/message", headers=AUTH,
                      json={"session_id": sid, "message": "after the restart",
                            "disclaimer_accepted": True})
        check("resume: post-restart turn -> 200", rres.status_code == 200, f"{rres.status_code}")
        with get_db_context() as _s:
            _msgs = (_s.query(Conversation)
                     .filter(Conversation.session_id == sid).first().messages) or []
        check("resume: post-restart turn was persisted (grew by user+assistant)",
              len(_msgs) >= _before + 2, f"{_before} -> {len(_msgs)}")
        check("resume: the resumed user message is in the stored history",
              any(m.get("content") == "after the restart" for m in _msgs),
              str([m.get("content") for m in _msgs][-4:]))

        check("GET /api/chat/auto-prompt/status -> 200", c.get("/api/chat/auto-prompt/status", headers=AUTH).status_code == 200)
        check("POST /api/chat/auto-prompt/start -> 200 (stubbed)", c.post("/api/chat/auto-prompt/start", headers=AUTH).status_code == 200)
        check("POST /api/chat/auto-prompt/stop -> 200", c.post("/api/chat/auto-prompt/stop", headers=AUTH).status_code == 200)

        # ---- incident (no real load: drive_traffic false, then stop) ----
        check("GET /api/incident/status -> 200", c.get("/api/incident/status", headers=AUTH).status_code == 200)
        rinc = c.post("/api/incident/start", headers=AUTH,
                      json={"latency_ms": 0, "error_rate": 0, "duration_s": 10, "drive_traffic": False})
        check("POST /api/incident/start (no load) -> 200 + active",
              rinc.status_code == 200 and rinc.json().get("active") is True, f"{rinc.status_code}")
        check("POST /api/incident/stop -> 200 + inactive",
              c.post("/api/incident/stop", headers=AUTH).json().get("active") is False)

        # ---- prompt-injection spray (no real turns: drive_turns false) ----
        # drive_turns=False keeps the suite off the live AI Defense API; the
        # control plane (state, counters, auto-stop wiring) is still exercised.
        check("GET /api/spray/status -> 200", c.get("/api/spray/status", headers=AUTH).status_code == 200)
        rspray = c.post("/api/spray/start", headers=AUTH,
                        json={"actor": "t.nguyen", "duration_s": 10, "intensity": 5,
                              "secondary_actors": 1, "drive_turns": False})
        check("POST /api/spray/start (no turns) -> 200 + active",
              rspray.status_code == 200 and rspray.json().get("active") is True,
              f"{rspray.status_code}")
        check("POST /api/spray/start reports the requested actor",
              rspray.json().get("actor") == "t.nguyen", str(rspray.json().get("actor")))
        _first_campaign = rspray.json().get("campaign_id")
        check("POST /api/spray/start mints a campaign_id", bool(_first_campaign))
        # Re-running must produce a *fresh* campaign, not a no-op: a demo gets
        # rehearsed, and stale ids would collide in Splunk.
        rspray2 = c.post("/api/spray/start", headers=AUTH,
                         json={"actor": "t.nguyen", "duration_s": 10, "intensity": 5,
                               "secondary_actors": 1, "drive_turns": False})
        check("POST /api/spray/start twice -> new campaign_id (re-runnable)",
              rspray2.json().get("campaign_id") not in (None, _first_campaign))
        check("POST /api/spray/stop -> 200 + inactive",
              c.post("/api/spray/stop", headers=AUTH).json().get("active") is False)
        check("spray start rejects an out-of-range intensity",
              c.post("/api/spray/start", headers=AUTH,
                     json={"intensity": 0, "drive_turns": False}).status_code == 422)
        # The campaign is attributed to the app that triggered it. It used to
        # rotate a fixed roster, so a spray launched from medadvice stamped
        # governance events with pseudoco-assistant-financeadvice/-legaladvice too. Planned
        # directly: drive_turns=False records no turns, so `apps_targeted` on the
        # status response can't observe this.
        import random as _random  # noqa: PLC0415 - local to this check
        from backend.routers.spray import SprayStart, _build_plan  # noqa: PLC0415

        def _plan_apps(theme):
            body = SprayStart(drive_turns=False) if theme is None else \
                SprayStart(theme=theme, drive_turns=False)
            return sorted({t.app["service_name"] for t in _build_plan(body, _random.Random(11))})

        check("spray plan stamps only the triggering app",
              _plan_apps("medadvice") == ["pseudoco-assistant-medadvice"], str(_plan_apps("medadvice")))
        check("spray plan follows a non-default theme",
              _plan_apps("taxadvice") == ["pseudoco-assistant-taxadvice"], str(_plan_apps("taxadvice")))
        check("spray plan defaults to medadvice when no theme is sent",
              _plan_apps(None) == ["pseudoco-assistant-medadvice"], str(_plan_apps(None)))
        check("spray duration defaults to 60s (matches the drawer default)",
              SprayStart(drive_turns=False).duration_s == 60, str(SprayStart(drive_turns=False).duration_s))

        # ---- agentic tool guard ----
        # 401 without the key (auth gate), 200 with it. Use a benign read whose
        # path is inside the workspace so tool_policy short-circuits locally and
        # no live AI Defense call is made (AI Defense is not stubbed here).
        check("POST /api/toolguard/inspect -> 401 without key",
              c.post("/api/toolguard/inspect",
                     json={"tool_name": "read", "arguments": {}}).status_code == 401)
        roots = settings.tool_guard_workspace_roots_list
        safe_path = (roots[0] if roots else "/tmp") + "/inbox/note.md"
        rtg = c.post("/api/toolguard/inspect", headers=AUTH,
                     json={"tool_name": "read", "arguments": {"path": safe_path},
                           "session_id": "api-test", "tool_call_id": "c1"})
        check("POST /api/toolguard/inspect (benign read) -> 200 allow",
              rtg.status_code == 200 and rtg.json().get("decision") == "allow"
              and rtg.json().get("block") is False, f"{rtg.status_code} {rtg.text[:120]}")
        check("GET /api/toolguard/policy -> 200 + sensitive_tools",
              (rpol := c.get("/api/toolguard/policy", headers=AUTH)).status_code == 200
              and "sensitive_tools" in rpol.json(), f"{rpol.status_code}")
        check("policy report carries the NemoClaw layer", "nemoclaw" in rpol.json())

        # ---- NemoClaw Guardrails: server-side toggle + policy-layer enforcement ----
        # The toggle persists to the AppSettings row: snapshot and restore it.
        _saved_nc = c.get("/api/toolguard/nemoclaw", headers=AUTH).json()
        _saved_tg = settings.tool_guard_enabled
        try:
            check("GET /api/toolguard/nemoclaw -> enabled/policy/runtime",
                  {"enabled", "policy", "runtime"} <= set(_saved_nc) and _saved_nc["policy"].get("loaded") is True,
                  str(_saved_nc)[:160])
            ron = c.put("/api/toolguard/nemoclaw", headers=AUTH, json={"enabled": True})
            check("PUT /api/toolguard/nemoclaw enabled -> 200 + enabled", ron.status_code == 200 and ron.json()["enabled"] is True)
            settings.tool_guard_enabled = False   # the NemoClaw toggle enforces on its own
            rblk = c.post("/api/toolguard/inspect", headers=AUTH,
                          json={"tool_name": "web_fetch", "arguments": {"url": "https://evil.example.com/collect"},
                                "session_id": "api-test", "tool_call_id": "c2"})
            jb = rblk.json() if rblk.status_code == 200 else {}
            check("NemoClaw ON: unlisted egress is blocked and enforced by nemoclaw with the tool guard OFF",
                  jb.get("decision") == "block" and jb.get("block") is True and jb.get("enforced_by") == ["nemoclaw"]
                  and "NemoClaw: network egress" in jb.get("rule_names", []), f"{rblk.status_code} {rblk.text[:200]}")
            rok = c.post("/api/toolguard/inspect", headers=AUTH,
                         json={"tool_name": "read", "arguments": {"path": safe_path}, "session_id": "api-test"})
            check("NemoClaw ON: a benign in-scope read still passes", rok.json().get("block") is False, rok.text[:160])
            c.put("/api/toolguard/nemoclaw", headers=AUTH, json={"enabled": False})
            rob = c.post("/api/toolguard/inspect", headers=AUTH,
                         json={"tool_name": "web_fetch", "arguments": {"url": "https://evil.example.com/collect"}})
            check("NemoClaw OFF: the same egress is observed (legacy egress rule) but not enforced by nemoclaw",
                  rob.json().get("block") is False and "nemoclaw" not in rob.json().get("enforced_by", []), rob.text[:200])
            # Runtime feed: an OCSF denial from the sandbox and an after_tool_call error.
            rev = c.post("/api/toolguard/nemoclaw/events", headers=AUTH, json={"records": [
                {"class_uid": 4001, "action": "Denied", "disposition": "Blocked", "status_detail": "no matching policy",
                 "dst_endpoint": {"domain": "evil.example.com", "port": 443},
                 "actor": {"process": {"name": "/usr/bin/curl"}}, "firewall_rule": {"name": "baseline"}},
                {"class_uid": 4001, "action": "Allowed", "dst_endpoint": {"domain": "pypi.org", "port": 443}},
            ]})
            check("POST /api/toolguard/nemoclaw/events -> logs only the Denied record",
                  rev.status_code == 200 and rev.json().get("denials_logged") == 1 and rev.json().get("received") == 2, rev.text[:160])
            robs = c.post("/api/toolguard/observe", headers=AUTH,
                          json={"tool_name": "web_fetch", "error": '{"error":"policy_denied","detail":"POST /collect not permitted by policy"}'})
            check("POST /api/toolguard/observe attributes a policy_denied tool error", robs.json().get("attributed") is True)
            check("... and ignores an ordinary error",
                  c.post("/api/toolguard/observe", headers=AUTH, json={"tool_name": "read", "error": "ECONNRESET"}).json().get("attributed") is False)
            check("runtime status counts the forwarded denials",
                  c.get("/api/toolguard/nemoclaw", headers=AUTH).json()["runtime"]["events_recent"] >= 2)
        finally:
            settings.tool_guard_enabled = _saved_tg
            c.put("/api/toolguard/nemoclaw", headers=AUTH, json={"enabled": bool(_saved_nc.get("enabled"))})

        # ---- settings ----
        # These PUTs persist to the AppSettings row in ./medadvice.db — the SAME
        # database the live app reads. Snapshot and restore both values so a test
        # run cannot silently disable an operator's Emit Static Model or reset a
        # custom logs directory (this suite advertises itself as side-effect-safe).
        _saved_logs_dir = c.get("/api/settings", headers=AUTH).json().get("logs_directory")
        _saved_emit = c.get("/api/settings/emit-model", headers=AUTH).json()

        rs = c.get("/api/settings", headers=AUTH)
        check("GET /api/settings -> 200 + logs_directory", rs.status_code == 200 and "logs_directory" in rs.json())
        check("PUT /api/settings -> 200", c.put("/api/settings", headers=AUTH, json={"logs_directory": "logs"}).status_code == 200)
        rem = c.get("/api/settings/emit-model", headers=AUTH)
        check("GET /api/settings/emit-model -> 200 + choices", rem.status_code == 200 and "choices" in rem.json())
        check("PUT /api/settings/emit-model valid -> 200",
              c.put("/api/settings/emit-model", headers=AUTH, json={"enabled": False, "model_name": "gpt-4o", "random": False}).status_code == 200)
        check("PUT /api/settings/emit-model unknown model -> 422",
              c.put("/api/settings/emit-model", headers=AUTH, json={"enabled": True, "model_name": "not-a-real-model", "random": False}).status_code == 422)

        # ---- host capabilities (what this box can run -> greyed-out options) ----
        rsi = c.get("/api/server-info", headers=AUTH)
        check("GET /api/server-info -> 200 + hostname", rsi.status_code == 200 and "hostname" in rsi.json())
        check("server-info carries the running app version (chat footer)",
              isinstance(rsi.json().get("version"), str) and rsi.json()["version"].count(".") == 2)
        check("server-info carries capabilities + gated (may be empty before the first probe)",
              "capabilities" in rsi.json() and "gated" in rsi.json())
        rref = c.post("/api/server-info/refresh", headers=AUTH)
        gated = rref.json().get("gated", {}) if rref.status_code == 200 else {}
        check("POST /api/server-info/refresh -> 200 + probed gating rules",
              rref.status_code == 200 and {"provider_nvidia", "nim_local", "nemoclaw_runtime", "nvidia_models"} <= set(gated),
              f"{rref.status_code} {sorted(gated)}")
        check("each gate is {enabled, reason}",
              all({"enabled", "reason"} <= set(gated[k]) for k in ("provider_nvidia", "nim_local", "nemoclaw_runtime")))
        check("GET /api/settings/ai-provider exposes the local-NIM status block",
              "nvidia" in c.get("/api/settings/ai-provider", headers=AUTH).json())

        # ---- blueprint (agentic architecture) selection — persists: snapshot/restore ----
        rbp = c.get("/api/settings/blueprint", headers=AUTH)
        _saved_bp = rbp.json().get("active") if rbp.status_code == 200 else None
        try:
            choices = {b["key"]: b for b in rbp.json().get("choices", [])} if rbp.status_code == 200 else {}
            check("GET /api/settings/blueprint -> 200 + active + choices with labels/stage_labels",
                  rbp.status_code == 200 and _saved_bp in choices
                  and all({"key", "label", "description", "workflow_name", "stage_labels", "core_nodes"} <= set(b) for b in choices.values()),
                  rbp.text[:200])
            check("the shipped architecture is a blueprint choice", "pseudoco_multi_agent" in choices)
            check("PUT /api/settings/blueprint unknown -> 422",
                  c.put("/api/settings/blueprint", headers=AUTH, json={"key": "not-a-blueprint"}).status_code == 422)
            rput = c.put("/api/settings/blueprint", headers=AUTH, json={"key": "pseudoco_multi_agent"})
            check("PUT /api/settings/blueprint valid -> 200 + active echoed",
                  rput.status_code == 200 and rput.json().get("active") == "pseudoco_multi_agent")
            # A per-request override is accepted by the chat endpoint (unknown keys fall back).
            _bp_sid = c.post("/api/chat/session/new", headers=AUTH).json()["session_id"]
            rturn = c.post("/api/chat/message", headers=AUTH,
                           json={"session_id": _bp_sid, "message": "parity check", "disclaimer_accepted": True,
                                 "blueprint": "pseudoco_multi_agent"})
            check("POST /api/chat/message accepts a per-request blueprint", rturn.status_code == 200, rturn.text[:160])
        finally:
            if _saved_bp:
                c.put("/api/settings/blueprint", headers=AUTH, json={"key": _saved_bp})

        # Restore the operator's values (mirrors the ai_defense discovery restore
        # further down). Best-effort: a failure here must not mask a real result.
        try:
            if _saved_logs_dir:
                c.put("/api/settings", headers=AUTH, json={"logs_directory": _saved_logs_dir})
            if _saved_emit.get("model_name"):
                c.put("/api/settings/emit-model", headers=AUTH, json={
                    "enabled": bool(_saved_emit.get("enabled")),
                    "model_name": _saved_emit["model_name"],
                    "random": bool(_saved_emit.get("random")),
                })
        except Exception as exc:  # noqa: BLE001
            print(f"  WARN: could not restore settings: {exc}")
        rsi = c.get("/api/server-info", headers=AUTH)
        check("GET /api/server-info -> 200 + non-empty hostname",
              rsi.status_code == 200 and bool(rsi.json().get("hostname")), f"{rsi.status_code}")
        check("GET /api/server-info -> 401 without key", c.get("/api/server-info").status_code == 401)

        # ---- HEC destinations CRUD ----
        rd = c.get("/api/hec/destinations", headers=AUTH)
        check("GET /api/hec/destinations -> 200 + list", rd.status_code == 200 and "destinations" in rd.json())
        rc = c.post("/api/hec/destinations", headers=AUTH, json={"name": "apitest-dest"})
        check("POST /api/hec/destinations -> 200 + id", rc.status_code == 200 and rc.json().get("id"), f"{rc.status_code}")
        did = rc.json().get("id", "") if rc.status_code == 200 else ""
        check("GET /api/hec/destinations/{id} -> 200", c.get(f"/api/hec/destinations/{did}", headers=AUTH).status_code == 200)
        check("PUT /api/hec/destinations/{id} -> 200", c.put(f"/api/hec/destinations/{did}", headers=AUTH, json={"index": "main2"}).status_code == 200)
        check("GET /api/hec/stats -> 200 + destinations", "destinations" in c.get("/api/hec/stats", headers=AUTH).json())
        check("DELETE /api/hec/destinations/{id} -> 200", c.delete(f"/api/hec/destinations/{did}", headers=AUTH).status_code == 200)
        check("GET /api/hec/destinations/{bad} -> 404", c.get("/api/hec/destinations/nope", headers=AUTH).status_code == 404)

        # HEC envelope: a key in BOTH the indexed "fields" block and the event
        # body is indexed *and* extracted at search time (gen_ai:json sets
        # KV_MODE=json), so Splunk returns it as a two-value multivalue field and
        # every `stats ... by <key>` silently doubles -- including the ES prompt
        # injection rule's per-actor risk. Pin the invariant here.
        from backend.hec.config import HECConfig as _HECConfig
        from backend.hec.forwarder import HECForwarder as _HECFwd, _BODY_OWNED_KEYS
        _fwd = _HECFwd(_HECConfig(id="t", name="t", url="https://localhost:8088"), "tok")
        _body = {"session_id": "s1", "request_id": "r1", "trace_id": "t1",
                 "enduser_id": "t.nguyen", "risk_score": 60}
        _env = _fwd._build_event("governance", _body)
        _dupes = sorted(set(_env["fields"]) & set(_env["event"]))
        check("HEC envelope: no field is both indexed and in the event body",
              not _dupes, f"duplicated: {_dupes}")
        check("HEC envelope: correlation ids stay in the event body",
              all(k in _env["event"] for k in _BODY_OWNED_KEYS))
        check("HEC envelope: forwarder-owned log_type is still indexed",
              _env["fields"].get("log_type") == "governance")

        # ---- admin ----
        for path in ("/admin/logs/interactions", "/admin/logs/escalations", "/admin/logs/metrics", "/admin/logs/export"):
            check(f"GET {path} -> 200", c.get(path, headers=AUTH).status_code == 200)

        # Escalation review: reviewer_id/review_notes are BODY fields. They were
        # bare scalar params, which FastAPI binds as required QUERY params, so
        # the admin UI's JSON body produced a 422 on every single click. A 404
        # here is the pass condition — it proves the body validated and the
        # handler ran far enough to look the escalation up.
        rrev = c.put("/admin/escalations/no-such-escalation/review?new_status=reviewed",
                     headers=AUTH, json={"reviewer_id": "admin", "review_notes": "looks fine"})
        check("PUT /admin/escalations/{id}/review (JSON body) -> body accepted, 404 for unknown id",
              rrev.status_code == 404, f"{rrev.status_code} {rrev.text[:160]}")
        check("PUT /admin/escalations/{id}/review missing body -> 422",
              c.put("/admin/escalations/x/review?new_status=reviewed",
                    headers=AUTH).status_code == 422)
        check("PUT /admin/escalations/{id}/review bad new_status -> 422",
              c.put("/admin/escalations/x/review?new_status=bogus", headers=AUTH,
                    json={"reviewer_id": "a", "review_notes": "b"}).status_code == 422)

        # ---- CORS: explicit origins only, and preflights survive the gate ----
        # The access-key middleware wraps CORSMiddleware, so an unauthenticated
        # OPTIONS used to 401 before CORS could answer it.
        pre = c.options("/api/settings", headers={
            "Origin": f"http://localhost:{settings.port}",
            "Access-Control-Request-Method": "GET",
        })
        check("OPTIONS preflight is not blocked by the access-key gate",
              pre.status_code != 401, f"{pre.status_code}")
        check("preflight echoes the configured origin",
              pre.headers.get("access-control-allow-origin") == f"http://localhost:{settings.port}",
              str(pre.headers.get("access-control-allow-origin")))
        eviltrip = c.get("/health", headers={"Origin": "https://evil.example.com"})
        check("unconfigured origin gets no allow-origin header",
              "access-control-allow-origin" not in eviltrip.headers,
              str(eviltrip.headers.get("access-control-allow-origin")))

        # ---- auth (login/logout) ----
        bad = c.post("/login", data={"access_code": "wrong-code"}, follow_redirects=False)
        check("POST /login wrong code -> not authenticated (no md_access cookie)",
              "md_access" not in bad.cookies)
        good = c.post("/login", data={"access_code": KEY}, follow_redirects=False)
        check("POST /login correct code -> redirect + md_access cookie",
              good.status_code in (302, 303, 200) and "md_access" in good.cookies, f"{good.status_code}")
        check("GET /logout -> 2xx/3xx", c.get("/logout", headers=AUTH, follow_redirects=False).status_code in (200, 302, 303))

        # ---- settings gate (a SECOND code, hardcoded, in front of /settings-ui) ----
        # Runs before anything unlocks it, so the locked case is genuinely locked.
        from backend.middleware.settings_gate import SETTINGS_ACCESS_CODE  # noqa: PLC0415
        locked = c.get("/settings-ui", headers=AUTH, follow_redirects=False)
        check("GET /settings-ui without the settings code -> redirect to /settings-login",
              locked.status_code in (302, 303)
              and "/settings-login" in locked.headers.get("location", ""),
              f"{locked.status_code} {locked.headers.get('location')}")
        check("GET /settings-login -> 200 HTML (still behind the app key)",
              c.get("/settings-login", headers=AUTH).status_code == 200)
        check("GET /settings-login without the app key -> 401",
              c.get("/settings-login", headers={"accept": "text/html"}).status_code == 401)
        s_bad = c.post("/settings-login", headers=AUTH,
                       data={"access_code": "wrong-code"}, follow_redirects=False)
        check("POST /settings-login wrong code -> no md_settings cookie",
              "md_settings" not in s_bad.cookies)
        check("the app key alone does not unlock settings",
              c.get("/settings-ui", headers=AUTH, follow_redirects=False).status_code in (302, 303))
        s_ok = c.post("/settings-login", headers=AUTH,
                      data={"access_code": SETTINGS_ACCESS_CODE}, follow_redirects=False)
        check("POST /settings-login correct code -> redirect + md_settings cookie",
              s_ok.status_code in (302, 303) and "md_settings" in s_ok.cookies,
              f"{s_ok.status_code}")
        check("GET /settings-ui with the settings code -> 200 HTML",
              (lambda r: r.status_code == 200 and "<html" in r.text.lower())(
                  c.get("/settings-ui", headers=AUTH)))
        check("the settings cookie is not the app cookie (one gate never opens the other)",
              c.cookies.get("md_settings") != c.cookies.get("md_access"))
        check("GET /settings-logout -> 2xx/3xx",
              c.get("/settings-logout", headers=AUTH, follow_redirects=False).status_code in (200, 302, 303))
        check("after /settings-logout, /settings-ui is locked again",
              c.get("/settings-ui", headers=AUTH, follow_redirects=False).status_code in (302, 303))
        # Re-unlock: the Settings UI invariants further down read the real page.
        c.post("/settings-login", headers=AUTH,
               data={"access_code": SETTINGS_ACCESS_CODE}, follow_redirects=False)

        # ---- server-rendered pages (HTML, with key) ----
        # /settings-ui is NOT here: it sits behind a second code (block above).
        for path in ("/app", "/admin-ui", "/governance-ui", "/appointments-ui"):
            r = c.get(path, headers=AUTH)
            check(f"GET {path} -> 200 HTML", r.status_code == 200 and "<html" in r.text.lower(), f"{r.status_code}")

        # ---- appointment scheduling, end to end through the API (docs/scheduling.md) ----
        # The stubbed LLM answers LOW, so medadvice offers on the first answer.
        import json as _json  # noqa: PLC0415
        import uuid as _uuid  # noqa: PLC0415
        from backend.services.scheduling import store as _appt_store  # noqa: PLC0415
        _cid = f"test-{_uuid.uuid4().hex[:10]}"
        _ssid = c.post("/api/chat/session/new", headers=AUTH).json()["session_id"]
        _sp = {"session_id": _ssid, "message": "I have a mild sore throat and want advice",
               "disclaimer_accepted": True, "client_id": _cid, "client_tz": "America/New_York"}
        try:
            r1 = c.post("/api/chat/message", headers=AUTH, json=_sp)
            s1 = (r1.json().get("scheduling") if r1.status_code == 200 else None) or {}
            check("scheduling: first answer asks whether it resolved the concern (JSON endpoint)",
                  r1.status_code == 200 and s1.get("state") == "check_resolved" and bool(s1.get("message"))
                  and not s1.get("slots"), r1.text[:200])
            check("scheduling: the check's chips are Yes / No",
                  [a.get("action") for a in s1.get("actions", [])] == ["resolved", "not_resolved"])
            check("scheduling: the answer itself carries no offer copy", "follow-up visit" not in r1.json().get("message", ""))
            rs = c.post("/api/chat/message/stream", headers=AUTH, json=dict(_sp, message="I also have a mild headache"))
            _frames = [_json.loads(l[6:]) for l in rs.text.splitlines() if l.startswith("data: ")]
            _final = next((f for f in _frames if f.get("event") == "final"), {})
            check("scheduling: SSE final frame carries the scheduling key", rs.status_code == 200 and "scheduling" in _final)
            # The stub's answer parses to one severity for both turns; medadvice
            # re-offers on a later MEDIUM/HIGH answer and stays quiet on LOW.
            _sev = r1.json().get("severity")
            check("scheduling: later answers re-offer only per the theme's severity policy",
                  (_final.get("scheduling") is not None) == (_sev in ("MEDIUM", "HIGH")),
                  f"severity={_sev} re-offered={_final.get('scheduling') is not None}")
            check("scheduling: scheduling stage frames streamed",
                  {"scheduling_intake", "scheduling"} <= {f.get("node") for f in _frames if f.get("event") == "stage"})
            r1b = c.post("/api/chat/message", headers=AUTH,
                         json=dict(_sp, message="No, I still have concerns", scheduling_action={"action": "not_resolved"}))
            s1b = r1b.json().get("scheduling") or {}
            check("scheduling: 'No' brings the offer with 3 slot chips + More times + No thanks",
                  s1b.get("state") == "offered"
                  and [a.get("action") for a in s1b.get("actions", [])] == ["book", "book", "book", "more_times", "decline"],
                  r1b.text[:200])
            check("scheduling: the verticalized offer copy is the reply", "follow-up visit" in r1b.json().get("message", ""))
            _slot = s1b["slots"][1]
            r2 = c.post("/api/chat/message", headers=AUTH,
                        json=dict(_sp, message="Book " + _slot["label"],
                                  scheduling_action={"action": "book", "slot_id": _slot["slot_id"]}))
            s2 = r2.json().get("scheduling") or {}
            check("scheduling: chip book without a known name -> awaiting_name",
                  s2.get("state") == "awaiting_name" and (s2.get("pending") or {}).get("slot_id") == _slot["slot_id"], r2.text[:200])
            r3 = c.post("/api/chat/message", headers=AUTH, json=dict(_sp, message="Alex Rivera"))
            s3 = r3.json().get("scheduling") or {}
            _appt = s3.get("appointment") or {}
            check("scheduling: a bare name completes the booking",
                  s3.get("state") == "booked" and _appt.get("name") == "Alex Rivera" and _appt.get("label") == _slot["label"], r3.text[:200])
            _last_meta = ((c.get(f"/api/chat/session/{_ssid}", headers=AUTH).json().get("messages") or [{}])[-1].get("metadata") or {})
            check("scheduling: metadata.scheduling persisted on the assistant message",
                  (_last_meta.get("scheduling") or {}).get("state") == "booked")
            r4 = c.post("/api/chat/message", headers=AUTH, json=dict(_sp, message="what's on my schedule?"))
            s4 = r4.json().get("scheduling") or {}
            check("scheduling: 'my schedule' lists with Reschedule/Cancel chips",
                  s4.get("state") == "listed" and [a.get("action") for a in s4.get("actions", [])] == ["reschedule", "cancel"], r4.text[:200])
            check("scheduling: a scheduling turn is not escalated by the safety rules", r4.json().get("escalated") is False)
            check("GET /api/appointments requires client_id", c.get("/api/appointments", headers=AUTH).status_code == 422)
            la = c.get(f"/api/appointments?client_id={_cid}&tz=America/New_York", headers=AUTH).json()
            check("GET /api/appointments lists the booking with its local label",
                  la.get("total") == 1 and la["appointments"][0]["id"] == _appt.get("id")
                  and la["appointments"][0].get("label") == _slot["label"], str(la)[:200])
            check("GET /api/appointments is per client",
                  c.get("/api/appointments?client_id=someone-else", headers=AUTH).json().get("total") == 0)
            check("PUT /api/appointments/{id} with the wrong client -> 404",
                  c.put(f"/api/appointments/{_appt.get('id')}", headers=AUTH,
                        json={"client_id": "someone-else", "status": "cancelled"}).status_code == 404)
            check("PUT /api/appointments/{id} with nothing to update -> 422",
                  c.put(f"/api/appointments/{_appt.get('id')}", headers=AUTH, json={"client_id": _cid}).status_code == 422)
            up = c.put(f"/api/appointments/{_appt.get('id')}", headers=AUTH, json={"client_id": _cid, "status": "cancelled"})
            check("PUT /api/appointments/{id} cancels", up.status_code == 200 and up.json().get("status") == "cancelled", up.text[:160])
            check("GET /api/appointments hides the cancelled booking by default",
                  c.get(f"/api/appointments?client_id={_cid}", headers=AUTH).json().get("total") == 0)
            _nosid = c.post("/api/chat/session/new", headers=AUTH).json()["session_id"]
            r5 = c.post("/api/chat/message", headers=AUTH,
                        json={"session_id": _nosid, "message": "mild sore throat", "disclaimer_accepted": True})
            check("scheduling: no client_id -> inert (no scheduling key)", r5.status_code == 200 and r5.json().get("scheduling") is None)
            check("scheduling: a malformed client_id is rejected (422)",
                  c.post("/api/chat/message", headers=AUTH, json=dict(_sp, client_id="bad id!")).status_code == 422)
        finally:
            _appt_store.delete_for_client(_cid)   # the suite runs against the live DB

        # ---- Settings page UI invariants: collapsible sections + read-only provider pill ----
        s_html = c.get("/settings-ui", headers=AUTH).text
        _js = (ROOT / "frontend" / "js" / "settings.js").read_text()
        SETTINGS_JS_SECTIONS = re.search(r"const SECTIONS = \[(.*?)\]", _js).group(1)
        # Every collapsible card. Keep in sync with SECTIONS in frontend/js/settings.js —
        # a card missing from that array still toggles, but its collapsed state is
        # silently dropped on reload.
        sections = ("controls", "logs", "creds", "aidefense", "nemo", "o11y", "hec")
        check(f"Settings: a collapsible toggle per section ({len(sections)})",
              all(f'data-toggle="{s}"' in s_html for s in sections))
        check(f"Settings: a collapsible body per section ({len(sections)})",
              all(f'id="section-{s}"' in s_html for s in sections))
        check("Settings: a chevron per collapsible header",
              s_html.count("data-chevron") == len(sections))
        check("Settings: settings.js registers every section for collapse persistence",
              all(f"'{s}'" in SETTINGS_JS_SECTIONS for s in sections))
        check("Settings: read-only provider/model pill present", 'id="providerPill"' in s_html)
        # The integration cards render client-side; assert their mount points exist.
        check("Settings: AI Defense + NeMo Guardrails + Splunk O11y field containers present",
              'id="aiDefenseFields"' in s_html and 'id="nemoFields"' in s_html and 'id="o11yFields"' in s_html)
        check("Settings: Demo Controls visibility panel mount point + status line present",
              'id="demoControlsList"' in s_html and 'id="controlsStatus"' in s_html)
        check("Settings: host-capabilities strip present (greyed-out options explained here)",
              'id="hostCaps"' in s_html)
        # Accordion a11y: each toggle is a <button> nested INSIDE its <h2> (heading role preserved),
        # never an <h2> nested inside a <button> (which screen readers flatten away).
        check("Settings: headers use accordion <h2><button> (heading not nested in button)",
              s_html.count('aria-controls="section-') == len(sections)
              and re.search(r"<button[^>]*>\s*<h2", s_html) is None)

        # HEC destination cards: loadDestinations() re-renders the card's innerHTML,
        # which blanks the <span data-result> feedback. So the re-render MUST come
        # before setResult(), or the Save/Test result flashes and vanishes.
        for _fn in ("saveDestination", "testDestination"):
            _body = re.search(r"async function " + _fn + r"\(id\) \{(.*?)\n\}", _js, re.S).group(1)
            _try = _body[:_body.index("} catch")]   # the catch handler always trails; ignore it
            _reload = _try.find("loadDestinations()")
            _result = _try.rfind("setResult(")
            check(f"Settings: {_fn} re-renders before writing its result",
                  _reload != -1 and _result != -1 and _reload < _result)

        # ---- Chat page UI invariants: Demo Controls drawer groups + uniform pills ----
        a_html = c.get("/app", headers=AUTH).text
        _chat_js = (ROOT / "frontend" / "js" / "chat.js").read_text()
        _drawer = a_html[a_html.index('id="settingsDrawer"'):a_html.index('id="drawerToggle"')]
        for g in ("guardrails", "pipeline", "synthetic", "generators", "display"):
            check(f"Drawer: group section '{g}' present", f'data-group="{g}"' in _drawer)
        _card = 'bg-gray-50 border border-gray-200 rounded-lg p-3'
        _in_groups = sum(sec.count(_card) for sec in
                         re.findall(r"<section [^>]*data-group=[^>]*>(.*?)</section>", _drawer, re.S))
        check("Drawer: every control card sits inside a group (none loose at top level)",
              _drawer.count(_card) == _in_groups and _in_groups >= 14, f"{_drawer.count(_card)} vs {_in_groups}")
        # The Settings-page visibility panel keys on this hook (CLAUDE.md sync rule;
        # tests/test_demo_controls.py checks the keys against the registry).
        check("Drawer: every control card carries a data-control hook (visibility panel)",
              _drawer.count('data-control="') == _drawer.count(_card),
              f"{_drawer.count('data-control=')} hooks vs {_drawer.count(_card)} cards")
        check("Drawer: spray card is 'Prompt Injection Spray' (no hyphen anywhere on the page)",
              "Prompt Injection Spray" in _drawer and "Prompt-Injection" not in a_html)
        check("Drawer: spray duration defaults to 60s",
              re.search(r'id="sprayDuration"[^>]*value="60"', _drawer) is not None)
        check("Drawer: pills carry only the uniform On/Off text in the markup",
              re.search(r'id="\w+Status"[^>]*>\s*(OFF|ON|ALWAYS ON)\s*<', _drawer) is None)
        check("Drawer: the default-on pill (Internal Policy) is the green On pill",
              re.search(r'id="internalPolicyStatus"[^>]*bg-green-100 text-green-700[^>]*>\s*On\s*<', _drawer) is not None)
        # One toggle accent for every card: an On switch looks the same whichever control it is.
        _accents = set(re.findall(r"peer-checked:bg-[a-z]+-\d+|peer-focus:ring-[a-z]+-\d+", _drawer))
        check("Drawer: every toggle uses the same On accent (green-600 / ring-green-300)",
              _accents == {"peer-checked:bg-green-600", "peer-focus:ring-green-300"}, str(sorted(_accents)))
        # Pill classes come from ONE place (setPill) so no card can grow its own ON palette.
        check("chat.js: pill classes are only assigned by setPill()",
              "function setPill(" in _chat_js and "rounded-full bg-" not in _chat_js)
        check("Chat: Show Recent button + modal present",
              'id="showRecentButton"' in a_html and 'id="recentSessionsModal"' in a_html)
        check("chat.js: Show Recent reloads via the existing session endpoint",
              "function loadRecentSession(" in _chat_js and "'/api/chat/session/' + encodeURIComponent(id)" in _chat_js)

    # ---- AI Defense per-direction guardrail config (no client needed) ----
    prompt_rules = {r["rule_name"] for r in settings.ai_defense_rule_config}
    resp_rules = {r["rule_name"] for r in settings.ai_defense_response_rule_config}
    check("AI Defense response rules drop prompt-only Prompt Injection",
          "Prompt Injection" not in resp_rules)
    check("AI Defense response rules drop prompt-only Code Detection",
          "Code Detection" not in resp_rules)
    check("AI Defense response rules keep PHI/PII content-harm guardrails",
          {"PHI", "PII"} <= resp_rules)
    check("AI Defense prompt rules still include Prompt Injection",
          "Prompt Injection" in prompt_rules)
    _saved = settings.ai_defense_prescription_guardrail
    settings.ai_defense_prescription_guardrail = "Unauthorized Prescription"
    check("AI Defense custom prescription guardrail appends on response direction",
          settings.ai_defense_response_rule_config[-1]["rule_name"] == "Unauthorized Prescription")
    settings.ai_defense_prescription_guardrail = _saved

    # ---- AI Defense enabled_rules discovery persists across restarts ----
    # A connection with an SCC policy bound rejects config.enabled_rules (HTTP
    # 400 + one retry). The discovery is persisted so a fresh client (i.e. a
    # process restart) skips the wasted round-trip instead of re-probing.
    import backend.settings_store as settings_store
    from backend.services.ai_defense import AIDefenseClient
    _prev = settings_store.get_ai_defense_enabled_rules_supported()
    settings_store.set_ai_defense_enabled_rules_supported(False)
    check("AI Defense enabled_rules discovery persists (set False -> read False)",
          settings_store.get_ai_defense_enabled_rules_supported() is False)
    check("fresh AIDefenseClient honors the persisted discovery (no re-probe)",
          AIDefenseClient()._rules_supported() is False)
    settings_store.set_ai_defense_enabled_rules_supported(_prev)

    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
