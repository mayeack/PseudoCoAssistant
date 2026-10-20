#!/usr/bin/env python3
"""Regression: the NVIDIA AI Virtual Assistant blueprint
(backend/agents/blueprints/nvidia_virtual_assistant.py + data / retrieval + /api/analytics).

Parity with the PseudoCo Assistant blueprint is asserted by tests/test_blueprint_parity.py;
this suite guards what is SPECIFIC to the port:
  - tool-call routing: To<Sub>Assistant / HandleOtherTalk parsing, the 1-vs-2
    limit under Multi-Agent Mode, the primary-specialist default, and the
    native-tools -> JSON-plan fallback;
  - the tools: record lookup is stable per end user; knowledge retrieval finds
    the right article by keyword with no model, and never fails a turn;
  - a full turn: primary assistant -> sub-assistant (with knowledge + record) ->
    responder, agent_trace in that order, attributed to the NVIDIA workflow;
  - the analytics service: summary + sentiment cached per session, per-message
    sentiment aligned to user turns, feedback stored, sessions listed.

Offline: the LLM boundary is stubbed. Run:
    venv/bin/python tests/test_nvidia_blueprint.py    # exit 0 = pass
"""
import base64
import json
import os
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
# Survives backend.config's .env load (which only sets keys not already present).
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: E402,F401
from backend.config import settings  # noqa: E402

settings.prewarm_llm = False
settings.pii_injection_rate = settings.toxic_injection_rate = 0.0
settings.hallucination_injection_rate = settings.authority_injection_rate = 0.0
settings.ai_provider = "anthropic"
settings.blueprint_routing = "json"

from backend.agents.blueprints import data, retrieval  # noqa: E402
from backend.agents.blueprints import nvidia_virtual_assistant as nva  # noqa: E402
from backend.agents.llm import ChatModelError, NormalizedLLMResponse  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


MED = THEMES["medadvice"]
VALID = {nva.tool_name_for(s.key): s.key for s in MED.specialists}


def test_tool_names_and_routing_parse() -> None:
    check("tool name derived from the specialist key", nva.tool_name_for("symptom_analysis") == "ToSymptomAnalysisAssistant")
    sel, other = nva.parse_route('{"tool": "ToTriageAssistant", "args": {"query": "chest pain"}}', VALID, "triage", limit=1)
    check("single tool call -> that sub-assistant", sel == ["triage"] and other is False)
    sel, _ = nva.parse_route('[{"tool":"ToTriageAssistant"},{"tool":"ToSymptomAnalysisAssistant"}]', VALID, "triage", limit=2)
    check("two calls under Multi-Agent Mode -> two sub-assistants, in order", sel == ["triage", "symptom_analysis"])
    sel, _ = nva.parse_route('[{"tool":"ToTriageAssistant"},{"tool":"ToSymptomAnalysisAssistant"}]', VALID, "triage", limit=1)
    check("two calls without Multi-Agent Mode -> capped at one", sel == ["triage"])
    sel, other = nva.parse_route('{"tool": "HandleOtherTalk", "args": {"query": "hello"}}', VALID, "triage", limit=1)
    check("HandleOtherTalk -> no sub-assistant, other_talk flagged", sel == [] and other is True)
    sel, other = nva.parse_route("I think triage is best", VALID, "triage", limit=1)
    check("no JSON -> primary specialist default (a turn always has an assistant)", sel == ["triage"] and other is False)
    sel, _ = nva.parse_route('{"tool": "ToNonexistentAssistant"}', VALID, "triage", limit=1)
    check("unknown tool -> primary specialist default", sel == ["triage"])


def test_routing_mode() -> None:
    orig_mode, orig_prov = settings.blueprint_routing, settings.ai_provider
    try:
        settings.blueprint_routing = "auto"
        settings.ai_provider = "ollama"
        check("auto + ollama (no tools template) -> json plan", nva.routing_mode() == "json")
        settings.ai_provider = "nvidia"
        check("auto + nvidia NIM -> native tools", nva.routing_mode() == "tools")
        settings.blueprint_routing = "json"
        check("forced json wins", nva.routing_mode() == "json")
    finally:
        settings.blueprint_routing, settings.ai_provider = orig_mode, orig_prov


def test_records_and_retrieval() -> None:
    a = data.record_for("medadvice", "eu-1")
    b = data.record_for("medadvice", "eu-1")
    check("record lookup is stable per end user", a and a == b and a["record_id"] in {r["record_id"] for r in data.records_for("medadvice")})
    check("no end user -> the first record", data.record_for("medadvice", None) == data.records_for("medadvice")[0])
    check("every theme ships records + docs",
          all(data.records_for(t) and data.docs_for(t) for t in THEMES), str({t: (len(data.records_for(t)), len(data.docs_for(t))) for t in THEMES}))
    hits = retrieval.search("telecomchatbot", "my internet keeps dropping every evening", k=2)
    check("keyword retrieval finds the outage article first", hits and hits[0]["title"] == "Internet outage troubleshooting", str([h["title"] for h in hits]))
    check("retrieval reports its method (no embedding endpoint configured)", hits and hits[0]["method"] == "keyword")
    check("KB hits keep their shape (no doc_id / kind from the internal-docs corpus)",
          hits and set(hits[0]) == {"title", "text", "score", "method"}, str(hits[0] if hits else None))
    check("the KB index is separate from the internal document database",
          not any(h["title"] == "Retention Offer Ceilings"
                  for h in retrieval.search("telecomchatbot", "retention offer ceilings tier 2 desk", k=5)))
    check("empty query -> no hits, no error", retrieval.search("medadvice", "   ") == [])
    check("unknown theme -> no hits, no error", retrieval.search("nope", "anything") == [])
    check("no embedding endpoint -> keyword mode", retrieval.embed_endpoint() is None)
    orig = settings.blueprint_embed_url
    try:
        settings.blueprint_embed_url = "http://10.0.0.5:8001/v1"
        check("a remote embedding URL is ignored (local-only rule)", retrieval.embed_endpoint() is None)
    finally:
        settings.blueprint_embed_url = orig


class _FakeLLM:
    def __init__(self, primary_plan: str, fail: tuple = ()):
        self.primary_plan = primary_plan
        self.fail = set(fail)
        self.calls: List[str] = []

    def __call__(self, settings_, *, agent_name, system, messages, max_tokens=2048, temperature=0.7,
                 fallback_model=None, model_override=None, **_kw):
        self.calls.append(agent_name)
        if agent_name in self.fail:
            raise ChatModelError(f"boom: {agent_name}")
        if agent_name.endswith("_primary_assistant"):
            content = self.primary_plan
        elif agent_name.endswith("_assistant"):
            check(f"sub-assistant prompt carries the tools' output ({agent_name})",
                  "retrieve_knowledge" in system and "lookup_record" in system and "record_id" in system)
            content = "- finding one\n- finding two"
        else:
            content = "LOW\nAssessment: test. Guidance: rest, fluids."
        return NormalizedLLMResponse(id="r", content=content, model="fake", input_tokens=10, output_tokens=5, stop_reason="end_turn")


def _install(fake):
    saved = []
    for name, mod in list(sys.modules.items()):
        if name.startswith("backend.agents") and hasattr(mod, "invoke_agent"):
            saved.append((mod, getattr(mod, "invoke_agent")))
            setattr(mod, "invoke_agent", fake)
    return saved


def _restore(saved):
    for mod, orig in saved:
        mod.invoke_agent = orig


def _capture():
    from backend.logging import governance_logger as gl

    g = gl.governance_logger
    events = []
    orig = {n: getattr(g, n) for n in ("log_response", "log_request", "log_escalation", "log_error", "log_decision")}
    g.log_response = lambda **kw: events.append(kw)
    for n in ("log_request", "log_escalation", "log_error", "log_decision"):
        setattr(g, n, lambda **kw: None)
    return events, lambda: [setattr(g, n, f) for n, f in orig.items()]


def test_full_turn() -> None:
    from backend.agents import graph

    fake = _FakeLLM('{"tool": "ToTriageAssistant", "args": {"query": "sore throat"}}')
    saved = _install(fake)
    events, restore = _capture()
    try:
        result = graph.run_turn(session_id="nva", user_message="I have a sore throat and mild fever",
                                conversation_history=[{"role": "user", "content": "I have a sore throat and mild fever"}],
                                theme="medadvice", enduser_id="eu-7", blueprint="nvidia_virtual_assistant",
                                internal_policy_review=True)
    finally:
        _restore(saved)
        restore()
    check("turn answers with a recommendation", getattr(result.get("type"), "value", result.get("type")) == "recommendation", str(result)[:160])
    check("agents ran primary -> triage sub-assistant -> responder (domain agent)",
          fake.calls == ["medadvice_primary_assistant", "medadvice_triage_assistant", "medadvice_domain_agent"], str(fake.calls))
    last = events[-1] if events else {}
    roles = [t.get("role") for t in (last.get("agent_trace") or [])]
    check("agent_trace roles in order", roles == ["primary_assistant", "sub_assistant", "synthesizer"], str(roles))
    check("attributed to the NVIDIA workflow + blueprint",
          last.get("workflow_name") == "pseudoco_nvidia_virtual_assistant" and last.get("blueprint") == "nvidia_virtual_assistant")
    check("token usage is summed across the three agents", last.get("usage_data", {}).get("usage_total_tokens", 0) == 45
          or last.get("usage_total_tokens") == 45, str({k: v for k, v in last.items() if "usage" in k}))


def test_other_talk_and_multi_agent_and_failure() -> None:
    from backend.agents import graph

    fake = _FakeLLM('{"tool": "HandleOtherTalk", "args": {"query": "hi"}}')
    saved = _install(fake); events, restore = _capture()
    try:
        r = graph.run_turn(session_id="nva2", user_message="hello there!", conversation_history=[{"role": "user", "content": "hello there!"}],
                           theme="medadvice", blueprint="nvidia_virtual_assistant")
    finally:
        _restore(saved); restore()
    check("HandleOtherTalk skips the sub-assistant; the responder still answers",
          fake.calls == ["medadvice_primary_assistant", "medadvice_domain_agent"] and r.get("message"), str(fake.calls))

    fake = _FakeLLM('[{"tool":"ToTriageAssistant"},{"tool":"ToMedicationSafetyAssistant"}]')
    saved = _install(fake); events, restore = _capture()
    try:
        graph.run_turn(session_id="nva3", user_message="can I take ibuprofen for this headache",
                       conversation_history=[{"role": "user", "content": "can I take ibuprofen for this headache"}],
                       theme="medadvice", blueprint="nvidia_virtual_assistant", multi_agent_mode=True)
    finally:
        _restore(saved); restore()
    check("Multi-Agent Mode -> two sub-assistants consulted",
          fake.calls[1:3] == ["medadvice_triage_assistant", "medadvice_medication_safety_assistant"], str(fake.calls))

    fake = _FakeLLM('{"tool": "ToTriageAssistant"}', fail=("medadvice_triage_assistant",))
    saved = _install(fake); events, restore = _capture()
    try:
        r = graph.run_turn(session_id="nva4", user_message="sore throat", conversation_history=[{"role": "user", "content": "sore throat"}],
                           theme="medadvice", blueprint="nvidia_virtual_assistant")
    finally:
        _restore(saved); restore()
    check("all sub-assistants failing degrades to the safe reply",
          getattr(r.get("type"), "value", r.get("type")) == "safety_warning" and r.get("escalated") is True)


def test_tools_mode_falls_back_to_json() -> None:
    orig_mode, orig_route = settings.blueprint_routing, nva._route_with_tools
    fake = _FakeLLM('{"tool": "ToTriageAssistant"}')
    saved = _install(fake)
    try:
        settings.blueprint_routing = "tools"

        def _boom(*a, **k):
            raise ChatModelError("model has no tools template")
        nva._route_with_tools = _boom
        node = nva.make_primary_assistant(MED)
        out = node({"session_id": "s", "request_id": "r", "trace_id": "t", "start_time": 0.0, "theme": "medadvice",
                    "user_message": "sore throat", "conversation_history": [{"role": "user", "content": "sore throat"}]})
        check("native tools failing -> JSON plan fallback routes the turn",
              out.get("selected_specialists") == ["triage"] and out["blueprint_route"]["mode"] == "json", str(out.get("blueprint_route")))
    finally:
        settings.blueprint_routing, nva._route_with_tools = orig_mode, orig_route
        _restore(saved)


def test_analytics_service() -> None:
    from fastapi.testclient import TestClient

    from backend.routers import analytics as an
    import backend.agents.llm as llm

    key = settings.access_key or "test-access-key"
    settings.access_key = key
    auth = {"Authorization": "Basic " + base64.b64encode(f"x:{key}".encode()).decode()}
    fake = _FakeLLM('{"tool": "ToTriageAssistant"}')
    saved = _install(fake)
    orig_chat = llm.invoke_chat
    llm.invoke_chat = fake
    orig_llm_json = an._llm_json
    calls = {"n": 0}

    def _fake_json(system, transcript, max_tokens=400):
        calls["n"] += 1
        if "EACH user" in system:
            n = transcript.count("user:")
            return {"sentiments": ["negative"] * n}
        return {"summary": "User asked about a sore throat; advised rest and fluids.", "sentiment": "neutral"}
    an._llm_json = _fake_json
    try:
        from backend.main import app
        with TestClient(app) as c:
            check("analytics gated by the access key", c.get("/api/analytics/sessions").status_code == 401)
            sid = c.post("/api/chat/session/new", headers=auth).json()["session_id"]
            r = c.post("/api/chat/message", headers=auth, json={"session_id": sid, "message": "I have a sore throat",
                                                                 "disclaimer_accepted": True, "blueprint": "nvidia_virtual_assistant"})
            check("a turn through the NVIDIA blueprint via the API", r.status_code == 200, r.text[:160])
            s1 = c.get(f"/api/analytics/session/summary?session_id={sid}", headers=auth)
            check("GET /session/summary -> summary + sentiment", s1.status_code == 200 and s1.json()["sentiment"] == "neutral"
                  and "sore throat" in s1.json()["summary"], s1.text[:160])
            s2 = c.get(f"/api/analytics/session/summary?session_id={sid}", headers=auth)
            check("summary is cached on the second call", s2.json().get("cached") is True and calls["n"] == 1)
            conv = c.get(f"/api/analytics/session/conversation?session_id={sid}", headers=auth).json()
            users = [m for m in conv["messages"] if m["role"] == "user"]
            check("per-message sentiment for every user turn", users and all(m.get("sentiment") == "negative" for m in users), str(conv)[:200])
            fb = c.post("/api/analytics/feedback/summary", headers=auth, json={"session_id": sid, "rating": 4, "comment": "good"})
            check("feedback stored", fb.status_code == 200 and fb.json()["feedback"]["summary"]["rating"] == 4)
            check("unknown feedback kind -> 404", c.post("/api/analytics/feedback/nope", headers=auth, json={"session_id": sid, "rating": 3}).status_code == 404)
            lst = c.get("/api/analytics/sessions?hours=1", headers=auth).json()
            check("session listed with analysed flag", any(s["session_id"] == sid and s["analysed"] for s in lst["sessions"]))
            check("unknown session -> 404", c.get("/api/analytics/session/summary?session_id=nope", headers=auth).status_code == 404)
    finally:
        an._llm_json = orig_llm_json
        llm.invoke_chat = orig_chat
        _restore(saved)


def main() -> int:
    for fn in (test_tool_names_and_routing_parse, test_routing_mode, test_records_and_retrieval, test_full_turn,
               test_other_talk_and_multi_agent_and_failure, test_tools_mode_falls_back_to_json, test_analytics_service):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            global _fails
            _fails += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
