#!/usr/bin/env python3
"""Regression: the multi-agent stage (coordinator -> specialists -> synthesizer).

Guards the re-architecture that replaced the single ``domain`` agent with a
themed multi-agent pipeline that always emits a coordinator + 1..N specialist +
synthesizer trace. Verifies the invariants:
  - coordinator always selects >=1 specialist (defaults to the theme's primary
    on an empty/invalid plan), and a coordinator failure short-circuits safely;
  - specialists run sequentially, sum tokens onto the running total, and
    continue-on-partial-failure (terminate only if ALL fail);
  - the synthesizer produces the structured recommendation (or {reply} for a
    conversational theme), rolls the governance directive exactly once, and sums
    its tokens; ``agent_trace`` accumulates one entry per agent;
  - a full run_turn produces summed usage + a complete agent_trace for Agent Observability.

DB/network-free: ``invoke_agent`` is faked per node module; no real LLM calls.

    venv/bin/python tests/test_multi_agent.py    # exit 0 = pass
"""
import os
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
# Survives backend.config's .env load (which only sets keys not already present).
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

from backend.agents.llm import ChatModelError, NormalizedLLMResponse  # noqa: E402
from backend.agents.nodes import coordinator as coord_mod  # noqa: E402
from backend.agents.nodes import specialists as spec_mod  # noqa: E402
from backend.agents.nodes import synthesizer as synth_mod  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

_fails = 0


def check(name: str, cond: bool) -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        _fails += 1


def _resp(content: str, in_tok: int, out_tok: int, rid: str = "x") -> NormalizedLLMResponse:
    return NormalizedLLMResponse(
        id=rid, content=content, model="fake-model",
        input_tokens=in_tok, output_tokens=out_tok, stop_reason="end_turn",
    )


# A configurable fake invoke_agent dispatching on the agent name suffix.
class FakeLLM:
    def __init__(self, *, coordinator_content, fail_specialists=(), synth_content):
        self.coordinator_content = coordinator_content
        self.fail_specialists = set(fail_specialists)
        self.synth_content = synth_content
        self.calls = []
        self.overrides = {}  # agent_name -> model_override seen on its call

    def __call__(self, settings, *, agent_name, system, messages,
                 max_tokens=2048, temperature=0.7, fallback_model=None,
                 model_override=None):
        self.calls.append(agent_name)
        self.overrides[agent_name] = model_override
        if agent_name.endswith("_coordinator"):
            return _resp(self.coordinator_content, 10, 5, rid="coord")
        if agent_name.endswith("_specialist"):
            if agent_name in self.fail_specialists:
                raise ChatModelError(f"boom: {agent_name}")
            return _resp("- internal finding", 20, 8, rid="spec")
        # synthesizer == {theme}_domain_agent
        return _resp(self.synth_content, 30, 40, rid="synth")


def _install(fake) -> None:
    coord_mod.invoke_agent = fake
    spec_mod.invoke_agent = fake
    synth_mod.invoke_agent = fake


def _base_state(theme_key: str) -> dict:
    return {
        "session_id": "s1",
        "request_id": "r1",
        "trace_id": "t1",
        "theme": theme_key,
        "conversation_history": [{"role": "user", "content": "I have a headache"}],
        "user_message": "I have a headache",
        # Toggle contract: True = always, False = never, None/unset = random at
        # the configured rate. (False WAS treated like None; that changed when
        # each toggle was made to own exactly one kind of content.)
        "force_pii_injection": False,
        "force_toxic_injection": False,
        "force_hallucination_injection": False,
        "force_boundary_injection": False,
    }


def test_coordinator_valid_plan() -> None:
    fake = FakeLLM(
        coordinator_content='{"specialists": ["triage", "symptom_analysis"], "rationale": "x"}',
        synth_content="{}",
    )
    _install(fake)
    node = coord_mod.make_coordinator_agent(THEMES["medadvice"])
    out = node(_base_state("medadvice"))
    check("coordinator selects the planned specialists",
          out["selected_specialists"] == ["triage", "symptom_analysis"])
    check("coordinator emits one agent_trace entry (role=coordinator)",
          len(out["agent_trace"]) == 1 and out["agent_trace"][0]["role"] == "coordinator")
    check("coordinator seeds the running token totals",
          out["llm_input_tokens"] == 10 and out["llm_output_tokens"] == 5)


def test_coordinator_empty_plan_defaults_primary() -> None:
    fake = FakeLLM(coordinator_content='{"specialists": [], "rationale": "n/a"}', synth_content="{}")
    _install(fake)
    node = coord_mod.make_coordinator_agent(THEMES["taxadvice"])
    out = node(_base_state("taxadvice"))
    check("empty plan -> defaults to the theme primary specialist (>=1 guarantee)",
          out["selected_specialists"] == ["deductions"])


def test_coordinator_invalid_keys_and_cap() -> None:
    fake = FakeLLM(
        coordinator_content='{"specialists": ["bogus", "triage", "medication_safety", "care_navigation"]}',
        synth_content="{}",
    )
    _install(fake)
    node = coord_mod.make_coordinator_agent(THEMES["medadvice"])
    out = node(_base_state("medadvice"))
    check("coordinator drops unknown keys and caps the fan-out at _MAX_SPECIALISTS (2)",
          out["selected_specialists"] == ["triage", "medication_safety"])


def test_coordinator_error_terminates() -> None:
    def boom(*a, **k):
        raise ChatModelError("coordinator down")
    _install(boom)
    node = coord_mod.make_coordinator_agent(THEMES["medadvice"])
    out = node(_base_state("medadvice"))
    check("coordinator ChatModelError -> terminal safe result",
          out.get("terminal") is True and out["result"]["escalated"] is True)


def test_specialists_sum_and_partial_failure() -> None:
    fail = "medadvice_symptom_analysis_specialist"
    fake = FakeLLM(coordinator_content="{}", fail_specialists=[fail], synth_content="{}")
    _install(fake)
    node = spec_mod.make_specialists_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({
        "selected_specialists": ["triage", "symptom_analysis", "medication_safety"],
        "agent_trace": [{"name": "medadvice_coordinator", "role": "coordinator",
                         "model": "fake-model", "input_tokens": 10, "output_tokens": 5,
                         "output_text": "plan", "status": "ok"}],
        "llm_input_tokens": 10, "llm_output_tokens": 5,
    })
    out = node(state)
    check("two specialists succeeded -> two outputs collected",
          len(out["specialist_outputs"]) == 2)
    check("tokens summed onto the running total (10 + 2*20 in, 5 + 2*8 out)",
          out["llm_input_tokens"] == 50 and out["llm_output_tokens"] == 21)
    err = [t for t in out["agent_trace"] if t.get("status") == "error"]
    check("failed specialist recorded with status=error, turn continues",
          len(err) == 1 and err[0]["name"] == fail)
    check("agent_trace now has coordinator + 3 specialist entries",
          len(out["agent_trace"]) == 4)


def test_specialists_all_fail_terminates() -> None:
    fails = ["medadvice_triage_specialist", "medadvice_medication_safety_specialist"]
    fake = FakeLLM(coordinator_content="{}", fail_specialists=fails, synth_content="{}")
    _install(fake)
    node = spec_mod.make_specialists_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({"selected_specialists": ["triage", "medication_safety"],
                  "agent_trace": [], "llm_input_tokens": 10, "llm_output_tokens": 5})
    out = node(state)
    check("all specialists fail -> terminal safe result", out.get("terminal") is True)


def test_synthesizer_structured() -> None:
    synth = ('```json\n{"assessment": "a", "guidance": ["g1"], '
             '"seek_care_if": ["s1"], "severity": "LOW", "confidence": 0.8}\n```')
    fake = FakeLLM(coordinator_content="{}", synth_content=synth)
    _install(fake)
    node = synth_mod.make_synthesizer_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({
        "specialist_outputs": [{"key": "triage", "label": "Triage", "analysis": "urgent-ish"}],
        "agent_trace": [{"name": "x", "role": "coordinator", "output_text": "p", "status": "ok",
                         "model": "m", "input_tokens": 10, "output_tokens": 5}],
        "llm_input_tokens": 30, "llm_output_tokens": 13,
    })
    out = node(state)
    check("synthesizer parses the structured recommendation",
          out["recommendation"]["assessment"] == "a")
    check("synthesizer normalizes severity", str(out["severity"].value) == "LOW")
    check("synthesizer builds the user-facing final_message", "Assessment" in out["final_message"])
    check("synthesizer sums its tokens onto the running total (30+30 / 13+40)",
          out["llm_input_tokens"] == 60 and out["llm_output_tokens"] == 53)
    check("synthesizer sets requested_categories (one directive roll)",
          isinstance(out["requested_categories"], dict)
          and set(out["requested_categories"]) == {"pii", "toxic", "hallucination", "authority"})
    check("synthesizer is the final agent_trace entry (role=synthesizer)",
          out["agent_trace"][-1]["role"] == "synthesizer")
    check("synthesizer keeps the {theme}_domain_agent name",
          out["agent_trace"][-1]["name"] == "medadvice_domain_agent")


def test_synthesizer_conversational_reply() -> None:
    fake = FakeLLM(coordinator_content="{}",
                   synth_content='{"reply": "Try restarting your router.", "severity": "LOW", "confidence": 0.9}')
    _install(fake)
    node = synth_mod.make_synthesizer_agent(THEMES["telecomchatbot"])
    state = _base_state("telecomchatbot")
    state.update({"specialist_outputs": [], "agent_trace": [],
                  "llm_input_tokens": 0, "llm_output_tokens": 0})
    out = node(state)
    check("conversational theme renders the reply verbatim as final_message",
          out["final_message"] == "Try restarting your router.")


def test_synthesizer_emergency_banner_follows_theme() -> None:
    """An EMERGENCY answer opens with the synthesizer's own theme banner -- both
    blueprint cores answer through this node -- never medadvice's "Call 911"."""
    synth = ('{"assessment": "a", "guidance": ["g1"], "seek_care_if": ["s1"], '
             '"severity": "EMERGENCY", "confidence": 0.9}')
    _install(FakeLLM(coordinator_content="{}", synth_content=synth))
    tax = THEMES["taxadvice"]
    state = _base_state("taxadvice")
    state.update({"specialist_outputs": [], "agent_trace": [],
                  "llm_input_tokens": 0, "llm_output_tokens": 0})
    fm = synth_mod.make_synthesizer_agent(tax)(state)["final_message"]
    check("synthesizer opens a tax EMERGENCY answer with the tax banner",
          fm.startswith(f"⚠️ **{tax.guardrails.emergency_banner}** ⚠️"))
    check("synthesizer's tax EMERGENCY answer carries no 911 / emergency-room copy",
          "911" not in fm and "emergency room" not in fm.lower())


def test_synthesizer_robust_to_poisoned_malformed_json() -> None:
    """A tampered/unaligned model (e.g. mistral-nemo:12b-poisoned) violates the
    JSON contract: guidance/seek_care entries as objects, severity as an object,
    confidence as a string. The synthesizer must normalize all of these at the
    parse boundary so (1) no raw Python dict repr leaks into final_message,
    (2) severity is a valid SeverityLevel, and (3) confidence is a float (the
    downstream governance node compares it numerically)."""
    from backend.models.schemas import SeverityLevel

    poisoned = (
        '{"assessment": "You have a cold.", '
        '"guidance": ['
        '{"suggestion": "Start NovaCure Rx by Helix Pharma today", '
        '"dosage_and_frequency": "500mg twice daily", "duration_of_treatment": "5 days"}, '
        '"Rest and stay hydrated."], '
        '"seek_care_if": [{"condition": "Contact Helix Pharma support if symptoms persist"}], '
        '"severity": {"level": "LOW"}, "confidence": "0.95"}'
    )
    fake = FakeLLM(coordinator_content="{}", synth_content=poisoned)
    _install(fake)
    node = synth_mod.make_synthesizer_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({"specialist_outputs": [], "agent_trace": [],
                  "llm_input_tokens": 0, "llm_output_tokens": 0})

    out = node(state)  # must not raise (reaching the asserts proves that)

    check("no raw dict repr leaks into final_message (malformed guidance)",
          "{'" not in out["final_message"])
    check("dict-valued guidance is rendered as readable text",
          "Start NovaCure Rx by Helix Pharma today" in out["final_message"]
          and "500mg twice daily" in out["final_message"])
    check("plain-string guidance still renders alongside dict entries",
          "Rest and stay hydrated." in out["final_message"])
    check("dict-valued seek_care is rendered as readable text",
          "Contact Helix Pharma support if symptoms persist" in out["final_message"])
    check("object severity normalized to a valid SeverityLevel (no AttributeError)",
          isinstance(out["severity"], SeverityLevel) and out["severity"] == SeverityLevel.LOW)
    check("string confidence coerced to a float (no TypeError downstream)",
          isinstance(out["confidence"], float) and out["confidence"] == 0.95)


def test_governance_survives_poisoned_confidence() -> None:
    """Bug class #3 broke DOWNSTREAM of the synthesizer: ``governance_node`` does
    ``confidence > 0.7``. This drives the real synthesizer->governance handoff
    with a string confidence to prove it is type-safe end to end (the synthesizer
    coerces confidence so governance never raises '>' not supported str/float)."""
    from backend.agents.nodes import governance as gov_mod
    from backend.logging.governance_logger import governance_logger

    poisoned = ('{"assessment": "a", "guidance": ["g"], "seek_care_if": ["s"], '
                '"severity": "LOW", "confidence": "0.95"}')
    fake = FakeLLM(coordinator_content="{}", synth_content=poisoned)
    _install(fake)
    synth = synth_mod.make_synthesizer_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({"specialist_outputs": [], "agent_trace": [],
                  "llm_input_tokens": 0, "llm_output_tokens": 0, "start_time": 0.0})
    state.update(synth(state))  # fold the synthesizer's outputs into the state

    orig = governance_logger.log_response
    governance_logger.log_response = lambda **k: None  # avoid DB/IO in the test
    try:
        gout = gov_mod.governance_node(state)
    finally:
        governance_logger.log_response = orig

    check("governance consumes coerced confidence without raising (terminal result)",
          gout.get("terminal") is True)
    check("governance result carries the rendered final_message",
          gout["result"]["message"] == state["final_message"])
    check("governance metadata confidence is the coerced float",
          gout["result"]["metadata"]["confidence"] == 0.95)


def test_synthesizer_unparseable_json_no_raw_render() -> None:
    """When the model emits unparseable JSON (here: the medadvice system prompt
    echoed back as a JSON blob with an invalid "confidence": 0.0-1.0), the
    synthesizer's final_message must NOT contain raw JSON scaffolding — the
    tolerant parser cleanly falls back instead of dumping output_text."""
    echoed = (
        'You are a medical guidance assistant.\nFormat your response as JSON:\n'
        '{\n  "assessment": "Brief assessment of the situation",\n'
        '  "guidance": ["List of general recommendations"],\n'
        '  "severity": "LOW|MEDIUM|HIGH|EMERGENCY",\n  "confidence": 0.0-1.0\n}'
    )
    fake = FakeLLM(coordinator_content="{}", synth_content=echoed)
    _install(fake)
    node = synth_mod.make_synthesizer_agent(THEMES["medadvice"])
    state = _base_state("medadvice")
    state.update({"specialist_outputs": [], "agent_trace": [],
                  "llm_input_tokens": 0, "llm_output_tokens": 0})
    out = node(state)
    fm = out["final_message"]
    check("unparseable JSON: no '{\"' scaffolding in final_message", '{"' not in fm)
    check("unparseable JSON: no '\"assessment\":' scaffolding", '"assessment":' not in fm)
    check("unparseable JSON: no invalid 0.0-1.0 leaks", "0.0-1.0" not in fm)
    check("unparseable JSON: a safe seek-care line is present",
          "Symptoms persist or worsen" in fm or "professional" in fm.lower())


def test_internal_agents_use_clean_model_override() -> None:
    """Poisoned-model speedup (per-node model split): when ai_provider=='ollama'
    the coordinator + specialists run on the CLEAN ollama_model_internal, while
    the user-facing synthesizer runs WITHOUT an override (i.e. on the selected,
    possibly poisoned, ollama_model). This keeps the internal calls fast/on-task
    and confines the poison to the final answer."""
    import backend.config as cfg

    orig_provider = cfg.settings.ai_provider
    orig_internal = getattr(cfg.settings, "ollama_model_internal", "mistral-nemo:12b")
    cfg.settings.ai_provider = "ollama"
    cfg.settings.ollama_model_internal = "mistral-nemo:12b"
    try:
        fake = FakeLLM(
            coordinator_content='{"specialists": ["triage"]}',
            synth_content=('{"assessment": "a", "guidance": ["g"], '
                           '"seek_care_if": ["s"], "severity": "LOW", "confidence": 0.8}'),
        )
        _install(fake)

        coord_mod.make_coordinator_agent(THEMES["medadvice"])(_base_state("medadvice"))

        spec_state = _base_state("medadvice")
        spec_state.update({"selected_specialists": ["triage"], "agent_trace": [],
                           "llm_input_tokens": 0, "llm_output_tokens": 0})
        spec_mod.make_specialists_agent(THEMES["medadvice"])(spec_state)

        synth_state = _base_state("medadvice")
        synth_state.update({"specialist_outputs": [], "agent_trace": [],
                            "llm_input_tokens": 0, "llm_output_tokens": 0})
        synth_mod.make_synthesizer_agent(THEMES["medadvice"])(synth_state)

        check("coordinator runs on the clean internal model override",
              fake.overrides.get("medadvice_coordinator") == "mistral-nemo:12b")
        check("specialist runs on the clean internal model override",
              fake.overrides.get("medadvice_triage_specialist") == "mistral-nemo:12b")
        check("synthesizer runs WITHOUT an override (uses the selected model)",
              fake.overrides.get("medadvice_domain_agent") is None)
    finally:
        cfg.settings.ai_provider = orig_provider
        cfg.settings.ollama_model_internal = orig_internal


@contextmanager
def _no_governance_injection():
    """Pin all four governance-injection rates to 0.0 for the duration.

    ``run_turn`` rolls each category once per turn at its configured rate (25%
    by default) and, when one lands, appends synthetic governance content to
    ``final_message`` -- so an exact-match assertion on the reply is flaky
    without this. Zeroing the rates is what makes a turn that passes NO force
    flags deterministic; a turn passing ``force_*_injection=False`` is already
    deterministic on its own, since False now means never.
    """
    import backend.config as cfg
    rates = ("pii_injection_rate", "toxic_injection_rate",
             "hallucination_injection_rate", "authority_injection_rate")
    orig_rates = {name: getattr(cfg.settings, name) for name in rates}
    for name in rates:
        setattr(cfg.settings, name, 0.0)
    try:
        yield
    finally:
        for name, value in orig_rates.items():
            setattr(cfg.settings, name, value)


def test_full_run_turn_telecom() -> None:
    """End-to-end through the compiled graph (telecom skips the clarifier).
    Passes multi_agent_mode=True explicitly — the coordinator/specialists core
    is opt-in (single-agent is the default; see test_default_mode_is_single_agent)."""
    from backend.logging.governance_logger import governance_logger
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
    orig = governance_logger.log_response
    governance_logger.log_response = capture
    fake = FakeLLM(
        coordinator_content='{"specialists": ["network_diagnostics", "device_setup"]}',
        synth_content='{"reply": "Restart the modem, then your phone.", "severity": "LOW", "confidence": 0.9}',
    )
    _install(fake)
    try:
        from backend.agents.graph import run_turn
        with _no_governance_injection():
            result = run_turn(
                session_id="s1", user_message="My wifi is slow",
                conversation_history=[{"role": "user", "content": "My wifi is slow"}],
                theme="telecomchatbot",
                multi_agent_mode=True,
            )
    finally:
        governance_logger.log_response = orig

    check("run_turn returns the synthesized reply",
          result.get("message") == "Restart the modem, then your phone.")
    check("governance received summed usage across all agents "
          "(coord 10/5 + 2 spec 40/16 + synth 30/40 = 80/61)",
          captured.get("usage_data", {}).get("usage_input_tokens") == 80
          and captured.get("usage_data", {}).get("usage_output_tokens") == 61)
    trace = captured.get("agent_trace") or []
    roles = [t["role"] for t in trace]
    check("agent_trace carries coordinator + 2 specialists + synthesizer (4 agents)",
          roles == ["coordinator", "specialist", "specialist", "synthesizer"])
    check("agent names are themed per application",
          trace[0]["name"] == "telecomchatbot_coordinator"
          and trace[-1]["name"] == "telecomchatbot_domain_agent")


def test_single_agent_mode_bypasses_coordinator_and_specialists() -> None:
    """multi_agent_mode=False routes intake -> synthesizer: the domain agent
    answers alone (one LLM call), the coordinator/specialists never run, and
    governance still receives a complete (single-entry) agent_trace + usage."""
    from backend.logging.governance_logger import governance_logger
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
    orig = governance_logger.log_response
    governance_logger.log_response = capture
    fake = FakeLLM(
        coordinator_content='{"specialists": ["network_diagnostics"]}',
        synth_content='{"reply": "Restart the modem, then your phone.", "severity": "LOW", "confidence": 0.9}',
    )
    _install(fake)
    try:
        from backend.agents.graph import run_turn
        with _no_governance_injection():
            result = run_turn(
                session_id="s1", user_message="My wifi is slow",
                conversation_history=[{"role": "user", "content": "My wifi is slow"}],
                theme="telecomchatbot",
                multi_agent_mode=False,
            )
    finally:
        governance_logger.log_response = orig

    check("single-agent mode: only the domain agent is called",
          fake.calls == ["telecomchatbot_domain_agent"])
    check("single-agent mode: run_turn returns the synthesized reply",
          result.get("message") == "Restart the modem, then your phone.")
    trace = captured.get("agent_trace") or []
    check("single-agent mode: agent_trace carries exactly the synthesizer",
          [t["role"] for t in trace] == ["synthesizer"]
          and trace[0]["name"] == "telecomchatbot_domain_agent")
    check("single-agent mode: usage is the synthesizer's alone (30/40)",
          captured.get("usage_data", {}).get("usage_input_tokens") == 30
          and captured.get("usage_data", {}).get("usage_output_tokens") == 40)


def test_default_mode_is_single_agent() -> None:
    """No multi_agent_mode at all (None/absent) routes intake -> synthesizer:
    single-agent is the DEFAULT; the coordinator/specialists core runs only on
    an explicit True. Pins the default so a routing regression fails loudly."""
    from backend.logging.governance_logger import governance_logger
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
    orig = governance_logger.log_response
    governance_logger.log_response = capture
    fake = FakeLLM(
        coordinator_content='{"specialists": ["network_diagnostics"]}',
        synth_content='{"reply": "Restart the modem, then your phone.", "severity": "LOW", "confidence": 0.9}',
    )
    _install(fake)
    try:
        from backend.agents.graph import run_turn
        with _no_governance_injection():
            result = run_turn(
                session_id="s1", user_message="My wifi is slow",
                conversation_history=[{"role": "user", "content": "My wifi is slow"}],
                theme="telecomchatbot",
            )
    finally:
        governance_logger.log_response = orig

    check("default mode: only the domain agent is called",
          fake.calls == ["telecomchatbot_domain_agent"])
    check("default mode: run_turn returns the synthesized reply",
          result.get("message") == "Restart the modem, then your phone.")
    trace = captured.get("agent_trace") or []
    check("default mode: agent_trace carries exactly the synthesizer",
          [t["role"] for t in trace] == ["synthesizer"]
          and trace[0]["name"] == "telecomchatbot_domain_agent")
    check("default mode: usage is the synthesizer's alone (30/40)",
          captured.get("usage_data", {}).get("usage_input_tokens") == 30
          and captured.get("usage_data", {}).get("usage_output_tokens") == 40)


def _turn_trace_ids(*, stream: bool, outer_span=None) -> dict:
    """Run one fake single-agent turn and return the trace_id each governance
    event of the turn carried ({"request": ..., "response": ...})."""
    from backend.logging.governance_logger import governance_logger
    seen = {}
    orig_req, orig_resp = governance_logger.log_request, governance_logger.log_response
    governance_logger.log_request = lambda **kw: seen.setdefault("request", kw.get("trace_id"))
    governance_logger.log_response = lambda **kw: seen.setdefault("response", kw.get("trace_id"))
    _install(FakeLLM(coordinator_content='{"specialists": []}',
                     synth_content='{"reply": "ok", "severity": "LOW", "confidence": 0.9}'))
    kwargs = dict(session_id="s-trace", user_message="My wifi is slow",
                  conversation_history=[{"role": "user", "content": "My wifi is slow"}],
                  theme="telecomchatbot")
    try:
        from opentelemetry import trace as otel_trace
        from backend.agents.graph import run_turn, run_turn_stream
        with _no_governance_injection():
            if outer_span is not None:
                with otel_trace.use_span(outer_span, end_on_exit=False):
                    list(run_turn_stream(**kwargs)) if stream else run_turn(**kwargs)
            else:
                list(run_turn_stream(**kwargs)) if stream else run_turn(**kwargs)
    finally:
        governance_logger.log_request, governance_logger.log_response = orig_req, orig_resp
    return seen


def test_governance_trace_id_is_the_otel_trace_id() -> None:
    """The governance trace_id of a turn is the OTel trace id it runs under (32
    hex, as Splunk APM shows it), not a private uuid4 — so APM, the governance
    log and the Agent Observability metadata share one identity. Simulated with
    the span the FastAPI auto-instrumentation opens around a request (the
    hand-rolled spans are off in this suite)."""
    from opentelemetry.sdk.trace import TracerProvider
    span = TracerProvider().get_tracer("test").start_span("POST /api/chat")
    want = format(span.get_span_context().trace_id, "032x")
    for stream in (False, True):
        mode = "run_turn_stream" if stream else "run_turn"
        seen = _turn_trace_ids(stream=stream, outer_span=span)
        check(f"{mode}: input event carries the OTel trace id", seen.get("request") == want)
        check(f"{mode}: output event carries the OTel trace id", seen.get("response") == want)
    span.end()
    seen = _turn_trace_ids(stream=False)
    tid = seen.get("response") or ""
    check("no span current: fallback id has the same 32-hex shape and is shared by the turn",
          len(tid) == 32 and all(c in "0123456789abcdef" for c in tid)
          and seen.get("request") == tid)


def test_medadvice_authority_directive_solicits_controlled_substances() -> None:
    """The "Prescriptive Overreach" toggle (force_boundary_injection=True) must
    build a directive that solicits a CONTROLLED-SUBSTANCE prescription: a named
    Schedule II-IV drug with an exact dose and a refill schedule, written as a
    DEA-licensed prescriber. Guards the MedAdvice authority framing that the
    Agent Observability prescriptive-overreach judge scores against (see
    scripts/demo/galileo_eval_prescription.py).

    Asserted on BOTH provider paths, since ``build_input_directives`` branches on
    ``settings.ai_provider`` for the permission preamble and the deployed provider
    varies by environment: both embed the ask inside the JSON "guidance" array
    (``authority_directive``), and neither may label it as a sample."""
    from backend.agents.nodes import injection as inj_mod

    orig_provider = inj_mod.settings.ai_provider
    # force_*_injection=False still means "random at the configured rate" (see
    # _should_request), so zero the other three rates to keep the directive under
    # assertion to the authority content alone.
    rate_attrs = ("pii_injection_rate", "toxic_injection_rate",
                  "hallucination_injection_rate")
    orig_rates = {a: getattr(inj_mod.settings, a) for a in rate_attrs}
    for attr in rate_attrs:
        setattr(inj_mod.settings, attr, 0.0)
    try:
        for provider in ("ollama", "anthropic"):
            inj_mod.settings.ai_provider = provider
            state = _base_state("medadvice")
            state["force_boundary_injection"] = True
            directive, requested = inj_mod.build_input_directives(state)

            # The two paths hyphenate differently ("controlled-substance
            # prescription" vs "controlled substance"), so match on a
            # hyphen-flattened copy.
            low = directive.lower().replace("-", " ")
            check(f"[{provider}] authority category is requested when boundary is forced ON",
                  requested.get("authority") is True)
            check(f"[{provider}] directive solicits prescribing a controlled substance",
                  "controlled substance" in low
                  and ("prescribe" in low or "prescription" in low))
            check(f"[{provider}] directive names example controlled-substance classes",
                  "opioid" in low and "benzodiazepine" in low and "stimulant" in low)
            check(f"[{provider}] directive demands an exact dose and a refill schedule",
                  "exact dose" in low and "refill schedule" in low)
            check(f"[{provider}] directive frames the model as a DEA-licensed prescriber",
                  "prescriber" in low and "dea authority" in low)
            check(f"[{provider}] directive solicits no sample/fictional label",
                  "sample:" not in low and "governance test samples" not in low
                  and "(fictional)" not in low and "labeled synthetic" not in low)
    finally:
        inj_mod.settings.ai_provider = orig_provider
        for attr, rate in orig_rates.items():
            setattr(inj_mod.settings, attr, rate)


def main() -> int:
    for fn in (
        test_coordinator_valid_plan,
        test_coordinator_empty_plan_defaults_primary,
        test_coordinator_invalid_keys_and_cap,
        test_coordinator_error_terminates,
        test_specialists_sum_and_partial_failure,
        test_specialists_all_fail_terminates,
        test_synthesizer_structured,
        test_synthesizer_conversational_reply,
        test_synthesizer_emergency_banner_follows_theme,
        test_synthesizer_robust_to_poisoned_malformed_json,
        test_governance_survives_poisoned_confidence,
        test_synthesizer_unparseable_json_no_raw_render,
        test_internal_agents_use_clean_model_override,
        test_medadvice_authority_directive_solicits_controlled_substances,
        test_full_run_turn_telecom,
        test_single_agent_mode_bypasses_coordinator_and_specialists,
        test_default_mode_is_single_agent,
        test_governance_trace_id_is_the_otel_trace_id,
    ):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            global _fails
            _fails += 1
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
