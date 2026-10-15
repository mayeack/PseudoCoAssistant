#!/usr/bin/env python3
"""Regression: the NVIDIA NeMo Guardrails toggle (backend/services/nemo_guardrails.py
+ backend/agents/nodes/nemo_rails.py).

Guards the guardrail contract without the nemoguardrails package or a judge
model: the client's rails are stubbed with fake NeMo result objects, and the
nodes are driven directly with a synthetic state (like tests/test_guardrail_nodes.py).

  - RailVerdict.should_block: a real unsafe verdict blocks; an error honors
    nemo_guardrails_fail_open (default open).
  - _run_check maps both NeMo APIs (0.24 check() -> RailsResult, and the
    generate(options={"rails": ...}) fallback) onto the verdict, naming the rail.
  - nodes are no-ops unless the request opted in AND the master switch is on;
    an input block short-circuits with the NeMo banner and guardrail_ids
    ["nemo_guardrails"]; an output block echoes the real model + token spend;
    a fail-open error releases the turn and is attributed, not claimed.
  - graph order: nemo_input_rails after prompt_defense, nemo_output_rails
    between agent_control and response_defense (Cisco stays the last word).
  - Settings: the nemo_guardrails integration card fields + live reconfigure;
    the content-safety URL obeys the local-only rule; _BLOCK_GUARDRAILS maps it.

Run:  venv/bin/python tests/test_nemo_guardrails.py    # exit 0 = pass
"""
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"

from backend.config import settings  # noqa: E402
from backend.models.schemas import MessageType, SeverityLevel  # noqa: E402
from backend.services import nemo_guardrails as ng  # noqa: E402
from backend.services.nemo_guardrails import RailVerdict, nemo_guardrails_client  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


def base_state(**over):
    s = {
        "session_id": "S-nemo", "request_id": "R-nemo", "trace_id": "T-nemo",
        "theme": "medadvice", "user_message": "I have a mild sore throat.",
        "conversation_history": [], "messages": [{"role": "user", "content": "I have a mild sore throat."}],
        "final_message": "**Assessment:**\nLikely a mild viral sore throat.",
        "severity": SeverityLevel.LOW, "confidence": 0.9, "start_time": time.time(),
        "enduser_id": "eu-1", "client_address": "127.0.0.1",
        "llm_model": "nvidia/nvidia-nemotron-nano-9b-v2", "llm_input_tokens": 40, "llm_output_tokens": 12,
        "nemo_guardrails_review": True,
    }
    s.update(over)
    return s


def test_verdict_fail_policy() -> None:
    orig = settings.nemo_guardrails_fail_open
    try:
        check("unsafe verdict blocks", RailVerdict(is_safe=False).should_block is True)
        check("safe verdict passes", RailVerdict(is_safe=True).should_block is False)
        settings.nemo_guardrails_fail_open = True
        check("error + fail-open -> released", RailVerdict(errored=True).should_block is False)
        settings.nemo_guardrails_fail_open = False
        check("error + fail-closed -> withheld", RailVerdict(errored=True).should_block is True)
    finally:
        settings.nemo_guardrails_fail_open = orig


def test_run_check_maps_both_nemo_apis() -> None:
    # 0.24 check() API: RailsResult(status, rail, content)
    class _Status:
        name = "BLOCKED"

    class _Rails024:
        def check(self, messages, rail_types):
            return SimpleNamespace(status=_Status(), rail=SimpleNamespace(name="self check input"),
                                   content="I can't help with that.")

    v = ng.NemoGuardrailsClient._run_check(_Rails024(), [{"role": "user", "content": "x"}], ["input"])
    check("check(): BLOCKED -> unsafe", v.is_safe is False)
    check("check(): rail name recorded", v.rule_names == ["self check input"], str(v.rule_names))
    check("check(): stage from rail_types", v.stage == "input")

    class _Pass:
        name = "PASSED"

    class _Rails024Pass:
        def check(self, messages, rail_types):
            return SimpleNamespace(status=_Pass(), rail=None, content="ok")

    v = ng.NemoGuardrailsClient._run_check(_Rails024Pass(), [{"role": "user", "content": "x"}], ["output"])
    check("check(): PASSED -> safe with no rails", v.is_safe is True and v.rule_names == [])

    # Older API: generate(options={"rails": ...}) with log.activated_rails
    class _RailsGen:
        def generate(self, messages, options):
            rail = SimpleNamespace(name="self check output $variant=overreach", type="output", stop=True)
            return SimpleNamespace(log=SimpleNamespace(activated_rails=[rail]),
                                   output_data={"triggered_output_rail": "self check output $variant=overreach"})

    v = ng.NemoGuardrailsClient._run_check(_RailsGen(), [{"role": "user", "content": "x"},
                                                         {"role": "assistant", "content": "y"}], ["output"])
    check("generate(): stopped rail -> unsafe, deduped name",
          v.is_safe is False and v.rule_names == ["self check output $variant=overreach"], str(v.rule_names))


class _StubClient:
    """Stand-in for the module singleton: scripted verdicts, no rails built."""

    def __init__(self, input_verdict=None, output_verdict=None, configured=True):
        self.input_verdict = input_verdict or RailVerdict()
        self.output_verdict = output_verdict or RailVerdict(stage="output")
        self.is_configured = configured
        self.calls = []

    def check_input(self, user_message):
        self.calls.append(("input", user_message))
        return self.input_verdict

    def check_output(self, user_message, assistant_message):
        self.calls.append(("output", assistant_message))
        return self.output_verdict


def _capture_log():
    from backend.logging import governance_logger as gl

    captured = {}
    orig = gl.governance_logger.log_response
    gl.governance_logger.log_response = lambda **kw: captured.update(kw)
    return captured, lambda: setattr(gl.governance_logger, "log_response", orig)


def test_nodes() -> None:
    from backend.agents.nodes import nemo_rails as nr

    orig_client = nr.nemo_guardrails_client
    captured, restore = _capture_log()
    try:
        # No-op paths: toggle off / master off.
        nr.nemo_guardrails_client = _StubClient()
        check("input node: toggle off -> no-op", nr.nemo_input_rails_node(base_state(nemo_guardrails_review=None)) == {})
        nr.nemo_guardrails_client = _StubClient(configured=False)
        check("input node: master switch off -> no-op", nr.nemo_input_rails_node(base_state()) == {})

        # Allowed input: verdict carried, no terminal.
        stub = _StubClient()
        nr.nemo_guardrails_client = stub
        out = nr.nemo_input_rails_node(base_state())
        check("allowed input: not terminal, verdict + timing recorded",
              not out.get("terminal") and out.get("nemo_guardrails_input") is stub.input_verdict
              and "nemo_input_rails_ms" in out["stage_timings"])
        check("input rails saw the user message", stub.calls == [("input", "I have a mild sore throat.")])

        # Blocked input: short-circuit + governance contract.
        captured.clear()
        blocked = RailVerdict(is_safe=False, stage="input", rule_names=["self check input"])
        nr.nemo_guardrails_client = _StubClient(input_verdict=blocked)
        out = nr.nemo_input_rails_node(base_state())
        res = out["result"]
        check("blocked input: terminal", out.get("terminal") is True)
        check("blocked input: SAFETY_WARNING/MEDIUM, policy_blocked, not escalated",
              res["type"] == MessageType.SAFETY_WARNING and res["severity"] == SeverityLevel.MEDIUM
              and res["policy_blocked"] is True and res["escalated"] is False)
        check("blocked input: NeMo metadata names the rail",
              res["metadata"]["nemo_guardrails"]["rails"] == ["self check input"])
        check("blocked input: governance guardrail_ids=[nemo_guardrails]",
              captured.get("guardrail_ids") == ["nemo_guardrails"] and captured.get("policy_blocked") is True)
        check("blocked input: banner names NeMo + stage",
              "POLICY BLOCKED (NVIDIA NeMo Guardrails - input)" in captured.get("response_text", ""))
        check("blocked input: rails in safety_categories", captured.get("safety_categories") == ["self check input"])
        check("blocked input: zero tokens (nothing was generated)",
              captured["usage_data"]["usage_total_tokens"] == 0)

        # Blocked output: real model + token spend echoed.
        captured.clear()
        blocked_out = RailVerdict(is_safe=False, stage="output", rule_names=["self check output $variant=overreach"])
        nr.nemo_guardrails_client = _StubClient(output_verdict=blocked_out)
        out = nr.nemo_output_rails_node(base_state())
        check("blocked output: terminal + banner", out.get("terminal") is True
              and "NeMo Guardrails - output" in captured.get("response_text", ""))
        check("blocked output: echoes the model that answered",
              captured.get("response_model") == "nvidia/nvidia-nemotron-nano-9b-v2")
        check("blocked output: echoes the real token spend", captured["usage_data"]["usage_total_tokens"] == 52)
        check("blocked output: overreach rail attributed",
              captured.get("safety_categories") == ["self check output $variant=overreach"])

        # Errored, fail-open: released, verdict carried for attribution.
        orig_fo = settings.nemo_guardrails_fail_open
        try:
            settings.nemo_guardrails_fail_open = True
            errored = RailVerdict(stage="output", errored=True, error_message="judge down")
            nr.nemo_guardrails_client = _StubClient(output_verdict=errored)
            out = nr.nemo_output_rails_node(base_state())
            check("errored + fail-open: turn released with the verdict recorded",
                  not out.get("terminal") and out.get("nemo_guardrails_output") is errored)
            settings.nemo_guardrails_fail_open = False
            captured.clear()
            out = nr.nemo_output_rails_node(base_state())
            check("errored + fail-closed: withheld with the unavailable reason",
                  out.get("terminal") is True and "unavailable" in captured.get("safety_categories", [""])[0])
        finally:
            settings.nemo_guardrails_fail_open = orig_fo
    finally:
        nr.nemo_guardrails_client = orig_client
        restore()


def test_governance_attributes_nonblocking_rail() -> None:
    from backend.agents.nodes import governance as gov

    captured, restore = _capture_log()
    orig_esc = gov.governance_logger.log_escalation
    try:
        gov.governance_logger.log_escalation = lambda **kw: None
        state = base_state(llm_response_id="r1", llm_stop_reason="end_turn",
                           nemo_guardrails_output=RailVerdict(stage="output", rule_names=["self check output"]))
        gov.governance_node(state)
        check("non-blocking rail -> guardrail_ids includes nemo_guardrails, not a violation",
              "nemo_guardrails" in (captured.get("guardrail_ids") or []) and captured.get("safety_violated") is False)
        captured.clear()
        gov.governance_node(base_state(llm_response_id="r1", llm_stop_reason="end_turn"))
        check("no verdict -> no NeMo attribution", "nemo_guardrails" not in (captured.get("guardrail_ids") or []))
    finally:
        gov.governance_logger.log_escalation = orig_esc
        restore()


def test_graph_order() -> None:
    from backend.agents.graph import build_theme_subgraph
    from backend.agents.themes import THEMES

    g = build_theme_subgraph(THEMES["medadvice"]).get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    # NeMo's input rails stay the last SCREEN (after AI Defense and the Agent
    # Control prompt stage); the scheduling intake (no model, never terminal —
    # docs/scheduling.md) then the MCP tool-thrash launch (no model, never
    # terminal — docs/mcp-tool-thrash.md) sit between them and the core.
    check("prompt_defense -> agent_control_prompt -> nemo_input_rails -> scheduling_intake -> mcp_thrash_launch -> intake",
          ("prompt_defense", "agent_control_prompt") in edges
          and ("agent_control_prompt", "nemo_input_rails") in edges
          and ("nemo_input_rails", "scheduling_intake") in edges
          and ("scheduling_intake", "mcp_thrash_launch") in edges
          and ("mcp_thrash_launch", "intake") in edges)
    check("agent_control -> nemo_output_rails -> response_defense (Cisco stays last)",
          ("agent_control", "nemo_output_rails") in edges and ("nemo_output_rails", "response_defense") in edges)
    check("both rails can short-circuit to END",
          ("nemo_input_rails", "__end__") in edges and ("nemo_output_rails", "__end__") in edges)


def test_settings_card_and_mapping() -> None:
    from backend import settings_store
    from backend.logging.executive_fields import _BLOCK_GUARDRAILS

    check("nemo_guardrails is an integration choice", "nemo_guardrails" in settings_store.INTEGRATION_CHOICES)
    fields = {f["key"]: f for f in settings_store.get_integration_fields()["nemo_guardrails"]}
    check("card fields: enabled / rails / content_safety_url / fail_open",
          set(fields) == {"enabled", "rails", "content_safety_url", "fail_open"}, str(sorted(fields)))
    check("enabled + fail_open are booleans; rails is wide",
          fields["enabled"]["boolean"] and fields["fail_open"]["boolean"] and fields["rails"].get("wide") is True)
    check("_BLOCK_GUARDRAILS names the NeMo policy",
          _BLOCK_GUARDRAILS.get("nemo_guardrails") == ("NVIDIA NeMo Guardrails policy", "blocked_by_nemo_guardrails"))

    # Save path: in-memory store, live reconfigure, local-only content-safety URL.
    mem = {"integration_creds": {}}
    orig_load, orig_persist = settings_store.load, settings_store._persist
    orig = (settings.nemo_guardrails_enabled, settings.nemo_guardrails_rails,
            settings.nemo_guardrails_content_safety_url, settings.nemo_guardrails_fail_open)
    reconf = {"n": 0}
    orig_reconf = nemo_guardrails_client.reconfigure
    try:
        settings_store.load = lambda: {k: dict(v) if isinstance(v, dict) else v for k, v in mem.items()}
        settings_store._persist = lambda data: (mem.clear(), mem.update(data))
        nemo_guardrails_client.reconfigure = lambda: reconf.__setitem__("n", reconf["n"] + 1)
        restart = settings_store.set_integration_creds("nemo_guardrails", {
            "enabled": "true", "rails": "self_check_input", "fail_open": "false"})
        check("save applies live (master on, rails, fail-closed) with no restart",
              settings.nemo_guardrails_enabled is True and settings.nemo_guardrails_rails == "self_check_input"
              and settings.nemo_guardrails_fail_open is False and restart == [])
        check("save reconfigures the client", reconf["n"] == 1)
        try:
            settings_store.set_integration_creds("nemo_guardrails", {"content_safety_url": "http://10.0.0.9:8001/v1"})
            check("remote content-safety NIM URL rejected", False)
        except ValueError:
            check("remote content-safety NIM URL rejected", True)
        settings_store.set_integration_creds("nemo_guardrails", {"content_safety_url": "http://localhost:8001/v1"})
        check("loopback content-safety URL applied", settings.nemo_guardrails_content_safety_url == "http://localhost:8001/v1")
    finally:
        settings_store.load, settings_store._persist = orig_load, orig_persist
        nemo_guardrails_client.reconfigure = orig_reconf
        (settings.nemo_guardrails_enabled, settings.nemo_guardrails_rails,
         settings.nemo_guardrails_content_safety_url, settings.nemo_guardrails_fail_open) = orig


def test_ollama_judge_folds_call_kwargs_into_options() -> None:
    """Found live: NeMo's LangChain adapter passes temperature / max_tokens as
    per-call kwargs; ChatOllama spreads unknown kwargs into ollama's
    AsyncClient.chat(), which rejects them. The Ollama judge must fold them into
    the request's `options` (merged with the model defaults) and drop the rest."""
    from langchain_core.messages import HumanMessage

    orig = (settings.ai_provider, settings.ollama_model, settings.ollama_num_ctx)
    try:
        settings.ai_provider, settings.ollama_model, settings.ollama_num_ctx = "ollama", "mistral-nemo:12b", 4096
        judge = ng._judge_model(64)
        check("ollama judge is a ChatOllama subclass", type(judge).__name__ == "_JudgeOllama"
              and any(b.__name__ == "ChatOllama" for b in type(judge).__mro__))
        params = judge._chat_params([HumanMessage(content="hi")], temperature=0.0, max_tokens=32, foo="bar")
        opts = params.get("options") or {}
        check("temperature folded into options", opts.get("temperature") == 0.0, str(opts))
        check("max_tokens mapped to num_predict", opts.get("num_predict") == 32, str(opts))
        check("model defaults kept alongside (num_ctx)", opts.get("num_ctx") == 4096, str(opts))
        check("unknown kwargs dropped, none leak to the request",
              "temperature" not in params and "max_tokens" not in params and "foo" not in params, str(sorted(params)))
        settings.ai_provider = "anthropic"
        check("non-ollama providers use the regular chat model", type(ng._judge_model(64)).__name__ != "_JudgeOllama")
    finally:
        settings.ai_provider, settings.ollama_model, settings.ollama_num_ctx = orig

    try:
        from nemoguardrails.rails.llm.options import RailType
        enums = ng._rail_type_enums(["input", "output"])
        check("rail types passed to check() as RailType enums (0.24 reads .value)",
              enums == [RailType.INPUT, RailType.OUTPUT], str(enums))
    except ImportError:
        check("rail types fall back to strings without the package", ng._rail_type_enums(["input"]) == ["input"])


def test_client_degrades_without_package() -> None:
    """Without nemoguardrails installed (or with a broken config) the client must
    return an errored verdict — never raise into the graph."""
    c = ng.NemoGuardrailsClient()
    orig_build = c._build_rails
    try:
        def _boom():
            raise ImportError("No module named nemoguardrails")
        c._build_rails = _boom
        v = c.check_input("hello")
        check("missing package -> errored verdict, not an exception", v.errored is True and "not installed" in (v.error_message or ""))
        check("errored verdict is cached until reconfigure", c._build_error is not None)
        c.reconfigure()
        check("reconfigure clears the cached failure", c._build_error is None and c._rails is None)
    finally:
        c._build_rails = orig_build


def main() -> int:
    for fn in (
        test_verdict_fail_policy,
        test_run_check_maps_both_nemo_apis,
        test_nodes,
        test_governance_attributes_nonblocking_rail,
        test_graph_order,
        test_settings_card_and_mapping,
        test_ollama_judge_folds_call_kwargs_into_options,
        test_client_degrades_without_package,
    ):
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
