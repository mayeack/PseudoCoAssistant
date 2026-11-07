#!/usr/bin/env python3
"""Regression: gen_ai spans must carry message CONTENT (prompt + response).

The bug this guards (fixed 2026-06-23): the app emitted gen_ai spans with only
metadata (model / token usage) and never set the conversation messages, so Splunk
Observability Cloud's "AI trace data" view — which indexes gen_ai spans by their
input/output *content* and runs the Content / quality / risk evaluations on it —
stayed EMPTY even though the spans reached APM (and were visible in Trace
Analyzer). The metrics-only checks (verify_observability.sh Tier 3 /
check_o11y_metadata.py) passed throughout, which is exactly why this slipped by.

This is a code-level check (no live Splunk needed): it drives the util-genai
invocation helpers exactly as backend/agents/llm.py does, emits the spans through
an in-memory exporter, and asserts the emitted span attributes carry the prompt
(gen_ai.input.messages) and response (gen_ai.output.messages). It therefore fails
loudly if anyone stops populating message content on the gen_ai invocations.

Run:  venv/bin/python tests/observability/test_genai_span_content.py
Exit 0 = pass, non-zero = fail.
"""
import os
import sys

# Mirror the app's telemetry env (run.sh / .env) BEFORE the util-genai handler is
# created: content capture on, and the same emitters the app uses (the emitter is
# what writes input at span-start and output at span-stop).
os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "SPAN_ONLY"
os.environ["OTEL_INSTRUMENTATION_GENAI_EMITTERS"] = "span_metric,splunk"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

from backend.telemetry import otel  # noqa: E402

# Quote/brace-free so the raw substring survives JSON-escaping inside the span
# attribute (gen_ai.*.messages serialize as JSON, escaping any embedded quotes).
SYS = "You are a medical guidance assistant providing general health information."
USER = "I have a sore throat and mild fever"
RESP = "Likely a viral upper respiratory infection; severity LOW. Rest and hydrate."

_EXPORTER = InMemorySpanExporter()


def _setup_tracer():
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_EXPORTER))
    trace.set_tracer_provider(provider)


def _attr(span, key):
    return (span.attributes or {}).get(key)


def _find(name_prefix):
    for s in _EXPORTER.get_finished_spans():
        if s.name.startswith(name_prefix):
            return s
    return None


def check_llm():
    _EXPORTER.clear()
    with otel.genai_llm_invocation(
        request_model="claude-sonnet-4-5-20250929", provider="anthropic",
        system=SYS, messages=[{"role": "user", "content": USER}],
    ) as inv:
        assert inv is not None, "util-genai handler unavailable (splunk-otel-util-genai installed?)"
        otel.record_genai_output(inv, text=RESP, finish_reason="end_turn")
    span = _find("chat ")
    assert span is not None, "no 'chat' gen_ai span was emitted"
    in_msgs = _attr(span, "gen_ai.input.messages")
    out_msgs = _attr(span, "gen_ai.output.messages")
    assert in_msgs and USER in str(in_msgs), "gen_ai.input.messages missing the user prompt"
    assert out_msgs and RESP in str(out_msgs), "gen_ai.output.messages missing the response"


def check_output_token_cache_split():
    """The cache split rides in the invocation's custom attributes dict (the
    handler has no field for it), so it has to actually reach the span."""
    _EXPORTER.clear()
    with otel.genai_llm_invocation(
        request_model="mistral-nemo:12b", provider="ollama",
        system=SYS, messages=[{"role": "user", "content": USER}],
    ) as inv:
        assert inv is not None, "util-genai handler unavailable"
        inv.input_tokens, inv.output_tokens = 120, 260
        otel.record_output_token_cache_split(inv, 90, 170)
        otel.record_genai_output(inv, text=RESP, finish_reason="end_turn")
    span = _find("chat ")
    assert span is not None, "no 'chat' gen_ai span was emitted"
    cached = _attr(span, otel.ATTR_OUTPUT_TOKENS_CACHED)
    uncached = _attr(span, otel.ATTR_OUTPUT_TOKENS_UNCACHED)
    assert cached == 90, f"{otel.ATTR_OUTPUT_TOKENS_CACHED} missing/wrong: {cached}"
    assert uncached == 170, f"{otel.ATTR_OUTPUT_TOKENS_UNCACHED} missing/wrong: {uncached}"
    total = _attr(span, "gen_ai.usage.output_tokens")
    assert cached + uncached == total, f"split {cached}+{uncached} != output_tokens {total}"


def check_agent():
    _EXPORTER.clear()
    with otel.genai_agent_invocation(
        agent_name="medadvice_domain_agent", request_model="claude-sonnet-4-5-20250929",
        provider="anthropic", system=SYS, messages=[{"role": "user", "content": USER}],
    ) as inv:
        assert inv is not None, "util-genai handler unavailable"
        otel.record_genai_output(inv, text=RESP, finish_reason="end_turn")
    chat = _find("chat ")
    agent = _find("invoke_agent ")
    assert chat is not None, "no nested 'chat' span under the agent"
    assert agent is not None, "no 'invoke_agent' gen_ai span was emitted"
    assert USER in str(_attr(chat, "gen_ai.input.messages") or ""), "agent's LLM span missing prompt content"
    assert RESP in str(_attr(chat, "gen_ai.output.messages") or ""), "agent's LLM span missing response content"


def check_workflow_parents_agents_across_a_generator():
    """The workflow span must still parent its agent spans when the ``with``
    block is a generator that yields, driven across a ``copy_context()`` hop.

    That is the shape of ``run_turn_stream`` (backend/agents/graph.py):
    ``with otel.workflow_span(...)`` around ``for chunk in runner.stream(...)``,
    yielding a stage event per node, with the whole generator driven from a
    worker thread by the SSE route. ``start_as_current_span`` logged an ERROR
    traceback per streamed turn there (``Failed to detach context``), so
    ``_span`` now attaches and detaches explicitly.

    This asserts the PARENTING half only. It does not reproduce the detach
    error: doing that needs each generator resumption to run in a genuinely
    different Context, and a harness aggressive enough to force that also
    orphans the second agent span, which production does not do. The detach fix
    itself is verified against the running app -- count
    ``Failed to detach context`` in the app log, drive streamed turns, confirm
    the count holds. What this guards is the regression a careless rewrite of
    ``_span`` would cause: agents no longer parented by the workflow, which no
    other test would catch.
    """
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    _EXPORTER.clear()
    provider = trace.get_tracer_provider()
    otel._STATE["tracer"] = trace.get_tracer("test", tracer_provider=provider)
    otel._STATE["enabled"] = True
    try:
        def streaming_turn():
            with otel.workflow_span(workflow_name="pseudoco_multi_agent", theme="medadvice"):
                for node in ("policy", "medadvice_domain_agent"):
                    with otel.agent_span(node, theme="medadvice"):
                        pass
                    yield {"event": "stage", "node": node}

        # Model the production shape: the whole generator is driven inside one
        # worker thread (asyncio.to_thread in the SSE route), and each graph
        # step re-copies the driver's Context (langgraph/pregel/_executor.py).
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(contextvars.copy_context().run,
                        lambda: list(streaming_turn())).result()
    finally:
        otel._STATE["enabled"] = False
        otel._STATE["tracer"] = None

    workflow = _find("workflow ")
    assert workflow is not None, "no workflow span was emitted"
    agents = [s for s in _EXPORTER.get_finished_spans() if s.name.startswith("invoke_agent ")]
    assert len(agents) == 2, f"expected 2 agent spans, got {len(agents)}"
    wf_id = workflow.get_span_context().span_id
    for a in agents:
        parent = a.parent.span_id if a.parent else None
        assert parent == wf_id, (
            f"agent span {a.name!r} is not parented by the workflow span "
            f"(parent={parent}, workflow={wf_id}) — the streamed turn would "
            f"show orphaned agents in Splunk's AI trace view"
        )


def check_workflow_span_carries_actor():
    """The workflow span names who the turn is for and where it came from
    (Lab 5): ``enduser.id`` (the governance event's enduser_id -- the verified
    username when signed in) and ``client.address``. Unset values are skipped."""
    _EXPORTER.clear()
    provider = trace.get_tracer_provider()
    otel._STATE["tracer"] = trace.get_tracer("test", tracer_provider=provider)
    otel._STATE["enabled"] = True
    try:
        with otel.workflow_span(workflow_name="pseudoco_multi_agent", theme="medadvice",
                                enduser_id="nina.osei", client_address="203.0.113.7"):
            pass
        with otel.workflow_span(workflow_name="pseudoco_multi_agent", theme="medadvice"):
            pass
    finally:
        otel._STATE["enabled"] = False
        otel._STATE["tracer"] = None
    spans = [s for s in _EXPORTER.get_finished_spans() if s.name.startswith("workflow ")]
    assert len(spans) == 2, f"expected 2 workflow spans, got {len(spans)}"
    assert _attr(spans[0], "enduser.id") == "nina.osei", f"enduser.id missing: {_attr(spans[0], 'enduser.id')}"
    assert _attr(spans[0], "client.address") == "203.0.113.7", "client.address missing on the workflow span"
    assert "enduser.id" not in (spans[1].attributes or {}) and "client.address" not in (spans[1].attributes or {}), \
        "unset actor attributes must be skipped, not set to None"


def check_both_graph_call_sites_pass_the_actor():
    """run_turn and run_turn_stream both open the workflow span with the
    turn's enduser_id and client_address (a static read of backend/agents/graph.py,
    so no graph is compiled here)."""
    import re as _re
    from pathlib import Path as _Path

    src = (_Path(__file__).resolve().parents[2] / "backend" / "agents" / "graph.py").read_text()
    calls = _re.findall(r"otel\.workflow_span\((.*?)\) as span", src, _re.S)
    assert len(calls) == 2, f"expected the two graph call sites, found {len(calls)}"
    for call in calls:
        assert 'enduser_id=state.get("enduser_id")' in call and 'client_address=state.get("client_address")' in call, \
            "a graph call site does not pass enduser_id / client_address to the workflow span"


def main():
    _setup_tracer()
    ok = True
    for name, fn in [("LLM span carries prompt+response", check_llm),
                     ("LLM span carries the output-token cache split", check_output_token_cache_split),
                     ("Agent span carries prompt+response", check_agent),
                     ("workflow parents agents across a generator + thread hop",
                      check_workflow_parents_agents_across_a_generator),
                     ("workflow span carries enduser.id + client.address", check_workflow_span_carries_actor),
                     ("both graph call sites pass the actor to the workflow span",
                      check_both_graph_call_sites_pass_the_actor)]:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            ok = False
            print(f"  FAIL  {name}: {e}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  ERROR {name}: {e}")
    print(f"\nRESULT: {'passed' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
