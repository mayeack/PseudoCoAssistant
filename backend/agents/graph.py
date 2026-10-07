"""LangGraph assembly: supervisor + per-theme subgraphs, per selected BLUEPRINT.

Workshop sections 4.4 ("Defining the Graph") and 4.8 ("Decomposition Pattern").

Topology:

    START -> router -> {theme}_subgraph -> END

Each ``{theme}_subgraph`` is the shared guardrail chain wired around the active
blueprint's generation core (backend/agents/blueprints):

    policy -> prompt_defense -> nemo_input_rails -> <core> -> safety
          -> injection -> compliance -> agent_control -> nemo_output_rails
          -> response_defense -> governance

For the shipped ``pseudoco_multi_agent`` blueprint the core is
``intake -> synthesizer`` (one LLM call as the theme's ``*_domain_agent``), or
``intake -> coordinator -> specialists -> synthesizer`` when the request sets
``multi_agent_mode`` True. The ``nvidia_virtual_assistant`` blueprint swaps in
the NVIDIA AI Virtual Assistant core (primary assistant, sub-assistants,
retrieval, analytics). Every guardrail node runs in both — that is enforced
structurally by ``blueprints.guardrails.wire_guardrails`` and asserted by
tests/test_blueprint_parity.py.

There are conditional short-circuits to END whenever a node sets ``terminal``
(policy block, AI Defense block, NeMo rail, Agent Control deny,
clarifying question, agent generation error).

Each compiled workflow is tagged with the blueprint's ``workflow_name`` so
Splunk AI Agent Monitoring promotes it to a recognized workflow, and the two
architectures show up as distinct workflows.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Dict, Iterator, Optional

from langgraph.graph import END, START, StateGraph

from backend.agents.blueprints import DEFAULT_BLUEPRINT, get_blueprint
from backend.agents.blueprints.guardrails import wire_guardrails
from backend.agents.state import PseudoCoAssistantState, build_initial_state
from backend.agents.supervisor import route_to_theme, router_node
from backend.agents.themes import THEMES
from backend.config import settings
from backend.logging.governance_logger import governance_logger
from backend.models.schemas import MessageType, SeverityLevel
from backend.telemetry import otel

logger = logging.getLogger(__name__)


def active_blueprint_key() -> str:
    """The server-default blueprint (ACTIVE_BLUEPRINT / PUT /api/settings/blueprint)."""
    return (getattr(settings, "active_blueprint", "") or "").strip() or DEFAULT_BLUEPRINT


def build_theme_subgraph(theme_config, blueprint=None):
    """Build and compile one theme's subgraph for a blueprint (default: the
    active one). Kept as the public name tests and tooling use."""
    bp = blueprint if blueprint is not None else get_blueprint(active_blueprint_key())
    return wire_guardrails(theme_config, bp)


def build_workflow_graph(blueprint_key: Optional[str] = None):
    """Build and compile the supervisor-routed workflow for one blueprint."""
    bp = get_blueprint(blueprint_key or active_blueprint_key())
    g = StateGraph(PseudoCoAssistantState)
    g.add_node("router", router_node)

    route_map: Dict[str, str] = {}
    for key, theme_config in THEMES.items():
        node_name = f"{key}_subgraph"
        g.add_node(node_name, build_theme_subgraph(theme_config, bp))
        g.add_edge(node_name, END)
        route_map[node_name] = node_name

    g.add_edge(START, "router")
    g.add_conditional_edges("router", route_to_theme, route_map)

    compiled = g.compile().with_config(
        metadata={"workflow_name": bp.workflow_name, "blueprint": bp.key}
    )
    logger.info(
        "Agentic workflow '%s' (blueprint %s) compiled with %d theme subgraphs: %s",
        bp.workflow_name, bp.key, len(THEMES), ", ".join(THEMES.keys()),
    )
    return compiled


# Lazily-built compiled workflows, one per blueprint (both can be live at once:
# the header dropdown picks the default, a request may override).
_COMPILED: Dict[str, Any] = {}
_COMPILE_LOCK = threading.Lock()


def get_agentic_runner(blueprint_key: Optional[str] = None):
    """Return the compiled workflow for a blueprint, building it once on first use."""
    key = get_blueprint(blueprint_key or active_blueprint_key()).key
    runner = _COMPILED.get(key)
    if runner is None:
        with _COMPILE_LOCK:
            runner = _COMPILED.get(key)
            if runner is None:
                runner = build_workflow_graph(key)
                _COMPILED[key] = runner
    return runner


def clear_compiled() -> None:
    """Drop every compiled workflow (a code/theme change; a blueprint switch
    does not need this — the cache is keyed by blueprint)."""
    _COMPILED.clear()


def _generic_error_result() -> Dict[str, Any]:
    return {
        "message": (
            "I apologize, but I encountered an error. Please try again or seek "
            "immediate medical care if this is urgent."
        ),
        "type": MessageType.SAFETY_WARNING,
        "severity": SeverityLevel.MEDIUM,
        "escalated": True,
    }


def _build_turn_state(
    *,
    session_id: str,
    user_message: str,
    conversation_history,
    client_address: Optional[str] = None,
    theme: Optional[str] = "medadvice",
    force_pii_injection: Optional[bool] = None,
    force_toxic_injection: Optional[bool] = None,
    force_hallucination_injection: Optional[bool] = None,
    force_boundary_injection: Optional[bool] = None,
    ai_defense_review: Optional[bool] = None,
    internal_policy_review: Optional[bool] = None,
    multi_agent_mode: Optional[bool] = None,
    agent_control_review: Optional[bool] = None,
    nemo_guardrails_review: Optional[bool] = None,
    enduser_id: Optional[str] = None,
    service_name: Optional[str] = None,
    deployment_id: Optional[str] = None,
    blueprint: Optional[str] = None,
    client_id: Optional[str] = None,
    client_tz: Optional[str] = None,
    scheduling_action: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the initial workflow state shared by run_turn / run_turn_stream."""
    bp = get_blueprint(blueprint or active_blueprint_key())
    state = build_initial_state(
        session_id=session_id,
        user_message=user_message,
        conversation_history=conversation_history,
        theme=theme,
        client_address=client_address,
        enduser_id=enduser_id,
        force_pii_injection=force_pii_injection,
        force_toxic_injection=force_toxic_injection,
        force_hallucination_injection=force_hallucination_injection,
        force_boundary_injection=force_boundary_injection,
        ai_defense_review=ai_defense_review,
        internal_policy_review=internal_policy_review,
        multi_agent_mode=multi_agent_mode,
        agent_control_review=agent_control_review,
        nemo_guardrails_review=nemo_guardrails_review,
        service_name=service_name,
        deployment_id=deployment_id,
        client_id=client_id,
        client_tz=client_tz,
        scheduling_action=scheduling_action,
    )
    state["request_id"] = str(uuid.uuid4())
    # Provisional: replaced by the OTel trace id once the workflow span is open
    # (_adopt_otel_trace_id), before any governance event is written.
    state["trace_id"] = uuid.uuid4().hex
    state["start_time"] = time.time()
    # Which architecture serves this turn: read by governance (workflow_name +
    # the additive `blueprint` field) and the OTel workflow span.
    state["blueprint"] = bp.key
    state["workflow_name"] = bp.workflow_name
    return state


def _adopt_otel_trace_id(state: Dict[str, Any], span) -> None:
    """Give the turn the OTel trace id it is running under.

    Called first thing inside the workflow span, so the router's input event and
    every later governance event, the Agent Observability metadata
    (``pseudoco_assistant_trace_id``) and the span attribute
    ``pseudoco-assistant.trace_id`` all carry the id Splunk APM shows for this
    turn — one identity, joinable without a lookup. Under an HTTP request the
    workflow span is a child of the FastAPI span, so that is the request's
    trace. With no span current the provisional id stands.
    """
    state["trace_id"] = otel.current_trace_id() or state["trace_id"]
    otel.set_span_attributes(span, {"pseudoco-assistant.trace_id": state["trace_id"]})


def run_turn(
    *,
    session_id: str,
    user_message: str,
    conversation_history,
    client_address: Optional[str] = None,
    theme: Optional[str] = "medadvice",
    force_pii_injection: Optional[bool] = None,
    force_toxic_injection: Optional[bool] = None,
    force_hallucination_injection: Optional[bool] = None,
    force_boundary_injection: Optional[bool] = None,
    ai_defense_review: Optional[bool] = None,
    internal_policy_review: Optional[bool] = None,
    multi_agent_mode: Optional[bool] = None,
    agent_control_review: Optional[bool] = None,
    nemo_guardrails_review: Optional[bool] = None,
    enduser_id: Optional[str] = None,
    service_name: Optional[str] = None,
    deployment_id: Optional[str] = None,
    blueprint: Optional[str] = None,
    client_id: Optional[str] = None,
    client_tz: Optional[str] = None,
    scheduling_action: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run one chat turn through the multi-agent workflow.

    Drop-in replacement for ``RecommendationEngine.process_message`` - returns a
    dict with the same shape: {message, type, severity, escalated, [policy_blocked],
    metadata}. The whole invocation is wrapped in a GenAI Workflow span.
    """
    state = _build_turn_state(
        session_id=session_id,
        user_message=user_message,
        conversation_history=conversation_history,
        theme=theme,
        client_address=client_address,
        enduser_id=enduser_id,
        force_pii_injection=force_pii_injection,
        force_toxic_injection=force_toxic_injection,
        force_hallucination_injection=force_hallucination_injection,
        force_boundary_injection=force_boundary_injection,
        ai_defense_review=ai_defense_review,
        internal_policy_review=internal_policy_review,
        multi_agent_mode=multi_agent_mode,
        agent_control_review=agent_control_review,
        nemo_guardrails_review=nemo_guardrails_review,
        service_name=service_name,
        deployment_id=deployment_id,
        blueprint=blueprint,
        client_id=client_id,
        client_tz=client_tz,
        scheduling_action=scheduling_action,
    )
    runner = get_agentic_runner(state["blueprint"])
    request_id = state["request_id"]

    try:
        with otel.workflow_span(
            workflow_name=state["workflow_name"],
            theme=theme,
            session_id=session_id,
            request_id=request_id,
            blueprint=state["blueprint"],
        ) as span:
            _adopt_otel_trace_id(state, span)
            final_state = runner.invoke(state)
        result = final_state.get("result")
        if result is None:
            logger.error("Agentic workflow returned no result; using generic reply")
            return _generic_error_result()
        return result
    except Exception as exc:  # noqa: BLE001 - mirror legacy top-level handler
        logger.exception("Agentic workflow failed: %s", exc)
        governance_logger.log_error(
            session_id=session_id,
            request_id=request_id,
            error_type=type(exc).__name__,
            error_message=str(exc),
            stack_trace=None,
            enduser_id=enduser_id,
        )
        return _generic_error_result()


def run_turn_stream(**kwargs: Any) -> Iterator[Dict[str, Any]]:
    """Run one chat turn, yielding a progress event per completed graph node.

    Same inputs, governance events, and telemetry as ``run_turn`` — only the
    delivery differs: the graph is driven with ``runner.stream`` so callers
    (the SSE chat endpoint) can surface live multi-agent progress instead of
    a 30-40s blank wait. Yields ``{"event": "stage", "node", "elapsed_ms"}``
    per node, then exactly one ``{"event": "final", "result": <run_turn dict>}``.

    No answer text is emitted before the full pipeline (including the
    response_defense output guardrail) has finished — stage events carry node
    names only, so nothing bypasses governance.
    """
    state = _build_turn_state(**kwargs)
    runner = get_agentic_runner(state["blueprint"])
    request_id = state["request_id"]
    turn_start = state["start_time"]

    result: Optional[Dict[str, Any]] = None
    try:
        with otel.workflow_span(
            workflow_name=state["workflow_name"],
            theme=kwargs.get("theme"),
            session_id=kwargs.get("session_id"),
            request_id=request_id,
            blueprint=state["blueprint"],
        ) as span:
            _adopt_otel_trace_id(state, span)
            # subgraphs=True surfaces the theme subgraph's inner nodes
            # (policy, coordinator, specialists, ...) as they complete; chunks
            # arrive as (namespace, {node: update}) tuples, top-level ones may
            # be bare {node: update} dicts depending on langgraph version.
            for chunk in runner.stream(state, stream_mode="updates", subgraphs=True):
                update = chunk[1] if isinstance(chunk, tuple) and len(chunk) == 2 else chunk
                if not isinstance(update, dict):
                    continue
                for node_name, node_update in update.items():
                    if isinstance(node_update, dict) and node_update.get("result"):
                        result = node_update["result"]
                    yield {
                        "event": "stage",
                        "node": node_name,
                        "elapsed_ms": round((time.time() - turn_start) * 1000, 1),
                    }
        if result is None:
            logger.error("Agentic workflow stream returned no result; using generic reply")
            result = _generic_error_result()
    except Exception as exc:  # noqa: BLE001 - mirror run_turn's top-level handler
        logger.exception("Agentic workflow (stream) failed: %s", exc)
        governance_logger.log_error(
            session_id=kwargs.get("session_id"),
            request_id=request_id,
            error_type=type(exc).__name__,
            error_message=str(exc),
            stack_trace=None,
            enduser_id=kwargs.get("enduser_id"),
        )
        result = _generic_error_result()
    yield {"event": "final", "result": result}
