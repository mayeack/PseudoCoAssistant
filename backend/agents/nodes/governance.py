"""Governance logging agent node (happy-path terminal).

Emits the output governance event and (when escalated) the escalation event,
exactly matching the Splunk field contract produced by the legacy
``_generate_recommendation``. Reuses the same ``trace_id`` / ``request_id`` as
the OTel spans so logs and traces correlate in Splunk.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from backend.agents.nodes.shared import clarifying_service, escalation_rules
from backend.agents.state import governance_identity_overrides
from backend.agents.token_usage import governance_usage_data
from backend.config import settings
from backend.logging.governance_logger import governance_logger
from backend.models.schemas import MessageType
from backend.telemetry import otel


def governance_node(state: Dict[str, Any]) -> Dict[str, Any]:
    session_id = state["session_id"]
    request_id = state["request_id"]
    trace_id = state["trace_id"]
    enduser_id = state.get("enduser_id")
    client_address = state.get("client_address")
    conversation_history = state.get("conversation_history", [])
    user_message = state["user_message"]

    messages = state.get("messages", [])
    final_message = state["final_message"]
    complete_display_text = state.get("complete_display_text", final_message)
    severity = state["severity"]
    confidence = state.get("confidence", 0.5)
    should_escalate = state.get("should_escalate", False)
    escalation_reasons = state.get("escalation_reasons", []) or []

    pii_injected = state.get("pii_injected", False)
    pii_types = state.get("pii_types", []) or []
    toxic_injected = state.get("toxic_injected", False)
    toxic_types = state.get("toxic_types", []) or []
    hallucination_injected = state.get("hallucination_injected", False)
    hallucination_types = state.get("hallucination_types", []) or []
    boundary_injected = state.get("boundary_injected", False)
    boundary_types = state.get("boundary_types", []) or []
    # Report what actually reached the user, not what was requested: the
    # ``*_detected`` flags are set by the injection node from the delivered text,
    # and a declined directive (no canned fallback exists) leaves them False. Use
    # the request flag only for states that predate the field.
    boundary_detected = state.get("boundary_detected", boundary_injected)
    hallucination_detected = state.get("hallucination_detected", hallucination_injected)
    pii_detected = state.get("pii_detected", pii_injected)
    toxic_detected = state.get("toxic_detected", toxic_injected)

    # Non-blocking Agent Control match (observe / steer, or a fail-open error)
    # at either stage: attribute the guardrail without claiming a safety
    # violation. A deny never reaches this node — it short-circuits to the
    # blocked event in ``_handle_agent_control_prompt_block`` /
    # ``_handle_agent_control_block``. Both verdicts ride on the event as
    # ``agent_control_verdicts`` (prompt stage first) so Agent Observability can
    # rebuild them as control spans on the turn's trace.
    control_verdicts = [
        v for v in (state.get("agent_control_prompt"), state.get("agent_control")) if v is not None
    ]
    matched_controls = [
        name for v in control_verdicts for name in (getattr(v, "matched_controls", None) or [])
    ]
    control_records = [v.record() for v in control_verdicts if hasattr(v, "record")] or None
    guardrail_ids = ["escalation_rules"] if should_escalate else []
    if matched_controls:
        guardrail_ids.append("galileo_agent_control")
    # Same for NeMo Guardrails: a rail that fired without withholding the turn
    # (a MODIFIED verdict, or a fail-open error) is attributed, not claimed as a
    # violation. A blocking rail short-circuits in nodes/nemo_rails.py.
    nemo_rails = [
        name
        for verdict in (state.get("nemo_guardrails_input"), state.get("nemo_guardrails_output"))
        for name in (getattr(verdict, "rule_names", None) or [])
    ]
    if nemo_rails:
        guardrail_ids.append("nemo_guardrails")

    # The blueprint that served the turn names the workflow (each architecture
    # is its own workflow in Splunk / Galileo); the setting is the fallback.
    workflow_name = state.get("workflow_name") or settings.agentic_workflow_name
    # Per-turn identity overrides; workflow/blueprint are passed explicitly
    # below (with the fallback), so drop them from the splat.
    identity = governance_identity_overrides(state)
    identity.pop("workflow_name", None)
    identity.pop("blueprint", None)
    duration = time.time() - state["start_time"]

    with otel.agent_span("governance_agent", theme=state.get("theme")):
        governance_logger.log_response(
            session_id=session_id,
            request_id=request_id,
            response_id=state["llm_response_id"],
            operation_name="chat",
            input_messages=messages,
            output_messages=[{"role": "assistant", "content": final_message}],
            response_text=complete_display_text,
            usage_data=governance_usage_data(state),
            # stage_timings ({stage}_ms, e.g. AI Defense inspections) is additive
            # next to the existing client_operation_duration — never renamed.
            performance_data={
                "client_operation_duration": duration,
                "stage_timings": state.get("stage_timings") or None,
            },
            response_model=state.get("llm_model"),
            response_finish_reasons=[state.get("llm_stop_reason", "end_turn")],
            safety_violated=should_escalate,
            safety_categories=escalation_reasons if should_escalate else None,
            guardrail_triggered=should_escalate or bool(matched_controls) or bool(nemo_rails),
            guardrail_ids=guardrail_ids or None,
            agent_control_verdicts=control_records,
            pii_detected=pii_detected,
            pii_types=pii_types if pii_detected else None,
            toxic_detected=toxic_detected,
            toxic_types=toxic_types if toxic_detected else None,
            evaluation_score_value=confidence,
            evaluation_score_label=(
                "high" if confidence > 0.7 else "medium" if confidence > 0.5 else "low"
            ),
            hallucination_detected=hallucination_detected,
            hallucination_types=hallucination_types if hallucination_detected else None,
            authority_violation_detected=boundary_detected,
            authority_violation_types=boundary_types if boundary_detected else None,
            severity=severity.value if severity else None,
            theme=state.get("theme"),
            agent_name=state.get("agent_name"),
            workflow_name=workflow_name,
            # Additive: which blueprint served the turn (None-stripped when unset).
            blueprint=state.get("blueprint"),
            # Per-agent transcript (coordinator + specialists + synthesizer) so the
            # Splunk Agent Observability SDK path can rebuild the multi-agent trace;
            # see backend/agent_observability.py and log_schemas.create_governance_log.
            agent_trace=state.get("agent_trace"),
            # Synthetic MCP tool-thrash records (backend/services/mcp_thrash.py);
            # the Agent Observability path rebuilds them as tool spans on the
            # turn's trace. None (dropped) when the toggle is off.
            tool_thrash=state.get("tool_thrash_trace"),
            trace_id=trace_id,
            client_address=client_address,
            enduser_id=enduser_id,
            **identity,
        )

        if should_escalate:
            user_info = clarifying_service.extract_user_info(conversation_history)
            symptoms = escalation_rules.extract_symptoms(
                conversation_history + [{"role": "user", "content": user_message}]
            )
            governance_logger.log_escalation(
                session_id=session_id,
                request_id=request_id,
                reason="; ".join(escalation_reasons),
                severity=severity.value,
                conversation_history=conversation_history
                + [
                    {"role": "user", "content": user_message},
                    {"role": "assistant", "content": final_message},
                ],
                symptoms=symptoms,
                user_demographics=user_info,
                enduser_id=enduser_id,
            )

    result: Dict[str, Any] = {
        "message": final_message,
        "type": MessageType.ESCALATION if should_escalate else MessageType.RECOMMENDATION,
        "severity": severity,
        "escalated": should_escalate,
        "metadata": {
            "confidence": confidence,
            "escalation_reasons": escalation_reasons if should_escalate else [],
        },
    }
    # Appointment scheduling payload (docs/scheduling.md): returned to the UI
    # (ChatResponse.scheduling / the SSE final frame) and persisted with the
    # message as metadata.scheduling, which is how the next turn knows about a
    # pending name, a prior offer or a decline.
    scheduling = state.get("scheduling")
    if scheduling:
        result["scheduling"] = scheduling
        result["metadata"]["scheduling"] = scheduling
    return {"terminal": True, "result": result}
