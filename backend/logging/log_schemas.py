from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid

from backend.config import settings


def cim_identity(*, user: Optional[str] = None, src: Optional[str] = None,
                 app: Optional[str] = None) -> Dict[str, Any]:
    """The Splunk Common Information Model identity fields for an event.

    ES correlation searches, risk-based alerting and the ES Triage agent pivot on
    CIM ``user`` / ``src`` / ``app``. Without them the governance event's actor
    was reachable only through the TA's ``gen_ai.user.id`` alias of
    ``enduser_id``, so the Triage agent searched for the actor and source and
    found no evidence. They are copies of the native fields (``enduser_id``,
    ``client_address``, ``app_name``), which keep their names and meaning;
    unset values are omitted, like every other field here.
    """
    return {k: v for k, v in (("user", user), ("src", src), ("app", app)) if v}


def create_governance_log(
    operation_name: str,
    request_model: str,
    conversation_id: str,
    session_id: str,
    input_messages: List[Dict[str, Any]],
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a standardized governance log entry"""

    log_entry = {
        # Unique identifier for this specific log entry
        "event_id": str(uuid.uuid4()),
        # Core operation / model identity
        "operation_name": operation_name,
        "provider_name": kwargs.get("provider_name", settings.ai_provider),
        "request_model": request_model,
        "response_model": kwargs.get("response_model"),
        "response_id": kwargs.get("response_id"),
        "conversation_id": conversation_id,
        "deployment_id": kwargs.get("deployment_id", "pseudoco-assistant-prod"),
        # Additive: which agentic blueprint served the turn (None-stripped when unset).
        "blueprint": kwargs.get("blueprint"),
        "request_id": request_id or str(uuid.uuid4()),
        "session_id": session_id,
        "trace_id": trace_id or str(uuid.uuid4()),

        # Input / output payload
        "input_messages": input_messages,
        "output_messages": kwargs.get("output_messages"),
        "response_text": kwargs.get("response_text"),  # Final formatted response text shown to user
        "system_instructions": kwargs.get("system_instructions"),
        "tool_definitions": kwargs.get("tool_definitions"),
        "output_type": kwargs.get("output_type", "text"),

        # Request parameters
        "token_type": kwargs.get("token_type", "input"),
        "request_max_tokens": kwargs.get("request_max_tokens"),
        "request_temperature": kwargs.get("request_temperature"),
        "request_top_p": kwargs.get("request_top_p"),
        "request_frequency_penalty": kwargs.get("request_frequency_penalty"),
        "request_presence_penalty": kwargs.get("request_presence_penalty"),
        "request_stop_sequences": kwargs.get("request_stop_sequences"),
        "response_finish_reasons": kwargs.get("response_finish_reasons"),
        "request_choice_count": kwargs.get("request_choice_count", 1),
        "request_seed": kwargs.get("request_seed"),

        # Usage, performance, and cost
        "usage_input_tokens": kwargs.get("usage_input_tokens"),
        "usage_output_tokens": kwargs.get("usage_output_tokens"),
        # Output tokens split by cache origin. Additive: the two always sum back
        # to usage_output_tokens, which keeps its meaning, so a cost review can
        # price a cached token apart from a decoded one and chart a cache-hit
        # ratio. See backend/agents/token_usage.py for where each comes from.
        "usage_output_tokens_cached": kwargs.get("usage_output_tokens_cached"),
        "usage_output_tokens_uncached": kwargs.get("usage_output_tokens_uncached"),
        "usage_total_tokens": kwargs.get("usage_total_tokens"),
        "client_operation_duration": kwargs.get("client_operation_duration"),
        "server_time_per_output_token": kwargs.get("server_time_per_output_token"),
        "server_time_to_first_token": kwargs.get("server_time_to_first_token"),
        # Additive latency-triage detail: per-stage wall-clock for non-LLM
        # stages, e.g. {"prompt_defense_ms": 812.4, "response_defense_ms": ...}
        # from the AI Defense nodes. Nested so the flat field namespace stays
        # stable (Splunk JSON indexing reads stage_timings.*). Per-agent LLM
        # timing rides in agent_trace[].duration_ms.
        "stage_timings": kwargs.get("stage_timings"),

        # Safety, guardrails, and policy
        "safety_violated": kwargs.get("safety_violated", False),
        "safety_categories": kwargs.get("safety_categories"),
        "guardrail_triggered": kwargs.get("guardrail_triggered", False),
        "guardrail_ids": kwargs.get("guardrail_ids"),
        "policy_blocked": kwargs.get("policy_blocked", False),
        # Additive: the Agent Control verdict(s) of the turn, one record per
        # stage — {stage, backend, target, is_safe, confidence, controls,
        # decisions, messages, evaluator_errors, errored, error_message,
        # transport, duration_ms}. The Agent Observability path rebuilds them as
        # control spans on the turn's trace; None (dropped) when no review ran.
        "agent_control_verdicts": kwargs.get("agent_control_verdicts"),

        # PII detection
        "pii_detected": kwargs.get("pii_detected", False),
        "pii_types": kwargs.get("pii_types"),

        # Toxic content detection
        "toxic_detected": kwargs.get("toxic_detected", False),
        "toxic_types": kwargs.get("toxic_types"),

        # Outside-of-authority / scope-violation detection (the app's own
        # test-injected signal — e.g. prescribing for med, money laundering for
        # tax). Populated when the "Outside of Authority" toggle requests it.
        "authority_violation_detected": kwargs.get("authority_violation_detected", False),
        "authority_violation_types": kwargs.get("authority_violation_types"),

        # Evaluation / TEVV
        "evaluation_name": kwargs.get("evaluation_name"),
        "evaluation_score_value": kwargs.get("evaluation_score_value"),
        "evaluation_score_label": kwargs.get("evaluation_score_label"),
        "evaluation_explanation": kwargs.get("evaluation_explanation"),
        "drift_metric_name": kwargs.get("drift_metric_name"),
        "drift_metric_value": kwargs.get("drift_metric_value"),
        "drift_status": kwargs.get("drift_status"),

        # Hallucination signal. ``hallucination_detected`` is the app's own
        # (test-injected) signal; the scored ``hallucination_score`` /
        # ``groundedness_score`` are populated by the eval systems (Splunk GenAI
        # Scoring, Galileo) and pass through here only when explicitly provided.
        "hallucination_detected": kwargs.get("hallucination_detected", False),
        "hallucination_types": kwargs.get("hallucination_types"),
        "hallucination_score": kwargs.get("hallucination_score"),
        "groundedness_score": kwargs.get("groundedness_score"),

        # Workflow / agent context (inputs to the executive overlay below).
        "agent_name": kwargs.get("agent_name"),
        "workflow_name": kwargs.get("workflow_name"),
        # Per-agent transcript for the turn (coordinator + specialists +
        # synthesizer): list of {name, role, model, input_tokens, output_tokens,
        # output_text (truncated), status}. Consumed by the Galileo SDK path to
        # rebuild the multi-agent trace; None on non-chat events (then dropped).
        "agent_trace": kwargs.get("agent_trace"),
        "theme": kwargs.get("theme"),
        "severity": kwargs.get("severity"),
        "tool_name": kwargs.get("tool_name"),
        # Agentic tool-guard fields (operation_name == "tool_call"). Populated
        # by governance_logger.log_tool_call; None (and dropped) on chat events.
        "tool_call_id": kwargs.get("tool_call_id"),
        "tool_arguments": kwargs.get("tool_arguments"),
        "tool_decision": kwargs.get("tool_decision"),
        "tool_denied_reason": kwargs.get("tool_denied_reason"),
        "agent_surface": kwargs.get("agent_surface"),
        "user_type": kwargs.get("user_type"),

        # Error and infra fields
        "error_type": kwargs.get("error_type"),
        "server_address": kwargs.get("server_address"),
        "server_port": kwargs.get("server_port"),

        # Actor / application context
        "enduser_id": kwargs.get("enduser_id"),
        "service_name": kwargs.get("service_name", "pseudoco-assistant"),
        "client_address": kwargs.get("client_address"),

        # Timestamp
        "timestamp": kwargs.get("timestamp", datetime.utcnow()).isoformat()
    }

    # Executive overlay: derive the board-level normalized fields (risk_score,
    # policy_action, business_outcome, estimated_cost, contains_phi,
    # audit_status, ...) from the assembled event. Additive and fully defensive
    # — a derivation failure leaves the event unchanged.
    try:
        from backend.logging.executive_fields import derive_executive_fields
        log_entry.update(derive_executive_fields(log_entry))
    except Exception:  # noqa: BLE001 - enrichment must never break logging
        pass

    # CIM identity (user / src / app) — see cim_identity. ``app`` follows the
    # overlay's ``app_name`` (the governed app, e.g. pseudoco-assistant-medadvice).
    log_entry.update(cim_identity(
        user=log_entry.get("enduser_id"),
        src=log_entry.get("client_address"),
        app=log_entry.get("app_name") or log_entry.get("service_name"),
    ))

    # Remove None values for cleaner logs
    return {k: v for k, v in log_entry.items() if v is not None}

def create_escalation_log(
    escalation_id: str,
    session_id: str,
    request_id: str,
    reason: str,
    severity: str,
    conversation_history: List[Dict[str, Any]],
    symptoms: List[str],
    **kwargs
) -> Dict[str, Any]:
    """Create a standardized escalation log entry"""

    entry = {
        "escalation_id": escalation_id,
        "session_id": session_id,
        "request_id": request_id,
        "timestamp": kwargs.get("timestamp", datetime.utcnow()).isoformat(),
        "reason": reason,
        "severity": severity,
        "conversation_history": conversation_history,
        "user_demographics": kwargs.get("user_demographics"),
        "symptoms": symptoms,
        "review_status": kwargs.get("review_status", "pending"),
        "reviewer_id": kwargs.get("reviewer_id"),
        "review_notes": kwargs.get("review_notes"),
        "review_timestamp": kwargs.get("review_timestamp"),
        "enduser_id": kwargs.get("enduser_id")
    }
    entry.update(cim_identity(user=kwargs.get("enduser_id")))
    return entry

def create_audit_log(
    audit_id: str,
    session_id: str,
    request_id: str,
    action: str,
    actor: str,
    details: Dict[str, Any],
    **kwargs
) -> Dict[str, Any]:
    """Create a standardized audit log entry"""

    entry = {
        "audit_id": audit_id,
        "session_id": session_id,
        "request_id": request_id,
        "timestamp": kwargs.get("timestamp", datetime.utcnow()).isoformat(),
        "action": action,
        "actor": actor,
        "details": details,
        "ip_address": kwargs.get("ip_address"),
        "enduser_id": kwargs.get("enduser_id")
    }
    entry.update(cim_identity(user=kwargs.get("enduser_id"), src=kwargs.get("ip_address")))
    return entry
