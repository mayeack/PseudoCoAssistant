"""Executive AI-governance field overlay.

Derives a flat block of **board-level, dashboard-ready** fields from an
already-populated governance log dict, so a single Splunk panel can answer
"are our AI systems safe, reliable, compliant, and delivering value?" without
re-deriving anything at search time.

Design goals:
- **Additive / non-breaking.** Only *new* keys are added; no existing
  ``gen_ai.*`` / governance field is renamed or removed. The Splunk props that
  alias the raw fields to ``gen_ai.*`` keep working unchanged.
- **Honest.** Composite signals that the app can legitimately compute
  (``risk_score``, ``estimated_cost``, ``business_outcome``, ``policy_action``,
  ``audit_status``) are computed here. Scores that belong to the evaluation
  systems (real ``hallucination_score`` / ``groundedness_score``) are passed
  through when present and left ``None`` otherwise — they are sourced from the
  Splunk GenAI Scoring pipelines and Galileo, not invented here.
- **Defensive.** ``derive_executive_fields`` never raises; logging must never
  break a chat turn. Any failure yields ``{}`` (the event is logged unchanged).

The emitted field names match the executive dashboard contract exactly:
``app_name, user_type, risk_score, policy_action, policy_name, model_name,
agent_name, tool_name, prompt_category, contains_phi, contains_pii,
hallucination_score, groundedness_score, latency_ms, token_count,
estimated_cost, business_outcome, human_escalation, audit_status``, plus the
additive ``input_modality`` (``text`` | ``text+pdf`` on chat events; see
:func:`_input_modality`).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cost estimation. Splunk O11y Cloud's server-side pricing lookup does not price
# the current Claude models in this org (Cost KPI shows $0), so we compute a
# transparent app-side estimate here. USD per 1,000,000 tokens (input, output);
# matched by model-id prefix. These are demo defaults — treat the value as an
# estimate for the executive cost trend, not an authoritative billing figure.
# ---------------------------------------------------------------------------
_PRICES_PER_MTOK: Dict[str, tuple] = {
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-haiku-4": (1.00, 5.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-opus": (15.00, 75.00),
    "claude-3-sonnet": (3.00, 15.00),
    "claude-3-haiku": (0.25, 1.25),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "gemini-1.5-pro": (1.25, 5.00),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-2.0-flash": (0.10, 0.40),
    # provider=nvidia is a NIM on the box's own GPU: no per-token bill, so the
    # executive cost trend must not price it as a Sonnet-class API call.
    "nvidia/": (0.0, 0.0),
}
_DEFAULT_PRICE = (3.00, 15.00)  # fall back to a Sonnet-class estimate

# Guardrail-id -> (policy_name, business_outcome) for blocking guardrails.
_BLOCK_GUARDRAILS = {
    "cisco_ai_defense": ("Cisco AI Defense policy", "blocked_by_ai_defense"),
    "policy_block": ("Self-harm safety policy", "blocked_unsafe"),
    "tool_policy": ("Agentic tool policy", "blocked_tool_call"),
    "openclaw_tool_guard": ("OpenClaw tool guard", "blocked_tool_call"),
    "nemo_guardrails": ("NVIDIA NeMo Guardrails policy", "blocked_by_nemo_guardrails"),
    "nemoclaw_guardrails": ("NVIDIA NemoClaw guardrails", "blocked_tool_call"),
}

# PII types that are also Protected Health Information in a medical context.
_PHI_PII_TYPES = {
    "medical_record_number", "mrn", "diagnosis", "health_condition",
    "medication", "insurance_id", "member_id", "ssn", "social_security_number",
    "date_of_birth", "dob", "patient_id",
}
# Themes whose detected PII is treated as PHI (health-domain consults).
_MEDICAL_THEMES = {"medadvice", "benefitsadvice"}


def _f(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _price_for(model: Optional[str]) -> tuple:
    if not model:
        return _DEFAULT_PRICE
    m = str(model).lower()
    for prefix, price in _PRICES_PER_MTOK.items():
        if m.startswith(prefix):
            return price
    return _DEFAULT_PRICE


def _estimated_cost(model: Optional[str], in_tok: Any, out_tok: Any) -> Optional[float]:
    i, o = _f(in_tok), _f(out_tok)
    if i is None and o is None:
        return None
    price_in, price_out = _price_for(model)
    cost = ((i or 0.0) * price_in + (o or 0.0) * price_out) / 1_000_000.0
    return round(cost, 6)


def _severity_points(severity: Optional[str]) -> int:
    s = (severity or "").upper()
    return {"EMERGENCY": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 0}.get(s, 5)


def _policy_action(
    *, policy_blocked: bool, guardrail_triggered: bool, safety_violated: bool,
    pii_detected: bool, toxic_detected: bool, authority_violation_detected: bool = False,
) -> str:
    if policy_blocked:
        return "block"
    if safety_violated or guardrail_triggered:
        return "warn"        # delivered to the user, but escalated/flagged for review
    if pii_detected or toxic_detected or authority_violation_detected:
        return "flag"        # content present in the turn but not blocked
    return "allow"


def _policy_name(guardrail_ids: List[str], safety_categories: List[str]) -> Optional[str]:
    names: List[str] = []
    for gid in guardrail_ids:
        mapped = _BLOCK_GUARDRAILS.get(gid)
        if mapped:
            names.append(mapped[0])
        elif gid == "escalation_rules":
            names.append("Clinical escalation rules")
        elif gid:
            names.append(gid)
    # Surface AI Defense classifications (e.g. PRIVACY_VIOLATION) when present.
    for cat in safety_categories:
        if "classifications:" in cat.lower():
            names.append(cat.split(":", 1)[1].strip())
    return "; ".join(dict.fromkeys(n for n in names if n)) or None


def _business_outcome(
    *, operation_name: str, policy_blocked: bool, guardrail_ids: List[str],
    human_escalation: bool, finish_reasons: List[str],
) -> str:
    if operation_name == "error":
        return "service_error"
    if "clarify" in finish_reasons or "clarifying_question" in finish_reasons:
        return "clarification_requested"
    for gid in guardrail_ids:
        mapped = _BLOCK_GUARDRAILS.get(gid)
        if mapped and policy_blocked:
            return mapped[1]
    if policy_blocked:
        return "blocked_unsafe"
    if human_escalation:
        return "escalated_to_human"
    return "advice_delivered"


def _prompt_category(
    *, severity: Optional[str], policy_blocked: bool, guardrail_ids: List[str],
    contains_phi: bool, contains_pii: bool, safety_categories: List[str],
    confidence: Optional[float], toxic_detected: bool,
    operation_name: str = "chat",
) -> str:
    cats_text = " ".join(safety_categories).lower()
    # Agentic tool calls are a distinct risk category from chat prompts — a
    # governed tool action (exfiltration attempt, unapproved egress) is
    # "tool_exploitation" regardless of what PHI/PII rode in its arguments.
    if operation_name == "tool_call":
        return "tool_exploitation"
    if "policy_block" in guardrail_ids or "self-harm" in cats_text:
        return "self_harm_crisis"
    if (severity or "").upper() == "EMERGENCY" or "emergency" in cats_text:
        return "emergency_symptom"
    if any("security_violation" in c.lower() or "injection" in c.lower() for c in safety_categories):
        return "prompt_injection"
    if contains_phi or contains_pii:
        return "phi_pii_exposure"
    if toxic_detected:
        return "policy_violating_content"
    if confidence is not None and confidence < 0.5:
        return "low_confidence_medical"
    return "general_medical_advice"


def _audit_status(log: Dict[str, Any]) -> str:
    """Evidence completeness: is the full audit chain present on this event?"""
    # Tool-call events have no token usage or eval score (they are not model
    # calls), so the chat completeness contract would always read "partial".
    # Their audit chain is the correlation identity of the governed action.
    if log.get("operation_name") == "tool_call":
        required = ("request_id", "trace_id", "session_id", "tool_call_id")
        return "complete" if all(log.get(k) for k in required) else "partial"
    required = ("request_id", "trace_id", "session_id", "response_id")
    have_ids = all(log.get(k) for k in required)
    have_usage = log.get("usage_total_tokens") is not None
    have_eval = log.get("evaluation_score_value") is not None
    return "complete" if (have_ids and have_usage and have_eval) else "partial"


def _input_modality(log: Dict[str, Any]) -> Optional[str]:
    """What the user sent on a chat turn: ``"text"``, or ``"text+<kind>"`` when
    the turn carried a document (the ``attachment`` record, docs/attachments.md
    -- the rule ``attachments.input_modality`` states). ``None`` on non-chat
    events (tool calls, errors, decisions): they carry no user input."""
    record = log.get("attachment")
    if isinstance(record, dict) and record:
        return f"text+{record.get('kind') or 'pdf'}"
    return "text" if log.get("operation_name", "chat") == "chat" else None


def _risk_score(
    *, severity: Optional[str], policy_blocked: bool, safety_violated: bool,
    guardrail_triggered: bool, contains_phi: bool, contains_pii: bool,
    toxic_detected: bool, hallucination_detected: bool,
    authority_violation_detected: bool,
    confidence: Optional[float], latency_ms: Optional[float],
    operation_name: str = "chat",
) -> int:
    score = 5
    score += _severity_points(severity)
    if policy_blocked:
        score += 30
    if operation_name == "tool_call" and policy_blocked:
        # A blocked *action* is materially worse than a blocked prompt: the
        # agent actually tried to exfiltrate/execute. Stack on top of the
        # policy_blocked points above.
        score += 20
    if safety_violated or guardrail_triggered:
        score += 20
    if contains_phi:
        score += 15
    elif contains_pii:
        score += 8
    if toxic_detected:
        score += 15
    if hallucination_detected:
        score += 15
    if authority_violation_detected:
        # Out-of-authority / prescriptive-overreach content is a governance breach
        # in its own right — without this the board risk panel stays clean when the
        # "Outside of Authority" toggle fires.
        score += 15
    if confidence is not None and confidence < 0.5:
        score += 10
    if latency_ms is not None and latency_ms > 8000:
        score += 5
    return max(0, min(100, score))


def derive_executive_fields(log: Dict[str, Any]) -> Dict[str, Any]:
    """Return the executive overlay for a governance event. Never raises."""
    try:
        guardrail_ids = _as_list(log.get("guardrail_ids"))
        safety_categories = _as_list(log.get("safety_categories"))
        finish_reasons = _as_list(log.get("response_finish_reasons"))
        theme = (log.get("theme") or "").lower()

        policy_blocked = bool(log.get("policy_blocked"))
        safety_violated = bool(log.get("safety_violated"))
        guardrail_triggered = bool(log.get("guardrail_triggered"))
        pii_detected = bool(log.get("pii_detected"))
        toxic_detected = bool(log.get("toxic_detected"))
        hallucination_detected = bool(log.get("hallucination_detected"))
        authority_violation_detected = bool(log.get("authority_violation_detected"))
        pii_types = {t.lower() for t in _as_list(log.get("pii_types"))}

        contains_pii = pii_detected
        contains_phi = pii_detected and (
            theme in _MEDICAL_THEMES or bool(pii_types & _PHI_PII_TYPES)
        )

        confidence = _f(log.get("evaluation_score_value"))
        duration_s = _f(log.get("client_operation_duration"))
        latency_ms = round(duration_s * 1000.0, 1) if duration_s is not None else None
        human_escalation = safety_violated or "escalation_rules" in guardrail_ids
        severity = log.get("severity")
        model_name = log.get("response_model") or log.get("request_model")

        fields: Dict[str, Any] = {
            "app_name": log.get("service_name") or log.get("gen_ai.app.name"),
            "user_type": log.get("user_type")
            or ("patient" if theme in _MEDICAL_THEMES else "customer"),
            "model_name": model_name,
            "agent_name": log.get("agent_name") or log.get("workflow_name"),
            # The chat pipeline is tool-less, but the OpenClaw agentic surface
            # makes governed tool calls logged with operation_name=="tool_call".
            "tool_name": log.get("tool_name"),
            "session_id": log.get("session_id"),
            "prompt_category": _prompt_category(
                severity=severity, policy_blocked=policy_blocked,
                guardrail_ids=guardrail_ids, contains_phi=contains_phi,
                contains_pii=contains_pii, safety_categories=safety_categories,
                confidence=confidence, toxic_detected=toxic_detected,
                operation_name=log.get("operation_name", "chat"),
            ),
            "contains_pii": contains_pii,
            "contains_phi": contains_phi,
            "policy_action": _policy_action(
                policy_blocked=policy_blocked, guardrail_triggered=guardrail_triggered,
                safety_violated=safety_violated, pii_detected=pii_detected,
                toxic_detected=toxic_detected,
                authority_violation_detected=authority_violation_detected,
            ),
            "policy_name": _policy_name(guardrail_ids, safety_categories),
            # Real eval scores are passed through from the eval systems when set;
            # otherwise left None (sourced downstream from GenAI Scoring / Galileo).
            "hallucination_score": _f(log.get("hallucination_score")),
            "groundedness_score": _f(log.get("groundedness_score")),
            "latency_ms": latency_ms,
            "token_count": log.get("usage_total_tokens"),
            "estimated_cost": _estimated_cost(
                model_name, log.get("usage_input_tokens"), log.get("usage_output_tokens")
            ),
            "human_escalation": human_escalation,
            "business_outcome": _business_outcome(
                operation_name=log.get("operation_name", "chat"),
                policy_blocked=policy_blocked, guardrail_ids=guardrail_ids,
                human_escalation=human_escalation, finish_reasons=finish_reasons,
            ),
            "audit_status": _audit_status(log),
            "input_modality": _input_modality(log),
        }
        fields["risk_score"] = _risk_score(
            severity=severity, policy_blocked=policy_blocked,
            safety_violated=safety_violated, guardrail_triggered=guardrail_triggered,
            contains_phi=contains_phi, contains_pii=contains_pii,
            toxic_detected=toxic_detected, hallucination_detected=hallucination_detected,
            authority_violation_detected=authority_violation_detected,
            confidence=confidence, latency_ms=latency_ms,
            operation_name=log.get("operation_name", "chat"),
        )
        return fields
    except Exception:  # noqa: BLE001 - enrichment must never break logging
        logger.debug("executive field derivation failed", exc_info=True)
        return {}
