"""Internal policy block node (pre-AI safety gate).

Mirrors the built-in policy block in the legacy ``process_message``: dangerous
content (e.g. self-harm patterns) is intercepted before any model call. Defaults
to OFF: it runs only when the request explicitly enables it
(``internal_policy_review`` is True). An unset flag -- an API caller, the
Auto-Generate Sessions traffic, a card hidden on the Settings page -- skips it,
like the other guardrails. Self-harm escalation (``safety`` node) is separate
and still runs either way.

It screens ``screened_prompt(state)``: the typed message, plus the attached
document's text on a document turn (docs/attachments.md) -- so a real document
that mentions self-harm trips it too, the honest cost of a substring engine.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from backend.agents.nodes.attachment import (
    attachment_governance_fields,
    block_banner_suffix,
    screened_prompt,
)
from backend.agents.nodes.shared import clarifying_service, escalation_rules
from backend.agents.state import governance_identity_overrides, identity_turn_fields
from backend.agents.token_usage import governance_usage_data
from backend.logging.governance_logger import active_response_model, governance_logger
from backend.models.schemas import MessageType, SeverityLevel
from backend.services.escalation_rules import EscalationRules
from backend.services.recommendation_engine import guardrail_copy
from backend.telemetry import otel


def policy_block_node(state: Dict[str, Any]) -> Dict[str, Any]:
    run_internal = state.get("internal_policy_review") is True
    # Exactly user_message without an attachment.
    user_message = screened_prompt(state)

    should_block, block_reasons = (
        escalation_rules.check_policy_block(user_message)
        if run_internal
        else (False, [])
    )
    if not should_block:
        return {}

    session_id = state["session_id"]
    request_id = state["request_id"]
    trace_id = state["trace_id"]
    conversation_history = state.get("conversation_history", [])
    enduser_id = state.get("enduser_id")
    client_address = state.get("client_address")
    duration = time.time() - state["start_time"]
    blocked_message = EscalationRules.policy_block_response(
        guardrail_copy(state.get("theme")).advice_noun
    )
    note = block_banner_suffix(state)
    if note:
        blocked_message = f"{blocked_message}\n\n{note}"

    with otel.agent_span("internal_policy_agent", theme=state.get("theme")):
        governance_logger.log_response(
            session_id=session_id,
            request_id=request_id,
            response_id="policy-blocked",
            operation_name="chat",
            input_messages=[{"role": "user", "content": user_message}],
            output_messages=[{"role": "assistant", "content": blocked_message}],
            response_text=f"EMERGENCY\n\u26a0\ufe0f POLICY BLOCKED\n{blocked_message}",
            usage_data=governance_usage_data(),
            performance_data={"client_operation_duration": duration},
            response_model=_response_model(),
            response_finish_reasons=["policy_blocked"],
            safety_violated=True,
            safety_categories=block_reasons,
            guardrail_triggered=True,
            guardrail_ids=["policy_block"],
            policy_blocked=True,
            pii_detected=False,
            pii_types=[],
            toxic_detected=False,
            toxic_types=[],
            evaluation_score_value=1.0,
            evaluation_score_label="high",
            severity=SeverityLevel.EMERGENCY.value,
            theme=state.get("theme"),
            agent_name="internal_policy_agent",
            trace_id=trace_id,
            client_address=client_address,
            enduser_id=enduser_id,
            **governance_identity_overrides(state),
            **attachment_governance_fields(state),
        )

        governance_logger.log_escalation(
            session_id=session_id,
            request_id=request_id,
            reason="; ".join(block_reasons),
            severity=SeverityLevel.EMERGENCY.value,
            conversation_history=conversation_history
            + [
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": blocked_message},
            ],
            symptoms=escalation_rules.extract_symptoms(
                conversation_history + [{"role": "user", "content": user_message}]
            ),
            user_demographics=clarifying_service.extract_user_info(conversation_history),
            enduser_id=enduser_id,
            # A signed-in turn's identity evidence (Lab 5); {} when anonymous.
            **identity_turn_fields(state),
        )

    return {
        "terminal": True,
        "result": {
            "message": blocked_message,
            "type": MessageType.ESCALATION,
            "severity": SeverityLevel.EMERGENCY,
            "escalated": True,
            "policy_blocked": True,
            "metadata": {
                "confidence": 1.0,
                "escalation_reasons": block_reasons,
            },
        },
    }


def _response_model() -> str:
    """Active model id for governance logging (matches legacy behavior)."""
    return active_response_model()
