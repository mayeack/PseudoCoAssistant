"""Intake / clarifying-question agent node.

Rule-based pre-LLM specialist that decides whether more information is needed
before generating a recommendation. Conversational themes (e.g. telecom) handle
follow-ups in-prompt, so they skip this node.
"""

from __future__ import annotations

from typing import Any, Dict

from backend.agents.nodes.attachment import attachment_governance_fields
from backend.agents.nodes.shared import clarifying_service
from backend.agents.state import identity_turn_fields
from backend.logging.governance_logger import governance_logger
from backend.models.schemas import MessageType
from backend.telemetry import otel


def intake_node(state: Dict[str, Any]) -> Dict[str, Any]:
    # Conversational themes self-manage follow-up questions in-prompt.
    if state.get("conversational"):
        return {}
    # A scheduling-intent turn ("cancel my appointment") never needs a
    # clarifying question; the clarifier would re-read the earlier symptom text
    # and ask about it (docs/scheduling.md).
    if (state.get("scheduling_context") or {}).get("action"):
        return {}

    conversation_history = state.get("conversation_history", [])
    user_message = state["user_message"]

    if not clarifying_service.should_ask_questions(conversation_history, user_message):
        return {}

    with otel.agent_span("intake_agent", theme=state.get("theme")):
        next_question = clarifying_service.get_next_question(
            conversation_history, user_message
        )
        if not next_question:
            return {}

        governance_logger.log_decision(
            session_id=state["session_id"],
            request_id=state["request_id"],
            decision_type="clarifying_question",
            decision_value=next_question["category"],
            rationale=f"Missing {next_question['category']} information",
            enduser_id=state.get("enduser_id"),
            # A signed-in turn's identity evidence (Lab 5), as on every other
            # event of the turn and on the legacy engine's decision event; {}
            # on an anonymous turn. Not governance_identity_overrides: the
            # decision event has never carried workflow_name / blueprint, and
            # Labs 0-4 events stay unchanged.
            **identity_turn_fields(state),
            # A document turn's decision names its document (docs/attachments.md).
            **attachment_governance_fields(state),
        )

    return {
        "terminal": True,
        "result": {
            "message": next_question["question"],
            "type": MessageType.CLARIFYING_QUESTION,
            "severity": None,
            "escalated": False,
            "metadata": {
                "question_category": next_question["category"],
                "priority": next_question["priority"],
            },
        },
    }
