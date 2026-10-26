"""Compliance / formatting agent node.

Assembles the complete display text exactly as the frontend renders it (severity
badge + escalation warning + message body). This is the ``response_text`` that
the governance node logs to Splunk.
"""

from __future__ import annotations

from typing import Any, Dict

from backend.telemetry import otel


def display_text(state: Dict[str, Any], final_message: str) -> str:
    """The display text for ``final_message`` under this turn's severity and
    escalation. Also used by ``agent_control_node`` when a steer rewrites the
    answer after this node ran."""
    display_text_parts = []
    severity = state.get("severity")
    if severity:
        display_text_parts.append(severity.value)
    if state.get("should_escalate"):
        display_text_parts.append("⚠️ ESCALATED FOR REVIEW")
    display_text_parts.append(final_message)
    return "\n".join(display_text_parts)


def compliance_node(state: Dict[str, Any]) -> Dict[str, Any]:
    with otel.agent_span("compliance_agent", theme=state.get("theme")):
        complete_display_text = display_text(state, state["final_message"])

    return {"complete_display_text": complete_display_text}
