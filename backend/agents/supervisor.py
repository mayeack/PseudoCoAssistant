"""Supervisor / router (workshop section 4.3 "Orchestration").

The router is the entry node of the workflow. It:
- establishes correlation IDs (request_id / trace_id) and the start time,
- resolves the Application Theme to its config (system prompt, agent name,
  conversational flag), and
- emits the input governance event (console-only, per the Splunk contract).

It then hands off to the selected theme's decomposed subgraph via
``route_to_theme``.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict

from backend.agents.nodes.agent_common import (
    SYNTHESIZER_MAX_TOKENS,
    SYNTHESIZER_TEMPERATURE,
)
from backend.agents.themes import get_theme
from backend.logging.governance_logger import governance_logger
from backend.telemetry import otel


def router_node(state: Dict[str, Any]) -> Dict[str, Any]:
    theme_config = get_theme(state.get("theme"))
    request_id = state.get("request_id") or str(uuid.uuid4())
    trace_id = state.get("trace_id") or otel.turn_trace_id()
    start_time = state.get("start_time") or time.time()
    user_message = state["user_message"]

    with otel.agent_span("supervisor_router", theme=theme_config.key):
        # Input event: console-only (output events carry input_messages).
        governance_logger.log_request(
            session_id=state["session_id"],
            request_id=request_id,
            operation_name="chat",
            input_messages=[{"role": "user", "content": user_message}],
            # The user-facing generation's real params, from the one place that
            # defines them. (Coordinator and specialists use their own smaller
            # caps; the synthesizer is the call that produces the answer.)
            request_params={
                "request_max_tokens": SYNTHESIZER_MAX_TOKENS,
                "request_temperature": SYNTHESIZER_TEMPERATURE,
            },
            trace_id=trace_id,
            client_address=state.get("client_address"),
            system_instructions=theme_config.system_prompt,
            user_prompt=user_message,
            enduser_id=state.get("enduser_id"),
        )

    return {
        "request_id": request_id,
        "trace_id": trace_id,
        "start_time": start_time,
        "theme": theme_config.key,
        "system_prompt": theme_config.system_prompt,
        "agent_name": theme_config.agent_name,
        "conversational": theme_config.conversational,
    }


def route_to_theme(state: Dict[str, Any]) -> str:
    """Conditional-edge function: pick the theme subgraph node name."""
    theme_config = get_theme(state.get("theme"))
    return f"{theme_config.key}_subgraph"
