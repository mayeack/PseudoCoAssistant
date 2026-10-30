"""Coordinator agent node (always runs).

The first agent of the multi-agent stage. It does NOT answer the user; it reads
the query + theme and returns a JSON plan selecting 1-3 themed specialists from
the theme's roster. The selection is enforced to be >=1 (defaults to the theme's
primary specialist when the model returns an empty/invalid plan) so the
"always at least one coordinator + one specialist" invariant always holds.

Telemetry: emits a ``{theme}_coordinator`` AgentInvocation span wrapping its LLM
call, so it appears as a distinct agent in Splunk AI Agent Monitoring / Agent Observability.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Dict, List

from backend.agents.llm import ChatModelError, invoke_agent
from backend.agents.nodes.agent_common import (
    handle_agent_error,
    request_model,
    trace_entry,
)
from backend.agents.nodes.attachment import with_attachment_note
from backend.agents.nodes.shared import build_llm_messages
from backend.agents.token_usage import TokenTally
from backend.agents.themes.base import build_coordinator_prompt
from backend.config import settings
from backend.telemetry import otel

logger = logging.getLogger(__name__)

# Cap the per-turn specialist fan-out to bound latency/cost (sequential calls).
_MAX_SPECIALISTS = 2


def _parse_plan(output_text: str) -> Dict[str, Any]:
    """Extract the coordinator's JSON plan (tolerant of surrounding prose)."""
    text = output_text or ""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    raw = match.group(0) if match else text
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {}


def make_coordinator_agent(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Build the coordinator node for a specific theme."""
    coordinator_prompt = build_coordinator_prompt(theme_config)
    valid_keys = [s.key for s in theme_config.specialists]
    primary = theme_config.primary_specialist
    agent_name = theme_config.coordinator_agent_name

    def coordinator_node(state: Dict[str, Any]) -> Dict[str, Any]:
        # On a document turn the coordinator learns a document exists (its name,
        # never its text -- docs/attachments.md), so it plans instead of asking for it.
        messages = with_attachment_note(build_llm_messages(state.get("conversation_history", [])), state)
        provider = settings.ai_provider
        # Internal (non-user-facing) agent: run on the clean Ollama model so a
        # selected poisoned model only affects the user-facing synthesizer.
        model_override = settings.ollama_model_internal if provider == "ollama" else None

        agent_start = time.perf_counter()
        with otel.agent_span(agent_name, theme=theme_config.key):
            try:
                with otel.llm_span(
                    request_model=request_model(provider, model_override), provider=provider
                ) as llm_sp:
                    response = invoke_agent(
                        settings,
                        agent_name=agent_name,
                        system=coordinator_prompt,
                        messages=messages,
                        max_tokens=128,
                        temperature=0.3,
                        model_override=model_override,
                    )
                    otel.record_llm_result(
                        llm_sp,
                        response_id=response.id,
                        response_model=response.model,
                        input_tokens=response.input_tokens,
                        output_tokens=response.output_tokens,
                        output_tokens_cached=response.output_tokens_cached,
                        output_tokens_uncached=response.output_tokens_uncached,
                        finish_reason=response.stop_reason,
                    )
            except ChatModelError as exc:
                return handle_agent_error(state, exc)

        plan = _parse_plan(response.content)
        # A poisoned/garbage model may return a non-list here (str/int/dict); coerce
        # to a list so the roster loop below can't raise (which would crash the turn)
        # and we fall through to the primary-specialist default instead.
        requested = plan.get("specialists")
        if not isinstance(requested, list):
            requested = []

        # Keep only valid roster keys, dedup preserving order, cap at the max.
        selected: List[str] = []
        for key in requested:
            if key in valid_keys and key not in selected:
                selected.append(key)
            if len(selected) >= _MAX_SPECIALISTS:
                break

        # Guarantee >=1 specialist (the architecture's core invariant).
        if not selected and primary is not None:
            selected = [primary.key]
            logger.info(
                "coordinator returned no valid specialists; defaulting to primary '%s'",
                primary.key,
            )

        return {
            "selected_specialists": selected,
            "coordinator_plan": {
                "specialists": selected,
                "rationale": plan.get("rationale"),
            },
            "agent_trace": [
                trace_entry(
                    name=agent_name, role="coordinator", response=response,
                    duration_ms=round((time.perf_counter() - agent_start) * 1000, 1),
                )
            ],
            **TokenTally().add(response).updates(),
        }

    return coordinator_node
