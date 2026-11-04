"""Specialists agent node.

Runs each coordinator-selected specialist as its own themed agent, sequentially.
Each specialist is a distinct named agent (``{theme}_{key}_specialist``) so it
emits its own AgentInvocation span -> the multi-agent trace shows one span per
specialist in Splunk AI Agent Monitoring / Agent Observability.

Design notes:
- Sequential (not LangGraph parallel ``Send``) because ``PseudoCoAssistantState`` has no
  merge reducers; parallel writes to ``agent_trace`` / token sums would clobber.
- Continue-on-partial-failure: a specialist that raises is recorded with
  ``status="error"`` and the turn proceeds; the stage only short-circuits if
  ZERO specialists succeed.
- Token sums (``llm_input_tokens`` / ``llm_output_tokens``) are accumulated onto
  the running totals the coordinator started, so the governance contract reports
  the multi-agent total for the turn.
"""

from __future__ import annotations

import logging
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
from backend.agents.themes.base import build_specialist_prompt
from backend.config import settings
from backend.telemetry import otel

logger = logging.getLogger(__name__)


def make_specialists_agent(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Build the specialists node for a specific theme."""

    def specialists_node(state: Dict[str, Any]) -> Dict[str, Any]:
        # On a document turn each specialist learns a document exists (its name,
        # never its text -- docs/attachments.md): its findings reach the
        # synthesizer, which does read the text, so they must not deny it exists.
        messages = with_attachment_note(build_llm_messages(state.get("conversation_history", [])), state)
        provider = settings.ai_provider
        # Internal (non-user-facing) agents: run on the clean Ollama model so a
        # selected poisoned model only affects the user-facing synthesizer.
        model_override = settings.ollama_model_internal if provider == "ollama" else None

        selected = list(state.get("selected_specialists") or [])
        if not selected and theme_config.primary_specialist is not None:
            # Defensive: coordinator should always set >=1, but never run zero.
            selected = [theme_config.primary_specialist.key]

        trace: List[Dict[str, Any]] = list(state.get("agent_trace", []))
        specialist_outputs: List[Dict[str, Any]] = []
        tally = TokenTally(state)
        successes = 0

        for key in selected:
            spec = theme_config.specialist(key)
            if spec is None:
                continue
            agent_name = theme_config.specialist_agent_name(key)
            system_prompt = build_specialist_prompt(theme_config, spec)

            agent_start = time.perf_counter()
            with otel.agent_span(agent_name, theme=theme_config.key):
                try:
                    with otel.llm_span(
                        request_model=request_model(provider, model_override), provider=provider
                    ) as llm_sp:
                        response = invoke_agent(
                            settings,
                            agent_name=agent_name,
                            system=system_prompt,
                            messages=messages,
                            max_tokens=256,
                            temperature=0.5,
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
                    # Continue-on-partial-failure: record + keep going.
                    logger.warning("specialist '%s' failed: %s", agent_name, exc)
                    trace.append(
                        trace_entry(
                            name=agent_name, role="specialist", status="error",
                            duration_ms=round((time.perf_counter() - agent_start) * 1000, 1),
                        )
                    )
                    continue

            successes += 1
            tally.add(response)
            specialist_outputs.append(
                {"key": key, "label": spec.label, "analysis": response.content}
            )
            trace.append(
                trace_entry(
                    name=agent_name, role="specialist", response=response,
                    duration_ms=round((time.perf_counter() - agent_start) * 1000, 1),
                )
            )

        # Terminate only if EVERY selected specialist failed.
        if successes == 0:
            return handle_agent_error(
                state, ChatModelError("all selected specialists failed")
            )

        return {
            "specialist_outputs": specialist_outputs,
            "agent_trace": trace,
            **tally.updates(),
        }

    return specialists_node
