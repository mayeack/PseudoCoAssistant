"""Synthesizer agent node (the turn's only user-facing agent).

The final agent of the multi-agent stage. It fuses the specialist findings into
the single structured recommendation the downstream nodes expect, and — because
it is the only user-facing agent — it carries the governance test-content
directive (so any solicited PII/toxic/hallucination/authority content lands in
the final answer for the guardrail/eval demo). Every category is solicited INTO
the theme's answer fields, so nothing after the JSON answer is kept: an
unfenced local model drops it anyway, and a censored model's trailing text is
where a "these samples are fictional" note would live (see nodes/injection.py).

Absorbs the former ``domain_agent`` node: same parsing (``_parse_recommendation``),
same formatting (``content_engine``), and it sets the same state fields.
Differences from the old domain agent:
- ``llm_input_tokens`` / ``llm_output_tokens`` are the running SUM across
  coordinator + specialists + synthesizer (the multi-agent token contract).
- ``agent_name`` stays ``{theme}_domain_agent`` for Splunk dashboard continuity.

Telemetry: emits a ``{theme}_domain_agent`` AgentInvocation span wrapping its LLM
call.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List

from backend.agents.llm import ChatModelError, invoke_agent
from backend.agents.nodes.agent_common import (
    SYNTHESIZER_MAX_TOKENS,
    SYNTHESIZER_TEMPERATURE,
    handle_agent_error,
    request_model,
    trace_entry,
)
from backend.agents.nodes.injection import (
    build_input_directives,
    embed_hallucination_contract,
    relax_scope_rules,
)
from backend.agents.nodes.shared import build_llm_messages, content_engine
from backend.agents.token_usage import TokenTally
from backend.agents.themes.base import build_synthesizer_prompt
from backend.config import settings
from backend.telemetry import otel

# Recommendation parsing is centralized on RecommendationEngine and reused here
# via ``content_engine._parse_recommendation`` (see backend/agents/nodes/shared.py).

# SYNTHESIZER_MAX_TOKENS / SYNTHESIZER_TEMPERATURE live in agent_common so the
# router can log the real values on the governance INPUT event without importing
# this module (see the import above).


def _format_specialist_findings(specialist_outputs: List[Dict[str, Any]]) -> str:
    """Concatenate specialist analyses into one labeled block for the synth prompt."""
    parts: List[str] = []
    for out in specialist_outputs or []:
        label = out.get("label") or out.get("key") or "Specialist"
        analysis = (out.get("analysis") or "").strip()
        if analysis:
            parts.append(f"[{label}]\n{analysis}")
    return "\n\n".join(parts)


def make_synthesizer_agent(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Build the synthesizer node for a specific theme."""
    base_prompt = build_synthesizer_prompt(theme_config)
    agent_name = theme_config.agent_name  # {key}_domain_agent

    def synthesizer_node(state: Dict[str, Any]) -> Dict[str, Any]:
        messages = build_llm_messages(state.get("conversation_history", []))

        # Fold specialist findings into the system prompt, then append the
        # governance directive (one roll per turn — must live on the user-facing
        # agent so the post-LLM injection node sees the same decision).
        findings = _format_specialist_findings(state.get("specialist_outputs", []))
        directive_text, requested_categories = build_input_directives(state)
        system_prompt = base_prompt
        # When the authority (prescriptive-overreach) category is active, lift the
        # base-prompt rules that forbid it so the model actually complies with the
        # directive; ordinary turns keep the safe OTC-only rules untouched.
        if requested_categories.get("authority"):
            system_prompt = relax_scope_rules(system_prompt, theme_config.key)
        # Same idea for the hallucination category: an appended directive alone is
        # ignored by the local model, so the fabrication requirement is written into
        # the theme's own answer contract (harmless on providers that would have
        # complied anyway, and one path is easier to keep at parity).
        if requested_categories.get("hallucination"):
            system_prompt = embed_hallucination_contract(system_prompt, theme_config.key)
        if findings:
            system_prompt = f"{system_prompt}\n\nSPECIALIST FINDINGS:\n{findings}"
        # Internal-document RAG (docs/internal-docs-rag.md): the passages the shared
        # internal_docs node retrieved on an explicit ask; empty otherwise. Context,
        # so it sits with the findings, ahead of the governance directive.
        system_prompt = system_prompt + ((state.get("internal_docs") or {}).get("context") or "")
        system_prompt = system_prompt + directive_text
        # Scheduling-intent turns (docs/scheduling.md): the full context in
        # single-agent mode, a hand-off note in Multi-Agent Mode; empty otherwise.
        system_prompt = system_prompt + (state.get("scheduling_directive") or "")
        provider = settings.ai_provider

        agent_start = time.perf_counter()
        with otel.agent_span(agent_name, theme=theme_config.key):
            try:
                with otel.llm_span(
                    request_model=request_model(provider), provider=provider
                ) as llm_sp:
                    response = invoke_agent(
                        settings,
                        agent_name=agent_name,
                        system=system_prompt,
                        messages=messages,
                        # Worst-case cap only (typical answers are ~200-300
                        # tokens). At local-8B decode speeds every extra token
                        # is user-visible wait, so don't leave 2048 on the
                        # table for a runaway generation.
                        max_tokens=SYNTHESIZER_MAX_TOKENS,
                        temperature=SYNTHESIZER_TEMPERATURE,
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

        recommendation = content_engine._parse_recommendation(
            response.content, theme_config.conversational, theme_config.key
        )
        severity = content_engine._normalize_severity(
            recommendation.get("severity", "MEDIUM")
        )
        confidence = content_engine._coerce_confidence(recommendation.get("confidence", 0.5))
        final_message = content_engine._format_recommendation(recommendation, theme_config.key)

        trace = list(state.get("agent_trace", []))
        trace.append(
            trace_entry(
                name=agent_name, role="synthesizer", response=response,
                duration_ms=round((time.perf_counter() - agent_start) * 1000, 1),
            )
        )

        return {
            "messages": messages,
            "requested_categories": requested_categories,
            "recommendation": recommendation,
            "agent_trace": trace,
            "llm_response_id": response.id,
            "llm_model": response.model,
            **TokenTally(state).add(response).updates(),
            "llm_stop_reason": response.stop_reason,
            "severity": severity,
            "confidence": confidence,
            "final_message": final_message,
        }

    return synthesizer_node
