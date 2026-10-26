"""Agent Control evaluation nodes (prompt stage + response stage).

The "Agent Observability Controls" toggle in the settings drawer. Both nodes
submit one ``llm`` step to the Agent Control server — either the standalone
Galileo console's or the one hosted inside Splunk Observability Cloud's Agent
Observability (``galileo_agent_control_backend``) — and short-circuit the turn
when a control returns ``deny``.

- ``agent_control_prompt_node`` (PRE chain, after Cisco AI Defense) screens the
  user's prompt as a pre-stage step before any model call. It runs only when
  the backend's stages include ``pre`` (the default on splunk_ao, whose UI
  attaches controls to both stages; off on galileo, whose console controls are
  post-scoped). A prompt-stage ``steer`` is recorded, not acted on.
- ``agent_control_node`` (POST chain, after ``compliance`` so it sees the final
  post-injection text, before ``response_defense`` so Cisco AI Defense keeps the
  last word) judges the finished answer — e.g. the
  ``PseudoCoAssistant-block-hallucinated-output`` control, which fails a response
  whose Correctness score falls below threshold. A ``steer`` here is enforced:
  a steer agent rewrites the answer with the matched controls' steering context,
  the rewrite is evaluated again, and the rewrite is what the user gets (and what
  NeMo's output rails and AI Defense screen next). Bounded by
  ``galileo_agent_control_steer_attempts``; the outcome rides on the verdict.

Both are no-ops unless the request opted in (``agent_control_review``) and the
client is configured; errors honor ``galileo_agent_control_fail_open`` (default:
release the turn and log). Each records its verdict on its own state key so the
governance event carries both stages.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Tuple

from backend.agents.llm import ChatModelError, invoke_agent
from backend.agents.nodes.agent_common import SYNTHESIZER_MAX_TOKENS, request_model, trace_entry
from backend.agents.nodes.compliance import display_text
from backend.agents.nodes.injection import delivered_flags
from backend.agents.nodes.shared import content_engine
from backend.agents.state import governance_identity_overrides
from backend.agents.token_usage import TokenTally, governance_usage_data
from backend.config import settings
from backend.services.agent_control import ControlVerdict, agent_control_client
from backend.telemetry import otel

logger = logging.getLogger(__name__)

# The steer agent only applies the control's guidance; the guidance itself comes
# from the control (``steering_context.message``), so a new control needs no code.
_STEER_SYSTEM = (
    "You apply an output guardrail's correction to an assistant reply. A control "
    "flagged the reply and returned guidance. Rewrite the reply so it follows the "
    "guidance. Change only what the guidance asks for and keep everything else as "
    "it is: wording, facts, formatting, line breaks, list markers and language. "
    "Return only the rewritten reply, with no preamble, no note about what you "
    "changed, and no quotation marks or tags around it."
)
_STEER_TEMPERATURE = 0.2
# The reply is handed over between <reply> tags; a model sometimes echoes them.
_REPLY_TAG_RE = re.compile(r"</?reply>", re.IGNORECASE)


def _stage_timing(state: Dict[str, Any], stage: str, started: float) -> Dict[str, float]:
    """Merge this stage's elapsed wall-clock into the running stage_timings."""
    timings = dict(state.get("stage_timings") or {})
    timings[f"{stage}_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return timings


def _wants(stage: str, state: Dict[str, Any]) -> bool:
    """Opted in, configured, and this stage is enabled on the active backend.
    A client without ``stages`` (a test stub) runs the response stage only."""
    if not (state.get("agent_control_review") and agent_control_client.is_configured):
        return False
    stages = getattr(agent_control_client, "stages", None) or ["post"]
    return stage in stages


def agent_control_prompt_node(state: Dict[str, Any]) -> Dict[str, Any]:
    if not _wants("pre", state):
        return {}

    started = time.perf_counter()
    with otel.agent_span("galileo_agent_control_prompt_agent", theme=state.get("theme")):
        verdict = agent_control_client.evaluate_prompt(
            state["user_message"],
            enduser_id=state.get("enduser_id"),
            session_id=state.get("session_id"),
            theme=state.get("theme"),
        )
        if not verdict.should_block:
            # Non-blocking verdicts (clean, steer, observe, or a fail-open
            # error) still travel to the governance event via agent_control_prompt.
            return {
                "agent_control_prompt": verdict,
                "stage_timings": _stage_timing(state, "agent_control_prompt", started),
            }

        result = content_engine._handle_agent_control_prompt_block(
            session_id=state["session_id"],
            request_id=state["request_id"],
            trace_id=state["trace_id"],
            user_message=state["user_message"],
            conversation_history=state.get("conversation_history", []),
            verdict=verdict,
            start_time=state["start_time"],
            client_address=state.get("client_address"),
            enduser_id=state.get("enduser_id"),
            governance_overrides=governance_identity_overrides(state),
            theme=state.get("theme"),
        )

    return {
        "terminal": True,
        "result": result,
        "agent_control_prompt": verdict,
        "stage_timings": _stage_timing(state, "agent_control_prompt", started),
    }


def _evaluate(state: Dict[str, Any], text: str) -> ControlVerdict:
    return agent_control_client.evaluate_response(
        user_message=state["user_message"],
        assistant_message=text,
        enduser_id=state.get("enduser_id"),
        session_id=state.get("session_id"),
        theme=state.get("theme"),
        model=state.get("llm_model"),
    )


def _steer_prompt(guidance: List[str], text: str) -> str:
    lines = "\n".join(f"- {g}" for g in guidance)
    return f"Guidance:\n{lines}\n\n<reply>\n{text}\n</reply>"


def _steer(state: Dict[str, Any], verdict: ControlVerdict) -> Tuple[Dict[str, Any], ControlVerdict]:
    """Rewrite the answer with the steer guidance until a re-check stops
    steering, or the attempts run out.

    Returns the state updates and the verdict to record. That is the original
    steer verdict, with ``steer`` describing the outcome, unless the re-check
    denied the rewrite; then it is the denying verdict, which the caller blocks
    on. A rewrite that fails marks the steer verdict errored, so the fail-open
    policy decides between releasing the original answer and withholding it.
    """
    theme = state.get("theme") or "medadvice"
    agent_name = f"{theme}_agent_control_steer_agent"
    provider = settings.ai_provider
    # Run the rewrite on the clean internal model, like the other internal agents.
    model_override = settings.ollama_model_internal if provider == "ollama" else None
    original = state["final_message"]
    text = original
    guidance = list(verdict.steering)
    trace = list(state.get("agent_trace", []))
    tally = TokenTally(state)
    recheck = None
    attempts = 0
    outcome = "unresolved"

    while attempts < settings.galileo_agent_control_steer_attempts:
        attempts += 1
        agent_start = time.perf_counter()
        with otel.agent_span(agent_name, theme=theme):
            try:
                with otel.llm_span(request_model=request_model(provider, model_override), provider=provider) as llm_sp:
                    response = invoke_agent(
                        settings, agent_name=agent_name, system=_STEER_SYSTEM,
                        messages=[{"role": "user", "content": _steer_prompt(guidance, text)}],
                        max_tokens=SYNTHESIZER_MAX_TOKENS, temperature=_STEER_TEMPERATURE,
                        model_override=model_override,
                    )
                    otel.record_llm_result(
                        llm_sp, response_id=response.id, response_model=response.model,
                        input_tokens=response.input_tokens, output_tokens=response.output_tokens,
                        output_tokens_cached=response.output_tokens_cached,
                        output_tokens_uncached=response.output_tokens_uncached,
                        finish_reason=response.stop_reason,
                    )
            except ChatModelError as exc:
                logger.warning("agent control steer '%s' failed: %s", agent_name, exc)
                trace.append(trace_entry(name=agent_name, role="steer", status="error",
                                         duration_ms=round((time.perf_counter() - agent_start) * 1000, 1)))
                verdict.errored = True
                verdict.error_message = f"steer rewrite failed: {exc}"
                outcome = "error"
                break
        trace.append(trace_entry(name=agent_name, role="steer", response=response,
                                 duration_ms=round((time.perf_counter() - agent_start) * 1000, 1)))
        tally.add(response)
        rewritten = _REPLY_TAG_RE.sub("", response.content or "").strip()
        if not rewritten:
            verdict.errored = True
            verdict.error_message = "steer rewrite returned no text"
            outcome = "error"
            break
        text = rewritten
        recheck = _evaluate(state, text)
        if recheck.should_block:
            outcome = "denied"
            break
        if recheck.errored:
            outcome = "unverified"
            break
        if not recheck.steered:
            outcome = "applied"
            break
        guidance = recheck.steering or guidance

    verdict.steer = {
        "attempts": attempts,
        "outcome": outcome,
        "recheck_controls": list(recheck.matched_controls) if recheck else [],
        "recheck_decisions": list(recheck.decisions) if recheck else [],
    }
    updates: Dict[str, Any] = {"agent_trace": trace, **tally.updates()}
    if text != original:
        updates["final_message"] = text
        updates["complete_display_text"] = display_text(state, text)
        # The rewrite changed what reaches the user: report the Synthetic Content
        # categories from it, as the injection node did from the original.
        updates.update(delivered_flags(text, theme, state.get("requested_categories") or {}))
    if outcome == "denied":
        recheck.steer = dict(verdict.steer)
        return updates, recheck
    return updates, verdict


def agent_control_node(state: Dict[str, Any]) -> Dict[str, Any]:
    if not _wants("post", state):
        return {}

    started = time.perf_counter()
    updates: Dict[str, Any] = {}
    with otel.agent_span("galileo_agent_control_agent", theme=state.get("theme")):
        verdict = _evaluate(state, state["final_message"])
        if not verdict.should_block and verdict.steered and settings.galileo_agent_control_steer_attempts > 0:
            if verdict.steering:
                updates, verdict = _steer(state, verdict)
            else:
                # A steer control with no steering context has nothing to apply.
                verdict.steer = {"attempts": 0, "outcome": "no_guidance",
                                 "recheck_controls": [], "recheck_decisions": []}
        if not verdict.should_block:
            # Non-blocking verdicts (clean, steer, observe, or a fail-open
            # error) still travel to the governance event via agent_control.
            return {
                **updates,
                "agent_control": verdict,
                "stage_timings": _stage_timing(state, "agent_control", started),
            }

        result = content_engine._handle_agent_control_block(
            session_id=state["session_id"],
            request_id=state["request_id"],
            trace_id=state["trace_id"],
            conversation_messages=state.get("messages", []),
            verdict=verdict,
            start_time=state["start_time"],
            client_address=state.get("client_address"),
            enduser_id=state.get("enduser_id"),
            llm_model=state.get("llm_model"),
            usage_data=governance_usage_data({**state, **updates}),
            governance_overrides=governance_identity_overrides(state),
            theme=state.get("theme"),
            prompt_verdict=state.get("agent_control_prompt"),
        )

    return {
        **updates,
        "terminal": True,
        "result": result,
        "agent_control": verdict,
        "stage_timings": _stage_timing(state, "agent_control", started),
    }
