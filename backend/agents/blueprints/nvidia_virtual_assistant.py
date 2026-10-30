"""The NVIDIA AI Virtual Assistant blueprint — a faithful port of
NVIDIA-AI-Blueprints/ai-virtual-assistant's agent onto PseudoCo Assistant's themes.

The reference graph: ``fetch_purchase_history -> primary_assistant`` which
routes by the tool the model calls (``ToProductQAAssistant``,
``ToOrderStatusAssistant``, ``ToReturnProcessing``, ``HandleOtherTalk``) into a
specialized assistant that uses tools over an unstructured knowledge base
(RAG) and structured customer records, with ``ProductValidation ->
ask_clarification`` when a request is ambiguous. Here, per Application Theme:

    fetch_record -> ask_clarification -> primary_assistant -> sub_assistant -> respond

- ``fetch_record``      the session's synthetic record (``lookup_record``),
                        stable per end user — the blueprint's user memory.
- ``ask_clarification`` the rule-based clarifier (short-circuits with a question).
- ``primary_assistant`` does NOT answer: it routes by calling one
                        ``To<Sub>Assistant`` tool derived from the theme's
                        specialist roster (or ``HandleOtherTalk``). Native
                        tool-calling when the provider supports it, a JSON
                        tool-call plan otherwise (``blueprint_routing``).
- ``sub_assistant``     runs the chosen assistant(s) with the blueprint's tools
                        applied — ``retrieve_knowledge`` (RAG over the theme's
                        knowledge articles) and ``lookup_record`` (the structured
                        record) — producing internal findings.
- ``respond``           the user-facing answer in the theme's contract. It is
                        the same synthesizer agent as the PseudoCo Assistant blueprint
                        (agent name ``{theme}_domain_agent``), which is what
                        guarantees the governance-directive and state contract
                        the shared POST chain relies on.

Multi-Agent Mode here means the primary assistant may hand the turn to up to
two sub-assistants instead of one. Every guardrail is outside this core.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from langgraph.graph import END, StateGraph

from backend.agents.blueprints import data, retrieval
from backend.agents.blueprints.base import Blueprint
from backend.agents.llm import ChatModelError, invoke_agent
from backend.agents.nodes.agent_common import handle_agent_error, request_model, trace_entry
from backend.agents.nodes.attachment import with_attachment_note
from backend.agents.nodes.clarify import intake_node
from backend.agents.nodes.shared import build_llm_messages
from backend.agents.nodes.synthesizer import make_synthesizer_agent
from backend.agents.token_usage import TokenTally
from backend.config import settings
from backend.telemetry import otel

logger = logging.getLogger(__name__)

KEY = "nvidia_virtual_assistant"
OTHER_TALK = "HandleOtherTalk"
_TOOL_PROVIDERS = {"anthropic", "openai", "bedrock", "nvidia"}


def _terminal_router(state: Dict[str, Any]) -> str:
    return "end" if state.get("terminal") else "next"


def _camel(key: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^a-zA-Z0-9]+", key) if part)


def tool_name_for(sub_key: str) -> str:
    return f"To{_camel(sub_key)}Assistant"


def routing_mode() -> str:
    """tools | json — resolved from settings.blueprint_routing (auto = tools
    when the provider speaks native tool calling, else a JSON plan)."""
    mode = (getattr(settings, "blueprint_routing", "auto") or "auto").lower()
    if mode in ("tools", "json"):
        return mode
    return "tools" if (settings.ai_provider or "").lower() in _TOOL_PROVIDERS else "json"


def _internal_override() -> Optional[str]:
    # Internal (non-user-facing) agents run on the clean Ollama model, like the
    # PseudoCo Assistant blueprint's coordinator/specialists.
    return settings.ollama_model_internal if settings.ai_provider == "ollama" else None


# ------------------------------------------------------------------ prompts
def build_primary_prompt(theme_config, *, allow_multi: bool) -> str:
    menu = "\n".join(f"- {tool_name_for(s.key)}: {s.role}" for s in theme_config.specialists)
    plural = "one or two tools (most relevant first)" if allow_multi else "exactly one tool"
    return (
        f"You are the primary assistant for {theme_config.label}. You do NOT answer the user "
        "yourself. Your only job is to hand the conversation to the specialized assistant "
        "that should handle the user's latest message, by calling a tool.\n\n"
        f"Available tools:\n{menu}\n- {OTHER_TALK}: greetings, thanks, small talk, or a request "
        "outside this service's scope (the responder will redirect politely)\n\n"
        f"Call {plural}. Respond with ONLY a JSON object in exactly this shape (no prose):\n"
        '{"tool": "<tool name>", "args": {"query": "<the user\'s need in one sentence>"}}\n'
        + ('or a JSON list of such objects when two assistants are needed.\n' if allow_multi else "")
    )


def build_sub_assistant_prompt(theme_config, spec, knowledge: List[Dict[str, Any]], record: Dict[str, Any]) -> str:
    kb = "\n\n".join(f"[{i + 1}] ({k['title']})\n{k['text']}" for i, k in enumerate(knowledge)) or "(no matching articles)"
    rec = json.dumps(record, indent=2) if record else "(no record on file)"
    return (
        f"You are the {spec.label} assistant on the {theme_config.label} team.\n"
        f"Your focus: {spec.focus}\n\n"
        "Two tools have already been run for you:\n"
        f"retrieve_knowledge — matching knowledge-base articles:\n{kb}\n\n"
        f"lookup_record — the user's record (synthetic demo data):\n{rec}\n\n"
        "Analyze the user's latest message strictly through your focus, using the "
        "articles and the record where relevant. Return a brief internal analysis (3-6 "
        "concise bullet points) for the responding assistant, citing the article number "
        "or record field you relied on. This is NOT shown to the user and must NOT be a "
        "full answer or address the user directly. No greetings or disclaimers."
    )


# ------------------------------------------------------------------ routing
def parse_route(output_text: str, valid: Dict[str, str], primary_key: Optional[str], *, limit: int) -> Tuple[List[str], bool]:
    """Map the model's tool call(s) to sub-assistant keys.

    ``valid`` maps tool name -> sub key. Returns (selected keys, other_talk).
    An empty/invalid plan defaults to the theme's primary specialist so a turn
    always has an assistant (the reference raises; PseudoCo Assistant degrades).
    """
    text = output_text or ""
    # Tool names are plain strings, so read them straight out of the JSON text:
    # this survives nested "args" objects, lists of calls, and the prose a
    # smaller model sometimes wraps around its JSON.
    names = [n.strip() for n in re.findall(r'"tool"\s*:\s*"([^"]+)"', text)]
    if any(n == OTHER_TALK for n in names) and not any(n in valid for n in names):
        return [], True
    selected: List[str] = []
    for n in names:
        key = valid.get(n)
        if key and key not in selected:
            selected.append(key)
        if len(selected) >= limit:
            break
    if not selected and primary_key:
        selected = [primary_key]
    return selected, False


def _route_with_tools(theme_config, system: str, messages: List[Dict[str, Any]], agent_name: str,
                      model_override: Optional[str]):
    """Native tool calling: bind To<Sub>Assistant tools and read tool_calls.
    Returns (tool_call_names, NormalizedLLMResponse-like)."""
    from backend.agents.llm import (
        NormalizedLLMResponse, _extract_metadata, _extract_usage, _to_langchain_messages, get_chat_model,
    )

    tools = [
        {"name": tool_name_for(s.key), "description": s.role,
         "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}
        for s in theme_config.specialists
    ] + [{"name": OTHER_TALK, "description": "greetings, thanks, small talk or out-of-scope requests",
          "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}}]
    provider = settings.ai_provider
    model = get_chat_model(settings, max_tokens=160, temperature=0.2, model_override=model_override)
    bound = model.bind_tools(tools)
    fallback = model_override or request_model(provider)
    with otel.genai_agent_invocation(
        agent_name=agent_name, request_model=fallback, provider=provider, system=system, messages=messages,
    ) as inv:
        try:
            ai = bound.invoke(_to_langchain_messages(system, messages))
        except Exception as exc:  # noqa: BLE001
            raise ChatModelError(f"Agent '{agent_name}' tool routing failed: {exc}") from exc
        usage = _extract_usage(ai, provider)
        meta = _extract_metadata(ai, fallback)
        names = [tc.get("name", "") for tc in (getattr(ai, "tool_calls", None) or []) if isinstance(tc, dict)]
        content = json.dumps([{"tool": n, "args": {}} for n in names]) if names else (getattr(ai, "content", "") or "")
        if inv is not None:
            inv.input_tokens = usage["input_tokens"]
            inv.output_tokens = usage["output_tokens"]
            otel.record_output_token_cache_split(
                inv, usage["output_tokens_cached"], usage["output_tokens_uncached"]
            )
            inv.response_model_name = meta["model"]
            inv.response_id = meta["id"]
            otel.record_genai_output(inv, text=str(content), finish_reason=meta["stop_reason"])
    return names, NormalizedLLMResponse(
        id=meta["id"], content=str(content), model=meta["model"],
        input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
        output_tokens_cached=usage["output_tokens_cached"],
        output_tokens_uncached=usage["output_tokens_uncached"],
        stop_reason=meta["stop_reason"],
    )


# ------------------------------------------------------------------ nodes
def make_fetch_record(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def fetch_record(state: Dict[str, Any]) -> Dict[str, Any]:
        with otel.agent_span(f"{theme_config.key}_record_lookup", theme=theme_config.key):
            record = data.record_for(theme_config.key, state.get("enduser_id"))
        return {"blueprint_record": record}

    return fetch_record


def make_primary_assistant(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    valid = {tool_name_for(s.key): s.key for s in theme_config.specialists}
    primary_key = theme_config.primary_specialist.key if theme_config.primary_specialist else None
    agent_name = f"{theme_config.key}_primary_assistant"

    def primary_assistant(state: Dict[str, Any]) -> Dict[str, Any]:
        # A scheduling-intent turn routes to no sub-assistant (the HandleOtherTalk
        # path): the responder answers with the scheduling directive and the
        # shared scheduling node follows. No routing model call (docs/scheduling.md).
        if (state.get("scheduling_context") or {}).get("action"):
            return {
                "selected_specialists": [],
                "blueprint_route": {"tools": [OTHER_TALK], "other_talk": True, "mode": "scheduling"},
            }
        allow_multi = state.get("multi_agent_mode") is True
        limit = 2 if allow_multi else 1
        system = build_primary_prompt(theme_config, allow_multi=allow_multi)
        # On a document turn the router learns a document exists (its name, never
        # its text -- docs/attachments.md), as the PseudoCo Assistant coordinator does.
        messages = with_attachment_note(build_llm_messages(state.get("conversation_history", [])), state)
        provider = settings.ai_provider
        override = _internal_override()
        mode = routing_mode()

        started = time.perf_counter()
        with otel.agent_span(agent_name, theme=theme_config.key):
            try:
                if mode == "tools":
                    try:
                        names, response = _route_with_tools(theme_config, system, messages, agent_name, override)
                        selected, other = parse_route(json.dumps([{"tool": n} for n in names]) if names else "",
                                                      valid, primary_key, limit=limit)
                    except ChatModelError as exc:
                        # A provider that advertises tools but rejects the bound schema
                        # (or a model without a tools template) falls back to the plan.
                        logger.warning("tool routing failed (%s); falling back to a JSON plan", exc)
                        mode = "json"
                if mode == "json":
                    with otel.llm_span(request_model=request_model(provider, override), provider=provider) as sp:
                        response = invoke_agent(
                            settings, agent_name=agent_name, system=system, messages=messages,
                            max_tokens=160, temperature=0.2, model_override=override,
                        )
                        otel.record_llm_result(
                            sp, response_id=response.id, response_model=response.model,
                            input_tokens=response.input_tokens, output_tokens=response.output_tokens,
                            output_tokens_cached=response.output_tokens_cached,
                            output_tokens_uncached=response.output_tokens_uncached,
                            finish_reason=response.stop_reason,
                        )
                    selected, other = parse_route(response.content, valid, primary_key, limit=limit)
            except ChatModelError as exc:
                return handle_agent_error(state, exc)

        return {
            "selected_specialists": selected,
            "blueprint_route": {"tools": [tool_name_for(k) for k in selected] or [OTHER_TALK],
                                "other_talk": other, "mode": mode},
            "agent_trace": [trace_entry(name=agent_name, role="primary_assistant", response=response,
                                        duration_ms=round((time.perf_counter() - started) * 1000, 1))],
            **TokenTally().add(response).updates(),
        }

    return primary_assistant


def make_sub_assistant(theme_config) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def sub_assistant(state: Dict[str, Any]) -> Dict[str, Any]:
        selected = list(state.get("selected_specialists") or [])
        if not selected:
            # HandleOtherTalk: the responder handles small talk / out-of-scope directly.
            return {"specialist_outputs": [], "blueprint_tools": []}

        # The document's name, never its text, as the PseudoCo Assistant specialists
        # get it: their findings reach the responder, which does read the text.
        messages = with_attachment_note(build_llm_messages(state.get("conversation_history", [])), state)
        provider = settings.ai_provider
        override = _internal_override()
        # Retrieval stays on the typed message (deterministic; docs/attachments.md).
        user_message = state.get("user_message", "")
        record = state.get("blueprint_record") or {}
        trace: List[Dict[str, Any]] = list(state.get("agent_trace", []))
        outputs: List[Dict[str, Any]] = []
        tools_used: List[Dict[str, Any]] = []
        tally = TokenTally(state)
        successes = 0

        for key in selected:
            spec = theme_config.specialist(key)
            if spec is None:
                continue
            agent_name = f"{theme_config.key}_{key}_assistant"
            with otel.tool_span("retrieve_knowledge", agent_surface="blueprint") as tsp:
                knowledge = retrieval.search(theme_config.key, user_message, k=3)
                otel.record_tool_result(tsp, decision="allow", rule_names=None, event_id=None,
                                        denied_reason=None)
            tools_used.append({"tool": "retrieve_knowledge", "assistant": key, "hits": len(knowledge),
                               "method": knowledge[0]["method"] if knowledge else "none"})
            tools_used.append({"tool": "lookup_record", "assistant": key, "found": bool(record)})
            system = build_sub_assistant_prompt(theme_config, spec, knowledge, record)

            started = time.perf_counter()
            with otel.agent_span(agent_name, theme=theme_config.key):
                try:
                    with otel.llm_span(request_model=request_model(provider, override), provider=provider) as sp:
                        response = invoke_agent(
                            settings, agent_name=agent_name, system=system, messages=messages,
                            max_tokens=256, temperature=0.5, model_override=override,
                        )
                        otel.record_llm_result(
                            sp, response_id=response.id, response_model=response.model,
                            input_tokens=response.input_tokens, output_tokens=response.output_tokens,
                            output_tokens_cached=response.output_tokens_cached,
                            output_tokens_uncached=response.output_tokens_uncached,
                            finish_reason=response.stop_reason,
                        )
                except ChatModelError as exc:
                    logger.warning("sub-assistant '%s' failed: %s", agent_name, exc)
                    trace.append(trace_entry(name=agent_name, role="sub_assistant", status="error",
                                             duration_ms=round((time.perf_counter() - started) * 1000, 1)))
                    continue
            successes += 1
            tally.add(response)
            outputs.append({"key": key, "label": spec.label, "analysis": response.content,
                            "knowledge": [k["title"] for k in knowledge], "record_used": bool(record)})
            trace.append(trace_entry(name=agent_name, role="sub_assistant", response=response,
                                     duration_ms=round((time.perf_counter() - started) * 1000, 1)))

        if successes == 0:
            return handle_agent_error(state, ChatModelError("all selected sub-assistants failed"))
        return {
            "specialist_outputs": outputs,
            "blueprint_tools": tools_used,
            "agent_trace": trace,
            **tally.updates(),
        }

    return sub_assistant


def build_generation_core(g: StateGraph, theme_config) -> Tuple[str, str]:
    g.add_node("fetch_record", make_fetch_record(theme_config))
    g.add_node("ask_clarification", intake_node)
    g.add_node("primary_assistant", make_primary_assistant(theme_config))
    g.add_node("sub_assistant", make_sub_assistant(theme_config))
    # The responder IS the PseudoCo Assistant synthesizer: same answer contract, directive
    # handling, agent name and state fields, so the shared POST chain sees no
    # difference between blueprints.
    g.add_node("respond", make_synthesizer_agent(theme_config))

    g.add_edge("fetch_record", "ask_clarification")
    g.add_conditional_edges("ask_clarification", _terminal_router, {"end": END, "next": "primary_assistant"})
    g.add_conditional_edges("primary_assistant", _terminal_router, {"end": END, "next": "sub_assistant"})
    g.add_conditional_edges("sub_assistant", _terminal_router, {"end": END, "next": "respond"})
    return "fetch_record", "respond"


BLUEPRINT = Blueprint(
    key=KEY,
    label="NVIDIA AI Virtual Assistant",
    description=(
        "NVIDIA's AI Virtual Assistant blueprint: a primary assistant routes each turn by "
        "tool call to a specialized assistant that uses retrieval over the theme's knowledge "
        "base and a structured record lookup, then a responder answers in the theme's contract. "
        "Session analytics (summary, sentiment) are served on demand from /api/analytics."
    ),
    workflow_name="pseudoco_nvidia_virtual_assistant",
    build_generation_core=build_generation_core,
    stage_labels={
        "fetch_record": "Looking up your record…",
        "ask_clarification": "Reviewing your message…",
        "primary_assistant": "Primary assistant routing…",
        "sub_assistant": "Specialized assistant working (knowledge + record lookup)…",
        "respond": "Composing your answer…",
    },
    core_nodes=("fetch_record", "ask_clarification", "primary_assistant", "sub_assistant", "respond"),
    multi_agent_note="ON = the primary assistant may hand the turn to two specialized assistants. OFF = one.",
)
