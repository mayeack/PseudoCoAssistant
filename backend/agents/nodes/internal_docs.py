"""Shared-chain node that searches the theme's internal document database when the
user explicitly asks for it, recording the search as a governed tool call.

One PRE node in the SHARED guardrail chain (blueprints/guardrails.py), so both
blueprints get it by construction (parity) with no core changes. It fires only
when the user message explicitly asks for the internal documents
(``internal_docs.docs_requested`` -- the shared phrasing plus the theme profile's
``trigger_terms``); nothing is parsed from model output. When it fires it:

1. asks the in-process internal-docs MCP server for the best-matching passages
   of the theme's collection (``backend/services/internal_docs.py``),
2. records the search as a governed tool call -- an ``execute_tool`` OTel span
   plus a ``tool_call`` governance event (``agent_surface="internal-docs"``) --
   the shape the EHR lookup and the scheduling booking use, and
3. stashes the passages on ``state["internal_docs"]``: the synthesizer appends
   ``context`` to its system prompt (RAG grounding), and the governance node
   carries ``hits`` on the chat event so the Agent Observability path can rebuild
   the search as a retriever span.

A search with no hits still records the tool call (the search happened) but
leaves no context. Never terminal, never blocks, and wrapped so a corpus fault can
never break a turn. Like ``ehr_lookup`` it has no SSE stage label, so it is
invisible in the chat UI.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from backend.agents.state import governance_identity_overrides
from backend.agents.themes import get_theme
from backend.logging.governance_logger import governance_logger
from backend.services import internal_docs
from backend.telemetry import otel

logger = logging.getLogger(__name__)


def internal_docs_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PRE node: on an explicit ask, search the internal documents and record the
    search as a governed tool call."""
    message = state.get("user_message", "") or ""
    profile = get_theme(state.get("theme")).docs
    if not profile.collection or not internal_docs.docs_requested(message, profile):
        return {}
    tool_name = internal_docs.TOOL_NAME
    call_id = internal_docs.new_call_id()
    try:
        # The span wraps the search itself, so its duration is the tool call's
        # wall time; a failed search ends it with an ERROR status (otel._span).
        with otel.tool_span(tool_name, tool_call_id=call_id, agent_surface=internal_docs.AGENT_SURFACE) as span:
            hits, facts = internal_docs.run_search(profile.collection, message, call_id=call_id)
            otel.record_tool_result(span, decision="allow")
    except Exception:  # noqa: BLE001 - a corpus or telemetry fault must never break a turn
        logger.exception("internal_docs: document search failed")
        return {}

    try:
        governance_logger.log_tool_call(
            session_id=state["session_id"],
            request_id=state["request_id"],
            tool_name=tool_name,
            tool_decision="allow",
            tool_call_id=call_id,
            tool_arguments=str(facts["arguments"]),
            agent_surface=internal_docs.AGENT_SURFACE,
            enduser_id=state.get("enduser_id"),
            # The turn's trace id, so the tool_call event joins the chat event's trace.
            trace_id=state.get("trace_id"),
            **governance_identity_overrides(state),
        )
    except Exception:  # noqa: BLE001 - logging must never break the turn
        logger.exception("internal_docs: tool_call governance logging failed")

    return {"internal_docs": {
        "tool_name": tool_name,
        "call_id": call_id,
        "collection": profile.collection,
        "query": facts["arguments"]["query"],
        "duration_ms": facts["duration_ms"],
        "hits": [{"doc_id": h.get("doc_id"), "kind": h.get("kind"), "title": h["title"],
                  "text": h["text"], "score": h["score"], "method": h["method"]} for h in hits],
        "context": internal_docs.format_context(hits),
    }}
