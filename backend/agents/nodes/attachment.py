"""Shared-chain node that reads the document attached to a chat turn, plus the
helpers that put its text in front of every prompt screen and the model
(docs/attachments.md).

``attachment_intake`` is PRE_NODES[0] in the SHARED guardrail chain
(blueprints/guardrails.py), ahead of ``policy``, so both blueprints get it by
construction (parity) and every prompt screen sees the document. It is
deterministic (no model). When the turn carries an attachment it:

1. extracts the PDF's text layer in a killable worker process
   (``backend/services/pdf_worker.py``) inside an ``execute_tool`` span,
2. records the read as a governed tool call -- the span plus a ``tool_call``
   governance event (``agent_surface="attachment-intake"``) -- the shape the EHR
   lookup and the internal-docs search use, and
3. leaves ``state["attachment_extraction"]`` (the capped text and its facts) and
   replaces ``state["attachment"]`` with a metadata-only copy, so the bytes go
   no further than this node.

Never terminal, never blocks: a failed read is recorded as ``status: "error"``
and the turn goes on with a note where the text would be.

The document text reaches two kinds of reader, and both get the SAME composed
text (:func:`screened_prompt`: the typed message, then the delimited document):

- the prompt-stage guardrails (policy, prompt_defense, agent_control_prompt,
  nemo_input_rails) screen :func:`screened_prompt`;
- the answering agent (the shared synthesizer) gets :func:`with_attachment`.

The internal agents (coordinator, specialists, the NVIDIA primary and
sub-assistants) get :func:`with_attachment_note` -- the document's name, never its
text -- so they neither ask for it nor see a payload. Every deterministic decision
(EHR lookup, internal docs, scheduling, PII exfiltration, safety, routing, the
response-stage guardrail context) keeps reading the typed ``user_message`` only:
the model is the thing a hidden instruction can fool, and no code path fakes it.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from backend.agents.state import governance_identity_overrides
from backend.logging.governance_logger import governance_logger
from backend.services import attachments
from backend.telemetry import otel

logger = logging.getLogger(__name__)


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def _span_attributes(extraction: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pseudoco-assistant.attachment.kind": extraction.get("kind"),
        "pseudoco-assistant.attachment.sha256": extraction.get("sha256"),
        "pseudoco-assistant.attachment.pages": extraction.get("pages"),
        "pseudoco-assistant.attachment.pages_read": extraction.get("pages_read"),
        "pseudoco-assistant.attachment.chars": extraction.get("chars"),
        "pseudoco-assistant.attachment.truncated": extraction.get("truncated"),
        "pseudoco-assistant.attachment.status": extraction.get("status"),
    }


def attachment_intake_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PRE node: read the attached document's text as a governed tool call."""
    att = state.get("attachment")
    if not isinstance(att, dict) or not att.get("data"):
        return {}
    started = time.perf_counter()
    call_id = attachments.new_call_id()
    try:
        # The span wraps the extraction itself, so its duration is the tool
        # call's wall time; a failed extraction ends it with an ERROR status
        # (otel._span) before the except below records the failure.
        with otel.tool_span(attachments.TOOL_NAME, tool_call_id=call_id,
                            agent_surface=attachments.AGENT_SURFACE) as span:
            extraction = attachments.extract_text(att, call_id=call_id)
            otel.set_span_attributes(span, _span_attributes(extraction))
            otel.record_tool_result(span, decision="allow")
    except Exception as exc:  # noqa: BLE001 - a hostile or broken file must never break a turn
        logger.exception("attachment_intake: text extraction failed")
        extraction = attachments.failed_extraction(att, call_id, exc, _elapsed_ms(started))

    try:
        governance_logger.log_tool_call(
            session_id=state["session_id"],
            request_id=state["request_id"],
            tool_name=attachments.TOOL_NAME,
            tool_decision="allow",
            tool_call_id=call_id,
            tool_arguments=str(attachments.message_metadata(att)),
            agent_surface=attachments.AGENT_SURFACE,
            enduser_id=state.get("enduser_id"),
            # The turn's trace id, so the tool_call event joins the chat event's trace.
            trace_id=state.get("trace_id"),
            **governance_identity_overrides(state),
        )
    except Exception:  # noqa: BLE001 - logging must never break the turn
        logger.exception("attachment_intake: tool_call governance logging failed")

    timings = dict(state.get("stage_timings") or {})
    timings["attachment_intake_ms"] = _elapsed_ms(started)
    return {
        "attachment": attachments.message_metadata(att),
        "attachment_extraction": extraction,
        "stage_timings": timings,
    }


# --------------------------------------------------------------------------- helpers
def screened_prompt(state: Dict[str, Any]) -> str:
    """The text the prompt-stage guardrails screen: exactly ``user_message``
    without an attachment; otherwise the typed message plus the document block
    (``attachments.compose_user_turn``) -- the same text the model gets."""
    extraction = state.get("attachment_extraction")
    if not extraction:
        return state.get("user_message", "")
    return attachments.compose_user_turn(state.get("user_message") or "", extraction)


def _role(message: Any) -> Any:
    role = message.get("role") if isinstance(message, dict) else None
    return role.value if hasattr(role, "value") else role


def _with_current_turn(messages: List[Dict[str, Any]], state: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
    """A new list whose current user turn reads ``content``.

    The current turn is the last user message when it is the typed
    ``user_message`` (production: the router's history ends with it, and so
    does the spray's); otherwise -- the parity tests pass a history without it
    -- a user turn is appended. The input list and its dicts are never mutated.
    """
    out = list(messages or [])
    typed = state.get("user_message") or ""
    for index in range(len(out) - 1, -1, -1):
        message = out[index]
        if _role(message) == "user":
            if message.get("content") == typed:
                out[index] = {**message, "content": content}
                return out
            break
    out.append({"role": "user", "content": content})
    return out


def with_attachment(messages: List[Dict[str, Any]], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The answering agent's messages with the current user turn replaced by
    :func:`screened_prompt` (so the model reads what the screens inspected).
    The input unchanged without an extraction; never mutated."""
    if not state.get("attachment_extraction"):
        return messages
    return _with_current_turn(messages, state, screened_prompt(state))


def attachment_note(state: Dict[str, Any]) -> str:
    """A metadata-only note for the internal agents ('' without an attachment):
    they learn a document exists and must not ask for it, but never see its
    text."""
    meta = state.get("attachment_extraction") or state.get("attachment")
    if not isinstance(meta, dict) or not meta:
        return ""
    label = attachments.kind_label(meta.get("kind"))
    pages = meta.get("pages")
    facts = f" ({attachments.pages_label(pages)})" if pages is not None else ""
    name = meta.get("name") or "document.pdf"
    if meta.get("status") in (None, "ok"):
        tail = "Its text is provided to the answering agent only; do not ask the user for it."
    else:
        tail = "Its text could not be read, and the answering agent has been told so; do not ask the user for it."
    return f"[The user attached a {label} '{name}'{facts}. {tail}]"


def with_attachment_note(messages: List[Dict[str, Any]], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """An internal agent's messages with :func:`attachment_note` appended to the
    current user turn (the last user message when it is the typed message, else
    a new user turn: typed message + note). The input unchanged without an
    attachment; never mutated."""
    note = attachment_note(state)
    if not note:
        return messages
    typed = state.get("user_message") or ""
    return _with_current_turn(messages, state, f"{typed}\n\n{note}" if typed.strip() else note)


def attachment_governance_fields(state: Dict[str, Any]) -> Dict[str, Any]:
    """``{"attachment": <metadata record>}`` to splat into a governance event,
    or ``{}`` -- never a ``None`` value (see governance_identity_overrides)."""
    record = attachments.governance_record(state.get("attachment_extraction"))
    return {"attachment": record} if record else {}


def block_banner_suffix(state: Dict[str, Any]) -> str:
    """The sentence a prompt-stage block banner appends when the turn carried a
    document ('' otherwise)."""
    return attachments.block_note(state.get("attachment_extraction"))
