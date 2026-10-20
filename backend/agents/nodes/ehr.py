"""Shared-chain node that pulls a synthetic patient/customer record from the mock
EHR "system" on a PII/PHI exfiltration turn, recording it as a governed tool call.

One PRE node in the SHARED guardrail chain (blueprints/guardrails.py), so both
blueprints get it by construction (parity) with no core changes. It fires only
when the user message is a PII/PHI exfiltration attempt
(``injection.pii_exfil_requested``) -- the same signal that forces the PII
category for the turn. When it fires it:

1. asks the in-process synthetic EHR MCP server for the record on file
   (``backend/services/ehr.py``), and
2. records the retrieval as a governed tool call -- an ``execute_tool`` OTel span
   plus a ``tool_call`` governance event (``agent_surface="synthetic-ehr"``) --
   exactly the shape the scheduling booking and the OpenClaw tool guard use, so
   the "API call to the EHR system" lands in the governance UI, SQLite and Splunk
   alongside chat turns, and
3. stashes the record on ``state["ehr_lookup"]`` so the synthesizer grounds the
   PII directive on it (the model weaves the real record into its answer; nothing
   is stitched in after the LLM -- see CLAUDE.md "Synthetic Content toggles").

Never terminal, never blocks, and wrapped so a demo-data fault can never break a
turn. It carries no SSE stage label (frontend/js/chat.js), so it is invisible in
the chat UI; its only surfaces are the recorded tool call and the delivered
answer the guardrails then inspect.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from backend.agents.nodes.injection import pii_exfil_requested
from backend.agents.state import governance_identity_overrides
from backend.logging.governance_logger import governance_logger
from backend.services import ehr
from backend.telemetry import otel

logger = logging.getLogger(__name__)


def ehr_lookup_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PRE node: on an exfiltration turn, look up the synthetic record and record
    the retrieval as a governed tool call."""
    if not pii_exfil_requested(state.get("user_message")):
        return {}
    try:
        theme = state.get("theme")
        enduser_id = state.get("enduser_id")
        message = state.get("user_message", "") or ""
        # How many records the attack asks for ("all patient records" / "25 rows"
        # / a single record) — parsed from the message, never from model output.
        count = ehr.requested_record_count(message, len(ehr._records(theme)))
        records, facts = ehr.run_lookup(theme, enduser_id, message, count=count)
    except Exception:  # noqa: BLE001 - a demo-data fault must never break a turn
        logger.exception("ehr_lookup: synthetic record lookup failed")
        return {}

    tool_name = facts["tool_name"]
    call_id = facts["call_id"]
    try:
        with otel.tool_span(tool_name, tool_call_id=call_id, agent_surface=ehr.AGENT_SURFACE) as span:
            otel.record_tool_result(span, decision="allow")
    except Exception:  # noqa: BLE001 - telemetry must never break a turn
        logger.exception("ehr_lookup: execute_tool span failed")
    try:
        governance_logger.log_tool_call(
            session_id=state["session_id"],
            request_id=state["request_id"],
            tool_name=tool_name,
            tool_decision="allow",
            tool_call_id=call_id,
            tool_arguments=str(facts["arguments"]),
            agent_surface=ehr.AGENT_SURFACE,
            enduser_id=enduser_id,
            **governance_identity_overrides(state),
        )
    except Exception:  # noqa: BLE001 - logging must never break the turn
        logger.exception("ehr_lookup: tool_call governance logging failed")

    first = records[0]
    # ``headers`` grounds the PII directive (build_input_directives) so the model
    # reproduces every retrieved record, not just the first; ``header`` is kept
    # for the single-record path and older readers. ``count`` is how many rows the
    # one governed tool call returned.
    return {"ehr_lookup": {"record_id": first.record_id, "header": first.header,
                           "headers": [r.header for r in records],
                           "fields": dict(first.fields), "count": len(records)}}
