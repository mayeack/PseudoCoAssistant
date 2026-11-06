"""The Identity Risk Gate node (``identity_risk``, Lab 5; docs/identity.md).

``PRE_NODES[1]`` in the SHARED guardrail chain (blueprints/guardrails.py):
after ``attachment_intake`` (which has already reduced the document to
metadata) and before ``policy``, so a compromised identity is refused before
any screen or model runs, in both blueprints by construction. The legacy
engine calls ``identity_gate_turn`` before its own policy check (parity).

- **No identity session** (an anonymous turn, the spray's actor): ``{}``
  before any span, log or lookup. Labs 0-4 are unchanged.
- **Signed in:** ``identity_lookup.lookup`` (Duo status, CII trust level and
  failing checks; cached, bounded, never raises), then the pure
  ``identity_gate.decide``. The verdict goes on the state (``identity_risk``),
  so every later event of the turn carries it.
- **Block:** one ``log_response`` in the shape of policy.py's: guardrail id
  ``cisco_identity_intelligence``, ``policy_blocked``, zero usage, the theme
  (so the block reaches the theme's Agent stream), the turn's identity and
  attachment metadata, and the TYPED message only -- the gate screens no text,
  so no document text rides on the event and the banner never says the
  document was screened. ``safety_categories=["compromised_identity"]``,
  severity HIGH (never EMERGENCY), no escalation event, never "injection".
- **Fail open (A3):** an unavailable lookup allows the turn with
  ``identity_check="unavailable"``; with ``IDENTITY_FAIL_OPEN`` off it is
  blocked, and that block is neutral (nothing is known against the identity:
  ``identity_gate.unverified_only``): ``safety_categories=["identity_unverified"]``,
  severity MEDIUM and the IDENTITY NOT VERIFIED "could not be verified"
  banner, never the compromised-identity block above.
- **Unblock me:** a session with ``override`` True gets the real verdict
  recorded (``identity_risk``, plus ``identity_override`` on every event) and
  the turn goes on.
- **No side effects:** the gate never revokes a session and never writes to
  Duo or CII. Revocation follows Duo status, in the identity middleware.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from backend.agents.nodes.attachment import attachment_governance_fields
from backend.agents.state import governance_identity_overrides, identity_risk_fields, verified_identity
from backend.agents.token_usage import governance_usage_data
from backend.config import settings
from backend.logging.governance_logger import active_response_model, governance_logger
from backend.models.schemas import MessageType, SeverityLevel
from backend.services import identity_gate, identity_lookup
from backend.services.recommendation_engine import block_banner
from backend.telemetry import otel

logger = logging.getLogger(__name__)

GUARDRAIL_ID = "cisco_identity_intelligence"
AGENT_NAME = "identity_risk_agent"
SAFETY_CATEGORY = "compromised_identity"
UNVERIFIED_CATEGORY = "identity_unverified"
BANNER = "POLICY BLOCKED (Cisco Identity Intelligence)"
UNVERIFIED_BANNER = "IDENTITY NOT VERIFIED (Cisco Identity Intelligence)"


def evaluate(identity_session: Mapping[str, Any]) -> Dict[str, Any]:
    """The verdict for one verified identity session. Never raises: a failure
    here is an unavailable lookup, decided under IDENTITY_FAIL_OPEN."""
    fail_open = bool(getattr(settings, "identity_fail_open", True))
    try:
        status = identity_lookup.lookup(identity_session.get("username"))
    except Exception:  # noqa: BLE001 - lookup never raises; belt and braces
        logger.exception("identity lookup failed")
        status = {"available": False, "sources": {}}
    return identity_gate.decide(status, fail_open=fail_open)


def block_message(verdict: Mapping[str, Any], theme: Optional[str]) -> str:
    """The banner text for a gate block (theme's urgent-help line last)."""
    if identity_gate.unverified_only(verdict):
        body = ("Your signed-in identity could not be verified right now, so your message was not "
                "processed. Please try again in a moment.")
    else:
        body = (f"Your message was not processed: Cisco Identity Intelligence reports a risk on your "
                f"signed-in identity ({identity_gate.reasons_text(verdict)}). Messages from this "
                f"identity are refused until the risk is cleared.")
    return block_banner(body, theme)


def log_identity_block(
    *,
    verdict: Mapping[str, Any],
    session_id: str,
    request_id: str,
    trace_id: Optional[str],
    user_message: str,
    start_time: float,
    theme: Optional[str],
    client_address: Optional[str],
    enduser_id: Optional[str],
    governance_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Log the block and return the turn's result (shared by the node and the
    legacy engine). ``governance_fields`` are the turn's identity / blueprint /
    attachment fields; the verdict's fields are added here."""
    unverified = identity_gate.unverified_only(verdict)
    message = block_message(verdict, theme)
    severity = SeverityLevel.MEDIUM if unverified else SeverityLevel.HIGH
    reasons = [identity_gate.REASON_TEXT.get(r, r) for r in verdict.get("reasons") or []]
    fields = {**(governance_fields or {}), **identity_risk_fields(verdict)}
    governance_logger.log_response(
        session_id=session_id,
        request_id=request_id,
        response_id="identity-blocked",
        operation_name="chat",
        # The typed message only: the gate screens no text.
        input_messages=[{"role": "user", "content": user_message}],
        output_messages=[{"role": "assistant", "content": message}],
        response_text=f"⚠️ {UNVERIFIED_BANNER if unverified else BANNER}\n{message}",
        usage_data=governance_usage_data(),
        performance_data={"client_operation_duration": time.time() - start_time},
        response_model=active_response_model(),
        response_finish_reasons=["policy_blocked"],
        safety_violated=True,
        safety_categories=[UNVERIFIED_CATEGORY if unverified else SAFETY_CATEGORY],
        guardrail_triggered=True,
        guardrail_ids=[GUARDRAIL_ID],
        policy_blocked=True,
        pii_detected=False,
        pii_types=[],
        toxic_detected=False,
        toxic_types=[],
        evaluation_score_value=1.0,
        evaluation_score_label="high",
        severity=severity.value,
        theme=theme,
        agent_name=AGENT_NAME,
        trace_id=trace_id,
        client_address=client_address,
        enduser_id=enduser_id,
        **fields,
    )
    return {
        "message": message,
        "type": MessageType.SAFETY_WARNING,
        "severity": severity,
        "escalated": False,
        "policy_blocked": True,
        "metadata": {
            "confidence": 1.0,
            "escalation_reasons": reasons,
            "identity_risk": {k: verdict.get(k) for k in ("verdict", "reasons", "check")},
        },
    }


def identity_gate_turn(
    *,
    identity_session: Any,
    session_id: str,
    request_id: str,
    trace_id: Optional[str],
    user_message: str,
    start_time: float,
    theme: Optional[str],
    client_address: Optional[str],
    enduser_id: Optional[str],
    governance_fields: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """``(verdict, blocked result)`` for one turn: ``(None, None)`` without a
    verified identity session (nothing looked up or logged), ``(verdict,
    None)`` when the turn goes on (allowed, or overridden by Unblock me)."""
    session = verified_identity(identity_session)
    if not session:
        return None, None
    verdict = evaluate(session)
    if verdict["verdict"] != identity_gate.BLOCK or session.get("override") is True:
        return verdict, None
    with otel.agent_span(AGENT_NAME, theme=theme):
        result = log_identity_block(
            verdict=verdict, session_id=session_id, request_id=request_id, trace_id=trace_id,
            user_message=user_message, start_time=start_time, theme=theme,
            client_address=client_address, enduser_id=enduser_id, governance_fields=governance_fields)
    return verdict, result


def identity_risk_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PRE node: the Identity Risk Gate (see the module docstring)."""
    if not verified_identity(state.get("identity_session")):
        return {}
    started = time.perf_counter()
    verdict, result = identity_gate_turn(
        identity_session=state.get("identity_session"),
        session_id=state["session_id"],
        request_id=state["request_id"],
        trace_id=state.get("trace_id"),
        user_message=state.get("user_message") or "",
        start_time=state["start_time"],
        theme=state.get("theme"),
        client_address=state.get("client_address"),
        enduser_id=state.get("enduser_id"),
        governance_fields={**governance_identity_overrides(state), **attachment_governance_fields(state)},
    )
    timings = dict(state.get("stage_timings") or {})
    timings["identity_risk_ms"] = round((time.perf_counter() - started) * 1000, 1)
    update: Dict[str, Any] = {"identity_risk": verdict, "stage_timings": timings}
    if result is not None:
        update.update(terminal=True, result=result)
    return update
