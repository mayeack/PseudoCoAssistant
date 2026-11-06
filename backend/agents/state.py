"""Shared state model for the PseudoCo Assistant LangGraph workflow.

Maps to the workshop's "Shared State" concept (section 4.2): a single
``TypedDict`` threaded through every node, replacing the local variables that
used to live inside ``RecommendationEngine.process_message``.

Notes on conventions:
- ``total=False`` so nodes can return partial updates (LangGraph merges them).
- ``terminal``/``result`` implement the short-circuit paths (policy block,
  AI Defense block, clarifying question) that used to be early ``return``s.
- Correlation fields (``request_id``, ``trace_id``) are generated once and
  reused across governance logs *and* OTel spans so logs and traces line up in
  Splunk. ``trace_id`` is the OTel trace id of the turn (32 hex, as APM shows
  it), adopted when the workflow span opens (``graph._adopt_otel_trace_id``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, TypedDict


class PseudoCoAssistantState(TypedDict, total=False):
    # ---- Inputs (set by the router from the inbound request) ----
    session_id: str
    user_message: str
    conversation_history: List[Dict[str, Any]]
    theme: str
    client_address: Optional[str]
    enduser_id: Optional[str]
    force_pii_injection: Optional[bool]
    force_toxic_injection: Optional[bool]
    force_hallucination_injection: Optional[bool]
    force_boundary_injection: Optional[bool]
    ai_defense_review: Optional[bool]
    internal_policy_review: Optional[bool]
    multi_agent_mode: Optional[bool]
    agent_control_review: Optional[bool]
    nemo_guardrails_review: Optional[bool]
    # Per-turn governance identity overrides. Unset on ordinary chat (the
    # governance log then falls back to its own "pseudoco-assistant" defaults); the
    # prompt-injection spray campaign sets them so one process can emit turns
    # tagged as several apps/deployments. Never forward these as ``None`` —
    # see the note in ``backend/logging/log_schemas.py``.
    service_name: Optional[str]
    deployment_id: Optional[str]
    # ---- Appointment scheduling inputs (docs/scheduling.md) ----
    client_id: Optional[str]          # the browser's stable id: owner of its bookings (partition key)
    client_tz: Optional[str]          # IANA zone the slot labels are rendered in
    scheduling_action: Optional[Dict[str, Any]]  # structured chip action; wins over typed intent

    # ---- Verified identity (Lab 5) ----
    # ``identity_session``: the turn's VERIFIED identity session
    # (``IdentitySnapshot.to_state()``: username, source, session_ref,
    # signed_in_at, expires_at), or None on an anonymous turn. It only ever
    # comes from ``request.state.identity`` (the identity middleware), never
    # from a request body or from ``enduser_id`` -- it is a run_turn /
    # build_initial_state parameter, deliberately NOT a ChatRequest field.
    # (``identity`` alone already means the service identity overrides below.)
    # ``identity_risk``: the Identity Risk Gate's verdict for the turn
    # (``identity_gate.decide``: verdict, reasons, check, duo_status,
    # trust_level, failing_checks, as_of), set by the shared-chain
    # ``identity_risk`` PRE node on a signed-in turn and unset otherwise. Every
    # later event of the turn carries it (``identity_turn_fields``). An
    # ``identity_session`` with ``override`` True is an Unblock me session:
    # the gate records the real verdict and lets the turn through.
    identity_session: Optional[Dict[str, Any]]
    identity_risk: Dict[str, Any]

    # ---- Correlation / timing (set by the router node) ----
    request_id: str
    trace_id: str
    start_time: float
    # Which agentic architecture serves this turn (backend/agents/blueprints):
    # its key, and the workflow_name governance + the OTel workflow span carry.
    blueprint: str
    workflow_name: str
    # Wall-clock per non-LLM stage (e.g. AI Defense inspections), reported in
    # the governance event's performance_data for latency triage. Keys are
    # ``{stage}_ms``. Per-agent LLM timing lives in agent_trace.duration_ms.
    stage_timings: Dict[str, float]
    system_prompt: str
    agent_name: str
    conversational: bool

    # ---- Governance directive decision (domain agent, one roll per turn) ----
    # Which test-content categories were requested for this turn (pii / toxic /
    # hallucination / authority). Set PRE-LLM so the input directive and the
    # post-LLM injection fallback agree on a single decision.
    requested_categories: Dict[str, bool]

    # ---- NVIDIA AI Virtual Assistant blueprint (blueprints/nvidia_virtual_assistant.py) ----
    # LangGraph only carries keys declared here: a node's undeclared return key
    # is silently dropped, so every blueprint's core keys must be listed.
    blueprint_record: Dict[str, Any]      # lookup_record: the session's synthetic record
    blueprint_route: Dict[str, Any]       # the primary assistant's tool call(s) + routing mode
    blueprint_tools: List[Dict[str, Any]] # tools the sub-assistants ran (retrieve_knowledge, lookup_record)

    # ---- Multi-agent stage (coordinator -> specialists -> synthesizer) ----
    # The coordinator picks 1-N specialists per query; the specialists node runs
    # each as its own themed agent; the synthesizer fuses their findings into the
    # final answer. ``agent_trace`` is the per-agent transcript (one entry per
    # coordinator/specialist/synthesizer call) used to rebuild the multi-agent
    # trace for Agent Observability. ``llm_*_tokens`` below are the SUM across all agents.
    selected_specialists: List[str]
    coordinator_plan: Dict[str, Any]
    specialist_outputs: List[Dict[str, Any]]
    agent_trace: List[Dict[str, Any]]

    # ---- Synthetic MCP tool-thrash (backend/services/mcp_thrash.py) ----
    # One record per redundant tool call the "MCP Tool Thrash" Demo Control ran
    # this turn (hidden from the user; rebuilt as tool spans on the Agent
    # Observability trace by backend/agent_observability.py). Produced entirely
    # by the shared chain (mcp_thrash launch/join nodes), not by a blueprint
    # core, so it is NOT part of CORE_STATE_CONTRACT. Empty / unset on an
    # ordinary turn.
    tool_thrash_trace: List[Dict[str, Any]]

    # ---- Synthetic EHR record lookup (backend/services/ehr.py) ----
    # Set by the shared-chain ``ehr_lookup`` PRE node on a PII/PHI exfiltration
    # turn: the synthetic record pulled from the mock EHR "system" (as a governed
    # tool call) plus its one-line header. The synthesizer grounds the PII
    # directive on ``header`` so the model reproduces THIS record rather than
    # inventing one. Produced by the shared chain, not a blueprint core, so (like
    # ``tool_thrash_trace``) it is NOT part of CORE_STATE_CONTRACT. Unset on an
    # ordinary turn.
    ehr_lookup: Dict[str, Any]

    # ---- Internal document search (backend/services/internal_docs.py) ----
    # Set by the shared-chain ``internal_docs`` PRE node when the user explicitly
    # asks for the theme's internal documents: the governed search's call facts,
    # the passages it returned (``hits``: doc_id, kind, title, text, score) and
    # the prompt block the synthesizer appends (``context``). Produced by the
    # shared chain, not a blueprint core, so (like ``ehr_lookup``) it is NOT part
    # of CORE_STATE_CONTRACT. Unset on an ordinary turn.
    internal_docs: Dict[str, Any]

    # ---- Chat attachment (docs/attachments.md) ----
    # ``attachment`` comes in from the request: the validated upload
    # (``attachments.validate_upload`` -- metadata plus the bytes, for this turn
    # only). The shared-chain ``attachment_intake`` PRE node reads it, replaces it
    # with a metadata-only copy (the bytes go no further) and sets
    # ``attachment_extraction``: the extracted text capped at
    # ``attachment_max_chars`` plus its facts (status, pages, chars, truncated,
    # sha256, call id). Produced by the shared chain, not a blueprint core, so
    # (like ``internal_docs``) it is NOT part of CORE_STATE_CONTRACT. Unset on an
    # ordinary turn.
    attachment: Optional[Dict[str, Any]]
    attachment_extraction: Dict[str, Any]

    # ---- LLM messages + raw model output (synthesizer; tokens summed) ----
    messages: List[Dict[str, Any]]
    recommendation: Dict[str, Any]
    llm_response_id: str
    llm_model: str
    llm_input_tokens: int
    llm_output_tokens: int
    # ``llm_output_tokens`` split by cache origin; the two always sum back to it
    # (backend/agents/token_usage.py). Summed across agents like the totals.
    llm_output_tokens_cached: int
    llm_output_tokens_uncached: int
    llm_stop_reason: str

    # ---- Derived assessment (domain agent) ----
    severity: Any  # SeverityLevel
    confidence: float
    final_message: str
    complete_display_text: str

    # ---- Safety / escalation (safety agent) ----
    should_escalate: bool
    escalation_reasons: List[str]

    # ---- Test-injection flags (injection agent) ----
    # ``*_injected`` = the category was requested this turn; ``*_detected`` = it is
    # present in the delivered response, which the governance flags read. They
    # diverge whenever the model declines the directive: there is deliberately no
    # canned fallback (see nodes/injection.py), so an event never claims content
    # the user never saw.
    pii_injected: bool
    pii_detected: bool
    pii_types: List[str]
    toxic_injected: bool
    toxic_detected: bool
    toxic_types: List[str]
    hallucination_injected: bool
    hallucination_types: List[str]
    hallucination_detected: bool
    boundary_injected: bool
    boundary_types: List[str]
    boundary_detected: bool

    # ---- Agent Control verdict (agent_control node) ----
    # The ``ControlVerdict`` for this turn when the request opted into the
    # "Agent Observability Controls" review — present for allowed turns too, so
    # the governance event can record an observe/steer match that did not block.
    agent_control: Any  # ControlVerdict
    # Prompt-stage verdict (agent_control_prompt node, PRE chain). Its own key:
    # governance reads both stages, and the response-stage verdict must not
    # overwrite what the prompt screen decided.
    agent_control_prompt: Any  # ControlVerdict

    # ---- NVIDIA NeMo Guardrails verdicts (nemo_input_rails / nemo_output_rails) ----
    # Present for allowed turns too (a fail-open error is recorded), so the
    # governance event can attribute a non-blocking rail outcome.
    nemo_guardrails_input: Any  # RailVerdict
    nemo_guardrails_output: Any  # RailVerdict

    # ---- Appointment scheduling (scheduling_intake PRE node / scheduling POST node) ----
    # docs/scheduling.md. The intake node resolves the turn's scheduling action,
    # the client's appointments and candidate slots; the POST node executes the
    # action / decides the offer and leaves the structured payload the router
    # returns as result["scheduling"] and persists as metadata.scheduling.
    scheduling_context: Dict[str, Any]
    scheduling_directive: str   # prompt tail for the domain agent (full in single-agent mode, hand-off in MA)
    scheduling: Dict[str, Any]

    # ---- Short-circuit + final result ----
    # ``terminal`` is set by any node that fully handled the turn (policy block,
    # AI Defense block, clarifying question). ``result`` is the
    # ChatResponse-shaped dict the router returns, identical in shape to the
    # legacy ``RecommendationEngine.process_message`` return value:
    #   {message, type, severity, escalated, [policy_blocked], metadata}
    terminal: bool
    result: Dict[str, Any]


def build_initial_state(
    *,
    session_id: str,
    user_message: str,
    conversation_history: List[Dict[str, Any]],
    theme: Optional[str] = "medadvice",
    client_address: Optional[str] = None,
    enduser_id: Optional[str] = None,
    force_pii_injection: Optional[bool] = None,
    force_toxic_injection: Optional[bool] = None,
    force_hallucination_injection: Optional[bool] = None,
    force_boundary_injection: Optional[bool] = None,
    ai_defense_review: Optional[bool] = None,
    internal_policy_review: Optional[bool] = None,
    multi_agent_mode: Optional[bool] = None,
    agent_control_review: Optional[bool] = None,
    nemo_guardrails_review: Optional[bool] = None,
    service_name: Optional[str] = None,
    deployment_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_tz: Optional[str] = None,
    scheduling_action: Optional[Dict[str, Any]] = None,
    attachment: Optional[Dict[str, Any]] = None,
    identity_session: Optional[Dict[str, Any]] = None,
) -> PseudoCoAssistantState:
    """Build the initial graph state from an inbound chat request.

    Mirrors the argument list of the legacy
    ``RecommendationEngine.process_message`` so the router integration is a
    drop-in replacement. A verified ``identity_session`` names the turn's end
    user: ``enduser_id`` becomes its username whatever the caller passed.
    """
    identity_session = verified_identity(identity_session)
    if identity_session:
        enduser_id = identity_session["username"]
    return PseudoCoAssistantState(
        session_id=session_id,
        user_message=user_message,
        conversation_history=conversation_history or [],
        theme=theme or "medadvice",
        client_address=client_address,
        enduser_id=enduser_id,
        identity_session=identity_session,
        force_pii_injection=force_pii_injection,
        force_toxic_injection=force_toxic_injection,
        force_hallucination_injection=force_hallucination_injection,
        force_boundary_injection=force_boundary_injection,
        ai_defense_review=ai_defense_review,
        internal_policy_review=internal_policy_review,
        multi_agent_mode=multi_agent_mode,
        agent_control_review=agent_control_review,
        nemo_guardrails_review=nemo_guardrails_review,
        service_name=service_name,
        deployment_id=deployment_id,
        client_id=client_id,
        client_tz=client_tz,
        scheduling_action=scheduling_action,
        attachment=attachment,
        terminal=False,
    )


def verified_identity(identity_session: Any) -> Optional[Dict[str, Any]]:
    """A copy of a turn's identity session when it names a user, else None.

    Accepts the dict form (``IdentitySnapshot.to_state()``) or anything with a
    ``to_state()`` (the snapshot itself). The username is stripped and
    lowercased the way the identity store stores it; ``override`` (Unblock me)
    is kept only when it is True."""
    if identity_session is not None and not isinstance(identity_session, Mapping):
        to_state = getattr(identity_session, "to_state", None)
        identity_session = to_state() if callable(to_state) else None
    if not isinstance(identity_session, Mapping):
        return None
    username = str(identity_session.get("username") or "").strip().lower()
    if not username:
        return None
    verified = {**dict(identity_session), "username": username,
                "source": str(identity_session.get("source") or "duo")}
    if verified.get("override") is not True:
        verified.pop("override", None)
    return verified


def identity_risk_fields(identity_risk: Any) -> Dict[str, Any]:
    """The Identity Risk Gate's verdict as flat governance fields (Lab 5):
    ``identity_risk`` ("allow" / "block", the REAL verdict, also under an
    override), ``identity_check`` ("ok" / "unavailable"), and, when known,
    ``identity_risk_reasons``, ``identity_duo_status``,
    ``identity_trust_level`` and ``identity_failing_checks``. ``{}`` without
    a verdict (an anonymous turn, or an event before the gate ran)."""
    if not isinstance(identity_risk, Mapping) or identity_risk.get("verdict") not in ("allow", "block"):
        return {}
    fields: Dict[str, Any] = {"identity_risk": identity_risk["verdict"],
                              "identity_check": identity_risk.get("check") or "unavailable"}
    for key, out in (("reasons", "identity_risk_reasons"), ("failing_checks", "identity_failing_checks")):
        values = identity_risk.get(key)
        if isinstance(values, (list, tuple)) and values:
            fields[out] = [str(v) for v in values]
    for key, out in (("duo_status", "identity_duo_status"), ("trust_level", "identity_trust_level")):
        if identity_risk.get(key):
            fields[out] = str(identity_risk[key])
    return fields


def identity_governance_fields(identity_session: Any, identity_risk: Any = None) -> Dict[str, Any]:
    """The identity evidence for one turn's governance events.

    Present only when the turn carries a verified identity session; an anonymous
    turn contributes no key at all, so Labs 0-4 events are unchanged. Fresh
    names, never ``enduser_id``: every emit site already passes that one, so a
    second ``enduser_id`` would be a duplicate keyword. ``identity_verified`` /
    ``identity_source`` always; ``identity_override`` True on an Unblock me
    session; the gate's verdict (``identity_risk_fields``) once it is known."""
    verified = verified_identity(identity_session)
    if not verified:
        return {}
    fields: Dict[str, Any] = {"identity_verified": True, "identity_source": verified["source"]}
    if verified.get("override") is True:
        fields["identity_override"] = True
    fields.update(identity_risk_fields(identity_risk))
    return fields


def identity_turn_fields(state: Mapping[str, Any]) -> Dict[str, Any]:
    """``identity_governance_fields`` for a turn's state: its identity session
    plus the gate's verdict once the ``identity_risk`` node has run."""
    return identity_governance_fields(state.get("identity_session"), state.get("identity_risk"))


def governance_identity_overrides(state: Dict[str, Any]) -> Dict[str, Any]:
    """Per-turn governance identity kwargs, omitting anything unset.

    ``create_governance_log`` resolves these with ``kwargs.get(key, default)``,
    so a key that is *present but None* erases the default instead of falling
    back to it — which would blank ``app_name`` on ordinary chat turns. Callers
    splat this dict so unset overrides contribute no key at all.
    """
    overrides: Dict[str, Any] = {}
    # workflow_name / blueprint: which architecture served the turn. Carried by
    # EVERY governance event of the turn — blocked ones included — so a block is
    # attributable to the blueprint it happened under (parity contract).
    for key in ("service_name", "deployment_id", "workflow_name", "blueprint"):
        value = state.get(key)
        if value:
            overrides[key] = value
    # The verified end user (Lab 5): identity_verified / identity_source, the
    # override and, once the gate has run, its verdict ride on every event of a
    # signed-in turn, blocked ones included, through this same splat. Nothing
    # on an anonymous turn.
    overrides.update(identity_turn_fields(state))
    return overrides
