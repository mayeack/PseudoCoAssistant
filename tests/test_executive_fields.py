"""Regression tests for the executive AI-governance field overlay.

Asserts the board-level normalized fields (risk_score, policy_action,
business_outcome, estimated_cost, contains_phi, audit_status, ...) that power
the Splunk "Executive AI Governance Overview" dashboard (workshop Section 0).

Standalone (no pytest required), mirroring tests/test_api.py:
    venv/bin/python tests/test_executive_fields.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.config  # noqa: F401  (sets SSL_CERT_FILE / loads .env)
from backend.logging.executive_fields import derive_executive_fields
from backend.logging.log_schemas import create_governance_log

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def _base(**over):
    """A minimal governance output event, overridable per scenario."""
    log = {
        "operation_name": "chat",
        "token_type": "output",
        "service_name": "pseudoco-assistant",
        "request_model": "claude-sonnet-4-5-20250929",
        "response_model": "claude-sonnet-4-5-20250929",
        "session_id": "S1",
        "request_id": "R1",
        "trace_id": "T1",
        "response_id": "resp-1",
        "usage_input_tokens": 663,
        "usage_output_tokens": 410,
        "usage_total_tokens": 1073,
        "client_operation_duration": 2.5,
        "evaluation_score_value": 0.92,
        "theme": "medadvice",
        "agent_name": "medadvice_domain_agent",
    }
    log.update(over)
    return log


# 1. Clean advice -------------------------------------------------------------
f = derive_executive_fields(_base())
check("clean: policy_action=allow", f["policy_action"] == "allow", f["policy_action"])
check("clean: business_outcome=advice_delivered", f["business_outcome"] == "advice_delivered")
check("clean: user_type=patient", f["user_type"] == "patient")
check("clean: app_name mapped from service_name", f["app_name"] == "pseudoco-assistant")
check("clean: latency_ms from duration", f["latency_ms"] == 2500.0, f["latency_ms"])
check("clean: token_count", f["token_count"] == 1073)
check("clean: low risk", f["risk_score"] < 25, f["risk_score"])
check("clean: audit complete", f["audit_status"] == "complete", f["audit_status"])
check("clean: estimated_cost computed", f["estimated_cost"] and f["estimated_cost"] > 0)
# Sonnet pricing: 663*3 + 410*15 = 1989 + 6150 = 8139 / 1e6 = 0.008139
check("clean: cost math", abs(f["estimated_cost"] - 0.008139) < 1e-6, str(f["estimated_cost"]))

# 2. Emergency escalation -----------------------------------------------------
f = derive_executive_fields(_base(
    severity="EMERGENCY", safety_violated=True, guardrail_triggered=True,
    guardrail_ids=["escalation_rules"], safety_categories=["Emergency symptoms detected"],
))
check("emergency: human_escalation", f["human_escalation"] is True)
check("emergency: outcome escalated", f["business_outcome"] == "escalated_to_human")
check("emergency: prompt_category", f["prompt_category"] == "emergency_symptom", f["prompt_category"])
check("emergency: policy_action=warn", f["policy_action"] == "warn")
check("emergency: high risk", f["risk_score"] >= 60, f["risk_score"])

# 3. Internal policy block (self-harm) ---------------------------------------
f = derive_executive_fields(_base(
    severity="EMERGENCY", policy_blocked=True, safety_violated=True,
    guardrail_triggered=True, guardrail_ids=["policy_block"],
    response_finish_reasons=["policy_blocked"],
))
check("policyblock: action=block", f["policy_action"] == "block")
check("policyblock: outcome", f["business_outcome"] == "blocked_unsafe", f["business_outcome"])
check("policyblock: category self_harm", f["prompt_category"] == "self_harm_crisis", f["prompt_category"])
check("policyblock: very high risk", f["risk_score"] >= 90, f["risk_score"])
check("policyblock: policy_name set", "Self-harm" in (f["policy_name"] or ""), f["policy_name"])

# 4. Cisco AI Defense block ---------------------------------------------------
f = derive_executive_fields(_base(
    policy_blocked=True, guardrail_triggered=True, guardrail_ids=["cisco_ai_defense"],
    safety_categories=["classifications: PRIVACY_VIOLATION, SECURITY_VIOLATION"],
    response_finish_reasons=["policy_blocked"],
))
check("aidefense: action=block", f["policy_action"] == "block")
check("aidefense: outcome blocked_by_ai_defense", f["business_outcome"] == "blocked_by_ai_defense", f["business_outcome"])
check("aidefense: policy_name carries classification",
      "PRIVACY_VIOLATION" in (f["policy_name"] or ""), f["policy_name"])

# 5. PHI exposure (medical theme) --------------------------------------------
f = derive_executive_fields(_base(pii_detected=True, pii_types=["ssn", "diagnosis"]))
check("phi: contains_pii", f["contains_pii"] is True)
check("phi: contains_phi (medical theme)", f["contains_phi"] is True)
check("phi: category phi_pii_exposure", f["prompt_category"] == "phi_pii_exposure")

# 6. PII on a non-medical theme is not PHI unless type matches ---------------
f = derive_executive_fields(_base(theme="telecomchatbot", pii_detected=True, pii_types=["email"]))
check("nonmedical: contains_pii", f["contains_pii"] is True)
check("nonmedical: not phi", f["contains_phi"] is False)
check("nonmedical: user_type=customer", f["user_type"] == "customer")

# 7. Hallucination signal raises risk ----------------------------------------
clean_risk = derive_executive_fields(_base())["risk_score"]
f = derive_executive_fields(_base(hallucination_detected=True,
                                  hallucination_types=["fabricated_fact"]))
check("halluc: raises risk", f["risk_score"] > clean_risk, f"{f['risk_score']} vs {clean_risk}")

# 8. Partial audit when usage missing ----------------------------------------
f = derive_executive_fields(_base(usage_total_tokens=None, evaluation_score_value=None))
check("audit: partial when evidence missing", f["audit_status"] == "partial", f["audit_status"])

# 9. End-to-end through create_governance_log --------------------------------
log = create_governance_log(
    operation_name="chat", request_model="claude-sonnet-4-5-20250929",
    conversation_id="S1", session_id="S1", input_messages=[],
    usage_total_tokens=1000, usage_input_tokens=600, usage_output_tokens=400,
    client_operation_duration=1.0, evaluation_score_value=0.9,
    response_id="r", trace_id="t", service_name="pseudoco-assistant",
    theme="medadvice", severity="LOW", token_type="output",
)
check("e2e: overlay present in create_governance_log", "risk_score" in log and "business_outcome" in log)
check("e2e: existing fields untouched", log["request_model"] == "claude-sonnet-4-5-20250929")

# 9b. Additive latency-triage fields (2026-07 latency remediation): per-stage
# wall-clock passes through performance_data ({stage}_ms) and agent_trace
# entries carry duration_ms — both additive, existing fields never renamed.
from backend.agents.nodes.agent_common import trace_entry  # noqa: E402

log_t = create_governance_log(
    operation_name="chat", request_model="m", conversation_id="S1", session_id="S1",
    input_messages=[], token_type="output",
    client_operation_duration=1.0,
    stage_timings={"response_defense_ms": 42.0},
    agent_trace=[trace_entry(name="a", role="coordinator", duration_ms=123.4)],
)
check("perf: stage_timings ({stage}_ms) pass through to the event",
      (log_t.get("stage_timings") or {}).get("response_defense_ms") == 42.0,
      str(log_t.get("stage_timings")))
check("perf: client_operation_duration still present alongside stage timings",
      log_t.get("client_operation_duration") == 1.0)
check("perf: agent_trace entry carries duration_ms",
      log_t["agent_trace"][0].get("duration_ms") == 123.4,
      str(log_t["agent_trace"][0]))
check("perf: trace_entry keeps the pre-existing field set (additive contract)",
      {"name", "role", "model", "input_tokens", "output_tokens", "output_text",
       "status"} <= set(log_t["agent_trace"][0].keys()))

# 9c. Agentic tool-call event (OpenClaw tool guard) --------------------------
# A blocked exfiltration attempt: operation_name=="tool_call" must map to the
# tool_exploitation category, a blocked_tool_call outcome, and stacked risk.
tc = create_governance_log(
    operation_name="tool_call", request_model="llama3.2:3b",
    conversation_id="S9", session_id="S9", input_messages=[], token_type="tool_call",
    request_id="R9", trace_id="T9", tool_call_id="call-9",
    tool_name="web_fetch", tool_decision="block",
    tool_denied_reason="unapproved egress host: evil.example",
    agent_surface="openclaw", policy_blocked=True, guardrail_triggered=True,
    guardrail_ids=["openclaw_tool_guard"], theme="medadvice",
)
check("toolcall: category tool_exploitation", tc["prompt_category"] == "tool_exploitation", tc["prompt_category"])
check("toolcall: action=block", tc["policy_action"] == "block", tc["policy_action"])
check("toolcall: outcome blocked_tool_call", tc["business_outcome"] == "blocked_tool_call", tc["business_outcome"])
check("toolcall: tool_name surfaced", tc["tool_name"] == "web_fetch", tc.get("tool_name"))
check("toolcall: audit complete on id chain (no tokens)", tc["audit_status"] == "complete", tc["audit_status"])
# policy_blocked (30) + tool_call escalation (20) puts this well above a chat block.
check("toolcall: risk stacked above chat block", tc["risk_score"] >= 55, tc["risk_score"])

# 9d. Unenforced tool-call (control run) still categorizes honestly ----------
tc_allow = create_governance_log(
    operation_name="tool_call", request_model="llama3.2:3b",
    conversation_id="S10", session_id="S10", input_messages=[], token_type="tool_call",
    request_id="R10", trace_id="T10", tool_call_id="call-10",
    tool_name="read", tool_decision="allow", agent_surface="openclaw",
)
check("toolcall-allow: category still tool_exploitation", tc_allow["prompt_category"] == "tool_exploitation")
check("toolcall-allow: action=allow", tc_allow["policy_action"] == "allow", tc_allow["policy_action"])

# 9e. CIM identity: user / src / app -----------------------------------------
# ES and its Triage agent pivot on CIM user/src/app; without them the actor was
# reachable only through gen_ai.user.id and the Triage agent found no evidence.
from backend.logging.log_schemas import create_audit_log, create_escalation_log  # noqa: E402

cim = create_governance_log(
    operation_name="chat", request_model="m", conversation_id="S11", session_id="S11",
    input_messages=[], token_type="output", request_id="R11", trace_id="T11",
    enduser_id="t.nguyen", client_address="10.72.14.37",
    service_name="pseudoco-assistant-medadvice", policy_blocked=True,
)
check("cim: user is the enduser_id", cim.get("user") == "t.nguyen", str(cim.get("user")))
check("cim: src is the client_address", cim.get("src") == "10.72.14.37", str(cim.get("src")))
check("cim: app is the governed app (app_name)",
      cim.get("app") == cim.get("app_name") == "pseudoco-assistant-medadvice", str(cim.get("app")))
check("cim: native identity fields keep their names and values",
      cim.get("enduser_id") == "t.nguyen" and cim.get("client_address") == "10.72.14.37")
anon = create_governance_log(
    operation_name="chat", request_model="m", conversation_id="S12", session_id="S12",
    input_messages=[], token_type="output",
)
check("cim: no actor/source -> no user/src key (no empty values)",
      "user" not in anon and "src" not in anon, str({k: anon.get(k) for k in ("user", "src")}))
check("cim: app falls back to the default service name", anon.get("app") == "pseudoco-assistant",
      str(anon.get("app")))
esc = create_escalation_log("E1", "S13", "R13", "reason", "HIGH", [], [], enduser_id="t.nguyen")
check("cim: escalation event carries user", esc.get("user") == "t.nguyen", str(esc.get("user")))
aud = create_audit_log("A1", "S14", "R14", "session_started", "user", {},
                       enduser_id="t.nguyen", ip_address="10.72.14.37")
check("cim: audit event carries user + src",
      aud.get("user") == "t.nguyen" and aud.get("src") == "10.72.14.37", str(aud))

# 9f. input_modality (docs/attachments.md) ------------------------------------
# What the user sent on a chat turn: "text", or "text+pdf" when the turn carried
# a document (the metadata-only ``attachment`` record every chat event of a
# document turn carries, blocked ones too). Additive; absent on non-chat events.
_att = {"tool_name": "attachment-intake.extract_text", "call_id": "att-0123456789ab", "kind": "pdf",
        "name": "lab-results-summary.pdf", "mime": "application/pdf", "bytes": 2048, "sha256": "ab" * 32,
        "pages": 1, "pages_read": 1, "chars": 640, "truncated": False, "status": "ok", "duration_ms": 41.0}
check("modality: a plain chat turn is text", derive_executive_fields(_base())["input_modality"] == "text")
check("modality: a chat turn with a PDF attachment is text+pdf",
      derive_executive_fields(_base(attachment=_att))["input_modality"] == "text+pdf")
check("modality: an empty attachment record is still text",
      derive_executive_fields(_base(attachment={}))["input_modality"] == "text")
check("modality: non-chat events carry no modality",
      derive_executive_fields(_base(operation_name="tool_call"))["input_modality"] is None
      and derive_executive_fields(_base(operation_name="error"))["input_modality"] is None)
doc = create_governance_log(
    operation_name="chat", request_model="m", conversation_id="S15", session_id="S15",
    input_messages=[{"role": "user", "content": "Summarize this.\n\n[Attached document: lab-results-summary.pdf "
                                                "(1 page, PDF)]\n...\n[End of attached document]"}],
    token_type="output", request_id="R15", trace_id="T15", attachment=_att, policy_blocked=True,
    guardrail_ids=["cisco_ai_defense"],
)
check("modality: create_governance_log passes the attachment record through and derives text+pdf",
      doc.get("attachment") == _att and doc.get("input_modality") == "text+pdf",
      str({k: doc.get(k) for k in ("attachment", "input_modality")}))
check("modality: a document turn's block keeps its block outcome",
      doc.get("business_outcome") == "blocked_by_ai_defense", str(doc.get("business_outcome")))
check("modality: a chat event without a document has no attachment key and reads text",
      "attachment" not in anon and anon.get("input_modality") == "text", str(anon.get("input_modality")))
check("modality: a tool_call event has no input_modality key",
      "input_modality" not in tc and "input_modality" not in tc_allow)

# 9b. Lab 5: the Identity Risk Gate's block (backend/agents/nodes/identity.py) --
ident = derive_executive_fields(_base(
    policy_blocked=True, guardrail_triggered=True, safety_violated=True, severity="HIGH",
    guardrail_ids=["cisco_identity_intelligence"], safety_categories=["compromised_identity"],
    usage_input_tokens=0, usage_output_tokens=0, usage_total_tokens=0))
check("identity gate: policy name and business outcome",
      ident["policy_name"] == "Cisco Identity Intelligence identity risk"
      and ident["business_outcome"] == "blocked_compromised_identity" and ident["policy_action"] == "block",
      str({k: ident.get(k) for k in ("policy_name", "business_outcome", "policy_action")}))
check("identity gate: its own prompt category (never self-harm, emergency or prompt injection)",
      ident["prompt_category"] == "compromised_identity", str(ident["prompt_category"]))
unverified = derive_executive_fields(_base(
    policy_blocked=True, guardrail_triggered=True, severity="MEDIUM",
    guardrail_ids=["cisco_identity_intelligence"], safety_categories=["identity_unverified"]))
# A fail-closed block (IDENTITY_FAIL_OPEN off, Duo or CII unreachable) knows
# nothing against the identity: during an outage it would otherwise count every
# signed-in user as a compromised identity.
check("identity gate: a fail-closed 'could not be verified' block is neutral, never a compromised identity",
      unverified["prompt_category"] == "identity_unverified"
      and unverified["business_outcome"] == "blocked_identity_unverified"
      and unverified["policy_name"] == "Cisco Identity Intelligence identity verification"
      and unverified["policy_action"] == "block",
      str({k: unverified.get(k) for k in ("prompt_category", "business_outcome", "policy_name")}))
both = derive_executive_fields(_base(
    policy_blocked=True, guardrail_triggered=True, severity="HIGH",
    guardrail_ids=["cisco_identity_intelligence"], safety_categories=["compromised_identity", "identity_unverified"]))
check("identity gate: a block with a real reason stays a compromised identity",
      both["prompt_category"] == "compromised_identity" and both["business_outcome"] == "blocked_compromised_identity")
built = create_governance_log(
    operation_name="chat", request_model="m", conversation_id="S16", session_id="S16", input_messages=[],
    token_type="output", request_id="R16", trace_id="T16", enduser_id="nina.osei", identity_verified=True,
    identity_source="duo", identity_override=True, identity_risk="block", identity_check="ok",
    identity_risk_reasons=["mfa_flood"], identity_duo_status="active", identity_trust_level="UNTRUSTED",
    identity_failing_checks=["MFA Flood"])
check("identity gate: create_governance_log keeps every identity field (explicit dict, nothing dropped)",
      all(built.get(k) is not None for k in ("identity_override", "identity_risk", "identity_check",
                                               "identity_risk_reasons", "identity_duo_status",
                                               "identity_trust_level", "identity_failing_checks")),
      str({k: v for k, v in built.items() if k.startswith("identity")}))
plain = create_governance_log(operation_name="chat", request_model="m", conversation_id="S17", session_id="S17",
                              input_messages=[], token_type="output", request_id="R17", trace_id="T17")
check("identity gate: an anonymous event has no identity key at all",
      not any(k.startswith("identity") for k in plain), str([k for k in plain if k.startswith("identity")]))

# 10. Never raises on garbage -------------------------------------------------
check("robust: empty dict -> dict", isinstance(derive_executive_fields({}), dict))
check("robust: junk types -> dict",
      isinstance(derive_executive_fields({"usage_total_tokens": "x", "guardrail_ids": 5}), dict))

print()
if _failures:
    print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
    sys.exit(1)
print("All executive-field regression checks passed.")
