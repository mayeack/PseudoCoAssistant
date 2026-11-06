import logging
import json
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from sqlalchemy.orm import Session

from backend.config import settings
from backend.logging.log_handlers import GovernanceFileHandler
from backend.logging.log_schemas import create_governance_log, create_escalation_log, create_audit_log
from backend.models.db_models import AIGovernanceLog, EscalationQueue, AuditLog
from backend.database.db import get_db_context
from backend.hec.runtime import hec_runtime

logger = logging.getLogger("governance")

# Last Agent Observability submit failure already warned about, so a permanent
# fault warns once instead of once per chat turn (see _write_log).
_ao_submit_warned = ""


def _emit_model(model: str) -> str:
    """Apply the demo model-name override (backend/model_emitter.py). Defensive:
    logging must never break a chat turn."""
    try:
        from backend.model_emitter import model_emitter
        return model_emitter.emit(model)
    except Exception:
        return model


def _active_provider_info():
    """Return (provider_name, model) for the currently configured AI provider.

    The model is passed through the demo model-name override, so governance logs
    report the emitted (static/random) model when that setting is on."""
    provider = settings.ai_provider
    if provider == "bedrock":
        name, model = provider, settings.bedrock_model_id
    elif provider == "openai":
        name, model = provider, settings.openai_model
    elif provider == "nvidia":
        name, model = provider, settings.nvidia_model
    elif provider == "ollama":
        name, model = provider, settings.ollama_model
    else:
        name, model = "anthropic", settings.anthropic_model
    return name, _emit_model(model)


def active_response_model() -> str:
    """Model id to report as ``response_model`` when no real model reply exists.

    Blocked turns (policy pre-block, AI Defense prompt block) never reach the
    provider, so there is no ``response.model`` to echo. Reporting the *active*
    provider's configured model keeps the event internally consistent with the
    ``provider_name``/``request_model`` fields, which come from the same helper."""
    return _active_provider_info()[1]


class GovernanceLogger:
    """Centralized AI governance logging with multi-destination support"""

    def __init__(self):
        self.file_handler = GovernanceFileHandler()
        self.console_logging = settings.log_to_console
        self.file_logging = settings.log_to_file
        self.db_logging = settings.log_to_database

    def set_logs_directory(self, path: str):
        """Re-point governance file logging at a new directory (runtime)."""
        try:
            self.file_handler.repoint(path)
        except Exception:
            logger.exception("failed to repoint governance logs to %s", path)

    def log_request(
        self,
        session_id: str,
        request_id: str,
        operation_name: str,
        input_messages: List[Dict[str, Any]],
        request_params: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log AI request (console only -- output events contain input_messages
        so input events are not written to the governance JSON file or DB)."""
        user_prompt = kwargs.pop("user_prompt", None)

        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name=operation_name,
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            input_messages=input_messages,
            token_type="input",
            provider_name=_provider_name,
            **(request_params or {}),
            **kwargs
        )

        if user_prompt is not None:
            log_data["user_prompt"] = user_prompt

        if self.console_logging:
            logger.info(json.dumps(log_data))

    def log_response(
        self,
        session_id: str,
        request_id: str,
        response_id: str,
        output_messages: List[Dict[str, Any]],
        usage_data: Optional[Dict[str, Any]] = None,
        performance_data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log AI response"""
        # Extract params that are explicitly set to avoid duplicate keyword arguments
        operation_name = kwargs.pop("operation_name", "chat")
        input_messages = kwargs.pop("input_messages", [])

        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name=operation_name,
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            response_id=response_id,
            input_messages=input_messages,
            output_messages=output_messages,
            token_type="output",
            provider_name=_provider_name,
            **(usage_data or {}),
            **(performance_data or {}),
            **kwargs
        )

        self._write_log(log_data, "governance")

        # Also write to database
        if self.db_logging:
            self._write_to_database(log_data)

    def log_prompt(
        self,
        session_id: str,
        request_id: str,
        system_prompt: str,
        user_prompt: str,
        **kwargs
    ):
        """Log prompt details using standardized governance schema"""
        # Use create_governance_log for consistent schema across all event types
        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name="prompt",
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            input_messages=[{"role": "user", "content": user_prompt}],
            system_instructions=system_prompt,
            token_type="prompt",
            provider_name=_provider_name,
            **kwargs
        )
        # Add prompt-specific field
        log_data["user_prompt"] = user_prompt

        self._write_log(log_data, "governance")

    def log_decision(
        self,
        session_id: str,
        request_id: str,
        decision_type: str,
        decision_value: Any,
        rationale: Optional[str] = None,
        **kwargs
    ):
        """Log AI decision points using standardized governance schema"""
        # Use create_governance_log for consistent schema across all event types
        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name="decision",
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            input_messages=[],
            token_type="decision",
            provider_name=_provider_name,
            **kwargs
        )
        # Add decision-specific fields
        log_data["decision_type"] = decision_type
        log_data["decision_value"] = decision_value
        if rationale:
            log_data["rationale"] = rationale

        self._write_log(log_data, "governance")

    def log_tool_call(
        self,
        session_id: str,
        request_id: str,
        tool_name: str,
        tool_decision: str,
        *,
        tool_call_id: Optional[str] = None,
        tool_arguments: Optional[str] = None,
        tool_denied_reason: Optional[str] = None,
        agent_surface: str = "openclaw",
        **kwargs
    ):
        """Log a governed agent tool call (the OpenClaw tool guard).

        Written to the governance JSON file, SQLite, and any HEC destinations —
        the same fan-out as ``log_response`` — so a blocked/allowed tool action
        shows up alongside chat turns in the governance UI and Splunk. The
        executive overlay maps ``operation_name == "tool_call"`` to a
        ``blocked_tool_call`` business outcome when denied.
        """
        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name="tool_call",
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            input_messages=[],
            token_type="tool_call",
            provider_name=_provider_name,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            tool_arguments=tool_arguments,
            tool_decision=tool_decision,
            tool_denied_reason=tool_denied_reason,
            agent_surface=agent_surface,
            policy_blocked=(tool_decision == "block"),
            guardrail_triggered=(tool_decision == "block"),
            **kwargs
        )

        self._write_log(log_data, "governance")

        if self.db_logging:
            self._write_to_database(log_data)

    def log_error(
        self,
        session_id: str,
        request_id: str,
        error_type: str,
        error_message: str,
        stack_trace: Optional[str] = None,
        **kwargs
    ):
        """Log errors using standardized governance schema"""
        # Use create_governance_log for consistent schema across all event types
        _provider_name, _model = _active_provider_info()
        log_data = create_governance_log(
            operation_name="error",
            request_model=_model,
            conversation_id=session_id,
            session_id=session_id,
            request_id=request_id,
            input_messages=[],
            token_type="error",
            provider_name=_provider_name,
            error_type=error_type,
            **kwargs
        )
        # Add error-specific fields
        log_data["error_message"] = error_message
        if stack_trace:
            log_data["stack_trace"] = stack_trace

        self._write_log(log_data, "error")

        if self.console_logging:
            logger.error(f"Error in session {session_id}: {error_type} - {error_message}")

    def log_escalation(
        self,
        session_id: str,
        request_id: str,
        reason: str,
        severity: str,
        conversation_history: List[Dict[str, Any]],
        symptoms: List[str],
        **kwargs
    ):
        """Log escalation event"""
        escalation_id = kwargs.get("escalation_id", str(uuid.uuid4()))

        log_data = create_escalation_log(
            escalation_id=escalation_id,
            session_id=session_id,
            request_id=request_id,
            reason=reason,
            severity=severity,
            conversation_history=conversation_history,
            symptoms=symptoms,
            **kwargs
        )

        self._write_log(log_data, "escalation")

        # Write to database
        if self.db_logging:
            self._write_escalation_to_db(log_data)

        if self.console_logging:
            logger.warning(f"ESCALATION - Session {session_id}: {reason} (Severity: {severity})")

    def log_audit(
        self,
        session_id: str,
        request_id: str,
        action: str,
        actor: str,
        details: Dict[str, Any],
        **kwargs
    ):
        """Log audit event"""
        audit_id = kwargs.get("audit_id", str(uuid.uuid4()))

        log_data = create_audit_log(
            audit_id=audit_id,
            session_id=session_id,
            request_id=request_id,
            action=action,
            actor=actor,
            details=details,
            **kwargs
        )

        self._write_log(log_data, "audit")

        # Write to database
        if self.db_logging:
            self._write_audit_to_db(log_data)

    def _write_log(self, log_data: Dict[str, Any], log_type: str):
        """Write log to appropriate destinations"""
        if self.console_logging:
            logger.info(json.dumps(log_data))

        if self.file_logging:
            if log_type == "governance":
                self.file_handler.write_governance_log(log_data)
            elif log_type == "escalation":
                self.file_handler.write_escalation_log(log_data)
            elif log_type == "audit":
                self.file_handler.write_audit_log(log_data)
            elif log_type == "error":
                self.file_handler.write_error_log(log_data)

        # Fan out to any configured Splunk HEC destinations. Non-blocking
        # enqueue; never breaks local logging if HEC is down/misconfigured.
        try:
            hec_runtime.submit(log_type, log_data)
        except Exception:
            logger.debug("hec submit failed", exc_info=True)

        # Fan out completed chat turns to Splunk Agent Observability with
        # governance metadata (no-op unless SPLUNK_AO_O11Y_TOKEN + SPLUNK_AO_REALM
        # are set; self-gates to chat response events; non-blocking enqueue to a
        # single worker thread, so it never adds request latency).
        # A WARNING, not debug: maybe_log_turn is written never to raise, so
        # anything landing here is a real defect (a bad import, a broken queue)
        # that silently costs every turn its Agent Observability trace. At debug
        # it was undiagnosable. Deduped by cause so one permanent fault does not
        # print per turn.
        try:
            from backend import agent_observability
            agent_observability.maybe_log_turn(log_data)
        except Exception as exc:
            global _ao_submit_warned
            cause = f"{type(exc).__name__}: {exc}"
            if cause != _ao_submit_warned:
                logger.warning("agent observability submit failed (%s); turns are not "
                               "reaching Agent Observability", cause, exc_info=True)
                _ao_submit_warned = cause
            else:
                logger.debug("agent observability submit failed", exc_info=True)

    def _write_to_database(self, log_data: Dict[str, Any]):
        """Write governance log to database"""
        try:
            with get_db_context() as db:
                # Parse timestamp if it's a string
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

                db_log = AIGovernanceLog(
                    operation_name=log_data.get("operation_name"),
                    provider_name=log_data.get("provider_name"),
                    request_model=log_data.get("request_model"),
                    response_model=log_data.get("response_model"),
                    response_id=log_data.get("response_id"),
                    conversation_id=log_data.get("conversation_id"),
                    deployment_id=log_data.get("deployment_id"),
                    request_id=log_data.get("request_id"),
                    session_id=log_data.get("session_id"),
                    trace_id=log_data.get("trace_id"),
                    input_messages=log_data.get("input_messages"),
                    output_messages=log_data.get("output_messages"),
                    response_text=log_data.get("response_text"),
                    system_instructions=log_data.get("system_instructions"),
                    tool_definitions=log_data.get("tool_definitions"),
                    output_type=log_data.get("output_type"),
                    token_type=log_data.get("token_type"),
                    request_max_tokens=log_data.get("request_max_tokens"),
                    request_temperature=log_data.get("request_temperature"),
                    request_top_p=log_data.get("request_top_p"),
                    usage_input_tokens=log_data.get("usage_input_tokens"),
                    usage_output_tokens=log_data.get("usage_output_tokens"),
                    usage_output_tokens_cached=log_data.get("usage_output_tokens_cached"),
                    usage_output_tokens_uncached=log_data.get("usage_output_tokens_uncached"),
                    usage_total_tokens=log_data.get("usage_total_tokens"),
                    client_operation_duration=log_data.get("client_operation_duration"),
                    safety_violated=log_data.get("safety_violated", False),
                    safety_categories=log_data.get("safety_categories"),
                    guardrail_triggered=log_data.get("guardrail_triggered", False),
                    guardrail_ids=log_data.get("guardrail_ids"),
                    pii_detected=log_data.get("pii_detected", False),
                    pii_types=log_data.get("pii_types"),
                    policy_blocked=log_data.get("policy_blocked", False),
                    toxic_detected=log_data.get("toxic_detected", False),
                    toxic_types=log_data.get("toxic_types"),
                    hallucination_detected=log_data.get("hallucination_detected", False),
                    hallucination_types=log_data.get("hallucination_types"),
                    authority_violation_detected=log_data.get("authority_violation_detected", False),
                    authority_violation_types=log_data.get("authority_violation_types"),
                    tool_name=log_data.get("tool_name"),
                    tool_call_id=log_data.get("tool_call_id"),
                    tool_decision=log_data.get("tool_decision"),
                    tool_denied_reason=log_data.get("tool_denied_reason"),
                    agent_surface=log_data.get("agent_surface"),
                    error_type=log_data.get("error_type"),
                    enduser_id=log_data.get("enduser_id"),
                    service_name=log_data.get("service_name"),
                    client_address=log_data.get("client_address"),
                    timestamp=timestamp or datetime.utcnow()
                )
                db.add(db_log)
        except Exception as e:
            logger.error(f"Failed to write governance log to database: {e}")

    def _write_escalation_to_db(self, log_data: Dict[str, Any]):
        """Write escalation to database"""
        try:
            with get_db_context() as db:
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

                escalation = EscalationQueue(
                    escalation_id=log_data.get("escalation_id"),
                    session_id=log_data.get("session_id"),
                    request_id=log_data.get("request_id"),
                    timestamp=timestamp or datetime.utcnow(),
                    reason=log_data.get("reason"),
                    severity=log_data.get("severity"),
                    conversation_history=log_data.get("conversation_history"),
                    user_demographics=log_data.get("user_demographics"),
                    symptoms=log_data.get("symptoms"),
                    review_status=log_data.get("review_status", "pending")
                )
                db.add(escalation)
        except Exception as e:
            logger.error(f"Failed to write escalation to database: {e}")

    def _write_audit_to_db(self, log_data: Dict[str, Any]):
        """Write audit log to database"""
        try:
            with get_db_context() as db:
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

                audit = AuditLog(
                    audit_id=log_data.get("audit_id"),
                    session_id=log_data.get("session_id"),
                    request_id=log_data.get("request_id"),
                    timestamp=timestamp or datetime.utcnow(),
                    action=log_data.get("action"),
                    actor=log_data.get("actor"),
                    details=log_data.get("details"),
                    ip_address=log_data.get("ip_address"),
                    enduser_id=log_data.get("enduser_id"),
                )
                db.add(audit)
        except Exception as e:
            logger.error(f"Failed to write audit log to database: {e}")

# Global governance logger instance
governance_logger = GovernanceLogger()
