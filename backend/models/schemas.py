from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    EMERGENCY = "EMERGENCY"

class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"

class MessageType(str, Enum):
    USER_MESSAGE = "user_message"
    CLARIFYING_QUESTION = "clarifying_question"
    RECOMMENDATION = "recommendation"
    SAFETY_WARNING = "safety_warning"
    ESCALATION = "escalation"

# Request/Response Models
class ChatMessage(BaseModel):
    role: MessageRole
    content: str
    type: Optional[MessageType] = MessageType.USER_MESSAGE
    timestamp: Optional[datetime] = None

class SchedulingAction(BaseModel):
    """A structured scheduling action sent when the user clicks a chip in the
    chat (docs/scheduling.md). It wins over the typed-text intent parser."""
    action: Literal["book", "accept", "more_times", "decline", "list", "cancel", "reschedule", "choose_slot",
                    "resolved", "not_resolved", "clarify_slot"]
    slot_id: Optional[str] = Field(default=None, max_length=32)
    appointment_id: Optional[str] = Field(default=None, max_length=64)
    page: int = Field(default=0, ge=0, le=50)

class ChatAttachment(BaseModel):
    """A document attached to one chat turn (docs/attachments.md). PDF only
    today (backend/services/attachments.py SUPPORTED); images come later. The
    bytes are validated and read for this turn only and never persisted — only
    their metadata (kind, name, mime, bytes, sha256, pages) is."""
    name: str = Field("document.pdf", max_length=255)
    mime: str = Field("application/pdf", max_length=100)
    # Base64 file content; a `data:<mime>;base64,` prefix is tolerated. No
    # max_length here: the size limits answer 413 with a string detail
    # (backend/middleware/body_limit.py, attachments.validate_upload).
    data: str

class ChatRequest(BaseModel):
    session_id: str
    message: str
    disclaimer_accepted: bool = False
    theme: Optional[str] = "medadvice"
    force_pii_injection: Optional[bool] = None  # Override PII injection rate
    force_toxic_injection: Optional[bool] = None  # Override toxic response injection rate
    force_hallucination_injection: Optional[bool] = None  # Override hallucination injection rate
    force_boundary_injection: Optional[bool] = None  # Force the theme's outside-of-authority content (MedAdvice: prescriptive overreach; TelecomChatbot: unauthorized commitment; Retail: unauthorized refund; Manufacturing: safety override) in the response
    ai_defense_review: Optional[bool] = None  # Send prompt to Cisco AI Defense for policy review
    internal_policy_review: Optional[bool] = None  # Run the built-in internal policy engine (default on)
    multi_agent_mode: Optional[bool] = None  # True = coordinator/specialists/synthesizer pipeline; None/False (default) = the domain agent answers directly
    agent_control_review: Optional[bool] = None  # Submit the response to Agent Control for evaluation against the console's Controls
    nemo_guardrails_review: Optional[bool] = None  # Run NVIDIA NeMo Guardrails input rails on the prompt and output rails on the answer
    blueprint: Optional[str] = None  # Agentic architecture for this turn (pseudoco_multi_agent | nvidia_virtual_assistant); None = the server default
    # Appointment scheduling (docs/scheduling.md): the browser's stable id (the
    # owner of its bookings — a partition key, never authorization), its IANA
    # zone for slot labels, and a structured action when a scheduling chip was
    # clicked. Without client_id the scheduling nodes stay inert.
    client_id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    client_tz: Optional[str] = Field(default=None, max_length=64)
    scheduling_action: Optional[SchedulingAction] = None
    # Chat attachment (docs/attachments.md): a PDF whose extracted text is
    # screened together with `message` by every enabled prompt guardrail —
    # always, there is no toggle. Not a Demo Control, so not Optional[bool].
    attachment: Optional[ChatAttachment] = None

class ChatCompletionMessage(BaseModel):
    """One OpenAI-style chat message. ``content`` is a string or a list of
    content parts (only ``{"type": "text", "text": ...}`` parts are read).
    Unknown keys (``name``, ``tool_calls``, ...) are ignored."""
    role: str = Field(..., max_length=32)
    content: Optional[Any] = None


class ChatCompletionRequest(BaseModel):
    """``POST /api/chat/completions`` (docs/red-teaming.md): a stateless,
    OpenAI-compatible way into the same governed turn as ``/api/chat/message``.

    Every call is a brand-new session. The last message is the turn and must
    be a user message. Earlier user/assistant messages become that session's
    history, which is how a red-teaming tool runs a multi-turn attack. System,
    developer and tool messages are dropped: the app's own system prompt is
    part of what is under test.

    The PseudoCo Assistant fields after ``messages`` carry the same meaning
    and defaults as on ``ChatRequest``. A caller sets them as constants in its
    request template, for example ``"ai_defense_review": true`` for a
    protected run. OpenAI parameters such as ``model``, ``temperature`` and
    ``max_tokens`` are accepted and ignored.
    """
    messages: List[ChatCompletionMessage] = Field(..., min_length=1, max_length=100)
    model: Optional[str] = None
    stream: Optional[bool] = False
    theme: Optional[str] = "medadvice"
    force_pii_injection: Optional[bool] = None
    force_toxic_injection: Optional[bool] = None
    force_hallucination_injection: Optional[bool] = None
    force_boundary_injection: Optional[bool] = None
    ai_defense_review: Optional[bool] = None
    internal_policy_review: Optional[bool] = None
    multi_agent_mode: Optional[bool] = None
    agent_control_review: Optional[bool] = None
    nemo_guardrails_review: Optional[bool] = None
    blueprint: Optional[str] = None


class ChatResponse(BaseModel):
    session_id: str
    message: str
    type: MessageType
    severity: Optional[SeverityLevel] = None
    escalated: bool = False
    timestamp: datetime
    # Structured scheduling payload (state, slots, appointments, the chips to
    # render as `actions`); None when the turn had nothing to schedule.
    scheduling: Optional[Dict[str, Any]] = None

# Governance Log Models
class GenAILogEntry(BaseModel):
    # Core operation / model identity
    operation_name: str
    provider_name: str = "anthropic"
    request_model: str
    response_model: Optional[str] = None
    response_id: Optional[str] = None
    conversation_id: str
    deployment_id: str = "pseudoco-assistant-prod"
    request_id: str
    session_id: str
    trace_id: str

    # Input / output payload
    input_messages: List[Dict[str, Any]]
    output_messages: Optional[List[Dict[str, Any]]] = None
    system_instructions: Optional[str] = None
    tool_definitions: Optional[List[Dict[str, Any]]] = None
    output_type: str = "text"

    # Request parameters
    token_type: str
    request_max_tokens: Optional[int] = None
    request_temperature: Optional[float] = None
    request_top_p: Optional[float] = None
    request_frequency_penalty: Optional[float] = None
    request_presence_penalty: Optional[float] = None
    request_stop_sequences: Optional[List[str]] = None
    response_finish_reasons: Optional[List[str]] = None
    request_choice_count: Optional[int] = 1
    request_seed: Optional[int] = None

    # Usage, performance, and cost
    usage_input_tokens: Optional[int] = None
    usage_output_tokens: Optional[int] = None
    usage_output_tokens_cached: Optional[int] = None
    usage_output_tokens_uncached: Optional[int] = None
    usage_total_tokens: Optional[int] = None
    client_operation_duration: Optional[float] = None  # seconds
    server_time_per_output_token: Optional[float] = None
    server_time_to_first_token: Optional[float] = None

    # Safety, guardrails, and policy
    safety_violated: bool = False
    safety_categories: Optional[List[str]] = None
    guardrail_triggered: bool = False
    guardrail_ids: Optional[List[str]] = None
    pii_detected: bool = False
    pii_types: Optional[List[str]] = None
    policy_blocked: bool = False

    # Evaluation / TEVV
    evaluation_name: Optional[str] = None
    evaluation_score_value: Optional[float] = None
    evaluation_score_label: Optional[str] = None
    evaluation_explanation: Optional[str] = None
    drift_metric_name: Optional[str] = None
    drift_metric_value: Optional[float] = None
    drift_status: Optional[str] = None

    # Error and infra fields
    error_type: Optional[str] = None
    server_address: Optional[str] = None
    server_port: Optional[int] = None

    # Actor / application context
    enduser_id: Optional[str] = None
    service_name: str = "pseudoco-assistant"
    client_address: Optional[str] = None

    # Chat attachment (docs/attachments.md): the extraction's metadata record
    # (attachments.governance_record — never the text, never the bytes) and
    # what the turn carried: "text" or "text+pdf".
    attachment: Optional[Dict[str, Any]] = None
    input_modality: Optional[str] = None

    # Timestamp
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class EscalationLog(BaseModel):
    escalation_id: str
    session_id: str
    request_id: str
    timestamp: datetime
    reason: str
    severity: SeverityLevel
    conversation_history: List[Dict[str, Any]]
    user_demographics: Optional[Dict[str, Any]] = None
    symptoms: List[str]
    review_status: str = "pending"  # pending, reviewed, resolved
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    review_timestamp: Optional[datetime] = None

class AuditLogEntry(BaseModel):
    audit_id: str
    session_id: str
    request_id: str
    timestamp: datetime
    action: str
    actor: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None

# Metrics Models
class MetricsResponse(BaseModel):
    total_interactions: int
    escalation_count: int
    escalation_rate: float
    average_latency: float
    total_input_tokens: int
    total_output_tokens: int
    # Cache split of total_output_tokens. Defaulted so an older client (or a
    # pre-split row set) still validates.
    total_output_tokens_cached: int = 0
    total_output_tokens_uncached: int = 0
    total_tokens: int
    severity_distribution: Dict[str, int]
    pii_detection_count: int
    guardrail_trigger_count: int
    hallucination_detection_count: int = 0
    authority_violation_count: int = 0
    time_period_start: datetime
    time_period_end: datetime

class SessionExport(BaseModel):
    session_id: str
    created_at: datetime
    messages: List[ChatMessage]
    governance_logs: List[GenAILogEntry]
    escalations: List[EscalationLog]
    final_severity: Optional[SeverityLevel] = None
