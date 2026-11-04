from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
import asyncio
import logging
import time
import uuid
import json
from datetime import datetime, timedelta

from backend.config import settings
from backend.models.schemas import (
    ChatCompletionMessage,
    ChatCompletionRequest,
    ChatRequest,
    ChatResponse,
    MessageRole,
    MessageType,
)
from backend.models.db_models import Conversation
from backend.database.db import get_db
from backend.services import attachments
from backend.services.recommendation_engine import RecommendationEngine
from backend.services.auto_prompter import auto_prompter
from backend.services.enduser_pool import pick_enduser_id
from backend.logging.governance_logger import governance_logger
from backend.incident_mode import incident_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat", tags=["chat"])
recommendation_engine = RecommendationEngine()

# How long the SSE stream may go without putting bytes on the wire. Well under
# the 60s idle timeout common to proxies and load balancers.
SSE_HEARTBEAT_S = 10.0

# In-memory session store (in production, use Redis or similar).
# Bounded — see _evict_stale_sessions.
sessions: Dict[str, Dict[str, Any]] = {}


def _evict_stale_sessions() -> int:
    """Drop in-memory sessions idle longer than settings.session_timeout_minutes.

    This dict is a CACHE: every session is durably persisted as a Conversation
    row, and _prepare_session transparently reloads one that isn't resident. It
    previously had no eviction at all, so it grew for the process lifetime with
    the full message history of every session — while the auto-prompter creates
    one per minute and the incident load driver one every 2.5 seconds. The
    advertised SESSION_TIMEOUT_MINUTES (README and .env.example) was read by
    nothing; this is what makes it real.

    Returns the number of sessions evicted.
    """
    timeout = getattr(settings, "session_timeout_minutes", 0) or 0
    if timeout <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(minutes=timeout)
    stale = [
        sid for sid, s in sessions.items()
        if (s.get("last_activity") or s.get("created_at") or datetime.utcnow()) < cutoff
    ]
    for sid in stale:
        sessions.pop(sid, None)
    if stale:
        logger.info("Evicted %d idle in-memory session(s)", len(stale))
    return len(stale)


def _dispatch_chat_turn(**kwargs: Any) -> Dict[str, Any]:
    """Route a chat turn to the agentic LangGraph workflow or the legacy engine.

    When ``settings.use_agentic_engine`` is enabled the request is served by the
    supervisor-routed multi-agent graph (backend/agents). If the agentic
    dependencies are missing or the graph cannot be built, we transparently fall
    back to ``RecommendationEngine.process_message`` so the service stays up.
    Both paths return an identically-shaped dict and emit the same governance
    events, so this switch is invisible to the rest of the request flow.
    """
    if settings.use_agentic_engine:
        try:
            from backend.agents.graph import run_turn

            return run_turn(**kwargs)
        except ImportError as exc:
            logger.warning(
                "Agentic engine unavailable (%s); using legacy RecommendationEngine",
                exc,
            )
        except Exception:  # noqa: BLE001 - never fail the request on build issues
            logger.exception(
                "Agentic engine failed to run; using legacy RecommendationEngine"
            )
    return recommendation_engine.process_message(**kwargs)

async def _apply_incident_mode() -> None:
    """Demo-incident fault injection: inflate latency and/or fail with 5xx so the
    pseudoco-assistant APM service breaches its latency / error-rate detectors, giving
    the AI Troubleshooting Agent an alert to analyze. See backend/incident_mode.py.
    """
    if incident_mode.is_active():
        delay = incident_mode.delay_seconds()
        if delay:
            await asyncio.sleep(delay)
        if incident_mode.should_error():
            raise HTTPException(status_code=500, detail="Simulated demo incident on pseudoco-assistant")


async def _validated_attachment(chat_request: ChatRequest) -> Optional[Dict[str, Any]]:
    """Validate the turn's attachment before anything is recorded
    (docs/attachments.md). None when the request carries none.

    Called by both message endpoints BEFORE ``_prepare_session``, so a rejected
    file never becomes a message or a session. Raises HTTPException with the
    validator's status (413 / 415 / 422, 503 when this host has no PDF support)
    and a plain-string detail the chat UI shows as is -- and, on the stream
    endpoint, as JSON before any SSE frame. On the threadpool: the parse waits
    on a worker process.

    The returned dict carries the file's bytes for THIS turn only; what gets
    persisted is ``attachments.message_metadata`` of it.
    """
    attachment = chat_request.attachment
    if attachment is None:
        return None
    try:
        return await run_in_threadpool(
            attachments.validate_upload, attachment.name, attachment.mime, attachment.data
        )
    except attachments.AttachmentRejected as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None


def _typed_message(chat_request: ChatRequest, attachment: Optional[Dict[str, Any]]) -> str:
    """The turn's typed text. A turn that only carries a document gets a fixed
    prompt, so the stored history never holds an empty user turn (Anthropic
    rejects one when the history is replayed)."""
    if attachment is not None and not (chat_request.message or "").strip():
        return attachments.ATTACHMENT_ONLY_PROMPT
    return chat_request.message


def _prepare_session(
    chat_request: ChatRequest,
    client_host,
    db: Session,
    *,
    typed: Optional[str] = None,
    attachment: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Load or create the chat session and record the incoming user message.

    Shared by the JSON and SSE message endpoints; raises 400 when a new session
    hasn't accepted the disclaimer. ``typed`` overrides the stored text (see
    ``_typed_message``); a validated ``attachment`` is recorded on the message
    as metadata only -- never its bytes. ``history`` seeds the earlier turns
    of a brand-new session (``/completions``); an existing session ignores it.
    """
    session_id = chat_request.session_id

    # Check if session exists (in-memory or database)
    if session_id not in sessions:
        # Check database first
        existing_conversation = db.query(Conversation).filter(
            Conversation.session_id == session_id
        ).first()

        if existing_conversation:
            # Load existing session from database into memory.
            # list(...) COPIES: Conversation.messages is a plain JSON column with
            # no MutableList, so holding the ORM-loaded list by reference and
            # mutating it in place left SQLAlchemy comparing the attribute
            # against itself. History looked unchanged and `messages` was
            # omitted from the UPDATE, silently dropping the first turn of any
            # conversation resumed after a restart.
            sessions[session_id] = {
                "created_at": existing_conversation.created_at,
                "messages": list(existing_conversation.messages or []),
                "disclaimer_accepted": existing_conversation.disclaimer_accepted,
                "escalated": existing_conversation.escalated,
                "enduser_id": pick_enduser_id(),
                "last_activity": datetime.utcnow()
            }
        else:
            # New session - require disclaimer, unless the operator turned the
            # requirement off. The setting existed with no readers, so
            # REQUIRE_DISCLAIMER_ACCEPTANCE=False silently did nothing and the
            # gate was unconditional.
            if settings.require_disclaimer_acceptance and not chat_request.disclaimer_accepted:
                raise HTTPException(
                    status_code=400,
                    detail="Medical disclaimer must be accepted before starting consultation"
                )

            sessions[session_id] = {
                "created_at": datetime.utcnow(),
                "messages": list(history or []),
                "disclaimer_accepted": True,
                "escalated": False,
                "enduser_id": pick_enduser_id(),
                "last_activity": datetime.utcnow()
            }

            # Create conversation in database
            conversation = Conversation(
                session_id=session_id,
                disclaimer_accepted=True,
                messages=[]
            )
            db.add(conversation)
            db.commit()

            # Log audit event
            governance_logger.log_audit(
                session_id=session_id,
                request_id=str(uuid.uuid4()),
                action="session_started",
                actor="user",
                details={
                    "disclaimer_accepted": True,
                    "client_address": client_host
                },
                ip_address=client_host,
                enduser_id=sessions[session_id]["enduser_id"]
            )

    session = sessions[session_id]

    # Add user message to session
    user_message = {
        "role": MessageRole.USER,
        "content": chat_request.message if typed is None else typed,
        "timestamp": datetime.utcnow().isoformat(),
        "type": MessageType.USER_MESSAGE
    }
    if attachment is not None:
        # Metadata only (kind, name, mime, bytes, sha256, pages): Show Recent
        # and the Governance Logs conversation pane render the 📎 chip from it.
        user_message["attachments"] = [attachments.message_metadata(attachment)]
    session["messages"].append(user_message)
    session["last_activity"] = datetime.utcnow()
    # Sweep idle sessions on the way through; the durable copy is in the DB, so
    # this only trims the cache. Cheap: a dict scan per turn, and the turn that
    # follows costs an LLM call.
    _evict_stale_sessions()
    return session


def _turn_kwargs(
    chat_request: ChatRequest,
    session: Dict[str, Any],
    client_host,
    *,
    typed: Optional[str] = None,
    attachment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Keyword arguments for one chat turn (run_turn / run_turn_stream / legacy)."""
    return dict(
        session_id=chat_request.session_id,
        user_message=chat_request.message if typed is None else typed,
        conversation_history=session["messages"],
        client_address=client_host,
        theme=chat_request.theme,
        force_pii_injection=chat_request.force_pii_injection,
        force_toxic_injection=chat_request.force_toxic_injection,
        force_hallucination_injection=chat_request.force_hallucination_injection,
        force_boundary_injection=chat_request.force_boundary_injection,
        ai_defense_review=chat_request.ai_defense_review,
        internal_policy_review=chat_request.internal_policy_review,
        multi_agent_mode=chat_request.multi_agent_mode,
        agent_control_review=chat_request.agent_control_review,
        nemo_guardrails_review=chat_request.nemo_guardrails_review,
        blueprint=chat_request.blueprint,
        enduser_id=session.get("enduser_id"),
        # Appointment scheduling (docs/scheduling.md): rides on every request,
        # never on the (evictable) session dict.
        client_id=chat_request.client_id,
        client_tz=chat_request.client_tz,
        scheduling_action=(chat_request.scheduling_action.model_dump()
                           if chat_request.scheduling_action else None),
        # The validated attachment, bytes included, for this turn only: the
        # shared-chain attachment_intake node reads it and keeps metadata.
        attachment=attachment,
    )


def _record_assistant_turn(
    session_id: str, session: Dict[str, Any], response_data: Dict[str, Any], db: Session
) -> None:
    """Append the assistant reply to the session and persist the conversation."""
    assistant_message = {
        "role": MessageRole.ASSISTANT,
        "content": response_data["message"],
        "timestamp": datetime.utcnow().isoformat(),
        "type": response_data["type"],
        "severity": response_data.get("severity"),
        "metadata": response_data.get("metadata", {})
    }
    session["messages"].append(assistant_message)

    # Update session escalation status
    if response_data.get("escalated"):
        session["escalated"] = True

    # Update database
    conversation = db.query(Conversation).filter(
        Conversation.session_id == session_id
    ).first()

    if conversation:
        # Assign a NEW list so change detection always sees a distinct object,
        # even if some future path reintroduces a shared reference.
        conversation.messages = list(session["messages"])
        conversation.escalated = session["escalated"]
        conversation.updated_at = datetime.utcnow()
        if response_data.get("severity"):
            conversation.final_severity = response_data["severity"].value
        db.commit()


@router.post("/message", response_model=ChatResponse)
async def send_message(
    chat_request: ChatRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Send a message and get a response"""

    # request.client is Optional per the ASGI spec (None under the TestClient and
    # behind some proxies); guard it like the access-key / request-logging middleware.
    client_host = request.client.host if request.client else None

    await _apply_incident_mode()

    attachment = await _validated_attachment(chat_request)
    typed = _typed_message(chat_request, attachment)
    session = _prepare_session(chat_request, client_host, db, typed=typed, attachment=attachment)
    session_id = chat_request.session_id

    # Process message (agentic LangGraph workflow, with legacy fallback).
    # The turn is fully synchronous (blocking LangGraph invoke + blocking AI Defense
    # HTTP + sync LLM calls), so run it in a worker thread instead of on the event
    # loop. Otherwise a single in-flight turn serializes every concurrent request
    # (all attendees freeze until it completes). Output and telemetry are unchanged;
    # only the execution thread differs.
    response_data = await run_in_threadpool(
        _dispatch_chat_turn,
        **_turn_kwargs(chat_request, session, client_host, typed=typed, attachment=attachment),
    )

    _record_assistant_turn(session_id, session, response_data, db)

    # Return response
    return ChatResponse(
        session_id=session_id,
        message=response_data["message"],
        type=response_data["type"],
        severity=response_data.get("severity"),
        escalated=response_data.get("escalated", False),
        timestamp=datetime.utcnow(),
        scheduling=response_data.get("scheduling"),
    )


# ---------------------------------------------------------------------------
# POST /api/chat/completions -- stateless, OpenAI-compatible (docs/red-teaming.md)
# ---------------------------------------------------------------------------

# The ChatCompletionRequest fields that carry over to ChatRequest unchanged:
# the theme, every Demo Controls flag and the blueprint override.
# tests/test_chat_completions.py fails if a ChatRequest flag is missing here.
COMPLETION_TURN_FIELDS = frozenset(ChatCompletionRequest.model_fields) - {"messages", "model", "stream"}

# Roles a caller may send. Only user and assistant messages become history.
_COMPLETION_ROLES = frozenset({"system", "developer", "user", "assistant", "tool", "function"})


def _completion_text(message: ChatCompletionMessage) -> str:
    """Plain text of one OpenAI-style message: the string itself, or the text
    parts of a content-part list, joined with newlines."""
    content = message.content
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif (isinstance(part, dict) and part.get("type") in ("text", "input_text")
                  and isinstance(part.get("text"), str)):
                parts.append(part["text"])
        return "\n".join(parts)
    raise HTTPException(status_code=422,
                        detail="message content must be a string or a list of text parts")


def _completion_turn(body: ChatCompletionRequest) -> tuple:
    """Split a /completions body into (the turn's text, the history to seed).

    The last message is the turn and must be a non-empty user message. Earlier
    user/assistant messages become the history, in order. System, developer
    and tool messages are dropped, because the app's own system prompt is part
    of what is under test. Empty turns are dropped too: Anthropic rejects an
    empty message when the history is replayed.
    """
    if body.stream:
        raise HTTPException(status_code=400,
                            detail="stream is not supported on /api/chat/completions")
    for message in body.messages:
        if message.role not in _COMPLETION_ROLES:
            raise HTTPException(status_code=422,
                                detail=f"unsupported message role: {message.role!r}")
    last = body.messages[-1]
    if last.role != "user":
        raise HTTPException(status_code=422, detail="the last message must be a user message")
    typed = _completion_text(last)
    if not typed.strip():
        raise HTTPException(status_code=422, detail="the last user message is empty")

    now = datetime.utcnow().isoformat()
    history: List[Dict[str, Any]] = []
    for message in body.messages[:-1]:
        if message.role not in ("user", "assistant"):
            continue
        text = _completion_text(message)
        if not text.strip():
            continue
        is_user = message.role == "user"
        history.append({
            "role": MessageRole.USER if is_user else MessageRole.ASSISTANT,
            "content": text,
            "timestamp": now,
            "type": MessageType.USER_MESSAGE if is_user else MessageType.RECOMMENDATION,
        })
    return typed, history


@router.post("/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """OpenAI-compatible, stateless entry to the governed chat turn.

    Built for AI Defense AI Red Teaming and similar tools, whose request
    templates can only fill in ``{{prompt}}``, so they cannot supply a fresh
    ``session_id`` per attack (docs/red-teaming.md). Every call starts a new
    session seeded with the caller's earlier turns, then runs exactly the
    ``/api/chat/message`` turn: same shared chain, guardrails, governance
    events and persistence. The access-key gate applies as usual, and calling
    this endpoint counts as accepting the disclaimer.

    The answer is ``choices[0].message.content``. A turn a guardrail blocks
    returns 200 with the block banner as the content, exactly as the chat UI
    would show it.
    """
    client_host = request.client.host if request.client else None
    typed, history = _completion_turn(body)

    await _apply_incident_mode()

    chat_request = ChatRequest(
        session_id=str(uuid.uuid4()),
        message=typed,
        disclaimer_accepted=True,
        **body.model_dump(include=COMPLETION_TURN_FIELDS),
    )
    session = _prepare_session(chat_request, client_host, db, history=history)
    response_data = await run_in_threadpool(
        _dispatch_chat_turn, **_turn_kwargs(chat_request, session, client_host)
    )
    _record_assistant_turn(chat_request.session_id, session, response_data, db)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "pseudoco-assistant",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": response_data["message"]},
            "finish_reason": "stop",
        }],
        "pseudoco_assistant_turn": {
            "session_id": chat_request.session_id,
            "type": response_data["type"],
            "severity": response_data.get("severity"),
            "escalated": response_data.get("escalated", False),
        },
    }


def _turn_event_stream(**kwargs: Any):
    """Yield per-node progress events, then the final result event.

    Streaming variant of ``_dispatch_chat_turn`` with the same fallback ladder:
    agentic graph first, legacy RecommendationEngine (single final event) if the
    graph is unavailable.
    """
    if settings.use_agentic_engine:
        try:
            from backend.agents.graph import run_turn_stream

            yield from run_turn_stream(**kwargs)
            return
        except ImportError as exc:
            logger.warning(
                "Agentic engine unavailable (%s); using legacy RecommendationEngine",
                exc,
            )
        except Exception:  # noqa: BLE001 - never fail the request on build issues
            logger.exception(
                "Agentic engine failed to run; using legacy RecommendationEngine"
            )
    yield {"event": "final", "result": recommendation_engine.process_message(**kwargs)}


@router.post("/message/stream")
async def send_message_stream(
    chat_request: ChatRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Send a message and stream progress as Server-Sent Events.

    Same turn, governance, and guardrails as ``POST /message`` — the pipeline
    still completes (including the response_defense output scan) before any
    answer text is emitted. What streams earlier is *progress*: one
    ``{"event": "stage", "node", "elapsed_ms"}`` frame per completed graph
    node, so the UI can show live multi-agent status instead of a 30-40s
    spinner. The last frame is ``{"event": "final", ...ChatResponse fields}``.
    """
    client_host = request.client.host if request.client else None

    await _apply_incident_mode()

    # Before the StreamingResponse exists: a rejected attachment is a plain
    # JSON 4xx/503, never an SSE stream.
    attachment = await _validated_attachment(chat_request)
    typed = _typed_message(chat_request, attachment)
    session = _prepare_session(chat_request, client_host, db, typed=typed, attachment=attachment)
    session_id = chat_request.session_id
    turn_kwargs = _turn_kwargs(chat_request, session, client_host, typed=typed, attachment=attachment)

    async def _sse():
        # The turn is fully synchronous (see send_message); pump the sync
        # generator from a worker thread into a queue so the event loop stays
        # free. Session/DB bookkeeping runs back on the event loop, before the
        # final frame is sent, so a client disconnect can't skip persistence.
        #
        # A queue rather than iterate_in_threadpool because the consumer has to
        # be able to time out: stage frames are emitted per completed graph
        # node, and the LLM node alone can run for a minute or more on a slow
        # self-hosted model. That silence is long enough for an intermediary to
        # drop an idle connection, which the UI sees as a failed stream and
        # answers by replaying the whole turn against /api/chat/message --
        # double the inference cost, double the governance events.
        events: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        done = object()

        def _pump() -> None:
            try:
                for event in _turn_event_stream(**turn_kwargs):
                    loop.call_soon_threadsafe(events.put_nowait, event)
            except BaseException as exc:  # noqa: BLE001 - re-raised on the loop
                loop.call_soon_threadsafe(events.put_nowait, exc)
            else:
                loop.call_soon_threadsafe(events.put_nowait, done)

        turn = asyncio.create_task(asyncio.to_thread(_pump))

        while True:
            try:
                event = await asyncio.wait_for(events.get(), SSE_HEARTBEAT_S)
            except asyncio.TimeoutError:
                # A comment frame. The UI's reader keeps only lines starting
                # with "data: ", so this is invisible to it, but it puts bytes
                # on the wire often enough that nothing in the path considers
                # the connection idle.
                yield ": ping\n\n"
                continue

            if event is done:
                break
            if isinstance(event, BaseException):
                raise event

            if event.get("event") == "final":
                response_data = event["result"]
                _record_assistant_turn(session_id, session, response_data, db)
                severity = response_data.get("severity")
                msg_type = response_data["type"]
                final_frame = {
                    "event": "final",
                    "session_id": session_id,
                    "message": response_data["message"],
                    "type": getattr(msg_type, "value", msg_type),
                    "severity": getattr(severity, "value", severity) if severity is not None else None,
                    "escalated": response_data.get("escalated", False),
                    "timestamp": datetime.utcnow().isoformat(),
                    # Same key as ChatResponse: the UI reads the stream first.
                    "scheduling": response_data.get("scheduling"),
                }
                yield f"data: {json.dumps(final_frame)}\n\n"
            else:
                yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        _sse(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@router.get("/session/{session_id}")
async def get_session(session_id: str, db: Session = Depends(get_db)):
    """Get session conversation history"""

    # Check in-memory first
    if session_id in sessions:
        return {
            "session_id": session_id,
            "messages": sessions[session_id]["messages"],
            "escalated": sessions[session_id].get("escalated", False),
            "created_at": sessions[session_id]["created_at"]
        }

    # Check database
    conversation = db.query(Conversation).filter(
        Conversation.session_id == session_id
    ).first()

    if not conversation:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": session_id,
        "messages": conversation.messages,
        "escalated": conversation.escalated,
        "created_at": conversation.created_at
    }

@router.post("/session/new")
async def create_session():
    """Create a new session"""
    session_id = str(uuid.uuid4())
    return {"session_id": session_id}

@router.get("/disclaimer")
async def get_disclaimer(theme: str = "medadvice"):
    """Get the disclaimer text for an Application Theme.

    Theme-aware because this used to return the MEDICAL disclaimer
    unconditionally, with no theme parameter at all — so an API consumer got
    wrong text for five of the six themes. The detailed medical copy below is
    medadvice's; other themes get a disclaimer built from their own label.

    The web UI renders its own per-theme copy client-side (frontend/js/chat.js
    THEMES) and does not call this endpoint; deliberately not duplicating all six
    bodies here, which would just create a second place to drift.
    """
    from backend.agents.themes import get_theme

    theme_config = get_theme(theme)
    if theme_config.key != "medadvice":
        return {
            "title": f"{theme_config.label} Disclaimer",
            "theme": theme_config.key,
            "content": (
                f"**IMPORTANT DISCLAIMER — {theme_config.label.upper()}**\n\n"
                "This service provides general information and guidance only. It "
                "is NOT a substitute for advice from a qualified professional in "
                "this domain, and no professional relationship is created by "
                "using it.\n\n"
                "**Key Points:**\n\n"
                "• Responses are generated by an AI system and may be incomplete "
                "or incorrect.\n\n"
                "• Do not rely on this service for decisions with legal, "
                "financial, medical, or contractual consequences.\n\n"
                "• Always confirm anything material with a qualified professional "
                "or an official source.\n\n"
                "• Do not share sensitive personal information you would not want "
                "logged for governance review.\n\n"
                "**By continuing, you acknowledge that:**\n\n"
                "1. You understand this is not professional advice\n"
                "2. You will verify important information independently\n"
                "3. You understand the limitations of this service\n\n"
                "Do you accept these terms and wish to continue?\n"
            ),
            "version": "1.0",
        }
    return {
        "title": "Medical Disclaimer",
        "theme": theme_config.key,
        "content": """**IMPORTANT MEDICAL DISCLAIMER**

This service provides general health information and guidance only. It is NOT a substitute for professional medical advice, diagnosis, or treatment.

**Key Points:**

• This is NOT emergency medical care. If you are experiencing a medical emergency, call 911 or go to the nearest emergency room immediately.

• The information provided is for educational purposes only and should not be used to diagnose or treat any health condition.

• Always seek the advice of your physician or other qualified health provider with any questions you may have regarding a medical condition.

• Never disregard professional medical advice or delay in seeking it because of something you have read here.

• This service does NOT provide prescription medication advice or pediatric dosing.

• If you are pregnant, elderly, or have chronic health conditions, consult with a healthcare provider before following any recommendations.

**By continuing, you acknowledge that:**

1. You understand this is not professional medical care
2. You will seek emergency care for urgent symptoms
3. You will consult a healthcare provider for proper diagnosis and treatment
4. You understand the limitations of this service

Do you accept these terms and wish to continue?
""",
        "version": "1.0"
    }


# Auto-prompter endpoints
@router.post("/auto-prompt/start")
async def start_auto_prompter():
    """Start automatic session generation (one session per minute)"""
    if auto_prompter.is_running:
        return {"status": "already_running", "message": "Auto-prompter is already running", **auto_prompter.stats}
    
    await auto_prompter.start()
    return {"status": "started", "message": "Auto-prompter started - will create one session per minute", **auto_prompter.stats}


@router.post("/auto-prompt/stop")
async def stop_auto_prompter():
    """Stop automatic session generation"""
    if not auto_prompter.is_running:
        return {"status": "already_stopped", "message": "Auto-prompter is not running", **auto_prompter.stats}
    
    await auto_prompter.stop()
    return {"status": "stopped", "message": "Auto-prompter stopped", **auto_prompter.stats}


@router.get("/auto-prompt/status")
async def get_auto_prompter_status():
    """Get auto-prompter status"""
    return {"status": "running" if auto_prompter.is_running else "stopped", **auto_prompter.stats}
