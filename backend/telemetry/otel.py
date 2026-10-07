"""Code-based OpenTelemetry GenAI instrumentation (workshop sections 6-7).

The agentic workflow is instrumented with three nested GenAI span kinds that map
onto Splunk AI Agent Monitoring's data model:

    Workflow         -> the whole graph invocation (root GenAI span)
    AgentInvocation  -> each agent node (intake, domain, safety, compliance)
    LLMInvocation    -> each model call (with token usage + model/provider)

Implementation notes:
- This module is defensive. If the OpenTelemetry SDK (or the optional
  ``opentelemetry-util-genai`` package) is not installed, or telemetry is
  disabled, every helper degrades to a no-op context manager so the application
  runs unchanged.
- Spans carry the OpenTelemetry GenAI semantic-convention attributes
  (``gen_ai.*``) so Splunk Observability Cloud recognizes and groups them. When
  ``opentelemetry-util-genai`` is present its ``TelemetryHandler`` is also
  initialized for richer GenAI emission / evaluations.
- Export endpoint/protocol/headers come from the standard ``OTEL_*`` environment
  variables (e.g. ``OTEL_EXPORTER_OTLP_ENDPOINT``).
"""

from __future__ import annotations

import contextlib
import logging
import os
import uuid
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger(__name__)

# Module-level telemetry state.
_STATE: Dict[str, Any] = {
    "initialized": False,
    "enabled": False,
    "tracer": None,
    "genai_handler": None,
}

# GenAI semantic-convention operation names.
OP_WORKFLOW = "workflow"
OP_AGENT = "invoke_agent"
OP_CHAT = "chat"
OP_EXECUTE_TOOL = "execute_tool"


def _build_exporter():
    """Return an OTLP span exporter, preferring gRPC then HTTP."""
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter as GrpcExporter,
        )

        return GrpcExporter()
    except Exception:  # noqa: BLE001 - fall through to HTTP
        pass
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as HttpExporter,
        )

        return HttpExporter()
    except Exception as exc:  # noqa: BLE001
        logger.warning("No OTLP exporter available: %s", exc)
        return None


def init_telemetry(settings) -> None:
    """Initialize the OTel tracer provider and (optional) GenAI handler.

    Idempotent and safe to call once at FastAPI startup.
    """
    if _STATE["initialized"]:
        return
    _STATE["initialized"] = True

    if not getattr(settings, "otel_enabled", False):
        logger.info("OTel GenAI telemetry disabled (settings.otel_enabled=False)")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        service_name = os.getenv("OTEL_SERVICE_NAME") or getattr(
            settings, "otel_service_name", "pseudoco-assistant"
        )
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
        )
        exporter = _build_exporter() if endpoint else None
        if exporter is None and getattr(settings, "debug", False):
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter

            exporter = ConsoleSpanExporter()

        if exporter is not None:
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        _STATE["tracer"] = trace.get_tracer("pseudoco-assistant.agents")
        _STATE["enabled"] = True

        # Optional: richer GenAI emission via opentelemetry-util-genai.
        try:
            from opentelemetry.util.genai.handler import get_telemetry_handler

            _STATE["genai_handler"] = get_telemetry_handler()
            logger.info("opentelemetry-util-genai TelemetryHandler initialized")
        except Exception:  # noqa: BLE001 - optional dependency
            logger.info(
                "opentelemetry-util-genai not available; using gen_ai.* span attributes"
            )

        logger.info(
            "OTel GenAI telemetry initialized (service=%s, endpoint=%s)",
            service_name,
            endpoint or "console",
        )
    except Exception as exc:  # noqa: BLE001 - never break app startup
        logger.warning("Failed to initialize OTel telemetry: %s", exc)
        _STATE["enabled"] = False


def is_enabled() -> bool:
    return bool(_STATE["enabled"] and _STATE["tracer"] is not None)


def current_trace_id() -> Optional[str]:
    """The active span's OTel trace id as 32 lowercase hex — the form Splunk APM
    and Agent Observability show — or None when no valid span is current.

    Reads the global context rather than ``_STATE["tracer"]``, so it also sees a
    span started by the auto-instrumentation (the FastAPI request span under
    ``opentelemetry-instrument``) when the hand-rolled spans are off."""
    try:
        from opentelemetry import trace

        ctx = trace.get_current_span().get_span_context()
    except Exception:  # noqa: BLE001 - OTel missing or a broken context
        return None
    if ctx is None or not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x")


def turn_trace_id() -> str:
    """The trace id a turn's governance events carry: the OTel trace id when a
    span is current, so ``trace_id`` in the governance log, the
    ``pseudoco-assistant.trace_id`` span attribute and the APM trace are one
    value. With no span (telemetry off, an in-process caller outside a request)
    it falls back to a random id of the same 32-hex shape."""
    return current_trace_id() or uuid.uuid4().hex


def set_span_attributes(span, attributes: Optional[Dict[str, Any]]) -> None:
    """Set attributes on a span from one of the helpers here; a no-op for the
    ``None`` they yield when telemetry is off."""
    if span is None:
        return
    _set_attrs(span, attributes)


def _set_attrs(span, attributes: Optional[Dict[str, Any]]) -> None:
    if not attributes:
        return
    for key, value in attributes.items():
        if value is None:
            continue
        try:
            span.set_attribute(key, value)
        except Exception:  # noqa: BLE001 - attribute typing edge cases
            span.set_attribute(key, str(value))


@contextlib.contextmanager
def _span(name: str, operation: str, attributes: Optional[Dict[str, Any]]) -> Iterator[Any]:
    """Start a span and make it current for the body of the ``with``.

    Deliberately NOT ``tracer.start_as_current_span``. That helper detaches its
    context token through the public ``opentelemetry.context.detach``, which
    logs a full ERROR traceback when the token cannot be reset -- and it cannot
    be reset whenever the ``with`` block is a generator that ``yield``s from
    inside it. ``run_turn_stream`` (backend/agents/graph.py) is exactly that:
    the workflow span wraps a ``for chunk in runner.stream(...)`` loop that
    yields a stage event per node. A generator has no Context of its own, so
    each resumption runs in whatever Context is current in the caller, and two
    ``copy_context()`` boundaries sit in between -- ``asyncio.to_thread`` in the
    SSE route and LangGraph's per-step ``executor.submit(ctx.run, ...)``. By
    teardown the current Context is not the one the token came from.

    The span itself is fine either way (export was never affected); only the
    reset fails. So we attach and detach explicitly and swallow that specific
    failure, which is what ``opentelemetry.util.genai``'s own
    ``_pop_current_span`` does for the same reason -- it names LangGraph's
    ``copy_context().run()`` boundaries in its docstring.
    """
    if not is_enabled():
        yield None
        return
    from opentelemetry import context as context_api, trace

    tracer = _STATE["tracer"]
    span = tracer.start_span(name)
    token = context_api.attach(trace.set_span_in_context(span))
    try:
        span.set_attribute("gen_ai.operation.name", operation)
        _set_attrs(span, attributes)
        try:
            yield span
        except Exception as exc:  # noqa: BLE001 - record + re-raise
            try:
                span.record_exception(exc)
                from opentelemetry.trace import Status, StatusCode

                span.set_status(Status(StatusCode.ERROR, str(exc)))
            except Exception:  # noqa: BLE001
                pass
            raise
    finally:
        try:
            # Bypasses opentelemetry.context.detach on purpose: that wrapper
            # turns a benign cross-Context reset into logger.exception().
            context_api._RUNTIME_CONTEXT.detach(token)  # noqa: SLF001
        except Exception:  # noqa: BLE001 - resumed in a different Context
            pass
        span.end()


def workflow_span(
    *,
    workflow_name: str,
    theme: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    blueprint: Optional[str] = None,
):
    """Root GenAI Workflow span for the whole graph invocation."""
    return _span(
        f"workflow {workflow_name}",
        OP_WORKFLOW,
        {
            "gen_ai.workflow.name": workflow_name,
            "workflow_name": workflow_name,
            "pseudoco-assistant.theme": theme,
            # Which agentic architecture served the turn (additive attribute).
            "pseudoco-assistant.blueprint": blueprint,
            "session.id": session_id,
            "pseudoco-assistant.request_id": request_id,
            "pseudoco-assistant.trace_id": trace_id,
        },
    )


def agent_span(agent_name: str, *, theme: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    """AgentInvocation span for an agent node."""
    attrs = {
        "gen_ai.agent.name": agent_name,
        "agent_name": agent_name,
        "pseudoco-assistant.theme": theme,
    }
    if attributes:
        attrs.update(attributes)
    return _span(f"invoke_agent {agent_name}", OP_AGENT, attrs)


def tool_span(
    tool_name: str,
    *,
    tool_call_id: Optional[str] = None,
    agent_surface: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
):
    """Execute-tool span for a governed agent tool call (the tool guard).

    Carries gen_ai.operation.name=execute_tool + gen_ai.tool.* so the span
    survives the collector's Galileo genai_only filter and groups with the
    other GenAI operations in Splunk AI Agent Monitoring.
    """
    attrs = {
        "gen_ai.tool.name": tool_name,
        "gen_ai.tool.call.id": tool_call_id,
        "tool_name": tool_name,
        "pseudoco-assistant.agent_surface": agent_surface,
    }
    if attributes:
        attrs.update(attributes)
    return _span(f"execute_tool {tool_name}", OP_EXECUTE_TOOL, attrs)


def record_tool_result(
    span,
    *,
    decision: str,
    denied_reason: Optional[str] = None,
    rule_names: Optional[list] = None,
    event_id: Optional[str] = None,
) -> None:
    """Attach the tool-guard verdict to an execute_tool span."""
    if span is None:
        return
    _set_attrs(
        span,
        {
            "pseudoco-assistant.tool.decision": decision,
            "pseudoco-assistant.tool.denied_reason": denied_reason,
            "pseudoco-assistant.guardrail.rule_names": rule_names,
            "pseudoco-assistant.ai_defense.event_id": event_id,
        },
    )


def llm_span(*, request_model: str, provider: str, attributes: Optional[Dict[str, Any]] = None):
    """LLMInvocation span for a single model call."""
    attrs = {
        "gen_ai.request.model": request_model,
        "gen_ai.system": provider,
        "gen_ai.provider.name": provider,
    }
    if attributes:
        attrs.update(attributes)
    return _span(f"chat {request_model}", OP_CHAT, attrs)


# Output tokens split by cache origin. Additive next to the semconv
# gen_ai.usage.output_tokens (which keeps its meaning: the two always sum to
# it), so a Splunk dashboard can chart a cache-hit ratio and price cached and
# decoded tokens apart. See backend/agents/token_usage.py.
ATTR_OUTPUT_TOKENS_CACHED = "gen_ai.usage.output_tokens_cached"
ATTR_OUTPUT_TOKENS_UNCACHED = "gen_ai.usage.output_tokens_uncached"


def record_llm_result(
    span,
    *,
    response_id: Optional[str] = None,
    response_model: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    output_tokens_cached: Optional[int] = None,
    output_tokens_uncached: Optional[int] = None,
    finish_reason: Optional[str] = None,
) -> None:
    """Attach GenAI response/usage attributes to an LLM span."""
    if span is None:
        return
    total = None
    if input_tokens is not None or output_tokens is not None:
        total = (input_tokens or 0) + (output_tokens or 0)
    _set_attrs(
        span,
        {
            "gen_ai.response.id": response_id,
            "gen_ai.response.model": response_model,
            "gen_ai.usage.input_tokens": input_tokens,
            "gen_ai.usage.output_tokens": output_tokens,
            "gen_ai.usage.total_tokens": total,
            ATTR_OUTPUT_TOKENS_CACHED: output_tokens_cached,
            ATTR_OUTPUT_TOKENS_UNCACHED: output_tokens_uncached,
            "gen_ai.response.finish_reasons": finish_reason,
        },
    )


def record_output_token_cache_split(inv, cached: Optional[int], uncached: Optional[int]) -> None:
    """Put the output-token cache split on a util-genai invocation.

    The handler has no field for these, and its span emitter drops any custom
    ``attributes`` key that is not an allow-listed semconv one — so they are set
    straight on the invocation's span, which exists from ``start_llm`` and is not
    ended until the context manager exits. The ``attributes`` dict gets them too,
    for the emitters that do read it. No-op when the invocation is unavailable
    (handler not configured).
    """
    if inv is None or (cached is None and uncached is None):
        return
    attrs = {
        ATTR_OUTPUT_TOKENS_CACHED: int(cached or 0),
        ATTR_OUTPUT_TOKENS_UNCACHED: int(uncached or 0),
    }
    span = getattr(inv, "span", None)
    try:
        inv.attributes.update(attrs)
        if span is not None:
            _set_attrs(span, attrs)
    except Exception:  # noqa: BLE001 - telemetry must never break a turn
        logger.debug("could not attach output-token cache split", exc_info=True)


# ---------------------------------------------------------------------------
# GenAI emission via the opentelemetry-util-genai TelemetryHandler.
#
# The Splunk LangChain auto-instrumentation (a) does not emit an AgentInvocation
# for create_react_agent, so Splunk's "AI agents" view shows nothing, and (b)
# reports gen_ai.request.model as "unknown" on the create_react_agent +
# LangChain-1.x path, so server-side cost (price x tokens) can't be computed. We
# emit the GenAI entities ourselves from the app's accurate data via the shared
# TelemetryHandler, which routes through the active span_metric/splunk emitters ->
# proper Agent + LLM entities with the real model + token usage. No-op (yields
# None) when opentelemetry-util-genai is unavailable. The buggy auto langchain
# instrumentation is disabled in run.sh so these are the single source of truth.
# ---------------------------------------------------------------------------


def _get_handler():
    try:
        from opentelemetry.util.genai.handler import get_telemetry_handler

        return get_telemetry_handler()
    except Exception:  # noqa: BLE001 - optional dependency / not configured
        return None


def _genai_error(exc: Exception):
    try:
        from opentelemetry.util.genai.types import Error

        return Error(message=str(exc), type=type(exc))
    except Exception:  # noqa: BLE001
        return None


def _input_messages(system: Optional[str], messages: Optional[list]):
    """Build a util-genai InputMessage list (system prompt + conversation turns).

    Splunk AI Agent Monitoring's "AI trace data" view indexes gen_ai spans by their
    message *content* (prompt/response) — it powers the Content column and the
    quality/risk evaluations. Without messages, the spans still reach APM (and show
    in Trace Analyzer) but never surface in AI trace data. Degrades to [] if the
    optional util-genai types are unavailable.
    """
    try:
        from opentelemetry.util.genai.types import InputMessage, Text
    except Exception:  # noqa: BLE001 - optional dependency
        return []
    out = []
    if system:
        out.append(InputMessage(role="system", parts=[Text(content=str(system))]))
    for m in messages or []:
        role = m.get("role")
        role = role.value if hasattr(role, "value") else role
        content = m.get("content", "")
        if content:
            out.append(InputMessage(role=str(role or "user"), parts=[Text(content=str(content))]))
    return out


def record_genai_output(inv, *, text: Optional[str], finish_reason: Optional[str] = None) -> None:
    """Attach the model's response text to an LLM/agent invocation as an
    OutputMessage so the gen_ai span carries the completion (paired with the input
    messages set at creation). No-op when the invocation/types are unavailable."""
    if inv is None or text is None:
        return
    try:
        from opentelemetry.util.genai.types import OutputMessage, Text
    except Exception:  # noqa: BLE001
        return
    inv.output_messages = [
        OutputMessage(role="assistant", parts=[Text(content=str(text))], finish_reason=finish_reason)
    ]


@contextlib.contextmanager
def genai_llm_invocation(
    *, request_model: str, provider: str, operation: str = OP_CHAT,
    system: Optional[str] = None, messages: Optional[list] = None,
):
    """Emit a GenAI LLMInvocation via the util-genai handler, carrying the real
    request model + token usage (so the model is no longer "unknown" and Splunk
    can price it). Pass ``system`` + ``messages`` so the span carries the prompt;
    yields the LLMInvocation — set ``input_tokens`` / ``output_tokens`` /
    ``response_model_name`` / ``response_id`` and call ``record_genai_output`` on it
    inside the block — or None when the handler is unavailable."""
    handler = _get_handler()
    if handler is None:
        yield None
        return
    from opentelemetry.util.genai.types import LLMInvocation

    inv = LLMInvocation(
        request_model=request_model, operation=operation,
        provider=provider, system=provider,
        input_messages=_input_messages(system, messages),
    )
    handler.start_llm(inv)
    try:
        yield inv
    except Exception as exc:  # noqa: BLE001 - mark span errored, then re-raise
        err = _genai_error(exc)
        try:
            handler.fail_llm(inv, err) if err else handler.stop_llm(inv)
        except Exception:  # noqa: BLE001
            pass
        raise
    else:
        try:
            handler.stop_llm(inv)
        except Exception:  # noqa: BLE001
            pass


@contextlib.contextmanager
def genai_agent_invocation(
    *, agent_name: str, request_model: str, provider: str, agent_type: Optional[str] = None,
    system: Optional[str] = None, messages: Optional[list] = None,
):
    """Emit a GenAI AgentInvocation (so the named agent appears in Splunk's "AI
    agents" view) wrapping a nested LLMInvocation, via the util-genai handler. The
    handler automatically inherits the agent name/id onto the LLM and nests its
    span under the agent. Pass ``system`` + ``messages`` so both spans carry the
    prompt. Yields the nested LLMInvocation — set token usage / ``response`` via
    ``record_genai_output`` inside the block — or None when the handler is
    unavailable."""
    handler = _get_handler()
    if handler is None:
        yield None
        return
    from opentelemetry.util.genai.types import AgentInvocation, LLMInvocation

    _inputs = _input_messages(system, messages)
    agent = AgentInvocation(
        name=agent_name, model=request_model, agent_type=agent_type,
        provider=provider, system=provider,
        system_instructions=system, input_messages=list(_inputs),
    )
    inv = LLMInvocation(
        request_model=request_model, operation=OP_CHAT,
        provider=provider, system=provider,
        input_messages=list(_inputs),
    )
    handler.start_agent(agent)
    handler.start_llm(inv)
    try:
        yield inv
    except Exception as exc:  # noqa: BLE001 - mark spans errored, then re-raise
        err = _genai_error(exc)
        for fail, stop, obj in (
            (handler.fail_llm, handler.stop_llm, inv),
            (handler.fail_agent, handler.stop_agent, agent),
        ):
            try:
                fail(obj, err) if err else stop(obj)
            except Exception:  # noqa: BLE001
                pass
        raise
    else:
        # Mirror the LLM's response onto the agent span so the agent operation row
        # in AI trace data also carries the completion content.
        try:
            if getattr(inv, "output_messages", None):
                agent.output_messages = list(inv.output_messages)
        except Exception:  # noqa: BLE001
            pass
        try:
            handler.stop_llm(inv)
            handler.stop_agent(agent)
        except Exception:  # noqa: BLE001
            pass
