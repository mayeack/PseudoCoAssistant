"""Splunk Agent Observability emission of completed chat turns.

Each completed chat turn — the governance ``chat``/``output`` event, the one
chokepoint that carries the safety / PII / toxicity / policy / evaluation picture —
is sent to Splunk Agent Observability (the ``splunk-ao`` SDK in Observability
Cloud mode: OTLP/HTTP to ``ingest.<realm>.observability.splunkcloud.com``) as one
trace::

    workflow "chat_turn"                      governance metadata on every span
      agent <coordinator>   (AgentType.supervisor)
        llm  <model>        real token usage + wall time
      agent <specialist> ... / <synthesizer>
        llm  ...

or, for a turn without an ``agent_trace`` (legacy engine, blocked turns), the
workflow span wrapping a single LLM span. Every span carries the governance
metadata plus ``pseudoco_assistant_trace_id`` — the turn's OTel trace id, the same value
as the governance event's ``trace_id``, the span attribute ``pseudoco-assistant.trace_id``
and the trace id Splunk APM shows — so an Agent Observability trace can be joined back
to APM and the governance logs. (The Agent Observability trace's own id is minted by
the SDK, which takes no trace id, so the join runs through that metadata field.)
PseudoCo Assistant's ``session_id`` (one
conversation) is mapped to an Agent Observability session, best-effort.

Why the SDK logger and not the LangChain callback: the governance flags are
computed by the safety / injection / governance graph nodes *after* the domain
agent's LLM call, so a callback (which fires when that call returns) cannot carry
them. (Raw ``gen_ai.*`` spans still reach Agent Observability through the OTel
Collector overlay ``otel-collector-agent-obs.yaml`` for the model/token view.)

Agent stream per theme: a turn is logged to the stream named after its theme's
own label (``medadvice`` -> ``MedAdvice``), so each vertical is its own Agent
stream in the console rather than every theme sharing one. The label is read from
the theme registry, so a new theme needs no change here; an unresolvable theme
falls back to ``SPLUNK_AO_AGENT_STREAM``, and setting
``SPLUNK_AO_AGENT_STREAM_PER_THEME=False`` pins every turn to that one stream.

Lifecycle: one long-lived ``SplunkAOLogger`` per agent stream (the stream is
fixed at construction), owned by a single daemon worker thread that drains a
bounded queue; the request path does an env check and a ``put_nowait`` — nothing
else. Loggers are built lazily on the first turn of a theme and are bounded by
the registry, so an idle theme costs nothing. Verified against splunk-ao 0.4.0: the
logger is not thread-safe, every instance owns a BatchSpanProcessor thread, a
private TracerProvider and atexit hooks, and the SDK's own singleton keys loggers
by *thread name* — so per-turn construction leaks and a per-turn thread would
mint a new logger every time.

Fully defensive: a no-op when the ``splunk_ao`` package is missing or
``SPLUNK_AO_O11Y_TOKEN`` / ``SPLUNK_AO_REALM`` are unset; never raises into a
chat turn; never adds request latency. Never imports the legacy ``galileo``
package (kept installed only for ``scripts/demo/galileo_*.py``). TLS uses the CA
bundle that ``backend.config`` sets via ``SSL_CERT_FILE`` / ``REQUESTS_CA_BUNDLE``
at import.

Surviving a network change (added after the 2026-09-09 stall: the Mac moved
networks, the worker blocked inside the SDK on sockets bound to the old
interface, and the app kept answering chat turns for six days while nothing
reached Agent Observability and the app log said nothing at all). The SDK has
one wait with no deadline at all — ``start_session`` runs its coroutine on a
galileo-core event-loop thread and blocks on ``future.result()`` with no
timeout — and one budget it does not enforce: ``flush`` reaches
``BatchProcessor.force_flush``, which discards its ``timeout_millis`` and
drains the whole span queue synchronously. Three guards, in order:

* **Bounded calls.** Every SDK call that can touch the network
  (``start_session``, ``flush``, ``terminate``) runs through ``_bounded_call``:
  on a daemon thread with a hard deadline. An overrun is an emit failure that
  tears the logger down and rebuilds it — new exporter, new sockets on the new
  interface. The wedged call is abandoned on its thread; nothing waits for it.
* **A bounded export.** ``_bounded_sink`` builds the SDK's own O11y exporter
  with an explicit per-POST ``timeout`` and a bounded span queue, so a healthy
  ``flush`` against a black-holed socket costs a number we can state
  (``_EXPORT_TIMEOUT_S`` x export rounds), well inside the call deadline.
* **A stall signal.** ``_check_stall`` warns once per wedged turn and
  ``status()`` reports it — the last resort for a hang outside the bounded
  calls. It runs on the REQUEST path, not just the worker's idle tick: a worker
  blocked inside the SDK never reaches its own idle tick, which is precisely why
  the 9/09 stall was invisible.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

QUEUE_MAXSIZE = 500
_MAX_CONSECUTIVE_FAILURES = 5      # then terminate + rebuild the logger
_BUILD_BACKOFF_S = 60.0            # after a failed SplunkAOLogger() build
_SESSION_BACKOFF_S = 300.0         # after start_session fails
_SESSION_CACHE_SIZE = 512
_DRAIN_ON_SHUTDOWN_S = 5.0
_FAILURE_TRACEBACK_EVERY_S = 60.0
# Export bounds (see _bounded_sink). One drain is at most
# ceil(_EXPORT_QUEUE_SIZE / _EXPORT_BATCH_SIZE) export rounds of
# _EXPORT_TIMEOUT_S each, so a flush against a black-holed socket costs ~16 s,
# not an open-ended number of rounds at the ambient OTel default.
_EXPORT_TIMEOUT_S = 8.0
_EXPORT_QUEUE_SIZE = 1024
_EXPORT_BATCH_SIZE = 512
# Hard deadline on any one SDK call that can touch the network (see
# _bounded_call). Generous next to a healthy call (< 1 s) and to the bounded
# flush above; a session lookup slower than this is as good as failed.
_CALL_TIMEOUT_S = 30.0
# A turn still in flight this long means the worker is wedged OUTSIDE the
# bounded calls: a fully failing turn is at most two call deadlines. Warned once
# per wedged turn, reported by status().
_STALL_WARN_AFTER_S = 120.0
_SDK_LOGGER = "splunk_ao"
_DEFAULT_PROJECT = "PseudoCo Assistant"
_DEFAULT_AGENT_STREAM = "PseudoCo Assistant"
_ROOT_SPAN_NAME = "chat_turn"
_STOP = object()
_WAKE = object()

# Fields from the governance log JSON carried into Agent Observability as span
# metadata (the SDK does not export the trace envelope, so metadata rides on the
# workflow / agent / llm spans).
_GOVERNANCE_KEYS = (
    "session_id", "request_id", "conversation_id",
    "provider_name", "request_model", "response_model",
    "service_name", "deployment_id", "enduser_id",
    "safety_violated", "safety_categories", "guardrail_triggered",
    "policy_blocked", "pii_detected", "pii_types",
    "toxic_detected", "toxic_types",
    "evaluation_score_value", "evaluation_score_label",
    "response_finish_reasons", "client_operation_duration",
    # The LLM span carries only a flat output-token count, so the cache split
    # rides in the span metadata instead (the two sum to that count).
    "usage_output_tokens_cached", "usage_output_tokens_uncached",
)


class TurnEmitError(RuntimeError):
    """start_trace failed (returned None or raised) — the turn cannot be built."""


class SdkCallTimeout(RuntimeError):
    """An SDK call overran ``_CALL_TIMEOUT_S`` and was abandoned on its thread."""


# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
@dataclass
class _Runtime:
    queue: "queue.Queue[Any]"
    lock: threading.Lock
    stop_event: threading.Event
    thread: Optional[threading.Thread] = None
    generation: int = 0                 # bumped by reconfigure(); read under lock
    dropped: int = 0
    drop_warned: bool = False
    # ---- worker-owned below: touched only on the worker thread ----
    # One SDK logger per agent stream: the stream is fixed at construction, so a
    # per-theme stream means a logger per theme. Bounded by the theme registry
    # (see _stream_for), built lazily on the first turn of that theme.
    loggers: "Dict[str, Any]" = field(default_factory=dict)
    logger_generation: int = -1
    build_backoff_until: float = 0.0
    last_build_error: str = ""
    last_sink_error: str = ""
    consecutive_failures: int = 0
    last_failure_traceback_at: float = 0.0
    sessions: "OrderedDict[str, str]" = field(default_factory=OrderedDict)
    sessions_unavailable_until: float = 0.0
    session_warned: bool = False
    # Surfaced by status(): a sessions 401 used to be invisible outside the log,
    # which is how an unset SPLUNK_AO_O11Y_API_TOKEN went unnoticed for weeks
    # (turns kept logging, just ungrouped). None = not attempted yet. The last
    # error is also the dedupe key: a NEW cause (a timeout after the known 401)
    # warns again.
    sessions_ok: Optional[bool] = None
    sessions_last_error: str = ""
    turns_logged: int = 0
    # ---- stall detection: written by the worker, READ off it ----
    # Plain float reads/writes, no lock: the reader only ever sees the previous
    # or the next value, and a stale read costs one extra elapsed computation.
    turn_started_at: float = 0.0        # monotonic; 0.0 = the worker is idle
    turn_started_desc: str = ""         # request_id of the in-flight turn
    turn_completed_at: float = 0.0      # monotonic of the last turn that returned
    stall_warned_for: float = 0.0       # the turn_started_at already warned about
    stalls: int = 0
    abandoned_calls: int = 0            # SDK calls left running past their deadline


def _new_runtime(maxsize: int = QUEUE_MAXSIZE) -> _Runtime:
    return _Runtime(queue=queue.Queue(maxsize=maxsize), lock=threading.Lock(),
                    stop_event=threading.Event())


_rt = _new_runtime()


# ---------------------------------------------------------------------------
# Public API (request path + hooks)
# ---------------------------------------------------------------------------
def is_enabled() -> bool:
    """Emission is on only while ``SPLUNK_AO_O11Y_TOKEN`` and ``SPLUNK_AO_REALM``
    are both set in the process environment — read at CALL time, so a Settings
    save applies on the next turn — and the SDK kill switch
    ``SPLUNK_AO_LOGGING_DISABLED`` is not truthy (with it set every SDK method
    returns None and every turn would count as a failure). Explicit variables
    only: no fallback to ``SPLUNK_REALM`` / ``O11Y_INGEST``."""
    if not (os.getenv("SPLUNK_AO_O11Y_TOKEN") and os.getenv("SPLUNK_AO_REALM")):
        return False
    return os.getenv("SPLUNK_AO_LOGGING_DISABLED", "false").strip().lower() not in ("true", "1", "t")


def maybe_log_turn(log_data: Dict[str, Any]) -> None:
    """Entry point called by ``governance_logger._write_log`` for EVERY event.
    Gates to completed chat turns, copies, enqueues. Never blocks, never raises."""
    if not is_enabled():
        return
    if log_data.get("operation_name") != "chat" or log_data.get("token_type") != "output":
        return
    try:
        _ensure_worker()
        _rt.queue.put_nowait(dict(log_data))
    except queue.Full:
        _rt.dropped += 1
        if not _rt.drop_warned:
            logger.warning("agent observability: queue full (%d); dropping turns until it drains",
                           _rt.queue.maxsize)
            _rt.drop_warned = True
        else:
            logger.debug("agent observability: dropped turn (%d total)", _rt.dropped)
    except Exception:  # noqa: BLE001 - must never break a chat turn
        logger.debug("agent observability: enqueue failed", exc_info=True)
    try:
        _check_stall()                    # after the enqueue: a wedged worker cannot report itself
    except Exception:  # noqa: BLE001
        logger.debug("agent observability: stall check failed", exc_info=True)


def reconfigure() -> None:
    """Settings changed (``settings_store._reconfigure_integration``): retire the
    live logger and rebuild lazily from the CURRENT environment on the next turn
    (new token / realm / project / agent stream). Non-blocking — safe from the
    event loop. Does not start the worker (nothing to retire if it never ran)."""
    with _rt.lock:
        _rt.generation += 1
        started = _rt.thread is not None and _rt.thread.is_alive()
    if started:
        try:
            _rt.queue.put_nowait(_WAKE)   # wake an idle worker so the stale exporter dies now
        except queue.Full:
            pass                          # the generation check runs before the next turn anyway


def shutdown(timeout: float = 10.0) -> None:
    """``main.py`` shutdown hook: drain briefly, terminate the logger. Bounded and
    idempotent."""
    with _rt.lock:
        t = _rt.thread
    if t is None or not t.is_alive():
        return
    _rt.stop_event.set()
    try:
        _rt.queue.put(_STOP, timeout=1.0)
    except queue.Full:
        pass                              # stop_event is checked on every idle tick
    t.join(timeout)
    if t.is_alive():
        logger.warning("agent observability: worker did not stop within %.0fs", timeout)


def status() -> Dict[str, Any]:
    """Diagnostics snapshot (never raises, never logs).

    ``worker_alive`` is not enough to tell a healthy emitter from a wedged one:
    a worker blocked inside the SDK is still a live thread. ``stalled`` /
    ``turn_in_flight_s`` are what separate the two."""
    with _rt.lock:
        alive = _rt.thread is not None and _rt.thread.is_alive()
    in_flight = _in_flight_s()
    return {
        "enabled": is_enabled(),
        "worker_alive": alive,
        "queued": _rt.queue.qsize(),
        "dropped": _rt.dropped,
        "turns_logged": _rt.turns_logged,
        "logger_ready": bool(_rt.loggers),
        "last_build_error": _rt.last_build_error,
        "sessions_cached": len(_rt.sessions),
        "sessions_ok": _rt.sessions_ok,
        "sessions_last_error": _rt.sessions_last_error,
        "stalled": in_flight >= _STALL_WARN_AFTER_S,
        "turn_in_flight_s": round(in_flight, 1),
        "stalls": _rt.stalls,
        "abandoned_calls": _rt.abandoned_calls,
        "last_turn_completed_s_ago": (
            round(time.monotonic() - _rt.turn_completed_at, 1) if _rt.turn_completed_at else None
        ),
        "project": os.getenv("SPLUNK_AO_PROJECT") or _DEFAULT_PROJECT,
        "agent_stream": _default_stream(),
        "agent_stream_per_theme": _per_theme_streams(),
        "agent_streams_live": sorted(_rt.loggers),
    }


# ---------------------------------------------------------------------------
# Bounded SDK calls (worker thread only)
# ---------------------------------------------------------------------------
def _bounded_call(what: str, fn, *args, timeout: Optional[float] = None, **kwargs):
    """Run one SDK call that can touch the network under a hard deadline.

    The call runs on a throwaway DAEMON thread and the worker joins it with a
    timeout. A Python thread cannot be interrupted, so on overrun the call is
    abandoned where it is — it keeps its thread until (if ever) the SDK returns
    — and ``SdkCallTimeout`` is raised on the worker, which tears the logger
    down and rebuilds it rather than reuse an instance whose I/O is wedged.

    A daemon thread rather than a ``ThreadPoolExecutor``: since Python 3.9
    executor workers are joined at interpreter exit, so one wedged call would
    also hang shutdown. Thread creation costs ~0.1 ms per call, nothing next to
    the request it wraps."""
    if timeout is None:
        timeout = _CALL_TIMEOUT_S
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the worker below
            box["error"] = exc

    t = threading.Thread(target=run, name=f"agent-observability-io:{what}", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        _rt.abandoned_calls += 1
        raise SdkCallTimeout(f"{what} exceeded {timeout:.0f}s; call abandoned on its thread")
    if "error" in box:
        raise box["error"]
    return box.get("value")


# ---------------------------------------------------------------------------
# Stall detection
# ---------------------------------------------------------------------------
def _in_flight_s() -> float:
    """Seconds the worker has been inside the current turn (0.0 when idle)."""
    started = _rt.turn_started_at
    return max(0.0, time.monotonic() - started) if started else 0.0


def _check_stall() -> None:
    """Emit ONE WARNING per wedged turn.

    Called from ``maybe_log_turn`` — the request path — and deliberately NOT
    from the worker: the failure mode is a worker blocked *inside* the SDK,
    which never gets back to its loop, and its idle tick only ever runs between
    turns, when there is nothing in flight to report. On 2026-09-09 that left
    the app streaming nothing for six days while every static check passed —
    ``is_enabled()`` True, the module imported, the queue below its 500-slot
    warning threshold and chat turns answering normally."""
    started = _rt.turn_started_at
    if not started:
        return
    elapsed = time.monotonic() - started
    if elapsed < _STALL_WARN_AFTER_S or _rt.stall_warned_for == started:
        return
    _rt.stall_warned_for = started
    _rt.stalls += 1
    logger.warning(
        "agent observability: WORKER STALLED — turn %s has been in flight %.0fs "
        "(>%.0fs) and %d turn(s) are queued behind it; nothing is reaching Agent "
        "Observability. Check for dead sockets to the ingest endpoint "
        "(lsof -nP -a -p <pid> -i) and restart the app to clear it.",
        _rt.turn_started_desc or "?", elapsed, _STALL_WARN_AFTER_S, _rt.queue.qsize(),
    )


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
def _ensure_worker() -> None:
    if _rt.thread is not None and _rt.thread.is_alive():
        return
    with _rt.lock:
        if _rt.thread is not None and _rt.thread.is_alive():
            return
        _rt.stop_event.clear()
        _rt.thread = threading.Thread(target=_worker_loop, name="agent-observability", daemon=True)
        _rt.thread.start()


def _worker_loop() -> None:
    while True:
        try:
            item = _rt.queue.get(timeout=1.0)
        except queue.Empty:
            if _rt.stop_event.is_set():
                break
            _maybe_retire_logger()        # idle tick: a Settings save retires the stale exporter within ~1 s
            continue                      # (no stall check here: idle means no turn in flight — see _check_stall)
        try:
            if item is _STOP:
                break
            if item is _WAKE:
                _maybe_retire_logger()
                continue
            _process_turn(item)
        except BaseException:              # noqa: BLE001 - the loop must survive anything
            logger.warning("agent observability: unexpected worker error", exc_info=True)
        finally:
            _rt.queue.task_done()
    # shutdown: bounded drain, then release the SDK's threads
    deadline = time.monotonic() + _DRAIN_ON_SHUTDOWN_S
    while time.monotonic() < deadline:
        try:
            item = _rt.queue.get_nowait()
        except queue.Empty:
            break
        try:
            if item is not _STOP and item is not _WAKE:
                _process_turn(item)
        except BaseException:              # noqa: BLE001
            logger.debug("agent observability: drain error", exc_info=True)
        finally:
            _rt.queue.task_done()
    _terminate_logger()


# ---------------------------------------------------------------------------
# Agent stream selection (worker thread only)
# ---------------------------------------------------------------------------
def _default_stream() -> str:
    """The stream for turns whose theme cannot be resolved, and the one the
    collector overlay sends its raw gen_ai spans to."""
    return os.getenv("SPLUNK_AO_AGENT_STREAM") or _DEFAULT_AGENT_STREAM


def _per_theme_streams() -> bool:
    """True unless ``SPLUNK_AO_AGENT_STREAM_PER_THEME`` is falsey, which pins
    every turn to ``SPLUNK_AO_AGENT_STREAM``."""
    return os.getenv("SPLUNK_AO_AGENT_STREAM_PER_THEME", "true").strip().lower() \
        not in ("false", "0", "f", "no", "off")


def _stream_for(log_data: Dict[str, Any]) -> str:
    """Agent stream for this turn: the theme's own label — ``medadvice`` ->
    ``MedAdvice`` — so each vertical lands in its own stream in the console
    instead of every theme sharing one.

    The label comes from the theme REGISTRY, never from the raw request value:
    an unknown (or hostile) theme falls back to the default stream, so the
    number of live loggers is bounded by the number of themes + 1."""
    if not _per_theme_streams():
        return _default_stream()
    theme = log_data.get("theme")
    if not theme:
        return _default_stream()
    try:
        from backend.agents.themes import THEMES   # lazy: keeps this module importable standalone
    except Exception:  # noqa: BLE001
        return _default_stream()
    cfg = THEMES.get(str(theme).strip().lower())
    return cfg.label if cfg is not None else _default_stream()


# ---------------------------------------------------------------------------
# Logger lifecycle (worker thread only)
# ---------------------------------------------------------------------------
def _maybe_retire_logger() -> None:
    """Terminate every live logger if ``reconfigure()`` bumped the generation
    since they were built; also forget sessions (they belong to a project/stream),
    failure counters, backoffs and one-time-warning flags."""
    with _rt.lock:
        gen = _rt.generation
    if _rt.loggers and _rt.logger_generation != gen:
        logger.info("agent observability: configuration changed; retiring %d logger(s)",
                    len(_rt.loggers))
        _terminate_logger()
        _rt.sessions.clear()
        _rt.sessions_unavailable_until = 0.0
        _rt.session_warned = False
        _rt.sessions_ok = None            # not attempted yet under the new configuration
        _rt.sessions_last_error = ""
        _rt.consecutive_failures = 0
        _rt.build_backoff_until = 0.0
        _rt.last_build_error = ""
        _rt.last_sink_error = ""


def _terminate_logger() -> None:
    """Terminate every stream's logger (an ingest problem is never one stream's)."""
    loggers, _rt.loggers = list(_rt.loggers.values()), {}
    for lg in loggers:
        try:
            # idempotent; force_flush + sink shutdown — both block on the same
            # export lock a wedged flush holds, hence bounded
            _bounded_call("terminate", lg.terminate)
        except Exception:  # noqa: BLE001 - the reference is dropped either way
            logger.debug("agent observability: terminate failed", exc_info=True)


def _ensure_logger(stream: str):
    """Return the live ``SplunkAOLogger`` for ``stream``, building it lazily.
    ``None`` when a build failed recently (60 s backoff, shared across streams
    because the cause is the token/realm/ingest) — the caller drops the turn."""
    _maybe_retire_logger()
    lg = _rt.loggers.get(stream)
    if lg is not None:
        return lg
    now = time.monotonic()
    if now < _rt.build_backoff_until:
        return None
    with _rt.lock:
        gen = _rt.generation              # capture BEFORE building: a reconfigure() during the build retires it next tick
    try:
        lg = _build_logger(stream)
    except Exception as exc:  # noqa: BLE001 - MissingConfigurationError, AmbiguousConfigurationError, ImportError, ...
        msg = f"{type(exc).__name__}: {exc}"
        if msg != _rt.last_build_error:   # one WARNING per distinct cause
            logger.warning("agent observability: cannot build SplunkAOLogger (%s); retrying in %.0fs",
                           msg, _BUILD_BACKOFF_S, exc_info=True)
            _rt.last_build_error = msg
        _rt.build_backoff_until = now + _BUILD_BACKOFF_S
        return None
    _rt.loggers[stream] = lg
    _rt.logger_generation, _rt.last_build_error = gen, ""
    logger.info("agent observability: logger ready (realm=%s, project=%s, agent_stream=%s)",
                os.getenv("SPLUNK_AO_REALM"), getattr(lg, "project_name", None),
                getattr(lg, "agent_stream_name", None))
    return lg


def _build_logger(stream: str):
    """Construct the SDK logger from the current environment. Observability Cloud
    mode is auto-detected from ``SPLUNK_AO_REALM`` / ``SPLUNK_AO_O11Y_TOKEN``; no
    network call happens here (the exporter is built, the project and agent
    stream are created server-side on first ingest)."""
    # The SDK mutes its own "splunk_ao" logger tree unless a level is configured;
    # ingest/auth problems would otherwise be invisible in the app log. Set both
    # the env knob the SDK honours and the logger level before the first import.
    os.environ.setdefault("SPLUNK_AO_LOG_LEVEL", "WARNING")
    sdk_log = logging.getLogger(_SDK_LOGGER)
    if sdk_log.level == logging.NOTSET or sdk_log.level > logging.WARNING:
        sdk_log.setLevel(logging.WARNING)
    from splunk_ao import SplunkAOLogger  # lazy: keeps the module importable without the package
    project = os.getenv("SPLUNK_AO_PROJECT") or _DEFAULT_PROJECT
    sink = _bounded_sink(project, stream)
    if sink is None:                      # SDK shape drifted; unbounded but working
        return SplunkAOLogger(project=project, agent_stream=stream)
    return SplunkAOLogger(project=project, agent_stream=stream, _sink=sink)


def _bounded_sink(project: str, stream: str):
    """The SDK's own O11y span sink, built with an explicit export budget.

    Why this is not left to the SDK's default: ``SplunkAOLogger`` builds its sink
    as ``build_span_sink(build_o11y_exporter(...))`` with no timeout and no batch
    config, so the per-POST timeout falls back to whatever ``OTEL_EXPORTER_OTLP_*``
    happens to be in the environment and the span queue keeps the OTel default of
    2048. That matters because the SDK's flush budget is NOT enforced anywhere:
    ``lg.flush()`` -> ``SpanSink.force_flush(30000)`` -> ``TracerProvider.force_flush``
    -> ``BatchProcessor.force_flush``, which discards ``timeout_millis`` outright
    and drains the entire queue synchronously, one export round per
    ``max_export_batch_size`` spans, under a lock it shares with the SDK's own
    batch thread. Against a black-holed socket each round costs a full timeout, so
    the only way to bound the worker's time in ``flush()`` is to bound both
    numbers here.

    ``_sink`` is the constructor's injection seam; the three builders below are
    public module functions in splunk-ao 0.4.0. Returns None (and warns once) if
    any of that drifts, so a future SDK loses the bound but never loses emission.

    NOTE for reviewers: this is deliberately NOT a timeout on
    ``splunk_ao/resources/client.py`` (whose ``_timeout`` field does default to
    ``None``). That generated ``Client`` / ``AuthenticatedClient`` pair is never
    instantiated on this path — the generated API functions are handed
    ``config.api_client`` and call ``.request()`` on it, which is a galileo-core
    ``ApiClient`` that already builds httpx with ``Timeout(60.0, connect=5.0)``.
    And the ingest path is not httpx at all; it is the OTel ``OTLPSpanExporter``
    over ``requests`` (traced against splunk-ao 0.4.0 and its galileo-core)."""
    try:
        from splunk_ao.deployment import DeploymentMode, O11yConfig, resolve_deployment
        from splunk_ao.exporter.config import resolve_routing
        from splunk_ao.exporter.o11y import build_o11y_exporter
        from splunk_ao.exporter.sink import BatchConfig, build_span_sink

        if resolve_deployment() != DeploymentMode.O11Y:
            return None                   # standalone mode builds a different exporter
        routing = resolve_routing(DeploymentMode.O11Y, project=project, agent_stream=stream)
        exporter = build_o11y_exporter(O11yConfig.from_env(), routing, timeout=_EXPORT_TIMEOUT_S)
        return build_span_sink(exporter, BatchConfig(max_queue_size=_EXPORT_QUEUE_SIZE,
                                                    max_export_batch_size=_EXPORT_BATCH_SIZE))
    except Exception as exc:  # noqa: BLE001 - never block the build over the bound
        msg = f"{type(exc).__name__}: {exc}"
        if msg != _rt.last_sink_error:    # one WARNING per distinct cause
            logger.warning("agent observability: cannot bound the export timeout (%s); "
                           "falling back to the SDK default sink", msg, exc_info=True)
            _rt.last_sink_error = msg
        return None


# ---------------------------------------------------------------------------
# Per-turn processing (worker thread only)
# ---------------------------------------------------------------------------
def _process_turn(log_data: Dict[str, Any]) -> None:
    """Mark the turn in flight, emit it, mark it done.

    The markers are the only trace a wedged worker leaves: everything inside
    ``_emit_turn`` logs on success and on failure, but a thread blocked in the
    SDK reaches neither."""
    _rt.turn_started_desc = str(log_data.get("request_id") or "?")
    _rt.turn_started_at = time.monotonic()
    try:
        _emit_turn(log_data)
    finally:
        _rt.turn_completed_at = time.monotonic()
        _rt.turn_started_at = 0.0


def _emit_turn(log_data: Dict[str, Any]) -> None:
    stream = _stream_for(log_data)
    lg = _ensure_logger(stream)
    if lg is None:
        _rt.dropped += 1
        return
    model = log_data.get("response_model") or log_data.get("request_model") or "unknown"
    agents = len(log_data.get("agent_trace") or []) or 1
    try:
        _recover_dangling(lg)
        ao_sid = _session_for(lg, stream, log_data.get("session_id"))
        if ao_sid:
            lg.set_session(ao_sid)
        else:
            lg.clear_session()            # never let the previous turn's session leak onto this one
        _build_turn(lg, log_data)
        flush_errors: List[BaseException] = []
        _bounded_call("flush", lg.flush, on_error=flush_errors.append)
        _rt.consecutive_failures = 0
        _rt.turns_logged += 1
        logger.info(
            "agent observability: logged turn (model=%s, agents=%s, project=%s, agent_stream=%s, export=%s)",
            model, agents, getattr(lg, "project_name", None), getattr(lg, "agent_stream_name", None),
            _export_label(lg, flush_errors),
        )
    except Exception as exc:  # noqa: BLE001 - emission must never escape the worker loop
        _rt.consecutive_failures += 1
        _log_turn_failure(model, exc)
        try:
            lg.reset_parent_tracking()
        except Exception:  # noqa: BLE001
            pass
        if isinstance(exc, SdkCallTimeout):
            # Its I/O is wedged (dead sockets after a network move, a stuck
            # event-loop future): rebuild now, on fresh sockets, rather than
            # pay the deadline N more times on the same instance.
            logger.warning(
                "agent observability: %s; terminating and rebuilding the logger in %.0fs",
                exc, _BUILD_BACKOFF_S,
            )
        elif _rt.consecutive_failures < _MAX_CONSECUTIVE_FAILURES:
            return
        else:
            logger.warning(
                "agent observability: %d consecutive failures; terminating and rebuilding the logger in %.0fs",
                _rt.consecutive_failures, _BUILD_BACKOFF_S,
            )
        _terminate_logger()
        _rt.consecutive_failures = 0
        _rt.build_backoff_until = time.monotonic() + _BUILD_BACKOFF_S


def _export_label(lg, flush_errors) -> str:
    """``healthy`` | ``rejected(n)`` | ``unknown`` | ``flush-error(...)`` from the
    SDK's ``export_health``. ``unknown`` also follows transport failures (401,
    DNS, timeout): the SDK records unknown on non-2xx and the real cause is
    logged by the OTel exporter under
    ``opentelemetry.exporter.otlp.proto.http.trace_exporter``."""
    if flush_errors:
        return f"flush-error({flush_errors[-1]})"[:160]
    health = getattr(lg, "export_health", None)
    healthy = getattr(health, "healthy", None)
    if healthy is True:
        return "healthy"
    if healthy is False:
        return f"rejected({getattr(health, 'consecutive_failures', 0)})"
    return "unknown"


def _recover_dangling(lg) -> None:
    """A previous build that died half-way leaves a parent on the logger; in
    splunk-ao 0.4.0 ``start_trace`` then RAISES ``ValueError`` (not swallowed)."""
    try:
        dangling = bool(lg.has_active_trace()) or lg.current_parent() is not None
    except Exception:  # noqa: BLE001
        dangling = True
    if dangling:
        logger.debug("agent observability: concluding a dangling trace")
        lg.conclude(conclude_all=True)
        lg.reset_parent_tracking()


def _session_for(lg, stream: str, session_id) -> Optional[str]:
    """PseudoCo Assistant ``session_id`` -> Agent Observability session id, once per session
    (LRU of 512). Keyed by stream as well: a session belongs to one agent stream,
    so the same chat session seen under two themes needs one session per stream.
    Best-effort: on failure warn once, back off five minutes and return None (the
    turn is still logged, just without a session)."""
    if not session_id:
        return None
    sid = str(session_id)
    key = f"{stream}\x00{sid}"
    cached = _rt.sessions.get(key)
    if cached:
        _rt.sessions.move_to_end(key)
        return cached
    now = time.monotonic()
    if now < _rt.sessions_unavailable_until:
        return None
    try:
        # Bounded: the SDK runs this on a galileo-core event-loop thread and
        # waits on future.result() with NO timeout — the one truly open-ended
        # wait on the turn, and it comes before flush.
        ao = _bounded_call("start_session", lg.start_session,
                           name=f"chat session {sid[:8]}", external_id=sid)
        if not ao:
            raise RuntimeError("start_session returned None")
    except Exception as exc:  # noqa: BLE001 - CRUD 401/403, project lookup, SdkCallTimeout, ...
        # The SDK's own message tells you to set SPLUNK_AO_API_KEY. Do not: that
        # is the standalone-mode variable, and resolve_deployment() raises
        # AmbiguousConfigurationError when it is set alongside an O11y one. The
        # sessions API is reached with SPLUNK_AO_O11Y_API_TOKEN, and when that is
        # unset the SDK silently falls back to the ingest token (crud_token in
        # splunk_ao/deployment.py), which the API rejects. Say so plainly.
        detail = f"{type(exc).__name__}: {exc}"
        if not os.getenv("SPLUNK_AO_O11Y_API_TOKEN"):
            detail = ("SPLUNK_AO_O11Y_API_TOKEN is not set, so the SDK fell back to the "
                      "ingest token, which the sessions API rejects. Set an Observability "
                      "Cloud API token with Agent Observability access and restart the app "
                      f"(underlying error: {detail})")
        # Once per cause: the standing missing-token 401 warns exactly once, and
        # a later, different failure (a start_session timeout) still gets a line.
        is_new_cause = not _rt.session_warned or detail != _rt.sessions_last_error
        _rt.sessions_ok = False
        _rt.sessions_last_error = detail
        if is_new_cause:
            logger.warning(
                "agent observability: sessions unavailable (%s); logging turns without a session, retry in %d min",
                detail, int(_SESSION_BACKOFF_S // 60),
                # Traceback only when the cause is not the known missing-token
                # case; that one is fully explained by the message above.
                exc_info=bool(os.getenv("SPLUNK_AO_O11Y_API_TOKEN")),
            )
            _rt.session_warned = True
        _rt.sessions_unavailable_until = now + _SESSION_BACKOFF_S
        return None
    _rt.sessions_ok = True
    _rt.sessions_last_error = ""
    _rt.session_warned = False
    _rt.sessions[key] = str(ao)
    while len(_rt.sessions) > _SESSION_CACHE_SIZE:
        _rt.sessions.popitem(last=False)
    return str(ao)


def _log_turn_failure(model: str, exc: BaseException) -> None:
    """WARNING (not debug): an outage leaves the Agent Observability pillar silently
    empty during a workshop, and debug is below the default console threshold. A
    traceback at most once a minute, a one-liner (still naming the cause) otherwise."""
    now = time.monotonic()
    with_tb = now - _rt.last_failure_traceback_at >= _FAILURE_TRACEBACK_EVERY_S
    if with_tb:
        _rt.last_failure_traceback_at = now
    logger.warning("agent observability: emit failed (model=%s, consecutive=%d, cause=%s: %s)",
                   model, _rt.consecutive_failures, type(exc).__name__, exc, exc_info=with_tb)


# ---------------------------------------------------------------------------
# Pure turn builder (the test seam)
# ---------------------------------------------------------------------------
def _build_turn(lg, log_data: Dict[str, Any]) -> None:
    """Emit one turn through ``lg`` (anything with the SplunkAOLogger span API).
    No module state, no session handling, no flush, no logging — tests drive it
    with a fake logger. Raises ``TurnEmitError`` when ``start_trace`` fails.

    The SDK never exports the trace envelope: the ``chat_turn`` workflow span is
    the root that lands in Agent Observability, so the governance metadata rides on
    it and on every child, and durations/timestamps are set per span (a child's
    default ``created_at`` is "now" at emission time, i.e. after the turn)."""
    inp = _text(log_data.get("input_messages")) or log_data.get("user_prompt", "") or "(empty)"
    out = _text(log_data.get("output_messages")) or log_data.get("response_text", "") or "(empty)"
    model = log_data.get("response_model") or log_data.get("request_model") or "unknown"
    meta = {k: _coerce(log_data.get(k)) for k in _GOVERNANCE_KEYS if log_data.get(k) is not None}
    if log_data.get("trace_id"):
        meta["pseudoco_assistant_trace_id"] = str(log_data["trace_id"])
    agent_trace = log_data.get("agent_trace") or []
    request_id = log_data.get("request_id")
    turn_ns = _seconds_to_ns(log_data.get("client_operation_duration"))
    turn_end = _parse_ts(log_data.get("timestamp"))
    turn_start = (turn_end - timedelta(microseconds=turn_ns / 1000)) if (turn_end and turn_ns) else turn_end

    try:
        trace = lg.start_trace(input=inp, name="chat turn", metadata=meta, created_at=turn_start,
                               external_id=str(request_id) if request_id else None)
    except Exception as exc:  # noqa: BLE001 - ValueError on a dangling parent is NOT swallowed in 0.4.0
        raise TurnEmitError(f"start_trace raised {type(exc).__name__}: {exc}") from exc
    if trace is None:                     # swallowed infrastructure error or SPLUNK_AO_LOGGING_DISABLED
        raise TurnEmitError("start_trace returned None")

    lg.add_workflow_span(input=inp, output=out, name=_ROOT_SPAN_NAME, metadata=meta,
                         created_at=turn_start, duration_ns=turn_ns)
    if agent_trace:
        _add_agent_spans(lg, agent_trace, inp, model, meta, turn_start)
    else:
        lg.add_llm_span(input=inp, output=out, model=model, name="chat",
                        num_input_tokens=log_data.get("usage_input_tokens"),
                        num_output_tokens=log_data.get("usage_output_tokens"),
                        total_tokens=log_data.get("usage_total_tokens"),
                        duration_ns=turn_ns, created_at=turn_start, metadata=meta)
    _add_control_spans(lg, log_data.get("agent_control_verdicts"), inp, out, meta, turn_start, turn_ns)
    lg.conclude(output=out, duration_ns=turn_ns)      # pop the workflow span
    lg.conclude(output=out, duration_ns=turn_ns)      # pop the trace envelope


def _add_agent_spans(lg, agent_trace, inp: str, model: str, meta: Dict[str, Any], turn_start) -> None:
    """Rebuild the multi-agent turn as nested spans under the current workflow:
    one agent span per coordinator / specialist / synthesizer call, each wrapping
    one LLM span with that agent's real token usage, back-dated sequentially by
    ``duration_ms`` so the waterfall shows the real turn timeline."""
    cursor = turn_start
    for rec in agent_trace:
        agent_out = rec.get("output_text") or "(empty)"
        dur_ns = _ms_to_ns(rec.get("duration_ms"))
        name = rec.get("name") or "agent"
        lg.add_agent_span(input=inp, output=agent_out, name=name, agent_type=_agent_type(rec.get("role")),
                          metadata=meta, created_at=cursor, duration_ns=dur_ns)
        lg.add_llm_span(input=inp, output=agent_out, model=rec.get("model") or model, name=name,
                        num_input_tokens=rec.get("input_tokens"), num_output_tokens=rec.get("output_tokens"),
                        metadata=meta, created_at=cursor, duration_ns=dur_ns)
        lg.conclude(output=agent_out, duration_ns=dur_ns)      # pop the agent span
        if cursor is not None and dur_ns:
            cursor = cursor + timedelta(microseconds=dur_ns / 1000)


def _add_control_spans(lg, records: Any, inp: str, out: str, meta: Dict[str, Any],
                       turn_start, turn_ns: Optional[int]) -> None:
    """One control span per Agent Control verdict of the turn (prompt stage,
    response stage) as a leaf under the ``chat_turn`` workflow span — the
    shield-icon span the Agent Observability trace view shows and the stream's
    Control View counts. The official SDK's splunk-ao bridge would emit these
    in-process during the turn; this app rebuilds the turn afterwards, so the
    verdicts ride in on the governance event (``agent_control_verdicts``,
    written by the governance node and the two block handlers) instead.

    A verdict with matched controls becomes one span per control, named after
    it and carrying its action; a clean or errored verdict becomes one
    ``observe`` span named after the stage, so an evaluation that ran is always
    visible. Native in splunk-ao 0.4.0 (``SplunkAOLogger.add_control_span``); a
    logger without it, an SDK without the control schema, or a turn without
    verdicts adds nothing."""
    if not records or not hasattr(lg, "add_control_span"):
        return
    try:
        from splunk_ao.logger.control import (   # type: ignore[import-not-found]
            ControlAppliesTo, ControlCheckStage, ControlResult,
        )
    except Exception:  # noqa: BLE001 - an SDK without control spans
        return
    for rec in records:
        if not isinstance(rec, dict):
            continue
        stage = "pre" if rec.get("stage") == "pre" else "post"
        controls = [str(c) for c in (rec.get("controls") or [])]
        decisions = [str(d).lower() for d in (rec.get("decisions") or [])]
        errored = bool(rec.get("errored"))
        dur_ns = _ms_to_ns(rec.get("duration_ms"))
        # The prompt screen ran before the model; the response judge at the end.
        if stage == "post" and turn_start is not None and turn_ns and dur_ns and turn_ns > dur_ns:
            created = turn_start + timedelta(microseconds=(turn_ns - dur_ns) / 1000)
        else:
            created = turn_start
        span_meta = dict(meta)
        span_meta.update({
            "agent_control_stage": stage,
            "agent_control_backend": str(rec.get("backend") or ""),
            "agent_control_transport": str(rec.get("transport") or ""),
            "agent_control_target": str(rec.get("target") or ""),
            "agent_control_errored": errored,
        })
        confidence = rec.get("confidence")
        try:
            confidence = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        error_message = str(rec.get("error_message")) if errored and rec.get("error_message") else None
        for i, name in enumerate(controls or [f"agent-control-{stage}"]):
            decision = decisions[i] if i < len(decisions) else "observe"
            # ControlResult.action is the SDK's str-enum (deny | steer | observe);
            # the vendor's allow/warn/log aliases all read as observe.
            action = decision if decision in ("deny", "steer", "observe") else "observe"
            lg.add_control_span(
                input=inp if stage == "pre" else out,
                output=ControlResult(action=action, matched=bool(controls),
                                     confidence=confidence, error_message=error_message),
                name=name, created_at=created, duration_ns=dur_ns, metadata=span_meta,
                status_code=500 if errored else 200,
                agent_name=rec.get("agent_name") or None,
                check_stage=ControlCheckStage(stage), applies_to=ControlAppliesTo("llm_call"),
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _coerce(value: Any):
    """Span metadata accepts str | bool | int | float | None."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _text(messages: Any) -> str:
    """Flatten input/output_messages ([{role, content}, ...]) into a string."""
    if isinstance(messages, str):
        return messages
    if isinstance(messages, list):
        parts = []
        for m in messages:
            parts.append(str(m.get("content", "")) if isinstance(m, dict) else str(m))
        return "\n".join(p for p in parts if p)
    return str(messages or "")


def _agent_type(role: Any):
    """Map an agent_trace role to the SDK's ``AgentType`` (None if unavailable)."""
    try:
        from galileo_core.schemas.logging.agent import AgentType
    except Exception:  # noqa: BLE001 - optional dependency / schema moved
        return None
    return {
        "coordinator": AgentType.supervisor,
        "specialist": AgentType.default,
        "synthesizer": AgentType.default,
    }.get(role, AgentType.default)


def _seconds_to_ns(value: Any) -> Optional[int]:
    try:
        secs = float(value)
    except (TypeError, ValueError):
        return None
    return int(secs * 1e9) if secs > 0 else None


def _ms_to_ns(value: Any) -> Optional[int]:
    try:
        ms = float(value)
    except (TypeError, ValueError):
        return None
    return int(ms * 1e6) if ms > 0 else None


def _parse_ts(value: Any) -> Optional[datetime]:
    """Governance timestamps are ``datetime.utcnow().isoformat()`` (naive UTC)."""
    if isinstance(value, datetime):
        ts = value
    else:
        try:
            ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Test seams
# ---------------------------------------------------------------------------
def _reset_for_tests(maxsize: int = QUEUE_MAXSIZE) -> None:
    global _rt
    shutdown(5.0)
    _rt = _new_runtime(maxsize)


def _drain_for_tests(timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _rt.queue.unfinished_tasks == 0:
            return True
        time.sleep(0.02)
    return _rt.queue.unfinished_tasks == 0
