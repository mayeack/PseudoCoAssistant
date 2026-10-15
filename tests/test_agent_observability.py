#!/usr/bin/env python3
"""Regression: the Splunk Agent Observability integration
(backend/agent_observability.py + wiring).

Guards (1) the no-op safety guarantee — without SPLUNK_AO_O11Y_TOKEN +
SPLUNK_AO_REALM (or with the SDK kill switch set) emission is a silent no-op and
never raises into a chat turn; (2) the shape of the emitted trace (one chat_turn
workflow root, one agent + llm span per agent_trace record, governance metadata on
every span, back-dated timestamps); (3) the worker lifecycle (one logger per
process, sessions cached per PseudoCo Assistant session, dangling-parent recovery, build and
session failures backed off, reconfigure retires the logger, bounded queue drops
instead of blocking, shutdown terminates); (4) the collector + app wiring, so the
integration can't regress into breaking requests or losing its export path.

The splunk_ao SDK is replaced by a recording fake in sys.modules, so nothing here
touches the network.

    venv/bin/python tests/test_agent_observability.py    # exit 0 = pass
"""
import logging
import os
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_fails = 0


def check(name: str, cond: bool) -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        _fails += 1


# SPLUNK_AO_O11Y_API_TOKEN is scrubbed too: _session_for branches on it to
# explain a sessions failure, so a real value in .env would otherwise change
# which message [6] sees.
for _k in ("SPLUNK_AO_O11Y_TOKEN", "SPLUNK_AO_REALM", "SPLUNK_AO_LOGGING_DISABLED",
           "SPLUNK_AO_PROJECT", "SPLUNK_AO_AGENT_STREAM", "SPLUNK_AO_O11Y_API_TOKEN"):
    os.environ.pop(_k, None)

import backend.agent_observability as ao
from backend.agents.themes import THEMES as _THEMES

_THEME_KEYS = sorted(_THEMES)  # noqa: E402


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def messages(self, level=None, contains=None):
        out = []
        for r in self.records:
            if level is not None and r.levelno != level:
                continue
            msg = r.getMessage()
            if contains is not None and contains not in msg:
                continue
            out.append(r)
        return out

    def clear(self):
        self.records.clear()


_cap = _LogCapture()
_mod_logger = logging.getLogger("backend.agent_observability")
_mod_logger.addHandler(_cap)
_mod_logger.setLevel(logging.DEBUG)


# ---- fake SDK --------------------------------------------------------------
class _FakeLogger:
    instances = []
    ctor_error = None

    def __init__(self, project=None, agent_stream=None, _sink=None, **kw):
        if _FakeLogger.ctor_error is not None:
            raise _FakeLogger.ctor_error
        self.project_name = project
        self.agent_stream_name = agent_stream
        self.sink = _sink                      # the bounded sink the emitter injects
        self.calls = []
        self.fail_start = False
        self.raise_start = None
        self.session_error = False
        self.dangling = False
        self.block_event = None                # blocks start_trace (NOT a bounded call)
        self.flush_block_event = None          # blocks flush (a bounded call)
        self.flush_error = None
        self.healthy = True
        _FakeLogger.instances.append(self)

    def _rec(self, name, k):
        self.calls.append((name, k))

    def start_trace(self, **k):
        self._rec("start_trace", k)
        if self.block_event is not None:
            self.block_event.wait(10)
        if self.raise_start is not None:
            raise self.raise_start
        return None if self.fail_start else object()

    def add_workflow_span(self, **k): self._rec("add_workflow_span", k)
    def add_agent_span(self, **k): self._rec("add_agent_span", k)
    def add_llm_span(self, **k): self._rec("add_llm_span", k)
    def add_control_span(self, **k): self._rec("add_control_span", k)
    def add_tool_span(self, **k): self._rec("add_tool_span", k)
    def conclude(self, **k): self._rec("conclude", k)

    def flush(self, on_error=None):
        self._rec("flush", {})
        if self.flush_block_event is not None:
            self.flush_block_event.wait(30)
        if self.flush_error is not None and on_error is not None:
            on_error(self.flush_error)

    def start_session(self, **k):
        self._rec("start_session", k)
        if self.session_error:                 # True -> the known 401; an exception -> raised as-is
            raise self.session_error if isinstance(self.session_error, BaseException) \
                else RuntimeError("401 unauthorized")
        return "ao-sess-1"

    def set_session(self, session_id): self._rec("set_session", {"session_id": session_id})
    def clear_session(self): self._rec("clear_session", {})

    def reset_parent_tracking(self):
        self._rec("reset_parent_tracking", {})
        self.dangling = False

    def terminate(self): self._rec("terminate", {})
    def has_active_trace(self): return self.dangling
    def current_parent(self): return object() if self.dangling else None

    @property
    def export_health(self):
        return SimpleNamespace(healthy=self.healthy, consecutive_failures=0, last_failure=None)


_fake_sdk = types.ModuleType("splunk_ao")
_fake_sdk.SplunkAOLogger = _FakeLogger
_fake_sdk.__version__ = "0.4.0-fake"
sys.modules["splunk_ao"] = _fake_sdk


# ---- fake SDK exporter plumbing, so _bounded_sink takes its real path -------
class _FakeSink:
    def __init__(self, exporter, batch):
        self.exporter, self.batch = exporter, batch


class _DeploymentMode:
    O11Y, STANDALONE = "o11y", "standalone"


_sdk_deployment = types.ModuleType("splunk_ao.deployment")
_sdk_deployment.DeploymentMode = _DeploymentMode
_sdk_deployment.resolve_deployment = lambda: _DeploymentMode.O11Y
_sdk_deployment.O11yConfig = SimpleNamespace(from_env=lambda: SimpleNamespace(realm="us1"))
_sdk_expcfg = types.ModuleType("splunk_ao.exporter.config")
_sdk_expcfg.resolve_routing = lambda mode, project=None, agent_stream=None: SimpleNamespace(
    project_name=project, agent_stream_name=agent_stream)

# The control-span schema (splunk_ao.logger.control): the real 0.4.0 re-exports
# galileo-core's str-enums + ControlResult; the fake mirrors their values so
# _add_control_spans takes its real path against the fake logger.
import enum as _enum  # noqa: E402


class _FakeControlResult:
    def __init__(self, action, matched, confidence=None, error_message=None):
        self.action, self.matched, self.confidence, self.error_message = action, matched, confidence, error_message


_sdk_logger_pkg = types.ModuleType("splunk_ao.logger")
_sdk_control = types.ModuleType("splunk_ao.logger.control")
_sdk_control.ControlCheckStage = _enum.Enum("ControlCheckStage", {"pre": "pre", "post": "post"})
_sdk_control.ControlAppliesTo = _enum.Enum("ControlAppliesTo", {"llm_call": "llm_call", "tool_call": "tool_call"})
_sdk_control.ControlResult = _FakeControlResult
sys.modules["splunk_ao.logger"] = _sdk_logger_pkg
sys.modules["splunk_ao.logger.control"] = _sdk_control
_sdk_o11y = types.ModuleType("splunk_ao.exporter.o11y")
_sdk_o11y.exporter_error = None
_sdk_o11y.build_o11y_exporter = lambda cfg, routing, timeout=None: (
    (_ for _ in ()).throw(_sdk_o11y.exporter_error) if _sdk_o11y.exporter_error is not None
    else SimpleNamespace(routing=routing, timeout=timeout))
_sdk_sink = types.ModuleType("splunk_ao.exporter.sink")
_sdk_sink.BatchConfig = lambda max_queue_size=None, max_export_batch_size=None: SimpleNamespace(
    max_queue_size=max_queue_size, max_export_batch_size=max_export_batch_size)
_sdk_sink.build_span_sink = lambda exporter, batch=None: _FakeSink(exporter, batch)
for _name, _mod in (("splunk_ao.deployment", _sdk_deployment), ("splunk_ao.exporter", types.ModuleType("splunk_ao.exporter")),
                    ("splunk_ao.exporter.config", _sdk_expcfg), ("splunk_ao.exporter.o11y", _sdk_o11y),
                    ("splunk_ao.exporter.sink", _sdk_sink)):
    sys.modules[_name] = _mod

_TRACE = [
    {"name": "medadvice_coordinator", "role": "coordinator", "model": "m",
     "input_tokens": 10, "output_tokens": 5, "output_text": "plan", "status": "ok", "duration_ms": 500.0},
    {"name": "medadvice_triage_specialist", "role": "specialist", "model": "m",
     "input_tokens": 20, "output_tokens": 8, "output_text": "triage", "status": "ok", "duration_ms": 1000.0},
    {"name": "medadvice_domain_agent", "role": "synthesizer", "model": "m",
     "input_tokens": 30, "output_tokens": 40, "output_text": "final", "status": "ok", "duration_ms": 1500.0},
]
_LOG = {
    "operation_name": "chat", "token_type": "output", "request_id": "rid",
    "session_id": "sess-abc", "trace_id": "tid-1", "timestamp": "2026-09-08T10:00:03",
    "client_operation_duration": 3.0,
    "input_messages": [{"role": "user", "content": "headache"}],
    "output_messages": [{"role": "assistant", "content": "final"}],
    "response_model": "m", "usage_input_tokens": 60, "usage_output_tokens": 53,
    "usage_total_tokens": 113, "pii_detected": True, "agent_trace": _TRACE,
}


def _names(calls):
    return [c[0] for c in calls]


def _turn(**over):
    d = dict(_LOG)
    d.update(over)
    return d


def _enable():
    os.environ["SPLUNK_AO_O11Y_TOKEN"] = "test-token-unused"
    os.environ["SPLUNK_AO_REALM"] = "us1"


def _disable():
    os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
    os.environ.pop("SPLUNK_AO_REALM", None)


def _fresh(maxsize=ao.QUEUE_MAXSIZE):
    ao._reset_for_tests(maxsize)
    _FakeLogger.instances.clear()
    _FakeLogger.ctor_error = None
    _cap.clear()


# ---- 1. no-op safety guarantee (must never raise into a chat turn) -----------
print("\n[1] no-op safety")
_disable()
check("disabled when SPLUNK_AO_O11Y_TOKEN / SPLUNK_AO_REALM unset", ao.is_enabled() is False)
os.environ["SPLUNK_AO_O11Y_TOKEN"] = "t"
check("token without realm stays disabled", ao.is_enabled() is False)
try:
    ao.maybe_log_turn(_turn())
    check("maybe_log_turn is a silent no-op when disabled", True)
except Exception:
    check("maybe_log_turn is a silent no-op when disabled", False)
check("no worker thread is started while disabled", ao._rt.thread is None)
_enable()
check("enabled when token + realm set", ao.is_enabled() is True)
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"
check("SPLUNK_AO_LOGGING_DISABLED is treated as disabled", ao.is_enabled() is False)
os.environ.pop("SPLUNK_AO_LOGGING_DISABLED")
try:
    ao.maybe_log_turn({"operation_name": "prompt", "token_type": "prompt"})
    check("maybe_log_turn ignores non-chat events", ao._rt.queue.qsize() == 0 and ao._rt.thread is None)
except Exception:
    check("maybe_log_turn ignores non-chat events", False)
_disable()

# ---- 2. helpers -------------------------------------------------------------
print("\n[2] helpers")
check("_coerce keeps scalars, stringifies non-scalars",
      ao._coerce(True) is True and ao._coerce(["a", "b"]) == "['a', 'b']")
check("_text flattens message lists + passes strings",
      ao._text([{"role": "user", "content": "abc"}]) == "abc" and ao._text("x") == "x")
check("coordinator role -> supervisor AgentType",
      getattr(ao._agent_type("coordinator"), "value", None) == "supervisor")
check("specialist / synthesizer / unknown roles -> default AgentType",
      all(getattr(ao._agent_type(r), "value", None) == "default" for r in ("specialist", "synthesizer", "??")))
check("_seconds_to_ns", ao._seconds_to_ns(3.0) == 3_000_000_000 and ao._seconds_to_ns(None) is None
      and ao._seconds_to_ns(0) is None)
check("_ms_to_ns", ao._ms_to_ns(12.5) == 12_500_000 and ao._ms_to_ns("x") is None)
_ts = ao._parse_ts("2026-09-08T10:00:03")
check("_parse_ts makes a naive governance timestamp UTC-aware",
      _ts is not None and _ts.tzinfo is not None and _ts == datetime(2026, 9, 8, 10, 0, 3, tzinfo=timezone.utc))
check("_parse_ts rejects garbage", ao._parse_ts("garbage") is None and ao._parse_ts(None) is None)

# ---- 3. builder shape (pure) ------------------------------------------------
print("\n[3] trace shape")
fake = _FakeLogger()
ao._build_turn(fake, _turn())
names = _names(fake.calls)
check("one chat_turn workflow root", names.count("add_workflow_span") == 1
      and fake.calls[1][1].get("name") == "chat_turn")
check("one agent span + one llm span per agent_trace record",
      names.count("add_agent_span") == 3 and names.count("add_llm_span") == 3)
check("conclude() balanced: 3 agents + workflow + trace = 5, trace last",
      names.count("conclude") == 5 and names[-1] == "conclude" and names[0] == "start_trace")
check("builder is pure: no flush / session calls",
      not any(n in ("flush", "set_session", "start_session", "clear_session") for n in names))
_start = fake.calls[0][1]
check("start_trace carries name, external_id and the back-dated created_at",
      _start.get("name") == "chat turn" and _start.get("external_id") == "rid"
      and _start.get("created_at") == datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc))
_spans = [c for c in fake.calls if c[0] in ("add_workflow_span", "add_agent_span", "add_llm_span")]
check("governance metadata (pii_detected) rides on every span",
      all(c[1].get("metadata", {}).get("pii_detected") is True for c in _spans))
check("pseudoco_assistant_trace_id rides on every span (joins the trace to APM / governance logs)",
      all(c[1].get("metadata", {}).get("pseudoco_assistant_trace_id") == "tid-1" for c in _spans))
_agents = [c for c in fake.calls if c[0] == "add_agent_span"]
check("coordinator agent span tagged with the supervisor AgentType",
      getattr(_agents[0][1].get("agent_type"), "value", None) == "supervisor")
check("agent/llm spans carry duration_ns from duration_ms",
      [c[1].get("duration_ns") for c in _agents] == [500_000_000, 1_000_000_000, 1_500_000_000]
      and [c[1].get("duration_ns") for c in fake.calls if c[0] == "add_llm_span"]
      == [500_000_000, 1_000_000_000, 1_500_000_000])
_t0 = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
check("agent spans are back-dated sequentially by duration",
      [c[1].get("created_at") for c in _agents]
      == [_t0, _t0 + timedelta(milliseconds=500), _t0 + timedelta(milliseconds=1500)])
_concludes = [c[1] for c in fake.calls if c[0] == "conclude"]
check("workflow + trace concludes carry the turn duration",
      _concludes[-1].get("duration_ns") == 3_000_000_000 and _concludes[-2].get("duration_ns") == 3_000_000_000)
check("agent-span concludes carry the agent duration",
      [c.get("duration_ns") for c in _concludes[:3]] == [500_000_000, 1_000_000_000, 1_500_000_000])

fake = _FakeLogger()
ao._build_turn(fake, _turn(agent_trace=None))
names = _names(fake.calls)
_llm = [c for c in fake.calls if c[0] == "add_llm_span"]
check("no agent_trace -> chat_turn workflow wrapping a single LLM span with the turn's usage",
      names.count("add_workflow_span") == 1 and names.count("add_agent_span") == 0
      and len(_llm) == 1 and _llm[0][1].get("num_input_tokens") == 60
      and _llm[0][1].get("total_tokens") == 113 and _llm[0][1].get("duration_ns") == 3_000_000_000
      and names.count("conclude") == 2)

# Agent Control verdicts (agent_control_verdicts on the governance event) become
# control spans under the workflow span — what the AO trace view shows with the
# shield icon and the stream's Control View counts.
fake = _FakeLogger()
ao._build_turn(fake, dict(_turn(), agent_control_verdicts=[
    {"stage": "pre", "controls": [], "decisions": [], "errored": False, "duration_ms": 120.0,
     "backend": "splunk_ao", "target": "TelecomChatbot", "transport": "server",
     "agent_name": "pseudoco-assistant-agent"},
    {"stage": "post", "controls": ["block-x", "watch-y"], "decisions": ["deny", "observe"], "errored": False,
     "duration_ms": 800.0, "backend": "splunk_ao", "target": "TelecomChatbot", "transport": "server",
     "confidence": 0.9},
]))
names = _names(fake.calls)
_ctl = [c[1] for c in fake.calls if c[0] == "add_control_span"]
check("agent_control_verdicts -> one span per matched control, one observe span for a clean stage",
      [c.get("name") for c in _ctl] == ["agent-control-pre", "block-x", "watch-y"])
check("control spans sit under the workflow span, before its conclude",
      names.index("add_workflow_span") < names.index("add_control_span") < len(names) - 2
      and names[-2:] == ["conclude", "conclude"])
check("control spans carry stage, action, match and target",
      getattr(_ctl[0].get("check_stage"), "value", None) == "pre"
      and _ctl[0]["output"].action == "observe" and _ctl[0]["output"].matched is False
      and _ctl[1]["output"].action == "deny" and _ctl[1]["output"].matched is True
      and _ctl[2]["output"].action == "observe"
      and _ctl[1].get("metadata", {}).get("agent_control_target") == "TelecomChatbot"
      and _ctl[1].get("agent_name") is None and _ctl[0].get("agent_name") == "pseudoco-assistant-agent")
check("the prompt-stage span is back-dated to the turn start, the response stage to its end",
      _ctl[0].get("created_at") == _t0 and _ctl[1].get("created_at") == _t0 + timedelta(milliseconds=2200)
      and _ctl[0].get("duration_ns") == 120_000_000)
fake = _FakeLogger()
ao._build_turn(fake, dict(_turn(), agent_control_verdicts=[
    {"stage": "post", "controls": [], "decisions": [], "errored": True, "error_message": "HTTP 403: controls.read",
     "duration_ms": 50.0, "backend": "splunk_ao"}]))
_err = [c[1] for c in fake.calls if c[0] == "add_control_span"]
check("an errored evaluation is a status-500 observe span carrying the error",
      len(_err) == 1 and _err[0].get("status_code") == 500 and _err[0]["output"].error_message == "HTTP 403: controls.read")
fake = _FakeLogger()
ao._build_turn(fake, _turn())
check("additive: a turn without verdicts emits no control span", "add_control_span" not in _names(fake.calls))

# MCP tool-thrash records (tool_thrash on the governance event) become tool spans
# under a dedicated mcp_tool_broker agent span — one agent looping on tool calls
# that never converge, which is what Signals mines from the stream.
_THRASH = [
    {"name": "patient_record.lookup", "call_id": "mcp-thrash-0", "arguments": "query=x, iteration=0",
     "output": "Ambiguous: 7 candidates", "status": "ok", "duration_ms": 140.0, "step": 0,
     "iteration": 0, "converged": False},
    {"name": "patient_record.refine", "call_id": "mcp-thrash-1", "arguments": "query=x, iteration=0",
     "output": "Narrowed to 4, conflicts", "status": "ok", "duration_ms": 140.0, "step": 1,
     "iteration": 0, "converged": False},
    {"name": "patient_record.cross_check", "call_id": "mcp-thrash-2", "arguments": "query=x, iteration=1",
     "output": "record of truth disagrees", "status": "error", "duration_ms": 140.0, "step": 2,
     "iteration": 1, "converged": False},
]
fake = _FakeLogger()
ao._build_turn(fake, dict(_turn(agent_trace=None), tool_thrash=_THRASH))
names = _names(fake.calls)
_broker = [c[1] for c in fake.calls if c[0] == "add_agent_span"]
_tools = [c[1] for c in fake.calls if c[0] == "add_tool_span"]
check("tool_thrash -> one mcp_tool_broker agent span wrapping one tool span per record",
      len(_broker) == 1 and _broker[0].get("name") == "mcp_tool_broker" and len(_tools) == 3)
check("tool spans carry the tool name, step_number and the call id, in order",
      [c.get("name") for c in _tools] == ["patient_record.lookup", "patient_record.refine", "patient_record.cross_check"]
      and [c.get("step_number") for c in _tools] == [0, 1, 2]
      and [c.get("tool_call_id") for c in _tools] == ["mcp-thrash-0", "mcp-thrash-1", "mcp-thrash-2"])
check("an errored tool call is a status-500 span; a successful one is 200",
      [c.get("status_code") for c in _tools] == [200, 200, 500])
check("tool spans are back-dated sequentially from the turn start and nest under the broker",
      [c.get("created_at") for c in _tools]
      == [_t0, _t0 + timedelta(milliseconds=140), _t0 + timedelta(milliseconds=280)]
      and names.index("add_agent_span") < names.index("add_tool_span"))
check("the broker agent span is concluded (back to the workflow): conclude balanced at 3 (broker+workflow+trace)",
      names.count("conclude") == 3 and names[-2:] == ["conclude", "conclude"])
check("every tool span carries the governance metadata and marks non-convergence",
      all(c.get("metadata", {}).get("pii_detected") is True for c in _tools)
      and all(c.get("metadata", {}).get("mcp_thrash_converged") is False for c in _tools))

fake = _FakeLogger()
ao._build_turn(fake, _turn())
check("additive: a turn without tool_thrash emits no tool span", "add_tool_span" not in _names(fake.calls))

fake = _FakeLogger()
fake.fail_start = True
try:
    ao._build_turn(fake, _turn())
    check("start_trace returning None raises TurnEmitError", False)
except ao.TurnEmitError:
    check("start_trace returning None raises TurnEmitError", True)
fake = _FakeLogger()
fake.raise_start = ValueError("A trace cannot be created within a parent")
try:
    ao._build_turn(fake, _turn())
    check("start_trace raising (dangling parent) raises TurnEmitError", False)
except ao.TurnEmitError:
    check("start_trace raising (dangling parent) raises TurnEmitError", True)

# ---- 4. worker path ----------------------------------------------------------
print("\n[4] worker: one logger, sessions, log line")
_fresh()
_enable()
ao.maybe_log_turn(_turn())
ao.maybe_log_turn(_turn(request_id="rid2"))
check("worker drains both turns", ao._drain_for_tests(5.0))
check("exactly one SplunkAOLogger per process", len(_FakeLogger.instances) == 1)
lg = _FakeLogger.instances[0]
check("project / agent stream default to PseudoCo Assistant when env unset",
      lg.project_name == "PseudoCo Assistant" and lg.agent_stream_name == "PseudoCo Assistant")
_sessions = [c for c in lg.calls if c[0] == "start_session"]
check("start_session called once per PseudoCo Assistant session (cache reuse) with the external id",
      len(_sessions) == 1 and _sessions[0][1].get("external_id") == "sess-abc"
      and _sessions[0][1].get("name") == "chat session sess-abc")
_n = _names(lg.calls)
_second_start = [i for i, n in enumerate(_n) if n == "start_trace"][1]
check("set_session precedes start_trace on the second turn",
      "set_session" in _n[:_second_start] and lg.calls[_n.index("set_session")][1] == {"session_id": "ao-sess-1"})
check("each turn ends with conclude, flush", _n[-2:] == ["conclude", "flush"])
_info = _cap.messages(logging.INFO, "logged turn")
check("INFO log line per turn with model / agents / project / stream / export",
      len(_info) == 2 and _info[-1].getMessage()
      == "agent observability: logged turn (model=m, agents=3, project=PseudoCo Assistant, agent_stream=PseudoCo Assistant, export=healthy)")
check("logger-ready line logged once", len(_cap.messages(logging.INFO, "logger ready")) == 1)
check("status() counts logged turns", ao.status()["turns_logged"] == 2 and ao.status()["logger_ready"] is True)
check("the logger is built with the bounded sink: explicit OTLP timeout + capped span queue",
      isinstance(lg.sink, _FakeSink) and lg.sink.exporter.timeout == ao._EXPORT_TIMEOUT_S
      and lg.sink.exporter.routing.agent_stream_name == "PseudoCo Assistant"
      and lg.sink.batch.max_queue_size == ao._EXPORT_QUEUE_SIZE
      and lg.sink.batch.max_export_batch_size == ao._EXPORT_BATCH_SIZE)
check("no bound-fallback warning on the happy path", not _cap.messages(logging.WARNING, "cannot bound"))
_st = ao.status()
check("status() exposes the stall / session signals, idle after a healthy drain",
      _st["stalled"] is False and _st["turn_in_flight_s"] == 0.0 and _st["stalls"] == 0
      and _st["abandoned_calls"] == 0 and _st["sessions_ok"] is True
      and _st["last_turn_completed_s_ago"] is not None)

print("\n[5] worker: dangling parent recovery")
lg.calls.clear()
lg.dangling = True
ao.maybe_log_turn(_turn())
ao._drain_for_tests(5.0)
_n = _names(lg.calls)
check("a dangling trace is concluded + parent tracking reset before start_trace",
      _n[:2] == ["conclude", "reset_parent_tracking"] and lg.calls[0][1].get("conclude_all") is True
      and "start_trace" in _n)

print("\n[6] worker: sessions unavailable -> turn still logged, backoff")
_fresh()
_enable()
_FakeLogger.session_error_default = True


class _SessionFail(_FakeLogger):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.session_error = True


_fake_sdk.SplunkAOLogger = _SessionFail
ao.maybe_log_turn(_turn())
ao.maybe_log_turn(_turn(request_id="rid2"))
ao._drain_for_tests(5.0)
lg = _FakeLogger.instances[0]
_n = _names(lg.calls)
check("turns are logged without a session when start_session fails",
      _n.count("start_trace") == 2 and "clear_session" in _n)
check("start_session is not retried inside the backoff window",
      _n.count("start_session") == 1 and ao._rt.sessions_unavailable_until > 0)
check("exactly one WARNING about sessions", len(_cap.messages(logging.WARNING, "sessions unavailable")) == 1)
check("status() surfaces the sessions failure and names the missing token",
      ao.status()["sessions_ok"] is False
      and "SPLUNK_AO_O11Y_API_TOKEN is not set" in ao.status()["sessions_last_error"]
      and "401 unauthorized" in ao.status()["sessions_last_error"])
# dedupe is by CAUSE, not once-ever: a start_session timeout after the standing
# 401 must still get its own line, or a wedged session lookup is silent on a box
# where the 401 has already warned (every box without the API token).
ao._rt.sessions_unavailable_until = 0.0
lg.session_error = ao.SdkCallTimeout("start_session exceeded 30s; call abandoned on its thread")
ao.maybe_log_turn(_turn(request_id="rid3"))
ao._drain_for_tests(5.0)
_sw = _cap.messages(logging.WARNING, "sessions unavailable")
check("a NEW sessions cause after the known 401 warns again, and the turn still logs",
      len(_sw) == 2 and "start_session exceeded 30s" in _sw[-1].getMessage()
      and "exceeded 30s" in ao.status()["sessions_last_error"] and ao.status()["turns_logged"] == 3)
ao._rt.sessions_unavailable_until = 0.0
ao.maybe_log_turn(_turn(request_id="rid4"))
ao._drain_for_tests(5.0)
check("the SAME cause again stays quiet", len(_cap.messages(logging.WARNING, "sessions unavailable")) == 2)
_fake_sdk.SplunkAOLogger = _FakeLogger

print("\n[7] worker: build failure is contained")
_fresh()
_enable()
_FakeLogger.ctor_error = RuntimeError("MissingConfigurationError: O11y deployment requires SPLUNK_AO_O11Y_TOKEN")
try:
    ao.maybe_log_turn(_turn())
    ao.maybe_log_turn(_turn(request_id="rid2"))
    ao._drain_for_tests(5.0)
    check("maybe_log_turn never raises on a build failure", True)
except Exception:
    check("maybe_log_turn never raises on a build failure", False)
check("turns are dropped while the build backs off",
      ao.status()["dropped"] == 2 and ao.status()["logger_ready"] is False and ao.status()["last_build_error"])
check("one WARNING per distinct build failure", len(_cap.messages(logging.WARNING, "cannot build SplunkAOLogger")) == 1)
_FakeLogger.ctor_error = None

print("\n[7b] the export bound degrades, never blocks emission")
_fresh()
_enable()
_sdk_o11y.exporter_error = TypeError("build_o11y_exporter() got an unexpected keyword argument 'timeout'")
ao.maybe_log_turn(_turn())
ao.maybe_log_turn(_turn(request_id="rid2"))
ao._drain_for_tests(5.0)
check("an SDK shape drift falls back to the default sink and still logs the turn",
      len(_FakeLogger.instances) == 1 and _FakeLogger.instances[0].sink is None
      and ao.status()["turns_logged"] == 2)
check("the lost bound is ONE WARNING per distinct cause",
      len(_cap.messages(logging.WARNING, "cannot bound the export timeout")) == 1)
_sdk_o11y.exporter_error = None
_fresh()
_enable()
_sdk_deployment.resolve_deployment = lambda: _DeploymentMode.STANDALONE
ao.maybe_log_turn(_turn())
ao._drain_for_tests(5.0)
check("a standalone deployment keeps the SDK's own exporter, silently",
      _FakeLogger.instances[0].sink is None and ao.status()["turns_logged"] == 1
      and not _cap.messages(logging.WARNING))
_sdk_deployment.resolve_deployment = lambda: _DeploymentMode.O11Y

print("\n[8] reconfigure retires the logger")
_fresh()
_enable()
ao.maybe_log_turn(_turn())
ao._drain_for_tests(5.0)
os.environ["SPLUNK_AO_PROJECT"] = "P"
ao.reconfigure()
ao.maybe_log_turn(_turn())
ao._drain_for_tests(5.0)
check("the previous logger is terminated and a new one built from the current env",
      len(_FakeLogger.instances) == 2 and "terminate" in _names(_FakeLogger.instances[0].calls)
      and _FakeLogger.instances[1].project_name == "P")
check("the session cache is dropped with the logger",
      "start_session" in _names(_FakeLogger.instances[1].calls))
os.environ.pop("SPLUNK_AO_PROJECT")

print("\n[8b] one agent stream per theme")
_fresh()
_enable()
os.environ.pop("SPLUNK_AO_AGENT_STREAM", None)
os.environ.pop("SPLUNK_AO_AGENT_STREAM_PER_THEME", None)

check("a theme resolves to its own label, from the registry",
      ao._stream_for({"theme": "medadvice"}) == "MedAdvice"
      and ao._stream_for({"theme": "taxadvice"}) == "TaxAdvice")
check("theme matching is case/whitespace tolerant",
      ao._stream_for({"theme": " MedAdvice "}) == "MedAdvice")
check("every registered theme maps to a distinct stream",
      len({ao._stream_for({"theme": k}) for k in _THEME_KEYS}) == len(_THEME_KEYS))
check("an unknown or missing theme falls back to the default stream",
      ao._stream_for({"theme": "not-a-theme"}) == "PseudoCo Assistant"
      and ao._stream_for({}) == "PseudoCo Assistant"
      and ao._stream_for({"theme": None}) == "PseudoCo Assistant")

os.environ["SPLUNK_AO_AGENT_STREAM"] = "Fallback"
check("the fallback stream is SPLUNK_AO_AGENT_STREAM", ao._stream_for({}) == "Fallback")
check("a known theme still wins over the fallback",
      ao._stream_for({"theme": "legaladvice"}) == "LegalAdvice")
os.environ["SPLUNK_AO_AGENT_STREAM_PER_THEME"] = "False"
check("PER_THEME=False pins every turn to the one stream",
      ao._stream_for({"theme": "legaladvice"}) == "Fallback")
os.environ.pop("SPLUNK_AO_AGENT_STREAM_PER_THEME")
os.environ.pop("SPLUNK_AO_AGENT_STREAM")

# turns on two themes -> two loggers, each constructed with its own stream
ao.maybe_log_turn(_turn(request_id="t-med", theme="medadvice"))
ao.maybe_log_turn(_turn(request_id="t-tax", theme="taxadvice"))
ao.maybe_log_turn(_turn(request_id="t-med2", theme="medadvice"))
ao._drain_for_tests(5.0)
_streams = [i.agent_stream_name for i in _FakeLogger.instances]
check("one logger per theme, built with that theme's stream (not one per turn)",
      _streams == ["MedAdvice", "TaxAdvice"], )
check("all three turns were logged", ao._rt.turns_logged == 3)
check("the live streams are reported by status()",
      sorted(ao.status()["agent_streams_live"]) == ["MedAdvice", "TaxAdvice"]
      and ao.status()["agent_stream_per_theme"] is True)
check("each stream keeps its own project", {i.project_name for i in _FakeLogger.instances} == {"PseudoCo Assistant"})
check("sessions are per (stream, session): the same session_id twice, once per stream",
      len(ao._rt.sessions) == 2)
check("reconfigure retires every stream's logger",
      (ao.reconfigure(), ao.maybe_log_turn(_turn(request_id="t-after", theme="medadvice")),
       ao._drain_for_tests(5.0), len(_FakeLogger.instances) == 3)[-1])

print("\n[9] consecutive failures rebuild the logger")
_fresh()
_enable()


class _FailStart(_FakeLogger):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.fail_start = True


_fake_sdk.SplunkAOLogger = _FailStart
for i in range(ao._MAX_CONSECUTIVE_FAILURES):
    ao.maybe_log_turn(_turn(request_id=f"r{i}"))
ao._drain_for_tests(5.0)
check("after N consecutive failures the logger is terminated and rebuilt after a backoff",
      "terminate" in _names(_FakeLogger.instances[0].calls) and not ao._rt.loggers
      and ao._rt.build_backoff_until > 0)
check("one WARNING announces the rebuild", len(_cap.messages(logging.WARNING, "consecutive failures")) == 1)
_fails_w = _cap.messages(logging.WARNING, "emit failed")
check("emit failures are WARNINGs: traceback once, one-liners afterwards",
      len(_fails_w) == ao._MAX_CONSECUTIVE_FAILURES and sum(1 for r in _fails_w if r.exc_info) == 1)
_fake_sdk.SplunkAOLogger = _FakeLogger

print("\n[10] bounded queue drops instead of blocking")
_fresh(maxsize=1)
_enable()
_gate = threading.Event()


class _Blocking(_FakeLogger):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.block_event = _gate


_fake_sdk.SplunkAOLogger = _Blocking
try:
    ao.maybe_log_turn(_turn(request_id="a"))   # occupies the worker (blocked in start_trace)
    import time as _time
    _deadline = _time.monotonic() + 5
    while _time.monotonic() < _deadline and not (_FakeLogger.instances and _FakeLogger.instances[0].calls):
        _time.sleep(0.02)
    ao.maybe_log_turn(_turn(request_id="b"))   # fills the 1-slot queue
    ao.maybe_log_turn(_turn(request_id="c"))   # Full -> dropped
    ao.maybe_log_turn(_turn(request_id="d"))
    check("maybe_log_turn never raises or blocks on a full queue", True)
except Exception:
    check("maybe_log_turn never raises or blocks on a full queue", False)
check("dropped turns are counted and warned once",
      ao.status()["dropped"] >= 1 and len(_cap.messages(logging.WARNING, "queue full")) == 1)
_gate.set()
ao._drain_for_tests(5.0)
_fake_sdk.SplunkAOLogger = _FakeLogger

# ---- 10b. the 2026-09-09 wedge: a flush that never returns ----------------
print("\n[10b] a blocked flush is bounded: warned, logger rebuilt, next turn streams")
_fresh()
_enable()
_flush_gate = threading.Event()


class _FlushHangs(_FakeLogger):
    """Only the FIRST logger hangs in flush (dead sockets); its replacement is healthy."""
    def __init__(self, **kw):
        super().__init__(**kw)
        if len(_FakeLogger.instances) == 1:
            self.flush_block_event = _flush_gate


_fake_sdk.SplunkAOLogger = _FlushHangs
_orig_call, _orig_backoff = ao._CALL_TIMEOUT_S, ao._BUILD_BACKOFF_S
ao._CALL_TIMEOUT_S, ao._BUILD_BACKOFF_S = 0.3, 0.0
try:
    _t0 = time.monotonic()
    ao.maybe_log_turn(_turn(request_id="hangs"))
    ao._drain_for_tests(5.0)
    _took = time.monotonic() - _t0
    check("the worker is back within the call deadline instead of blocking on flush",
          0.3 <= _took < 3.0 and ao._rt.turn_started_at == 0.0)
    _w = _cap.messages(logging.WARNING, "emit failed")
    check("the overrun is a WARNING naming the call and the deadline",
          len(_w) == 1 and "SdkCallTimeout: flush exceeded 0s" in _w[0].getMessage())
    check("an abandoned call rebuilds the logger at once, not after N failures",
          len(_cap.messages(logging.WARNING, "call abandoned on its thread; terminating and rebuilding")) == 1
          and "terminate" in _names(_FakeLogger.instances[0].calls) and not ao._rt.loggers)
    check("status() counts the abandoned call and no turn as logged",
          ao.status()["abandoned_calls"] == 1 and ao.status()["turns_logged"] == 0
          and ao.status()["stalled"] is False)
    ao.maybe_log_turn(_turn(request_id="after"))
    ao._drain_for_tests(5.0)
    check("the next turn streams through a fresh logger (new exporter, new sockets)",
          len(_FakeLogger.instances) == 2 and _names(_FakeLogger.instances[1].calls)[-2:] == ["conclude", "flush"]
          and ao.status()["turns_logged"] == 1 and ao.status()["logger_ready"] is True)
    check("the abandoned flush is still parked on its own daemon thread, harmless",
          any(t.name == "agent-observability-io:flush" and t.daemon for t in threading.enumerate()))
finally:
    _flush_gate.set()
    ao._CALL_TIMEOUT_S, ao._BUILD_BACKOFF_S = _orig_call, _orig_backoff
_fake_sdk.SplunkAOLogger = _FakeLogger

# ---- 10c. a wedge OUTSIDE the bounded calls: the last-resort stall signal --
print("\n[10c] a wedge outside the bounded calls is loud: request path warns once, status() reports it")
_fresh()
_enable()
_gate2 = threading.Event()


class _StartHangs(_FakeLogger):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.block_event = _gate2          # start_trace is local, deliberately not bounded


_fake_sdk.SplunkAOLogger = _StartHangs
_orig_stall = ao._STALL_WARN_AFTER_S
ao._STALL_WARN_AFTER_S = 0.2
try:
    ao.maybe_log_turn(_turn(request_id="wedged"))
    _deadline = time.monotonic() + 5
    while time.monotonic() < _deadline and not ao._rt.turn_started_at:
        time.sleep(0.02)
    time.sleep(0.35)                       # past the (lowered) stall threshold
    _st = ao.status()
    check("status() reports the stall while worker_alive is still True (the trap)",
          _st["stalled"] is True and _st["worker_alive"] is True and _st["turn_in_flight_s"] >= 0.2
          and _st["turns_logged"] == 0)
    check("nothing has been warned yet: the wedged worker cannot report itself",
          not _cap.messages(logging.WARNING, "WORKER STALLED"))
    ao.maybe_log_turn(_turn(request_id="behind-1"))   # the request path is what notices
    ao.maybe_log_turn(_turn(request_id="behind-2"))
    _w = _cap.messages(logging.WARNING, "WORKER STALLED")
    check("exactly ONE WARNING per wedged turn, naming it and what is queued behind it",
          len(_w) == 1 and "turn wedged has been in flight" in _w[0].getMessage()
          and "1 turn(s) are queued behind it" in _w[0].getMessage())
    check("the stall is counted", ao.status()["stalls"] == 1 and ao.status()["queued"] == 2)
finally:
    ao._STALL_WARN_AFTER_S = _orig_stall
    _gate2.set()
    ao._drain_for_tests(5.0)
_st = ao.status()
check("the stall clears once the worker returns and the backlog streams",
      _st["stalled"] is False and _st["turn_in_flight_s"] == 0.0 and _st["turns_logged"] == 3
      and _st["queued"] == 0 and len(_cap.messages(logging.WARNING, "WORKER STALLED")) == 1)
_fake_sdk.SplunkAOLogger = _FakeLogger

print("\n[11] shutdown")
_fresh()
_enable()
ao.maybe_log_turn(_turn())
ao._drain_for_tests(5.0)
ao.shutdown(5.0)
check("shutdown stops the worker and terminates the logger",
      (ao._rt.thread is None or not ao._rt.thread.is_alive())
      and "terminate" in _names(_FakeLogger.instances[-1].calls))
try:
    ao.shutdown(1.0)
    check("shutdown is idempotent", True)
except Exception:
    check("shutdown is idempotent", False)
_disable()

# ---- 12. wiring presence (export paths) ------------------------------------
print("\n[12] wiring")
collector = (ROOT / "otel-collector-config.yaml").read_text()
overlay = (ROOT / "otel-collector-agent-obs.yaml").read_text()
check("agent-obs overlay exports to the O11y trace ingest with the SDK's routing headers",
      "otlphttp/agent_obs" in overlay
      and "ingest.${env:SPLUNK_AO_REALM}.observability.splunkcloud.com/v2/trace/otlp" in overlay
      and 'X-SF-Token: "${env:SPLUNK_AO_O11Y_TOKEN}"' in overlay
      and 'project: "${env:SPLUNK_AO_PROJECT}"' in overlay
      and 'logstream: "${env:SPLUNK_AO_AGENT_STREAM}"' in overlay)
_overlay_pipes = overlay.split("pipelines:", 1)[-1]
check("agent-obs exporter is on a GenAI-only traces pipeline in the overlay",
      "traces/agent_obs" in _overlay_pipes and "otlphttp/agent_obs" in _overlay_pipes
      and "filter/genai_only" in _overlay_pipes)
_base_no_comment = collector.replace("# traces/agent_obs is defined in otel-collector-agent-obs.yaml", "")
check("BASE collector config carries NO agent-obs (or galileo) exporter or pipeline",
      "otlphttp/agent_obs" not in collector and "traces/agent_obs" not in _base_no_comment
      and "galileo" not in collector.lower())
check("collector defines a GenAI-only filter (drops non-gen_ai spans)",
      "filter/genai_only" in collector and "gen_ai.operation.name" in collector)
_splunk_block = collector.split("pipelines:", 1)[-1]
check("Splunk APM traces pipeline keeps the full trace (no GenAI filter)",
      "otlphttp/traces" in _splunk_block and "filter/genai_only" not in _splunk_block)
rc = (ROOT / "run-collector.sh").read_text()
check("run-collector.sh layers the overlay only when SPLUNK_AO_O11Y_TOKEN is set",
      'if [ -n "${SPLUNK_AO_O11Y_TOKEN:-}" ]' in rc and "otel-collector-agent-obs.yaml" in rc
      and "otel-collector-galileo.yaml" not in rc)
check("run-collector.sh injects SPLUNK_AO_* into the collector",
      all(k in rc for k in ("SPLUNK_AO_REALM", "SPLUNK_AO_O11Y_TOKEN", "SPLUNK_AO_PROJECT", "SPLUNK_AO_AGENT_STREAM"))
      and "-e SPLUNK_AO_AGENT_STREAM \\" in rc)
run_sh = (ROOT / "run.sh").read_text()
check("run.sh exports SPLUNK_AO_* / AGENT_CONTROL_* to the app process",
      "SPLUNK_AO_" in run_sh and "AGENT_CONTROL_" in run_sh and "GALILEO_" not in run_sh)
gov = (ROOT / "backend/logging/governance_logger.py").read_text()
check("governance logger fans completed turns out to agent_observability",
      "agent_observability" in gov and "maybe_log_turn" in gov and "galileo_integration" not in gov)
src = (ROOT / "backend/agent_observability.py").read_text()
check("the emitter never imports the legacy galileo SDK",
      "from galileo import" not in src and "GalileoLogger" not in src)
import re as _re
check("every network-touching SDK call is bounded (start_session, flush, terminate)",
      '_bounded_call("start_session", lg.start_session' in src
      and '_bounded_call("flush", lg.flush' in src
      and '_bounded_call("terminate", lg.terminate' in src
      # no direct call left as a code line (docstrings may still mention them)
      and _re.search(r"^\s*(\w+\s*=\s*)?lg\.(flush|terminate|start_session)\(", src, _re.M) is None)
check("the emitter bounds its export and injects the sink through the SDK's own seam",
      "_EXPORT_TIMEOUT_S" in src and "_sink=sink" in src and "timeout=_EXPORT_TIMEOUT_S" in src)
check("governance logger WARNS (deduped) when the AO submit fails, instead of debug-swallowing it",
      'logger.warning("agent observability submit failed' in gov and "_ao_submit_warned" in gov)
check("legacy files are gone",
      not (ROOT / "otel-collector-galileo.yaml").exists() and not (ROOT / "backend/galileo_integration.py").exists()
      and not (ROOT / "tests/test_galileo_integration.py").exists())
check("run_all.sh runs this suite", "tests/test_agent_observability.py" in (ROOT / "tests/run_all.sh").read_text())

ao.shutdown(2.0)
del sys.modules["splunk_ao"]
_disable()
print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
sys.exit(1 if _fails else 0)
