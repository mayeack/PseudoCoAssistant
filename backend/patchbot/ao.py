"""PatchBot runs as Agent Observability traces on the PatchBot Agent stream.

``agent_observability`` routes a record with ``_patchbot`` to the stream named
by ``PATCHBOT_AGENT_STREAM`` and hands it to ``build_run``, which rebuilds the
run in order::

    workflow "patchbot_run"
      agent PatchBot
        llm   <model>                 one per model call
        control <name>                one per control verdict, before its tool
        tool  <tool name>             403 when a control denied it

Control spans apply to ``tool_call`` at the ``pre`` stage, so the stream's
Control View counts PatchBot's allows and denies.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _coerce(v: Any) -> Any:
    if v is None or isinstance(v, (str, bool, int, float)):
        return v
    return str(v)


def _ns(ms: Any) -> Optional[int]:
    try:
        return int(float(ms) * 1_000_000) if ms is not None else None
    except (TypeError, ValueError):
        return None


def _parse(ts: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", ""))
    except (TypeError, ValueError):
        return None


def build_run(lg, rec: Dict[str, Any], agent_type=None) -> None:
    meta = {k: _coerce(rec.get(k)) for k in ("initiator", "initiator_role", "auth_method", "estate_owner",
                                             "finding_id", "investigation_id", "kind", "session_id", "trace_id")
            if rec.get(k) not in (None, "")}
    meta["feature"] = "patchbot"
    meta["pseudoco_assistant_trace_id"] = str(rec.get("trace_id") or "")
    start = _parse(rec.get("timestamp")) or datetime.utcnow()
    total_ns = _ns(rec.get("duration_ms"))
    inp = str(rec.get("input") or rec.get("kind") or "patchbot")
    out = str(rec.get("output") or "")
    trace = lg.start_trace(input=inp, name="patchbot run", metadata=meta, created_at=start,
                           external_id=str(rec.get("run_id") or "") or None)
    if trace is None:
        raise RuntimeError("start_trace returned None")
    lg.add_workflow_span(input=inp, output=out, name="patchbot_run", metadata=meta, created_at=start,
                         duration_ns=total_ns)
    lg.add_agent_span(input=inp, output=out, name="PatchBot", agent_type=agent_type, metadata=meta,
                      created_at=start, duration_ns=total_ns)
    steps: List[Dict[str, Any]] = [dict(r, _kind="llm") for r in rec.get("llm_calls") or []]
    steps += [dict(r, _kind="tool") for r in rec.get("tool_calls") or []]
    steps.sort(key=lambda r: float(r.get("at") or 0.0))
    try:
        from splunk_ao.logger.control import ControlAppliesTo, ControlCheckStage, ControlResult
    except Exception:  # noqa: BLE001
        ControlAppliesTo = ControlCheckStage = ControlResult = None  # type: ignore[assignment]
    n = 0
    for step in steps:
        dur = _ns(step.get("duration_ms"))
        at = start + timedelta(seconds=float(step.get("at") or 0.0)) - timedelta(
            microseconds=(dur or 0) / 1000)
        if step["_kind"] == "llm":
            lg.add_llm_span(input=str(step.get("input") or ""), output=str(step.get("output") or ""),
                            model=str(step.get("model") or rec.get("model") or "unknown"), name="patchbot_llm",
                            num_input_tokens=step.get("input_tokens"), num_output_tokens=step.get("output_tokens"),
                            created_at=at, duration_ns=dur, metadata=meta)
            continue
        n += 1
        control = step.get("control") or {}
        decision = str(step.get("decision") or "allow")
        tool_meta = dict(meta)
        tool_meta.update({"tool_server": str(step.get("server") or ""), "tool_origin": str(step.get("origin") or ""),
                          "control_decision": decision,
                          "controls_matched": ",".join(control.get("controls") or []),
                          "controls_mode": str(control.get("backend") or "")})
        if ControlResult is not None and hasattr(lg, "add_control_span"):
            names = control.get("controls") or ["patchbot-tool-pre"]
            decisions = control.get("decisions") or []
            for i, name in enumerate(names):
                d = decisions[i] if i < len(decisions) else ("observe" if decision in ("allow", "error") else decision)
                action = d if d in ("deny", "steer", "observe") else "observe"
                lg.add_control_span(
                    input=str(step.get("arguments") or ""),
                    output=ControlResult(action=action, matched=bool(control.get("controls")),
                                         confidence=None,
                                         error_message=control.get("error_message") if control.get("errored") else None),
                    name=str(name), created_at=at, duration_ns=_ns(control.get("duration_ms")), metadata=tool_meta,
                    status_code=500 if control.get("errored") else 200, agent_name=control.get("agent_name") or None,
                    check_stage=ControlCheckStage("pre"), applies_to=ControlAppliesTo("tool_call"))
        status = 200 if step.get("ok") else (403 if decision in ("deny", "steer") else 500)
        lg.add_tool_span(input=str(step.get("arguments") or ""), output=str(step.get("output") or ""),
                         name=str(step.get("name") or "tool"), tool_call_id=step.get("call_id"), step_number=n,
                         status_code=status, created_at=at, duration_ns=dur, metadata=tool_meta)
    lg.conclude(output=out, duration_ns=total_ns)   # agent
    lg.conclude(output=out, duration_ns=total_ns)   # workflow
    lg.conclude(output=out, duration_ns=total_ns)   # trace envelope
