"""Which PatchBot tool calls may run (docs/patchbot.md).

Every proposed tool call becomes an Agent Control ``tool`` step at the ``pre``
stage: ``input`` is the call's arguments enriched with what the rules read
(the host's OS and environment, the change's status), ``context`` is who the
call acts for. Two modes (``PATCHBOT_CONTROLS_MODE``):

- ``agent_observability`` (the workshop): the Splunk Agent Observability
  Controls attached to the PatchBot Agent stream decide. When they cannot
  answer, read tools run and every other tool is refused (``fail_closed``):
  an unreachable policy server must never let a production patch through.
- ``local``: ``CONTROL_DEFINITIONS`` below are evaluated in-process with the
  same scope / selector / list / regex / and-or-not semantics. For offline
  development and tests only; every event says which mode decided.

``CONTROL_DEFINITIONS`` is also what ``scripts/patchbot/ao_controls.py``
creates in Agent Observability, so the rules attendees read in the Controls
UI are the rules the local mode runs.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.config import settings

READ_TOOLS = frozenset({"list_servers", "get_server", "get_finding", "lookup_cve",
                        "scan_server", "verify_patch", "get_change", "report_vulnerability"})
MUTATING_TOOLS = frozenset({"update_exposure_model", "triage_finding", "create_change",
                            "apply_patch", "run_command", "stop_service"})
AGENT_NAME = "pseudoco-assistant-patchbot"
SENTINEL = "observe-all-patches"   # matches every apply_patch when the controls are attached

_ROLE = "context.initiator_role"


def _list(path: str, values: List[str], *, match_on: str = "match") -> Dict[str, Any]:
    return {"selector": {"path": path},
            "evaluator": {"name": "list", "config": {"values": values, "logic": "any",
                                                      "match_on": match_on, "match_mode": "exact",
                                                      "case_sensitive": False}}}


def _any(path: str) -> Dict[str, Any]:
    return {"selector": {"path": path}, "evaluator": {"name": "regex", "config": {"pattern": ".+"}}}


def _control(name: str, description: str, *, steps: List[str], condition: Dict[str, Any],
             decision: str, message: str) -> Dict[str, Any]:
    return {
        "name": name,
        "data": {
            "description": description,
            "enabled": True,
            "execution": "server",
            "scope": {"step_types": ["tool"], "step_names": steps, "stages": ["pre"]},
            "condition": condition,
            "action": {"decision": decision, "steering_context": {"message": message}},
        },
    }


CONTROL_DEFINITIONS: List[Dict[str, Any]] = [
    _control(
        "deny-patch-outside-role-os",
        "PatchBot patches only the operating system the initiator's role covers.",
        steps=["apply_patch"],
        condition={"or": [
            {"and": [_list(_ROLE, ["linux_patch_operator"]), _list("input.os_family", ["windows"])]},
            {"and": [_list(_ROLE, ["windows_patch_operator"]), _list("input.os_family", ["linux"])]},
        ]},
        decision="deny",
        message="This patch is outside your role: a Linux Patch Operator patches Linux hosts and a "
                "Windows Patch Operator patches Windows hosts.",
    ),
    _control(
        "deny-viewer-actions",
        "Patch Viewers and Change Approvers can look, not change. Approvers approve on the Change Board.",
        steps=["triage_finding", "update_exposure_model", "create_change", "apply_patch"],
        condition=_list(_ROLE, ["patch_viewer", "change_approver"]),
        decision="deny",
        message="Your role can view findings but not change anything.",
    ),
    _control(
        "deny-prod-without-approved-change",
        "No production patch without an approved change.",
        steps=["apply_patch"],
        condition={"and": [_list("input.environment", ["production"]),
                           _list("context.change_status", ["approved"], match_on="no_match")]},
        decision="deny",
        message="Production needs an approved change. Request approval on the Change Board first.",
    ),
    _control(
        "deny-patch-outside-change",
        "A production patch must match its approved change: same CVE, a listed host.",
        steps=["apply_patch"],
        condition={"and": [_list("input.environment", ["production"]),
                           _list("context.change_status", ["approved"]),
                           _list("context.change_covers_call", ["no"])]},
        decision="deny",
        message="This patch is not on the approved change. Patch only the CVE and hosts the change lists.",
    ),
    _control(
        "steer-outside-window",
        "Production patches go inside the change window.",
        steps=["apply_patch"],
        condition={"and": [_list("input.environment", ["production"]),
                           _list("context.change_status", ["approved"]),
                           _list("context.in_change_window", ["no"])]},
        decision="steer",
        message="The change window is not open. Schedule this patch inside the window on the change.",
    ),
    _control(
        "deny-restricted-tools",
        "Commands and service stops are not PatchBot's to run, for any role.",
        steps=["run_command", "stop_service"],
        condition=_any(_ROLE),
        decision="deny",
        message="PatchBot does not run commands or stop services.",
    ),
    _control(
        "observe-all-patches",
        "Record every patch attempt.",
        steps=["apply_patch"],
        condition=_any(_ROLE),
        decision="observe",
        message="Recorded.",
    ),
]


@dataclass
class Verdict:
    decision: str = "allow"           # allow | deny | steer | observe | error
    enforced: bool = False            # a deny that stopped the call
    controls_matched: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    deny_reason: Optional[str] = None
    steer_message: Optional[str] = None
    fail_closed: bool = False
    errored: bool = False
    error_message: Optional[str] = None
    mode: str = "local"
    duration_ms: float = 0.0
    target: Optional[str] = None
    transport: Optional[str] = None

    @property
    def runs(self) -> bool:
        return self.decision not in ("deny", "steer")

    def record(self) -> Dict[str, Any]:
        """The AO control-span record (agent_observability rebuilds spans from it)."""
        return {"stage": "pre", "controls": list(self.controls_matched), "decisions": list(self.decisions),
                "errored": self.errored, "error_message": self.error_message, "duration_ms": self.duration_ms,
                "backend": "splunk_ao" if self.mode == "agent_observability" else "local",
                "transport": self.transport or self.mode, "target": self.target or "",
                "agent_name": AGENT_NAME}


# --------------------------------------------------------------------------- local engine

def _resolve(path: str, step: Dict[str, Any]) -> Any:
    if path == "*":
        return step
    cur: Any = step
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _leaf(node: Dict[str, Any], step: Dict[str, Any]) -> bool:
    value = _resolve((node.get("selector") or {}).get("path") or "*", step)
    ev = node.get("evaluator") or {}
    cfg = ev.get("config") or {}
    if ev.get("name") == "regex":
        return value is not None and re.search(cfg.get("pattern") or "", str(value)) is not None
    if ev.get("name") == "list":
        values = [str(v) for v in cfg.get("values") or []]
        target = str(value) if value is not None else ""
        if not cfg.get("case_sensitive"):
            values = [v.lower() for v in values]
            target = target.lower()
        hit = target in values
        return hit if (cfg.get("match_on") or "match") == "match" else not hit
    raise ValueError(f"unsupported evaluator {ev.get('name')!r}")


def _matches(node: Dict[str, Any], step: Dict[str, Any]) -> bool:
    if "and" in node:
        return all(_matches(c, step) for c in node["and"])
    if "or" in node:
        return any(_matches(c, step) for c in node["or"])
    if "not" in node:
        return not _matches(node["not"], step)
    return _leaf(node, step)


def evaluate_local(tool_name: str, tool_input: Dict[str, Any], context: Dict[str, Any]) -> Verdict:
    started = time.perf_counter()
    step = {"type": "tool", "name": tool_name, "input": tool_input, "context": context}
    v = Verdict(mode="local", transport="local")
    for control in CONTROL_DEFINITIONS:
        data = control["data"]
        scope = data["scope"]
        if tool_name not in scope["step_names"]:
            continue
        if _matches(data["condition"], step):
            decision = data["action"]["decision"]
            v.controls_matched.append(control["name"])
            v.decisions.append(decision)
            message = (data["action"].get("steering_context") or {}).get("message")
            if decision == "deny" and not v.deny_reason:
                v.deny_reason = message
            if decision == "steer" and not v.steer_message:
                v.steer_message = message
    _settle(v)
    v.duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return v


def _settle(v: Verdict) -> None:
    if "deny" in v.decisions:            # deny wins
        v.decision, v.enforced = "deny", True
    elif "steer" in v.decisions:
        v.decision = "steer"
    elif v.decisions:
        v.decision = "observe"
    else:
        v.decision = "allow"


# --------------------------------------------------------------------------- the decision point

def mode() -> str:
    m = (settings.patchbot_controls_mode or "agent_observability").strip().lower()
    return "local" if m == "local" else "agent_observability"


def decide(tool_name: str, tool_input: Dict[str, Any], context: Dict[str, Any]) -> Verdict:
    """The verdict on one proposed call. Never raises."""
    if mode() == "local":
        return evaluate_local(tool_name, tool_input, context)
    from backend.services.agent_control import agent_control_client
    try:
        cv = agent_control_client.evaluate_tool_call(
            tool_name, tool_input, context,
            stream=settings.patchbot_agent_stream or "PatchBot", agent_name=AGENT_NAME,
            tool_names=sorted(READ_TOOLS | MUTATING_TOOLS))
    except Exception as exc:  # noqa: BLE001
        cv = None
        error = str(exc)[:200]
    v = Verdict(mode="agent_observability")
    if cv is None or cv.errored:
        v.errored = True
        v.error_message = (cv.error_message if cv is not None else error) or "unavailable"
        v.duration_ms = getattr(cv, "duration_ms", 0.0) or 0.0
        v.target = getattr(cv, "target", None)
        v.transport = getattr(cv, "transport", None)
        if tool_name in READ_TOOLS:
            v.decision = "error"          # reads run; the event says the check could not run
        else:
            v.decision, v.enforced, v.fail_closed = "deny", True, True
            v.deny_reason = ("Agent Observability Controls could not be reached, so PatchBot refused "
                             "this change (fail closed).")
        return v
    v.controls_matched = list(cv.matched_controls)
    v.decisions = [str(d).lower() for d in cv.decisions]
    msgs = list(getattr(cv, "messages", []) or [])
    if "deny" in v.decisions:
        # The denying control's own message, as its author wrote it in the
        # Controls UI; the evaluator's reason ("Condition tree matched") only
        # when the control has none.
        authored = getattr(cv, "guidance_by_control", {}) or {}
        denying = [n for n, d in zip(v.controls_matched, v.decisions) if d == "deny"]
        v.deny_reason = (next((authored[n] for n in denying if authored.get(n)), None) or cv.reason
                         or (msgs[0] if msgs else "Denied by Agent Observability Controls."))
    if "steer" in v.decisions:
        steering = list(cv.steering or [])
        v.steer_message = steering[0] if steering else (msgs[0] if msgs else "Adjust the call to the policy.")
    _settle(v)
    if cv.should_block and v.decision != "deny":
        v.decision, v.enforced = "deny", True
        v.deny_reason = v.deny_reason or cv.reason or "Denied by Agent Observability Controls."
    # Sentinel: observe-all-patches matches EVERY apply_patch once the controls are
    # attached. An answer without it means the stream has no PatchBot controls, and
    # a clean verdict from an empty policy must never let a patch through.
    if tool_name == "apply_patch" and v.decision != "deny" and SENTINEL not in v.controls_matched:
        v.decision, v.enforced, v.fail_closed = "deny", True, True
        v.deny_reason = (f"The PatchBot controls are not attached to the {settings.patchbot_agent_stream or 'PatchBot'} "
                         "Agent stream, so PatchBot refused this patch (fail closed).")
    v.duration_ms = cv.duration_ms
    v.target = cv.target
    v.transport = cv.transport
    return v
