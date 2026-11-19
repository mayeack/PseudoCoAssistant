"""PatchBot's tools, and the one door every tool call goes through (docs/patchbot.md).

``call(run, name, args)`` is the only way anything changes an estate:

1. the arguments are enriched with what the rules read (host OS and
   environment, the change and its status) — never with anything the caller
   sends about who they are;
2. ``controls.decide`` judges the call BEFORE it runs (Agent Observability
   Controls on the PatchBot Agent stream, fail closed for changes);
3. Cisco AI Defense inspects the rendered call when it is configured
   (recorded, not enforced: the Controls enforce);
4. the tool runs only if the verdict lets it;
5. a ``pseudoco:patchbot:tool`` event and a tool record for the trace are
   written whatever happened.

The UI's buttons (Patch, Dismiss, the exposure answer) call the same tools as
the model does, so a Viewer's Dismiss is denied exactly like a model's.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from backend.patchbot import catalog, controls, splunk_mcp, store, telemetry
from backend.patchbot import estate as est
from backend.patchbot.run import Run, short_json

logger = logging.getLogger(__name__)

_SERVERS = list(est.HOSTS.keys())
_CVES = catalog.cve_ids()

# name -> (description, JSON schema properties, required, server)
SPECS: Dict[str, Dict[str, Any]] = {
    "list_servers": {"description": "List the servers in your estate with OS, environment and exposure.",
                     "properties": {}, "required": [], "server": "patchops"},
    "get_server": {"description": "Show one server: OS, environment, packages and open findings.",
                   "properties": {"server": {"type": "string", "enum": _SERVERS}},
                   "required": ["server"], "server": "patchops"},
    "get_finding": {"description": "Read a vulnerability finding by CVE, including its Splunk ES finding when one exists.",
                    "properties": {"cve": {"type": "string", "enum": _CVES}},
                    "required": ["cve"], "server": "splunk-mcp"},
    "lookup_cve": {"description": "Look up a CVE: KEV status, EPSS, CVSS, fixed version, BOD 26-04 inputs.",
                   "properties": {"cve": {"type": "string", "enum": _CVES}},
                   "required": ["cve"], "server": "patchops"},
    "scan_server": {"description": "Rescan one server; open CVEs are reported to Splunk.",
                    "properties": {"server": {"type": "string", "enum": _SERVERS}},
                    "required": ["server"], "server": "scanner-mcp"},
    "update_exposure_model": {"description": "Record who can reach a server (exposure model), and any compensating control.",
                              "properties": {"server": {"type": "string", "enum": _SERVERS},
                                             "publicly_exposed": {"type": "boolean"},
                                             "compensating_control": {"type": "string"}},
                              "required": ["server", "publicly_exposed"], "server": "patchops"},
    "triage_finding": {"description": "Dismiss a finding (false_positive, accepted_risk, duplicate) with a note, or reopen it.",
                       "properties": {"cve": {"type": "string", "enum": _CVES},
                                      "action": {"type": "string", "enum": ["dismiss", "reopen"]},
                                      "reason": {"type": "string", "enum": list(est.DISMISS_REASONS)},
                                      "note": {"type": "string"}},
                       "required": ["cve", "action"], "server": "patchops"},
    "create_change": {"description": "Open a change: normal (production, the Change Board approves it) or standard "
                                     "(non-production, pre-approved by the standard change template).",
                      "properties": {"cve": {"type": "string", "enum": _CVES},
                                     "servers": {"type": "array", "items": {"type": "string", "enum": _SERVERS}},
                                     "model": {"type": "string", "enum": ["normal", "standard"]},
                                     "plan": {"type": "string"}},
                      "required": ["cve", "servers"], "server": "patchops"},
    "get_change": {"description": "Read a change on the Change Board.",
                   "properties": {"change_id": {"type": "string"}},
                   "required": ["change_id"], "server": "patchops"},
    "apply_patch": {"description": "Apply the fix for one CVE to one server. Production needs an approved change.",
                    "properties": {"server": {"type": "string", "enum": _SERVERS},
                                   "cve": {"type": "string", "enum": _CVES},
                                   "change_id": {"type": "string"}},
                    "required": ["server", "cve"], "server": "patchops"},
    "verify_patch": {"description": "Check a patch: CVE gone, no new exposure, service healthy.",
                     "properties": {"server": {"type": "string", "enum": _SERVERS},
                                    "cve": {"type": "string", "enum": _CVES}},
                     "required": ["server", "cve"], "server": "patchops"},
    "run_command": {"description": "Run a shell command on a server.",
                    "properties": {"server": {"type": "string", "enum": _SERVERS},
                                   "command": {"type": "string"}},
                    "required": ["server", "command"], "server": "patchops"},
    "stop_service": {"description": "Stop a service on a server.",
                     "properties": {"server": {"type": "string", "enum": _SERVERS},
                                    "service": {"type": "string"}},
                     "required": ["server", "service"], "server": "patchops"},
    "report_vulnerability": {"description": "Scanner: report one open CVE on one host to Splunk.",
                             "properties": {"server": {"type": "string"}, "cve": {"type": "string"}},
                             "required": ["server", "cve"], "server": "scanner-mcp"},
    # The third-party vendor server's one tool. Its description comes from
    # mcp_servers (clean or poisoned); it is offered only while connected.
    "get_vendor_advisory": {"description": "Return the vendor's remediation advisory for a CVE.",
                            "properties": {"cve": {"type": "string", "enum": _CVES}},
                            "required": ["cve"], "server": "vendor-advisories"},
}

# What the model is offered (the scanner's own report tool is not a model tool;
# the vendor's tool joins only while its server is connected).
MODEL_TOOLS = [n for n in SPECS if n not in ("report_vulnerability", "get_vendor_advisory")]


def _schema(name: str, description: str) -> Dict[str, Any]:
    spec = SPECS[name]
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": spec["properties"],
                       "required": spec["required"], "additionalProperties": False}}}


def schemas(owner: Optional[str] = None) -> List[Dict[str, Any]]:
    """OpenAI-style tool schemas for ``bind_tools``. With an owner whose vendor
    server is connected, the vendor's tool comes with the description its server
    publishes, which is how a poisoned description reaches the model."""
    out = [_schema(name, SPECS[name]["description"]) for name in MODEL_TOOLS]
    if owner:
        from backend.patchbot import mcp_scan, mcp_servers
        state = store.load_estate(owner)
        if mcp_scan.vendor_usable(state):
            poisoned = bool(mcp_scan.vendor_state(state).get("poisoned"))
            out.append(_schema("get_vendor_advisory", mcp_servers.vendor_description(poisoned)))
    return out


# --------------------------------------------------------------------------- enrichment

def _now() -> datetime:
    return datetime.utcnow()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", ""))
    except ValueError:
        return None


def _change_for(run: Run, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cid = str(args.get("change_id") or "").strip()
    if cid:
        change = store.get_change(cid)
        return change if change and change.get("owner") == run.owner else None
    cve = str(args.get("cve") or "").upper()
    return store.open_change_for(run.owner, cve) if cve else None


def build_step(run: Run, state: Dict[str, Any], name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """``{"input": ..., "context": ...}`` for the Controls."""
    tool_input: Dict[str, Any] = dict(args)
    server = str(args.get("server") or "")
    h = est.host(state, server) if server else None
    if h:
        tool_input.update({"os_family": h["os_family"], "environment": h["environment"],
                           "publicly_exposed": "yes" if h.get("publicly_exposed") else "no"})
    elif name == "create_change":
        listed = [est.host(state, s) for s in (args.get("servers") or [])]
        families = {x["os_family"] for x in listed if x}
        envs = {x["environment"] for x in listed if x}
        if len(families) == 1:
            tool_input["os_family"] = families.pop()
        if envs:
            tool_input["environment"] = "production" if "production" in envs else sorted(envs)[0]
    context: Dict[str, Any] = {"app": "pseudoco-assistant", "feature": "patchbot",
                               "estate_owner": run.owner, "session_id": run.session_id,
                               **run.initiator.context()}
    if name == "apply_patch":
        change = _change_for(run, args)
        context["change_id"] = (change or {}).get("id") or ""
        context["change_status"] = (change or {}).get("status") or "none"
        covers = bool(change) and change["cve"] == str(args.get("cve") or "").upper() \
            and server in (change.get("servers") or [])
        context["change_covers_call"] = "yes" if covers else "no"
        start, end = _parse_iso((change or {}).get("window_start")), _parse_iso((change or {}).get("window_end"))
        inside = bool(start and end and start <= _now() <= end)
        context["in_change_window"] = "yes" if (inside or not change) else "no"
    return {"input": tool_input, "context": context}


# --------------------------------------------------------------------------- AI Defense (recorded)

def _ai_defense(rendered: str, enduser: str) -> Dict[str, Any]:
    try:
        from backend.services.ai_defense import ai_defense_client
        if not ai_defense_client.is_configured:
            return {"action": "not_configured", "rules": []}
        res = ai_defense_client.inspect_prompt(rendered, enduser_id=enduser, src_app="pseudoco-assistant-patchbot")
        if getattr(res, "errored", False):
            return {"action": "error", "rules": []}
        return {"action": "block" if getattr(res, "should_block", False) else "allow",
                "rules": list(getattr(res, "rule_names", []) or [])}
    except Exception:  # noqa: BLE001
        logger.debug("PatchBot AI Defense inspection failed", exc_info=True)
        return {"action": "error", "rules": []}


# --------------------------------------------------------------------------- the door

def call(run: Run, name: str, args: Optional[Dict[str, Any]] = None, *, call_id: Optional[str] = None,
         origin: str = "model") -> Dict[str, Any]:
    """Judge, then (maybe) run one tool call. Returns
    ``{"ok", "denied", "steered", "output", "verdict", "call_id"}``. Never raises."""
    args = dict(args or {})
    call_id = call_id or f"call_{uuid.uuid4().hex[:12]}"
    started = time.perf_counter()
    spec = SPECS.get(name)
    if spec is None:
        return _finish(run, name, args, call_id, started, None, {"error": f"unknown tool {name}"},
                       ok=False, origin=origin, server="patchops", ai={})
    with store.owner_lock(run.owner):
        state = store.load_estate(run.owner)
        step = build_step(run, state, name, args)
        verdict = controls.decide(name, step["input"], step["context"])
        ai = {}
        if name in controls.MUTATING_TOOLS:
            from backend.services.tool_policy import render_tool_call
            ai = _ai_defense(render_tool_call(name, args), run.initiator.username)
        if not verdict.runs:
            text = verdict.deny_reason if verdict.decision == "deny" else verdict.steer_message
            output = {"denied": verdict.decision == "deny", "steered": verdict.decision == "steer",
                      "message": text, "controls": verdict.controls_matched}
            return _finish(run, name, args, call_id, started, verdict, output, ok=False, origin=origin,
                           server=spec["server"], ai=ai, step=step)
        try:
            output = _HANDLERS[name](run, state, args)
            ok = not (isinstance(output, dict) and output.get("error"))
        except ValueError as exc:
            output, ok = {"error": str(exc)}, False
        except Exception as exc:  # noqa: BLE001
            logger.exception("PatchBot tool %s failed", name)
            output, ok = {"error": f"{type(exc).__name__}"}, False
        return _finish(run, name, args, call_id, started, verdict, output, ok=ok, origin=origin,
                       server=spec["server"], ai=ai, step=step)


def _finish(run: Run, name: str, args: Dict[str, Any], call_id: str, started: float,
            verdict: Optional[controls.Verdict], output: Any, *, ok: bool, origin: str, server: str,
            ai: Dict[str, Any], step: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latency = round((time.perf_counter() - started) * 1000, 1)
    v = verdict or controls.Verdict(decision="error", errored=True, error_message="unknown tool")
    step_input = (step or {}).get("input") or {}
    step_ctx = (step or {}).get("context") or {}
    telemetry.emit("tool", "tool_call", {
        **run.common(),
        "tool_name": name, "tool_server": server, "tool_call_id": call_id, "origin": origin,
        "decision": v.decision, "enforced": v.enforced, "controls_matched": v.controls_matched,
        "control_decisions": v.decisions, "deny_reason": v.deny_reason, "steer_message": v.steer_message,
        "fail_closed": v.fail_closed, "controls_mode": v.mode, "controls_error": v.error_message,
        "dest": step_input.get("server") or args.get("server"), "dest_os": step_input.get("os_family"),
        "dest_env": step_input.get("environment"), "cve": str(args.get("cve") or "").upper() or None,
        "change_id": step_ctx.get("change_id"), "change_status": step_ctx.get("change_status"),
        "ai_defense_action": ai.get("action"), "ai_defense_rules": ai.get("rules"),
        "status": "ok" if ok else ("denied" if v.decision == "deny" else "steered" if v.decision == "steer" else "error"),
        "latency_ms": latency, "controls_latency_ms": v.duration_ms,
        "model": run.model, "args_redacted": short_json(args, 1500),
    })
    if v.decision in ("deny", "steer") and origin != "scanner":
        cve = str(args.get("cve") or "").upper() or None
        what = f"{name.replace('_', ' ')}" + (f" on {args.get('server')}" if args.get("server") else "")
        try:
            store.add_activity(run.owner, "denied", f"{what.capitalize()} {'denied' if v.decision == 'deny' else 'steered'}: "
                               f"{v.deny_reason or v.steer_message or 'policy'}", actor="Agent Observability Controls",
                               actor_type="agent", finding_id=est.finding_id(run.owner, cve) if cve else None,
                               data={"controls": v.controls_matched, "initiator": run.initiator.username})
        except Exception:  # noqa: BLE001
            logger.debug("PatchBot deny activity write failed", exc_info=True)
    run.add_tool({"name": name, "server": server, "call_id": call_id, "arguments": short_json(args, 1500),
                  "output": short_json(output, 2000), "ok": ok, "duration_ms": latency,
                  "decision": v.decision, "control": v.record(), "origin": origin})
    return {"ok": ok, "denied": v.decision == "deny", "steered": v.decision == "steer",
            "output": output, "verdict": {"decision": v.decision, "controls": v.controls_matched,
                                          "message": v.deny_reason or v.steer_message,
                                          "fail_closed": v.fail_closed, "mode": v.mode},
            "call_id": call_id}


# --------------------------------------------------------------------------- handlers

def _save(run: Run, state: Dict[str, Any]) -> None:
    store.save_estate(run.owner, state)


def _h_list_servers(run: Run, state, args):
    found = est.findings(state, run.owner)
    return {"servers": [{"name": h["name"], "os": h["os"], "os_family": h["os_family"],
                         "environment": h["environment"], "purpose": h["purpose"],
                         "publicly_exposed": h["publicly_exposed"],
                         "open_findings": [f["cve"] for f in found if f["status"] == "open" and h["name"] in f["open_hosts"]]}
                        for h in est.hosts(state)]}


def _h_get_server(run: Run, state, args):
    h = est.host(state, str(args.get("server")))
    if not h:
        raise ValueError("unknown server")
    found = est.findings(state, run.owner)
    return {**{k: h[k] for k in ("name", "os", "os_family", "environment", "purpose", "publicly_exposed",
                                 "exposure_source", "compensating_control", "packages")},
            "open_findings": [f["cve"] for f in found if f["status"] == "open" and h["name"] in f["open_hosts"]]}


def _h_get_finding(run: Run, state, args):
    cve = str(args.get("cve") or "").upper()
    f = est.finding(state, run.owner, cve)
    if not f:
        raise ValueError("unknown finding")
    es = None
    if splunk_mcp.configured():
        es = splunk_mcp.find_es_finding(run.owner, cve)
    keep = ("id", "cve", "title", "severity", "status", "hosts", "open_hosts", "package", "installed_version",
            "fixed_version", "kev", "epss", "bod", "how_to_fix", "change_id")
    return {**{k: f[k] for k in keep},
            "es_finding": (es or {}).get("text") if es and es.get("ok") else None,
            "es_source": "splunk-mcp" if es and es.get("ok") else ("splunk-mcp unavailable" if es else "local record")}


def _h_lookup_cve(run: Run, state, args):
    entry = catalog.cve(str(args.get("cve")))
    if not entry:
        raise ValueError("unknown CVE")
    keep = ("cve", "short", "kev", "kev_date_added", "kev_ransomware", "epss", "epss_percentile", "cvss",
            "exploitation", "automatable", "technical_impact", "package", "vulnerable_version", "fixed_version",
            "fix_text")
    return {k: entry.get(k) for k in keep}


def scan(run: Run, state: Dict[str, Any], hosts: Optional[List[str]], mode: str) -> Dict[str, Any]:
    """The Scanner MCP server: read the hosts, report each open CVE through
    ``report_vulnerability`` (a judged MCP tool call that writes the Splunk event)."""
    scan_id = f"scan-{uuid.uuid4().hex[:6]}"
    rows = est.scan_results(state, hosts)
    open_rows = [r for r in rows if r["status"] == "open"]
    for r in open_rows:
        call(run, "report_vulnerability", {"server": r["dest"], "cve": r["cve"], "_scan_id": scan_id,
                                           "_mode": mode}, origin="scanner")
    for r in rows:
        if r["status"] == "fixed":
            telemetry.emit("vuln", "vulnerability_report", {**run.common(), **_vuln_fields(r, scan_id, mode),
                                                            "finding_id": est.finding_id(run.owner, r["cve"])})
    return {"scan_id": scan_id, "hosts": hosts or list(state["hosts"].keys()),
            "open": [{"server": r["dest"], "cve": r["cve"], "severity": r["severity"]} for r in open_rows],
            "fixed": [{"server": r["dest"], "cve": r["cve"]} for r in rows if r["status"] == "fixed"]}


def _vuln_fields(r: Dict[str, Any], scan_id: str, mode: str) -> Dict[str, Any]:
    return {"scan_id": scan_id, "scan_mode": mode, "dest": r["dest"], "dest_os": r["dest_os"],
            "dest_env": r["dest_env"], "cve": r["cve"], "signature": r["signature"], "severity": r["severity"],
            "cvss": r["cvss"], "category": "os_package", "vendor_product": "PseudoCo Scanner",
            "package": r["package"], "installed_version": r["installed_version"],
            "fixed_version": r["fixed_version"], "status": r["status"], "kev": r["kev"], "epss": r["epss"],
            "automatable": r["automatable"], "technical_impact": r["technical_impact"],
            "publicly_exposed": r["publicly_exposed"], "bod_row": r["bod_row"], "bod_timeline": r["bod_timeline"],
            "due_days": r["due_days"], "forensic_triage": "yes" if r["forensic_triage"] else "no"}


def _h_report_vulnerability(run: Run, state, args):
    server, cve = str(args.get("server")), str(args.get("cve")).upper()
    row = next((r for r in est.scan_results(state, [server]) if r["cve"] == cve), None)
    if row is None:
        raise ValueError("not applicable")
    telemetry.emit("vuln", "vulnerability_report", {
        **run.common(), **_vuln_fields(row, str(args.get("_scan_id") or ""), str(args.get("_mode") or "rescan")),
        "finding_id": est.finding_id(run.owner, cve)})
    return {"reported": True, "server": server, "cve": cve, "severity": row["severity"]}


def _after_scan(run: Run, result: Dict[str, Any]) -> None:
    from backend.patchbot import service
    service.after_scan(run, result)


def _h_scan_server(run: Run, state, args):
    server = str(args.get("server"))
    if server not in state["hosts"]:
        raise ValueError("unknown server")
    result = scan(run, state, [server], "rescan")
    _after_scan(run, result)
    return result


def _h_update_exposure_model(run: Run, state, args):
    from backend.patchbot import service
    return service.update_exposure(run, state, str(args.get("server")), bool(args.get("publicly_exposed")),
                                   args.get("compensating_control"))


def _h_triage_finding(run: Run, state, args):
    from backend.patchbot import service
    return service.triage(run, state, str(args.get("cve")).upper(), str(args.get("action")),
                          str(args.get("reason") or ""), str(args.get("note") or ""))


def _h_create_change(run: Run, state, args):
    from backend.patchbot import service
    return service.open_change(run, state, str(args.get("cve")).upper(), list(args.get("servers") or []),
                               str(args.get("plan") or ""), model=str(args.get("model") or "normal"),
                               **{k: args[k] for k in ("investigation_id", "es_finding_id", "es_requested_by",
                                                       "auto_execute") if k in args})


def _h_get_change(run: Run, state, args):
    change = store.get_change(str(args.get("change_id")))
    if not change or change["owner"] != run.owner:
        raise ValueError("unknown change")
    return change


def _h_apply_patch(run: Run, state, args):
    from backend.patchbot import service
    return service.patch(run, state, str(args.get("server")), str(args.get("cve")).upper(),
                         str(args.get("change_id") or "") or None)


def _h_verify_patch(run: Run, state, args):
    from backend.patchbot import service
    return service.verify(run, state, str(args.get("server")), str(args.get("cve")).upper())


def _h_restricted(run: Run, state, args):
    # Never executes anything: the estate is synthetic, and the Controls deny these first.
    return {"error": "PatchBot has no permission to run this."}


def _h_get_vendor_advisory(run: Run, state, args):
    from backend.patchbot import mcp_scan, service
    if not mcp_scan.vendor_usable(state):
        return {"error": "The vendor's MCP server is not connected."}
    cve = str(args.get("cve") or "").upper()
    if cve not in _CVES:
        raise ValueError(f"unknown CVE {cve}")
    # A poisoned vendor server poisons what it returns as well as its description:
    # the scan can only see the description; the Controls stop what the payload asks.
    poisoned = bool(mcp_scan.vendor_state(state).get("poisoned"))
    return {"cve": cve, "advisory": service.advisory_text(cve, poisoned=poisoned), "source": "vendor-advisories"}


_HANDLERS: Dict[str, Callable[[Run, Dict[str, Any], Dict[str, Any]], Any]] = {
    "list_servers": _h_list_servers, "get_server": _h_get_server, "get_finding": _h_get_finding,
    "lookup_cve": _h_lookup_cve, "scan_server": _h_scan_server, "update_exposure_model": _h_update_exposure_model,
    "triage_finding": _h_triage_finding, "create_change": _h_create_change, "get_change": _h_get_change,
    "apply_patch": _h_apply_patch, "verify_patch": _h_verify_patch, "run_command": _h_restricted,
    "stop_service": _h_restricted, "report_vulnerability": _h_report_vulnerability,
    "get_vendor_advisory": _h_get_vendor_advisory,
}
