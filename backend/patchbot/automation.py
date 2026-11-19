"""Splunk SOAR → PatchBot automation, and the lab's attack console (docs/patchbot-automation-api.md).

The Splunk-first labs start in Enterprise Security: a detection sees CVE-2021-41773 being
exploited, the Guided Response assistant runs the PatchBot SOAR connector, and the connector
calls :func:`remediate`. PatchBot then:

1. checks its own toolchain has a clean, current Cisco AI Defense MCP Scanner verdict
   (an unsafe or unscanned toolchain refuses the job);
2. reads the ES investigation through the Splunk MCP Server, when it was named and the
   server is configured (a failed read is reported, never fatal);
3. opens a pre-approved standard change for the non-production servers and patches and
   verifies them, every call judged by the Controls with the operator's role from Duo;
4. opens a normal change for the production servers, which waits for the Change Board.
   An approval runs the queued patches on its own (:func:`execute_change`).

The attack console (:func:`attack`) replays the exploitation as web events for the detection.
"""
from __future__ import annotations

import hmac
import logging
import threading
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.patchbot import catalog, mcp_scan, roles, splunk_mcp, store, telemetry, tools
from backend.patchbot import estate as est
from backend.patchbot.run import Run

logger = logging.getLogger(__name__)

OWN_SERVERS = ("scanner-mcp", "patchops", "splunk-mcp")
SCANNER_NAME = "Cisco AI Defense MCP Scanner"
ATTACKER = "203.0.113.66"          # TEST-NET-3: documentation range, never a real host
ATTACK_UA = "curl/7.68.0"
EXPLOIT_CVE = "CVE-2021-41773"
SYNC_EXECUTION = False             # tests run an approved change inline


class AutomationError(Exception):
    def __init__(self, status: int, detail: str, body: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.status, self.detail, self.body = status, detail, body or {}


# --------------------------------------------------------------------------- settings and auth

def enabled() -> bool:
    return bool(str(getattr(settings, "patchbot_automation_token", "") or "").strip())


def token_ok(given: Any) -> bool:
    want = str(getattr(settings, "patchbot_automation_token", "") or "").strip()
    return bool(want) and hmac.compare_digest(str(given or "").strip().encode(), want.encode())


def owner() -> str:
    value = str(getattr(settings, "patchbot_automation_owner", "") or "pseudoco").strip()
    return value if est.valid_owner(value) else "pseudoco"


def _finish(run: Run) -> None:
    try:
        from backend import agent_observability
        agent_observability.maybe_log_patchbot_run(run.ao_record())
    except Exception:  # noqa: BLE001
        logger.debug("PatchBot AO enqueue failed", exc_info=True)


def _service_initiator(name: str) -> roles.Initiator:
    return roles.Initiator(username=name, role=roles.ESTATE_OWNER, roles=[roles.ESTATE_OWNER],
                           auth_method="service")


# --------------------------------------------------------------------------- the estate's inventory

def ensure_inventory(max_age_minutes: int = 60) -> Dict[str, Any]:
    """Make sure the estate's vulnerability inventory is in Splunk: a full read when the
    estate never had one, or its last one is older than ``max_age_minutes``."""
    from backend.patchbot import service
    name = owner()
    state = store.load_estate(name)
    last = str(state.get("last_full_read_at") or "")
    fresh = False
    if state.get("full_read_done") and last:
        try:
            fresh = datetime.utcnow() - datetime.fromisoformat(last.rstrip("Z")) < timedelta(minutes=max_age_minutes)
        except ValueError:
            fresh = False
    if fresh:
        return {"full_read": False}
    run = Run(initiator=_service_initiator("vulnerability-scanner"), owner=name, kind="full_read",
              session_id="scanner-scheduled", request_text="Scheduled full read of the estate")
    result = tools.scan(run, state, None, "full_read")
    service.after_scan(run, result)
    with store.owner_lock(name):
        state = store.load_estate(name)
        state["last_full_read_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        store.save_estate(name, state)
    run.output_text = f"Full read: {len(result.get('open') or [])} open CVE reports."
    _finish(run)
    return {"full_read": True, "open": len(result.get("open") or [])}


# --------------------------------------------------------------------------- toolchain trust check

def toolchain(run: Run, *, rescan_stale: bool = True) -> Dict[str, Any]:
    """PatchBot's own MCP servers and their Cisco AI Defense MCP Scanner verdicts. A server
    whose catalogue changed since its scan (or was never scanned) is rescanned first.

    A finding on a tool that a deny Control refuses for every role (PatchOps ``run_command``
    and ``stop_service``) is covered at runtime: that server is COMPENSATED, not unsafe. Any
    other finding (a poisoned description, say) makes the toolchain unsafe."""
    state = store.load_estate(run.owner)
    stale = [s for s in OWN_SERVERS if not mcp_scan.scan_is_current(state, s)]
    if stale and rescan_stale:
        mcp_scan.scan(run, stale)
        state = store.load_estate(run.owner)
    scans = state.get("mcp_scans") or {}
    servers, unsafe, unscanned, times = [], [], [], []
    for server_id in OWN_SERVERS:
        scan = scans.get(server_id)
        if not scan or not mcp_scan.scan_is_current(state, server_id):
            unscanned.append(server_id)
            servers.append({"server": server_id, "verdict": "UNSCANNED"})
            continue
        times.append(str(scan.get("scanned_at") or ""))
        flagged = [t for t in scan.get("tools") or [] if not t.get("is_safe")]
        covered = [{"tool": t["tool"], "threats": list(t.get("threats") or []), "control": t["compensated_by"]}
                   for t in flagged if t.get("compensated_by")]
        open_tools = [t["tool"] for t in flagged if not t.get("compensated_by")]
        row = {"server": server_id, "scanned_at": scan.get("scanned_at")}
        if scan.get("is_safe") or not flagged:
            servers.append({**row, "verdict": "SAFE"})
        elif not open_tools:
            servers.append({**row, "verdict": "COMPENSATED", "compensated": covered})
        else:
            unsafe.append(server_id)
            servers.append({**row, "verdict": str(scan.get("severity") or "unsafe").upper(),
                            "unsafe_tools": open_tools, "compensated": covered})
    verdict = "unsafe" if unsafe else ("unscanned" if unscanned else "clean")
    return {"verdict": verdict, "scanner": SCANNER_NAME, "analyzers": mcp_scan.analyzers(),
            "scanned_at": max(times) if times else None, "servers": servers,
            "unsafe": unsafe, "unscanned": unscanned}


# --------------------------------------------------------------------------- the ES record (Splunk MCP Server)

def read_investigation(investigation_id: Optional[str], finding_id: Optional[str], cve: str) -> Optional[Dict[str, Any]]:
    if not (investigation_id or finding_id):
        return None
    base = {"read_via": "Splunk MCP Server", "id": investigation_id or finding_id}
    if not splunk_mcp.configured():
        return {**base, "found": False, "error": "Splunk MCP Server not configured on this box"}
    try:
        answer = splunk_mcp.read_es_record(investigation_id=investigation_id, finding_id=finding_id, cve=cve)
    except Exception as exc:  # noqa: BLE001 - a failed read is reported, never fatal
        return {**base, "found": False, "error": type(exc).__name__}
    return {**base, **answer}


# --------------------------------------------------------------------------- remediation

def _reason(res: Dict[str, Any]) -> str:
    out = res.get("output") if isinstance(res.get("output"), dict) else {}
    return str((res.get("verdict") or {}).get("message") or out.get("message") or out.get("error") or "")


def _control(res: Dict[str, Any]) -> str:
    matched = (res.get("verdict") or {}).get("controls") or []
    denying = [c for c in matched if c.startswith(("deny-", "steer-"))]
    return (denying or matched or [""])[0]


def _change_view(change: Dict[str, Any]) -> Dict[str, Any]:
    return {"change_id": change["id"], "model": change.get("change_model"), "status": change["status"],
            "template": change.get("template"), "servers": list(change.get("servers") or []),
            "approver": change.get("approver"), "requested_by": change.get("requested_by")}


def _patch_and_verify(run: Run, server: str, cve: str, change_id: str, model: str) -> Dict[str, Any]:
    res = tools.call(run, "apply_patch", {"server": server, "cve": cve, "change_id": change_id}, origin="workflow")
    if res.get("ok"):
        out = res.get("output") or {}
        if out.get("already_patched"):
            return {"server": server, "change_id": change_id, "change_model": model, "outcome": "already_fixed"}
        ver = tools.call(run, "verify_patch", {"server": server, "cve": cve}, origin="workflow")
        checks = ver.get("output") or {}
        return {"server": server, "change_id": change_id, "change_model": model, "outcome": "patched",
                "verified": checks.get("check_cve_gone") == "confident",
                "version_before": out.get("version_before"), "version_after": out.get("version_after")}
    if res.get("denied") or res.get("steered"):
        return {"server": server, "change_id": change_id, "change_model": model, "outcome": "denied",
                "tool": "apply_patch", "control": _control(res), "reason": _reason(res)}
    return {"server": server, "change_id": change_id, "change_model": model, "outcome": "failed",
            "reason": _reason(res)}


def _summary(operator: roles.Initiator, results: List[Dict[str, Any]], changes: List[Dict[str, Any]]) -> str:
    by = lambda outcome: [r["server"] for r in results if r["outcome"] == outcome]  # noqa: E731
    parts: List[str] = []
    std = next((c for c in changes if c["model"] == "standard"), None)
    nrm = next((c for c in changes if c["model"] == "normal"), None)
    if by("patched"):
        parts.append(f"Patched and verified {', '.join(by('patched'))}"
                     + (f" under standard change {std['change_id']}." if std else "."))
    if nrm and by("awaiting_approval"):
        parts.append(f"{nrm['change_id']} for {', '.join(by('awaiting_approval'))} waits for the Change Board.")
    if by("denied"):
        reason = next(r.get("reason") for r in results if r["outcome"] == "denied")
        parts.append(f"Denied for {operator.username} ({operator.role_label}) on {', '.join(by('denied'))}: {reason}")
    if by("already_fixed"):
        parts.append(f"Already fixed: {', '.join(by('already_fixed'))}.")
    if by("failed"):
        parts.append(f"Failed: {', '.join(by('failed'))}.")
    return " ".join(parts) or "Nothing to do."


def remediate(body: Dict[str, Any]) -> Dict[str, Any]:
    cve = str(body.get("cve") or "").strip().upper()
    if cve not in catalog.cve_ids():
        raise AutomationError(404, f"Unknown CVE {cve or '(none)'}.")
    operator = roles.from_username(body.get("operator"))
    if operator is None:
        raise AutomationError(403, f"Unknown operator {str(body.get('operator') or '')[:64]!r}: "
                                   "PatchBot acts only for a user it can identify.")
    name = owner()
    investigation_id = str(body.get("investigation_id") or "").strip()[:128] or None
    finding_id = str(body.get("finding_id") or "").strip()[:128] or None
    requested_by = str(body.get("requested_by") or "").strip()[:128]
    run = Run(initiator=operator, owner=name, kind="automation", session_id=f"soar-{uuid.uuid4().hex[:10]}",
              request_text=f"Splunk SOAR: patch {cve} as {operator.username}"
                           + (f" ({str(body.get('reason'))[:200]})" if body.get("reason") else ""))
    run.investigation_id = investigation_id
    run.finding_id = est.finding_id(name, cve)
    run.extra = {"es_finding_id": finding_id or "", "requested_by": requested_by,
                 "requested_via": "splunk_soar", "operator": operator.username}
    telemetry.emit("session", "session_started", {**run.common(), "duo_groups": operator.duo_groups})
    try:
        chain = toolchain(run)
        if chain["verdict"] != "clean":
            names = ", ".join(chain["unsafe"] or chain["unscanned"])
            run.output_text = f"Refused: PatchBot's toolchain is not clean ({chain['verdict']}: {names})."
            raise AutomationError(409, run.output_text, {"toolchain": chain})
        investigation = read_investigation(investigation_id, finding_id, cve)
        ensure_inventory()
        state = store.load_estate(name)
        f = est.finding(state, name, cve)
        if not f or not f.get("open_hosts"):
            run.output_text = f"{cve} is not open on any server in this estate."
            raise AutomationError(404, run.output_text)
        asked = [str(s) for s in (body.get("servers") or []) if str(s).strip()]
        targets = [h for h in (asked or f["open_hosts"]) if h in f["open_hosts"]]
        common = {"investigation_id": investigation_id, "es_finding_id": finding_id,
                  "es_requested_by": requested_by or None, "auto_execute": True}
        results: List[Dict[str, Any]] = []
        changes: List[Dict[str, Any]] = []
        for model in ("standard", "normal"):
            group = [h for h in targets if est.change_model(state, h) == model]
            if not group:
                continue
            res = tools.call(run, "create_change", {"cve": cve, "servers": group, "model": model, **common},
                             origin="workflow")
            if not res.get("ok"):
                outcome = "denied" if (res.get("denied") or res.get("steered")) else "failed"
                results += [{"server": h, "change_model": model, "outcome": outcome, "tool": "create_change",
                             "control": _control(res), "reason": _reason(res)} for h in group]
                continue
            change = (res.get("output") or {}).get("change") or {}
            changes.append(_change_view(change))
            if model == "standard":
                results += [_patch_and_verify(run, h, cve, change["id"], "standard") for h in group]
            else:
                results += [{"server": h, "change_id": change["id"], "change_model": "normal",
                             "outcome": "awaiting_approval"} for h in group]
        denied = [{"server": r["server"], "tool": r.get("tool"), "control": r.get("control"),
                   "message": r.get("reason")} for r in results if r["outcome"] == "denied"]
        summary = _summary(operator, results, changes)
        run.output_text = summary
        return {"run_id": run.run_id, "cve": cve, "estate_owner": name,
                "operator": {"username": operator.username, "role": operator.role,
                             "role_label": operator.role_label, "source": operator.auth_method},
                "toolchain": chain, "investigation": investigation, "changes": changes,
                "results": results, "denied": denied, "summary": summary}
    finally:
        _finish(run)


def change_status(change_id: str) -> Dict[str, Any]:
    change = store.get_change(str(change_id or "").strip().upper())
    if change is None:
        raise AutomationError(404, "Unknown change.")
    state = store.load_estate(change["owner"])
    results = []
    for h in change.get("servers") or []:
        open_now = est.is_vulnerable(state, h, change["cve"])
        results.append({"server": h, "change_model": change.get("change_model"),
                        "outcome": "awaiting_approval" if open_now and change["status"] == "awaiting_approval"
                        else ("open" if open_now else "patched")})
    return {**_change_view(change), "decided_at": change.get("decided_at"), "results": results}


# --------------------------------------------------------------------------- an approved change runs itself

def execute_change(change_id: str) -> Dict[str, Any]:
    """Run an approved change's patches, as the person who requested it (the Controls judge
    each call with that person's current role). Only changes opened from Splunk SOAR."""
    change = store.get_change(change_id)
    if not change or change["status"] != "approved" or not change.get("auto_execute"):
        return {"ran": False}
    who = roles.from_username(change["requested_by"])
    if who is None:
        store.add_activity(change["owner"], "change", f"{change_id} approved but not run: "
                           f"{change['requested_by']} can no longer be identified", actor="PatchBot",
                           actor_type="agent", finding_id=change.get("finding_id"))
        return {"ran": False}
    run = Run(initiator=who, owner=change["owner"], kind="change_execution",
              session_id=f"chg-{change_id.lower()}", request_text=f"Run approved change {change_id}")
    run.investigation_id = change.get("investigation_id")
    run.finding_id = change.get("finding_id")
    run.extra = {"es_finding_id": change.get("es_finding_id") or "", "requested_by": change.get("es_requested_by") or "",
                 "requested_via": "change_board_approval", "operator": who.username}
    try:
        results = [_patch_and_verify(run, h, change["cve"], change_id, change.get("change_model") or "normal")
                   for h in change.get("servers") or []]
        run.output_text = _summary(who, results, [_change_view(store.get_change(change_id) or change)])
        return {"ran": True, "results": results}
    finally:
        _finish(run)


def execute_change_async(change_id: str) -> None:
    if SYNC_EXECUTION:
        execute_change(change_id)
        return
    threading.Thread(target=execute_change, args=(change_id,), name=f"patchbot-{change_id}", daemon=True).start()


# --------------------------------------------------------------------------- the attack console

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n…")


def _attack_script(target: str, vulnerable: bool) -> List[Dict[str, Any]]:
    """The requests an attacker sends, and what a vulnerable (or patched) server answers."""
    def req(method: str, path: str, status: int, size: int, preview: str, body: str = "") -> Dict[str, Any]:
        return {"http_method": method, "uri_path": path, "status": status, "bytes_out": size,
                "request_body": body, "response_preview": preview}
    traversal = [
        req("GET", "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", 200 if vulnerable else 403,
            1892 if vulnerable else 199, _PASSWD if vulnerable else "Forbidden"),
        req("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 200 if vulnerable else 400,
            54 if vulnerable else 226, "uid=1(daemon) gid=1(daemon) groups=1(daemon)" if vulnerable else "Bad Request",
            body="echo; id"),
        req("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 200 if vulnerable else 400,
            41 if vulnerable else 226, target if vulnerable else "Bad Request", body="echo; hostname"),
    ]
    return [req("GET", "/", 200, 5120, "<!doctype html>… PseudoCo"),
            req("GET", "/cgi-bin/", 403, 199, "Forbidden")] + traversal


def attack(target: str = "web-prod-01") -> Dict[str, Any]:
    """Replay a CVE-2021-41773 exploitation against ``target`` as web events in Splunk."""
    name = owner()
    state = store.load_estate(name)
    if target not in est.APPLIES.get(EXPLOIT_CVE, []) or not (state.get("hosts") or {}).get(target):
        raise AutomationError(404, f"No web server {target} in this estate.")
    inventory = ensure_inventory()
    state = store.load_estate(name)
    vulnerable = est.is_vulnerable(state, target, EXPLOIT_CVE)
    requests = _attack_script(target, vulnerable)
    base = datetime.utcnow()
    for i, r in enumerate(requests):
        telemetry.emit("web", "http_request", {
            "estate_owner": name, "src": ATTACKER, "src_ip": ATTACKER, "dest": target, "site": target,
            "http_method": r["http_method"], "uri_path": r["uri_path"], "url": f"http://{target}{r['uri_path']}",
            "status": r["status"], "bytes_out": r["bytes_out"], "http_user_agent": ATTACK_UA,
            "vendor_product": "Apache HTTP Server", "server_version": "2.4.49" if vulnerable else "2.4.51",
            "request_time": (base + timedelta(milliseconds=350 * i)).isoformat() + "Z",
            "action": "allowed" if r["status"] < 400 else "blocked"})
    store.add_activity(name, "attack", f"Attack replay from {ATTACKER} against {target}: "
                       + ("the server answered the traversal requests" if vulnerable else "the server is patched"),
                       actor=ATTACKER, actor_type="attacker")
    return {"target": target, "attacker": ATTACKER, "cve": EXPLOIT_CVE, "vulnerable": vulnerable,
            "inventory": inventory, "requests": requests}


def reset_lab() -> Dict[str, Any]:
    """Instructor reset: the shared estate back to its vulnerable state (changes withdrawn)."""
    name = owner()
    store.reset_estate(name)
    telemetry.emit("estate", "estate_reset", {"estate_owner": name, "requested_via": "automation"})
    return {"reset": True, "estate_owner": name}
