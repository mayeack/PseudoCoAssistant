"""PatchBot API (docs/patchbot.md) — the backend of ``/patchbot-ui`` and ``/change-board-ui``.

Identity comes from the verified Duo session, or (Duo off) from the role-map
persona cookie; never from a request body. Every route that changes an estate
goes through ``tools.call``, so Agent Observability Controls judge it first.
The access-key middleware gates these routes like every other path.
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.config import settings
from backend.patchbot import agent, catalog, controls, mcp_scan, mcp_servers, roles, service, store, telemetry, tools
from backend.patchbot.run import Run

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/patchbot", tags=["patchbot"])
# The MCP endpoint: each server's tool catalogue, for scanners (mcp_servers).
mcp_router = APIRouter(prefix="/mcp/patchbot", tags=["patchbot-mcp"])
# Splunk SOAR's PatchBot connector (docs/patchbot-automation-api.md) and the lab's attack console.
automation_router = APIRouter(prefix="/api/patchbot/automation", tags=["patchbot-automation"])
attack_router = APIRouter(prefix="/api/patchbot/attack", tags=["patchbot-attack"])

_SESSION_RE = r"^[A-Za-z0-9_-]{6,64}$"
_seen_sessions: set = set()


class PersonaBody(BaseModel):
    username: str = Field(max_length=64)


class ExposureBody(BaseModel):
    server: str = Field(max_length=32)
    publicly_exposed: bool
    compensating_control: Optional[str] = Field(default=None, max_length=120)


class TriageBody(BaseModel):
    action: Literal["dismiss", "reopen"]
    reason: Optional[Literal["false_positive", "accepted_risk", "duplicate"]] = None
    note: Optional[str] = Field(default="", max_length=500)


class PatchBody(BaseModel):
    environment: Literal["staging", "production"]


class ChatBody(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: List[Dict[str, str]] = Field(default_factory=list, max_length=12)


class DecisionBody(BaseModel):
    decision: Literal["approve", "reject"]
    note: Optional[str] = Field(default="", max_length=1000)


class AdvisoryBody(BaseModel):
    cve: str = Field(max_length=24)
    poisoned: bool = False


class RollbackBody(BaseModel):
    cve: str = Field(max_length=24)
    server: Optional[str] = Field(default=None, max_length=32)


class McpScanBody(BaseModel):
    server: Optional[str] = Field(default=None, max_length=40)


class VendorBody(BaseModel):
    action: Literal["connect", "disconnect"]
    force: bool = False


class VendorPoisonBody(BaseModel):
    poisoned: bool


def _require_enabled() -> None:
    if not settings.patchbot_enabled:
        raise HTTPException(status_code=404, detail="PatchBot is not enabled on this box.")


def _initiator(request: Request) -> roles.Initiator:
    _require_enabled()
    who = roles.from_request(request)
    if who is None:
        detail = ("Sign in with Duo to use PatchBot." if roles.duo_mode()
                  else "Pick who you are on the PatchBot page first.")
        raise HTTPException(status_code=401, detail=detail)
    return who


def _session(request: Request, who: roles.Initiator) -> str:
    sid = str(request.headers.get("x-patchbot-session") or "")
    import re
    if not re.fullmatch(_SESSION_RE, sid):
        sid = f"pb-{uuid.uuid4().hex[:12]}"
    key = f"{who.username}|{sid}"
    if key not in _seen_sessions:
        _seen_sessions.add(key)
        telemetry.emit("session", "session_started", {
            "estate_owner": who.username, "patchbot_session_id": sid, "initiator": who.username,
            "initiator_role": who.role, "duo_groups": who.duo_groups, "auth_method": who.auth_method,
            "identity_session_ref": who.identity_session_ref, "model": agent._model_name()})
    return sid


def _run(request: Request, kind: str, *, owner: Optional[str] = None) -> Run:
    who = _initiator(request)
    return Run(initiator=who, owner=owner or who.username, kind=kind, session_id=_session(request, who))


def _finish(run: Run) -> None:
    try:
        from backend import agent_observability
        agent_observability.maybe_log_patchbot_run(run.ao_record())
    except Exception:  # noqa: BLE001
        logger.debug("PatchBot AO enqueue failed", exc_info=True)


def _cve(value: str) -> str:
    cve = str(value or "").upper()
    if cve not in catalog.cve_ids():
        raise HTTPException(status_code=404, detail="Unknown finding.")
    return cve


# --------------------------------------------------------------------------- identity

@router.get("/me")
async def me(request: Request) -> Dict[str, Any]:
    _require_enabled()
    who = await run_in_threadpool(roles.from_request, request)
    return {"initiator": who.as_dict() if who else None, "duo_mode": roles.duo_mode(),
            "personas": [] if roles.duo_mode() else roles.personas(),
            "controls_mode": controls.mode(), "agent_stream": settings.patchbot_agent_stream,
            "model": agent._model_name(), "telemetry": telemetry.status()}


@router.post("/persona")
async def pick_persona(body: PersonaBody, response: Response) -> Dict[str, Any]:
    _require_enabled()
    if roles.duo_mode():
        raise HTTPException(status_code=409, detail="This box signs people in with Duo.")
    name = body.username.strip().lower()
    if name not in roles.PERSONAS:
        raise HTTPException(status_code=400, detail="Unknown persona.")
    response.set_cookie(roles.PERSONA_COOKIE, name, httponly=True, samesite="lax", max_age=12 * 3600)
    return {"username": name, "role": roles.PERSONAS[name]}


# --------------------------------------------------------------------------- workspace

@router.get("/workspace")
async def workspace(request: Request) -> Dict[str, Any]:
    who = _initiator(request)
    _session(request, who)
    data = await run_in_threadpool(service.workspace, who.username)
    data["initiator"] = who.as_dict()
    data["activity"] = await run_in_threadpool(store.list_activity, who.username, limit=40)
    return data


@router.post("/full-read")
async def full_read(request: Request) -> Dict[str, Any]:
    run = _run(request, "full_read")
    run.request_text = "Full read of the estate"

    def go() -> Dict[str, Any]:
        state = store.load_estate(run.owner)
        result = tools.scan(run, state, None, "full_read")
        service.after_scan(run, result)
        run.output_text = f"Full read: {len(result['open'])} open CVE reports across {len(result['hosts'])} hosts."
        return result

    result = await run_in_threadpool(go)
    _finish(run)
    return {"result": result, "reply": run.output_text}


@router.post("/exposure")
async def exposure(body: ExposureBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "exposure")
    run.request_text = f"Exposure answer for {body.server}"
    res = await run_in_threadpool(tools.call, run, "update_exposure_model",
                                  body.model_dump(exclude_none=True), origin="ui")
    run.output_text = (res.get("verdict") or {}).get("message") or "Exposure model updated."
    _finish(run)
    return res


@router.get("/findings/{cve}")
async def finding(cve: str, request: Request) -> Dict[str, Any]:
    who = _initiator(request)
    detail = await run_in_threadpool(service.finding_detail, who.username, _cve(cve))
    if detail is None:
        raise HTTPException(status_code=404, detail="Not found yet: run the full read first.")
    return detail


@router.post("/findings/{cve}/triage")
async def triage(cve: str, body: TriageBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "triage")
    cve = _cve(cve)
    run.request_text = f"{body.action} {cve}"
    if body.action == "dismiss" and not body.reason:
        raise HTTPException(status_code=422, detail="A dismissal needs a reason.")
    res = await run_in_threadpool(tools.call, run, "triage_finding",
                                  {"cve": cve, **body.model_dump(exclude_none=True)}, origin="ui")
    run.output_text = (res.get("verdict") or {}).get("message") or "Triage recorded."
    _finish(run)
    return res


@router.post("/findings/{cve}/patch")
async def patch(cve: str, body: PatchBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "patch")
    result = await run_in_threadpool(agent.patch_flow, run, _cve(cve), body.environment)
    _finish(run)
    return result


@router.post("/findings/{cve}/advisory")
async def follow_advisory(cve: str, request: Request,
                          source: Literal["document", "vendor_mcp"] = "document") -> Dict[str, Any]:
    run = _run(request, "advisory")
    result = await run_in_threadpool(agent.advisory_flow, run, _cve(cve), source)
    _finish(run)
    return result


# --------------------------------------------------------------------------- MCP servers and Cisco MCP Scanner

@router.get("/mcp")
async def mcp_overview(request: Request) -> Dict[str, Any]:
    who = _initiator(request)
    return await run_in_threadpool(mcp_scan.overview, who.username)


@router.post("/mcp/scan")
async def mcp_scan_servers(body: McpScanBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "mcp_scan")
    if body.server and body.server not in mcp_servers.SERVERS:
        raise HTTPException(status_code=404, detail="No such MCP server.")
    results = await run_in_threadpool(mcp_scan.scan, run, [body.server] if body.server else None)
    return {"results": results, "overview": await run_in_threadpool(mcp_scan.overview, run.owner)}


@router.post("/mcp/vendor")
async def mcp_vendor(body: VendorBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "mcp_connect")
    if body.action == "disconnect":
        result = await run_in_threadpool(mcp_scan.disconnect_vendor, run)
    else:
        result = await run_in_threadpool(lambda: mcp_scan.connect_vendor(run, force=body.force))
    return {**result, "overview": await run_in_threadpool(mcp_scan.overview, run.owner)}


@router.post("/chat")
async def chat(body: ChatBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "chat")
    result = await run_in_threadpool(agent.chat, run, body.message, body.history)
    _finish(run)
    return result


@router.get("/activity")
async def activity(request: Request) -> Dict[str, Any]:
    who = _initiator(request)
    return {"activity": await run_in_threadpool(store.list_activity, who.username, limit=80)}


@router.post("/reset")
async def reset(request: Request) -> Dict[str, Any]:
    run = _run(request, "demo")
    await run_in_threadpool(store.reset_estate, run.owner)
    telemetry.emit("estate", "estate_reset", run.common())
    return {"reset": True}


# --------------------------------------------------------------------------- Demo Controls

@router.post("/demo/advisory")
async def demo_advisory(body: AdvisoryBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "demo")
    return await run_in_threadpool(service.publish_advisory, run, _cve(body.cve), body.poisoned)


@router.post("/demo/vendor-mcp")
async def demo_vendor_mcp(body: VendorPoisonBody, request: Request) -> Dict[str, Any]:
    """Lab 4, MCP variant: the vendor's server ships a poisoned tool description."""
    run = _run(request, "demo")
    vendor = await run_in_threadpool(mcp_scan.set_vendor_poisoned, run, body.poisoned)
    return {"vendor": vendor, "overview": await run_in_threadpool(mcp_scan.overview, run.owner)}


@router.post("/demo/rollback")
async def demo_rollback(body: RollbackBody, request: Request) -> Dict[str, Any]:
    run = _run(request, "demo")
    cve = _cve(body.cve)
    try:
        facts = await run_in_threadpool(service.roll_back, run, cve, body.server)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # The scanner's watch notices the package change and reports it, which reopens the finding.
    scan_run = Run(initiator=run.initiator, owner=run.owner, kind="watch", session_id=run.session_id,
                   request_text=f"Watch rescan of {facts['server']}")

    def rescan() -> Dict[str, Any]:
        result = tools.scan(scan_run, store.load_estate(run.owner), [facts["server"]], "watch")
        service.after_scan(scan_run, result)
        return result

    result = await run_in_threadpool(rescan)
    scan_run.output_text = f"Watch: {len(result['open'])} open on {facts['server']}"
    _finish(scan_run)
    return {"rolled_back": facts, "rescan": result}


# --------------------------------------------------------------------------- Change Board

@router.get("/changes")
async def changes(request: Request, scope: Literal["mine", "awaiting", "all"] = "mine") -> Dict[str, Any]:
    who = _initiator(request)
    if scope == "awaiting":
        rows = await run_in_threadpool(lambda: store.list_changes(statuses=["awaiting_approval"]))
    elif scope == "all":
        rows = await run_in_threadpool(store.list_changes)
    else:
        rows = await run_in_threadpool(lambda: store.list_changes(owner=who.username))
    return {"initiator": who.as_dict(), "changes": rows,
            "can_decide": who.role in (roles.CHANGE_APPROVER, roles.ESTATE_OWNER)}


@router.post("/changes/{change_id}/decision")
async def decide(change_id: str, body: DecisionBody, request: Request) -> Dict[str, Any]:
    who = _initiator(request)
    try:
        return await run_in_threadpool(service.decide_change, who, change_id, body.decision, body.note or "")
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


# --------------------------------------------------------------------------- MCP endpoint (catalogues for scanners)

_OWNER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _vendor_poisoned(owner: str) -> bool:
    state = store.peek_estate(owner)
    return bool(state and (state.get("vendor_mcp") or {}).get("poisoned"))


def _check_mcp_path(owner: str, server_id: str) -> None:
    _require_enabled()
    if server_id not in mcp_servers.SERVERS or not _OWNER_RE.match(owner):
        raise HTTPException(status_code=404, detail="No such MCP server.")


@mcp_router.post("/{owner}/{server_id}")
async def mcp_endpoint(owner: str, server_id: str, request: Request) -> Response:
    """Streamable HTTP, JSON responses: initialize, ping, tools/list."""
    _check_mcp_path(owner, server_id)
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                            status_code=400)
    poisoned = (await run_in_threadpool(_vendor_poisoned, owner)) if server_id == mcp_servers.VENDOR else False
    messages = payload if isinstance(payload, list) else [payload]
    replies = [r for r in (mcp_servers.handle(server_id, m, vendor_poisoned=poisoned) for m in messages) if r]
    if not replies:
        return Response(status_code=202)
    return JSONResponse(replies if isinstance(payload, list) else replies[0])


@mcp_router.get("/{owner}/{server_id}")
async def mcp_endpoint_get(owner: str, server_id: str) -> Response:
    _check_mcp_path(owner, server_id)
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


@mcp_router.delete("/{owner}/{server_id}")
async def mcp_endpoint_delete(owner: str, server_id: str) -> Response:
    _check_mcp_path(owner, server_id)
    return Response(status_code=204)


# --------------------------------------------------------------------------- Splunk SOAR automation

class RemediateBody(BaseModel):
    cve: str = Field(max_length=32)
    operator: str = Field(max_length=64)
    servers: Optional[List[str]] = Field(default=None, max_length=16)
    investigation_id: Optional[str] = Field(default=None, max_length=128)
    finding_id: Optional[str] = Field(default=None, max_length=128)
    requested_by: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=500)


class AttackBody(BaseModel):
    target: str = Field(default="web-prod-01", max_length=32)


def _automation_guard(request: Request) -> None:
    from backend.patchbot import automation
    if not settings.patchbot_enabled or not automation.enabled():
        raise HTTPException(status_code=503, detail="PatchBot automation is turned off on this box.")
    if not automation.token_ok(request.headers.get("x-patchbot-automation-token")):
        raise HTTPException(status_code=401, detail="Missing or wrong PatchBot automation token.")


def _automation_error(exc: Any) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"detail": exc.detail, **(exc.body or {})})


@automation_router.get("/health")
async def automation_health(request: Request) -> Dict[str, Any]:
    from backend.patchbot import automation
    _automation_guard(request)
    return {"ok": True, "version": settings.app_version, "controls_mode": settings.patchbot_controls_mode,
            "duo_mode": roles.duo_mode(), "estate_owner": automation.owner()}


@automation_router.post("/remediate")
async def automation_remediate(body: RemediateBody, request: Request) -> Any:
    from backend.patchbot import automation
    _automation_guard(request)
    try:
        return await run_in_threadpool(automation.remediate, body.model_dump())
    except automation.AutomationError as exc:
        return _automation_error(exc)


@automation_router.get("/changes/{change_id}")
async def automation_change(change_id: str, request: Request) -> Any:
    from backend.patchbot import automation
    _automation_guard(request)
    try:
        return await run_in_threadpool(automation.change_status, change_id)
    except automation.AutomationError as exc:
        return _automation_error(exc)


@automation_router.post("/toolchain/scan")
async def automation_scan(request: Request) -> Dict[str, Any]:
    from backend.patchbot import automation

    _automation_guard(request)

    def go() -> Dict[str, Any]:
        run = Run(initiator=automation._service_initiator("splunk-soar"), owner=automation.owner(),
                  kind="toolchain_scan", session_id=f"soar-{uuid.uuid4().hex[:10]}",
                  request_text="Splunk SOAR: scan PatchBot's toolchain")
        mcp_scan.scan(run, list(automation.OWN_SERVERS))
        result = automation.toolchain(run, rescan_stale=False)
        run.output_text = f"Toolchain {result['verdict']}"
        automation._finish(run)
        return result

    return await run_in_threadpool(go)


@automation_router.post("/reset")
async def automation_reset(request: Request) -> Dict[str, Any]:
    from backend.patchbot import automation
    _automation_guard(request)
    return await run_in_threadpool(automation.reset_lab)


@attack_router.post("/exploit")
async def attack_exploit(body: AttackBody) -> Any:
    """The lab's attack console: no PatchBot identity, only the room access key."""
    from backend.patchbot import automation
    if not settings.patchbot_enabled:
        raise HTTPException(status_code=404, detail="Not enabled.")
    try:
        return await run_in_threadpool(automation.attack, body.target)
    except automation.AutomationError as exc:
        return _automation_error(exc)
