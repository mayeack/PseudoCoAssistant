"""PatchBot API (docs/patchbot.md) — the backend of ``/patchbot-ui`` and ``/change-board-ui``.

Identity comes from the verified Duo session, or (Duo off) from the role-map
persona cookie; never from a request body. Every route that changes an estate
goes through ``tools.call``, so Agent Observability Controls judge it first.
The access-key middleware gates these routes like every other path.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from backend.config import settings
from backend.patchbot import agent, catalog, controls, roles, service, store, telemetry, tools
from backend.patchbot.run import Run

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/patchbot", tags=["patchbot"])

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
async def follow_advisory(cve: str, request: Request) -> Dict[str, Any]:
    run = _run(request, "advisory")
    result = await run_in_threadpool(agent.advisory_flow, run, _cve(cve))
    _finish(run)
    return result


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
