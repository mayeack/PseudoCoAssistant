"""Settings API: local log directory + Splunk HEC destinations.

Auto-gated by the access-key middleware (not in PUBLIC_PATHS). Tokens are
accepted on write but never returned — reads surface only token_present/last4.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, StrictBool, field_validator

from backend import settings_store
from backend.config import settings
from backend.hec.runtime import hec_runtime
from backend.model_emitter import MODEL_CHOICES, model_emitter

router = APIRouter(prefix="/api", tags=["settings"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class LogsSettings(BaseModel):
    logs_directory: str = Field(min_length=1, max_length=512)


def _validate_https(v: Optional[str]) -> Optional[str]:
    if v:
        v = v.strip()
        if v and not v.lower().startswith("https://"):
            raise ValueError("HEC URL must use https://")
    return v


class HECDestinationWrite(BaseModel):
    name: Optional[str] = Field(default=None, max_length=80)
    enabled: Optional[bool] = None
    url: Optional[str] = Field(default=None, max_length=512)
    token: Optional[str] = Field(default=None, max_length=200)
    verify_tls: Optional[bool] = None
    index: Optional[str] = Field(default=None, max_length=80)
    source: Optional[str] = Field(default=None, max_length=200)
    sourcetype: Optional[str] = Field(default=None, max_length=200)
    host: Optional[str] = Field(default=None, max_length=200)
    sourcetype_map: Optional[Dict[str, str]] = None
    batch_size: Optional[int] = Field(default=None, ge=1, le=10000)
    flush_interval_s: Optional[float] = Field(default=None, ge=0.1, le=300.0)
    queue_max: Optional[int] = Field(default=None, ge=1, le=1000000)
    request_timeout_s: Optional[float] = Field(default=None, ge=1.0, le=300.0)
    max_retries: Optional[int] = Field(default=None, ge=0, le=10)

    @field_validator("url")
    @classmethod
    def _url_https(cls, v):
        return _validate_https(v)


# ---------------------------------------------------------------------------
# Local logging settings
# ---------------------------------------------------------------------------
@router.get("/settings")
async def get_settings():
    return {"logs_directory": settings_store.get_logs_directory()}


@router.put("/settings")
async def update_settings(body: LogsSettings):
    path = settings_store.set_logs_directory(body.logs_directory)
    return {"logs_directory": path}


# ---------------------------------------------------------------------------
# Demo model-name emission override
# ---------------------------------------------------------------------------
class EmitModelSettings(BaseModel):
    enabled: bool = False
    model_name: str = Field(default="", max_length=120)
    random: bool = False


@router.get("/settings/emit-model")
async def get_emit_model():
    return model_emitter.status()


# ---------------------------------------------------------------------------
# Active LLM provider selection (which model backs the chat)
# ---------------------------------------------------------------------------
class AiProviderSettings(BaseModel):
    provider: str = Field(min_length=1, max_length=40)
    model: str = Field(default="", max_length=200)
    # Optional per-provider access fields (e.g. {"api_key": "..."}). Secrets are
    # write-only: blank values are ignored so an existing key is never wiped.
    fields: Optional[Dict[str, str]] = None


def _provider_payload() -> dict:
    """Current provider/model + discovered models + per-provider access-field
    metadata. Secret field values are NEVER included (presence only)."""
    from backend import model_catalog

    payload = settings_store.get_ai_provider()
    payload["available"] = model_catalog.available()
    payload["fields"] = settings_store.get_provider_fields()
    # Local-NIM status (readiness, served + featured models with GPU needs) from
    # the last catalog probe — never probed on the request path.
    payload["nvidia"] = model_catalog.nvidia_status()
    return payload


@router.get("/settings/ai-provider")
async def get_ai_provider():
    from backend import model_catalog

    # bounded sync refresh if startup discovery hasn't finished — offloaded to a
    # worker thread so the network probes don't block the event loop (freezing all
    # concurrent attendee requests) while a provider is slow/unreachable.
    await asyncio.to_thread(model_catalog.ensure_loaded)
    # Self-heal: if the active provider's startup probe came back empty (e.g.
    # Ollama wasn't reachable yet), re-probe it now so newly-available models
    # show up without an app restart. Throttled internally.
    active = settings_store.get_ai_provider().get("provider", "")
    await asyncio.to_thread(model_catalog.heal_if_empty, active)
    return _provider_payload()


@router.put("/settings/ai-provider")
async def update_ai_provider(body: AiProviderSettings):
    from backend import model_catalog

    provider = body.provider.strip().lower()
    if provider not in settings_store.AI_PROVIDER_CHOICES:
        raise HTTPException(
            status_code=422,
            detail=f"unknown provider: {provider}. Valid: {', '.join(settings_store.AI_PROVIDER_CHOICES)}",
        )
    try:
        settings_store.set_ai_provider(provider, body.model)
        if body.fields:
            settings_store.set_provider_creds(provider, body.fields)
            # New creds may reveal models — re-scan this so the dropdown updates.
            # Offloaded so the probe network I/O doesn't block the event loop.
            await asyncio.to_thread(model_catalog.refresh)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _provider_payload()


@router.post("/settings/ai-provider/refresh")
async def refresh_ai_provider_models():
    """Re-scan every provider for its currently available models (e.g. after
    pulling a new Ollama model). Returns the same shape as GET."""
    from backend import model_catalog

    await asyncio.to_thread(model_catalog.refresh)
    return _provider_payload()


class ProviderCredsSettings(BaseModel):
    provider: str = Field(min_length=1, max_length=40)
    fields: Dict[str, str] = Field(default_factory=dict)


@router.put("/settings/provider-creds")
async def update_provider_creds(body: ProviderCredsSettings):
    """Update one provider's access creds (API key / base URL / region) WITHOUT
    changing the active provider — unlike PUT /settings/ai-provider, which also
    switches the chat to that provider. Backs the Settings-page credentials section
    (provider/model selection itself moved to the /app header). Blank secrets are
    ignored (an existing key is never wiped); new creds may reveal models so the
    catalog is re-scanned."""
    from backend import model_catalog

    provider = body.provider.strip().lower()
    if provider not in settings_store.AI_PROVIDER_CHOICES:
        raise HTTPException(
            status_code=422,
            detail=f"unknown provider: {provider}. Valid: {', '.join(settings_store.AI_PROVIDER_CHOICES)}",
        )
    settings_store.set_provider_creds(provider, body.fields or {})
    await asyncio.to_thread(model_catalog.refresh)
    return _provider_payload()


# ---------------------------------------------------------------------------
# Active blueprint (which agentic architecture serves chat turns)
# ---------------------------------------------------------------------------
class BlueprintSettings(BaseModel):
    key: str = Field(min_length=1, max_length=60)


@router.get("/settings/blueprint")
async def get_blueprint_setting():
    """The server-default blueprint + every choice (key, label, description,
    workflow_name, stage labels). The UI reads it for stage labels only — it has
    no Blueprint picker."""
    return settings_store.get_blueprint_setting()


@router.put("/settings/blueprint")
async def update_blueprint_setting(body: BlueprintSettings):
    try:
        return settings_store.set_blueprint(body.key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Demo Controls visibility (which drawer cards the chat page shows)
# ---------------------------------------------------------------------------
class DemoControlsSettings(BaseModel):
    # StrictBool: "true" / 1 are not a visibility — a typo gets a 422, not a guess.
    visible: Dict[str, StrictBool] = Field(default_factory=dict)


class McpThrashToggle(BaseModel):
    enabled: bool


@router.get("/settings/demo-controls")
async def get_demo_controls():
    """Every Demo Controls card (key, label, group, kind, visible) in drawer order
    plus the group headers, generated from settings_store.DEMO_CONTROLS. The chat
    page reads it to hide cards (chat.js applyDemoControlVisibility); the Settings
    page renders its Demo Controls panel from it."""
    return settings_store.get_demo_controls()


@router.get("/settings/mcp-thrash")
async def get_mcp_thrash():
    """The "MCP Tool Thrash" server-side toggle state ({enabled}). The chat page's
    drawer card polls it; the state lives on the server (settings_store), applied
    to every chat turn by the shared mcp_thrash nodes."""
    return settings_store.get_mcp_tool_thrash()


@router.put("/settings/mcp-thrash")
async def set_mcp_thrash(body: McpThrashToggle):
    return settings_store.set_mcp_tool_thrash(body.enabled)


@router.put("/settings/demo-controls")
async def update_demo_controls(body: DemoControlsSettings):
    """Merge {key: shown} into the stored overrides. Hiding is not gating: a hidden
    per-request card sends no override (the server default governs its flag) and a
    hidden generator keeps running."""
    try:
        return settings_store.set_demo_controls(body.visible)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Integration credentials (Cisco AI Defense / Splunk Observability Cloud)
# ---------------------------------------------------------------------------
class IntegrationCredsSettings(BaseModel):
    integration: str = Field(min_length=1, max_length=40)
    fields: Dict[str, str] = Field(default_factory=dict)


@router.get("/settings/integrations")
async def get_integrations():
    """Field metadata for the AI Defense / Splunk Observability Settings cards.
    Secret VALUES are never included — presence only."""
    return {"integrations": settings_store.get_integration_fields()}


@router.put("/settings/integration-creds")
async def update_integration_creds(body: IntegrationCredsSettings):
    """Update one integration's credentials + identity fields.

    Blank secrets are ignored (an existing key is never wiped). Most fields apply
    live via the integration's reconfigure hook; the ones whose consumer is a
    separate process (the OTel collector) are written to .env instead, and the
    processes that still need restarting come back in ``restart_required``."""
    integration = body.integration.strip()
    if integration not in settings_store.INTEGRATION_CHOICES:
        raise HTTPException(
            status_code=422,
            detail=f"unknown integration: {integration}. "
                   f"Valid: {', '.join(settings_store.INTEGRATION_CHOICES)}",
        )
    try:
        restart = settings_store.set_integration_creds(integration, body.fields or {})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "integrations": settings_store.get_integration_fields(),
        "restart_required": restart,
    }


@router.put("/settings/emit-model")
async def update_emit_model(body: EmitModelSettings):
    name = (body.model_name or "").strip()
    if name and name not in MODEL_CHOICES:
        raise HTTPException(status_code=422, detail=f"unknown model_name: {name}")
    if body.enabled and not body.random and not name:
        raise HTTPException(
            status_code=422,
            detail="Select a model to emit (or enable Emit Random Model Name).",
        )
    settings_store.set_emit_model(body.enabled, name, body.random)
    return model_emitter.status()


# ---------------------------------------------------------------------------
# HEC destinations
# ---------------------------------------------------------------------------
@router.get("/hec/destinations")
async def list_hec_destinations():
    return {"destinations": [settings_store.mask(d) for d in settings_store.list_destinations()]}


@router.post("/hec/destinations")
async def create_hec_destination(body: HECDestinationWrite):
    record = settings_store.add_destination(body.model_dump(exclude_unset=True))
    await settings_store.reconfigure_hec()
    return settings_store.mask(record)


@router.get("/hec/destinations/{dest_id}")
async def get_hec_destination(dest_id: str):
    dest = settings_store.get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return settings_store.mask(dest)


@router.put("/hec/destinations/{dest_id}")
async def update_hec_destination(dest_id: str, body: HECDestinationWrite):
    record = settings_store.update_destination(dest_id, body.model_dump(exclude_unset=True))
    if record is None:
        raise HTTPException(status_code=404, detail="destination not found")
    await settings_store.reconfigure_hec()
    return settings_store.mask(record)


@router.delete("/hec/destinations/{dest_id}")
async def delete_hec_destination(dest_id: str):
    if not settings_store.delete_destination(dest_id):
        raise HTTPException(status_code=404, detail="destination not found")
    await settings_store.reconfigure_hec()
    return {"removed": True, "id": dest_id}


@router.post("/hec/destinations/{dest_id}/test")
async def test_hec_destination(dest_id: str):
    dest = settings_store.get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    result = await hec_runtime.test_send(settings_store.to_hec_config(dest))
    return {
        "ok": result.ok,
        "status_code": result.status_code,
        "latency_ms": round(result.latency_ms, 1),
        "error": result.error,
    }


# ---------------------------------------------------------------------------
# Live forwarder stats
# ---------------------------------------------------------------------------
@router.get("/hec/stats")
async def hec_stats():
    return {"destinations": [vars(s) for s in hec_runtime.stats()]}


@router.get("/hec/stats/{dest_id}")
async def hec_stats_for(dest_id: str):
    snap = hec_runtime.stats_for(dest_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return vars(snap)


# ---------------------------------------------------------------------------
# Server identity
# ---------------------------------------------------------------------------
def _server_info() -> dict:
    from backend import host_capabilities

    caps = host_capabilities.current()
    return {
        "hostname": settings.server_hostname or socket.gethostname(),
        # Running build, shown in the chat footer next to the hostname so a
        # workshop box can be told apart from a stale one at a glance.
        "version": settings.app_version,
        "environment": settings.environment,
        # What this box can run + the gating rules the UI applies (greying out
        # provider=nvidia / NIM images / the NemoClaw runtime with a reason).
        # Read from the cache — never probed on the request path.
        "capabilities": caps.get("capabilities", {}),
        "gated": caps.get("gated", {}),
    }


@router.get("/server-info")
async def get_server_info():
    """Identity + capabilities of the host serving this process, for the UI.

    Lives behind the access-key gate rather than on the public /health so a
    tunnelled deployment doesn't hand out its hostname unauthenticated.
    """
    return _server_info()


@router.post("/server-info/refresh")
async def refresh_server_info():
    """Re-probe host capabilities now (after starting a NIM, Colima, …)."""
    from backend import host_capabilities

    await asyncio.to_thread(host_capabilities.detect, True)
    return _server_info()
