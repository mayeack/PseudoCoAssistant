from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
import asyncio
import logging
import threading
from pathlib import Path

from backend.config import settings
from backend.database.db import init_db
from backend.logging.log_handlers import setup_logging
from backend.middleware.request_logging import RequestLoggingMiddleware
from backend.middleware.access_key import AccessKeyMiddleware
from backend.middleware.settings_gate import has_settings_access
from backend.routers import chat, admin, auth, settings as settings_routes, incident, spray, toolguard, analytics, appointments
from backend.telemetry import otel, tracestate_guard

# Cap inbound W3C tracestate before OpenTelemetry parses it (CVE-2026-114603).
# Must run before the first request; see backend/telemetry/tracestate_guard.py.
tracestate_guard.install()

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Initialize code-based OpenTelemetry GenAI instrumentation (no-op unless
# settings.otel_enabled). Must run before the agentic graph is first invoked.
otel.init_telemetry(settings)

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Medical guidance application with comprehensive AI governance logging",
    debug=settings.debug
)

# CORS middleware.
#
# Explicit origins, never "*". Responses here are credentialed (session cookie
# or Basic auth), and allow_origins=["*"] with allow_credentials=True makes
# Starlette echo whichever Origin asked whenever a cookie is present — i.e.
# every site becomes a credential-allowed origin, with only the cookie's
# SameSite=Lax standing between a hostile page and an authenticated read.
# The UI is same-origin with this app, so the default list is empty and nothing
# in the product needs an entry; set CORS_ORIGINS in .env for an external client.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Access-key gate (Basic Auth) — added before request logging so logging stays
# outermost and still records rejected (401) requests. No-op unless ACCESS_KEY is set.
#
# NOTE on ordering: add_middleware prepends, so this runs OUTSIDE CORSMiddleware
# and sees requests first. A cross-origin preflight carries neither cookie nor
# Authorization header, so the gate would 401 every OPTIONS before CORS could
# answer it — which silently broke every preflighted cross-origin request. The
# middleware therefore lets OPTIONS through to CORS; a preflight reveals nothing
# and grants nothing, and the real request that follows is still gated.
app.add_middleware(AccessKeyMiddleware)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Include routers
app.include_router(chat.router)
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(settings_routes.router)
app.include_router(incident.router)
app.include_router(spray.router)
app.include_router(toolguard.router)
app.include_router(analytics.router)
app.include_router(appointments.router)

def _prewarm_llm_stack() -> None:
    """Absorb the first-turn cold start off the request path.

    Ollama: an empty-prompt /api/generate loads the model weights (no tokens
    are generated) and starts the keep_alive clock; done for the user-facing
    and internal models. Graph: get_agentic_runner() compiles the workflow
    once so the first turn doesn't pay it either. Runs on a daemon thread —
    failures are logged, never fatal.
    """
    if (settings.ai_provider or "").lower() == "ollama":
        import httpx

        # Internal model first, user-facing synthesizer model LAST: on hosts
        # where both can't co-reside, the one warmed last stays resident, and
        # it's the only model the first turn needs under the single-agent
        # default.
        for model in dict.fromkeys([settings.ollama_model_internal, settings.ollama_model]):
            if not model:
                continue
            try:
                httpx.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={"model": model, "prompt": "",
                          "keep_alive": settings.ollama_keep_alive},
                    timeout=120.0,
                )
                logger.info("Pre-warmed Ollama model %s", model)
            except Exception as exc:  # noqa: BLE001 - pre-warm is best-effort
                logger.warning("Ollama pre-warm failed for %s: %s", model, exc)
    if settings.use_agentic_engine:
        try:
            from backend.agents.graph import get_agentic_runner

            get_agentic_runner()
        except Exception:  # noqa: BLE001
            logger.exception("Agent graph pre-compile failed")


# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")

    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Load persisted app settings: apply the configured log directory and start
    # the Splunk HEC forwarders (no-op until destinations are added).
    try:
        from backend import settings_store
        from backend.logging.governance_logger import governance_logger
        from backend.hec.runtime import hec_runtime
        app_cfg = settings_store.load()
        governance_logger.set_logs_directory(app_cfg.get("logs_directory", "logs"))
        hec_runtime.configure(settings_store.all_configs())
        from backend.model_emitter import model_emitter
        _em = settings_store.get_emit_model()
        model_emitter.configure(_em["enabled"], _em["model_name"], _em["random"])
        # Apply any persisted LLM provider override + access creds (Settings UI)
        # over the .env defaults, BEFORE discovery so it probes with the right creds.
        settings_store.apply_provider_creds_from_store()
        settings_store.apply_ai_provider_from_store()
        # Same for the AI Defense / Splunk Agent Observability integration creds.
        # (Collector-consumed keys are .env-owned and already loaded by config.)
        settings_store.apply_integration_creds_from_store()
        # The NemoClaw Guardrails drawer toggle is server-side state: restore it.
        settings_store.apply_nemoclaw_guardrails_from_store()
        # Same for the MCP Tool Thrash drawer toggle (server-side demo fault).
        settings_store.apply_mcp_tool_thrash_from_store()
        # Discover which models each provider currently offers (background thread so
        # startup isn't blocked) — populates the Settings "Model" dropdown.
        from backend import model_catalog
        model_catalog.refresh_async()
        # Probe what this host can run (GPU, container runtime, local NIM) so the
        # UI can grey out options that cannot work here. Background, best-effort.
        from backend import host_capabilities
        host_capabilities.refresh_async()
        await hec_runtime.start()
        logger.info("Settings loaded; HEC forwarders started")
    except Exception as e:
        logger.error(f"Failed to initialize settings/HEC: {e}")

    # Pre-warm AFTER the persisted provider/model override is applied so the
    # right model gets loaded. Background thread: startup isn't blocked.
    if settings.prewarm_llm:
        threading.Thread(
            target=_prewarm_llm_stack, name="llm-prewarm", daemon=True
        ).start()

    logger.info(f"Application started on {settings.host}:{settings.port}")

@app.on_event("shutdown")
async def shutdown_event():
    try:
        from backend.hec.runtime import hec_runtime
        await hec_runtime.stop()
    except Exception:
        logger.debug("HEC shutdown error", exc_info=True)
    try:
        from backend import agent_observability
        await asyncio.to_thread(agent_observability.shutdown, 10.0)
    except Exception:
        logger.debug("agent observability shutdown error", exc_info=True)
    logger.info(f"Shutting down {settings.app_name}")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment
    }

# Root endpoint
@app.get("/")
async def root(request: Request):
    # Browsers get the styled app; API clients get the JSON index.
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/app")
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "message": "Medical Advice API is running",
        "endpoints": {
            "chat": "/api/chat",
            "admin": "/admin",
            "health": "/health"
        }
    }

# Serve frontend (if running in production mode)
try:
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        @app.get("/app", response_class=HTMLResponse)
        async def serve_app():
            index_file = frontend_dir / "index.html"
            if index_file.exists():
                return index_file.read_text()
            return "<h1>Frontend not found</h1>"

        @app.get("/admin-ui", response_class=HTMLResponse)
        async def serve_admin():
            admin_file = frontend_dir / "admin.html"
            if admin_file.exists():
                return admin_file.read_text()
            return "<h1>Admin UI not found</h1>"

        @app.get("/governance-ui", response_class=HTMLResponse)
        async def serve_governance():
            gov_file = frontend_dir / "governance.html"
            if gov_file.exists():
                return gov_file.read_text()
            return "<h1>Governance UI not found</h1>"

        @app.get("/settings-ui", response_class=HTMLResponse)
        async def serve_settings(request: Request):
            # Settings has its own access code on top of the app gate — the
            # credentials edited here are not for the demo audience.
            if not has_settings_access(request):
                return RedirectResponse(url="/settings-login?next=/settings-ui",
                                        status_code=303)
            settings_file = frontend_dir / "settings.html"
            if settings_file.exists():
                return settings_file.read_text()
            return "<h1>Settings UI not found</h1>"

        @app.get("/appointments-ui", response_class=HTMLResponse)
        async def serve_appointments():
            appt_file = frontend_dir / "appointments.html"
            if appt_file.exists():
                return appt_file.read_text()
            return "<h1>Appointments UI not found</h1>"
except Exception as e:
    logger.warning(f"Could not mount frontend: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        # Don't reload on data/log churn (the app writes these as it serves),
        # otherwise the dev reloader restarts after almost every request.
        reload_excludes=["*.db", "*.db-journal", "*.db-wal", "*.log", "*.json"],
        log_level=settings.log_level.lower()
    )
