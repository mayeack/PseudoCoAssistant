"""Runtime-mutable app settings, persisted in a single ``app_settings`` row.

Holds the local log directory and the list of Splunk HEC destinations. This is
PseudoCo Assistant's analog of ThreatGenerator's active-config store. Tokens are kept in
the JSON blob (local SQLite, gitignored) and stripped by ``mask`` before they
ever reach an API response.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.database.db import get_db_context
from backend.hec.config import HECConfig
from backend.hec.runtime import hec_runtime
from backend.models.db_models import AppSettings

logger = logging.getLogger(__name__)

_ROW_ID = 1
_DEFAULTS: Dict[str, Any] = {
    "logs_directory": "logs",
    "hec_destinations": [],
    "emit_model": {"enabled": False, "model_name": "", "random": False},
    # Runtime override of the active LLM provider (empty = use .env/config default).
    "ai_provider": {"provider": "", "model": ""},
    # Per-provider access credentials/config entered via the Settings UI. Secrets
    # are stored here in the local (gitignored) SQLite blob, same as HEC tokens,
    # and are NEVER returned by the API (presence-only on read).
    "ai_provider_creds": {},
    # Whether the AI Defense connection accepts config.enabled_rules. Discovered
    # at runtime (a connection with an SCC policy bound rejects them with HTTP
    # 400) and persisted so the wasted 400+retry isn't re-paid on every restart.
    "ai_defense_enabled_rules_supported": True,
    # Per-integration credentials (Cisco AI Defense, Splunk Agent Observability)
    # entered via the Settings UI. Same storage contract as ai_provider_creds:
    # local gitignored SQLite, never returned by the API. Collector-consumed keys
    # (SPLUNK_REALM/O11Y_INGEST/...) are deliberately NOT kept here — they
    # live in .env only, so the two planes can't diverge.
    "integration_creds": {},
    # The "NemoClaw Guardrails" drawer toggle (server-side: tool calls are not
    # chat requests). Persisted so the demo posture survives a restart.
    "nemoclaw_guardrails": {"enabled": False},
    # Which Demo Controls drawer cards the chat page shows: {key: bool} holding
    # OVERRIDES only (an unlisted key is visible). Edited on the Settings page;
    # the registry of keys is DEMO_CONTROLS below. Never mutate this dict —
    # load() copies the blob shallowly, so a stored dict may still be this one.
    "demo_controls": {},
}
_ID_RE = re.compile(r"[^a-z0-9-]+")

# Supported LLM providers and the ``settings`` attribute that holds each one's
# model id. Keep in sync with backend/agents/llm.py::get_chat_model and
# backend/services/ai_client.py::get_ai_client.
AI_PROVIDER_CHOICES: List[str] = ["anthropic", "bedrock", "openai", "ollama", "nvidia"]
_PROVIDER_MODEL_ATTR: Dict[str, str] = {
    "anthropic": "anthropic_model",
    "bedrock": "bedrock_model_id",
    "openai": "openai_model",
    "ollama": "ollama_model",
    "nvidia": "nvidia_model",
}


class _CredField:
    """One access field surfaced per provider / integration in the Settings UI.

    ``secret`` fields are masked on read (presence only — never the value) and only
    overwritten on write when a non-empty value is supplied. Each field applies to
    a live ``settings`` attribute and/or a process env var (for the boto3 chain).

    ``boolean`` renders as a checkbox instead of a text input. Booleans are the one
    exception to blank-keeps-existing: a checkbox always reports its state.

    ``env_file`` means the value's consumer is a DIFFERENT PROCESS (the OTel
    collector, or run.sh before it re-execs the app), which reads ``.env`` directly.
    Those fields are written to ``.env`` and are NOT mirrored into the settings blob
    — ``.env`` stays their single source of truth. ``restart`` names the process that
    must be restarted before such a change takes effect ("collector" or "app").

    ``wide`` renders the input across both grid columns, for values too long to read
    in a half-width box. ``validate`` is an optional callable run on the submitted
    value before anything is applied; it raises ``ValueError`` to reject the save
    (the router turns that into a 422 the Settings page shows inline)."""

    def __init__(self, key, label, *, secret=False, boolean=False, settings_attr=None,
                 env=None, env_file=False, restart="", placeholder="", help="",
                 wide=False, validate=None):
        self.key = key
        self.label = label
        self.secret = secret
        self.boolean = boolean
        self.settings_attr = settings_attr
        self.env = env
        self.env_file = env_file
        self.restart = restart
        self.placeholder = placeholder
        self.help = help
        self.wide = wide
        self.validate = validate


def _validate_nim_base_url(value: str) -> None:
    """provider=nvidia is local inference only: reject a non-loopback NIM URL
    before it is applied (the same rule backend/agents/llm.py enforces at call
    time, surfaced here as a 422 with the reason instead of a failed chat turn)."""
    from backend import nvidia_nim

    nvidia_nim.validate_nim_base_url(value)


# Access fields per provider (the "Model" id is handled separately by the dropdown).
_PROVIDER_FIELDS: Dict[str, List[_CredField]] = {
    "anthropic": [
        _CredField("api_key", "API key", secret=True, settings_attr="anthropic_api_key",
                   placeholder="sk-ant-…"),
    ],
    "openai": [
        _CredField("api_key", "API key", secret=True, settings_attr="openai_api_key",
                   placeholder="sk-…"),
        _CredField("base_url", "Base URL", settings_attr="openai_base_url",
                   placeholder="https://api.openai.com/v1",
                   help="api.openai.com, or any OpenAI-compatible endpoint: a remote "
                        "NIM, Ray Serve or vLLM (provider=nvidia is local-only)."),
        _CredField("reasoning", "Reasoning (thinking) mode", boolean=True,
                   settings_attr="openai_reasoning",
                   help="Self-hosted endpoints only (api.openai.com ignores it). Nemotron 3 "
                        "defaults this ON; keep it off so the JSON answer contract is not "
                        "wrapped in a reasoning trace."),
    ],
    "bedrock": [
        _CredField("region", "AWS region", settings_attr="aws_region", env="AWS_DEFAULT_REGION",
                   placeholder="us-east-1"),
        _CredField("access_key_id", "AWS access key ID", secret=True, env="AWS_ACCESS_KEY_ID",
                   placeholder="AKIA…"),
        _CredField("secret_access_key", "AWS secret access key", secret=True,
                   env="AWS_SECRET_ACCESS_KEY"),
    ],
    "ollama": [
        _CredField("base_url", "Base URL", settings_attr="ollama_base_url",
                   placeholder="http://localhost:11434"),
    ],
    # Local NIM container on this host — never the hosted catalog. The URL is
    # validated as loopback; the key is only for a NIM started behind an
    # API-key gate; reasoning toggles Nemotron 3 "thinking" (default off).
    "nvidia": [
        _CredField("base_url", "NIM base URL (this host)", settings_attr="nvidia_base_url",
                   placeholder="http://localhost:8000/v1", validate=_validate_nim_base_url,
                   help="A NIM container on loopback. provider=nvidia never calls the "
                        "cloud API; a remote GPU box runs its own replica."),
        _CredField("api_key", "NIM API key (optional)", secret=True,
                   settings_attr="nvidia_api_key",
                   help="Only if the NIM was started behind an API-key gate."),
        _CredField("reasoning", "Reasoning (thinking) mode", boolean=True,
                   settings_attr="nvidia_reasoning",
                   help="Nemotron 3 defaults this ON; PseudoCo Assistant keeps it off so the "
                        "JSON answer contract is not wrapped in a reasoning trace."),
    ],
}


# ---------------------------------------------------------------------------
# Integration credentials (Cisco AI Defense / Splunk Observability Cloud /
# Splunk Agent Observability / NeMo Guardrails)
# ---------------------------------------------------------------------------
# Same _CredField vocabulary as _PROVIDER_FIELDS, one entry per Settings card
# group. Scope is deliberately CREDENTIALS + IDENTITY only: timeouts, fail-open
# posture, enabled-rule lists and Agent Control tuning stay in .env, where they
# are annotated and rarely change per-demo.
INTEGRATION_CHOICES: List[str] = ["ai_defense", "splunk_o11y", "agent_observability", "nemo_guardrails"]


def _validate_optional_nim_url(value: str) -> None:
    """An optional second local NIM (NemoGuard content safety) obeys the same
    local-only rule as the inference NIM. Blank never reaches here."""
    _validate_nim_base_url(value)


def _validate_resource_attributes(value: str) -> None:
    """Reject an OTEL_RESOURCE_ATTRIBUTES value the OTel SDK would silently ignore.

    The format is a comma-separated ``key=value`` list. A typo here fails SILENTLY —
    the SDK drops the malformed pair, the app still starts, telemetry still flows, and
    the box just never gets the identity it was supposed to have. That is exactly the
    failure a per-instance identity field exists to prevent, so validate on the way in
    rather than discovering it in O11y.
    """
    if " #" in value:
        # backend/config.py::_strip_env_value drops an unquoted trailing " # comment"
        # when it reloads .env, so this would be truncated on the next restart.
        raise ValueError(
            "resource attributes must not contain ' #' — it is stripped as a comment "
            "when .env is reloaded"
        )
    for pair in value.split(","):
        pair = pair.strip()
        if not pair:
            raise ValueError("resource attributes contain an empty entry (stray comma?)")
        if "=" not in pair:
            raise ValueError(
                f"resource attribute {pair!r} is not key=value — expected a "
                "comma-separated list like "
                "'deployment.environment=pseudoco-assistant-local,host.name=my-box'"
            )
        if not pair.split("=", 1)[0].strip():
            raise ValueError(f"resource attribute {pair!r} has an empty key")


_INTEGRATION_FIELDS: Dict[str, List[_CredField]] = {
    # Applies live: AIDefenseClient.reconfigure() re-reads the settings singleton.
    "ai_defense": [
        _CredField("enabled", "Enabled", boolean=True, settings_attr="ai_defense_enabled",
                   help="Master switch. The per-chat toggle is ignored when this is off."),
        _CredField("api_key", "Inspection API key", secret=True, settings_attr="ai_defense_api_key",
                   placeholder="paste the SCC connection key"),
        _CredField("region", "Region", settings_attr="ai_defense_region",
                   placeholder="us"),
        _CredField("endpoint", "Endpoint override", settings_attr="ai_defense_endpoint",
                   placeholder="https://us.api.inspect.aidefense.security.cisco.com"),
    ],
    # .env only — every one of these is read by a DIFFERENT process (the OTel
    # collector via run-collector.sh, or run.sh deciding whether to re-exec the app
    # under opentelemetry-instrument). Nothing in the app reads them, so there is
    # nothing to apply live.
    "splunk_o11y": [
        _CredField("realm", "Realm", env="SPLUNK_REALM", env_file=True, restart="collector",
                   placeholder="us1"),
        _CredField("access_token", "Ingest access token", secret=True, env="O11Y_INGEST",
                   env_file=True, restart="collector",
                   help="INGEST authorization. Not the API token — they are different."),
        _CredField("api_token", "API token", secret=True, env="O11Y_API", env_file=True,
                   help="Read-only API token used by the observability regression test."),
        _CredField("otlp_endpoint", "OTLP endpoint", env="OTEL_EXPORTER_OTLP_ENDPOINT",
                   env_file=True, restart="app", placeholder="http://localhost:4317"),
        _CredField("resource_attributes", "Resource attributes",
                   env="OTEL_RESOURCE_ATTRIBUTES", env_file=True, restart="app",
                   wide=True, validate=_validate_resource_attributes,
                   placeholder="deployment.environment=pseudoco-assistant-local,host.name=my-box",
                   help="Comma-separated key=value list stamped on every span and "
                        "metric. deployment.environment is what splits one PseudoCo Assistant "
                        "instance from another in O11y — give every box in a "
                        "multi-instance workshop a distinct value. Leave "
                        "service.name alone (OTEL_SERVICE_NAME) so they stay one "
                        "service."),
    ],
    # SPLUNK_AO_* are read by TWO consumers: the app's SDK path reads os.environ
    # when it (re)builds its logger — agent_observability.reconfigure() retires the
    # live logger on every save, so a change applies on the next chat turn — and
    # run-collector.sh reads .env at start for the collector's Agent Observability
    # overlay. env_file=True covers both, because set_integration_creds sets
    # os.environ AND writes .env; a save reports "collector" as needing a restart.
    # The Agent Control credentials are app-only, so they stay in the blob.
    "agent_observability": [
        _CredField("agent_control_enabled", "Agent Control enabled", boolean=True,
                   settings_attr="galileo_agent_control_enabled",
                   help="Master switch for the per-chat Agent Observability Controls toggle."),
        _CredField("realm", "Realm", env="SPLUNK_AO_REALM", env_file=True, restart="collector",
                   placeholder="us1",
                   help="Splunk Observability Cloud realm of the Agent Observability org "
                        "(ingest.<realm>.observability.splunkcloud.com) — normally the same "
                        "as the card above."),
        _CredField("o11y_token", "Ingest access token", secret=True, env="SPLUNK_AO_O11Y_TOKEN",
                   env_file=True, restart="collector", placeholder="paste an O11y ingest token",
                   help="Observability Cloud INGEST token. The single enable signal for trace "
                        "logging (SDK path and collector fan-out): chat turns are logged only "
                        "while this and the realm are set. Not the API token."),
        _CredField("o11y_api_token", "API token (sessions, optional)", secret=True,
                   env="SPLUNK_AO_O11Y_API_TOKEN", env_file=True,
                   placeholder="optional — O11y API token with Agent Observability access",
                   help="Only used to group turns into Agent Observability sessions — the "
                        "Session level of the AO views and evaluators (the ingest token cannot "
                        "call that API). Observability Cloud > Settings > Access Tokens > "
                        "Create Token, type API token, role agent_observability_admin. Leave "
                        "blank to log turns without sessions."),
        _CredField("project", "Project", env="SPLUNK_AO_PROJECT", env_file=True, restart="collector",
                   placeholder="PseudoCo Assistant", help="Created on first ingest if it does not exist."),
        _CredField("agent_stream", "Agent stream", env="SPLUNK_AO_AGENT_STREAM", env_file=True,
                   restart="collector", placeholder="PseudoCo Assistant",
                   help="Stream inside the project that this box's turns land in. Created on "
                        "first ingest."),
        _CredField("agent_control_api_key", "Agent Control API key", secret=True,
                   env="AGENT_CONTROL_API_KEY", placeholder="paste the Agent Control console API key",
                   help="Only for the Agent Observability Controls guardrail — independent of "
                        "trace logging."),
        _CredField("agent_control_console_url", "Agent Control console URL",
                   env="AGENT_CONTROL_CONSOLE_URL",
                   placeholder="https://console.multitenant.galileocloud.io"),
        # Which Agent Control server the guardrail talks to. splunk_ao is the one
        # hosted inside this realm's Agent Observability: controls are attached
        # to the Agent stream in the AO UI, the token below authenticates as
        # X-SF-Token, and the two console fields above are not used.
        _CredField("agent_control_backend", "Agent Control backend",
                   settings_attr="galileo_agent_control_backend", placeholder="galileo | splunk_ao",
                   help="galileo = the standalone Galileo console (key + console URL above). "
                        "splunk_ao = the Agent Control server inside this realm's Agent "
                        "Observability: controls attached to the Agent stream in the AO UI, "
                        "authenticated by the token below; the console fields are not used."),
        _CredField("splunk_ao_control_token", "AO control token (splunk_ao)", secret=True,
                   env="SPLUNK_AO_CONTROL_TOKEN",
                   placeholder="optional — O11y API token with the agent_observability_admin role",
                   help="Sent as X-SF-Token to /ao/agent-control and /ao/api. Blank = reuse the "
                        "API token (sessions) field above. A token without the role reaches the "
                        "gateway but gets 403 controls.read."),
        _CredField("splunk_ao_control_target_type", "AO control target type (splunk_ao)",
                   settings_attr="splunk_ao_control_target_type", placeholder="log_stream",
                   help="What the gateway binds stream-attached controls under. log_stream "
                        "(the default). agent_stream, from Splunk's how-to, is answered with "
                        "502 AUTH_UPSTREAM_REJECTED by the us1 gateway."),
        _CredField("splunk_ao_control_step_name", "AO control step name (splunk_ao)",
                   settings_attr="splunk_ao_control_step_name", placeholder="complete_chat",
                   help="The llm step the UI controls are scoped to."),
    ],
    # Applies live: NemoGuardrailsClient.reconfigure() drops the built rails so
    # the next chat turn rebuilds them from the settings singleton.
    "nemo_guardrails": [
        _CredField("enabled", "Enabled", boolean=True, settings_attr="nemo_guardrails_enabled",
                   help="Master switch. The per-chat NeMo Guardrails toggle is ignored when this is off."),
        _CredField("rails", "Rails", settings_attr="nemo_guardrails_rails", wide=True,
                   placeholder="self_check_input,self_check_output,overreach",
                   help="Comma-separated: self_check_input, self_check_output (NeMo's LLM "
                        "self-checks on the active chat model) and overreach (PseudoCo Assistant's "
                        "prescriptive-overreach output rail)."),
        _CredField("content_safety_url", "NemoGuard content-safety NIM (this host)",
                   settings_attr="nemo_guardrails_content_safety_url",
                   placeholder="http://localhost:8001/v1", validate=_validate_optional_nim_url,
                   help="Optional SECOND local NIM serving llama-3.1-nemoguard-8b-content-safety. "
                        "Leave empty to skip the content-safety rails."),
        _CredField("fail_open", "Fail open", boolean=True, settings_attr="nemo_guardrails_fail_open",
                   help="True releases the turn when the rails error; False withholds it."),
    ],
}


def _field_current(field: "_CredField") -> str:
    from backend.config import settings

    if field.settings_attr:
        cur = getattr(settings, field.settings_attr, "")
    elif field.env_file and field.env:
        # .env, NOT os.environ: an env_file field's value is owned by .env, and a
        # library may have rewritten the process copy. The Splunk OTel distro does
        # exactly that — under opentelemetry-instrument it appends its own
        # telemetry.distro.* attributes to OTEL_RESOURCE_ATTRIBUTES at bootstrap. If
        # the field prefilled from os.environ, a save the operator never edited would
        # write the distro's internal attributes into .env and pin a distro version
        # that the distro is supposed to report itself.
        cur = _read_env_file_value(field.env)
    elif field.env:
        cur = os.environ.get(field.env, "")
    else:
        return ""
    if field.boolean:
        return "true" if _as_bool(cur) else "false"
    return cur or ""


_TRUE = {"1", "true", "yes", "on"}


def _as_bool(value: Any) -> bool:
    """Coerce a checkbox / .env / pydantic value to a bool. Mirrors the string forms
    pydantic-settings accepts, so a value round-trips through .env unchanged."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in _TRUE


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def load() -> Dict[str, Any]:
    """Return the persisted settings, seeding defaults on first run."""
    with get_db_context() as db:
        row = db.query(AppSettings).filter(AppSettings.id == _ROW_ID).first()
        if row is None:
            row = AppSettings(id=_ROW_ID, data=dict(_DEFAULTS))
            db.add(row)
            db.commit()
            return dict(_DEFAULTS)
        data = dict(_DEFAULTS)
        data.update(row.data or {})
        return data


def _persist(data: Dict[str, Any]) -> None:
    with get_db_context() as db:
        row = db.query(AppSettings).filter(AppSettings.id == _ROW_ID).first()
        if row is None:
            row = AppSettings(id=_ROW_ID, data=data)
            db.add(row)
        else:
            row.data = data  # reassign so SQLAlchemy tracks the JSON change
        db.commit()


# ---------------------------------------------------------------------------
# Log directory
# ---------------------------------------------------------------------------
def get_logs_directory() -> str:
    return load().get("logs_directory") or "logs"


def set_logs_directory(path: str) -> str:
    path = (path or "").strip() or "logs"
    data = load()
    data["logs_directory"] = path
    _persist(data)
    try:
        from backend.logging.governance_logger import governance_logger
        governance_logger.set_logs_directory(path)
    except Exception:
        logger.exception("failed to apply logs_directory at runtime")
    return path


# ---------------------------------------------------------------------------
# AI Defense enabled_rules discovery
# ---------------------------------------------------------------------------
def get_ai_defense_enabled_rules_supported() -> bool:
    return bool(load().get("ai_defense_enabled_rules_supported", True))


def set_ai_defense_enabled_rules_supported(supported: bool) -> bool:
    data = load()
    data["ai_defense_enabled_rules_supported"] = bool(supported)
    _persist(data)
    return bool(supported)


# ---------------------------------------------------------------------------
# Active blueprint (which agentic architecture serves chat turns by default;
# always pseudoco_multi_agent unless ACTIVE_BLUEPRINT or a PUT says otherwise)
# ---------------------------------------------------------------------------
def get_blueprint_setting() -> Dict[str, Any]:
    from backend.agents.blueprints import get_blueprint, list_blueprints
    from backend.config import settings

    active = get_blueprint(settings.active_blueprint)
    return {
        "active": active.key,
        "choices": [bp.to_public() for bp in list_blueprints()],
    }


def set_blueprint(key: str) -> Dict[str, Any]:
    """Switch the active architecture for this process only. Deliberately NOT
    persisted: there is no Blueprint picker in the UI, so every restart comes
    back up on the ACTIVE_BLUEPRINT default (pseudoco_multi_agent) rather than on
    a choice nobody can see or undo."""
    from backend.agents.blueprints import BLUEPRINTS
    from backend.config import settings

    key = (key or "").strip()
    if key not in BLUEPRINTS:
        raise ValueError(f"unknown blueprint: {key}. Valid: {', '.join(BLUEPRINTS)}")
    settings.active_blueprint = key   # compiled workflows are cached per key: no rebuild needed
    return get_blueprint_setting()


# ---------------------------------------------------------------------------
# NemoClaw Guardrails toggle (enforcement switch for the NemoClaw policy layer)
# ---------------------------------------------------------------------------
def get_nemoclaw_guardrails() -> Dict[str, Any]:
    from backend.config import settings

    # The live setting is the truth (startup applies the stored value over .env).
    return {"enabled": bool(settings.nemoclaw_guardrails_enabled)}


def set_nemoclaw_guardrails(enabled: bool) -> Dict[str, Any]:
    from backend.config import settings

    data = load()
    data["nemoclaw_guardrails"] = {"enabled": bool(enabled)}
    _persist(data)
    settings.nemoclaw_guardrails_enabled = bool(enabled)
    return get_nemoclaw_guardrails()


def apply_nemoclaw_guardrails_from_store() -> None:
    """Startup hook: the persisted toggle wins over the .env default."""
    from backend.config import settings

    cfg = load().get("nemoclaw_guardrails")
    if isinstance(cfg, dict) and "enabled" in cfg:
        settings.nemoclaw_guardrails_enabled = bool(cfg["enabled"])


# ---------------------------------------------------------------------------
# Demo Controls visibility (which cards the chat page's Demo Controls drawer
# shows; edited on the Settings page, persisted so the posture survives a restart)
# ---------------------------------------------------------------------------
# The registry every drawer card is checked against. Each card container in
# frontend/index.html (#settingsDrawer) carries data-control="<key>"; the
# Settings panel and chat.js applyDemoControlVisibility() are generated from
# this list, in this order (= drawer order), and tests/test_demo_controls.py
# fails when the markup and the registry diverge (CLAUDE.md "Demo Controls
# drawer formatting"). ``kind``: "request" = the toggle's state rides on every
# ChatRequest (chat.js CONTROL_FLAGS; a hidden card sends no override, so the
# server default governs), "server" = the toggle drives a server-side API and
# keeps running while hidden, "display" = browser-only.
DEMO_CONTROL_GROUPS: List[Dict[str, str]] = [
    {"key": "guardrails", "label": "Guardrails"},
    {"key": "pipeline", "label": "Agent Pipeline"},
    {"key": "synthetic", "label": "Synthetic Content"},
    {"key": "generators", "label": "Load & Incident Generators"},
    {"key": "display", "label": "Display"},
]
DEMO_CONTROL_KINDS: Tuple[str, ...] = ("request", "server", "display")


def _control(key: str, label: str, group: str, kind: str) -> Dict[str, str]:
    return {"key": key, "label": label, "group": group, "kind": kind}


DEMO_CONTROLS: List[Dict[str, str]] = [
    _control("ai_defense", "Cisco AI Defense Policy Review", "guardrails", "request"),
    _control("agent_control", "Agent Observability Controls", "guardrails", "request"),
    _control("nemo_guardrails", "NeMo Guardrails", "guardrails", "request"),
    _control("nemoclaw_guardrails", "NemoClaw Guardrails", "guardrails", "server"),
    _control("internal_policy", "Internal Policy Engine", "guardrails", "request"),
    _control("multi_agent", "Multi-Agent Mode", "pipeline", "request"),
    _control("synthetic_pii", "Include Synthetic PII/PHI in Responses", "synthetic", "request"),
    _control("synthetic_toxic", "Include Toxic Content in Responses", "synthetic", "request"),
    _control("synthetic_hallucination", "Include Hallucinated Content in Responses", "synthetic", "request"),
    _control("synthetic_boundary", "Include Outside of Authority Content in Responses", "synthetic", "request"),
    _control("auto_sessions", "Auto-Generate Sessions", "generators", "server"),
    _control("demo_incident", "Trigger Demo Incident", "generators", "server"),
    _control("injection_spray", "Prompt Injection Spray", "generators", "server"),
    _control("appearance", "Appearance", "display", "display"),
]
DEMO_CONTROL_KEYS: Tuple[str, ...] = tuple(c["key"] for c in DEMO_CONTROLS)


def _check_demo_control_registry() -> None:
    """Fail at import, not at the first GET, when the registry is malformed."""
    groups = {g["key"] for g in DEMO_CONTROL_GROUPS}
    for c in DEMO_CONTROLS:
        if c["group"] not in groups or c["kind"] not in DEMO_CONTROL_KINDS:
            raise ValueError(f"DEMO_CONTROLS[{c['key']}]: unknown group {c['group']!r} "
                             f"or kind {c['kind']!r}")
    if len(set(DEMO_CONTROL_KEYS)) != len(DEMO_CONTROL_KEYS):
        raise ValueError("DEMO_CONTROLS: duplicate key")


_check_demo_control_registry()


def get_demo_controls() -> Dict[str, Any]:
    """Every registered control with its visibility, in drawer order, plus the
    group headers. The store holds overrides only; an unlisted key is visible."""
    stored = load().get("demo_controls")
    if not isinstance(stored, dict):
        stored = {}
    return {
        "controls": [dict(c, visible=bool(stored.get(c["key"], True))) for c in DEMO_CONTROLS],
        "groups": [dict(g) for g in DEMO_CONTROL_GROUPS],
    }


def set_demo_controls(visible: Dict[str, bool]) -> Dict[str, Any]:
    """Merge ``{key: shown}`` into the stored overrides. An unknown key or a
    non-bool raises ValueError before anything is written (the router turns
    that into a 422). Hiding is not gating: a hidden per-request card sends no
    override for its ChatRequest flag, a hidden generator keeps running."""
    unknown = [k for k in visible if k not in DEMO_CONTROL_KEYS]
    if unknown:
        raise ValueError(f"unknown demo control: {', '.join(unknown)}. "
                         f"Valid: {', '.join(DEMO_CONTROL_KEYS)}")
    bad = [k for k, v in visible.items() if not isinstance(v, bool)]
    if bad:
        raise ValueError(f"visible must be true or false for: {', '.join(bad)}")
    data = load()
    current = data.get("demo_controls")
    # A fresh dict: load() copies the blob shallowly, so updating the stored dict
    # in place would also rewrite the shared _DEFAULTS entry.
    merged = dict(current) if isinstance(current, dict) else {}
    merged.update(visible)
    data["demo_controls"] = merged
    _persist(data)
    return get_demo_controls()


# ---------------------------------------------------------------------------
# Demo model-name emission override
# ---------------------------------------------------------------------------
def get_emit_model() -> Dict[str, Any]:
    cfg = load().get("emit_model") or {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "model_name": cfg.get("model_name") or "",
        "random": bool(cfg.get("random", False)),
    }


def set_emit_model(enabled: bool, model_name: str, random_emit: bool) -> Dict[str, Any]:
    cfg = {
        "enabled": bool(enabled),
        "model_name": (model_name or "").strip(),
        "random": bool(random_emit),
    }
    data = load()
    data["emit_model"] = cfg
    _persist(data)
    try:
        from backend.model_emitter import model_emitter
        model_emitter.configure(
            enabled=cfg["enabled"], model_name=cfg["model_name"], random_emit=cfg["random"]
        )
    except Exception:
        logger.exception("failed to apply emit_model at runtime")
    return cfg


# ---------------------------------------------------------------------------
# Active LLM provider selection
# ---------------------------------------------------------------------------
def get_ai_provider() -> Dict[str, Any]:
    """Return the LIVE provider/model in effect plus the per-provider model map.

    Reads the runtime ``settings`` singleton (which reflects .env plus any
    persisted UI override applied at startup), so the UI always shows what is
    actually being used — not just what is stored."""
    from backend.config import settings

    provider = (settings.ai_provider or "anthropic").lower()
    models = {p: (getattr(settings, attr, "") or "") for p, attr in _PROVIDER_MODEL_ATTR.items()}
    return {
        "provider": provider,
        "model": models.get(provider, ""),
        "choices": list(AI_PROVIDER_CHOICES),
        "models": models,
    }


def _apply_ai_provider(provider: str, model: str = "") -> None:
    """Apply the provider/model to the live settings singleton and drop the LLM
    client caches so the next chat turn picks it up (no restart)."""
    from backend.config import settings

    settings.ai_provider = provider
    if model:
        setattr(settings, _PROVIDER_MODEL_ATTR[provider], model)
    try:
        from backend.agents import llm
        llm.clear_caches()
    except Exception:
        logger.exception("failed to clear LLM caches after provider change")


def set_ai_provider(provider: str, model: str = "") -> Dict[str, Any]:
    provider = (provider or "").strip().lower()
    if provider not in _PROVIDER_MODEL_ATTR:
        raise ValueError(f"unknown provider: {provider}")
    model = (model or "").strip()
    data = load()
    data["ai_provider"] = {"provider": provider, "model": model}
    _persist(data)
    _apply_ai_provider(provider, model)
    return get_ai_provider()


def apply_ai_provider_from_store() -> None:
    """Startup hook: apply any persisted provider override over the .env default."""
    cfg = load().get("ai_provider") or {}
    provider = (cfg.get("provider") or "").strip().lower()
    if provider in _PROVIDER_MODEL_ATTR:
        _apply_ai_provider(provider, (cfg.get("model") or "").strip())


# ---------------------------------------------------------------------------
# Per-provider access credentials (API keys etc.) — secrets never leave the box
# ---------------------------------------------------------------------------
def get_provider_fields() -> Dict[str, List[Dict[str, Any]]]:
    """Per-provider access-field metadata for the Settings UI.

    Secret fields report ONLY ``present`` (bool) — never the value, not even a
    suffix — so no secret is ever exposed. Non-secret fields (base URL, region)
    return their current value so the field can prefill."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for provider, fields in _PROVIDER_FIELDS.items():
        items: List[Dict[str, Any]] = []
        for f in fields:
            cur = _field_current(f)
            item = {
                "key": f.key,
                "label": f.label,
                "secret": f.secret,
                "boolean": f.boolean,
                "placeholder": f.placeholder,
                "help": f.help,
                "present": bool(cur) if not f.boolean else True,
            }
            if not f.secret:
                item["value"] = cur
            items.append(item)
        out[provider] = items
    return out


def set_provider_creds(provider: str, fields: Dict[str, str]) -> None:
    """Apply + persist provider access fields. Blank values are ignored (a blank
    secret keeps the existing one), so a save never accidentally wipes a key."""
    from backend.config import settings

    provider = (provider or "").strip().lower()
    specs = _PROVIDER_FIELDS.get(provider)
    if not specs or not fields:
        return

    # Resolve + validate EVERY submitted field before applying any of them, so a
    # rejected field (e.g. a non-loopback NIM URL) leaves nothing half-applied.
    # Booleans are the one exception to blank-keeps-existing: a checkbox always
    # reports its state (same rule as set_integration_creds).
    pending: List[tuple] = []
    for f in specs:
        if f.key not in fields:
            continue
        raw = fields.get(f.key)
        if f.boolean:
            val = "true" if _as_bool(raw) else "false"
        else:
            val = (raw or "").strip()
            if not val:  # blank = keep existing (never wipe)
                continue
            if f.validate:
                f.validate(val)  # ValueError -> 422, nothing written
        pending.append((f, val))

    data = load()
    store = dict(data.get("ai_provider_creds") or {})
    pstore = dict(store.get(provider) or {})
    applied: List[str] = []
    for f, val in pending:
        if f.settings_attr:
            setattr(settings, f.settings_attr, _as_bool(val) if f.boolean else val)
        if f.env:
            os.environ[f.env] = val
        pstore[f.key] = val
        applied.append(f.key)

    if applied:
        store[provider] = pstore
        data["ai_provider_creds"] = store
        _persist(data)
        # Log field NAMES only — never values.
        logger.info("applied %s access fields: %s", provider, ", ".join(applied))
        try:
            from backend.agents import llm
            llm.clear_caches()  # rebuild provider clients with the new creds
        except Exception:
            logger.exception("failed to clear LLM caches after credential change")


def apply_provider_creds_from_store() -> None:
    """Startup hook: apply any persisted provider creds over the .env defaults."""
    from backend.config import settings

    store = load().get("ai_provider_creds") or {}
    for provider, fields in _PROVIDER_FIELDS.items():
        saved = store.get(provider) or {}
        for f in fields:
            val = (saved.get(f.key) or "").strip()
            if not val:
                continue
            if f.validate:
                try:
                    f.validate(val)
                except ValueError as exc:
                    # A stored value the current rules reject (e.g. a NIM URL
                    # saved before the local-only contract) must not win over
                    # the .env/config default — skip it and say why.
                    logger.warning("ignoring stored %s.%s: %s", provider, f.key, exc)
                    continue
            if f.settings_attr:
                setattr(settings, f.settings_attr, _as_bool(val) if f.boolean else val)
            if f.env:
                os.environ[f.env] = val


# ---------------------------------------------------------------------------
# Integration credentials — Cisco AI Defense / Splunk Observability Cloud
# ---------------------------------------------------------------------------
def _env_path() -> Path:
    from backend.config import BASE_DIR

    return Path(BASE_DIR) / ".env"


def _read_env_file_value(key: str) -> str:
    """Value of ``key`` as .env currently holds it, or "" if absent.

    Takes the FIRST match and applies the same quote/trailing-comment handling as
    backend/config.py's loader, so what the Settings page shows is what the app and
    the shell launchers will read back."""
    from backend.config import _strip_env_value

    path = _env_path()
    if not path.exists():
        return ""
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[len("export "):]
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == key:
            return _strip_env_value(v)
    return ""


def _write_env_key(key: str, value: str) -> None:
    """Set ``key`` in .env, replacing in place and collapsing any duplicates.

    A duplicate line is not cosmetic: backend/config.py takes the FIRST match while
    the shell readers in run.sh / run-collector.sh do `grep '^KEY=' | cut -d= -f2-`
    and yield BOTH values. So this rewrites the first occurrence and drops the rest.
    Values are written bare — no quoting, no trailing comment — because neither
    shell reader strips them.
    """
    if "\n" in value or "\r" in value:
        raise ValueError(f"{key}: value must not contain a newline")

    path = _env_path()
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    prefix = f"{key}="
    out: List[str] = []
    written = False
    for line in lines:
        bare = line[len("export "):] if line.startswith("export ") else line
        if bare.lstrip().startswith(prefix) and not bare.lstrip().startswith("#"):
            if written:
                continue  # duplicate of a key we already set — drop it
            out.append(f"{key}={value}\n")
            written = True
            continue
        out.append(line)
    if not written:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append(f"{key}={value}\n")

    # Atomic replace, preserving .env's mode (0600) so a secret is never briefly
    # world-readable — mkstemp creates at 0600 and the temp file lands in .env's own
    # directory, so os.replace is a rename within one filesystem.
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.writelines(out)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_integration_fields() -> Dict[str, List[Dict[str, Any]]]:
    """Per-integration field metadata for the Settings UI.

    Same contract as ``get_provider_fields``: secret fields report ONLY ``present``
    (bool) — never the value, not even a suffix. Non-secret and boolean fields
    return their current value so the control can prefill."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for integration, fields in _INTEGRATION_FIELDS.items():
        items: List[Dict[str, Any]] = []
        for f in fields:
            cur = _field_current(f)
            item = {
                "key": f.key,
                "label": f.label,
                "secret": f.secret,
                "boolean": f.boolean,
                "placeholder": f.placeholder,
                "help": f.help,
                "restart": f.restart,
                "wide": f.wide,
                "present": bool(cur) if not f.boolean else True,
            }
            if not f.secret:
                item["value"] = cur
            items.append(item)
        out[integration] = items
    return out


def _reconfigure_integration(integration: str) -> None:
    """Push a saved change into the live consumer, so no restart is needed.

    Both clients snapshot their config in ``__init__`` and are module-level
    singletons, so mutating the settings singleton alone is not enough — this is
    the analog of ``llm.clear_caches()`` on the provider path."""
    if integration == "ai_defense":
        from backend.services.ai_defense import ai_defense_client
        ai_defense_client.reconfigure()
    elif integration == "agent_observability":
        try:
            from backend.services.agent_control import agent_control_client
            agent_control_client.reconfigure()
        finally:
            # Retire the live SplunkAOLogger so the next turn rebuilds it from the
            # new realm / token / project / agent stream (non-blocking).
            from backend import agent_observability
            agent_observability.reconfigure()
    elif integration == "nemo_guardrails":
        from backend.services.nemo_guardrails import nemo_guardrails_client
        nemo_guardrails_client.reconfigure()


def set_integration_creds(integration: str, fields: Dict[str, str]) -> List[str]:
    """Apply + persist integration fields. Returns the processes that still need a
    restart for the change to take effect (empty when everything applied live).

    Blank values are ignored (a blank secret keeps the existing one), exactly as on
    the provider path. Booleans are the one exception — a checkbox always reports
    its state, so ``false`` is a real value rather than "leave alone"."""
    from backend.config import settings

    integration = (integration or "").strip()
    specs = _INTEGRATION_FIELDS.get(integration)
    if not specs or not fields:
        return []

    # Resolve + validate EVERY submitted field before applying any of them. A card
    # saves all its fields in one PUT and .env is written field-by-field, so
    # validating inside the apply loop below would leave .env half-updated whenever a
    # later field is rejected — reported to the operator as a plain error.
    pending: List[tuple] = []
    for f in specs:
        if f.key not in fields:
            continue
        raw = fields.get(f.key)
        if f.boolean:
            val = "true" if _as_bool(raw) else "false"
        else:
            val = (raw or "").strip()
            if not val:  # blank = keep existing (never wipe)
                continue
            if f.validate:
                f.validate(val)  # ValueError -> 422, nothing written
        if f.env_file and not f.env:
            raise ValueError(f"{f.key}: env_file field needs an env var name")
        pending.append((f, val))

    data = load()
    store = dict(data.get("integration_creds") or {})
    istore = dict(store.get(integration) or {})
    applied: List[str] = []
    restart: List[str] = []
    persist_blob = False

    for f, val in pending:
        if f.settings_attr:
            setattr(settings, f.settings_attr, _as_bool(val) if f.boolean else val)
        if f.env:
            os.environ[f.env] = val
        if f.env_file:
            # .env is the single source of truth for these — the consumer is a
            # different process, so mirroring them into the blob could only drift.
            _write_env_key(f.env, val)
        else:
            istore[f.key] = val
            persist_blob = True

        applied.append(f.key)
        if f.restart and f.restart not in restart:
            restart.append(f.restart)

    if applied:
        if persist_blob:
            store[integration] = istore
            data["integration_creds"] = store
            _persist(data)
        # Log field NAMES only — never values.
        logger.info("applied %s integration fields: %s", integration, ", ".join(applied))
        try:
            _reconfigure_integration(integration)
        except Exception:
            logger.exception("failed to reconfigure %s after credential change", integration)
    return restart


def apply_integration_creds_from_store() -> None:
    """Startup hook: apply any persisted integration creds over the .env defaults."""
    from backend.config import settings

    store = load().get("integration_creds") or {}
    for integration, fields in _INTEGRATION_FIELDS.items():
        saved = dict(store.get(integration) or {})
        if integration == "agent_observability":
            # Pre-4.9 blobs stored the Agent Control credentials under the keys the
            # legacy Galileo SDK path shared with it; keep a Settings-UI-only box working.
            for old_key, new_key in (("api_key", "agent_control_api_key"),
                                     ("console_url", "agent_control_console_url")):
                if saved.get(old_key) and not saved.get(new_key):
                    saved[new_key] = saved[old_key]
        for f in fields:
            if f.env_file:
                continue  # .env-owned; already loaded by backend.config
            val = (saved.get(f.key) or "").strip()
            if not val:
                continue
            if f.settings_attr:
                setattr(settings, f.settings_attr, _as_bool(val) if f.boolean else val)
            if f.env:
                os.environ[f.env] = val


# ---------------------------------------------------------------------------
# HEC destinations
# ---------------------------------------------------------------------------
def _default_destination() -> Dict[str, Any]:
    c = HECConfig()
    return {
        "id": "", "name": "New destination", "enabled": False, "url": "",
        "token": "", "verify_tls": True, "index": c.index, "source": c.source,
        "sourcetype": c.sourcetype, "host": c.host, "sourcetype_map": {},
        "batch_size": c.batch_size, "flush_interval_s": c.flush_interval_s,
        "queue_max": c.queue_max, "request_timeout_s": c.request_timeout_s,
        "max_retries": c.max_retries,
    }


def _new_id(name: str, existing: set) -> str:
    base = _ID_RE.sub("-", (name or "hec").strip().lower()).strip("-")[:32] or "hec"
    candidate = base
    while not candidate or candidate in existing:
        candidate = f"{base}-{uuid.uuid4().hex[:6]}"
    return candidate


def list_destinations() -> List[Dict[str, Any]]:
    return list(load().get("hec_destinations") or [])


def get_destination(dest_id: str) -> Optional[Dict[str, Any]]:
    for d in list_destinations():
        if d.get("id") == dest_id:
            return d
    return None


def add_destination(patch: Dict[str, Any]) -> Dict[str, Any]:
    data = load()
    dests = list(data.get("hec_destinations") or [])
    existing = {d.get("id") for d in dests}
    record = _default_destination()
    record.update({k: v for k, v in (patch or {}).items() if k != "id"})
    record["id"] = _new_id(record.get("name", ""), existing)
    dests.append(record)
    data["hec_destinations"] = dests
    _persist(data)
    return record


def update_destination(dest_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    data = load()
    dests = list(data.get("hec_destinations") or [])
    updated = None
    for d in dests:
        if d.get("id") == dest_id:
            for k, v in (patch or {}).items():
                if k == "id":
                    continue
                d[k] = v
            updated = d
            break
    if updated is None:
        return None
    data["hec_destinations"] = dests
    _persist(data)
    return updated


def delete_destination(dest_id: str) -> bool:
    data = load()
    dests = list(data.get("hec_destinations") or [])
    new_dests = [d for d in dests if d.get("id") != dest_id]
    if len(new_dests) == len(dests):
        return False
    data["hec_destinations"] = new_dests
    _persist(data)
    return True


# ---------------------------------------------------------------------------
# HEC runtime bridge
# ---------------------------------------------------------------------------
def to_hec_config(dest: Dict[str, Any]) -> HECConfig:
    return HECConfig.from_dict(dest)


def all_configs() -> List[HECConfig]:
    return [to_hec_config(d) for d in list_destinations()]


async def reconfigure_hec() -> None:
    """Push the current destination set into the runtime (restart forwarders)."""
    await hec_runtime.reconfigure(all_configs())


def mask(dest: Dict[str, Any]) -> Dict[str, Any]:
    """Strip the token from a destination for API responses."""
    out = {k: v for k, v in dest.items() if k != "token"}
    token = dest.get("token") or ""
    out["token_present"] = bool(token)
    out["token_last4"] = token[-4:] if token else ""
    return out
