"""Galileo Agent Control - runtime control evaluation client.

Thin, dependency-light wrapper around Galileo's Agent Control server, used to
submit the assistant's generated response for evaluation against the Controls
defined centrally in the Galileo console before PseudoCo Assistant returns it to the user.
This is the "Agent Observability Controls" surface in the settings drawer: the
Galileo counterpart of the Cisco AI Defense response review, and what makes a
deny control such as ``PseudoCoAssistant-block-hallucinated-output`` (Correctness score
below threshold) actually withhold an answer.

Grounded on the Agent Control Server 8.x contract (its published OpenAPI):
  - Register : POST {base}/api/v1/agents/initAgent
               {"agent": {"agent_name": ...}, "steps": [{"type","name"}]}
  - Attach   : POST {base}/api/v1/agents/{agent_name}/controls/{control_id}
  - Evaluate : POST {base}/api/v1/evaluation
               {"agent_name", "stage": "pre"|"post",
                "step": {"type","name","input","output"[,"context"]}}
               -> {"is_safe", "confidence", "reason",
                   "matches": [{"control_name","action",
                                "result": {"matched","confidence","message"}}]}

Auth is two-legged. The Galileo API key is first exchanged for a console access
token, which is then exchanged for a short-lived, target-bound *runtime* token;
``/api/v1/evaluation`` accepts only the runtime token as a Bearer credential.
Mirroring the official SDK's ``auto`` runtime-auth mode, an unavailable exchange
endpoint falls back to presenting the console token directly rather than failing
the turn outright.

Two transports, selected by ``galileo_agent_control_execution``:

  - **server** — ``POST /api/v1/evaluation``, the Agent Control server resolves
    and runs the agent's effective control set.
  - **client** — the ``execution: "sdk"`` equivalent: read the agent's control
    definitions from the management API (which needs only the console token) and
    run their Luna conditions here, scoring through the console API's
    ``POST /scorers/invoke``. This exists because a deployment whose org lacks a
    runtime-token grant cannot use the server path at all: the exchange returns
    502 and ``/evaluation`` then rejects the console token with
    ``401 Token is missing the "iat" claim``. ``auto`` prefers the server and
    falls back here, so a missing grant costs a transport, not the guardrail.

The local comparison (``score_matches`` / ``coerce_number``) is ported verbatim
from ``agent_control_evaluator_galileo`` so both transports decide identically —
including the rule that a numeric operator over a boolean scorer is an error, not
a 0/1 comparison.

Two backends, selected by ``galileo_agent_control_backend``:

  - **galileo** (default) — the standalone Galileo console + agent-control
    server described above.
  - **splunk_ao** — the same Agent Control server hosted INSIDE Splunk
    Observability Cloud's Agent Observability, at
    ``https://app.<realm>.observability.splunkcloud.com/ao/agent-control``. The
    O11y gateway authenticates every call with an O11y API token sent as
    ``X-SF-Token`` (``SPLUNK_AO_CONTROL_TOKEN``, falling back to
    ``SPLUNK_AO_O11Y_API_TOKEN``); there is no console login. Controls are
    authored in the Agent Observability Controls UI and attached to an Agent
    stream, so every request is bound to a *target* — the stream the turn is
    logged to (``agent_observability._stream_for``), resolved to its id once
    per stream through the AO API and cached. The runtime-token exchange is
    attempted for that target and, per the official SDK's ``auto`` mode, an
    unavailable exchange falls back to the API-key header alone. Client-side
    execution is not available on this backend (its scorers live in the AO
    org), so ``execution`` is always server there. The prompt stage runs too
    (``pre``), because the UI attaches controls to both stages.

Fully defensive: a no-op when the backend's credential is unset or the master
switch is off, and errors are normalized into a verdict that honors
``galileo_agent_control_fail_open`` (default True — release the response and log,
because this control layer sits *after* the internal policy engine and AI
Defense).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

_legacy_env_warned = False


def _warn_legacy_env_once() -> None:
    """GALILEO_API_KEY / GALILEO_CONSOLE_URL still work for Agent Control, but the
    names are deprecated now that trace logging runs on SPLUNK_AO_*."""
    global _legacy_env_warned
    if _legacy_env_warned:
        return
    _legacy_env_warned = True
    logger.warning(
        "agent control: GALILEO_API_KEY / GALILEO_CONSOLE_URL are deprecated; set "
        "AGENT_CONTROL_API_KEY / AGENT_CONTROL_CONSOLE_URL (Settings > Splunk Agent "
        "Observability)"
    )

# Re-attempt a failing runtime-token exchange no more than once per interval, so
# a tenant that has not enabled runtime tokens does not pay a wasted round-trip
# on every single turn.
_TOKEN_RETRY_COOLDOWN_SECONDS = 300.0
# Refresh cached tokens this long before they actually expire.
_TOKEN_REFRESH_MARGIN_SECONDS = 60.0
# Fallback lifetime when a token carries no parseable expiry.
_TOKEN_ASSUMED_TTL_SECONDS = 1800.0

# The only evaluator PseudoCo Assistant can run client-side. Anything else (a custom
# agent-scoped evaluator, regex/list/json/sql) is left to server execution —
# guessing at its semantics would be worse than reporting it unevaluated.
_LOCAL_EVALUATOR = "galileo.luna"

BACKEND_GALILEO = "galileo"
BACKEND_SPLUNK_AO = "splunk_ao"
# splunk_ao backend: the header the O11y gateway authenticates with, and the
# header the Agent Control server reads a target-bound runtime token from
# (raw, no Bearer prefix) because ``Authorization`` is reserved for the gateway.
_SF_TOKEN_HEADER = "X-SF-Token"
_RUNTIME_TOKEN_HEADER = "X-Agent-Control-Runtime-Token"
# Page size when scanning a project's Agent streams for a name.
_STREAM_PAGE_SIZE = 100
# Guard against a pagination cursor that never advances.
_STREAM_MAX_PAGES = 50


def coerce_number(value: Any) -> Optional[float]:
    """Numeric view of a JSON scalar, or None when it has none.

    Ported verbatim from ``agent_control_evaluator_galileo.luna.config`` so
    client-side execution decides exactly what the server would. The bool rule
    is load-bearing, not an oversight: a boolean scorer (``correctness`` emits
    true/false) has no numeric reading, so a numeric operator against it is a
    configuration error that must surface, not silently compare as 0/1.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _contains(score: Any, threshold: Any) -> bool:
    """Membership test matching the upstream Luna evaluator's ``contains``."""
    if threshold is None:
        return False
    if isinstance(score, str):
        return str(threshold) in score
    if isinstance(score, list):
        return threshold in score
    if isinstance(score, dict):
        return threshold in score.values()
    return False


def score_matches(score: Any, operator: str, threshold: Any) -> bool:
    """Apply a control's local comparison to a raw Luna score.

    Mirrors ``LunaEvaluator._score_matches``. Raises ``ValueError`` for a
    numeric operator against a non-numeric score — the same failure the server
    reports as an evaluator error (which fails open), and the reason a
    ``lt 0.5`` control over the boolean ``correctness`` scorer can never match.
    """
    if operator == "any":
        return bool(score)
    if operator == "eq":
        return score == threshold
    if operator == "ne":
        return score != threshold
    if operator == "contains":
        return _contains(score, threshold)

    score_number = coerce_number(score)
    threshold_number = coerce_number(threshold)
    if score_number is None:
        raise ValueError(f"Luna score {score!r} is not numeric")
    if threshold_number is None:
        raise ValueError(f"Luna threshold {threshold!r} is not numeric")

    if operator == "gt":
        return score_number > threshold_number
    if operator == "gte":
        return score_number >= threshold_number
    if operator == "lt":
        return score_number < threshold_number
    if operator == "lte":
        return score_number <= threshold_number

    raise ValueError(f"Unsupported Luna operator: {operator}")


def _confidence_from_score(score: Any) -> float:
    """Upstream's confidence mapping (bool -> 1.0/0.0, 0-1 float as-is)."""
    if isinstance(score, bool):
        return 1.0 if score else 0.0
    number = coerce_number(score)
    if number is not None and 0.0 <= number <= 1.0:
        return number
    return 1.0


def _scope_matches(scope: Dict[str, Any], *, stage: str, step_type: str, step_name: str) -> bool:
    """Whether a control's scope covers this step. Absent key = applies to all."""
    stages = scope.get("stages")
    if stages and stage not in stages:
        return False
    step_types = scope.get("step_types")
    if step_types and step_type not in step_types:
        return False
    step_names = scope.get("step_names")
    if step_names and step_name not in step_names:
        return False
    return True


def _steering_message(context: Any) -> Optional[str]:
    """The guidance text of a ``SteeringContext`` ({"message": ...}), or None."""
    if not isinstance(context, dict):
        return None
    message = str(context.get("message") or "").strip()
    return message or None


@dataclass
class ControlVerdict:
    """Normalized outcome of one Agent Control evaluation."""

    is_safe: bool = True
    confidence: float = 0.0
    reason: Optional[str] = None
    # Names of the controls that matched, and the action each one configured.
    matched_controls: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    # Per-control explanations from the evaluators (Luna score messages etc.).
    messages: List[str] = field(default_factory=list)
    # Controls whose evaluator itself failed server-side (fail-open per the
    # Agent Control contract, surfaced for triage).
    evaluator_errors: List[str] = field(default_factory=list)
    # True when this client could not obtain a real verdict (auth/network/parse).
    errored: bool = False
    error_message: Optional[str] = None
    # Which transport produced this verdict: "server" (POST /api/v1/evaluation)
    # or "client" (control definitions evaluated in-process). Recorded on the
    # governance event so a block can be attributed to the right path.
    transport: Optional[str] = None
    # Which stage was judged ("pre" = the prompt, "post" = the answer), which
    # backend judged it, and — splunk_ao only — the Agent stream the evaluation
    # was bound to. Wall-clock of the evaluation for the control span.
    stage: str = "post"
    backend: Optional[str] = None
    target: Optional[str] = None
    duration_ms: Optional[float] = None
    # The corrective guidance of each matched steer control
    # (``steering_context.message``), in match order. The response-stage node
    # rewrites the answer with it (backend/agents/nodes/agent_control.py).
    steering: List[str] = field(default_factory=list)
    # What that node did with a steer, set only on a steered response verdict:
    # {"attempts", "outcome" (applied | unresolved | unverified | error),
    #  "recheck_controls", "recheck_decisions"}.
    steer: Optional[Dict[str, Any]] = None

    def record(self) -> Dict[str, Any]:
        """Flat, JSON-safe view for the governance event
        (``agent_control_verdicts``) and the API response metadata."""
        return {
            "stage": self.stage,
            "backend": self.backend,
            "target": self.target,
            "is_safe": self.is_safe,
            "confidence": self.confidence,
            "reason": self.reason,
            "agent_name": settings.galileo_agent_control_agent_name,
            "controls": list(self.matched_controls),
            "decisions": list(self.decisions),
            "messages": list(self.messages),
            "evaluator_errors": list(self.evaluator_errors),
            "errored": self.errored,
            "error_message": self.error_message,
            "transport": self.transport,
            "duration_ms": self.duration_ms,
            "steering": list(self.steering),
            "steer": dict(self.steer) if self.steer else None,
        }

    @property
    def should_block(self) -> bool:
        """Whether the response must be withheld.

        - A real verdict containing a ``deny`` decision always blocks.
        - ``steer`` and ``observe`` never block. A response-stage steer is
          enforced by rewriting the answer with the control's guidance
          (``agent_control_node``), not by withholding it; a prompt-stage steer
          is recorded only.
        - On error, honor the configured fail-open / fail-closed policy.
        """
        if self.errored:
            return not settings.galileo_agent_control_fail_open
        return any(decision == "deny" for decision in self.decisions)

    @property
    def steered(self) -> bool:
        return any(decision == "steer" for decision in self.decisions)


class AgentControlError(Exception):
    """Raised for configuration problems (e.g. missing Galileo API key)."""


class AgentControlClient:
    """Synchronous client for the Galileo Agent Control evaluation API."""

    def __init__(self) -> None:
        self._base_url = (settings.galileo_agent_control_url or "").rstrip("/")
        self._timeout = settings.galileo_agent_control_timeout
        self._agent_name = settings.galileo_agent_control_agent_name
        self._step_name = settings.galileo_agent_control_step_name
        # Cached credentials: (token, expires_at_epoch).
        self._access_token: Optional[str] = None
        self._access_expires_at: float = 0.0
        self._runtime_token: Optional[str] = None
        self._runtime_expires_at: float = 0.0
        # Set when the runtime-token exchange is unavailable on this deployment;
        # holds the epoch after which we retry. 0.0 = never failed.
        self._runtime_retry_after: float = 0.0
        self._runtime_unavailable_logged = False
        # Cached control definitions for client-side execution:
        # [{"id", "name", <definition>}], plus the epoch it goes stale.
        self._controls: Optional[List[Dict[str, Any]]] = None
        self._controls_expires_at: float = 0.0
        self._server_control_locally_logged: set = set()
        self._reset_ao_state()

    def _reset_ao_state(self) -> None:
        """splunk_ao caches: stream -> id (with the project id), one runtime
        token per target, which targets this process has registered the agent
        for, and the once-per-process log flags."""
        self._project_id: Optional[str] = None
        self._stream_ids: Dict[str, str] = {}
        self._stream_ids_expires_at: float = 0.0
        self._ao_runtime_tokens: Dict[str, tuple] = {}
        self._ao_runtime_retry_after: float = 0.0
        self._registered_targets: set = set()
        self._registration_failed_logged: set = set()
        self._client_mode_logged = False

    def reconfigure(self) -> None:
        """Re-read config and drop every cached credential after a Settings-UI change.

        ``api_key`` / ``console_api_url`` are live ``os.getenv`` reads, but the base
        URL, timeout and agent/step names are snapshotted in ``__init__`` on a
        module-level singleton. Every cached token and control definition is also
        invalidated: a new API key means a different tenant, so a token minted for
        the old one is worthless (and the control set may differ entirely)."""
        self._base_url = (settings.galileo_agent_control_url or "").rstrip("/")
        self._timeout = settings.galileo_agent_control_timeout
        self._agent_name = settings.galileo_agent_control_agent_name
        self._step_name = settings.galileo_agent_control_step_name
        self._access_token = None
        self._access_expires_at = 0.0
        self._runtime_token = None
        self._runtime_expires_at = 0.0
        self._runtime_retry_after = 0.0
        self._runtime_unavailable_logged = False
        self._controls = None
        self._controls_expires_at = 0.0
        self._server_control_locally_logged = set()
        self._reset_ao_state()

    # ---------------------------------------------------------------- config

    @property
    def backend(self) -> str:
        """``galileo`` (default) or ``splunk_ao``; anything else reads as galileo."""
        value = (settings.galileo_agent_control_backend or "").strip().lower()
        return BACKEND_SPLUNK_AO if value in (BACKEND_SPLUNK_AO, "ao", "splunk") else BACKEND_GALILEO

    @property
    def is_splunk_ao(self) -> bool:
        return self.backend == BACKEND_SPLUNK_AO

    @property
    def stages(self) -> List[str]:
        """Stages the guardrail runs, in chain order. Explicit setting wins;
        otherwise post-only on galileo, pre+post on splunk_ao."""
        raw = (settings.galileo_agent_control_stages or "").strip().lower()
        if raw:
            wanted = [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]
            return [s for s in ("pre", "post") if s in wanted]
        return ["pre", "post"] if self.is_splunk_ao else ["post"]

    @property
    def step_name(self) -> str:
        """The ``llm`` step the controls are scoped to on this backend."""
        if self.is_splunk_ao:
            return settings.splunk_ao_control_step_name or self._step_name
        return self._step_name

    @property
    def api_key(self) -> str:
        """The backend's credential, read live so a Settings save applies
        immediately. Deliberately not a pydantic setting.

        galileo: ``AGENT_CONTROL_API_KEY`` (the console API key); the former
        ``GALILEO_API_KEY`` is honored as a deprecated fallback (one warning per
        process). splunk_ao: ``SPLUNK_AO_CONTROL_TOKEN``, an O11y API token that
        carries the ``agent_observability_admin`` role, falling back to the
        ``SPLUNK_AO_O11Y_API_TOKEN`` the AO worker already uses for sessions.
        The two backends never share a variable: on a box with both configured,
        switching backends must not present one vendor's secret to the other.
        """
        if self.is_splunk_ao:
            return (
                os.getenv("SPLUNK_AO_CONTROL_TOKEN", "")
                or os.getenv("SPLUNK_AO_O11Y_API_TOKEN", "")
            )
        key = os.getenv("AGENT_CONTROL_API_KEY", "")
        if key:
            return key
        legacy = os.getenv("GALILEO_API_KEY", "")
        if legacy:
            _warn_legacy_env_once()
        return legacy

    @property
    def control_url(self) -> str:
        """Agent Control server base URL for the active backend."""
        if self.is_splunk_ao:
            override = (settings.splunk_ao_control_url or "").strip().rstrip("/")
            if override:
                return override if "://" in override else f"https://{override}"
            realm = (os.getenv("SPLUNK_AO_REALM") or "").strip()
            return f"https://app.{realm}.observability.splunkcloud.com/ao/agent-control" if realm else ""
        return self._base_url

    @property
    def ao_api_url(self) -> str:
        """Agent Observability CRUD API (``/ao/api``) on the same host as the
        splunk_ao control server — used only to resolve stream ids."""
        base = self.control_url
        marker = "/ao/agent-control"
        if base.endswith(marker):
            return base[: -len(marker)] + "/ao/api"
        realm = (os.getenv("SPLUNK_AO_REALM") or "").strip()
        return f"https://app.{realm}.observability.splunkcloud.com/ao/api" if realm else ""

    @property
    def is_configured(self) -> bool:
        return bool(
            settings.galileo_agent_control_enabled and self.api_key and self.control_url
        )

    @property
    def console_api_url(self) -> str:
        """Base URL of the Agent Control *console* API that issues access tokens.

        Derived from ``AGENT_CONTROL_CONSOLE_URL`` the way the vendor SDK does
        (``console.<host>`` -> ``api.<host>``), defaulting to the hosted API.
        ``GALILEO_CONSOLE_URL`` is honored ONLY for the legacy pair (no
        ``AGENT_CONTROL_API_KEY``, legacy ``GALILEO_API_KEY`` set): the splunk-ao
        SDK injects ``GALILEO_CONSOLE_URL=https://app.<realm>.observability.splunkcloud.com/``
        into the process environment on its first session call, so a blind
        fallback would point the token exchange at the Observability Cloud host.
        """
        console = (os.getenv("AGENT_CONTROL_CONSOLE_URL") or "").strip().rstrip("/")
        if not console and not os.getenv("AGENT_CONTROL_API_KEY") and os.getenv("GALILEO_API_KEY"):
            console = (os.getenv("GALILEO_CONSOLE_URL") or "").strip().rstrip("/")
        if not console:
            return "https://api.galileo.ai"
        if "://" not in console:
            console = f"https://{console}"
        return console.replace("://console.", "://api.", 1)

    # ------------------------------------------------------------------ auth

    @staticmethod
    def _jwt_expiry(token: str) -> Optional[float]:
        """Best-effort ``exp`` claim (epoch seconds) from a JWT, or None."""
        try:
            payload = token.split(".")[1]
            padded = payload + "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded))
            exp = claims.get("exp")
            return float(exp) if exp is not None else None
        except Exception:  # noqa: BLE001 - any malformed token just means "unknown"
            return None

    def _fetch_access_token(self) -> str:
        """Exchange the Galileo API key for a console access token (cached)."""
        now = time.time()
        if self._access_token and now < self._access_expires_at:
            return self._access_token

        response = httpx.post(
            f"{self.console_api_url}/v2/login/api_key",
            json={"api_key": self.api_key},
            timeout=self._timeout,
        )
        response.raise_for_status()
        token = (response.json() or {}).get("access_token")
        if not token:
            raise AgentControlError(
                "Splunk Agent Observability login returned no access_token"
            )

        expiry = self._jwt_expiry(token) or (now + _TOKEN_ASSUMED_TTL_SECONDS)
        self._access_token = token
        self._access_expires_at = expiry - _TOKEN_REFRESH_MARGIN_SECONDS
        return token

    def _fetch_runtime_token(self, access_token: str) -> Optional[str]:
        """Mint a short-lived runtime token bound to this agent (cached).

        Returns None when the deployment cannot issue one, in which case the
        caller presents the console token instead (the SDK's ``auto`` mode).
        """
        now = time.time()
        if self._runtime_token and now < self._runtime_expires_at:
            return self._runtime_token
        if self._runtime_retry_after and now < self._runtime_retry_after:
            return None

        try:
            response = httpx.post(
                f"{self._base_url}/api/v1/auth/runtime-token-exchange",
                json={"target_type": "agent", "target_id": self._agent_name},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json() or {}
            token = data.get("token")
            if not token:
                raise AgentControlError("runtime-token exchange returned no token")
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            self._runtime_retry_after = now + _TOKEN_RETRY_COOLDOWN_SECONDS
            if not self._runtime_unavailable_logged:
                logger.warning(
                    "Galileo Agent Control runtime-token exchange unavailable "
                    "(%s); falling back to console-token auth. Evaluation "
                    "requires a runtime token on this deployment, so controls "
                    "will not enforce until the org's runtime grant is enabled.",
                    exc,
                )
                self._runtime_unavailable_logged = True
            return None

        expiry = self._jwt_expiry(token) or (now + _TOKEN_ASSUMED_TTL_SECONDS)
        self._runtime_token = token
        self._runtime_expires_at = expiry - _TOKEN_REFRESH_MARGIN_SECONDS
        self._runtime_retry_after = 0.0
        self._runtime_unavailable_logged = False
        return token

    def _bearer_token(self) -> str:
        access_token = self._fetch_access_token()
        return self._fetch_runtime_token(access_token) or access_token

    # ------------------------------------------------- splunk_ao: auth + target

    def _management_headers(self) -> Dict[str, str]:
        """Headers for the management endpoints (initAgent, controls, validate).

        galileo presents the console access token; splunk_ao presents the O11y
        API token on ``X-SF-Token`` — the gateway needs nothing else."""
        if self.is_splunk_ao:
            return {_SF_TOKEN_HEADER: self.api_key}
        return {"Authorization": f"Bearer {self._fetch_access_token()}"}

    def _fetch_ao_runtime_token(self, target: Dict[str, str]) -> Optional[str]:
        """Mint a target-bound runtime token on the splunk_ao backend (cached
        per target). Mirrors the official SDK's ``auto`` mode: an exchange that
        answers 404/5xx or cannot be reached marks the feature unavailable for
        a cooldown and the evaluation proceeds on the API-key header alone.
        A 401/403 is treated the same way rather than failing the turn — the
        gateway already authenticated the key, so the exchange is an optional
        hardening step here, not the credential."""
        now = time.time()
        key = target["target_id"]
        cached = self._ao_runtime_tokens.get(key)
        if cached and now < cached[1]:
            return cached[0]
        if self._ao_runtime_retry_after and now < self._ao_runtime_retry_after:
            return None
        try:
            response = httpx.post(
                f"{self.control_url}/api/v1/auth/runtime-token-exchange",
                json={"target_type": target["target_type"], "target_id": key},
                headers={_SF_TOKEN_HEADER: self.api_key, "accept": "application/json"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            token = (response.json() or {}).get("token")
            if not token:
                raise AgentControlError("runtime-token exchange returned no token")
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            self._ao_runtime_retry_after = now + _TOKEN_RETRY_COOLDOWN_SECONDS
            if not self._runtime_unavailable_logged:
                logger.info(
                    "Splunk Agent Observability Control runtime-token exchange unavailable "
                    "(%s); evaluating with the API token alone.",
                    exc,
                )
                self._runtime_unavailable_logged = True
            return None
        expiry = self._jwt_expiry(token) or (now + _TOKEN_ASSUMED_TTL_SECONDS)
        self._ao_runtime_tokens[key] = (token, expiry - _TOKEN_REFRESH_MARGIN_SECONDS)
        self._ao_runtime_retry_after = 0.0
        return token

    def _evaluation_headers(self, target: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Headers for ``POST /api/v1/evaluation`` on the active backend."""
        headers = {"Content-Type": "application/json", "accept": "application/json"}
        if self.is_splunk_ao:
            headers[_SF_TOKEN_HEADER] = self.api_key
            runtime = self._fetch_ao_runtime_token(target) if target else None
            if runtime:
                headers[_RUNTIME_TOKEN_HEADER] = runtime
            return headers
        headers["Authorization"] = f"Bearer {self._bearer_token()}"
        return headers

    @staticmethod
    def stream_for_theme(theme: Optional[str]) -> str:
        """The Agent stream this turn is logged to — the theme's label, or the
        default stream — from the SAME resolver the AO worker uses, so the
        control target and the trace never disagree."""
        from backend import agent_observability   # lazy: avoids a cycle at import

        return agent_observability._stream_for({"theme": theme} if theme else {})

    def _ao_get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        response = httpx.get(
            url,
            params=params,
            headers={_SF_TOKEN_HEADER: self.api_key, "accept": "application/json"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    def _resolve_project_id(self) -> str:
        if self._project_id:
            return self._project_id
        project = os.getenv("SPLUNK_AO_PROJECT") or "PseudoCo Assistant"
        body = self._ao_get(
            f"{self.ao_api_url}/projects", {"project_name": project, "type": "gen_ai"}
        )
        entries = body if isinstance(body, list) else (body or {}).get("projects") or []
        for entry in entries:
            if isinstance(entry, dict) and entry.get("id"):
                self._project_id = str(entry["id"])
                return self._project_id
        raise AgentControlError(
            f"Agent Observability project {project!r} not found (it is created on the "
            "first logged turn; log a turn first)"
        )

    def resolve_stream_id(self, stream: str) -> str:
        """The Agent stream's id, from ``GET /ao/api/projects/{id}/log_streams/paginated``
        scanned by name (the AO API has no name filter). Cached for the
        definition-refresh TTL; a stream that does not exist yet is an error the
        fail-open policy decides on — the guardrail never creates streams, the
        AO worker does that on the first logged turn."""
        now = time.time()
        if now >= self._stream_ids_expires_at:
            self._stream_ids = {}
            self._stream_ids_expires_at = now + max(60.0, settings.galileo_agent_control_refresh_seconds)
        cached = self._stream_ids.get(stream)
        if cached:
            return cached
        project_id = self._resolve_project_id()
        token = 0
        for _ in range(_STREAM_MAX_PAGES):
            page = self._ao_get(
                f"{self.ao_api_url}/projects/{project_id}/log_streams/paginated",
                {"limit": _STREAM_PAGE_SIZE, "starting_token": token},
            ) or {}
            for entry in page.get("log_streams") or []:
                if isinstance(entry, dict) and entry.get("id") and entry.get("name"):
                    self._stream_ids[str(entry["name"])] = str(entry["id"])
            if stream in self._stream_ids:
                return self._stream_ids[stream]
            next_token = page.get("next_starting_token")
            if next_token is None or not page.get("paginated", False) or next_token == token:
                break
            token = next_token
        raise AgentControlError(
            f"Agent stream {stream!r} not found in project {project_id} (streams are created "
            "on the first logged turn of a theme; attach the controls once it exists)"
        )

    def target_for(self, theme: Optional[str]) -> Optional[Dict[str, str]]:
        """splunk_ao: the target every call for this turn is bound to — the
        theme's Agent stream. None on the galileo backend (controls are attached
        to the agent name there)."""
        if not self.is_splunk_ao:
            return None
        stream = self.stream_for_theme(theme)
        return {
            "target_type": (settings.splunk_ao_control_target_type or "log_stream").strip(),
            "target_id": self.resolve_stream_id(stream),
            "stream": stream,
        }

    def _ensure_registered(self, target: Dict[str, str]) -> None:
        """Register the agent + step for this target once per process, the way
        the official SDK's ``init()`` does. A failure is logged once per target
        and never fails the turn: the agent may already exist server-side."""
        key = target["target_id"]
        if key in self._registered_targets:
            return
        try:
            self.register_agent(target=target)
            self._registered_targets.add(key)
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            if key not in self._registration_failed_logged:
                self._registration_failed_logged.add(key)
                logger.warning(
                    "Splunk Agent Observability Control: agent registration for stream %r "
                    "failed (%s); evaluating anyway.",
                    target.get("stream"), exc,
                )

    # ------------------------------------------------------------ evaluation

    def evaluate_prompt(
        self,
        user_message: str,
        *,
        enduser_id: Optional[str] = None,
        session_id: Optional[str] = None,
        theme: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ControlVerdict:
        """Screen the user's prompt as a pre-stage ``llm`` step (no output yet)."""
        return self.evaluate_response(
            user_message, "", stage="pre",
            enduser_id=enduser_id, session_id=session_id, theme=theme, model=model,
        )

    def evaluate_response(
        self,
        user_message: str,
        assistant_message: str,
        *,
        stage: str = "post",
        enduser_id: Optional[str] = None,
        session_id: Optional[str] = None,
        theme: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ControlVerdict:
        """Submit one ``llm`` step for evaluation at ``stage``.

        post (default): the step carries both sides of the turn (``input`` = the
        user's prompt, ``output`` = the generated answer) because the controls
        select ``path: "*"`` and their evaluators score input and output
        together — a correctness/hallucination judgement needs the question.
        pre: only the prompt, before any model call.

        Transport follows ``galileo_agent_control_execution``: ``auto`` (default)
        prefers the server and falls back to client-side execution when the
        deployment cannot mint a runtime token, so a missing runtime grant
        degrades the transport rather than the guardrail. The splunk_ao backend
        is always server-side (its scorers live in the AO org).
        """
        if not self.is_configured:
            raise AgentControlError(
                "Splunk Agent Observability Control is not configured (set the backend's "
                "credential — AGENT_CONTROL_API_KEY or SPLUNK_AO_CONTROL_TOKEN — and "
                "GALILEO_AGENT_CONTROL_ENABLED=True)."
            )
        stage = "pre" if str(stage).lower() == "pre" else "post"
        started = time.perf_counter()

        mode = (settings.galileo_agent_control_execution or "auto").strip().lower()
        if self.is_splunk_ao and mode == "client":
            if not self._client_mode_logged:
                self._client_mode_logged = True
                logger.warning(
                    "GALILEO_AGENT_CONTROL_EXECUTION=client is not available on the splunk_ao "
                    "backend (its evaluators run in the Agent Observability org); using server."
                )
            mode = "server"
        if mode == "client":
            verdict = self._evaluate_client_side(user_message, assistant_message, stage=stage)
            return self._finish(verdict, stage, None, started)

        target: Optional[Dict[str, str]] = None
        if self.is_splunk_ao:
            try:
                target = self.target_for(theme)
            except (httpx.HTTPError, ValueError, AgentControlError) as exc:
                logger.warning("Splunk Agent Observability Control target resolution failed: %s", exc)
                return self._finish(
                    ControlVerdict(errored=True, error_message=f"target: {exc}", transport="server"),
                    stage, None, started,
                )
            self._ensure_registered(target)

        verdict = self._evaluate_server_side(
            user_message,
            assistant_message,
            stage=stage,
            target=target,
            enduser_id=enduser_id,
            session_id=session_id,
            theme=theme,
            model=model,
        )
        if mode == "server" or not verdict.errored or self.is_splunk_ao:
            return self._finish(verdict, stage, target, started)

        # The server path could not produce a verdict (typically: this org has no
        # runtime-token grant, so /evaluation rejects the console token). Evaluate
        # the same controls locally rather than failing the guardrail open.
        local = self._evaluate_client_side(user_message, assistant_message, stage=stage)
        if local.errored and verdict.error_message:
            # Keep the server's diagnosis; it is the actionable one.
            local.error_message = f"{verdict.error_message}; client: {local.error_message}"
        return self._finish(local, stage, target, started)

    def _finish(self, verdict: ControlVerdict, stage: str, target: Optional[Dict[str, str]],
                started: float) -> ControlVerdict:
        verdict.stage = stage
        verdict.backend = self.backend
        verdict.target = (target or {}).get("stream")
        verdict.duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return verdict

    def _evaluate_server_side(
        self,
        user_message: str,
        assistant_message: str,
        *,
        stage: str = "post",
        target: Optional[Dict[str, str]] = None,
        enduser_id: Optional[str] = None,
        session_id: Optional[str] = None,
        theme: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ControlVerdict:
        """Evaluate via the Agent Control server (``POST /api/v1/evaluation``)."""
        context: Dict[str, Any] = {"app": settings.otel_service_name}
        if session_id:
            context["session_id"] = session_id
        if theme:
            context["theme"] = theme
        if model:
            context["model"] = model
        if enduser_id:
            context["user"] = enduser_id
        if target:
            context["agent_stream"] = target.get("stream")

        step: Dict[str, Any] = {
            "type": "llm",
            "name": self.step_name,
            "input": user_message,
            "context": context,
        }
        if stage == "post":
            step["output"] = assistant_message
        payload: Dict[str, Any] = {
            "agent_name": self._agent_name,
            "stage": stage,
            "step": step,
        }
        if target:
            payload["target_type"] = target["target_type"]
            payload["target_id"] = target["target_id"]

        try:
            headers = self._evaluation_headers(target)
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            logger.warning("Agent Control auth failed: %s", exc)
            return ControlVerdict(
                errored=True, error_message=f"auth: {exc}", transport="server"
            )

        try:
            response = httpx.post(
                f"{self.control_url}/api/v1/evaluation",
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            detail = self._safe_error_detail(exc.response) + self._target_type_hint(exc.response, target)
            # A rejected credential is usually a stale cached token; drop both
            # so the next turn re-authenticates from the API key.
            if exc.response.status_code in (401, 403):
                self._invalidate_tokens()
            logger.warning(
                "Agent Control evaluation HTTP %s: %s",
                exc.response.status_code,
                detail,
            )
            return ControlVerdict(
                errored=True,
                error_message=f"HTTP {exc.response.status_code}: {detail}",
                transport="server",
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Agent Control evaluation failed: %s", exc)
            return ControlVerdict(
                errored=True, error_message=str(exc), transport="server"
            )

        verdict = self._parse_response(data)
        verdict.transport = "server"
        return verdict

    # ------------------------------------------------- client-side execution

    def _load_controls(self) -> List[Dict[str, Any]]:
        """This agent's control definitions, cached for the configured TTL.

        Mirrors an Agent Control SDK's local control set. A refresh failure
        serves the last-known definitions rather than failing the turn; only a
        cold cache with no definitions is an error.
        """
        now = time.time()
        if self._controls is not None and now < self._controls_expires_at:
            return self._controls

        try:
            response = httpx.get(
                f"{self.control_url}/api/v1/agents/{self._agent_name}/controls",
                headers=self._management_headers(),
                timeout=self._timeout,
            )
            response.raise_for_status()
            body = response.json() or {}
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            if self._controls is not None:
                logger.warning(
                    "Galileo Agent Control definition refresh failed (%s); "
                    "reusing the %d cached control(s).",
                    exc,
                    len(self._controls),
                )
                # Back off before hammering a broken endpoint every turn.
                self._controls_expires_at = now + _TOKEN_RETRY_COOLDOWN_SECONDS
                return self._controls
            raise

        controls: List[Dict[str, Any]] = []
        for entry in body.get("controls") or []:
            if not isinstance(entry, dict):
                continue
            # This endpoint nests the definition under "control"; the
            # single-control endpoint uses "data". Accept either.
            definition = entry.get("control") or entry.get("data") or {}
            if isinstance(definition, dict) and definition:
                controls.append(
                    {
                        "id": entry.get("id"),
                        "name": entry.get("name") or str(entry.get("id")),
                        "definition": definition,
                    }
                )

        self._controls = controls
        self._controls_expires_at = now + max(
            0.0, settings.galileo_agent_control_refresh_seconds
        )
        logger.info(
            "Galileo Agent Control loaded %d control definition(s) for agent %s",
            len(controls),
            self._agent_name,
        )
        return controls

    def _log_server_control_run_locally(self, name: str) -> None:
        """Announce once that a server-scoped control is being run in-process."""
        if name in self._server_control_locally_logged:
            return
        self._server_control_locally_logged.add(name)
        logger.warning(
            "Galileo Agent Control '%s' is declared execution=server but is being "
            "evaluated in-process, because this deployment cannot mint a runtime "
            "token. The official engine would skip it; PseudoCo Assistant runs it so the "
            "guardrail still applies.",
            name,
        )

    def _invoke_scorer(
        self,
        config: Dict[str, Any],
        *,
        query: str,
        response_text: str,
        memo: Optional[Dict[Any, Any]] = None,
    ) -> Any:
        """Run one Luna scorer through the console API's ``/scorers/invoke``.

        Returns the raw score. Raises ``AgentControlError`` when the scorer
        itself could not produce one — the client-side equivalent of the
        server's evaluator error, which fails open rather than matching.

        ``memo`` is a per-evaluation cache keyed on (scorer, payload). A control
        that ORs several ``contains`` leaves over the SAME scorer — the natural
        shape for a list-valued scorer such as Output PII (SLM), which returns
        ``["ssn", "name", …]`` — then costs one judge call instead of one per
        category. Scoped to a single evaluation on purpose: caching verdicts
        across turns would mean stale safety decisions.
        """
        memo_key = (
            config.get("scorer_id"),
            config.get("scorer_version_id"),
            config.get("scorer_label"),
            query,
            response_text,
        )
        if memo is not None and memo_key in memo:
            cached = memo[memo_key]
            if isinstance(cached, Exception):
                raise cached
            return cached
        payload: Dict[str, Any] = {
            "inputs": {"query": query, "response": response_text},
        }
        for field_name in ("scorer_id", "scorer_version_id", "scorer_label"):
            if config.get(field_name):
                payload[field_name] = config[field_name]

        timeout = float(config.get("timeout_ms") or 0) / 1000.0 or self._timeout
        try:
            http_response = httpx.post(
                f"{self.console_api_url}/scorers/invoke",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self._fetch_access_token()}",
                    "Content-Type": "application/json",
                    "accept": "application/json",
                },
                timeout=max(timeout, self._timeout),
            )
            http_response.raise_for_status()
            body = http_response.json() or {}
            if body.get("status") != "success":
                raise AgentControlError(
                    f"scorer {body.get('scorer_label') or config.get('scorer_label')} "
                    f"{body.get('status')}: {body.get('error_message')}"
                )
        except Exception as exc:  # noqa: BLE001 - memoized and re-raised as-is
            if memo is not None:
                memo[memo_key] = exc
            raise

        score = body.get("score")
        if memo is not None:
            memo[memo_key] = score
        return score

    def _evaluate_condition(
        self,
        node: Dict[str, Any],
        *,
        query: str,
        response_text: str,
        memo: Dict[Any, Any],
    ) -> bool:
        """Evaluate a control's condition tree.

        Composite ``and``/``or``/``not`` nodes recurse and short-circuit like the
        official engine; a leaf is ``selector`` + ``evaluator``. Only the
        ``galileo.luna`` evaluator is supported client-side — anything else
        raises so the caller records it as unevaluated rather than guessing.
        """
        if node.get("and"):
            return all(
                self._evaluate_condition(
                    child, query=query, response_text=response_text, memo=memo
                )
                for child in node["and"]
            )
        if node.get("or"):
            return any(
                self._evaluate_condition(
                    child, query=query, response_text=response_text, memo=memo
                )
                for child in node["or"]
            )
        if node.get("not"):
            return not self._evaluate_condition(
                node["not"], query=query, response_text=response_text, memo=memo
            )

        evaluator = node.get("evaluator") or {}
        if evaluator.get("name") != _LOCAL_EVALUATOR:
            raise AgentControlError(
                f"{evaluator.get('name') or 'empty condition'} not supported client-side"
            )
        config = evaluator.get("config") or {}
        score = self._invoke_scorer(
            config, query=query, response_text=response_text, memo=memo
        )
        matched = score_matches(
            score, config.get("operator") or "any", config.get("threshold")
        )
        # Remember the score that decided, for the verdict message.
        memo.setdefault("_last_scores", []).append((score, config))
        return matched

    def _evaluate_client_side(
        self, user_message: str, assistant_message: str, *, stage: str = "post"
    ) -> ControlVerdict:
        """Evaluate this agent's controls in-process (``execution: "sdk"``).

        Only leaf ``galileo.luna`` conditions are supported; composite
        (and/or/not) conditions and other evaluators are reported as unevaluated
        instead of being guessed at.

        Deliberate deviation from the official engine, which skips any control
        whose ``execution`` differs from its context: PseudoCo Assistant also runs
        ``execution: "server"`` controls here, because the alternative on a
        deployment with no runtime-token grant is running nothing at all. It is
        logged once per process so a control marked *server* being enforced by
        the app is never a silent surprise. Flipping the control itself to
        ``sdk`` would be worse — it would drop out of the server path we want to
        inherit for free once the grant exists.
        """
        try:
            controls = self._load_controls()
        except (httpx.HTTPError, ValueError, AgentControlError) as exc:
            logger.warning("Galileo Agent Control definition load failed: %s", exc)
            return ControlVerdict(
                errored=True, error_message=f"controls: {exc}", transport="client"
            )

        verdict = ControlVerdict(transport="client")
        evaluated = 0

        for control in controls:
            definition = control["definition"]
            name = control["name"]
            if definition.get("enabled") is False:
                continue
            if not _scope_matches(
                definition.get("scope") or {},
                stage=stage,
                step_type="llm",
                step_name=self.step_name,
            ):
                continue

            condition = definition.get("condition") or {}
            if not condition:
                verdict.evaluator_errors.append(f"{name}: empty condition")
                continue

            if (definition.get("execution") or "server") != "sdk":
                self._log_server_control_run_locally(name)

            # One memo per control: leaves that share a scorer and payload — the
            # natural shape when OR-ing `contains` over a list-valued scorer —
            # cost a single judge call.
            memo: Dict[Any, Any] = {}
            try:
                matched = self._evaluate_condition(
                    condition,
                    query=user_message,
                    response_text=assistant_message,
                    memo=memo,
                )
            except (httpx.HTTPError, ValueError, AgentControlError) as exc:
                # Evaluator error: never a match, surfaced for triage.
                logger.warning("Galileo Agent Control '%s' evaluator failed: %s", name, exc)
                verdict.evaluator_errors.append(f"{name}: {exc}")
                continue

            evaluated += 1
            if not matched:
                continue

            action = definition.get("action") or {}
            decision = str(action.get("decision") or "observe").lower()
            scores = memo.get("_last_scores") or []
            score, config = scores[-1] if scores else (None, {})
            verdict.matched_controls.append(name)
            verdict.decisions.append(decision)
            guidance = _steering_message(action.get("steering_context"))
            if guidance and decision == "steer":
                verdict.steering.append(guidance)
            verdict.confidence = max(verdict.confidence, _confidence_from_score(score))
            verdict.messages.append(
                f"{name}: score {score!r} {config.get('operator')} "
                f"{config.get('threshold')!r}"
            )

        verdict.is_safe = not verdict.matched_controls
        if evaluated == 0 and not verdict.matched_controls:
            # Nothing could actually be judged — report it as an error so the
            # fail-open/fail-closed policy decides, rather than claiming "safe".
            verdict.errored = True
            verdict.error_message = (
                "; ".join(verdict.evaluator_errors)
                or f"no {stage}/llm controls attached to agent {self._agent_name}"
            )
        return verdict

    def _invalidate_tokens(self) -> None:
        self._access_token = None
        self._access_expires_at = 0.0
        self._runtime_token = None
        self._runtime_expires_at = 0.0
        self._ao_runtime_tokens = {}

    @staticmethod
    def _parse_response(data: Dict[str, Any]) -> ControlVerdict:
        if not isinstance(data, dict) or "is_safe" not in data:
            return ControlVerdict(
                errored=True, error_message="Malformed response: missing is_safe"
            )

        matched_controls: List[str] = []
        decisions: List[str] = []
        messages: List[str] = []
        steering: List[str] = []
        for match in data.get("matches") or []:
            if not isinstance(match, dict):
                continue
            name = match.get("control_name")
            if name:
                matched_controls.append(str(name))
            action = match.get("action")
            if action:
                decisions.append(str(action).lower())
            result = match.get("result")
            if isinstance(result, dict) and result.get("message"):
                messages.append(str(result["message"]))
            guidance = _steering_message(match.get("steering_context"))
            if guidance and str(action or "").lower() == "steer":
                steering.append(guidance)

        errors = [err for err in (data.get("errors") or []) if isinstance(err, dict)]
        evaluator_errors = [str(err.get("control_name") or "unknown") for err in errors]

        # A deny control whose evaluator ERRORED is reported under ``errors``,
        # not ``matches``, but the engine still flips is_safe to False for it
        # ("fail closed if a deny control errored" — agent_control_engine.core).
        # Reading only ``matches`` would take that as a clean pass, which is
        # exactly the response a mis-typed operator produces: neither blocked nor
        # subject to the fail-open policy. Treat it as errored so the configured
        # policy decides.
        is_safe = bool(data.get("is_safe", True))
        if not is_safe and not any(d == "deny" for d in decisions) and errors:
            denied = [
                str(err.get("control_name") or "unknown")
                for err in errors
                if str(err.get("action") or "").lower() == "deny"
            ] or evaluator_errors
            return ControlVerdict(
                is_safe=False,
                confidence=float(data.get("confidence") or 0.0),
                reason=data.get("reason"),
                evaluator_errors=evaluator_errors,
                errored=True,
                error_message=(
                    "deny control evaluator errored: " + ", ".join(denied)
                ),
            )

        return ControlVerdict(
            is_safe=is_safe,
            confidence=float(data.get("confidence") or 0.0),
            reason=data.get("reason"),
            matched_controls=matched_controls,
            decisions=decisions,
            messages=messages,
            evaluator_errors=evaluator_errors,
            steering=steering,
        )

    @staticmethod
    def _target_type_hint(response: httpx.Response, target: Optional[Dict[str, str]]) -> str:
        """The one misconfiguration this backend has a known fix for: a target
        type other than log_stream draws 502 AUTH_UPSTREAM_REJECTED from the AO
        gateway, whose message says nothing about the target."""
        if not target or target.get("target_type") == "log_stream" or response.status_code != 502:
            return ""
        if "AUTH_UPSTREAM_REJECTED" not in (response.text or ""):
            return ""
        return (f" (target_type {target.get('target_type')!r} is rejected by this gateway; "
                "set SPLUNK_AO_CONTROL_TARGET_TYPE=log_stream)")

    @staticmethod
    def _safe_error_detail(response: httpx.Response) -> str:
        try:
            body = response.json()
            if isinstance(body, dict):
                # Agent Control returns RFC 9457 problem documents. Lead with the
                # machine error_code when there is one: the O11y gateway's
                # "detail" is a generic "unexpected error" that hides it.
                code = body.get("error_code")
                for key in ("detail", "title", "message"):
                    if body.get(key):
                        return f"{code}: {body[key]}" if code else str(body[key])
                if code:
                    return str(code)
        except ValueError:
            pass
        return response.text[:200]

    # ---------------------------------------------------------- registration

    def register_agent(
        self,
        *,
        description: Optional[str] = None,
        version: str = "3.0.0",
        target: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Idempotently register this agent + its ``llm`` step with the server.

        galileo: not on the request path — the agent is registered once (see
        ``scripts/demo/register_agent_control.py``) and controls are attached to
        it in the console. splunk_ao: called lazily once per target (the theme's
        Agent stream) the way the official SDK's ``init()`` does, with the
        target in the body so the server merges the stream-attached controls.
        Exposed here so setup, the request path and tests share one contract.
        """
        if not self.is_configured:
            raise AgentControlError("Agent Control is not configured.")

        payload: Dict[str, Any] = {
            "agent": {
                "agent_name": self._agent_name,
                "agent_description": description
                or "PseudoCo Assistant multi-theme advisory assistant",
                "agent_version": version,
                "agent_metadata": {"app": settings.otel_service_name},
            },
            "steps": [
                {
                    "type": "llm",
                    "name": self.step_name,
                    "description": "PseudoCo Assistant synthesizer / domain agent response",
                }
            ],
            "conflict_mode": "overwrite",
        }
        if target:
            payload["target_type"] = target["target_type"]
            payload["target_id"] = target["target_id"]
        response = httpx.post(
            f"{self.control_url}/api/v1/agents/initAgent",
            json=payload,
            headers=self._management_headers(),
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json() or {}

    def attach_control(self, control_id: int) -> Dict[str, Any]:
        """Attach an existing console control to this agent (idempotent)."""
        if not self.is_configured:
            raise AgentControlError("Agent Control is not configured.")

        response = httpx.post(
            f"{self.control_url}/api/v1/agents/{self._agent_name}/controls/{control_id}",
            headers=self._management_headers(),
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json() or {}

    def validate_control_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dry-run a control definition (``POST /api/v1/controls/validate``)."""
        if not self.is_configured:
            raise AgentControlError("Agent Control is not configured.")

        response = httpx.post(
            f"{self.control_url}/api/v1/controls/validate",
            json={"data": data},
            headers={**self._management_headers(), "Content-Type": "application/json"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json() or {}

    def set_control_data(self, control_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a control's definition (``PUT /api/v1/controls/{id}/data``).

        ``PATCH /api/v1/controls/{id}`` only accepts name/enabled, so editing a
        condition — e.g. correcting an operator that can never match its
        scorer's output type — has to go through this full replace.
        """
        if not self.is_configured:
            raise AgentControlError("Agent Control is not configured.")

        response = httpx.put(
            f"{self.control_url}/api/v1/controls/{control_id}/data",
            json={"data": data},
            headers={**self._management_headers(), "Content-Type": "application/json"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        # A changed definition invalidates the client-side cache.
        self._controls = None
        self._controls_expires_at = 0.0
        return response.json() or {}

    def list_controls(self, *, theme: Optional[str] = None) -> List[Dict[str, Any]]:
        """Effective control set for this agent (direct + policy + bindings).
        splunk_ao: bound to the theme's Agent stream, so the stream-attached
        controls are included — the acceptance probe for a new deployment. It
        registers the agent for that stream first, as the first evaluation
        would: an agent the server has never seen answers 404 here."""
        if not self.is_configured:
            raise AgentControlError("Agent Control is not configured.")

        params: Dict[str, str] = {}
        target = self.target_for(theme) if self.is_splunk_ao else None
        if target:
            self._ensure_registered(target)
            params = {"target_type": target["target_type"], "target_id": target["target_id"]}
        response = httpx.get(
            f"{self.control_url}/api/v1/agents/{self._agent_name}/controls",
            params=params or None,
            headers=self._management_headers(),
            timeout=self._timeout,
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AgentControlError(
                f"HTTP {response.status_code}: {self._safe_error_detail(response)}"
                f"{self._target_type_hint(response, target)}"
            ) from exc
        data = response.json() or {}
        return list(data.get("controls") or [])


# Module-level singleton, mirrors other services in this package.
agent_control_client = AgentControlClient()
