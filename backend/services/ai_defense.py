"""Cisco AI Defense - Chat Inspection API client.

Thin, dependency-light wrapper around the AI Defense runtime Inspection API,
used to optionally submit user prompts for policy review before the PseudoCo Assistant
recommendation engine calls the model.

Grounded on the published contract:
  - Endpoint : POST {base}/api/v1/inspect/chat
               base = https://{region}.api.inspect.aidefense.security.cisco.com
  - Auth     : X-Cisco-AI-Defense-API-Key: <api key>   (header)
  - Request  : {"messages": [{"role","content"}, ...], "metadata": {}, "config": {}}
  - Response : {"is_safe": bool, "severity": "NONE_SEVERITY|LOW|MEDIUM|HIGH",
                "classifications": ["SECURITY_VIOLATION"|"PRIVACY_VIOLATION"|
                                    "SAFETY_VIOLATION"|"RELEVANCE_VIOLATION"],
                "rules": [{"rule_name","classification","entity_types","rule_id"}],
                "attack_technique": str, "explanation": str, "event_id": str}

References:
  https://developer.cisco.com/docs/ai-defense-inspection/getting-started/
  https://developer.cisco.com/docs/ai-defense-inspection/authentication/
  https://developer.cisco.com/docs/ai-defense-inspection/inspect-conversations/
  https://developer.cisco.com/docs/ai-defense-inspection/inspectresponse/
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import logging

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)


@dataclass
class InspectionResult:
    """Normalized outcome of a Chat Inspection call."""

    is_safe: bool = True
    severity: Optional[str] = None
    classifications: List[str] = field(default_factory=list)
    rule_names: List[str] = field(default_factory=list)
    attack_technique: Optional[str] = None
    explanation: Optional[str] = None
    event_id: Optional[str] = None
    # True when the call could not produce a real verdict (network/HTTP/parse error).
    errored: bool = False
    error_message: Optional[str] = None

    @property
    def should_block(self) -> bool:
        """Whether the prompt must be blocked.

        - A real verdict of is_safe == False always blocks.
        - On error, honor the configured fail-open / fail-closed policy.
        """
        if self.errored:
            return not settings.ai_defense_fail_open
        return not self.is_safe


class AIDefenseError(Exception):
    """Raised for configuration problems (e.g. missing API key)."""


class AIDefenseClient:
    """Synchronous client for the AI Defense Chat Inspection API."""

    def __init__(self) -> None:
        self._url = settings.ai_defense_chat_inspect_url
        self._api_key = settings.ai_defense_api_key
        self._timeout = settings.ai_defense_timeout
        # Whether this connection accepts an explicit config.enabled_rules list.
        # The Inspection API returns HTTP 400 ("This connection already has rules
        # configured...") when the connection (API key) already has an SCC policy
        # bound to it. We probe lazily on the first call and, if rejected, fall
        # back to the UI-configured policy (config: {}) for all subsequent calls
        # so we never pay a wasted round-trip per inspection. The discovery is
        # persisted (settings_store) so restarts don't re-pay the 400+retry;
        # None = not read from the store yet (lazy — this client is constructed
        # at import time, before the DB is guaranteed ready).
        self._enabled_rules_supported: Optional[bool] = None

    def reconfigure(self) -> None:
        """Re-read the settings singleton after a Settings-UI credential change.

        This client is constructed once at import time and snapshots the URL, key
        and timeout, so mutating ``settings.ai_defense_*`` alone would not take
        effect. Called by settings_store.set_integration_creds, and at startup by
        apply_integration_creds_from_store (this client is built before that hook
        overlays the Settings-page creds) — the analog of
        ``llm.clear_caches()`` on the provider path. The enabled_rules probe is
        reset too: a new API key means a different SCC connection, whose policy
        binding may differ from the one we discovered."""
        self._url = settings.ai_defense_chat_inspect_url
        self._api_key = settings.ai_defense_api_key
        self._timeout = settings.ai_defense_timeout
        self._enabled_rules_supported = None

    def _rules_supported(self) -> bool:
        if self._enabled_rules_supported is None:
            try:
                from backend import settings_store

                self._enabled_rules_supported = (
                    settings_store.get_ai_defense_enabled_rules_supported()
                )
            except Exception:  # noqa: BLE001 - never let the store break inspection
                logger.exception("failed to read AI Defense enabled_rules discovery")
                self._enabled_rules_supported = True
        return self._enabled_rules_supported

    @property
    def is_configured(self) -> bool:
        return bool(settings.ai_defense_enabled and self._api_key)

    def inspect_prompt(
        self,
        user_message: str,
        *,
        enduser_id: Optional[str] = None,
        src_app: str = "pseudoco-assistant",
    ) -> InspectionResult:
        """Submit a single user prompt to AI Defense for policy review.

        An empty ``config`` is sent so AI Defense applies the rules/policies
        configured in the UI for the connection that owns this API key.
        """
        return self._inspect(
            [{"role": "user", "content": user_message}],
            enduser_id=enduser_id,
            src_app=src_app,
            stage="prompt",
        )

    def inspect_response(
        self,
        user_message: str,
        assistant_message: str,
        *,
        enduser_id: Optional[str] = None,
        src_app: str = "pseudoco-assistant",
    ) -> InspectionResult:
        """Submit a model response (in conversation context) for policy review.

        The generated output is submitted as the content to inspect so AI
        Defense can evaluate it for leaked PII, toxic content, etc. and return
        a verdict the caller can use to withhold the response.

        NOTE on roles (verified 2026-06-24 against the live connection): the
        bound SCC policy now enforces the *response* direction for the content
        guardrails (PII/PHI/PCI, the Safety rules, Code Detection, …). The
        Inspection API infers direction from message role — a user-role message
        is treated as a prompt, an assistant-role message as a response — so the
        model output is submitted as an assistant-role message (with the
        original user prompt as preceding context) to inspect it on the genuine
        response direction. This is what makes response-only guardrails such as
        Code Detection fire; PII/PHI/PCI and the Safety rules fire on both
        directions, so they remain caught (verified — no regression to the
        force-injection governance demo). An empty config is sent because the
        connection already has the policy bound (an explicit enabled_rules
        override returns HTTP 400). Earlier this was submitted as user-role to
        work around a connection that enforced only the prompt direction; that
        is no longer the case.
        """
        return self._inspect(
            [
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": assistant_message},
            ],
            enduser_id=enduser_id,
            src_app=src_app,
            stage="response",
        )

    def _inspect(
        self,
        messages: List[Dict[str, str]],
        *,
        enduser_id: Optional[str] = None,
        src_app: str = "pseudoco-assistant",
        stage: str = "prompt",
    ) -> InspectionResult:
        """Shared Chat Inspection call for both prompt and response review."""
        if not self.is_configured:
            raise AIDefenseError(
                "AI Defense is not configured (set AI_DEFENSE_ENABLED=True and "
                "AI_DEFENSE_API_KEY)."
            )

        # metadata is optional per the contract; we pass non-sensitive context
        # (caller-supplied user notion + source app + timestamp + stage) to aid
        # triage in the AI Defense Events screen. No secrets are included.
        metadata: Dict[str, Any] = {
            "src_app": src_app,
            "stage": stage,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        if enduser_id:
            metadata["user"] = enduser_id

        # Build the inspection config. When enabled_rules are set, they are passed
        # explicitly so AI Defense applies them directly on this call
        # (self-contained) rather than relying on the SCC-configured policy. The
        # prompt and response directions enforce different rule sets: the response
        # inspection drops prompt-only rules and adds the custom prescription /
        # scope-of-authority guardrail (see config.ai_defense_response_rule_config).
        # An empty list — or a connection that already has an SCC policy bound
        # (see _enabled_rules_supported) — defers to the connection's UI policy.
        rules = (
            settings.ai_defense_response_rule_config
            if stage == "response"
            else settings.ai_defense_rule_config
        )
        send_enabled_rules = bool(rules) and self._rules_supported()
        config: Dict[str, Any] = {"enabled_rules": rules} if send_enabled_rules else {}

        headers = {
            "X-Cisco-AI-Defense-API-Key": self._api_key,
            "Content-Type": "application/json",
            "accept": "application/json",
        }

        result = self._post(messages, metadata, config, headers)

        # If the connection rejects enabled_rules because it already has an SCC
        # policy, remember that and retry once deferring to the UI policy. This
        # keeps the client working on connections both with and without rules.
        if (
            result.errored
            and send_enabled_rules
            and result.error_message
            and "already has rules configured" in result.error_message.lower()
        ):
            logger.info(
                "AI Defense connection has an SCC policy bound; disabling "
                "config.enabled_rules and deferring to the UI-configured policy."
            )
            self._enabled_rules_supported = False
            try:
                from backend import settings_store

                settings_store.set_ai_defense_enabled_rules_supported(False)
            except Exception:  # noqa: BLE001 - persistence is best-effort
                logger.exception("failed to persist AI Defense enabled_rules discovery")
            result = self._post(messages, metadata, {}, headers)

        return result

    def _post(
        self,
        messages: List[Dict[str, str]],
        metadata: Dict[str, Any],
        config: Dict[str, Any],
        headers: Dict[str, str],
    ) -> InspectionResult:
        """Single Chat Inspection HTTP attempt, normalized to InspectionResult."""
        payload = {
            "messages": messages,
            "metadata": metadata,
            "config": config,
        }
        try:
            response = httpx.post(
                self._url,
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            # 400 bad request, 401 unauthorized, 500 etc. carry a {"message": ...} body.
            detail = self._safe_error_detail(exc.response)
            logger.warning(
                "AI Defense inspection HTTP %s: %s",
                exc.response.status_code,
                detail,
            )
            return InspectionResult(
                errored=True,
                error_message=f"HTTP {exc.response.status_code}: {detail}",
            )
        except (httpx.HTTPError, ValueError) as exc:
            # Network/timeout errors and JSON decode errors.
            logger.warning("AI Defense inspection failed: %s", exc)
            return InspectionResult(errored=True, error_message=str(exc))

        return self._parse_response(data)

    @staticmethod
    def _parse_response(data: Dict[str, Any]) -> InspectionResult:
        rules = data.get("rules") or []
        rule_names = [
            r.get("rule_name")
            for r in rules
            if isinstance(r, dict) and r.get("rule_name")
        ]
        return InspectionResult(
            # Default to safe only if the field is explicitly present; treat a
            # missing is_safe as a malformed response (errored) for safety.
            is_safe=bool(data.get("is_safe", True)),
            severity=data.get("severity"),
            classifications=list(data.get("classifications") or []),
            rule_names=rule_names,
            attack_technique=data.get("attack_technique"),
            explanation=data.get("explanation"),
            event_id=data.get("event_id"),
            errored="is_safe" not in data,
            error_message=None if "is_safe" in data else "Malformed response: missing is_safe",
        )

    @staticmethod
    def _safe_error_detail(response: httpx.Response) -> str:
        try:
            body = response.json()
            if isinstance(body, dict) and "message" in body:
                return str(body["message"])
        except ValueError:
            pass
        return response.text[:200]


# Module-level singleton, mirrors other services in this package.
ai_defense_client = AIDefenseClient()
