"""PatchBot's Splunk events (TA-patchbot data contract, docs/patchbot.md).

Every PatchBot event goes to ``logs/patchbot.jsonl`` and, when
``PATCHBOT_HEC_URL`` and ``PATCHBOT_HEC_TOKEN`` are set, to its OWN HEC
forwarder: index ``PATCHBOT_HEC_INDEX`` (default ``patchbot``), source
``pseudoco-assistant:patchbot``, sourcetype ``pseudoco:patchbot:<kind>``.
It never uses the governance destinations, so PatchBot never changes what the
AI Governance TA counts in gen_ai_log.

``emit`` is thread-safe and never raises: telemetry must not break a patch.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from backend.config import settings
from backend.hec.config import HECConfig, effective_host
from backend.hec.forwarder import HECForwarder

logger = logging.getLogger(__name__)

KINDS = ("vuln", "finding", "change", "patch", "tool", "session", "estate", "mcp_scan")
SOURCE = "pseudoco-assistant:patchbot"
SOURCETYPES = {k: f"pseudoco:patchbot:{k}" for k in KINDS}

_lock = threading.Lock()
_forwarder: Optional[HECForwarder] = None
_counts: Dict[str, int] = {k: 0 for k in KINDS}
_last_error: Optional[str] = None


def _log_path() -> Path:
    base = Path("logs")
    try:
        # The governance file handler's directory (Settings > logs directory).
        from backend.logging.governance_logger import governance_logger
        base = Path(getattr(getattr(governance_logger, "file_handler", None), "logs_dir", None) or "logs")
    except Exception:  # noqa: BLE001
        pass
    base.mkdir(parents=True, exist_ok=True)
    return base / "patchbot.jsonl"


def hec_configured() -> bool:
    return bool((settings.patchbot_hec_url or "").strip() and (settings.patchbot_hec_token or "").strip())


def _config() -> HECConfig:
    return HECConfig(
        id="patchbot", name="PatchBot", enabled=True,
        url=settings.patchbot_hec_url.strip(), token=settings.patchbot_hec_token.strip(),
        verify_tls=bool(settings.patchbot_hec_verify_tls),
        index=(settings.patchbot_hec_index or "patchbot").strip(),
        source=SOURCE, sourcetype=SOURCETYPES["tool"], host=effective_host(""),
        sourcetype_map=dict(SOURCETYPES), batch_size=50, flush_interval_s=1.0,
    )


async def start() -> None:
    """Start the PatchBot forwarder on the running event loop (main.py startup)."""
    global _forwarder
    if not settings.patchbot_enabled or not hec_configured() or _forwarder is not None:
        return
    try:
        fwd = HECForwarder(_config(), settings.patchbot_hec_token.strip())
        await fwd.start()
        _forwarder = fwd
        logger.info("PatchBot HEC forwarder started (index=%s)", settings.patchbot_hec_index)
    except Exception:  # noqa: BLE001
        logger.exception("PatchBot HEC forwarder failed to start")


async def stop() -> None:
    global _forwarder
    fwd, _forwarder = _forwarder, None
    if fwd is not None:
        try:
            await fwd.stop()
        except Exception:  # noqa: BLE001
            logger.debug("PatchBot HEC forwarder stop failed", exc_info=True)


def emit(kind: str, event_type: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Write one PatchBot event; returns the event body (tests read it)."""
    global _last_error
    if kind not in KINDS:
        raise ValueError(f"unknown PatchBot event kind {kind!r}")
    body: Dict[str, Any] = {
        "event_type": event_type,
        "app": "pseudoco-assistant",
        "feature": "patchbot",
        "estate_owner": "",
        "patchbot_session_id": "",
        "investigation_id": "",
        "finding_id": "",
    }
    body.update({k: v for k, v in (fields or {}).items() if v is not None})
    body["timestamp"] = time.time()
    try:
        line = json.dumps({"sourcetype": SOURCETYPES[kind], **body}, default=str)
        with _lock:
            with open(_log_path(), "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            _counts[kind] += 1
    except Exception as exc:  # noqa: BLE001
        _last_error = str(exc)[:200]
        logger.debug("PatchBot jsonl write failed", exc_info=True)
    fwd = _forwarder
    if fwd is not None:
        try:
            fwd.submit(kind, body)
        except Exception as exc:  # noqa: BLE001
            _last_error = str(exc)[:200]
            logger.debug("PatchBot HEC submit failed", exc_info=True)
    return body


def status() -> Dict[str, Any]:
    fwd = _forwarder
    stats = None
    if fwd is not None:
        try:
            s = fwd.snapshot_stats()
            stats = {"sent": getattr(s, "events_sent", None), "dropped": getattr(s, "events_dropped", None),
                     "last_error": getattr(s, "last_error", None)}
        except Exception:  # noqa: BLE001
            stats = None
    return {"hec_configured": hec_configured(), "hec_running": bool(fwd and fwd.running),
            "index": settings.patchbot_hec_index, "events_written": dict(_counts),
            "forwarder": stats, "last_error": _last_error}
