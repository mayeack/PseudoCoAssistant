"""Module-level singleton that owns one HECForwarder per configured Splunk
destination and fans governance events out to all enabled forwarders.

Ported from ThreatGenerator. Tokens come from each destination's config
(persisted in the local DB) rather than the OS keychain.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from backend.hec.client import HECClient, HECSendResult
from backend.hec.config import DEFAULT_INDEX, DEFAULT_SOURCE, HECConfig, effective_host
from backend.hec.forwarder import HECForwarder, HECStats

logger = logging.getLogger(__name__)


class HECRuntime:
    def __init__(self) -> None:
        self._destinations: Dict[str, HECConfig] = {}
        self._forwarders: Dict[str, HECForwarder] = {}
        self._lock = asyncio.Lock()

    @property
    def destinations(self) -> List[HECConfig]:
        return list(self._destinations.values())

    def configure(self, cfgs: Optional[Iterable[HECConfig]]) -> None:
        """Record the desired destinations. Lifecycle handled by start/stop."""
        ordered: Dict[str, HECConfig] = {}
        for dest in (cfgs or []):
            if isinstance(dest, HECConfig) and dest.id:
                ordered[dest.id] = dest
        self._destinations = ordered

    async def start(self) -> None:
        async with self._lock:
            for dest_id, cfg in self._destinations.items():
                if not cfg.enabled or dest_id in self._forwarders:
                    continue
                # Isolate each destination: one bad config (e.g. a URL that fails
                # normalization) must not abort startup for the other, healthy
                # forwarders — otherwise a single typo silently kills all HEC output.
                try:
                    fwd = HECForwarder(cfg, cfg.token)
                    await fwd.start()
                    self._forwarders[dest_id] = fwd
                except Exception:
                    logger.exception("hec_forwarder_start_failed id=%s", dest_id)

    async def stop(self) -> None:
        async with self._lock:
            forwarders = list(self._forwarders.items())
            self._forwarders.clear()
        for dest_id, fwd in forwarders:
            try:
                await fwd.stop()
            except Exception:
                logger.exception("hec_forwarder_stop_failed id=%s", dest_id)

    async def reconfigure(self, cfgs: Optional[Iterable[HECConfig]] = None) -> None:
        """Apply a new destination set: stop everything, then start the enabled
        ones with fresh config/tokens. Simple and correct for low volume."""
        if cfgs is not None:
            self.configure(cfgs)
        await self.stop()
        await self.start()

    # ------------------------------------------------------------------
    # Hot path: fan-out submit (non-blocking, thread-safe per forwarder)
    # ------------------------------------------------------------------
    def submit(self, log_type: str, log_data: dict) -> None:
        if not self._forwarders:
            return
        # Snapshot before iterating. This runs on governance worker THREADS while
        # reconfigure()/stop() clear the same dict on the event loop, so
        # iterating it live could raise "dictionary changed size during
        # iteration" — outside the per-item try, so it propagated up to
        # governance_logger's blanket handler and silently dropped that event's
        # entire HEC fan-out.
        for dest_id, fwd in list(self._forwarders.items()):
            try:
                fwd.submit(log_type, log_data)
            except Exception:
                logger.debug("hec_submit_failed id=%s", dest_id, exc_info=True)

    # ------------------------------------------------------------------
    # Stats & test
    # ------------------------------------------------------------------
    def stats(self) -> List[HECStats]:
        out: List[HECStats] = []
        for dest_id, cfg in self._destinations.items():
            fwd = self._forwarders.get(dest_id)
            if fwd is None:
                out.append(HECStats(
                    id=dest_id, name=cfg.name, enabled=bool(cfg.enabled),
                    running=False, token_present=bool(cfg.token),
                    queue_capacity=max(1, int(cfg.queue_max)),
                ))
            else:
                snap = fwd.snapshot_stats()
                snap.id, snap.name = dest_id, cfg.name
                out.append(snap)
        return out

    def stats_for(self, dest_id: str) -> Optional[HECStats]:
        for snap in self.stats():
            if snap.id == dest_id:
                return snap
        return None

    async def test_send(self, cfg: HECConfig) -> HECSendResult:
        """Send a one-off connectivity test event via an ad-hoc client,
        independent of any running forwarder."""
        if not cfg.url:
            return HECSendResult(False, None, 0.0, error="HEC URL not configured")
        if not cfg.token:
            return HECSendResult(False, None, 0.0, error="HEC token not set")
        client = HECClient(cfg, cfg.token)
        try:
            ts = datetime.now(timezone.utc)
            event = {
                "time": round(ts.timestamp(), 3),
                "host": effective_host(cfg.host),
                "source": cfg.source or DEFAULT_SOURCE,
                "sourcetype": cfg.sourcetype or "medadvice:test",
                "index": cfg.index or DEFAULT_INDEX,
                "event": {"message": "PseudoCo Assistant HEC connectivity test",
                          "timestamp": ts.isoformat()},
            }
            return await client.send_batch([event])
        finally:
            await client.close()


hec_runtime = HECRuntime()
