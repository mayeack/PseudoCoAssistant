"""Async per-destination HEC forwarder: bounded queue, batching, retry with
exponential backoff, drop-oldest overflow, and live stats.

Ported from ThreatGenerator and adapted for PseudoCo Assistant:
- ``submit(log_type, log_data)`` enqueues a governance/audit dict.
- ``submit`` is thread-safe: ``_write_log`` (the call site) may run on a
  worker thread, so we hop onto the forwarder's event loop via
  ``call_soon_threadsafe`` when needed (asyncio.Queue is not thread-safe).
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.hec.client import HECClient, HECSendResult
from backend.hec.config import (DEFAULT_INDEX, DEFAULT_SOURCE, DEFAULT_SOURCETYPE,
                                HECConfig, effective_host)

logger = logging.getLogger(__name__)

# These correlation ids used to be promoted into the HEC envelope's "fields"
# block as indexed fields, so they'd be searchable via tstats. They are ALSO in
# the event body, and the canonical sourcetype extracts that body at SEARCH time
# (gen_ai:json sets KV_MODE = json) -- so Splunk saw each id twice and returned
# it as a two-value multivalue field.
#
# That silently doubled every `stats ... by enduser_id`: a spray campaign whose
# true total was 260 risk over 5 turns reported 520 over 10. The ES rule
# "AI Governance - Prompt Injection Attack Correlation - Rule" groups by an
# actor coalesced from enduser.id, so its correlation_risk -- and the severity
# derived from it -- were inflated the same way. A bare `| stats count` was
# unaffected; only the `by <field>` form.
#
# Nothing actually used the tstats path, so the body copy wins and these are no
# longer promoted. Do NOT put a key here that also exists in the event body;
# add genuinely forwarder-owned metadata (like log_type) instead. ``user`` (the
# CIM copy of enduser_id, and the signed-in username on identity events) is the
# same actor and must stay body-only for the same reason.
_BODY_OWNED_KEYS = ("session_id", "request_id", "trace_id", "enduser_id", "user")


def _epoch_from(log_data: Dict[str, Any]) -> Optional[float]:
    """Parse the event's ISO ``timestamp`` into epoch seconds, if present."""
    ts = log_data.get("timestamp") if isinstance(log_data, dict) else None
    if not ts:
        return None
    try:
        s = ts.replace("Z", "+00:00") if isinstance(ts, str) else ts
        dt = datetime.fromisoformat(s)
        # Producer timestamps are datetime.utcnow().isoformat() — naive UTC.
        # Naive .timestamp() reinterprets them as LOCAL time, skewing _time by
        # the UTC offset, so pin naive values to UTC before converting.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


@dataclass
class HECStats:
    id: str = ""
    name: str = ""
    enabled: bool = False
    running: bool = False
    token_present: bool = False
    events_sent: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    batches_sent: int = 0
    batches_failed: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    last_success_at: Optional[str] = None
    last_error_at: Optional[str] = None
    last_error: Optional[str] = None
    last_latency_ms: Optional[float] = None


class HECForwarder:
    # Pause before restarting a crashed consumer, so a persistently failing
    # loop cannot spin the event loop.
    _CRASH_BACKOFF_S = 2.0

    def __init__(self, cfg: HECConfig, token: Optional[str]) -> None:
        self._cfg = cfg
        self._token = token or ""
        self._client = HECClient(cfg, token)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, cfg.queue_max))
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = asyncio.Event()
        self._stats = HECStats(
            id=cfg.id, name=cfg.name, enabled=cfg.enabled,
            token_present=bool(token), queue_capacity=max(1, cfg.queue_max),
        )

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if not self._cfg.enabled:
            self._stats.enabled = False
            self._stats.running = False
            return
        if self.running:
            return
        self._loop = asyncio.get_running_loop()
        self._stopping.clear()
        self._task = asyncio.create_task(self._consume_loop())
        self._stats.enabled = True
        self._stats.running = True
        logger.info("hec_forwarder_started id=%s", self._cfg.id)

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            except Exception:
                logger.debug("hec_forwarder_stop_error", exc_info=True)
            self._task = None
        await self._client.close()
        self._stats.running = False
        logger.info("hec_forwarder_stopped id=%s", self._cfg.id)

    # ------------------------------------------------------------------
    # Hot path (thread-safe enqueue)
    # ------------------------------------------------------------------
    def submit(self, log_type: str, log_data: Dict[str, Any]) -> None:
        if not self._cfg.enabled or not self.running or self._loop is None:
            return
        if not isinstance(log_data, dict):
            return
        event = self._build_event(log_type, log_data)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            self._enqueue(event)
        else:
            try:
                self._loop.call_soon_threadsafe(self._enqueue, event)
            except RuntimeError:
                pass

    def _enqueue(self, event: Dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                self._stats.events_dropped += 1
            except asyncio.QueueEmpty:
                pass
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                self._stats.events_dropped += 1

    def _build_event(self, log_type: str, log_data: Dict[str, Any]) -> Dict[str, Any]:
        sourcetype = (self._cfg.sourcetype_map or {}).get(log_type) \
            or self._cfg.sourcetype or DEFAULT_SOURCETYPE
        epoch = _epoch_from(log_data) or time.time()
        event: Dict[str, Any] = {
            "time": round(epoch, 3),
            # HEC_HOST, else the destination's host, else "medadvice".
            "host": effective_host(self._cfg.host),
            "source": self._cfg.source or DEFAULT_SOURCE,
            "sourcetype": sourcetype,
            "index": self._cfg.index or DEFAULT_INDEX,
            "event": log_data,
        }
        # Only forwarder-owned metadata belongs in "fields". Anything also present
        # in the event body is dropped here rather than trusted to review: the
        # duplicate would be indexed AND extracted at search time, and the
        # resulting multivalue field double-counts every `stats ... by <key>`.
        fields: Dict[str, str] = {"log_type": log_type}
        event["fields"] = {k: v for k, v in fields.items()
                           if k not in _BODY_OWNED_KEYS}
        return event

    # ------------------------------------------------------------------
    # Consumer loop
    # ------------------------------------------------------------------
    async def _consume_loop(self) -> None:
        flush_interval = max(0.1, float(self._cfg.flush_interval_s))
        batch_size = max(1, int(self._cfg.batch_size))
        try:
            while not self._stopping.is_set():
                batch: list[dict[str, Any]] = []
                deadline = time.monotonic() + flush_interval
                try:
                    first = await asyncio.wait_for(self._queue.get(), timeout=flush_interval)
                    batch.append(first)
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    continue
                while len(batch) < batch_size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    batch.append(item)
                    self._queue.task_done()
                await self._send_with_retry(batch)
                self._stats.queue_depth = self._queue.qsize()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Do NOT let one unexpected error end forwarding for the process
            # lifetime. This used to exit the loop for good: `running` went
            # False, submit() silently dropped every subsequent event, and the
            # only signal was this single log line plus a flag in
            # /api/hec/stats — Splunk Core simply stopped receiving governance
            # events until someone reconfigured the destination by hand.
            # Back off briefly, then resume consuming.
            logger.exception(
                "hec_forwarder_loop_crashed id=%s — restarting consumer", self._cfg.id
            )
            if not self._stopping.is_set():
                try:
                    await asyncio.sleep(self._CRASH_BACKOFF_S)
                except asyncio.CancelledError:
                    raise
                self._task = asyncio.create_task(self._consume_loop())

    async def _send_with_retry(self, batch: list[dict[str, Any]]) -> None:
        retries = max(0, int(self._cfg.max_retries))
        attempt = 0
        last_result: Optional[HECSendResult] = None
        while attempt <= retries and not self._stopping.is_set():
            result = await self._client.send_batch(batch)
            last_result = result
            if result.ok:
                self._stats.events_sent += len(batch)
                self._stats.batches_sent += 1
                self._stats.last_success_at = datetime.now(timezone.utc).isoformat()
                self._stats.last_latency_ms = round(result.latency_ms, 1)
                return
            retryable = (result.status_code is None
                         or result.status_code >= 500
                         or result.status_code == 429)
            if not retryable or attempt >= retries:
                break
            backoff = min(30.0, (2 ** attempt) * 0.5) + random.uniform(0, 0.25)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=backoff)
                break
            except asyncio.TimeoutError:
                pass
            attempt += 1
        self._stats.events_failed += len(batch)
        self._stats.batches_failed += 1
        self._stats.last_error_at = datetime.now(timezone.utc).isoformat()
        self._stats.last_error = last_result.error if last_result else "unknown error"

    def snapshot_stats(self) -> HECStats:
        self._stats.id = self._cfg.id or self._stats.id
        self._stats.name = self._cfg.name or self._stats.name
        self._stats.queue_depth = self._queue.qsize()
        self._stats.queue_capacity = self._queue.maxsize
        self._stats.running = self.running
        self._stats.enabled = self._cfg.enabled
        self._stats.token_present = bool(self._token)
        return self._stats
