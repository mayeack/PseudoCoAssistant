"""Shared-chain nodes that run the synthetic MCP tool-thrash concurrently with
answer generation, hidden from the user.

Two nodes in the SHARED guardrail chain (blueprints/guardrails.py), so both
blueprints get the behavior by construction (parity) and no blueprint core
changes:

- ``mcp_thrash_launch_node`` — a PRE node. When the "MCP Tool Thrash" Demo
  Control is on and the theme has a profile, it spawns a daemon thread that
  drives the scripted, non-converging tool loop (``services/mcp_thrash.run_thrash``)
  and returns immediately. The thread overlaps the synthesizer's LLM call (the
  30-40 s long pole), so the thrash adds no user-visible latency.
- ``mcp_thrash_join_node`` — a POST node, placed just before ``governance``.
  It joins the thread (bounded) and writes the collected records to
  ``state["tool_thrash_trace"]`` so ``governance_node`` carries them onto the
  turn's governance event, from which ``backend/agent_observability.py`` rebuilds
  them as tool spans on the Agent Observability trace (the ``agent_control_verdicts``
  precedent: work happens in the turn, spans are rebuilt afterward from the event).

Neither node is terminal and neither has a label in ``frontend/js/chat.js``
``STAGE_LABELS``, so the SSE ``stage`` frame they emit changes nothing the user
sees ("Unknown nodes keep the previous label"). The whole feature is therefore
invisible in the chat UI; its only surface is the Agent Observability trace,
which is where Signals reads it.

Thread handoff: a graph node cannot read state a thread writes after the node
returns, so the launch node registers the run in a module-level map keyed by the
turn's ``request_id`` and the join node pops it. The thread is a daemon with a
bounded deadline, so a turn that is blocked in a guardrail (never reaching the
join node) abandons it harmlessly rather than leaking work past the turn.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from backend.agents.themes import get_theme
from backend.services.mcp_thrash import run_thrash

logger = logging.getLogger(__name__)

# Safety bound: the loop stops if it runs this long (it normally finishes in
# ~1.5 s), and the join waits at most this long before logging the turn without
# the thrash. Generous next to generation; a backstop, not a budget.
_DEADLINE_S = 20.0


class _ThrashRun:
    __slots__ = ("thread", "records", "lock")

    def __init__(self) -> None:
        self.thread: Optional[threading.Thread] = None
        self.records: List[Dict[str, Any]] = []
        self.lock = threading.Lock()


_INFLIGHT: Dict[str, _ThrashRun] = {}
_INFLIGHT_LOCK = threading.Lock()


def _enabled() -> bool:
    # Imported lazily: the live setting is the single source of truth (startup
    # applies the persisted toggle over the .env default).
    from backend.config import settings

    return bool(getattr(settings, "mcp_tool_thrash_enabled", False))


def mcp_thrash_launch_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PRE node: start the thrash on a daemon thread, concurrent with the turn."""
    if not _enabled():
        return {}
    profile = get_theme(state.get("theme")).thrash
    if profile is None or not profile.enabled:
        return {}
    request_id = str(state.get("request_id") or "")
    if not request_id:
        return {}
    query = state.get("user_message", "") or ""
    deadline = time.monotonic() + _DEADLINE_S
    run = _ThrashRun()

    def _work() -> None:
        try:
            records = run_thrash(profile, query, deadline=deadline)
        except Exception:  # noqa: BLE001 - a demo fault must never break a turn
            logger.exception("mcp thrash: run failed")
            records = []
        with run.lock:
            run.records = records

    run.thread = threading.Thread(target=_work, name=f"mcp-thrash-{request_id[:8]}", daemon=True)
    with _INFLIGHT_LOCK:
        # A stale entry (prior turn that never reached the join node) is replaced;
        # its daemon thread finishes on its own and is dropped.
        _INFLIGHT[request_id] = run
    run.thread.start()
    return {}


def mcp_thrash_join_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """POST node (before governance): join the thread and hand the records to the
    turn so governance_node carries them to Agent Observability."""
    request_id = str(state.get("request_id") or "")
    with _INFLIGHT_LOCK:
        run = _INFLIGHT.pop(request_id, None)
    if run is None or run.thread is None:
        return {}
    run.thread.join(_DEADLINE_S)
    with run.lock:
        records = list(run.records)
    if run.thread.is_alive():
        # Overran the deadline (should not happen): abandon the daemon thread and
        # log the turn with whatever completed, rather than stall the response.
        logger.warning("mcp thrash: join timed out for request %s; logging %d record(s)",
                       request_id, len(records))
    return {"tool_thrash_trace": records} if records else {}
