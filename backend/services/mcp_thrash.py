"""A synthetic, in-process MCP server and a scripted non-converging tool loop.

This is a *demo fault*: when the "MCP Tool Thrash" Demo Control is on, every chat
turn drives a short, deterministic sequence of redundant tool calls against the
in-process :class:`SyntheticMcpServer` below — ``lookup`` -> ``refine`` ->
``lookup`` -> ``refine`` ... — that never converges on an answer. The loop is
hidden from the chat user (it changes neither the answer text nor the visible SSE
stage frames); its only visible surface is the Agent Observability trace, where
each call is rebuilt as a tool span under the turn's ``chat_turn`` workflow
(``backend/agent_observability.py``). The point is that Splunk Agent Observability
**Signals** — the LLM that mines an agent stream for recurring failure patterns —
detects the oscillating-tool-call / no-convergence pattern from those spans.

Deliberately NOT a real MCP transport: the ``mcp`` / ``fastmcp`` packages are not
a dependency, and the behavior we want to surface is the *tool-thrash shape*, not
a network round-trip. ``SyntheticMcpServer`` mirrors the MCP tool surface
(``list_tools`` / ``call_tool`` returning ``{isError, content}``) over canned,
non-converging results, with a small synthetic per-call latency so the trace
waterfall shows real wall time.

Per-theme verticalization, exactly like ``SchedulingProfile`` (docs/scheduling.md):
each theme carries its own :class:`McpThrashProfile` on ``ThemeConfig.thrash`` —
its own synthetic server name, entity, tool set and oscillation script — so the
thrash reads like that vertical's own agent fumbling its backend. A theme that
defines none falls back to :data:`DEFAULT_THRASH`; never branch on the theme key
here.

Names are kept distinct from the real tool-guard surface (``execute_tool`` spans,
``schedule_appointment`` / ``retrieve_knowledge``) so no Splunk dashboard or
detector keyed on those strings picks these up: the tool names are
``<entity>.lookup`` / ``<entity>.refine`` / ``<entity>.cross_check`` and the spans
ride the Agent Observability SDK path only (they never become live ``gen_ai``
spans, so they reach neither the OTel collector nor Splunk APM).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Keep per-record text small: the trace rides on the governance event, which also
# fans out to HEC and the on-disk JSON. Enough to read the thrash, not enough to
# bloat every chat event.
_MAX_TEXT = 180


def _trunc(text: str) -> str:
    text = str(text or "")
    return text if len(text) <= _MAX_TEXT else text[: _MAX_TEXT - 1] + "…"


@dataclass(frozen=True)
class McpTool:
    """One tool the synthetic MCP server exposes. ``result`` is the canned,
    deliberately non-converging reply (it always points the caller at another
    call); ``{entity}`` / ``{query}`` / ``{iteration}`` are filled at call time."""

    name: str
    summary: str
    result: str


@dataclass(frozen=True)
class McpThrashProfile:
    """One theme's synthetic MCP server + scripted thrash. Frozen with tuple
    fields so it can live on the frozen ``ThemeConfig`` (like ``SchedulingProfile``).

    ``script`` is the order of tool calls, by tool name, that the loop makes —
    an oscillation that never resolves (lookup -> refine -> lookup -> ...). The
    runner fabricates each call's arguments; the server returns ``tool.result``.
    """

    server_name: str = "reference-directory-mcp"
    entity: str = "record"
    tools: Tuple[McpTool, ...] = field(default_factory=tuple)
    script: Tuple[str, ...] = field(default_factory=tuple)
    # Synthetic latency per call, so the trace shows real (overlapping) wall time.
    step_latency_ms: int = 140

    @property
    def enabled(self) -> bool:
        """A usable profile needs at least one tool and a non-empty script."""
        return bool(self.tools) and bool(self.script)


class SyntheticMcpServer:
    """In-process stand-in for an MCP server: a fixed tool set over canned,
    non-converging results. No I/O, no network — ``call_tool`` sleeps the
    profile's synthetic latency and returns the tool's templated ``result``."""

    def __init__(self, profile: McpThrashProfile) -> None:
        self._profile = profile
        self._tools: Dict[str, McpTool] = {t.name: t for t in profile.tools}

    def list_tools(self) -> List[Dict[str, str]]:
        return [{"name": t.name, "description": t.summary} for t in self._profile.tools]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tool = self._tools.get(name)
        if tool is None:
            return {"isError": True, "content": f"unknown tool: {name}"}
        if self._profile.step_latency_ms > 0:
            time.sleep(self._profile.step_latency_ms / 1000.0)
        values = {
            "entity": self._profile.entity,
            "query": arguments.get("query", ""),
            "iteration": arguments.get("iteration", 0),
            "hint": arguments.get("hint", ""),
        }
        try:
            content = tool.result.format(**values)
        except Exception:  # noqa: BLE001 - a malformed template must not break the turn
            content = tool.result
        return {"isError": False, "content": content}


def run_thrash(
    profile: McpThrashProfile,
    query: str,
    *,
    deadline: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Drive the scripted, non-converging tool loop and return one record per call.

    Each record: ``{name, call_id, arguments, output, status, duration_ms, step,
    iteration, converged}``. ``converged`` is always ``False`` — that is the
    pattern Signals is meant to find. ``deadline`` (``time.monotonic`` seconds) is
    a safety bound; the loop stops early if it is passed. Never raises."""
    if not profile.enabled:
        return []
    server = SyntheticMcpServer(profile)
    records: List[Dict[str, Any]] = []
    tool_names = {t.name for t in profile.tools}
    for step, name in enumerate(profile.script):
        if deadline is not None and time.monotonic() > deadline:
            logger.debug("mcp thrash: deadline passed at step %d", step)
            break
        if name not in tool_names:
            continue
        iteration = step // 2
        arguments = {
            "query": _trunc(query),
            "iteration": iteration,
            "hint": _refine_hint(name, step),
        }
        started = time.perf_counter()
        result = server.call_tool(name, arguments)
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        records.append({
            "name": name,
            "call_id": f"mcp-thrash-{step}",
            "arguments": _trunc(_fmt_args(arguments)),
            "output": _trunc(result.get("content", "")),
            "status": "error" if result.get("isError") else "ok",
            "duration_ms": duration_ms,
            "step": step,
            "iteration": iteration,
            "converged": False,
            # The agent's (scripted) thought that led to THIS call — the
            # floundering narrative the Agent Observability trace rebuilds as an
            # LLM reasoning span, so Signals reads a tool loop that never
            # converges (not just a row of tool calls). See _reasoning().
            "reasoning": _reasoning(profile.entity, name, step, len(profile.script)),
        })
    return records


def abandonment_text(entity: str, n: int) -> str:
    """The agent's final (scripted) give-up thought, used as the output of the
    closing reasoning span and of the abandoned broker span."""
    return (f"I have called the {entity} tools {n} times — looking up and refining over and over — "
            f"and the results keep conflicting with each other. I am going in circles and making no "
            f"progress, so I am abandoning the {entity} lookup without a resolved result.")


def _reasoning(entity: str, name: str, step: int, total: int) -> str:
    """One scripted 'agent thought' before a tool call. Escalates from a normal
    first lookup to visibly circular, no-progress retries — the wording Signals
    clusters into a tool-loop / non-convergence failure."""
    attempt = step // 2 + 1
    if step == 0:
        return (f"I need the caller's {entity} before I can answer safely. "
                f"Calling {name} to retrieve it.")
    if name.endswith(".lookup"):
        return (f"The refinement conflicted with the earlier candidate {entity}s (attempt {attempt}). "
                f"I cannot reconcile them, so I am re-running the lookup from scratch — again.")
    if name.endswith(".refine"):
        return (f"{name} returned 7 ambiguous candidate {entity}s at confidence 0.31 (attempt {attempt}) — "
                f"too many to trust. Refining the query to narrow the set, like the last few attempts.")
    if name.endswith(".cross_check"):
        return (f"I still cannot settle on one {entity} after {attempt} rounds of lookup and refine. "
                f"Cross-checking the leading candidate against the system of record before I give up.")
    return f"Retrying {name} on the {entity} (attempt {attempt}); still no convergence."


def _fmt_args(arguments: Dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in arguments.items() if v != "")


def _refine_hint(name: str, step: int) -> str:
    """A changing-but-never-resolving hint, so successive calls look like real
    (failed) refinement attempts rather than identical retries."""
    if name.endswith(".refine"):
        return f"narrow-candidate-set-pass-{step // 2 + 1}"
    if name.endswith(".cross_check"):
        return f"reconcile-conflict-{step // 2 + 1}"
    return f"broaden-match-pass-{step // 2 + 1}"


# ---------------------------------------------------------------------------
# Default profile (themes without their own) + a small builder for the shipped
# themes. The script is the oscillation the demo narrates: look up the entity,
# be told it is ambiguous, refine, be told the refinement conflicts, look up
# again — around and around, never converging.
# ---------------------------------------------------------------------------
def build_profile(server_name: str, entity: str, *, latency_ms: int = 140) -> McpThrashProfile:
    """One theme's profile from its vertical nouns. The tool set and the
    non-converging result copy are shared; only the server name + entity change,
    so a new theme is one line and never a new code path."""
    lookup = f"{entity}.lookup"
    refine = f"{entity}.refine"
    cross = f"{entity}.cross_check"
    tools = (
        McpTool(
            name=lookup,
            summary=f"Look up the {entity} that matches the user's request.",
            result=("Ambiguous: 7 candidate {entity}s match '{query}'. "
                    "Confidence 0.31 — refine before using."),
        ),
        McpTool(
            name=refine,
            summary=f"Refine the candidate {entity} set with an added filter.",
            result=("Narrowed to 4 candidates ({hint}), but the filter conflicts "
                    "with the prior result — re-run the lookup."),
        ),
        McpTool(
            name=cross,
            summary=f"Cross-check the leading {entity} against the system of record.",
            result=("System of record disagrees on 2 fields ({hint}); "
                    "cannot confirm — look the {entity} up again."),
        ),
    )
    # 10 calls: lookup/refine oscillation with a cross-check that sends it back,
    # never resolving — a clear recurring pattern for Signals.
    script = (lookup, refine, lookup, refine, cross, lookup, refine, lookup, refine, cross)
    return McpThrashProfile(server_name=server_name, entity=entity, tools=tools,
                            script=script, step_latency_ms=latency_ms)


DEFAULT_THRASH = build_profile("reference-directory-mcp", "record")
