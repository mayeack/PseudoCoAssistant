# MCP Tool Thrash (hidden agent fault for Agent Observability Signals)

A demo fault that makes every chat turn **thrash between tool calls** on a
synthetic MCP server — a loop of redundant `lookup` → `refine` → `lookup` →
`refine` … calls that never converges on an answer. The behavior is **hidden
from the chat user** (the answer text and the visible pipeline stages are
unchanged) and is designed to be **detected by Splunk Agent Observability
Signals**, the LLM that mines an agent stream's traces for recurring failure
patterns.

It ships as a server-side **Demo Controls** toggle, **MCP Tool Thrash**, in the
*Agent Pipeline* group — off by default.

## What the audience sees vs. what Signals sees

| Surface | With the toggle on |
| --- | --- |
| Chat answer | Unchanged — the real agent still answers normally. |
| Pipeline stage chips | Unchanged — the two thrash nodes have no label, so the UI ignores their SSE frames. |
| Governance Logs page / SQLite | Unchanged — the thrash is **not** a DB column (AO-only, like `agent_trace`). |
| Agent Observability trace | A `mcp_tool_broker` agent span wrapping ~10 tool spans — `lookup`/`refine`/`cross_check` — each reporting "ambiguous, refine" / "conflicts, re-run", none converging. |
| Agent Observability **Signals** | A recurring *tool-thrash / no-convergence* pattern across the theme's stream. |

## How it works

The thrash rides the **shared guardrail chain** so both blueprint cores
(`pseudoco_multi_agent`, `nvidia_virtual_assistant`) get it identically — no core
changes (`backend/agents/blueprints/guardrails.py`):

1. **`mcp_thrash_launch`** (last PRE node) — if the toggle is on and the theme
   has a profile, it spawns a **daemon thread** that drives the scripted loop
   against the in-process `SyntheticMcpServer` and returns immediately. The
   thread overlaps the synthesizer's 30–40 s LLM call, so the thrash adds **no
   user-visible latency**.
2. **`mcp_thrash_join`** (POST node, just before `governance`) — joins the
   thread (bounded) and writes the collected records to
   `state["tool_thrash_trace"]`.
3. **`governance_node`** carries the records onto the turn's governance event
   (`tool_thrash`), exactly as it carries `agent_control_verdicts`.
4. **`agent_observability._add_tool_spans`** rebuilds them as tool spans under a
   dedicated `mcp_tool_broker` agent span on the turn's `chat_turn` trace — in
   the **theme's own Agent stream**, where Signals runs.

Neither thrash node is terminal and neither has a label in
`frontend/js/chat.js` `STAGE_LABELS`, so the SSE `stage` frame they emit changes
nothing the user sees ("Unknown nodes keep the previous label").

### Why the SDK-rebuild path, not live `execute_tool` spans

The tool spans are rebuilt afterward from the governance event (the
`agent_control_verdicts` precedent), **not** emitted as live `otel.tool_span`
`execute_tool` spans during the turn. That keeps them:

- in the **per-theme** Agent stream and **inside the same trace** as the real
  turn (the collector overlay would pin raw `execute_tool` spans to the single
  default stream and a different trace id), and
- **out of** the OTel collector and Splunk APM entirely — so no `execute_tool`
  dashboard or detector is polluted and there is no double-count.

## Per-theme verticalization

Each theme carries its own `McpThrashProfile` on `ThemeConfig.thrash`
(`backend/services/mcp_thrash.py`), like `SchedulingProfile` — its own synthetic
server name, entity and tool set, so the thrash reads like that vertical's own
agent fumbling its backend. A theme that defines none falls back to
`DEFAULT_THRASH`; never branch on the theme key in the nodes.

| Theme | Synthetic MCP server | Entity (tools: `<entity>.lookup` / `.refine` / `.cross_check`) |
| --- | --- | --- |
| medadvice | `patient-records-mcp` | `patient_record` |
| taxadvice | `tax-filing-mcp` | `tax_return` |
| benefitsadvice | `benefits-enrollment-mcp` | `benefits_case` |
| legaladvice | `case-law-mcp` | `case_file` |
| financeadvice | `portfolio-mcp` | `portfolio_record` |
| telecomchatbot | `subscriber-crm-mcp` | `subscriber_account` |
| retail | `order-management-mcp` | `order` |
| manufacturing | `mes-mcp` | `work_order` |

The tool names are deliberately distinct from the real tool-guard surface
(`schedule_appointment`, `retrieve_knowledge`, `execute_tool`) so no Splunk
dashboard or detector keyed on those strings picks these up.

## The toggle

- **Server-side, persisted** (`settings_store` `mcp_tool_thrash`), like NemoClaw
  Guardrails: it applies to **every** chat turn from **every** client, and the
  posture survives a restart.
- Turn it on from the chat page's **Demo Controls → Agent Pipeline → MCP Tool
  Thrash**, or `PUT /api/settings/mcp-thrash {"enabled": true}`.
- Hiding the card from the Settings panel does **not** stop it (server-side
  toggles keep running while hidden) — the toggle is the only off switch.

## Files

- `backend/services/mcp_thrash.py` — the synthetic MCP server, the
  `McpThrashProfile` dataclass, `run_thrash`, and `build_profile`.
- `backend/agents/nodes/mcp_thrash.py` — the launch/join shared-chain nodes.
- `backend/agents/blueprints/guardrails.py` — wires the two nodes into
  `PRE_NODES` / `POST_NODES`.
- `backend/agents/state.py` — the `tool_thrash_trace` state key.
- `backend/agents/themes/*.py` + `themes/base.py` — the per-theme profiles.
- `backend/agents/nodes/governance.py`, `backend/logging/log_schemas.py` — carry
  `tool_thrash` onto the governance event.
- `backend/agent_observability.py` — `_add_tool_spans` rebuilds the trace.
- Toggle: `backend/config.py`, `backend/settings_store.py`, `backend/main.py`,
  `backend/routers/settings.py`, `frontend/index.html`, `frontend/js/chat.js`.
- Tests: `tests/test_demo_controls.py`, `tests/test_blueprint_parity.py`
  (`mcp_thrash` scenario), `tests/test_agent_observability.py`.
