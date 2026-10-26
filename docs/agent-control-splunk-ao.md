# Agent Control inside Splunk Agent Observability (`splunk_ao` backend)

The **Agent Observability Controls** toggle can now talk to two Agent Control
servers. The default is unchanged: the standalone Galileo console and its
agent-control server, with the two-legged API-key login. The new `splunk_ao`
backend talks to the Agent Control server that Splunk Observability Cloud hosts
inside Agent Observability, at
`https://app.<realm>.observability.splunkcloud.com/ao/agent-control`, so the
controls are authored in the Agent Observability **Controls** UI and attached to
an Agent stream — no Galileo console, no console key.

This is the design Kumar Aamit (Cisco) built on the `kumar-aamit/DemoBot` fork
on 2026-09-23, landed in the shared guardrail chain so it runs on every box and
every blueprint. His fork used the official `agent-control-sdk`; that package
requires Python 3.12 (it uses PEP 695 syntax, so it cannot even import on 3.11),
binds one target per process (this app routes each theme to its own stream) and
only records control spans when the evaluation runs inside an open SDK trace
(this app logs its turns after the fact, on a worker thread). The existing
`httpx` client already speaks the same server contract, so the backend is a mode
of that client instead. Nothing new is installed.

## What runs, and where

| Stage | Node | Position | What it sends |
|---|---|---|---|
| pre | `agent_control_prompt` | PRE chain, right after Cisco AI Defense | `stage=pre`, step `llm`/`complete_chat`, `input` = the user's prompt |
| post | `agent_control` | POST chain, after `compliance`, before AI Defense | `stage=post`, `input` = prompt, `output` = the answer |

Both stages run on `splunk_ao` by default; the galileo backend keeps running the
response stage only (its console controls are post-scoped). Override with
`GALILEO_AGENT_CONTROL_STAGES=pre`, `post` or `pre,post`.

Every request is **bound to the theme's Agent stream** — the same stream the
turn is logged to (`backend/agent_observability._stream_for`: the theme's label,
for example `TelecomChatbot`, or `SPLUNK_AO_AGENT_STREAM` when per-theme streams
are off). The stream's id is looked up once through `/ao/api` and cached. So a
control attached to the `TelecomChatbot` stream governs telecom turns and nothing
else, which is exactly how the UI presents it.

A deny withholds the turn with the same governance contract as every other
guardrail: `policy_blocked`, `guardrail_ids=["galileo_agent_control"]`,
`safety_categories` naming the control, the theme (so the block lands in its
stream), and the blueprint identity. A prompt-stage block reports zero token
usage because no model ran. Non-blocking matches (observe, steer, or a fail-open
error) are attributed on the allowed turn's event without claiming a violation.

Each event also carries `agent_control_verdicts`, one record per stage. The
Agent Observability worker turns those into **control spans** under the turn's
`chat_turn` workflow span — the shield-icon spans the trace view shows and the
stream's Control View counts. One span per matched control, carrying its action;
one `observe` span per clean or errored stage, so an evaluation that ran is
always visible.

### Steer

A response-stage **steer** is applied, not just recorded (since 4.19.0). The
matched controls' steering context — the **Steering context** field in the
Controls UI, `steering_context.message` on the evaluation — goes to a steer
agent (`<theme>_agent_control_steer_agent`, on the internal model under Ollama)
that rewrites the answer to follow it and changes nothing else. The rewrite is
evaluated again before it ships:

- clean — it is the answer the user gets, and NeMo's output rails and Cisco AI
  Defense screen it next;
- deny — the turn is withheld like any other deny;
- still steering — another attempt with the new guidance, up to
  `GALILEO_AGENT_CONTROL_STEER_ATTEMPTS` (default 1), then the last rewrite ships.

Before the re-check, two leftovers of a small rewrite model are removed (since
4.19.1): a heading line such as "Rewritten reply:", and the husk of a record
line whose values it blanked instead of dropping the line (`Customer: |
Rewards #: |`). A line is removed only when it is new in the rewrite, holds
labels and nothing else, and every label comes from a line of the original
answer that held values; the cleanup never adds text.

A rewrite that fails counts as an Agent Control error, so
`GALILEO_AGENT_CONTROL_FAIL_OPEN` decides between the original answer and
withholding it. `GALILEO_AGENT_CONTROL_STEER_ATTEMPTS=0` restores record-only
steers. A prompt-stage steer is recorded only.

The response verdict records the guidance (`steering`) and what happened
(`steer`: `attempts`, `outcome` = `applied` | `unresolved` | `unverified` |
`error` | `no_guidance` | `denied`, and the re-check's controls and decisions);
the control span carries `agent_control_steer_outcome` and
`agent_control_steer_attempts`. The steer agent is an entry in `agent_trace`
and its tokens count toward the turn. The Synthetic Content `*_detected` flags
are re-read from the rewrite, because they describe what was delivered.

## Configuration

```
GALILEO_AGENT_CONTROL_BACKEND=splunk_ao
SPLUNK_AO_REALM=us1                              # already set for trace logging
SPLUNK_AO_CONTROL_TOKEN=<O11y API token>         # blank = reuse SPLUNK_AO_O11Y_API_TOKEN
# SPLUNK_AO_CONTROL_URL=                          # override; default derived from the realm
# SPLUNK_AO_CONTROL_TARGET_TYPE=log_stream        # the default; see below
# SPLUNK_AO_CONTROL_STEP_NAME=complete_chat
# GALILEO_AGENT_CONTROL_STAGES=                   # empty = pre,post on splunk_ao
# GALILEO_AGENT_CONTROL_STEER_ATTEMPTS=1          # rewrites per steer; 0 = record only
```

The same fields are on the Settings page under **Splunk Agent Observability**
and apply live. `AGENT_CONTROL_API_KEY` / `AGENT_CONTROL_CONSOLE_URL` belong to
the galileo backend only; the two backends never share a credential.

**The token.** The gateway authenticates with `X-SF-Token` (verified 2026-09-23;
`Splunk-AO-API-Key` is the on-prem header and answers 401 here). The token has
to be an Observability Cloud access token created as **API token with roles**
carrying the `agent_observability_admin` role. A plain O11y API token reaches
the gateway (`/ao/agent-control/health` answers 200) but every controls call
answers `403 controls.read`, and the stream lookup on `/ao/api` answers 403 too.

**Target type.** `log_stream`, the splunk-ao SDK's own constant, and the
default since 4.12.1. Splunk's how-to (and Kumar's fork) use `agent_stream`, but
the us1 gateway answers every call bound to that type with
`502 AUTH_UPSTREAM_REJECTED` — the controls lookup, the attachment filter and
the runtime-token exchange (verified 2026-09-23). With `log_stream` the same
calls succeed and the exchange mints a runtime token. A 502 of that kind names
the fix in the error message.

**Execution.** Client-side execution (the `client` transport) is not available
on this backend — its evaluators live in the AO org — so author the controls
with **Execution environment: Server**.

## Setting it up

1. Create the token (Settings → Access tokens → API token with roles →
   `agent_observability_admin`) and put it in `SPLUNK_AO_CONTROL_TOKEN`.
2. Set `GALILEO_AGENT_CONTROL_BACKEND=splunk_ao` (or pick it on the Settings
   page). Restart is not needed; the next turn uses it.
3. Log one turn per theme you care about, so the stream exists.
4. In Agent Observability: **Controls → Create new control** (stages pre and/or
   post, execution Server, action Deny/Steer/Observe), then open the Agent
   stream → **Controls** tab → **Add control**. Scope it to step type `llm`,
   step name `complete_chat`.
5. Turn the **Agent Observability Controls** toggle on in the Demo Controls
   drawer and send a prompt the control should catch.

Acceptance probe, no app needed:

```bash
venv/bin/python -c "from backend.services.agent_control import agent_control_client as c; print(c.list_controls(theme='telecomchatbot'))"
```

It resolves the stream, registers the agent for it (the server answers 404
for an agent it has never seen) and returns the effective control set the
server would evaluate. An empty list with no error means no control is attached
to that stream yet; a 403 means the token lacks the role; a
`502 AUTH_UPSTREAM_REJECTED` means the target type is not `log_stream`.

## What changed in the code

- `backend/services/agent_control.py` — `galileo_agent_control_backend`,
  `stages`, `step_name`, `control_url`, `ao_api_url`; stream-id resolution and
  caching through `/ao/api`; `X-SF-Token` auth with the SDK's `auto`-mode
  runtime-token fallback; lazy per-target `initAgent`; `evaluate_prompt` and a
  `stage` argument on `evaluate_response`; `ControlVerdict.record()`.
- `backend/agents/nodes/agent_control.py` — the new `agent_control_prompt_node`
  next to the existing response node; `backend/agents/blueprints/guardrails.py`
  wires it after `prompt_defense`.
- `backend/services/recommendation_engine.py` — `_handle_agent_control_prompt_block`,
  and both Agent Control block events carry `agent_control_verdicts`.
- `backend/agents/nodes/governance.py`, `backend/logging/log_schemas.py` — the
  allowed turn carries both verdicts too.
- `backend/agent_observability.py` — `_add_control_spans` on the turn.
- `backend/settings_store.py`, `.env.example`, `frontend/` — the fields, the
  env block, the stage label and the card copy.
- Tests: `tests/test_agent_control.py` (backend, wire contract, prompt node),
  `tests/test_guardrail_nodes.py` (prompt block banner + stream),
  `tests/test_blueprint_parity.py` (`agent_control_prompt_deny` across every
  blueprint), `tests/test_agent_observability.py` (control spans),
  `tests/test_integration_settings.py`.

Not taken from the fork: the `agent-control-sdk` pins (Python 3.12 only), the
`invoke_chat` wrap (that function only serves the analytics summary; chat turns
use `invoke_agent`), the provider dropdown filter (a SAIF-local change), and the
second AO worker timeout (main already bounds every SDK call).
