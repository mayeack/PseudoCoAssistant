# Project Napkin — medadvice_v3

Curated, high-value runbook. Read before work; keep only recurring guidance.

## Testing — keep regressions in sync
- **Every material change updates its regression test in the same change** — new
  behavior, bug fix, or integration change. Don't just run tests; extend them so
  the new/fixed behavior is asserted and a future regression fails loudly.
  Observability → `tests/observability/` (run via `verify_observability.sh`).
- **API surface → `tests/test_api.py`** (`venv/bin/python tests/test_api.py`): a
  standalone TestClient suite over `backend.main:app` asserting auth gating (401
  w/o key), happy-path contracts, and validation (422) for every endpoint. It's
  side-effect-safe (LLM boundary + auto-prompter stubbed; incident `drive_traffic`
  false) so it makes no real Anthropic call / load / emission. **Needs httpx
  0.27.x** — httpx 0.28 dropped the `app=` shortcut that Starlette 0.35's
  TestClient uses (pinned in `requirements.txt`; the app itself never used `app=`).
- **Flag breaking/behavior changes to the user.** When a change alters an existing
  endpoint, response field, feature, or telemetry contract — or bumps a dependency
  in a way that changes runtime behavior — say so by name in that turn; never let
  it pass silently. `test_api.py` + `verify_observability.sh` are the detectors.
- **Anything asserting an injection DIRECTIVE must pin `settings.ai_provider`.**
  `build_input_directives` emits labeled `* SAMPLE:` text for censored providers
  but natural UNLABELED asks for ollama (and routes hallucination + authority into
  the JSON answer contract instead of an appended block). Five `test_api.py`
  checks silently asserted only the labeled markers, so the suite was RED in the
  shipped `.env` config (ollama) and nobody noticed. It now pins the provider per
  block and asserts both builders.
- **Other standalone suites:** `test_guardrail_nodes.py` (safety / policy /
  compliance / prompt+response defense / intake driven directly with a synthetic
  state — AI Defense stubbed, no network; catches a guardrail that silently
  no-ops, which the stream stage-name checks cannot) and `test_db_integrity.py`
  (per-session SQLite connections, JSON-column persistence, escalation-reason
  isolation, JSONL write serialization — runs against a temp DB, never
  `medadvice.db`).
- **[2026-09-21] Suites that drive the real governance logger write to the live box.**
  `test_guardrail_nodes.py` & co. append `S-guardrail` events to `logs/ai_governance.json` +
  `medadvice.db`, and a DIRECT run (`venv/bin/python tests/X.py`) loads `.env`, which enables
  Agent Observability export. Do instead: `export LOG_TO_FILE=false LOG_TO_DATABASE=false`
  (env beats `.env`) and run through `tests/run_all.sh` (sets `SPLUNK_AO_LOGGING_DISABLED=1`);
  a suite that emits blocked turns sets that default itself, like `test_guardrail_nodes.py`.
- **`test_api.py` writes to the LIVE `./medadvice.db`.** Its settings PUTs persist
  to the same AppSettings row the launchd app reads; it now snapshots and restores
  `logs_directory` + emit-model. Any new check that mutates persisted settings
  must do the same, or it silently reconfigures the running demo.

## Observability (Splunk O11y) — CRITICAL
- **After ANY change to the observability integration, run
  `./tests/observability/verify_observability.sh`** (the `verify-observability`
  skill lists the file triggers). It catches the #1 incident: a dead local
  collector silently dropping all telemetry.
- Pipeline = app (OTLP :4317) → local collector (`./run-collector.sh`) → Splunk
  us1. **Both the app AND the collector must be running.** The collector dies when
  the laptop sleeps; the app keeps generating telemetry but every export fails
  `StatusCode.UNAVAILABLE`. Fix = `./run-collector.sh` (restarting the app alone
  does nothing).
- GenAI Agent + LLM telemetry is emitted by the app via the **opentelemetry-util-genai
  TelemetryHandler** — `genai_agent_invocation` / `genai_llm_invocation` in
  `backend/telemetry/otel.py`, wired into `invoke_agent` / `invoke_chat` in
  `backend/agents/llm.py`. This is what puts the named agent in O11y's "AI agents"
  view and reports the real model. Don't revert to raw spans or the old manual
  token metric (`record_genai_tokens`, removed — it would double-count). The buggy
  auto LangChain instrumentor is disabled (`OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=langchain`
  in `run.sh`) so it can't double-emit with `model=unknown`.
- **The "AI trace data" span LIST view needs span CONTENT, not just gen_ai metadata.**
  It's indexed by `gen_ai.input.messages`/`gen_ai.output.messages` (captured via
  `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY`). `invoke_chat`/
  `invoke_agent` pass `system`+`messages` to `genai_*_invocation` and call
  `otel.record_genai_output(...)` to attach them — drop that and spans still reach
  APM (visible in **APM → Trace view / Agent flow**) but the AI-trace-data list is
  EMPTY. Metrics-only checks pass anyway (`spans.count` only tracks SERVER entry
  spans, so it can't even see the gen_ai CLIENT spans). Guard:
  `tests/observability/test_genai_span_content.py` (verify_observability.sh Tier 0);
  confirm via Trace view, not metrics.
- Cost KPI shows **$0** because Splunk's server-side pricing lookup doesn't include
  the current Claude models (all Claude usage prices to $0 in this org; older priced
  Claude IDs like `claude-3-5-sonnet` are deprecated/404 with our key). Not a bug —
  it auto-populates if/when Splunk prices `claude-sonnet-4-5`. OpenAI models *are*
  priced in this org.

## Executive governance overlay (Section 0 dashboard) — additive contract
- Every governance event carries a flat **executive overlay** derived in
  `backend/logging/executive_fields.py` (`derive_executive_fields`), called from
  `create_governance_log` (`log_schemas.py`) right before the None-strip. Fields:
  `app_name, user_type, risk_score(0-100), policy_action(allow|warn|flag|block),
  policy_name, model_name, agent_name, tool_name, prompt_category, contains_pii,
  contains_phi, hallucination_score, groundedness_score, latency_ms, token_count,
  estimated_cost, business_outcome, human_escalation, audit_status`.
  Do instead: it's **additive/non-breaking** — never rename existing
  `gen_ai.*`/governance fields (Splunk props alias them). Inputs come from
  `governance_node`/`policy.py` passing `severity/theme/agent_name/workflow_name/
  hallucination_*`. Regression: `venv/bin/python tests/test_executive_fields.py`.
- **Blocked turns have no `response.model` to echo** — use
  `governance_logger.active_response_model()` (never `settings.anthropic_model`,
  the old bug: on Ollama every blocked event read as a Claude turn, and
  `executive_fields`/Agent Observability both prefer `response_model` over `request_model`,
  so the wrong value won). Response-side blocks *do* have a real model + token
  usage — pass `llm_model`/`usage_data` (`nodes/defense.py`) or they report
  zeros. Regression: `venv/bin/python tests/test_provider_setting.py`.
- `estimated_cost` is an app-side estimate (Splunk prices Claude to $0); price map
  is in `executive_fields._PRICES_PER_MTOK`. Real `hallucination_score`/
  `groundedness_score` come from Splunk GenAI Scoring (`gen_ai_log` sourcetype
  `genai_scoring`) + Agent Observability, not the app — overlay passes them through if present.
- Demo seeder: `scripts/demo/seed_governance_scenarios.py` (10 safe-synthetic
  scenarios via `/api/chat`; needs app running + `ACCESS_KEY`).

## Splunk Agent Observability — second telemetry destination (splunk-ao SDK, 4.9.0)
- Two paths, both **no-op without `SPLUNK_AO_O11Y_TOKEN` + `SPLUNK_AO_REALM`** (an
  O11y INGEST token; explicit, no fallback to O11Y_INGEST): (1) the OTel Collector
  fans gen_ai spans through **`otel-collector-agent-obs.yaml`** (`otlphttp/agent_obs`
  → `ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp`, headers
  `X-SF-Token`/`project`/`logstream`), an OVERLAY `run-collector.sh` layers on with a
  second `--config` only when the token is set. Validate without emitting:
  `./scripts/validate-collector-config.sh` (base, then base+overlay). (2) a per-turn
  SDK trace with governance metadata from `backend/agent_observability.py`, fanned
  out from `governance_logger._write_log`. Expected app log lines:
  `agent observability: logger ready (realm=us1, project=PseudoCo Assistant, agent_stream=<theme label>)`
  once per theme, then `agent observability: logged turn (model=…, agents=N, project=PseudoCo Assistant,
  agent_stream=TelecomChatbot, export=healthy)` per turn. `export=unknown` = the POST was never
  acknowledged and the turn is usually LOST (no retry on a read timeout; an 8 s `ReadTimeout` to
  ingest.us1 dropped one on 2026-09-21) — the cause is the `opentelemetry.sdk._shared_internal`
  ERROR just above it.
- **[2026-09-21] The Agent stream comes from the governance event's `theme`**
  (`_stream_for`: registry label, `telecomchatbot` → `TelecomChatbot`; no/unknown theme →
  `SPLUNK_AO_AGENT_STREAM`, "PseudoCo Assistant" here). The AI Defense / Agent Control block
  handlers used `theme` only for the banner, so every blocked turn silently landed in the
  fallback stream. Do instead: every chat-turn `log_response` passes `theme`; guard = the
  "blocked turns keep their theme" section of `tests/test_guardrail_nodes.py`. The legacy
  engine's own policy-block / answer events (`process_message`, `_generate_recommendation`)
  still omit it (engine off by default).
- Env contract: `SPLUNK_AO_REALM` / `SPLUNK_AO_O11Y_TOKEN` / `SPLUNK_AO_PROJECT` /
  `SPLUNK_AO_AGENT_STREAM` ("Agent stream" is the user-visible name; the wire header
  is still `logstream` because that is what the SDK sends). Project + stream are
  created on first ingest — an empty listing before the first turn is normal.
- **SDK bridge gotcha:** the SDK still honors `GALILEO_PROJECT`/`GALILEO_LOG_STREAM`
  (and `SplunkAOConfig.reset()` pops every `GALILEO_*` key), and `backend/config.py`
  loads every `.env` key into `os.environ` — so stale GALILEO_* lines in `.env`
  silently override SPLUNK_AO_*. Delete them; `.env.bak.splunk-ao.<stamp>` holds the
  pre-migration copy. Never call `SplunkAOConfig.reset()` from the app.
- **One logger per process, on a worker thread** (`backend/agent_observability.py`):
  the SDK logger is not thread-safe, every instance owns a BatchSpanProcessor thread
  + atexit hooks, and `splunk_ao_context.get_logger_instance()` caches per THREAD
  NAME — a per-turn thread would mint a logger every turn. The SDK never exports the
  trace envelope: the `chat_turn` workflow span is the root that lands, so metadata
  rides on the spans and `created_at`/`duration_ns` are back-dated per span.
- Settings card: SPLUNK_AO_* fields are `env_file=True, restart="collector"` — the
  SDK path applies live (os.environ + `agent_observability.reconfigure()`), the
  collector needs a restart (.env). Regression: `venv/bin/python tests/test_agent_observability.py`.
- **Sessions need an API token:** `start_session` goes through `/ao/api` (CRUD), which
  rejects the INGEST token (401) and this box's read-only `O11Y_API` token (403 —
  verified 2026-09-08). The app warns once, backs off 5 min and logs turns
  sessionless; set `SPLUNK_AO_O11Y_API_TOKEN` (an O11y API token with Agent
  Observability access) to get per-conversation sessions. Trace ingest is unaffected.
- Console: https://app.us1.signalfx.com/#/agent-obs → project PseudoCo Assistant → one Agent
  stream per theme (MedAdvice, TelecomChatbot, …; PseudoCo Assistant is the fallback). API (`X-SF-Token`, needs an API token with AO access — not the ingest token):
  `/ao/api/projects?project_name=…&type=gen_ai`, `/ao/api/v2/projects/<id>/log_streams`,
  `/ao/api/v2/projects/<id>/traces/search`.
- Legacy: `scripts/demo/galileo_*.py`, `tests/test_galileo_experiment.py` and the
  `galileo==2.3.0` pin still target the standalone Galileo console with
  `GALILEO_API_KEY`/`GALILEO_PROJECT` (export them for a run; not in .env anymore).
- **CA gotcha (unchanged):** the SDK's httpx/requests need the corp CA (`SSL_CERT_FILE`
  / `REQUESTS_CA_BUNDLE` → `ca-bundle.pem`, set by `backend.config` at import); a
  standalone script must `import backend.config` FIRST.

## Agent Control ("Agent Observability Controls" toggle)
- **[2026-09-23] Second backend: `GALILEO_AGENT_CONTROL_BACKEND=splunk_ao`** — the Agent
  Control server INSIDE this realm's Agent Observability
  (`https://app.<realm>.observability.splunkcloud.com/ao/agent-control`; `/health` reports
  server 8.5.0 in us1). Same httpx client, no SDK: the official `agent-control-sdk` is
  Python>=3.12-only (PEP 695 syntax, cannot import on 3.11) and binds ONE target per process.
  Auth = `X-SF-Token: $SPLUNK_AO_CONTROL_TOKEN` (falls back to `SPLUNK_AO_O11Y_API_TOKEN`);
  the token MUST carry the `agent_observability_admin` role — a plain O11y API token gets
  `/health` 200 but `403 controls.read` and `/ao/api` 403 (verified with the Mac's `O11Y_API`).
  Every call is bound to the theme's Agent stream (`_stream_for`; id via `/ao/api`, cached);
  both stages run (`agent_control_prompt` PRE node after `prompt_defense`, `agent_control`
  POST); verdicts ride the governance event as `agent_control_verdicts` and become control
  spans in `_build_turn`. **Target type = `log_stream`** (default since 4.12.1): every call
  bound to `agent_stream` (Splunk's how-to, Kumar's fork) gets `502 AUTH_UPSTREAM_REJECTED`
  from the us1 gateway — that was "the 502". Probe with
  `agent_control_client.list_controls(theme=…)` (registers the agent first; an unregistered
  agent is 404). Controls: `PUT /api/v1/controls {name, data}`, attach with
  `PUT /api/v1/control-bindings/by-key {target_type, target_id, control_id}` (idempotent);
  an unfiltered `GET /control-bindings` also 502s. Design: docs/agent-control-splunk-ao.md.
- Credentials are `AGENT_CONTROL_API_KEY` / `AGENT_CONTROL_CONSOLE_URL` (old
  `GALILEO_API_KEY`/`GALILEO_CONSOLE_URL` honored as a deprecated fallback, one
  warning per process; `GALILEO_CONSOLE_URL` is ignored once `AGENT_CONTROL_API_KEY`
  is set because the splunk-ao SDK injects it with the O11y app host). The
  `GALILEO_AGENT_CONTROL_*` pydantic settings and the identifiers
  `galileo_agent_control`, `galileo_agent_control_agent`, `galileo.luna` do NOT
  change — dashboards key on them.
- **Two different auth schemes on `agent-control.multitenant.galileocloud.io`.**
  Management (`/api/v1/controls`, `/agents/initAgent`, `/agents/{a}/controls/{id}`,
  `/evaluators`) accepts `Authorization: Bearer <JWT>` where the JWT comes from
  `POST https://api.multitenant.galileocloud.io/v2/login/api_key {"api_key": …}`.
  A raw `X-API-Key: $AGENT_CONTROL_API_KEY` is rejected 401 on every endpoint.
  Do instead: always exchange the API key for the JWT first; the OpenAPI spec is
  public at `<base>/openapi.json` (no auth) — read it instead of guessing.
- **`POST /api/v1/evaluation` takes ONLY a minted HS256 runtime token**
  (`/api/v1/auth/runtime-token-exchange`), and that exchange returns **502
  AUTH_UPSTREAM_REJECTED** for org `splunkse` regardless of target_type (verified
  2026-07-29) — a tenant-side grant, not a payload bug (`/control-bindings` 502s
  identically). Presenting the console JWT instead gets
  `401 Token is missing the "iat" claim`. Do instead: don't wait on it — the app
  now falls back to **client-side execution** (below). Re-probe the exchange
  periodically; when it clears, the server path resumes automatically.
- **Client-side execution is the working transport today.** `execution: "sdk"`
  semantics, hand-rolled in `backend/services/agent_control.py`: read the agent's
  control definitions from the management API (console JWT is enough) and score
  through the core API's `POST /scorers/invoke`. `galileo_agent_control_execution`
  = `auto` (default, server-preferred) | `server` | `client`. Deliberate deviation:
  the official engine SKIPS controls whose `execution` != its context
  (`agent_control_engine/core.py`), we run `server` ones locally and log once —
  keep 259 as `execution: "server"` so it inherits the server path for free later.
  Don't add the `agent-control-sdk` dependency: its Luna evaluator mints an
  internal JWT from a secret we don't have, so the public `/scorers/invoke` is the
  only option, not a shortcut.
- **`/scorers/invoke` works for SLM scorers and is BROKEN for every LLM-judge
  scorer** (verified 2026-07-29): `correctness`, `context_adherence`,
  `instruction_adherence`, `ground_truth_adherence`, custom LLM scorers → HTTP 200
  with `status:"failed", error_message:"'str' object has no attribute
  'format_content_for_message'"` for EVERY input shape (plain strings, message
  lists, content parts). Both `code` scorers error in their own code. Working:
  `Output PII (SLM)` → `["ssn","phone_number"]`, `context_adherence_luna` → float.
  So hallucination cannot be measured at runtime yet — Galileo-side defect.
  Do NOT substitute `context_adherence_luna` for factuality: with no retrieval
  context it scored **0.025 on a badly hallucinated answer vs 0.111 on a correct
  one**, so `lt 0.5` there blocks nearly everything. Galileo's OFFLINE metric path
  for `correctness` works fine (that's the Logs-view column) — it is post-ingestion
  and cannot gate a live response.
- Controls are per-AGENT: a console control does nothing until attached to the
  registered agent (`pseudoco-assistant-agent`). Do instead:
  `venv/bin/python scripts/demo/register_agent_control.py --attach <id>`.
- Hallucination control **259** = `galileo.luna` + preset scorer **`correctness`**
  (`89d579ce-…`, alias `factuality`), scope `stages:[post] step_types:[llm]`,
  selector `path:"*"` (the judge needs question AND answer), operator **`eq`**,
  threshold **`false`**. Definition is checked in at
  `scripts/demo/controls/259-block-hallucinated-output.json`; apply with
  `register_agent_control.py --set-data 259 <file>` (`PATCH /controls/{id}` only
  edits name/enabled — a condition change needs `PUT /controls/{id}/data`).
  **The operator is load-bearing:** `correctness` emits a BOOLEAN, and
  `coerce_number()` returns None for bools, so a numeric operator (`lt 0.5`, the
  original config) raises `"score False is not numeric"` → evaluator error →
  fail-open → the control can never fire. `any` is inverted (fires on *correct*).
- Output-PII control **263** = `PseudoCoAssistant-block-output-pii`, the one that actually
  ENFORCES today (`Output PII (SLM)`, `88eada48-…`, is an SLM scorer so it invokes).
  Definition: `scripts/demo/controls/block-output-pii.json`. The scorer returns a
  **list** of categories and `contains` takes one category, so the condition is an
  **`or` of `contains` leaves** — with the per-evaluation memo that costs ONE judge
  call, not one per leaf (the memo key was originally shadowed by the payload
  loop variable; 8 leaves = 8 calls until that was fixed).
  **`name` is deliberately excluded**: a normal answer naming a care provider
  ("contact Dr. Robert Anderson") scores `['name']`, so `operator:"any"` or a
  `name` leaf withholds legitimate responses. Verified: PII-injected turn →
  blocked; same prompt without injection → allowed.
- **The block message must stay generic.** `_handle_agent_control_block` serves
  every deny control, so wording that asserts one cause ("not factually reliable")
  misdescribes a PII block. The matched control is in `safety_categories`.
- **A deny control whose evaluator errored is reported under `errors`, not
  `matches`,** while the engine still sets `is_safe:false`. Parsing only `matches`
  reads that as a clean pass — neither blocking nor honoring fail-open. Guarded in
  `_parse_response` + `tests/test_agent_control.py`.
- `GET /agents/{name}/controls` nests the definition under **`control`**;
  `/controls/{id}` uses **`data`**. Accept either or every field reads as None.
- Node order is `compliance -> agent_control -> response_defense`, so Cisco AI
  Defense stays the last word on output. Regression:
  `venv/bin/python tests/test_agent_control.py`.

## Cisco AI Defense — outbound API integration, fail-closed
- "Connecting" a box to AI Defense = six `AI_DEFENSE_*` vars in that box's `.env`;
  the **API key is the binding** to the SCC application/connection (org Yeack
  Industries → app **YeackBot** → API connection). `push-replica.sh` installs the
  Mac's `.env` verbatim, so fleet replicas inherit the connection for free — a box
  deployed *before* the Mac was configured has a stale `.env` and must be
  redeployed or patched + `systemctl restart pseudoco-assistant-app`.
- **`AI_DEFENSE_FAIL_OPEN=False` means an unreachable/401 Inspection API blocks
  EVERY prompt** — indistinguishable from working enforcement unless you also test
  a benign prompt. Never "fix" that by flipping it True (silently disables the
  guardrail while the UI still shows protection). Diagnose with the raw curl.
- Leave `AI_DEFENSE_ENABLED_RULES` **empty**: the connection is SCC-policy-bound,
  so explicit rules get HTTP 400 and fall back to the console policy anyway.
- Full procedure + 4-tier verification: skill `connect-ai-defense`.
- **AI Red Teaming + AI Inventory live in a DIFFERENT org (PseudoCo)** and use the
  Management key in `~/.aibom-ai-defense-key`, not the inspection key. Skill
  `ai-defense-red-team-and-inventory` (`refresh.py`); a desktop scheduled task
  reruns it on the 1st of each month against BOTH targets (protected, then the
  unprotected baseline: most of a day). Each run = ~2,000 real governed turns
  in the DB, Splunk and the MedAdvice Agent stream.

## Chat latency (2026-07-15 remediation — where the time goes)
- **Multi-Agent Mode defaults OFF (2026-07-28):** a default turn = 1 Ollama
  call (the theme's domain agent / synthesizer). The 3-4 sequential calls
  (coordinator → 1-2 specialists → synthesizer) run only with the drawer
  toggle ON (`multi_agent_mode=true`); non-UI callers must opt in explicitly
  (auto-prompter + demo/eval scripts already do). Guard tests:
  `test_default_mode_is_single_agent` + the stream-default checks in
  `tests/test_api.py`.
- A multi-agent turn = 3-4 sequential Ollama calls (coordinator → 1-2
  specialists → synthesizer). Per-agent wall-clock is in the governance event
  (`agent_trace[].duration_ms`) and AI Defense time in `stage_timings` — check
  `logs/ai_governance.json` FIRST when "latency is high"; no log archaeology.
- **Host memory pressure rules Ollama.** With Splunk ES resident, system_free
  is ~3-5GB, so the 3B internal + 8B synthesizer models can't co-reside — each
  turn pays a 3B↔8B swap (`sched.go "predicted to exceed available memory,
  evicting"` in `~/.ollama/logs/server.log`). Still fastest measured config:
  3B split = 38s/turn vs all-8B = 55s. Don't "fix" by reverting
  OLLAMA_MODEL_INTERNAL without re-measuring both.
- `POST /api/chat/message/stream` (SSE) streams one stage frame per graph node,
  then a final frame AFTER response_defense — never stream synthesizer tokens
  directly (bypasses the output guardrail). Old JSON endpoint stays for
  compatibility; frontend falls back to it.
- `launchctl setenv` from a Claude/SSH shell does NOT reach the GUI launchd
  domain that spawns Ollama.app — the com.yeack.ollama-env agent applies at
  login. Verify what the daemon ACTUALLY got via the "server config" line in
  `~/.ollama/logs/server.log`, not `launchctl getenv`.
- `scripts/demo/build_poisoned_model.sh` refuses to run while the app serves
  or a model is loaded (mid-generation `ollama cp/rm` stalls turns + evicts the
  resident model — observed 2026-07-15). `--force` overrides.

## Running the app
- `./run.sh` (local, :8001) launches under `opentelemetry-instrument` when
  `O11Y_INGEST`/OTLP is set in `.env`. `./tunnel.sh` for a public
  Cloudflare URL (ephemeral; needs the app running).
- Access gate: `ACCESS_KEY` in `.env` (currently word-style). Log in at `/login`,
  or `curl -u x:$ACCESS_KEY`. `/health` is the only open route.
- **Rotate ACCESS_KEY:** edit `.env`, then `launchctl kickstart -k gui/501/com.yeack.medadvice-app`
  (key is read at startup — no hot reload). Rotation logs out every browser
  (cookie = sha256 of key). The OpenClaw gateway bakes the key in at container
  start — rerun `./run-openclaw.sh` if `pseudoco-assistant-openclaw` is up. Verify old→401 /
  new→200 on both :8001 and pseudocoassistant.com (medadvice.yeackbot.com is gone since the
  2026-09-09 cutover).

## OpenClaw agentic surface (Mode C — opt-in demo)
- Gives an OpenClaw agent real tools so the demo can show agentic tool abuse
  governed at the tool boundary (`/api/toolguard/inspect` = tool_policy + Cisco
  AI Defense). `./run-openclaw.sh` (or `./start-all.sh --agentic`); off by
  default. `verify_openclaw_observability.sh` after touching the guard/plugin.
- **Runs in podman, NOT a host npm install.** Cisco Secure Endpoint (AMP)
  quarantines the npm `openclaw` entrypoint within ~2 min, repeatably. The
  gateway is the `pseudoco-assistant-openclaw` image (pinned `openclaw@2026.7.1-2`) on
  :18789. See the [[openclaw-edr-podman]] memory.
- **`openclaw/` is tracked but NOT checked out on this Mac.** AMP deletes
  OpenClaw files from the working tree, so the directory is excluded via
  sparse-checkout — nothing on disk to delete, and `git status` stays clean.
  Everything is still in `HEAD` and on GitHub, so a remote `git clone` gets it
  all. **Never `git restore openclaw/`** — that just hands AMP a target again.
  - Read/edit it with `scripts/openclaw-edit.sh` (`--list`, `--show <path>`, or
    `<path>` to edit): it round-trips through git object storage, so the repo
    path is never written. Edits land **staged** — commit them.
  - Setup, once per clone: `scripts/openclaw-edit.sh --apply-sparse` and
    `git config core.hooksPath .githooks`. The hook re-applies the exclusion in
    new worktrees (sparse state is per-worktree and is not inherited).
- **The image is built from git, plugin baked in.** `run-openclaw.sh` pipes
  `git archive HEAD:openclaw` into `podman build` as the build context and
  stamps the tree hash as the `pseudoco-assistant.openclaw.tree` label; a mismatch triggers
  a rebuild. So a plugin change takes effect once **committed**, not once staged,
  and the first build after a change costs a few minutes (npm install).
- **podman VM only shares `$HOME`.** A bind mount from `/Applications/DemoBot`
  fails `statfs ...: no such file or directory` — which is why the plugin is
  baked into the image rather than mounted. The remaining mounts are the state
  dir (`~/.demobot-openclaw`) and the decoy workspace (`~/DemoBotDecoy`).
- **The gateway runs as `--user 0:0`, NOT `--userns=keep-id`** (fixed 2026-07-30;
  it crash-looped before that with `EACCES ... mkdir '/home/node/.openclaw/state'`).
  keep-id maps the host user to the same uid, but the image's default `node` user
  (uid 1000) maps to a subuid that owns nothing, so the host-owned mounts stayed
  unwritable (`keep-id:uid=1000,gid=1000` doesn't bridge it either on macOS
  podman). Rootless podman already maps container uid 0 to the unprivileged host
  user, so container root gains **no host privilege** — it just makes the uid
  match the mount owner, which lets `$STATE_DIR` stay mode **600** (it holds the
  gateway token + `ACCESS_KEY`). Don't "fix" a future EACCES by loosening those
  perms; check the uid mapping first.
- **The guard is fail-closed:** with `TOOL_GUARD_ENABLED=True`, a dead app
  (:8001) denies EVERY agent tool call — looks like a broken agent, not a broken
  app. `TOOL_GUARD_ENABLED` gates *enforcement* only (default False = the
  unguarded control run); the app never calls the gateway, so `podman stop
  pseudoco-assistant-openclaw` is the real off switch.
- Agent model is Ollama **`llama3.2:3b`** (tool-capable); `mistral-nemo:12b` has no
  tools template. Decoy workspace: `venv/bin/python scripts/demo/seed_agentic_decoy.py`.

## Database (SQLite) — concurrency
- **Never put the file-backed SQLite engine on `StaticPool`.** It hands ONE sqlite3
  connection to every Session, and this app writes from both the event loop
  (`Depends(get_db)` handlers) and threadpool workers (chat turns → governance /
  escalation / audit rows via `get_db_context`). Measured cost of the shared
  connection: **12 of 40 rows lost** with 8 concurrent writers, failing with
  "cannot commit - no transaction is active" / NULL identity key — errors the
  governance writer only logs. `check_same_thread=False` stays (connections do
  cross threads). StaticPool IS still correct for `:memory:`, where a second
  connection is a second empty database. Guard: `tests/test_db_integrity.py`.
- `Conversation.messages` is a plain JSON column (**no MutableList**), so mutating
  the loaded list in place and assigning it back compares the attribute against
  itself and the column is dropped from the UPDATE. Copy on load
  (`list(row.messages or [])`) and assign a new list back.

## Environment
- venv is **Python 3.11** (the Splunk GenAI stack needs ≥3.10; 3.9 silently breaks
  the LangChain instrumentation). `venv.py39.bak/` is the old 3.9 venv.
- Secrets live only in `.env` + `medadvice.db` (both gitignored). Never commit them.

## NVIDIA stack (provider=nvidia, NeMo/NemoClaw toggles, blueprints) — 2026-09
- **A local NIM on the A10G needs three knobs** (`/etc/pseudoco-assistant-nim.env`, all
  overridable when bootstrapping): `NIM_MAX_NUM_SEQS=8` (Nemotron Nano's hybrid-
  Mamba SSM cache is pre-allocated per sequence — 33.75 GiB at the default 256,
  and capping the context does NOT help), `NIM_KVCACHE_PERCENT=0.95`,
  `NIM_MAX_MODEL_LEN=8192`. vLLM's `reserved for KV Cache is …GiB` log line must
  be positive (was −0.69 with 16 seqs at 0.90; 1.52 with 8 at 0.95). Expect
  ~26 tok/s per stream (bf16, no quantized A10G profile) vs Ollama's 85 (Q4).
- **NIM model downloads need the NGC org's NIM entitlement, not just a key.**
  402 `User does not have subscription to product` = generate the key through
  build.nvidia.com's NIM "deploy" flow (joins the Developer Program); a personal
  `nvapi-` key then works as a direct Bearer on api.ngc.nvidia.com (the legacy
  token-exchange 401s for it, which is fine). Legacy 84-char keys pull the
  image but not the weights on an un-entitled org.
- **NemoClaw user presets:** `preset:` header + `network_policies` map; target
  THIS HOST'S PRIVATE IP with `--trusted-private-host <ip>`; the validator
  refuses loopback (inside the sandbox 127.0.0.1 is the sandbox), its managed
  aliases (host.openshell.internal) and `allowed_ips` for user files. Read the
  rules in `~/.nemoclaw/source/dist/lib/security/trusted-private-endpoint.js`.
  Bound every `openshell sandbox exec` with `timeout` — one hung for 2 h 51 min.
- **EC2 `--with-nim` needs its `.env` override decided BEFORE step 8's rewrite.**
  4.2.0 prepended `AI_PROVIDER=nvidia` in step 9c, after the rewrite, so a NIM box
  booted on the Mac's Ollama provider with the NIM idle. Also: a NIM (~20 GB) and
  the fleet's resident Ollama models (~11 GB) don't both fit an A10G — a NIM box
  runs `OLLAMA_KEEP_ALIVE=0` and unloads after the GPU check. Order + VRAM rules
  are asserted by `tests/test_ec2_scripts.py` (in `run_all.sh`).
- **`provider=nvidia` is a LOCAL NIM, never the cloud catalog.** `backend/nvidia_nim.py`
  rejects a non-loopback `NVIDIA_BASE_URL` at every seam (llm factory, legacy client,
  Settings save, startup re-apply). This Mac has no NVIDIA GPU → the provider is
  greyed out by `backend/host_capabilities.py` (`GET /api/server-info` `gated`).
  Do instead: exercise it on a GPU replica (`ec2-bootstrap.sh --with-nim`).
- **Nemotron 3 defaults reasoning ON** → the JSON answer contract gets wrapped in a
  trace. `llm.py` sends `chat_template_kwargs.enable_thinking=False` unless
  `NVIDIA_REASONING`, and `_extract_text` strips a leading `<think>` block.
- **Featured-model VRAM floors are what the card REPORTS** (A10G ≈ 23028 MB, not
  24000) and per-GPU × count — Super = `76000|8`. A marketing-size floor greys out
  the very box that fits.
- **Artifactory token in `~/.pip/pip.conf` expires ~12 h after `dev-login`** — then
  EVERY package 403s and pip says "No matching distribution" (it looked like a
  curation block for `nemoguardrails`). Do instead: `dev-login artifactory`, retry.
- `nemoguardrails==0.24.0` core resolves against our pins (no LangChain dep);
  **never the `[server]` extra** (needs starlette>=0.49 → breaks the fastapi 0.109 /
  httpx 0.27 TestClient pin). In-process `LLMRails(config, llm=get_chat_model())`
  is the integration; `check()` runs rails without generation; sync calls only
  off the event loop (graph nodes run in a threadpool — fine).
- **NeMo node order:** `prompt_defense → nemo_input_rails → …` and
  `agent_control → nemo_output_rails → response_defense` — Cisco stays last.
  `test_agent_control` asserts the COMPILED graph edges, not source strings.
- **LangGraph drops state keys not declared on `PseudoCoAssistantState`.** The NVIDIA
  blueprint's `blueprint_record` silently vanished until declared. Any new core
  key → `state.py` first. Guard: `tests/test_nvidia_blueprint.py`.
- **Blueprint parity is structural**: cores only add generation nodes;
  `blueprints/guardrails.py` wires the chain. New guardrail/toggle → the chain +
  `tests/test_blueprint_parity.py` in the same change (CLAUDE.md rule). The suite
  found that blocked turns lacked `workflow_name`/`blueprint` — fixed via
  `governance_identity_overrides`; keep passing it from every block handler.
- **NemoClaw does not support podman** (onboarding refuses); Docker Engine /
  Docker Desktop / Colima only. Primary host = EC2 replica (`--with-nemoclaw`);
  Mac needs Colima. The drawer toggle is the *enforcement* switch for the policy
  layer (unlike `TOOL_GUARD_ENABLED`); the pill is the uniform On/Off — its
  tooltip says "Runtime" only when the sandbox's OCSF denials /
  `after_tool_call` reports arrive, "Policy layer" otherwise.
- Plugin edits still go through git objects (`git hash-object -w` +
  `update-index --cacheinfo` + `--skip-worktree`) — `openclaw-edit.sh` is
  interactive. `run-nemoclaw.sh` materialises the plugin into `nemoclaw/plugins/`
  only for the docker build and deletes it (EDR).
- **NeMo judge on Ollama needs the `_JudgeOllama` wrapper** (`services/nemo_guardrails.py`):
  NeMo's LangChain adapter passes `temperature`/`max_tokens` per call and
  `ChatOllama` spreads unknown kwargs into `ollama.AsyncClient.chat()` →
  `unexpected keyword argument 'temperature'`. Cloud models absorb them. Also
  `LLMRails.check()` wants `RailType` enums, not "input"/"output" strings.
  Both only surfaced live (verified 2026-09-02 on mistral-nemo:12b: jailbreak →
  `self check input`, oxycodone answer → `self check output`, ~4-9 s per judge
  call, so a toggled turn adds ~10-15 s on the 12B model).

## Appointment scheduling (2026-09-03, docs/scheduling.md)

- **Deterministic scheduling + LLM voice.** `services/scheduling.py` owns slots,
  intent, bookings and the chips (`scheduling.actions`); `nodes/scheduling.py`
  is the shared-chain pair (`scheduling_intake` last PRE, `scheduling` between
  `injection` and `compliance`). Never parse structure out of model text.
- A scheduling turn is recognised by `scheduling_context.action` (chip action >
  typed parser). On such turns: clarifier asks nothing, `safety_node` skips the
  escalation rules ("see a doctor" would flag a booking), both cores skip the
  domain specialists. The offer's "?" is excluded from the clarifier budget via
  `metadata.scheduling`.
- On Ollama the answer is a JSON contract and trailing prose is parsed away, so
  the offer/confirmation copy is appended by the POST node AFTER parsing.
- A node exception replaces the whole turn with the generic safety warning
  (graph.py) — every store call in the nodes degrades to `state="unavailable"`.
- `client_id` = browser localStorage id (partition key, not auth). The parity
  suite swaps `nodes.scheduling.store` for `tests/_scheduling_nodes_checks.FakeStore`
  so no scenario writes `./medadvice.db`; `test_api.py` cleans its `test-*` client.
