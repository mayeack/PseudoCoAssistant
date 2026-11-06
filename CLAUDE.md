# PseudoCo Assistant — project instructions

## Demo Controls drawer formatting

Every control card in the **Demo Controls** drawer (`frontend/index.html`, inside
`#settingsDrawer`) uses one neutral format. **Include Synthetic PII/PHI in
Responses** is the reference implementation — copy that card when adding a new
control.

- Card container: `bg-gray-50 border border-gray-200 rounded-lg p-3`
- Title: `text-sm font-semibold text-gray-700`
- Description: `text-xs text-gray-500`

Do **not** give a card its own accent palette (`bg-indigo-50`, `text-sky-700`,
`text-fuchsia-500`, `bg-red-50`, …) to make it stand out. The drawer has to read
as one list; per-card colors made unrelated controls look like separate widgets
and made "which of these is a guardrail vs. a load generator" harder to see, not
easier. A card that needs emphasis earns it from its position in the drawer.

The drawer is organized into named groups, each a `<section data-group="…">`
with a neutral `<h3>` header: **Guardrails** (Cisco AI Defense, Agent
Observability Controls, NeMo Guardrails, NemoClaw Guardrails, Internal Policy
Engine), **Agent Pipeline** (Multi-Agent Mode), **Synthetic Content** (the
injection toggles), **Load & Incident Generators** (Auto-Generate Sessions,
Trigger Demo Incident, Prompt Injection Spray) and **Display** (Appearance). A
new card goes inside the group it belongs to — never loose at the top level,
and not in a new group unless it fits none of these.

Two kinds of card exist and they look the same:

- **per-request toggles** (Cisco AI Defense, Agent Observability Controls,
  NeMo Guardrails, Internal Policy Engine, Multi-Agent Mode, the injection
  toggles) — the toggle's state is sent on every chat request
  (`chat.js buildChatPayload`);
- **server-side toggles** (Auto-Generate Sessions, NemoClaw Guardrails, Trigger
  Demo Incident, Prompt Injection Spray) — the toggle calls an API and polls its
  status; the state lives on the server (NemoClaw persists in `settings_store`).

Options a host cannot run are greyed out with the reason as a tooltip, driven by
`GET /api/server-info` `gated` (`backend/host_capabilities.py`) — never by a
client-side guess.

Every card also carries a `data-control="<key>"` hook, and that key is
registered in `backend/settings_store.py` `DEMO_CONTROLS` (key, label, group,
kind) — the same group as the card's `<section data-group>`. The Settings
page's **Demo Controls** panel and the chat page's per-card visibility
(`GET`/`PUT /api/settings/demo-controls`, `chat.js applyDemoControlVisibility`)
are generated from that registry, so adding, renaming, moving or removing a
card updates the registry in the same PR; `tests/test_demo_controls.py` fails
on any divergence between the markup and the registry. A card is never
hard-coded `hidden` in the markup — hide it from the Settings panel. Hiding is
not gating (gating stays `GET /api/server-info` `gated`): a hidden per-request
card sends no override for its `ChatRequest` flag (`CONTROL_FLAGS` → `null`),
so the server default applies, and a hidden server-side generator keeps
running.

Color is reserved for **state**, never identity. These may stay colored:

- the status pill (`#…Status`) — one look for every card, set only through
  `setPill()` in `frontend/js/chat.js`: **On** = `bg-green-100 text-green-700`,
  **Off** = `bg-gray-100 text-gray-600`. No per-card ON colors, no verbs
  ("REVIEWING", "SPRAYING"), no pulse; what a control is doing while On goes in
  the pill's `title` tooltip.
- live counters/timers beside the pill (`#autoPromptStats`, `#incidentRemaining`,
  `#sprayRemaining`)
- the toggle switch — one accent for every card: `peer-checked:bg-green-600`
  / `peer-focus:ring-green-300`. An On switch looks the same whichever control
  it is; no per-card switch colors (`tests/test_api.py` pins this).

Dark mode is handled centrally for the neutral classes (`html.dark .bg-gray-50`,
`.border-gray-200`, `.text-gray-700`, `.text-gray-500`), so a card that follows
this format needs no dark-mode rule of its own. A card that invents its own
palette does — which is another reason not to.

## Blueprint feature parity

`backend/agents/blueprints/` holds the selectable agentic architectures
(`pseudoco_multi_agent`, `nvidia_virtual_assistant`). The UI has **no Blueprint
picker** — chat turns run `ACTIVE_BLUEPRINT` (`pseudoco_multi_agent`) unless a
caller overrides it per request or via `PUT /api/settings/blueprint` (runtime
only, never persisted). A blueprint contributes only its **generation core**;
everything else is shared and must behave identically whichever blueprint is
selected:

- every guardrail node (`blueprints/guardrails.py` `PRE_NODES` / `POST_NODES`),
- every Demo Controls toggle and `ChatRequest` flag (`force_*_injection`,
  `ai_defense_review`, `internal_policy_review`, `agent_control_review`,
  `nemo_guardrails_review`, `multi_agent_mode`),
- the governance-event contract (`guardrail_ids`, `policy_blocked`,
  `*_detected`, token sums, `agent_trace`, `workflow_name`/`blueprint`),
- the SSE stage frames for the guardrail nodes and the OTel workflow/agent spans.

Rules:

- A new guardrail, toggle or governance field goes into the **shared chain**
  (`blueprints/guardrails.py`, the nodes it wires, `state.py`) — never inside one
  core. If a feature genuinely needs core work, land it in **both** cores in the
  same PR.
- Extend `tests/test_blueprint_parity.py` in that same PR (a scenario for a new
  guardrail/toggle; a key in `CORE_STATE_CONTRACT` for a new field the POST
  chain reads). It runs the scenario matrix through every registered blueprint
  and fails on any divergence; `tests/run_all.sh` runs it with the rest.
- Keys a core writes to the state must be declared on `PseudoCoAssistantState` — LangGraph
  silently drops undeclared keys.
- Blocked turns carry the same `workflow_name`/`blueprint` identity as the happy
  path (`governance_identity_overrides`); keep passing it from every block handler.

## Appointment scheduling

`docs/scheduling.md` is the design. The rules that keep it demo-safe:

- **Deterministic scheduling, LLM voice.** Slots, intent, bookings and the clickable
  options come from `backend/services/scheduling.py`; the model only writes wording.
  Never parse a time, a name or an action out of model text.
- The two nodes (`scheduling_intake` PRE, `scheduling` POST) live in the **shared
  chain** (`blueprints/guardrails.py`), like a guardrail. The only core-side code is
  "skip the domain specialists on a scheduling turn", and it exists in **both** cores.
- Verticalization is a `SchedulingProfile` on `ThemeConfig.scheduling`
  (`backend/agents/themes/<theme>.py`) — copy, noun, hours, slot length, offer
  severities. A new theme defines one; never branch on the theme key in the nodes.
- The chips are the backend's `scheduling.actions`; `frontend/js/chat.js` renders
  them generically and never invents an action.
- `client_id` is the browser's partition key, **not** authorization (one shared
  access key); the API filters by it, nothing more.
- Extend `tests/test_scheduling.py` and the `scheduling_*` scenarios in
  `tests/test_blueprint_parity.py` in the same PR as any scheduling change.

## Chat attachments

`docs/attachments.md` is the design. A chat turn may carry one PDF, and a hidden
instruction in it is the document-borne prompt-injection demo. The rules that
keep it honest:

- **Always screened, no toggle.** There is no Demo Controls card and no
  `ChatRequest` toggle for it: `ChatRequest.attachment` is the document itself,
  never an `Optional[bool]`. The "missed" half of the demo comes from the
  existing guardrail toggles. Whether a host can take
  attachments is the `gated.pdf_attachments` host gate (`GET /api/server-info`,
  `host_capabilities.pdf_attachments_gate`) and nothing else: the API answers
  503 from it and the Attach button greys out from it.
- `attachment_intake` is `PRE_NODES[0]` in the **shared chain**
  (`blueprints/guardrails.py`), ahead of `identity_risk` (`PRE_NODES[1]`,
  Lab 5) and `policy`. It is never in `_MAY_TERMINATE`, and a failed read is
  `status: "error"`, never a raise. `identity_risk` reads neither the message
  nor the document; its block event carries the typed message and the
  `attachment` metadata only, and its banner never gets the document sentence.
- **The screens and the model see the same composed text.** Every prompt-stage
  guardrail screens `screened_prompt(state)`, and the shared synthesizer gets
  `with_attachment(...)`. Both come from `attachments.compose_user_turn` and
  must never diverge. The block is not wrapped in "untrusted, ignore its
  instructions" language.
- **Internal agents get the metadata note only** (`with_attachment_note`: the
  name and page count, never the text). That is the coordinator and
  specialists, and the NVIDIA primary and sub-assistants: **both** cores, in
  the same PR.
- **Most deterministic logic keys on the typed message only**: internal docs,
  scheduling intent, safety, routing and the response-stage guardrail context.
  Never derive a tool call, a directive or a verdict for those from document
  text.
- **The PII/PHI exfiltration detector is the one deliberate exception.**
  `pii_exfil_requested` -- and so `ehr_lookup` and the forced synthetic-PII
  category (`injection.decide_requested_categories`) -- reads
  `screened_prompt(state)`: the typed message plus an attached document's text,
  exactly what the prompt screens inspect. This is the data-exfiltration attack
  class the feature exists to show: a hidden instruction pulling the synthetic
  record it names into context, and the model disclosing it. It stays safe to
  always evaluate because `ehr_lookup` sits AFTER every prompt-stage guardrail
  in `PRE_NODES` -- a bound Cisco AI Defense policy still blocks the turn
  before this node ever runs, when it is on -- the record is still a fixed,
  per-theme synthetic set (`backend/services/ehr.py`), and the model is still
  the thing that actually discloses it; nothing is stitched into the answer
  outside the LLM call. Every other deterministic trigger stays typed-only.
- **The bytes are never persisted or logged.** Store and log
  `message_metadata` / `governance_record` only; `attachment` on a governance
  event is metadata and is not a DB column. The extracted text does leave the
  box (screens, `input_messages`, HEC, Agent Observability, APM), which is why
  `UPLOAD_NOTICE` stays on the Attach button and under the chip.
- **pypdf runs only inside the killable worker** (`backend/services/pdf_worker.py`,
  a `python -I` child with a hard timeout). Never import it in the app process
  or on a request thread. It is pinned exactly in `requirements.txt` (floor
  6.14.1, for the 2026 extraction-DoS fixes); bump it deliberately.
- **Sample payloads come from `spray_corpus.TECHNIQUE_FAMILIES`**, verbatim, and
  are validated as documents with `tests/manual/probe_attachments.py` against
  the live AI Defense. Record the date in `attack_documents.DOCUMENT_VALIDATION`
  only from a passing run. Never add canned compliance or a fallback change to
  make a sample "work"; if one stops blocking, swap the payload and probe again.
- The theme covers are a `SampleDocumentProfile` on `ThemeConfig.sample_document`.
  A new theme defines one, and nodes never branch on the theme key. Covers follow
  the synthetic-content rules: no identifiers, no placeholders, no "sample"
  labels, and no text that trips a deterministic trigger.
- User-visible copy (the block-banner sentence, the upload notice, the Prompt
  Library rows) follows "Product naming": it says "Splunk Agent Observability",
  never "Galileo". The banner sentence goes only on a real prompt-stage
  verdict, never on a fail-closed "could not be reviewed" banner.
- Extend `tests/test_attachments.py` and the `document_injection_*` scenarios in
  `tests/test_blueprint_parity.py` in the same PR as any attachment change.

## Identity sign-in

`docs/identity.md` is the design (Lab 5, "Verify: Cisco Identity Intelligence").
Inert unless `DUO_ENABLED`: with it off Labs 0-4 behave exactly as before.

- **Identity comes only from the verified session**: `request.state.identity`,
  set by the identity middleware (`backend/middleware/identity.py`) from the
  `__Host-pseudoco_assistant_identity` cookie. Never from `enduser_id`, never
  from a request body. `identity_session` is a `run_turn` /
  `build_initial_state` / legacy `process_message` parameter, never a
  `ChatRequest` or `ChatCompletionRequest` field, and there is no Demo Controls
  card for anything identity: a client cannot switch enforcement off.
- **Secrets live in `.env` only** (`DUO_*`, `CII_*`, `IDENTITY_*`,
  `PUBLIC_BASE_URL`), never in `settings_store` or `_INTEGRATION_FIELDS`:
  anyone holding the room access key can rewrite those.
- **The Duo redirect URI comes only from `PUBLIC_BASE_URL`**
  (`settings.duo_redirect_uri`), never from the Host header; https only, on a
  DNS name, and the scheme is the trusted proxy's.
- Store and Duo calls run off the event loop; the middleware is pure ASGI (it
  sits on the SSE path).
- **No identity secret in any log, at any level.** `backend/logging/redaction.py`
  (installed by `setup_logging` as a log record factory, so child loggers such
  as `urllib3.connectionpool` are covered) redacts every record by pattern:
  - the `duo_code`, `code`, `state`, `client_assertion`, `assertion` and token
    query parameters;
  - Authorization, Cookie, Set-Cookie and X-Access-Key values, the app's own
    cookies, Bearer tokens and JWT-shaped strings;
  - the exact values of the configured secrets (`DUO_CLIENT_SECRET`,
    `DUO_ADMIN_SKEY`, `CII_CLIENT_SECRET`, `ACCESS_KEY`), compiled once at
    startup and again when the config changes.

  Nothing a request sends is ever registered, so no input can blank a username
  out of the logs. A new credential goes on that configured-secrets list.
  Every pattern must stay linear-time: a test times them all on adversarial
  input.
- **Inert means no requests.** `chat.js` polls `GET /api/identity/me` only
  while `gated.duo_signin` is open or `/api/server-info` `identity_session`
  says this browser holds a session (or the page already shows one). With
  `DUO_ENABLED` off, Labs 0-4 send no identity request.
- **Bounded Duo.** `begin()` checks the allowlist before it takes a rate
  slot; the rate table evicts least-recently-used names, never all at once.
  Every Duo call has a deadline that gives its slot back even if Duo never
  answers, and the SDK's sockets get `DUO_HTTP_TIMEOUT` (duo_universal takes
  no timeout). The `duo_signin` gate re-checks Duo's health every 5 minutes
  (every minute while it fails) on a daemon thread. Duo's TLS uses the CA
  bundle in `REQUESTS_CA_BUNDLE` (else `CURL_CA_BUNDLE`) like every other
  outbound client, and duo_universal's pinning only when none is configured.

## Identity Risk Gate

- **`identity_risk` is `PRE_NODES[1]`** in the shared chain, after
  `attachment_intake` and before `policy`, in `_MAY_TERMINATE`. Both
  blueprints get it by construction; the legacy engine calls the same
  `identity_gate_turn` before its policy check.
- **No identity session, no work:** the node returns `{}` before any span,
  log or lookup (the spray's actor has none, so AI Defense still sees it).
- **`identity_gate.decide` is pure.** Lookups (`backend/services/identity_lookup.py`:
  Duo Admin API, signed HMAC-SHA512; CII token + GraphQL) never raise, are
  bounded (3 s connect / 5 s read), cached 10 s, and go out only over https.
  The CII query is the one constant `CII_END_USER_QUERY`.
- **Fail open (A3):** an unavailable lookup allows the turn with
  `identity_check="unavailable"`; a block resting on what WAS learned still
  blocks. CII is asked with the email Duo last gave (`remembered_email`), so
  a Duo outage never hides a CII block; a source that was not asked is
  `unavailable`, never `not_found`, and "no such user" from CII is an answer
  (`identity_check="ok"`), not an outage.
- **No side effects in the chain.** The gate never revokes and never writes
  to Duo or CII. Revocation is the middleware's pull: Duo `disabled` revokes
  the session (a tombstone); `locked out` only blocks turns. `revoke()` is one
  `UPDATE ... WHERE revoked_at IS NULL` and writes its event only when it
  changed a row, so racing pulls make one tombstone and one event.
- **Unblock me** (`POST /api/identity/unblock` / `/reblock`) is per identity
  session, never a Demo Controls card or request field, and never touches Duo
  or CII. The gate records the real verdict plus `identity_override=true` on
  every event; the audit events are `identity_unblocked` / `identity_reblocked`.
  It never exempts a session from the pull: only an override that brought a
  session back from a Duo revocation (`unblock_cleared`, `holds_open`) keeps
  it open, and only while Duo keeps the account disabled.
- The block event: `guardrail_ids=["cisco_identity_intelligence"]`,
  `safety_categories=["compromised_identity"]`, severity HIGH (never
  EMERGENCY), no escalation, the typed message only, `theme=` and the turn's
  identity / attachment fields. Never tagged "injection" (Lab 4's correlation).
- Extend `tests/test_identity_gate.py` and the `identity_*` scenarios in
  `tests/test_blueprint_parity.py` in the same PR as any identity change. The
  attachment rules above are unchanged.

## Product naming

The product is **PseudoCo Assistant** (since 4.10.0). Its identifier forms are
fixed; use them consistently and never coin another:

- `PseudoCo Assistant` — the free-standing name: UI copy, docs, `app_name`
  (`"PseudoCo Assistant v4"`), the Agent Observability project / agent stream
  defaults;
- `pseudoco-assistant` — the slug: OTel service name and `pseudoco-assistant.*`
  span attributes, governance `service_name` / `deployment_id`, AI Defense
  `src_app`, Agent Control agent / step names, container, systemd-unit and
  plugin names, sourcetypes (`pseudoco-assistant:otel`);
- `PseudoCoAssistant` — the identifier: `PseudoCoAssistantState`,
  `EC2-PseudoCoAssistant-Runbook`, Agent Control controls
  `PseudoCoAssistant-block-*`;
- `PSEUDOCO_ASSISTANT_` — the env / template prefix
  (`PSEUDOCO_ASSISTANT_GUARD_URL`, `__PSEUDOCO_ASSISTANT_DIR__`);
- `pseudoco_*` — underscore keys: the blueprint / workflow keys
  `pseudoco_multi_agent` and `pseudoco_nvidia_virtual_assistant`, and
  `pseudoco_assistant_<word>` for everything else (`pseudoco_assistant_trace_id`).

User-visible text says **"Splunk Agent Observability"**, never "Galileo". This
covers UI copy, governance-log `reasons`, and `response_text` block banners —
anything an audience sees in the app, the Governance Logs page, or Splunk. The
"log stream" is called an **Agent stream** in user-visible text.

These keep their old names, because each is load-bearing — either a contract
something outside the repo reads, or the address of state that lives outside
the repo:

- the `splunk_ao` package (SDK imports) and the `SPLUNK_AO_REALM`,
  `SPLUNK_AO_O11Y_TOKEN`, `SPLUNK_AO_PROJECT`, `SPLUNK_AO_AGENT_STREAM` env contract
  (read by the SDK, `run.sh`, `run-collector.sh` and the collector overlay
  `otel-collector-agent-obs.yaml`); the overlay's `project` / `logstream` header
  keys are what the SDK itself sends
- Agent Control's `AGENT_CONTROL_API_KEY` / `AGENT_CONTROL_CONSOLE_URL`, and the
  unchanged `GALILEO_AGENT_CONTROL_*` settings (enabled / url / agent_name /
  step_name / timeout / execution / refresh_seconds / fail_open)
- schema/identifier values such as `guardrail_ids=["galileo_agent_control"]`, the
  OTel span name `galileo_agent_control_agent`, and `_LOCAL_EVALUATOR =
  "galileo.luna"` — Splunk dashboards and detectors key on these strings
- the `galileo` package and `GALILEO_API_KEY` / `GALILEO_PROJECT` — now used ONLY by
  the legacy eval scripts (`scripts/demo/galileo_*.py`,
  `tests/test_galileo_experiment.py`, the `galileo-poisoning-eval` skill) against
  the standalone Galileo console; the app's trace path must not import it
- `medadvice*`: `medadvice.db`, the launchd labels `com.yeack.medadvice-*`, the
  browser's localStorage keys, the `medadviceN.yeackbot.com` tunnel hostnames
  and the `launch-medadvice` skill — state on disks, in browsers and in
  Cloudflare that a rename would orphan. Retiring a tunnel hostname is a
  deliberate migration, never a rename: `deploy/cloudflare/` carries the
  preflight, the cutover and the list of external systems to re-point.
- the theme keys (`medadvice`, `taxadvice`, `financeadvice`, …) — governance
  rows and `src_app` values are keyed on them
- the GitHub repo `github.com/mayeack/DemoBot` (and the fork
  `github.com/kumar-aamit/DemoBot`), the checkout paths `/Applications/DemoBot`,
  `$HOME/DemoBot` / `~/DemoBot` / `/home/<user>/DemoBot`, and the memory-dir
  slug `-Applications-DemoBot`
- home-dir state: `~/.demobot-openclaw`, `~/.demobot-nemoclaw`, `~/DemoBotDecoy`
  (with its `.demobot-decoy` marker), `~/.ssh/demobot_ec2`, `~/demobot-payload`
- cloud objects that already exist under the old name: the cloudflared tunnels
  `demobot-<n>` and the matching EC2 `Name=demobot-<n>` tags, the EC2 tag key /
  schedule group `demobot-fleet`, the `Project=DemoBot` tag, the IAM role
  `DemoBotSchedulerRole` / policy `DemoBotFleetPower`, the EC2 key pair
  `FLEET_KEY_NAME=demobot`
- `LEGACY_UNIT_PREFIX="demobot"` in `deploy/ec2/ec2-bootstrap.sh`: the shim that
  retires the pre-4.10 units on a re-bootstrapped box has to name them

Internal comments, docstrings and log messages may still say Galileo where they
describe Agent Control's vendor server or the legacy eval; that is deliberate, not
an oversight.

**Renames are scripted, never a blanket sed.** The 4.10.0 rename was generated
by a re-runnable script whose rule set and exclusion list are recorded in the
rename commit's message and in `docs/fork-assessment-kumar-aamit-2026-09.md`.
It masks every address above span by span before substituting, renames paths
with `git mv`, and rewrites `openclaw/` through the index only (it is
sparse-excluded on the Mac). A case-insensitive search-and-replace turns those
addresses into `/Applications/PseudoCo Assistant` and
`~/.ssh/pseudoco-assistant_ec2` and breaks the box they point at — that is
what the fork's sed did. Any future rename re-runs the same approach with the
same list, and a new address of outside state goes on that list first.

## Versioning and releases

Semver, with the version in **two** places that must move in the same commit:
`app_version` in `backend/config.py` and `APP_VERSION` in `.env.example`.
`app_name` (`"PseudoCo Assistant v4"`) carries the product name and the MAJOR
line: the `v4` moves only with the MAJOR (it also appears in `run.sh`,
`Containerfile`, and `requirements.txt`, which say "v4" for the whole 4.x
series); the product word in front of it may change on a MINOR — the 4.10.0
rename did — never on a PATCH.

Releases are annotated `vX.Y.Z` tags cut from `main` **after** the PR merges,
then published with `gh release create`. Never tag a feature branch. Full
process, including why a deployed box can still report a stale version:
`docs/RELEASING.md`.

## Synthetic Content toggles

The four **Synthetic Content** controls (Include Synthetic PII/PHI, Include
Toxic Content, Include Hallucinated Content, Prescriptive Overreach) work by
asking the user-facing model to produce the content **itself**, inside its
answer (`backend/agents/nodes/injection.py`). The fourth control's label and
content follow the theme (`chat.js` `boundaryLabel`): for TelecomChatbot it is
**Unauthorized Commitment** — the agent announces a $240 loyalty credit, a waived
early-termination fee and a 24-month rate lock as already done, the exact output
the Telecom demo script narrates and its AI Defense Policy Studio guardrail
blocks. Retail's is **Unauthorized Refund** (a $189.99 refund with no return, a
30% discount and a two-year warranty extension, announced as done); Manufacturing's
is **Safety Override** (the assistant clearing an operator to run with an interlock
bypassed, skip lockout/tagout, and ship a lot that failed inspection); FinanceAdvice's
is **Securities Fraud** (a named buy ahead of earnings on a non-public figure, with a
guaranteed return). Where a theme's base prompt forbids exactly that act,
`_SCOPE_RULE_RELAXATIONS` lifts those rules on authority turns only (MedAdvice,
TelecomChatbot, Retail, FinanceAdvice, Manufacturing). Two rules:

- **Never add a deterministic / canned fallback.** Text stitched onto the reply
  after the LLM call is not what the guardrails and evals are scoring, so it
  fails to trigger them and misrepresents the demo. If the model declines a
  directive, the turn reports that category as not delivered (`*_detected`
  false) and that is the correct outcome. The only lever is the directive
  itself: its wording, where it lands in the theme's answer contract, and the
  permission framing for censored providers. Probe any wording change live
  (`tests/manual/probe_directives.py`, `probe_aidefense.py`) rather than
  papering over a refusal with canned text. The `_inject_*` / `_integrate_*`
  helpers on `RecommendationEngine` belong to the legacy non-agentic engine
  only; do not call them from the agentic chain.
- **Never label the content.** No "synthetic sample" banner, no `X SAMPLE:`
  prefix, no "(fictional)" tag, no closing disclaimer, no placeholder values
  (John Doe, 123-45-6789, example.com). The directives forbid that vocabulary,
  `strip_sample_labels` / `realize_pii_placeholders` clean up a slip, and the
  content goes where it belongs (record line opens the assessment, abuse in the
  assessment and first guidance item, fabrications as the opening guidance
  items, overreach as a guidance item; `reply` for the conversational theme).

`tests/test_synthetic_content.py` pins both rules; keep it in `tests/run_all.sh`.
