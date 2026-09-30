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
blocks. Two rules:

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
