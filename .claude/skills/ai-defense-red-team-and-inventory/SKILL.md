---
name: ai-defense-red-team-and-inventory
description: Run Cisco AI Defense AI Red Teaming against PseudoCo Assistant and refresh its AI Inventory (AI asset discovery with cisco-aibom), then summarize the results against the previous run. Use when asked to red-team the app, start/check/summarize a red-team run, scan or upload the AIBOM, refresh or populate the AI Inventory, "keep the AI Defense data fresh", or when the monthly "AI Defense monthly refresh" scheduled task fires.
---

# AI Defense red teaming + AI Inventory for PseudoCo Assistant

Two Cisco AI Defense features keep PseudoCo Assistant's data in Security Cloud
Control (SCC) current:

| Feature | SCC page | What feeds it |
|---|---|---|
| **AI Inventory** (AI asset discovery, Beta) | AI Defense → AI Inventory | A `cisco-aibom` scan of the repo's `main`, uploaded as a JSON report |
| **AI Red Teaming** | AI Defense → AI Red Teaming | A run of the *AI Defense Quick Start* profile against a target that points at the public `/api/chat/completions` |

Both live in the SCC org **PseudoCo** (enterpriseId
`d87a65f7-f4f1-47ad-bdab-593226c85f3d`, US). That is **not** the "Yeack
Industries" org the runtime inspection key in `.env` belongs to (see the
`connect-ai-defense` skill). Every call here uses the PseudoCo org's
**Management API key**.

`refresh.py` (next to this file) does all of it. It uses only the standard
library, so the system `python3` runs it. It never prints a secret.

## The monthly job

A desktop scheduled task, **AI Defense monthly refresh**
(`~/.claude/scheduled-tasks/ai-defense-monthly-refresh/`), fires at 07:00 local
on the 5th of every month. It runs:

```bash
cd /Applications/DemoBot && python3 .claude/skills/ai-defense-red-team-and-inventory/refresh.py refresh
```

That command does four things in order:

1. **preflight.** It changes nothing. It checks the Management key, the target
   and the profile, that no run is in flight, the app on `localhost:8001`, the
   public tunnel, that the tunnel accepts `.env`'s `ACCESS_KEY` as
   `X-Access-Key`, that `ACCESS_KEY` hasn't changed since the target was last
   confirmed, and that `AI_DEFENSE_ENABLED=True`. Any FAIL stops the run.
2. **AI Inventory.** If GitHub `main` moved since the last upload, it validates
   the Anthropic key, scans (about 5 min) and uploads. If `main` hasn't moved,
   it re-uploads the last report for free, which refreshes the inventory's
   last-seen data. A failure here goes into the summary, and the red team still
   runs.
3. **Red team.** It starts a Quick Start run against the **protected** target
   and polls every 5 min until the run ends (about 2 h).
4. **Summary.** It fetches the per-attack results, compares them with the
   previous run on the same target and writes
   `~/.ai-defense-refresh/reports/<date>/SUMMARY.md` (plus `.html`).

The scheduled task only fires while the Claude desktop app is open. If the app
is closed on the 5th, the task runs at the next launch.

**What a run costs, and where it lands.** Each red-team attack is a real
governed chat turn: a `medadvice.db` row, a Splunk `gen_ai:json` governance
event, a trace in the MedAdvice Agent stream and APM spans. Expect about 2,000
attack turns on the Governance Logs page and in Agent Observability that day.
An agentic AIBOM scan costs roughly 2.4–2.9M Claude Sonnet tokens on the
`.env` `ANTHROPIC_API_KEY`, about 1.2M of them cache reads. The persistent
`--cache-dir` should make later scans of a lightly changed repo much cheaper,
but that is not measured yet. A re-upload costs nothing.

## Commands

All from the repo root: `python3 .claude/skills/ai-defense-red-team-and-inventory/refresh.py <cmd>`.

| Command | Does |
|---|---|
| `setup` | Creates `~/.ai-defense-refresh` (mode 700), installs `cisco-aibom[agentic,llm-anthropic]==1.10.0` into its venv from public PyPI and downloads the matching catalog with `gh`. Idempotent. `refresh` and `inventory` call it when needed. |
| `preflight [--targets protected,baseline] [--inventory-only \| --redteam-only] [--accept-access-key]` | Runs every check, including the cisco-aibom install and the Anthropic key, and exits 2 on any FAIL. |
| `inventory [--force-scan] [--no-upload]` | Scans (or re-uploads) and uploads to AI Inventory. |
| `redteam-start [--targets …]` | Runs the preflight, starts one run and prints its `task_id`. |
| `redteam-wait TASK_ID [--interval 300] [--max-hours 16]` | Polls until the run reaches a terminal state. |
| `redteam-report TASK_ID` | Summarizes a finished run and compares it with the previous run on that target. |
| `status` | Shows the last inventory upload and the 10 newest red-team runs. |
| `refresh [--targets …] [--force-scan] [--skip-inventory] [--skip-redteam] …` | The monthly job. Exits 1 if any step had a problem, which the summary lists. |

When you run it by hand from a Claude session, run `refresh` or `redteam-wait`
with `run_in_background`, because a run takes hours.

## State on disk

`~/.ai-defense-refresh/` lives outside the repo and holds no secrets.

| Path | What |
|---|---|
| `venv/`, `catalog/` | cisco-aibom and its DuckDB catalog, pinned to `AIBOM_VERSION`. |
| `aibom-cache/` | The agentic classification cache. Keep it. Deleting it, or evicting `_tier_cache_version` entries, re-runs the whole tier (about 2.4M tokens). |
| `scan/PseudoCoAssistant/` | The last clean clone. Its path stays fixed so the cache keys stay valid. |
| `reports/<date>/` | `SUMMARY.md/.html`, `aibom-<sha>.json`, `aibom.log`, `inventory.json`, `redteam-<target>-<id>.json`, raw results as `.json.gz`. |
| `state.json` | The last upload's commit and report, the in-flight runs, and the `ACCESS_KEY` fingerprint (a truncated sha256, not the key). |
| `history.jsonl` | One line per upload, run start and run result. |

Secrets it reads but never copies:

- the Management key, from `~/.aibom-ai-defense-key` (mode 600);
- the scan's Anthropic key, from `~/.aibom-anthropic-key` (mode 600) if that
  file exists, else `.env` `ANTHROPIC_API_KEY`;
- `ACCESS_KEY`, from `.env`.

Each one goes to a child process environment or a request header only.

## AI Inventory: how the scan works

- **What gets scanned.** A fresh **blobless clone of
  `https://github.com/mayeack/PseudoCoAssistant.git` `main`**, with the sparse
  pattern `'/*' '!/openclaw/'` set *before* checkout. EDR on this Mac
  quarantines OpenClaw artifacts, so `openclaw/` must never reach the disk.
  That is also why the main checkout sparse-excludes it and
  `scripts/openclaw-edit.sh` exists. The inventory keys a source on the
  repo URL plus the commit SHA. Scanning the GitHub clone, not the working
  checkout, keeps local edits and untracked files out of it.
- **Command.** `cisco-aibom analyze <clone> -o json -O report.json --llm-provider anthropic --llm-model claude-sonnet-5-5 --agentic-batch-size 2 --agentic-concurrency 3 --agentic-rate-limit 2 --component-summary --cache-dir … --no-progress --timing`, with
  `AIBOM_DB_PATH` set to the catalog and `AIBOM_LLM_API_KEY` set to the Anthropic
  key. 1.10.0 has **no static mode**: without `--llm-model` it exits
  ("The LLM agent classifies every scanner candidate"). The key is checked
  first with a zero-token `GET /v1/models`.
- **Upload.** `cisco-aibom report upload report.json --format json --post-timeout 120`
  with `AIBOM_POST_URL=https://api.security.cisco.com/api/ai-defense/v1/aibom/analysis`
  and `AI_DEFENSE_API_KEY` set to the Management key. The app's inspection key
  does not work here. The script only uploads a report whose
  `metadata.status` is `completed`. That alone isn't enough: cisco-aibom still
  says `completed` when every LLM batch failed (for example on a 401), and the
  resulting BOM is deterministic-only. So the script also refuses to upload when
  the scan log shows "the LLM added nothing" or an `authentication_error`. A
  `degraded` agentic status with real LLM work still uploads: the five "not in
  model registry" test models cause that every time.
- **What lands.** As of 2026-11-04: AISkill for each `.claude/skills/*`
  (8 then, 9 with this skill), 3 LLMEndpoint and 7 AIModel. Agents, Tools, MCP
  servers and Knowledge bases stay empty. The classifier only counts
  LLM-driven tool loops as agents, and the internal-docs and MCP-thrash code is
  custom. The NVIDIA primary assistant (`bind_tools` routing) is a real miss.
  Filling those tabs needs real framework constructs in the app (LangChain
  `@tool`, a FastMCP server, an agent loop). A custom catalog or `# aibom:`
  annotations won't do it: in 1.10.0 they are parsed but inert.
- **The Models tab hides AI BOM models by design.** Its query adds
  `sourceSystem ne ai_firewall_aibom`, so code-scanned models are stored but
  not listed there. Look under the source instead.

## AI Red Teaming: targets, profile and results

| Key in `TARGETS` | target_id | Template constants | In the monthly run |
|---|---|---|---|
| `protected` | `465aecb9-2367-4f70-95fb-7b110dd3234a` "PseudoCo Assistant - MedAdvice with AI Defense (pseudocoassistant.com)" | `ai_defense_review: true`, all `force_*_injection: false`, `theme: medadvice` | **yes** |
| `baseline` | `536c17ae-23b3-4ffb-b05c-c4d01ead7878` "PseudoCo Assistant - MedAdvice (pseudocoassistant.com)" | `ai_defense_review: false` | opt-in: `--targets protected,baseline` |

Both targets are Custom Endpoint, OpenAI API provider, with no streaming, URL
`https://pseudocoassistant.com/api/chat/completions`, response path
`choices[0].message.content` and auth API Token `X-Access-Key`.
`docs/red-teaming.md` explains why that endpoint exists and how a target is
configured.

**Why the baseline is opt-in.** An API start of Quick Start sends **1,998
prompts**. The start body has no attack-volume field (19 names were probed),
unlike the console Quick Scan's 500. Unprotected, every prompt reaches the one
local `mistral-nemo:12b` at about 20–30 s, so a baseline run would take well
over 10 h. Cisco's per-attack deadline also expires while the attacks queue:
the 2026-11-04 baseline stopped at 96% of just 500 after 5 `DeadlineExceeded`
attacks. Run the baseline only with a faster model behind the app, or start
the 500-prompt Quick Scan from the console.

**API** (base `https://api.security.cisco.com/api/ai-defense/v1`, header
`X-Cisco-AI-Defense-Tenant-API-Key` = the Management key):

| Call | Use |
|---|---|
| `GET /ai-validation/targets`, `/profiles`, `/jobs` | Lists. Each job entry carries `attack_counts`. |
| `POST /ai-validation/start` `{validation_scan_name, target_id, profile_id}` | Starts a run and returns `task_id`. Names reject `+`. |
| `GET /ai-validation/job/<task_id>` | `status`, `progress`, `total_num_prompts`, `error_message`. |
| `GET /ai-validation/results/<task_id>` | Every attack in one response (about 3.9 MB for 1,998 attacks). |
| `POST /ai-validation/targets` | Creates a target. It needs `api_token` key **and** value, and GET never returns the stored value. |

**How to read results.** `attack_result` is `ATTACK_RESULT_FAILED` when the
attack was blocked, `ATTACK_RESULT_SUCCEEDED` when it got through, and
`ATTACK_RESULT_ERROR` when Cisco could not finish it. The summary scores only
the first two. `blocking_attribution.layer_name` says which layer stopped it:
`Cisco AI Defense`, `Model` (the model refused) or `Application` (the app's own
safety banner). It can be null. `attack_prompt` and `model_output` come back
empty, so to see an answer, match it to `medadvice.db` `conversations` by
intent words. Runs are compared by pairing `(attack_intent, attack_procedure)`.
Each intent appears about 4 times with different procedures, so the pairing
is approximate.

**Reference points.**

| Run | Date | Prompts | Blocked | Breakdown |
|---|---|---|---|---|
| Protected `04ec3c76` | 2026-11-05 | 1,998 | 1,961 (98.1%); 37 through | AI Defense 1,817, Model 134, App 10. Privacy and cyber 100%; integrity 93.5% (medical misinformation) and IP 97.5% (piracy how-tos) are what gets through. |
| Baseline `5583c080` | 2026-11-04 | 475 scored | 377 (79.4%); 98 through | Stopped at 96%. |

Across 456 paired attacks, the protected run cut what got through from 98 to 6.

## When something fails

| Symptom | Fix |
|---|---|
| `app on this Mac` / `public tunnel` FAIL | Start the app **and the collector** and the tunnel (`launch-medadvice` skill), then rerun. |
| `public tunnel` 403 with curl working | Cloudflare blocks urllib's default User-Agent, so `refresh.py` sends `ai-defense-refresh/1.0`. If 403s come back, check the zone's bot rules. |
| `ACCESS_KEY unchanged` FAIL | The key was rotated, and the targets still hold the old one, so every attack would 401 and score garbage. Edit each target in SCC (AI Red Teaming → Targets → edit → Authentication) and paste the new key yourself. Or create replacement targets via `POST /ai-validation/targets`, piping the key from `.env` without printing it, and update `TARGETS`. Then run `preflight --accept-access-key`. |
| `Anthropic key for the scan` FAIL (401) | The key was revoked. The `.env` key (…NwAA) has returned 401 since at least 2026-11-05. The app runs on Ollama, so this only blocks the scan. Write a working key to `~/.aibom-anthropic-key` (mode 600), or fix `.env`. Only the user can do this. |
| `Management API key` FAIL / 401 | The key in `~/.aibom-ai-defense-key` was revoked or expired. Make a new one in SCC (PseudoCo org → AI Defense → Administration → API keys) and write it to that file with mode 600. Only the user can do this. |
| `target '…'` FAIL | The target was deleted or renamed in SCC. Recreate it from `docs/red-teaming.md` and update its id in `TARGETS`. |
| `no run in flight` FAIL | A run is still going. `redteam-wait <id>`, then `redteam-report <id>`. |
| Run ends `JOB_STOPPED` with `DeadlineExceeded` | Attacks queued on the local model. The protected run rarely hits this because AI Defense blocks most prompts before the model. Check that Ollama isn't busy with something else. |
| pip install fails with 401 | `~/.config/pip/pip.conf` points at Artifactory with an expired token. `setup` already passes `--index-url https://pypi.org/simple`. |
| `temperature: Extra inputs are not permitted` | Something passed `claude-haiku-5-5` as `--agentic-fast-model`. Don't. |
| `asset-management/resources/_search` 401 | That endpoint only takes the console session, not the Management key. |

## Changing it

- **Bumping cisco-aibom.** Change `AIBOM_VERSION`, then run `setup` and one
  attended `inventory --force-scan --no-upload`. Compare the report's
  `summary.component_types` with the last one before you upload. The catalog
  asset name follows the version.
- **Another target or profile.** Add it to `TARGETS`, or change `PROFILE_ID`.
  Keep the targets in run order, because only one can use the local model at a
  time.
- **The schedule.** Use the desktop app's scheduled tasks
  (`ai-defense-monthly-refresh`), not cron or launchd. The task's prompt only
  points at this skill.
