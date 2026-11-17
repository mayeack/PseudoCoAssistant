---
name: fan-tunnel-to-agent-observability
description: Fan a PseudoCo Assistant public tunnel's (medadviceN.yeackbot.com) LLM telemetry into a Splunk Agent Observability project so chat turns land as traces with governance metadata. Use when asked to "send this box's traces to Agent Observability" (or "to Galileo"), to point a replica at a specific project / agent stream, or to verify why a box shows no traces in Agent Observability.
---

# Fan a PseudoCo Assistant tunnel's LLM telemetry into Splunk Agent Observability

Takes a running PseudoCo Assistant replica behind `medadviceN.yeackbot.com` and makes its
chat turns appear in a named Splunk Agent Observability project + agent stream.
Agent Observability is hosted in Splunk Observability Cloud (realm `us1`); the
console is `https://app.us1.signalfx.com/#/agent-obs`. Sibling of
`wire-tunnel-logs-to-o11y`, which does the same job for Splunk Log Observer.

## The one thing that trips everyone up

**There are two independent paths into Agent Observability, and they behave
differently.** Both are driven by the *same four* `.env` keys, so it is easy to
assume one working path means both are working.

```
Path A — SDK (backend/agent_observability.py, splunk-ao 0.8.0), the one that matters
  chat turn -> governance logger -> SplunkAOLogger (one per process, worker thread)
    -> OTLP/HTTP POST ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp
    -> trace "chat turn" carrying safety / PII / toxicity / policy / eval metadata

Path B — OTel Collector fan-out (otel-collector-agent-obs.yaml overlay)
  app OTLP :4317 -> filter/genai_only -> otlphttp/agent_obs
    -> OTLP/HTTP POST ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp
    -> raw gen_ai.* spans (model + token telemetry), no governance fields
```

Path A is what the workshop demos — it is the only one carrying the governance
picture, because those flags are computed by graph nodes *after* the LLM call
returns, which a LangChain callback can't see. Path B is the model/token view.

Consequences worth knowing before you debug anything:

- **Path A is a no-op with no error when `SPLUNK_AO_O11Y_TOKEN` is unset.** It is
  defensive by design and can never break a chat turn. Silence is the failure
  mode, not an exception.
- **Path B is not even loaded when `SPLUNK_AO_O11Y_TOKEN` is unset.**
  `run-collector.sh` layers the overlay on top of `otel-collector-config.yaml`
  only when the token is set; otherwise it prints
  `Agent Observability trace fan-out: OFF (no SPLUNK_AO_O11Y_TOKEN in .env)`
  and there is no exporter, no counter and no error.
- **Path B's counter legitimately sits at `0` on an idle box.** `filter/genai_only`
  drops every span that lacks `gen_ai.operation.name` — which is every FastAPI
  HTTP span, i.e. all health checks and UI polling. Until someone sends a real
  chat turn, `otelcol_exporter_sent_spans{exporter="otlphttp/agent_obs"}` does not
  exist in the metrics output at all. That is correct, not broken.
- The filter is **required**. Without it the ingest endpoint rejects the batch with
  "No GenAI patterns detected in spans" and drops good spans along with the HTTP noise.

## Inputs

| Input | Example | Where it comes from |
|---|---|---|
| Tunnel | `https://medadvice1.yeackbot.com/app` | the assignment row |
| Project | `PseudoCo Assistant` | `SPLUNK_AO_PROJECT` — created on first ingest, nothing to pre-create |
| Agent stream | `PseudoCo Assistant` | `SPLUNK_AO_AGENT_STREAM` — created on first ingest (the API still calls it a `log_stream`) |
| Realm | `us1` | `SPLUNK_AO_REALM` — the Observability Cloud realm |
| Token | (in the Mac's `.env`, gitignored) | `SPLUNK_AO_O11Y_TOKEN` — an Observability Cloud **INGEST** token, usually the same value as `O11Y_INGEST` |
| Console | `https://app.us1.signalfx.com/#/agent-obs` | browser address bar |

Box `demobot-N` serves `medadviceN.yeackbot.com`. Find its IP — never hand-derive it:

```bash
./deploy/ec2/fleet.sh status
```

SSH is `ubuntu@<ip>` port 22 with `~/.ssh/demobot_ec2`. (The *shared lab* box
from `[[pseudoco-assistant-ec2-deployment]]` is `splunk`@2222 — different machine, different
convention. See `[[pseudoco-assistant-gpu-fleet]]`.)

## Step 0 — is it already wired?

Almost always the answer on a fleet box is **yes**, because `push-replica.sh`
ships the Mac's `.env` verbatim and the Mac carries the `SPLUNK_AO_*` keys.
Check before changing anything (the token line is redacted, never printed):

```bash
# on the Mac
cd /Applications/DemoBot && grep '^SPLUNK_AO_' .env | sed 's/\(TOKEN=\).*/\1<redacted>/'

# on a fleet box
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> \
  "grep '^SPLUNK_AO_' ~/DemoBot/.env | sed 's/\(TOKEN=\).*/\1<redacted>/'"
```

Want:

```
SPLUNK_AO_REALM=us1
SPLUNK_AO_O11Y_TOKEN=<redacted>
SPLUNK_AO_PROJECT=PseudoCo Assistant
SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant
```

If those four are present and correct, skip to **Step 3 (verify)**. If
`SPLUNK_AO_PROJECT` / `SPLUNK_AO_AGENT_STREAM` name the wrong target, those are
the only values you need to change — everything else is already in place.

While you are in there, also run `grep -n '^GALILEO_PROJECT=\|^GALILEO_LOG_STREAM=' .env`
and expect **no output** — stale lines from the old integration silently
override the SDK (see Gotchas).

> **Token scopes (verified 2026-09-08 on this Mac):** the INGEST token is accepted by
> `/v2/trace/otlp` (traces land, `export=healthy`) but is rejected by the `/ao/api`
> CRUD endpoints with **401**, and the read-only `O11Y_API` token gets **403** there.
> Consequences: (1) the app's session mapping (`start_session`) fails once, backs off
> 5 min and turns are logged **without sessions** — that is expected until an API
> token with Agent Observability access is set as `SPLUNK_AO_O11Y_API_TOKEN`;
> (2) the API verification below needs such a token too — without it, verify in the
> console instead.

## Step 1 — look at the project and agent stream (nothing to create)

The project and the agent stream are **created on first ingest**. An empty
listing before the first chat turn is normal, not a misconfiguration — this
replaces the old "the project must already exist / won't auto-create" trap, so
do not go to the console to create anything first. To see what is there, use
the Agent Observability API with an Observability Cloud token in `X-SF-Token`
(`O11Y_API` works, and so does the ingest token):

```bash
cd /Applications/DemoBot
export T=$(grep '^O11Y_API=' .env | cut -d= -f2-)

# project id by name
curl -s "https://app.us1.observability.splunkcloud.com/ao/api/projects?project_name=PseudoCo Assistant&type=gen_ai" -H "X-SF-Token: $T"

# its agent streams (the API calls them log_streams)
curl -s "https://app.us1.observability.splunkcloud.com/ao/api/v2/projects/<id>/log_streams" -H "X-SF-Token: $T"
```

Note the three hosts: the **console** is `app.us1.signalfx.com/#/agent-obs`,
the **API** is `app.us1.observability.splunkcloud.com/ao/api/...`, and
**ingest** is `ingest.us1.observability.splunkcloud.com/v2/trace/otlp`. All of
them follow from the realm; the SDK and the collector overlay both build the
ingest URL from `SPLUNK_AO_REALM`.

## Step 2 — point the box at the project

Edit the **Mac's** `/Applications/DemoBot/.env` so every future replica inherits
it, then re-push. Editing only the box is fine for a hotfix but is lost on the
next `push-replica.sh`.

```
SPLUNK_AO_REALM=us1
SPLUNK_AO_O11Y_TOKEN=<Observability Cloud INGEST token — usually the O11Y_INGEST value>
SPLUNK_AO_PROJECT=PseudoCo Assistant
SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant
```

The token is explicit: there is **no fallback to `O11Y_INGEST`**. Both paths key
off `SPLUNK_AO_O11Y_TOKEN` alone, so it has to be set even though it usually
holds the same value.

Then confirm the two consumers are wired — on a current box both already are,
this is the checklist for a box built from an older bootstrap:

1. **`run-collector.sh`** exports the four `SPLUNK_AO_*` keys from `.env`
   (`SPLUNK_AO_REALM`, `SPLUNK_AO_O11Y_TOKEN`, `SPLUNK_AO_PROJECT`,
   `SPLUNK_AO_AGENT_STREAM`), layers `otel-collector-agent-obs.yaml` with a
   second `--config` only when the token is set, prints
   `Agent Observability trace fan-out: on -> ingest.us1.observability.splunkcloud.com (project=PseudoCo Assistant, agent stream=PseudoCo Assistant)`,
   *and* passes the keys on the container-fallback `run` line with exactly:
   ```
     -e SPLUNK_AO_REALM -e SPLUNK_AO_O11Y_TOKEN -e SPLUNK_AO_PROJECT -e SPLUNK_AO_AGENT_STREAM \
   ```
   The overlay's `${env:...}` must always resolve, so export them even when empty.
2. **`otel-collector-agent-obs.yaml`** exists next to `otel-collector-config.yaml`
   with the `otlphttp/agent_obs` exporter and the `traces/agent_obs` pipeline;
   the `filter/genai_only` processor it references lives in the base config.
   Verbatim block: `reference/otel-agent-obs-pipeline.yaml`. Validate both files
   together with `./scripts/validate-collector-config.sh`.
3. The app venv has the SDK: `~/DemoBot/venv/bin/pip show splunk-ao` (0.8.0 known good; 0.4.0-0.6.x lose sessions on the capability_based role).

Ship and restart:

```bash
cd /Applications/DemoBot
./deploy/ec2/push-replica.sh --host <ip> --replica N     # or edit .env on the box
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> \
  'sudo systemctl restart pseudoco-assistant-collector pseudoco-assistant-app'
```

Restarting `pseudoco-assistant-app` drops in-memory chat sessions. Don't do it mid-demo.

## Step 3 — verify

Never verify from an idle box — both paths only move on a real chat turn. Drive
one through the public tunnel. `/api/*` is access-key protected via HTTP Basic
(`./deploy/ec2/fleet.sh urls` prints the key):

```bash
curl -s -u "x:<ACCESS_KEY>" -X POST https://medadviceN.yeackbot.com/api/chat/message \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"agent-obs-verify-'"$(date +%s)"'","message":"What can I take for a mild headache?","disclaimer_accepted":true}' \
  -w '\nHTTP %{http_code}\n' | tail -c 200
```

Then check all three layers. Any one alone can lie.

```bash
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> 'sleep 15
  # Path B — collector counters. Want a nonzero otlphttp/agent_obs line and no send_failed.
  curl -s http://localhost:8888/metrics \
    | grep -E "otelcol_(exporter_(sent|send_failed)_spans|processor_filter_spans_filtered)"

  # Path A — SDK. Want "logged turn (... project=PseudoCo Assistant, agent_stream=PseudoCo Assistant, export=healthy)".
  sudo journalctl -u pseudoco-assistant-app --since "5 minutes ago" --no-pager | grep -i "agent observability" | tail -4

  # collector-side rejections, if any
  sudo journalctl -u pseudoco-assistant-collector --since "5 minutes ago" --no-pager | grep -iE "agent_obs|error"'
```

A healthy result looks like:

```
otelcol_exporter_sent_spans{exporter="otlphttp/agent_obs",server_address="ingest.us1.observability.splunkcloud.com",url_path="/v2/trace/otlp"} 20
otelcol_processor_filter_spans_filtered{filter="filter/genai_only"} 199
... backend.agent_observability - INFO - agent observability: logger ready (realm=us1, project=PseudoCo Assistant, agent_stream=PseudoCo Assistant)
... backend.agent_observability - INFO - agent observability: logged turn (model=..., agents=1, project=PseudoCo Assistant, agent_stream=PseudoCo Assistant, export=healthy)
```

`logger ready` is printed once, at first use after a start; `logged turn` once
per chat turn. The `filter_spans_filtered` count being far larger than the sent
count is normal — roughly 90% of spans are HTTP noise.

Finally, close the loop from Agent Observability's own side rather than
trusting a 200 (`<id>` / `<stream_id>` from Step 1):

```bash
cd /Applications/DemoBot && export T=$(grep '^O11Y_API=' .env | cut -d= -f2-)
curl -s -X POST "https://app.us1.observability.splunkcloud.com/ao/api/v2/projects/<id>/traces/search" \
  -H "X-SF-Token: $T" -H 'Content-Type: application/json' \
  -d '{"log_stream_id":"<stream_id>","limit":5}'
```

The newest trace should be within seconds of the turn you just sent. In the
console (`https://app.us1.signalfx.com/#/agent-obs`):
**Agent Observability > PseudoCo Assistant > Agent Stream: PseudoCo Assistant**.

## Gotchas

- Header keys on the collector exporter — and on the SDK — are fixed:
  `X-SF-Token`, `project`, `logstream`. `logstream` is the SDK's own header key
  for the agent stream, not a leftover to "fix". Only the values come from env.
- Both paths are keyed off `SPLUNK_AO_O11Y_TOKEN` being non-empty, with no
  fallback to `O11Y_INGEST`. Blanking it turns the whole integration off
  silently — that is the intended kill switch.
- Stale `GALILEO_PROJECT` / `GALILEO_LOG_STREAM` lines in `.env` silently
  override `SPLUNK_AO_PROJECT` / `SPLUNK_AO_AGENT_STREAM` through the SDK's
  compatibility bridge — delete them. (The Agent Control guardrail's
  `AGENT_CONTROL_*` / `GALILEO_AGENT_CONTROL_*` settings are a different
  integration and stay.)
- Path A is one `SplunkAOLogger` per process on a worker thread — an Agent
  Observability outage costs nothing at the app layer, so "the demo works" is
  not evidence that anything is being received. `export=healthy` in the log
  line is.
- `otlphttp` warns as a deprecated alias (`otlp_http`) on otelcol-contrib 0.157.0.
  Harmless; don't "fix" it and break the config on older binaries.
- Restarting `pseudoco-assistant-collector` resets the `:8888` counters to zero. A zero after
  a restart proves nothing until you send a turn.

## Applied instances

| Tunnel | EC2 | Project | Agent stream | Verified |
|---|---|---|---|---|
| medadvice1.yeackbot.com | (same instance) | `PseudoCo Assistant` | `PseudoCo Assistant` | re-verify after migration |
