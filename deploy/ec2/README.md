# EC2 replica deployment

The Linux counterpart to `deploy/launchd/` (which runs PseudoCo Assistant on the Mac).
Both produce the same thing: a host serving `https://medadvice.yeackbot.com` as
a replica of the **same named Cloudflare tunnel**, with its own telemetry
identity.

```bash
# single box, existing shared tunnel
./deploy/ec2/push-replica.sh --host 35.175.173.5 --replica 2

# GPU fleet in your own AWS account — COUNT IS ALWAYS EXPLICIT, never defaulted
./deploy/ec2/gen-access-keys.sh N
FLEET_COUNT=N ./deploy/ec2/fleet.sh preflight
FLEET_COUNT=N ./deploy/ec2/fleet.sh provision
./deploy/ec2/fleet.sh deploy
SCHED_TZ=America/Los_Angeles ./deploy/ec2/schedule.sh install
```

The `spin-up-ec2` skill (`.claude/skills/spin-up-ec2/`) walks this end to end
and **always asks how many instances first**.

| File | Runs on | Purpose |
|---|---|---|
| `push-replica.sh` | Mac | assembles the secret payload, ships it, invokes the bootstrap |
| `ec2-bootstrap.sh` | EC2 target | installs and configures everything; consumes the payload |
| `fleet.sh` | Mac | provisions and deploys N GPU instances, one subdomain each |
| `gen-access-keys.sh` | Mac | per-replica four-word `ACCESS_KEY` values (gitignored file) |
| `schedule.sh` | Mac | EventBridge start/stop schedules so the fleet isn't billed 24/7 |

---

## Why two scripts

`ec2-bootstrap.sh` can build 90% of a replica unaided — packages, Python 3.11,
Ollama, the repo, the venv, the collector binary, the systemd units. All of that
is public and fetchable.

The remaining 10% is **secrets, and secrets only exist on the Mac**:

- `.env` — API keys for Anthropic, Cisco AI Defense, Splunk O11y, Splunk Agent Observability, Agent Control
- the Cloudflare tunnel credentials JSON
- `Modelfile.poisoned` — the poisoned-model recipe, deliberately not in git

There is no way for a fresh EC2 box to obtain these on its own. `push-replica.sh`
is the bridge. The bootstrap refuses to run without a complete payload rather
than starting a half-configured replica that looks healthy and silently exports
nothing.

> A secrets manager (AWS Secrets Manager, SSM Parameter Store) would remove the
> Mac from the loop and let a box bootstrap itself from an instance profile.
> That is the right answer for anything beyond a demo. For a handful of workshop
> replicas, `scp` from the machine that already holds the secrets is simpler and
> has no standing cloud-side secret to rotate.

---

## What the bootstrap handles that you used to do by hand

### Models are derived from `.env`, not hard-coded

The old script pulled `mistral-nemo:12b` and stopped, so `llama3.2:3b` — the model
every internal coordinator and specialist agent runs on — had to be pulled by
hand on each box. Forgetting it did not fail at boot; it failed on the first
chat turn, mid-demo.

The bootstrap now reads **every** `OLLAMA_MODEL*` key out of `.env` and pulls
each one:

```
OLLAMA_MODEL=mistral-nemo:12b                 ->  pulled
OLLAMA_MODEL_INTERNAL=llama3.2:3b        ->  pulled
OLLAMA_MODEL_JUDGE=...                   ->  pulled, no script change needed
```

Adding an internal agent is therefore a `.env` edit, and every replica picks it
up on its next push.

### The poisoned model is built, always

`mistral-nemo:12b-poisoned` exists in no registry — `ollama pull` cannot fetch it. It
is a `FROM mistral-nemo:12b` overlay whose TEMPLATE injects a prescribing directive
*after* the application's own system prompt, and it is the exhibit the whole
guardrail-failure demo rests on.

The bootstrap builds it every run:

1. reads the `FROM` line to find the base model, and pulls that base first
   (`ollama create` needs it resident)
2. `ollama create <tag> -f Modelfile.poisoned`
3. the tag comes from `.env` if any `OLLAMA_MODEL*` value contains `poisoned`,
   else defaults to `mistral-nemo:12b-poisoned`

`push-replica.sh` sources the Modelfile from `deploy/ec2/Modelfile.poisoned` or
`~/Modelfile.poisoned`, and if neither exists exports it from the Mac's live
Ollama with `ollama show --modelfile`. One canonical recipe, byte-identical on
every replica.

> This matters more than it looks. As of 2026-07-27 the Mac's poisoned model was
> `b5eec43102c3` and the EC2's was `d22293974766` — two *different* models
> behind one demo, because each was built by hand at a different time. Building
> from a single Modelfile removes that drift.

If `ollama show --modelfile` emits `FROM /path/to/blob` instead of a tag (it
sometimes does), `push-replica.sh` rewrites it to the base tag — a blob path is
meaningless on another host.

### Tunnel config is rewritten, not copied

The Mac's `~/.cloudflared/config.yml` points at a Mac path:

```yaml
credentials-file: /Users/myeack/.cloudflared/52a942e8-….json
```

Copied verbatim to Linux, `cloudflared` starts, fails to find the credentials,
and the unit restart-loops. The bootstrap copies the file **verbatim except that
one line**, which it rewrites to the target's `$HOME`, then asserts the rewrite
took. Ingress rules, tunnel ID, and protocol carry over untouched, so the Mac
stays the single source of truth for the site config.

**`cert.pem` is never copied.** It is the Cloudflare *account* credential and
can create, route, and delete tunnels across the zone. A replica only runs
`cloudflared tunnel run`, which needs the per-tunnel credentials JSON and
nothing else. `push-replica.sh` refuses to stage it; the bootstrap warns if it
finds one. The visible symptom of doing this correctly is that
`cloudflared tunnel list` fails on a replica — expected, not a fault.

The payload is deleted from the target once the bootstrap finishes.

---

## `deployment.environment` — the one value that must differ per replica

```
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=pseudoco-assistant-ec2-2
```

`OTEL_RESOURCE_ATTRIBUTES` is a comma-separated list of OpenTelemetry **resource
attributes** — facts about the emitting process, attached to every span and
metric it produces. `deployment.environment` is the standard attribute for
"which deployment of this service is this," and it is the *only* thing
distinguishing one PseudoCo Assistant replica from another downstream. Everything else —
`service.name=pseudoco-assistant`, the ingest token, the realm, the tunnel — is
identical across replicas by design.

Current allocation:

| Host | Value |
|---|---|
| Mac, `/Applications/DemoBot` | `pseudoco-assistant-local` |
| EC2 `i-0883a0ddedf54e4e8` | `pseudoco-assistant-ec2-1` |
| next replica | `pseudoco-assistant-ec2-2`, … |

### Why a collision is worse than it sounds

Cloudflare load-balances across every connected replica, so a single user's
session can hop between hosts. If two replicas share a `deployment.environment`:

- **Splunk O11y** merges them into one apparent service. Latency and token-usage
  charts average two hosts together, so one sick replica hides behind a healthy
  one — exactly the failure the observability demo exists to make visible.
- **Agent Observability** files both hosts' traces into one agent stream, so a poisoned-model
  turn on box 2 is indistinguishable from a clean turn on box 1.
- Per-replica alerting becomes impossible: you cannot write "box 2's error rate
  spiked" if box 2 has no distinct identity.

Splitting by `host.name` afterwards does not rescue this — the demo's saved
views, detectors, and Agent Observability agent stream all filter on
`deployment.environment`.

### How the bootstrap sets it

The value arrives from the Mac saying `pseudoco-assistant-local` and must be rewritten. The
bootstrap rewrites **only** the `deployment.environment` key inside the list,
preserving any sibling attributes:

```
deployment.environment=pseudoco-assistant-local,service.version=3.0.0
   ->  deployment.environment=pseudoco-assistant-ec2-2,service.version=3.0.0
```

It adds the key if absent, and leaves the other ~50 `.env` lines byte-identical.

Three ways to choose the value:

| Invocation | Result | Use when |
|---|---|---|
| `--replica 2` | `pseudoco-assistant-ec2-2` | normal — matches the naming convention |
| `--env-name pseudoco-assistant-ec2-lab` | verbatim | one-off or non-numbered box |
| neither | `pseudoco-assistant-ec2-<instance-id>` from IMDS | unattended builds; guaranteed unique, ugly but collision-proof |

The numbered convention is human-readable but relies on you remembering which
numbers are taken. The IMDS default trades readability for a guarantee. Pick
per situation; the bootstrap prints the value it settled on and echoes it again
in the final summary.

### The Agent stream follows it, and a cloned `.env` is caught at start

An AI Trust dry run had three boxes reporting into one `demobot-ec2-1`: they
were built from one source and nothing tied the `.env` to the instance. The
bootstrap now hands the name to `deploy/box_identity.py assign`, which writes it
to **both** places a box is told apart and stamps the instance:

```
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=pseudoco-assistant-ec2-2
SPLUNK_AO_AGENT_STREAM=pseudoco-assistant-ec2-2
SPLUNK_AO_AGENT_STREAM_PER_THEME=False      # every turn of the box in its one stream
PSEUDOCO_ASSISTANT_BOX_ID=i-0883a0ddedf54e4e8
```

`--set SPLUNK_AO_AGENT_STREAM=…` or `--set SPLUNK_AO_AGENT_STREAM_PER_THEME=True`
still wins; they are applied after. Agent Control on the `splunk_ao` backend
binds controls to the stream a turn is logged to, so attach a box's controls to
*its* stream.

`run.sh` and `run-collector.sh` run `box_identity.py ensure` before they read
`.env`. When the stamp names a **different** instance — an AMI of a configured
box, a reused payload — the box renames itself to
`pseudoco-assistant-ec2-<instance-id>` (environment and stream) and logs
`box identity: cloned .env …`. An unstamped `.env` is adopted as-is (its name
may be hand-picked; renaming a working box would split its history), and off EC2
the check does nothing.

To give an existing box a name by hand (the fix for boxes already sharing one):

```bash
cd ~/DemoBot && git pull --ff-only
python3 deploy/box_identity.py assign --name pseudoco-assistant-lab-2
sudo systemctl restart pseudoco-assistant-collector pseudoco-assistant-app
python3 deploy/box_identity.py show
```

### Verifying the split

`tests/observability/verify_observability.sh` **hard-codes `pseudoco-assistant-local`** as
the environment (line 76), so tier 3 queries the wrong replica and fails on any
EC2 box even with a valid token. Run the checker directly instead — the
bootstrap prints this line for you, filled in:

```bash
python3 tests/observability/check_o11y_metadata.py \
    us1 "$(grep '^O11Y_API=' .env | cut -d= -f2-)" pseudoco-assistant pseudoco-assistant-ec2-2
```

Then confirm in Splunk O11y that the new value appears as its own environment
alongside `pseudoco-assistant-local`.

---

---

## GPU fleet mode

The original box was a `c6i.2xlarge` — CPU-only, and measured on live demo
traffic it was too slow for a workshop:

| Metric | c6i.2xlarge (measured) | g5.xlarge (A10G) expected |
|---|---|---|
| Decode | p50 **13.6 tok/s** | ~55–70 tok/s |
| Prefill | ~28 tok/s — **26 s for 729 tokens** | sub-second |
| Per-request total | p50 9.7 s, **p95 65 s**, max 101 s | a few seconds |

Prefill dominated, and prefill is exactly what a GPU collapses. Note also that
`c6i.2xlarge` advertises 8 vCPU but is **4 physical cores** — llama.cpp logged
`n_threads = 4`, because hyperthreads do not help inference.

### Replicas cannot be sticky — this is why each box gets its own tunnel AND subdomain

Cloudflare is explicit:

> "The load balancer does not distinguish between replicas of the same tunnel.
> If you run the same tunnel UUID on two separate hosts, the load balancer treats
> both hosts as a single endpoint."
> — [Public load balancers](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/public-load-balancers/)

Replicas also do no traffic steering at all: a request goes to the geographically
closest replica with no guarantee. Across N replicas of one tunnel a user lands
on a different box (N−1)/N of the time, and per-box SQLite means multi-turn
conversation history breaks.

`--own-tunnel` gives each host its own named tunnel (`demobot-N`) **and its own
subdomain**, derived from the shared hostname:

```
medadvice1.yeackbot.com ──CNAME──> <uuid-1>.cfargotunnel.com ──> box 1
medadvice2.yeackbot.com ──CNAME──> <uuid-2>.cfargotunnel.com ──> box 2
   …
medadvice.yeackbot.com  (no digit)  ──>  the Mac replica, untouched
```

The CNAME is created by `cloudflared tunnel route dns` — ordinary DNS on the
existing zone. **The URL is the session pin.** A user on `medadvice3` cannot
reach any other box, so affinity is structural rather than configured:

- no Load Balancing add-on ($5/mo for 2 origins + $5/mo each beyond, and
  session affinity possibly gated to Business plans — a dependency this design
  simply doesn't have)
- per-box SQLite is fine by construction, not by cookie TTL
- per-box demo states become possible: one box on `mistral-nemo:12b`, another on
  `mistral-nemo:12b-poisoned` (via the `OLLAMA_MODEL` override), shown side by side
  in the same workshop session

The trade is failover: a dead box takes down its own subdomain (Cloudflare 1033)
until its group is pointed at a spare. For assigned workshop groups that is an
acceptable, explicit failure — one URL down, blast radius one group.

### Per-replica .env overrides

The `.env` ships from the Mac identical to every box; a few keys must differ.
`push-replica.sh` writes them to `overrides.env` inside the payload (a file, not
argv — `ps` exposes argv to every user on the box), and the bootstrap applies
them as a map, preserving key order and leaving every untouched line
byte-identical:

| Key | Source | Why per-box |
|---|---|---|
| `deployment.environment` + `SPLUNK_AO_AGENT_STREAM` | `--replica N` → `pseudoco-assistant-ec2-N` (both) | telemetry split in O11y and Agent Observability |
| `ACCESS_KEY` | `deploy/ec2/access-keys.env` via `gen-access-keys.sh` | per-group credential, rotatable alone |
| `OLLAMA_MODEL` (optional) | `--set OLLAMA_MODEL=…` | clean-vs-poisoned box splits |

`gen-access-keys.sh N` maintains the key file: four-word keys
(`goose-duck-shovel-blob` style, `secrets.choice` over a curated noun list),
mode 600, gitignored, idempotent — an existing replica's key is never silently
regenerated; `--rotate N` replaces exactly one. PseudoCo Assistant itself has no
generator: `backend/config.py` just reads `ACCESS_KEY` from `.env` at startup,
so rotation requires an app restart and logs out that box's browser sessions
(cookie = sha256 of the key).

### GPU verification is not optional

A CPU fallback passes every health check and is ~5× slower — the likeliest way
to reach a workshop with a box that looks fine and is not. Always pass
`--gpu require` on a g5/g6 instance. The bootstrap then checks three things:

1. `nvidia-smi` returns a GPU
2. Ollama's startup log reports a CUDA backend
3. a model is warmed and `ollama ps` is read for actual placement — the decisive
   test, since the backend can be CUDA while a given model still sits on CPU

On GPU the bootstrap also raises `OLLAMA_MAX_LOADED_MODELS=3`,
`OLLAMA_KEEP_ALIVE=60m`, and `OLLAMA_NUM_PARALLEL=4`: all three models total
about 12 GB of the A10G's 24 GB, so nothing swaps and concurrency is cheap.

### Cost — per box; multiply by the count you choose

`g5.xlarge` is ~$1.006/hr in us-east-1:

| Per box | 8 h/weekday (~176 h/mo) | always-on |
|---|---|---|
| Compute | ~$177/mo | ~$734/mo |
| EBS (100 GB gp3, billed **even while stopped**) | ~$8/mo | ~$8/mo |
| Cloudflare CNAME | $0 | $0 |
| **Total** | **≈ $185/mo** | **≈ $742/mo** |

**The count is a run-time decision — `FLEET_COUNT` has no default, and
`provision` quotes the cost for the requested count before asking for "yes".**
`schedule.sh install` creates start, stop, **and a nightly safety-stop** — a
g5.xlarge left running is ~$24/day per box, so the backstop pays for itself the
first time an evening stop silently fails.

Quota is the gate: `g5.xlarge` is 4 vCPU of *Running On-Demand G and VT
instances* (`L-DB2E81BA`) each. New accounts default to **0** and approval takes
hours to days. `fleet.sh preflight` compares the quota against the requested
count and prints the exact increase request.

---

## Operational notes

- **Idempotent.** Re-run `push-replica.sh` to redeploy: it re-ships the current
  `.env`, re-pulls models, rebuilds the poisoned model, and restarts the units.
  It is the update path as well as the install path.
- **No `set -x`.** The original bootstrap ran under `set -euxo pipefail`, which
  echoed every line — including `.env` contents — to the console and any
  capturing log. Tracing is now opt-in with `DEBUG=1`.
- **Collector collision.** On the Splunk lab AMI an apt `splunk-otel-collector`
  is installed and binds the same `:4317`. The bootstrap masks it.
- **Python 3.11 is mandatory.** The venv is built with `python3.11` from
  deadsnakes; `python3 -m venv` picks Ubuntu 22.04's 3.10, on which LangChain
  1.x fails to install.
- **Sizing.** On a GPU box both models are VRAM-resident (~10.9 GB combined:
  `mistral-nemo:12b` at 8192 context plus `llama3.2:3b` at 4096). On a CPU-only
  box they sit in RAM instead, and below ~16 GB it thrashes between the 3B and
  12B models on every turn — which is why the fleet spec requires a GPU.
- **OpenClaw is not deployed here.** `run-openclaw.sh` needs podman, which these
  boxes do not have. It runs on the Mac only.

## NVIDIA options: local NIM and the NemoClaw runtime

```bash
# provider=nvidia = a NIM on THIS box (loopback :8000). Default image fits one A10G.
./ec2-bootstrap.sh --with-nim                                   # nvidia/nvidia-nemotron-nano-9b-v2
./ec2-bootstrap.sh --with-nim nvidia/nemotron-3-super-120b-a12b # needs 8x H100 (p5-class), not g5
# NemoClaw runtime (OpenClaw in an OpenShell sandbox, governed by /api/toolguard)
./ec2-bootstrap.sh --with-nemoclaw
```

`--with-nim` installs Docker + the NVIDIA Container Toolkit (the DL base AMI has
both), logs into `nvcr.io` with `NGC_API_KEY` (from `.env` or the payload
overrides), runs `pseudoco-assistant-nim.service` and sets `AI_PROVIDER=nvidia`,
`NVIDIA_BASE_URL`, `NVIDIA_MODEL` (an explicit `--set` still wins). First start
pulls the image + weights (minutes). `--with-nemoclaw` runs `run-nemoclaw.sh`
once (needs `NVIDIA_INFERENCE_API_KEY` in `.env` for the sandbox's provider) and
installs `pseudoco-assistant-nemoclaw` + `pseudoco-assistant-nemoclaw-forwarder` units — NemoClaw
restarts nothing after a reboot by itself. Units: `pseudoco-assistant-nim`,
`pseudoco-assistant-nemoclaw`, `pseudoco-assistant-nemoclaw-forwarder`. Details: `docs/nvidia-integration.md`.

### Fleet path (the normal way)

```bash
export FLEET_NIM=1 FLEET_NEMOCLAW=1 FLEET_VOLUME_GB=150   # + the usual FLEET_* config
./deploy/ec2/fleet.sh preflight     # confirms NGC_API_KEY / NVIDIA_INFERENCE_API_KEY are in this Mac's .env
./deploy/ec2/fleet.sh provision && ./deploy/ec2/fleet.sh deploy
```

`fleet.sh deploy` forwards `--with-nim [FLEET_NIM_MODEL]` and `--with-nemoclaw` to
`push-replica.sh`, which refuses to ship without the matching key in `.env`
(a personal `nvapi-…` key or a legacy NGC key; the keys ride in the payload,
never on argv, and `docker login nvcr.io` on the box is the real validation). Expect 25-45 minutes: the
NIM image (~10 GB) and weights (~18 GB) are pulled on first start, so the box
wants a 150 GB volume.

### What a NIM box does differently (fixed in 4.2.1)

- **The provider decision is made in step 3, before step 8 rewrites `.env`.** In
  4.2.0 the `AI_PROVIDER=nvidia` override was prepended *after* the rewrite, so a
  `--with-nim` box quietly booted on whatever `AI_PROVIDER` the Mac shipped.
  `tests/test_ec2_scripts.py` asserts the order.
- **Ollama holds no VRAM.** The Nemotron Nano NIM needs ~20 GB of the A10G's
  23 GB, and the standard fleet drop-in keeps ~11 GB of Ollama models resident.
  A NIM box gets `OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_KEEP_ALIVE=0`; the GPU
  warm-up check still runs (with its own 5-minute `keep_alive`), then the model
  is unloaded and `ollama ps` must be empty before `pseudoco-assistant-nim` starts. Ollama
  stays installed with every model pulled, so the box can switch back — **stop
  `pseudoco-assistant-nim` first**, or the Ollama model lands split CPU/GPU.
- **The NIM starts before the app** and is waited for (up to 40 minutes, progress
  every 30 s), so the app's startup catalog probe sees NIM READY. The final
  health gate includes `/v1/health/ready` and `/v1/models`: `BOOTSTRAP_OK` on a
  NIM box means the NIM is serving.
- **The NIM runs with 8 concurrent sequences, 0.95 GPU-memory utilization
  and 8192 tokens** (`NIM_MAX_NUM_SEQS`, `NIM_KVCACHE_PERCENT`, `NIM_MAX_MODEL_LEN`
  in `/etc/pseudoco-assistant-nim.env`, passed to the container; set any of them in the
  bootstrap's environment to change it).
  Nemotron Nano is a hybrid Mamba model: vLLM pre-allocates its SSM state cache
  for `max_num_seqs` (default 256), a flat 33.75 GiB that cannot sit next to
  17 GiB of weights on a 22 GiB A10G — the container OOM-loops without ever
  becoming ready, and the context cap alone does not help. vLLM's own profile
  line (`reserved for KV Cache is …GiB`) is the number to watch: 16 sequences at
  0.90 still left −0.69 GiB; 8 at 0.95 leaves ~1.5 GiB, ample for a model with
  only a few attention layers. 8192 is what the demo runs Ollama at.
- **NemoClaw prerequisites** (`binutils` for the installer's `strings` check,
  Node ≥ 22.19 from NodeSource) are installed by `--with-nemoclaw`; both keys are
  checked in the payload preflight (step 0), not twenty minutes in.
