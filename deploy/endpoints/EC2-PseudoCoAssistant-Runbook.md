# PseudoCo Assistant EC2 — Configuration Reference & Rebuild Runbook

**Captured:** 2026-07-27 from `i-0883a0ddedf54e4e8` (35.175.173.5)
**Revised:** 2026-08-11 — the instance was resized `c6i.2xlarge` → `g5.xlarge`
(NVIDIA A10G), its public IP changed to `54.196.13.169`, and the user-facing
synthesizer moved off `dolphin3:8b` to the approved open-weight
`mistral-nemo:12b`. Every figure below was re-measured on the resized box.
**Purpose:** document the running instance completely enough to rebuild it, or a
replica of it, from a raw EC2 instance.

---

## 1. Scope — what is actually reproducible

The instance runs two independent stacks. Only the second one is part of the
workshop deliverable.

| Layer | Origin | Reproducible on a raw EC2? |
|---|---|---|
| **A. Corporate base image** — CrowdStrike Falcon, Nessus agent, PBIS/AD join, fail2ban, ansible, SSM, CloudWatch agent, collectd, `AllowGroups` SSH policy | Cisco-managed AMI `ami-09860bb56ed1a5925` + Ansible | **No.** Comes from launching the same managed AMI in the same account. Not required for PseudoCo Assistant. |
| **B. Splunk Enterprise 10.4.1** (`/opt/splunk`, ports 8443/8089/8088) + Universal Forwarder | Pre-installed on the lab AMI | Optional. Independent of PseudoCo Assistant; PseudoCo Assistant exports to Splunk **Observability Cloud** (SaaS), not to this local Splunkd. |
| **C. PseudoCo Assistant workload** — Ollama, PseudoCo Assistant app, OTel collector, Cloudflare tunnel | Built 2026-07-27 by `~/ec2-bootstrap.sh` | **Yes, fully.** Section 6 rebuilds it end to end. |

If the goal is "another PseudoCo Assistant replica," you only need **§6**. Sections 2–5 are
the as-built record of this box.

---

## 2. AWS / instance facts

| Property | Value |
|---|---|
| Instance ID | `i-0883a0ddedf54e4e8` |
| Instance type | `g5.xlarge` (4 vCPU, 16 GiB RAM) — resized from `c6i.2xlarge` on 2026-08-11 |
| GPU | **NVIDIA A10G**, 23028 MiB VRAM, driver `580.173.02`. Installed *after* the resize — the Cisco base AMI ships no GPU driver |
| AMI | `ami-09860bb56ed1a5925` (Ubuntu 22.04.5 LTS, jammy) — unchanged by the resize |
| Kernel | `6.8.0-1061-aws`, x86_64 |
| Region / AZ | `us-east-1` / `us-east-1a` |
| Private IP | `172.31.27.241` |
| Public IP | `54.196.13.169` (was `35.175.173.5`; changed with the stop/start) |
| Security group | `SOAR-Hunter-Lab` |
| IAM instance profile | `aws_cloudwatch_role_for_ec2` (acct `754184243988`) |
| Root volume | 100 GiB gp3, ext4, single partition + 106 MB EFI. 61 GB used (63%) |
| Swap | none |
| Hostname | `show-demo-i-0883a0ddedf54e4e8` |
| Timezone | `Etc/UTC`, chrony synced |

**Sizing note.** Inference has been **GPU-resident since the 2026-08-11 resize**.
Both models load at 100% GPU — never a CPU split — for a combined **10.9 GB of
the A10G's 23 GB**: `mistral-nemo:12b` at 8.3 GB (8192 ctx) plus `llama3.2:3b` at
2.6 GB (4096 ctx). That leaves ~12 GB of headroom, so the poisoned variant can
also be resident without eviction.

Host RAM is no longer the binding constraint now that the weights live in VRAM,
but keep ≥16 GiB for Splunk Enterprise plus the app.

Measured on this box, 2026-08-11 (`mistral-nemo:12b`, 8192 ctx):

| | Measured |
|---|---|
| Decode | **58–60 tok/s** |
| Prefill | **2767 tok/s** (727-token prompt in 0.26 s) |
| Full generation, ~270 tokens | ~5 s |

A CPU-only rebuild still *works* but is not demo-viable: the predecessor
`c6i.2xlarge` measured 13.6 tok/s on the smaller 8B model, and a 12B model on CPU
is slower still. Treat the GPU as required, not optional — see §8.

### Ports that must be reachable

| Port | Bind | Purpose | Exposure needed |
|---|---|---|---|
| 2222 | `0.0.0.0` | SSH (non-standard port) | inbound from admin IPs |
| 8001 | `0.0.0.0` | PseudoCo Assistant / uvicorn | **not** publicly required — Cloudflare tunnel is outbound-only |
| 11434 | `127.0.0.1` | Ollama | local only |
| 4317 / 4318 | `0.0.0.0` | OTel collector OTLP gRPC / HTTP | local only |
| 8888 | `127.0.0.1` | Collector self-metrics | local only |
| 8443 / 8089 / 8088 | `0.0.0.0` | Splunk Enterprise web / mgmt / HEC | only if keeping layer B |

Outbound egress required: `*.signalfx.com`,
`ingest.us1.observability.splunkcloud.com` (Agent Observability),
`app.us1.observability.splunkcloud.com` (its API, verification only),
`api.multitenant.galileocloud.io` + `agent-control.multitenant.galileocloud.io`
(Agent Control only),
`*.argotunnel.com` / Cloudflare edge, `ollama.com`, `github.com`,
`us.api.inspect.aidefense.security.cisco.com`.

`ufw` is **inactive**. The only iptables rule is a fail2ban chain on 22/2222.
Network policy is enforced entirely by the AWS security group.

---

## 3. Users, access, and SSH

```
splunk:x:1003:1004  /home/splunk  /bin/bash   groups: splunk, wheel, ollama
ubuntu:x:1000:1000  (cloud-init default)
ansible:x:1001:100  (config management)
ssm-user:x:1002:1003 (SSM Session Manager)
```

PseudoCo Assistant runs entirely as **`splunk`**. That user needs:
- membership in `wheel` (passwordless sudo via `/etc/sudoers.d/wheel`) — also
  granted directly by `/etc/sudoers.d/splunk` and `/etc/sudoers.d/newuser`
- membership in `ollama` (created by the Ollama installer)
- inclusion in sshd's `AllowGroups` list

`/etc/ssh/sshd_config` — the non-default settings:

```
Port 2222
LogLevel VERBOSE
PasswordAuthentication yes          # inherited from 60-cloudimg-settings.conf
PubkeyAuthentication yes
Banner /etc/ssh/banner
AllowGroups sg-it-scip-dvo sg-it-scip-dvo-awf ssg-its-nspire-platform-services-all \
            sg-srv-rpa ssg-sgs-gso-splunkcirt-ic wheel ansible
```

> `AllowGroups` is the gate that matters: a new user cannot SSH in unless it is
> in one of those groups. `splunk` gets in via `wheel`.

`/home/splunk/.ssh/authorized_keys` holds two keys:

| Comment | Type | Fingerprint |
|---|---|---|
| `demo-migrate` | RSA 2048 | `SHA256:Fz9ftTJOHH4T0Asq7Z+bclNsIvWIGScqAKQqwjnvqUU` |
| `pseudoco-assistant-deploy` | ED25519 | `SHA256:lACYZxASafU0zNuZCY145FOUHf9wSqv31G4MC/gejms` |

The workstation-side private key for `pseudoco-assistant-deploy` is `~/.ssh/demobot_ec2`.

```bash
ssh -i ~/.ssh/demobot_ec2 -p 2222 splunk@54.196.13.169
```

---

## 4. Software inventory

### Installed outside the base image

| Component | Version | Path | Installed from |
|---|---|---|---|
| Python 3.11 | 3.11.15 | `/usr/bin/python3.11` | **deadsnakes PPA** (system default is 3.10.12) |
| Ollama | 0.32.4 | `/usr/local/bin/ollama` | `https://ollama.com/install.sh` |
| cloudflared | 2026.7.3 | `/usr/local/bin/cloudflared` | GitHub `.deb` release |
| otelcol-contrib | (415 MB binary) | `~/DemoBot/bin/otelcol-contrib` | GitHub release tarball |
| AWS CLI | — | `/usr/local/bin/aws` | base image |
| Splunk Enterprise | 10.4.1 (5a009d941268) | `/opt/splunk` | base image |

Not present: `node`/`npm`, `podman`, `docker`, `sqlite3` CLI, `uv`.
The OpenClaw gateway (`run-openclaw.sh`) therefore **does not run on this box** —
it needs podman. It runs only on the Mac replica.

### APT sources added

```
deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu/ jammy main
deb https://ppa.launchpadcontent.net/ansible/ansible/ubuntu/ jammy main
deb https://splunk.jfrog.io/splunk/otel-collector-deb release main
```

The apt-installed `splunk-otel-collector` service is **masked and inactive** —
PseudoCo Assistant uses its own `otelcol-contrib` binary instead. Leave it masked; two
collectors fighting over :4317 is a common failure mode here.

### Ollama models

| Model | ID | Size on disk | Role |
|---|---|---|---|
| `mistral-nemo:12b` | `e7e06d107c6c` | 7.1 GB | user-facing synthesizer (clean) |
| `mistral-nemo:12b-poisoned` | `92e606f8c363` | 7.1 GB | demo variant with an injected prescribing directive |
| `llama3.2:3b` | `a80c4f17acd5` | 2.0 GB | internal coordinator/specialist agents |

`dolphin3:8b` was removed on 2026-08-11 and is not to be reintroduced —
`mistral-nemo:12b` (Apache 2.0) is the approved open-weight replacement. The
poisoned variant reuses the clean model's weight layer, so the two 7.1 GB rows
are **not** additive on disk.

`mistral-nemo:12b-poisoned` is built from the canonical recipe now tracked **in
the repo** at `models/mistral-nemo-12b-poisoned.Modelfile` (`FROM
mistral-nemo:12b`). Its `TEMPLATE` places the prescribing directive after the
user content but still *inside* the final `[INST]` block, so it stays the last
instruction before generation and the app's own safety system prompt cannot
neutralise it. **This is the workshop's guardrail-failure exhibit; it is not a
stock model and must be rebuilt with `ollama create`, not pulled.**

> **Stale recipe on this box.** `/home/splunk/Modelfile.poisoned` (dated
> 2026-07-27) is the **old dolphin ChatML recipe**, left in place after the swap
> and no longer used. It was briefly a live hazard: `push-replica.sh` searched
> only `$REPO/deploy/ec2/Modelfile.poisoned` then `$HOME/Modelfile.poisoned`,
> neither of which is where the new canonical recipe lives — so a push from this
> box rebuilt a **dolphin-based** poisoned model onto an otherwise all-Mistral
> replica. Fixed 2026-08-11: the script now searches
> `models/<tag>.Modelfile` first and aborts if the resolved `FROM` is not
> `mistral-nemo:12b`. Deleting the stale file is still tidy, but it can no
> longer win.

Systemd drop-in `/etc/systemd/system/ollama.service.d/keepalive.conf`:

```ini
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_KEEP_ALIVE=30m"
```

### Python environment

`~/DemoBot/venv` built on **python3.11** (not the system 3.10 — LangChain 1.x
requires it). 102 packages; pinned by `requirements.txt`. Load-bearing ones:

```
fastapi 0.109.0 / uvicorn 0.27.0 / starlette 0.35.1
langchain 1.3.2 / langgraph 1.2.2 / langchain-ollama 1.1.0 / langchain-anthropic 1.4.6
anthropic 0.109.2 / openai 2.43.0 / ollama 0.6.2
opentelemetry-* 1.38.0 (sdk/api/exporters), instrumentation 0.59b0
splunk-opentelemetry 2.8.0
splunk-otel-util-genai 0.1.14 / splunk-otel-genai-emitters-splunk 0.1.8
splunk-otel-instrumentation-langchain 0.1.14   # present but DISABLED at runtime
splunk-ao 0.4.0 / galileo-core 4.5.0   # Agent Observability SDK
galileo 2.3.0   # legacy eval scripts only
SQLAlchemy 2.0.25
```

---

## 5. PseudoCo Assistant application configuration

### Layout

```
/home/splunk/
├── DemoBot/                     # git clone, branch main @ ef95063 (PR #48)
│   ├── .env                     # 0600, secrets — NOT in git
│   ├── venv/                    # python3.11
│   ├── bin/otelcol-contrib      # 415 MB, not in git
│   ├── medadvice.db             # SQLite, per-instance state + persisted settings
│   ├── models/mistral-nemo-12b-poisoned.Modelfile   # canonical poisoned recipe — IN git
│   ├── otel-collector-config.yaml
│   ├── run.sh  run-collector.sh  start-all.sh
│   └── logs/
├── .cloudflared/
│   ├── config.yml
│   └── 52a942e8-…-7865fc94c41b.json    # tunnel credentials — NOT in git
├── Modelfile.poisoned           # STALE dolphin-era recipe — superseded, see §4
└── ec2-bootstrap.sh             # the build script that produced this box
```

Repo: `https://github.com/mayeack/DemoBot.git`, `main` @ `ef95063` — the merge of
PR #48 `feat/mistral-nemo-fallback-free`, which carried the model swap. Working
tree clean as of 2026-08-11.

### `.env` — non-secret values (verbatim)

```ini
# --- AI provider: local open-weight model ------------------------------
AI_PROVIDER=ollama
OLLAMA_MODEL=mistral-nemo:12b
OLLAMA_MODEL_INTERNAL=llama3.2:3b
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_NUM_CTX=8192
OLLAMA_KEEP_ALIVE=30m
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929   # used when AI_PROVIDER=anthropic

# --- Cisco AI Defense guardrail ----------------------------------------
AI_DEFENSE_ENABLED=True
AI_DEFENSE_REGION=us
AI_DEFENSE_ENDPOINT=https://us.api.inspect.aidefense.security.cisco.com
AI_DEFENSE_TIMEOUT=30.0
AI_DEFENSE_FAIL_OPEN=False

# --- App / server ------------------------------------------------------
APP_NAME=PseudoCo Assistant v3
APP_VERSION=3.0.0
ENVIRONMENT=development
DEBUG=False
HOST=0.0.0.0
PORT=8001
DATABASE_URL=sqlite:///./medadvice.db
SESSION_TIMEOUT_MINUTES=30

# --- Logging -----------------------------------------------------------
LOG_LEVEL=INFO
LOG_TO_FILE=True
LOG_TO_CONSOLE=True
LOG_TO_DATABASE=True
LOG_ROTATION_SIZE=10485760
LOG_RETENTION_DAYS=90

# --- Governance demo injection rates (0 = toggles fully control) -------
PII_INJECTION_RATE=0
TOXIC_INJECTION_RATE=0
HALLUCINATION_INJECTION_RATE=0
AUTHORITY_INJECTION_RATE=0
REQUIRE_DISCLAIMER_ACCEPTANCE=True
MAX_CLARIFYING_QUESTIONS=3

# --- Splunk Observability Cloud ----------------------------------------
SPLUNK_REALM=us1
OTEL_ENABLED=True
OTEL_SERVICE_NAME=pseudoco-assistant
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=DELTA
OTEL_PYTHON_EXCLUDED_URLS=^(https?://)?[^/]+/health$
OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY
OTEL_INSTRUMENTATION_GENAI_EMITTERS=span_metric,splunk
OTEL_LOGS_EXPORTER=none
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=pseudoco-assistant-ec2-1   # <-- PER-REPLICA

# --- Splunk Agent Observability ---------------------------------------
SPLUNK_AO_REALM=us1
SPLUNK_AO_PROJECT=PseudoCo Assistant
SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant
# --- Agent Control ------------------------------------------------------
AGENT_CONTROL_CONSOLE_URL=https://console.multitenant.galileocloud.io
```

### `.env` — secrets (values withheld; copy from the Mac at `/Applications/DemoBot/.env`)

| Key | Notes |
|---|---|
| `ANTHROPIC_API_KEY` | only used if `AI_PROVIDER=anthropic` |
| `AI_DEFENSE_API_KEY` | Cisco AI Defense inspection key |
| `ACCESS_KEY` | HTTP Basic password gating public access — **required** when the tunnel is up |
| `O11Y_INGEST` | O11y **ingest** token, realm us1 |
| `O11Y_API` | O11y **API** token — ⚠️ currently expired (401), see §8 |
| `SPLUNK_AO_O11Y_TOKEN` | Agent Observability ingest token (an O11y INGEST token; same value as `O11Y_INGEST` here) |
| `AGENT_CONTROL_API_KEY` | Agent Control console API key (guardrail only) |

### The active model is set in **two** places — the database wins

This is the single most expensive gotcha on this box. `.env` supplies defaults;
a persisted override in SQLite is applied at startup and overrides them:

| Source | Where | Precedence |
|---|---|---|
| `.env` | `OLLAMA_MODEL`, `OLLAMA_MODEL_INTERNAL` | defaults only |
| `medadvice.db` | table `app_settings`, row `id=1`, JSON column `data` → key `ai_provider` = `{"provider": …, "model": …}` | **applied at startup, overrides `.env`** |

Editing `.env` and restarting `pseudoco-assistant-app` therefore *looks* like it worked —
the unit goes active, `.env` reads correctly — while the app keeps loading the
old model. Set it through `settings_store.set_ai_provider("ollama", "<model>")`,
which persists the row, re-applies it, and clears the LLM client cache (whose
keys omit the model name, so a stale client is served otherwise). Then restart.

**Authoritative check** — the pre-warm line, which runs *after* the override is
applied:

```bash
sudo journalctl -u pseudoco-assistant-app.service | grep "Pre-warmed Ollama model"
```

Expect one line per distinct model, alphabetically: `llama3.2:3b` then
`mistral-nemo:12b`. Calling `settings_store.get_ai_provider()` from a *separate*
process is **not** authoritative — it reads the `.env`-loaded settings singleton,
not the persisted row.

### `OTEL_RESOURCE_ATTRIBUTES` — the one value you must change per replica

Each replica sets a distinct `deployment.environment` so Splunk O11y and Agent Observability
can separate them:

- Mac (`/Applications/DemoBot`) → `pseudoco-assistant-local`
- this EC2 → `pseudoco-assistant-ec2-1`
- next replica → `pseudoco-assistant-ec2-2`, and so on

Everything else in `.env` is copied verbatim between replicas.

### Cloudflare tunnel

`~/.cloudflared/config.yml`:

```yaml
tunnel: 52a942e8-dddf-4a19-81fe-7865fc94c41b
credentials-file: /home/splunk/.cloudflared/52a942e8-dddf-4a19-81fe-7865fc94c41b.json
protocol: http2

ingress:
  - hostname: medadvice.yeackbot.com
    service: http://localhost:8001
  - service: http_status:404
```

**Architecture:** every host runs the *same named tunnel* (`medadvice`, id
`52a942e8-dddf-4a19-81fe-7865fc94c41b`) as a replica. Cloudflare load-balances
across whichever replicas are connected. Per-instance SQLite means sessions are
not shared between replicas — accepted for the demo.

Only the tunnel **credentials JSON** is copied to the boxes. The Cloudflare
account cert (`cert.pem`) stays on the Mac. Consequence: `cloudflared tunnel
list` / `create` / `route` fail on the EC2 with *"Cannot determine default origin
certificate path"* — this is expected and harmless. `tunnel run` works because it
only needs the credentials file.

### OTel collector pipelines (`otel-collector-config.yaml`)

Three pipelines off one OTLP receiver (:4317 gRPC, :4318 HTTP; the second only
when the agent-obs overlay is layered on):

| Pipeline | Processors | Exporter | Destination |
|---|---|---|---|
| `traces` | batch | `otlphttp/traces` | `https://ingest.us1.signalfx.com/v2/trace/otlp` (Splunk APM) — full traces incl. HTTP spans |
| `traces/agent_obs` (overlay `otel-collector-agent-obs.yaml`) | `filter/genai_only`, batch | `otlphttp/agent_obs` | `https://ingest.us1.observability.splunkcloud.com/v2/trace/otlp` + `project`/`logstream` headers — **gen_ai spans only** |
| `metrics` | batch | `signalfx` (`send_otlp_histograms: true`) | Splunk O11y metrics |

Two non-obvious settings, both load-bearing:

1. `send_otlp_histograms: true` — without it the GenAI histograms that Splunk AI
   Agent Monitoring depends on (`gen_ai.evaluation.score`, token usage) never
   ingest.
2. `filter/genai_only` drops spans without `gen_ai.operation.name` before the
   Agent Observability exporter, which rejects batches with no GenAI patterns, so
   unfiltered FastAPI HTTP spans cause partial-success drops.

### Instrumentation quirk

`run.sh` sets `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=langchain` before launching
under `opentelemetry-instrument`. The preview Splunk LangChain auto-instrumentor
reports the model as `"unknown"` and emits no AgentInvocation for
`create_react_agent`; the app emits GenAI entities itself in
`backend/telemetry/otel.py`. FastAPI instrumentation stays enabled.

### systemd units

Three units, all `User=splunk`, `Restart=always`, `RestartSec=5`, enabled:

| Unit | ExecStart | After |
|---|---|---|
| `pseudoco-assistant-collector` | `~/DemoBot/run-collector.sh` | `network-online.target` |
| `pseudoco-assistant-app` | `/bin/bash ~/DemoBot/run.sh` | `network-online`, `ollama`, `pseudoco-assistant-collector` |
| `pseudoco-assistant-tunnel` | `/usr/bin/cloudflared --config ~/.cloudflared/config.yml tunnel run medadvice` | `network-online`, `pseudoco-assistant-app` |

Plus `ollama.service` (installed by Ollama, `User=ollama`, `WantedBy=default.target`).

`pseudoco-assistant-app` sets `Environment=PATH=/home/splunk/DemoBot/venv/bin:/usr/local/bin:/usr/bin:/bin`
so `run.sh` finds `opentelemetry-instrument` in the venv.

---

## 6. Rebuild procedure — raw EC2 → working replica

### 6.0 Launch

Ubuntu 22.04 LTS, 100 GiB gp3 root. Security group: inbound TCP 22 (or 2222)
from admin IPs only; all egress allowed. No inbound rule is needed for 8001 —
the Cloudflare tunnel dials out.

**Take a GPU instance.** `g5.xlarge` (4 vCPU / 16 GiB / A10G 24 GB) is what this
box runs and what the fleet spec requires. A CPU-only `c6i.2xlarge` boots, passes
every health check in §7, and runs roughly **4× slower** — the most likely way to
arrive at a workshop with a broken box that looks fine. If the AMI ships no GPU
driver (the Cisco base image does not), install it before Ollama, and confirm
placement with `ollama ps` rather than trusting `nvidia-smi` alone.

### 6.1 Prepare the account

If not using the corporate AMI, create the service user (skip if `splunk` already
exists from the image):

```bash
sudo useradd -m -s /bin/bash splunk
echo 'splunk ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/splunk
sudo install -d -m700 -o splunk -g splunk /home/splunk/.ssh
sudo cp ~/.ssh/authorized_keys /home/splunk/.ssh/ && sudo chown splunk:splunk /home/splunk/.ssh/authorized_keys
```

If sshd has an `AllowGroups` line, add `splunk` to one of the listed groups
(`sudo usermod -aG wheel splunk`) **before** you disconnect — otherwise you lock
yourself out.

### 6.2 Run the deploy

From the **Mac**, inside the repo. One command builds the whole replica:

```bash
cd /Applications/DemoBot && ./deploy/ec2/push-replica.sh --host NEW_HOST --replica 2
```

Two scripts, both in `deploy/ec2/` (the Linux mirror of `deploy/launchd/`):

| Script | Runs on | Does |
|---|---|---|
| `push-replica.sh` | Mac | stages the secret payload, ships it, invokes the bootstrap |
| `ec2-bootstrap.sh` | target | installs and configures everything, starts, health-checks |

`push-replica.sh` assembles a payload of the four things a fresh box cannot
obtain on its own — `.env`, the Mac's `config.yml`, the tunnel credentials JSON,
and `Modelfile.poisoned` (exported from the Mac's live Ollama if no file exists)
— `scp`s them to `~/demobot-payload`, runs the bootstrap, and deletes the
payload afterwards. **`cert.pem` is never staged.**

`ec2-bootstrap.sh` is idempotent and arch-aware (x86_64 / aarch64):

1. base packages; `ppa:deadsnakes`; `python3.11` + venv + dev headers
2. `cloudflared` from the GitHub `.deb`
3. Ollama + the `OLLAMA_MAX_LOADED_MODELS=2` / `KEEP_ALIVE=30m` drop-in
4. clone PseudoCo Assistant, build the venv on 3.11, install requirements
5. `otelcol-contrib` binary; mask any apt `splunk-otel-collector` (:4317 clash)
6. install `.env` (0600) and tunnel credentials; rewrite `credentials-file:` in
   `config.yml` to the target's `$HOME`; warn if `cert.pem` is present
7. set `deployment.environment` (see §6.3)
8. **pull every model `.env` references**, then **build the poisoned model**
9. write the three systemd units
10. enable + start, then health-check all four endpoints

Flags: `--replica N`, `--env-name NAME`, `--stage-only`, `--no-start`,
`DEBUG=1` for tracing. Re-running is the update path as well as the install path.

### 6.3 What used to be manual, and now is not

The four post-bootstrap steps this runbook previously listed are automated. What
each one became:

| Was | Now |
|---|---|
| `ollama pull llama3.2:3b` by hand | every `OLLAMA_MODEL*` key in `.env` is pulled — adding an internal agent is a `.env` edit, not a script edit |
| `ollama create` the poisoned model by hand | built every run from one canonical `Modelfile.poisoned`, with its `FROM` base pulled first |
| `scp` secrets, hand-edit the Mac paths out of `config.yml` | `push-replica.sh` stages them; the bootstrap rewrites only the `credentials-file:` line and asserts the rewrite took |
| `sed` the replica number into `.env` | `--replica N` / `--env-name`, or an IMDS-derived unique default |

Full rationale for each in [`deploy/ec2/README.md`](../DemoBot/deploy/ec2/README.md).

> **Drift this fixes.** On 2026-07-27 the Mac's poisoned model was
> `b5eec43102c3` and the EC2's was `d22293974766` — two different models behind
> one demo, because each was built by hand at a different time.

**`deployment.environment` is still the one value that differs per replica**
(`pseudoco-assistant-local`, `pseudoco-assistant-ec2-1`, `pseudoco-assistant-ec2-2`, …). It is the only thing
separating replicas in Splunk O11y and Agent Observability — everything else, including
`service.name=pseudoco-assistant`, is identical by design. Two replicas sharing a value
merge into one apparent service, so a sick box hides behind a healthy one. The
bootstrap rewrites only that key inside `OTEL_RESOURCE_ATTRIBUTES`, preserving
sibling attributes.

### 6.4 Manual start (only with `--no-start`)

```bash
sudo systemctl enable --now pseudoco-assistant-collector pseudoco-assistant-app pseudoco-assistant-tunnel
systemctl --no-pager status pseudoco-assistant-collector pseudoco-assistant-app pseudoco-assistant-tunnel
```

Order matters on a cold box: the collector must own :4317 before the app starts,
or the app's first spans are dropped. The unit dependencies handle this.

---

## 7. Verification

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8001/health        # 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:11434/api/tags     # 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8888/metrics       # 200
curl -s -o /dev/null -w '%{http_code}\n' https://medadvice.yeackbot.com/health  # 200
ollama list  # expect mistral-nemo:12b, mistral-nemo:12b-poisoned, llama3.2:3b
ollama ps    # every loaded model must read 100% GPU — never a CPU split
```

All four returned `200` on this instance at capture time, and both models were
confirmed at 100% GPU on 2026-08-11.

Then confirm telemetry actually lands: in Splunk O11y (realm us1) filter on
`deployment.environment = pseudoco-assistant-ec2-N` and confirm the new replica appears
separately from `pseudoco-assistant-local`. Repo-side, `tests/observability/verify_observability.sh`
runs the same checks in tiers.

---

## 8. Known issues and gotchas

- **`O11Y_API` is expired** (401). It only affects tier 3 of
  `verify_observability.sh`, which queries O11y to confirm metrics landed. The
  *ingest* token (`O11Y_INGEST`) is valid and telemetry flows normally.
  See **§10** for the reissue procedure.
- **`cloudflared tunnel list` fails on EC2** — no `cert.pem` by design. Only
  `tunnel run` is supported on replicas. Not a fault.
- **Two collectors, one port.** The apt `splunk-otel-collector` package is
  installed (from the Splunk apt repo on the base image) and must stay masked;
  unmasking it collides with `otelcol-contrib` on :4317.
- **Python 3.10 will not work.** The venv must be built with `python3.11` from
  deadsnakes. `python3 -m venv` picks 3.10 and LangChain 1.x fails to install.
- **OpenClaw is Mac-only.** `run-openclaw.sh` requires podman, which is not
  installed here. Note also that Cisco Secure Endpoint quarantines host-installed
  OpenClaw and deletes working-tree copies of `openclaw/Containerfile` — hence
  the podman-based approach on the Mac.
- **Per-instance SQLite.** `medadvice.db` is local to each replica; conversation
  history does not follow a user across Cloudflare's load balancing. Accepted for
  the demo; would need Postgres (the `psycopg2-binary` dep is already present) to
  fix.
- **Silent CPU fallback.** Since the resize, inference must be GPU-resident. A
  box that has quietly fallen back to CPU passes every check in §7 and is ~4×
  slower. Verify with `ollama ps` (100% GPU) and
  `sudo journalctl -u ollama | grep -i cuda`, not with `nvidia-smi` alone.
  Keep-alive of 30m and `OLLAMA_MAX_LOADED_MODELS=2` avoid a cold reload between
  the internal 3B agents and the 12B synthesizer.
- **Editing `.env` alone does not change the model.** A persisted override in
  `medadvice.db` wins. See §5, "The active model is set in two places" — this
  cost real time on 2026-08-11.
- **`~/Modelfile.poisoned` is a stale dolphin recipe** — harmless since
  2026-08-11, when `push-replica.sh` started preferring the repo's
  `models/<tag>.Modelfile` and hard-failing on a base-model mismatch. Before
  that it silently won and shipped the wrong model. See §4.

---

## 9. Backup set — what is not in git

Losing these means the instance cannot be rebuilt from the repo alone:

1. `/Applications/DemoBot/.env` on the Mac (secrets — the source of truth that
   `push-replica.sh` ships to every replica)
2. `~/.cloudflared/52a942e8-dddf-4a19-81fe-7865fc94c41b.json` (tunnel credentials)
3. ~~`Modelfile.poisoned`~~ — **no longer a backup item.** The canonical recipe
   is tracked in the repo at `models/mistral-nemo-12b-poisoned.Modelfile`, and
   both `push-replica.sh` and `scripts/demo/build_poisoned_model.sh` build from
   it, so a fresh clone can rebuild the poisoned model with no live-Ollama
   export and nothing to restore.
4. Cloudflare account `cert.pem` — Mac only, never on a replica
5. `~/.ssh/demobot_ec2` on the workstation (access key)

The build scripts are now in the repo at `deploy/ec2/` and no longer need
separate backup.

`~/DemoBot/medadvice.db` is demo state and does not need backing up.

---

## 10. Reissuing `O11Y_API`

### What kind of token

Both consumers call `https://api.us1.signalfx.com` with an `X-SF-Token` header,
so this must be a token with **API authorization scope** — *not* an ingest token
(`O11Y_INGEST` is the ingest one and is a separate value).

| Consumer | Call | Minimum role |
|---|---|---|
| `tests/observability/check_o11y_metadata.py` | `GET /v2/metrictimeseries` | `read_only` |
| `scripts/observability/create_apm_detectors.py` | `POST` (creates detectors) | `power` |

Choose **`power`** so both work.

### Create it

In Splunk Observability Cloud — realm **us1**, `https://app.us1.signalfx.com`:

1. **Settings → Access Tokens → New Token**
2. Name it (e.g. `pseudoco-assistant-api`); **Authorization scope = API token**; select role
   **`power`**
3. Set visibility, then **set a long expiration date**. The default is 30 days —
   that is why the previous token expired. Max is 18 years.
4. **Create**, expand the token, **Show Token**, **Copy**

The same page mints the INGEST token that `SPLUNK_AO_O11Y_TOKEN` needs
(authorization scope = Ingest); `O11Y_INGEST` and `SPLUNK_AO_O11Y_TOKEN` may share
one token.

Creating org access tokens requires org admin. Alternatives:

- **Rotate** an existing token (Settings → Access Tokens → select → *Rotate
  token*) — only possible *before* it expires. Not an option for an already-dead
  token.
- Use a **personal user API access token** from your account settings: same
  header, no admin rights needed, but tied to your user account.

### Install it

Three places (Mac + each EC2 replica), same value.

Mac — BSD sed needs the empty `-i` argument:

```bash
cd /Applications/DemoBot && cp .env .env.bak && read -rs NEWTOK \
  && sed -i '' "s|^O11Y_API=.*|O11Y_API=${NEWTOK}|" .env \
  && grep -c '^O11Y_API=' .env
```

EC2 — GNU sed, no `''`:

```bash
cd ~/DemoBot && cp .env .env.bak && read -rs NEWTOK \
  && sed -i "s|^O11Y_API=.*|O11Y_API=${NEWTOK}|" .env \
  && chmod 600 .env && grep -c '^O11Y_API=' .env
```

`read -rs` keeps the secret out of shell history. Expect `1` from `grep -c`.

**No service restart is required.** `O11Y_API` is read only by the two
test/script files, at invocation, directly from `.env`. Neither `run.sh` nor
`run-collector.sh` references it — the live telemetry path uses
`O11Y_INGEST` and is unaffected.

### Verify

Test the token in isolation before blaming telemetry:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "X-SF-Token: $NEWTOK" \
  'https://api.us1.signalfx.com/v2/metrictimeseries?query=sf_metric:gen_ai.client.token.usage&limit=1'
```

`200` = good; `401` = wrong token or missing API scope. Then run the suite:

```bash
cd ~/DemoBot && ./tests/observability/verify_observability.sh
```

### Two script-side gotchas

- **`verify_observability.sh` hard-codes `pseudoco-assistant-local`** as the
  `deployment.environment` argument (line 76). On a replica whose environment is
  `pseudoco-assistant-ec2-N`, tier 3 queries the wrong replica and fails even with a good
  token. Run the checker directly instead:

  ```bash
  python3 tests/observability/check_o11y_metadata.py us1 "$NEWTOK" pseudoco-assistant pseudoco-assistant-ec2-1
  ```

- **A token containing `=` breaks tier 3.** Line 71 parses `.env` with
  `cut -d= -f2`, truncating at the first `=` (`run-collector.sh` correctly uses
  `-f2-`). Rare with Splunk tokens, but it explains a `curl`-succeeds /
  script-fails split.
