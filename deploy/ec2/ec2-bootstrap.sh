#!/bin/bash
# PseudoCo Assistant EC2 bootstrap — run as the service user (default 'splunk') on Ubuntu
# 22.04. Builds a complete, RUNNING replica: prereqs, Ollama + every model the
# .env asks for (including the locally-built poisoned model), PseudoCo Assistant, the OTel
# collector, the Cloudflare tunnel, and the systemd units.
#
#   ./ec2-bootstrap.sh                      # payload at ~/demobot-payload
#   ./ec2-bootstrap.sh --replica 2          # deployment.environment=pseudoco-assistant-ec2-2 (= Agent stream)
#   ./ec2-bootstrap.sh --env-name pseudoco-assistant-ec2-lab
#   ./ec2-bootstrap.sh --gpu require        # abort unless inference lands on the GPU
#   ./ec2-bootstrap.sh --num-parallel 4     # Ollama concurrent request slots
#   ./ec2-bootstrap.sh --set OLLAMA_MODEL=mistral-nemo:12b-poisoned   # .env override
#   ./ec2-bootstrap.sh --no-start           # install everything, don't start
#   ./ec2-bootstrap.sh --with-nim [model]   # + a LOCAL NVIDIA NIM on :8000, provider=nvidia
#   ./ec2-bootstrap.sh --with-nemoclaw      # + the NVIDIA NemoClaw sandbox runtime
#
# PER-REPLICA .env OVERRIDES: the .env shipped from the Mac is identical on every
# box; a few keys must differ. Overrides come from $PAYLOAD/overrides.env (one
# KEY=VALUE per line) and from repeatable --set flags, with --set winning.
# Secrets belong in overrides.env, NOT in --set: argv is visible to every user on
# the box via `ps`.
#
# GPU: --gpu auto (default) uses the GPU when nvidia-smi is present and warns if
# a detected GPU is not actually used; --gpu require turns that warning into a
# hard failure; --gpu off skips the checks for a CPU box. On a g5/g6 instance
# ALWAYS pass --gpu require: a silent CPU fallback still passes every health
# check and is ~5x slower, which is the single most likely way to arrive at a
# workshop with a box that looks fine and is not.
#
# SECRETS: this script does NOT invent secrets. It consumes a payload directory
# staged by deploy/ec2/push-replica.sh (run from the Mac), containing:
#     .env                 the Mac's .env, verbatim
#     config.yml           the Mac's ~/.cloudflared/config.yml, verbatim
#     <tunnel-id>.json     the named tunnel's credentials
#     Modelfile.poisoned   recipe for the guardrail-failure demo model
# The Cloudflare account cert.pem is deliberately NOT part of the payload and
# must never be copied to a replica (see step 6).
#
# Idempotent: safe to re-run. Re-running picks up an updated payload.
#
# NOTE: no `set -x`. The original bootstrap used `set -euxo pipefail`, which
# echoed every line — including .env contents — to the console and to any
# capturing log. Tracing is opt-in via DEBUG=1.
set -euo pipefail
[ "${DEBUG:-0}" = "1" ] && set -x

PAYLOAD="$HOME/demobot-payload"
ENV_NAME=""
REPLICA=""
START=true
GPU_MODE="auto"          # auto | require | off
NUM_PARALLEL=""
SETS=()
REPO_URL="https://github.com/mayeack/DemoBot.git"
REPO="$HOME/DemoBot"
# --with-nim [model]: run a LOCAL NVIDIA NIM (docker, :8000) and point
# provider=nvidia at it. Default model fits one A10G; nemotron-3-super-120b-a12b
# needs 8x H100 (p5-class). --with-nemoclaw: run the NVIDIA NemoClaw runtime
# (OpenClaw in an OpenShell sandbox) with PseudoCo Assistant's governance seat baked in.
WITH_NIM=false
NIM_MODEL="nvidia/nvidia-nemotron-nano-9b-v2"
WITH_NEMOCLAW=false

while [ $# -gt 0 ]; do
  case "$1" in
    --payload)   PAYLOAD="$2"; shift 2 ;;
    --env-name)  ENV_NAME="$2"; shift 2 ;;
    --replica)   REPLICA="$2";  shift 2 ;;
    --gpu)       GPU_MODE="$2"; shift 2 ;;
    --num-parallel) NUM_PARALLEL="$2"; shift 2 ;;
    --set)       SETS+=("$2");  shift 2 ;;
    --with-nim)  WITH_NIM=true
                 if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then NIM_MODEL="$2"; shift 2; else shift; fi ;;
    --with-nemoclaw) WITH_NEMOCLAW=true; shift ;;
    --no-start)  START=false;   shift ;;
    -h|--help)
      sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done
case "$GPU_MODE" in auto|require|off) ;; *) echo "--gpu must be auto|require|off" >&2; exit 2 ;; esac

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# apt on a fresh Ubuntu box races unattended-upgrades: it grabs the dpkg lock a
# few minutes after first boot, and a plain apt-get then dies with "Could not
# get lock /var/lib/dpkg/lock-frontend" (killed a deploy at step 9b on
# 2026-09-02, ~10 min in). Wait for the lock instead of failing.
wait_dpkg_lock() {
  local i
  for i in $(seq 1 120); do
    sudo fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || return 0
    [ "$i" -eq 1 ] && echo "  waiting for the dpkg lock (unattended-upgrades?) ..."
    sleep 5
  done
  warn "dpkg lock still held after 10 min — trying anyway"
}
apt_get() { wait_dpkg_lock; sudo -E apt-get -o DPkg::Lock::Timeout=600 "$@"; }

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  CF_ARCH=amd64; OTEL_ARCH=amd64 ;;
  aarch64) CF_ARCH=arm64; OTEL_ARCH=arm64 ;;
  *) die "unsupported arch $ARCH" ;;
esac

# --- 0. payload preflight --------------------------------------------------
# Fail here, loudly, rather than three minutes later with half a replica up.
[ -d "$PAYLOAD" ] || die "payload dir $PAYLOAD not found — run deploy/ec2/push-replica.sh from the Mac first"
for f in .env config.yml Modelfile.poisoned; do
  [ -f "$PAYLOAD/$f" ] || die "payload incomplete: $PAYLOAD/$f missing"
done
TUNNEL_ID=$(awk '/^tunnel:/{print $2; exit}' "$PAYLOAD/config.yml")
[ -n "$TUNNEL_ID" ] || die "no 'tunnel:' line in $PAYLOAD/config.yml"
[ -f "$PAYLOAD/$TUNNEL_ID.json" ] || die "payload incomplete: tunnel credentials $TUNNEL_ID.json missing"
# NVIDIA credentials travel inside the payload (.env or overrides.env), never
# argv. Check them here so a missing key fails before the 10-minute install.
# Shape only (personal nvapi-… keys and legacy 84-char NGC keys both work);
# `docker login nvcr.io` in step 9c is the real validation.
if [ "$WITH_NIM" = true ]; then
  grep -qsE '^NGC_API_KEY=[^[:space:]]{20,}$' "$PAYLOAD/.env" "$PAYLOAD/overrides.env" \
    || die "--with-nim needs NGC_API_KEY (personal nvapi-… or legacy NGC key) in the payload .env (image pull from nvcr.io)"
fi
if [ "$WITH_NEMOCLAW" = true ]; then
  grep -qsE '^NVIDIA_INFERENCE_API_KEY=[^[:space:]]{20,}$' "$PAYLOAD/.env" "$PAYLOAD/overrides.env" \
    || die "--with-nemoclaw needs NVIDIA_INFERENCE_API_KEY (an NGC key) in the payload .env (the sandbox's own inference provider)"
fi

# --- 1. base packages + Python 3.11 ---------------------------------------
# 3.11 from deadsnakes: Ubuntu 22.04 ships 3.10, on which LangChain 1.x fails.
log "base packages + Python 3.11"
export DEBIAN_FRONTEND=noninteractive
apt_get update -y
apt_get install -y git lsof curl jq software-properties-common
wait_dpkg_lock; sudo -E add-apt-repository -y ppa:deadsnakes/ppa
apt_get install -y python3.11 python3.11-venv python3.11-dev

# --- 2. cloudflared --------------------------------------------------------
log "cloudflared"
if ! command -v cloudflared >/dev/null; then
  curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}.deb" -o /tmp/cloudflared.deb
  sudo dpkg -i /tmp/cloudflared.deb
fi
cloudflared --version

# --- 3. GPU detection ------------------------------------------------------
# Decide GPU vs CPU BEFORE writing the Ollama drop-in, because the tuning
# differs: on a 24 GB A10G every model co-resides and requests can run in
# parallel; on CPU they contend for a handful of physical cores.
GPU=false
if [ "$GPU_MODE" != "off" ] && command -v nvidia-smi >/dev/null 2>&1; then
  if nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null; then
    GPU=true
  else
    warn "nvidia-smi present but returned an error — driver not loaded?"
  fi
fi
if [ "$GPU_MODE" = "require" ] && [ "$GPU" != true ]; then
  die "--gpu require but no working GPU found.
      On a Deep Learning AMI the driver is preinstalled; on plain Ubuntu run:
        sudo apt-get install -y nvidia-driver-535 && sudo reboot
      then re-run this script."
fi
log "GPU: $([ "$GPU" = true ] && echo yes || echo 'no — CPU inference')"

# provider=nvidia on this replica = the local NIM. This MUST be decided before
# step 8 rewrites .env: a prepend after that point never lands, and the box
# silently boots on whatever AI_PROVIDER the Mac shipped (seen 2026-09-02).
# Prepended so an explicit --set still wins.
if [ "$WITH_NIM" = true ]; then
  [ "$GPU" = true ] || die "--with-nim needs an NVIDIA GPU on this host (a NIM cannot run on CPU)"
  SETS=("AI_PROVIDER=nvidia" "NVIDIA_BASE_URL=http://localhost:8000/v1" "NVIDIA_MODEL=$NIM_MODEL" "${SETS[@]}")
  log "provider=nvidia -> local NIM $NIM_MODEL"
fi

# --- 4. Ollama daemon ------------------------------------------------------
log "Ollama daemon"
if ! command -v ollama >/dev/null; then
  curl -fsSL https://ollama.com/install.sh | sh   # installs + enables systemd unit
fi
# Keep the 3B internal model and the 8B synthesizer resident so a turn never
# pays a cold reload. On GPU there is VRAM for all three models at once and
# concurrency is cheap; on CPU, extra parallelism only causes core contention.
if [ "$WITH_NIM" = true ]; then
  # The NIM needs ~20 GB of the A10G's 23 GB. Ollama stays installed (models
  # pulled, provider switch-back possible) but must hold NO VRAM: one model at a
  # time, unloaded as soon as a request finishes. Stop pseudoco-assistant-nim before
  # switching this box back to provider=ollama.
  LOADED=1; KEEP="0"; PARALLEL="${NUM_PARALLEL:-1}"
elif [ "$GPU" = true ]; then
  LOADED=3; KEEP="60m"; PARALLEL="${NUM_PARALLEL:-4}"
else
  LOADED=2; KEEP="30m"; PARALLEL="${NUM_PARALLEL:-1}"
fi
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/keepalive.conf >/dev/null <<DROPIN
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=$LOADED"
Environment="OLLAMA_KEEP_ALIVE=$KEEP"
Environment="OLLAMA_NUM_PARALLEL=$PARALLEL"
DROPIN
sudo systemctl daemon-reload
sudo systemctl restart ollama       # restart, not start: pick up a changed drop-in
sudo systemctl enable ollama
for _ in $(seq 1 30); do
  curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://localhost:11434/api/tags >/dev/null || die "Ollama did not come up on :11434"

# Ollama logs its detected compute backend at startup. This catches the case
# where the driver exists but Ollama built/loaded a CPU-only runner.
if [ "$GPU" = true ]; then
  sleep 2
  if sudo journalctl -u ollama --since '2 min ago' --no-pager 2>/dev/null \
       | grep -qiE 'library=cuda|inference compute.*cuda'; then
    log "Ollama reports a CUDA backend"
  elif [ "$GPU_MODE" = "require" ]; then
    die "GPU present but Ollama did not report a CUDA backend.
      Inspect: sudo journalctl -u ollama -n 100 --no-pager | grep -i 'compute\|cuda\|rocm'"
  else
    warn "GPU present but Ollama did not report a CUDA backend — inference may be on CPU"
  fi
fi

# --- 5. PseudoCo Assistant repo + venv ------------------------------------------------
log "PseudoCo Assistant repo + venv"
if [ ! -d "$REPO/.git" ]; then git clone "$REPO_URL" "$REPO"; fi
cd "$REPO"
git pull --ff-only || warn "git pull failed (local changes?) — continuing with the current checkout"
python3.11 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# --- 6. OTel collector binary ---------------------------------------------
log "OTel collector binary"
mkdir -p bin
if [ ! -x bin/otelcol-contrib ]; then
  OTEL_VER=$(curl -fsSL https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/latest | grep -oP '"tag_name":\s*"v\K[0-9.]+' | head -1)
  curl -fsSL "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTEL_VER}/otelcol-contrib_${OTEL_VER}_linux_${OTEL_ARCH}.tar.gz" -o /tmp/otelcol.tgz
  tar -xzf /tmp/otelcol.tgz -C bin otelcol-contrib
fi
bin/otelcol-contrib --version
# The apt splunk-otel-collector (present on the Splunk lab AMI) binds the same
# :4317 and silently steals the app's telemetry. Ours is the only collector.
if systemctl list-unit-files 2>/dev/null | grep -q '^splunk-otel-collector\.service'; then
  sudo systemctl mask --now splunk-otel-collector 2>/dev/null || true
  warn "masked the apt splunk-otel-collector (port :4317 collision)"
fi

# --- 7. secrets: .env, tunnel credentials, tunnel config -------------------
log "installing secrets from $PAYLOAD"
install -m 600 "$PAYLOAD/.env" "$REPO/.env"

mkdir -p "$HOME/.cloudflared"; chmod 700 "$HOME/.cloudflared"
install -m 600 "$PAYLOAD/$TUNNEL_ID.json" "$HOME/.cloudflared/$TUNNEL_ID.json"

# The Mac's config.yml carries Mac paths (/Users/<you>/.cloudflared/...). Copy it
# verbatim EXCEPT credentials-file, which is rewritten to this host's $HOME —
# the single line that makes a Mac config valid on Linux.
sed -E "s|^([[:space:]]*credentials-file:[[:space:]]*).*|\1$HOME/.cloudflared/$TUNNEL_ID.json|" \
    "$PAYLOAD/config.yml" > "$HOME/.cloudflared/config.yml"
chmod 600 "$HOME/.cloudflared/config.yml"
grep -q "^credentials-file: $HOME/" "$HOME/.cloudflared/config.yml" \
  || die "credentials-file rewrite failed — check $PAYLOAD/config.yml formatting"

# A replica runs `tunnel run` only, which needs the credentials JSON and nothing
# else. cert.pem is the ACCOUNT credential (it can create/delete/route tunnels
# org-wide) and belongs on the Mac alone.
if [ -f "$HOME/.cloudflared/cert.pem" ]; then
  warn "cert.pem is present on this replica — it should not be. Remove it: rm ~/.cloudflared/cert.pem"
fi

# --- 8. per-replica .env overrides ----------------------------------------
# The .env arrives from the Mac identical for every box. A handful of keys must
# differ per replica; this applies them as a general override map rather than
# special-casing one key.
#
#   deployment.environment  what separates this replica from every other one in
#                           Splunk O11y. Two boxes sharing a value silently merge
#                           into one apparent service. The same name becomes the
#                           box's Agent Observability Agent stream.
#   ACCESS_KEY              per-box Basic-auth gate.
#   OLLAMA_MODEL            lets one box run the poisoned model and another the
#                           clean one — impossible under a load balancer, which
#                           is why the subdomain topology enables it.
#
# Secret-bearing overrides arrive in $PAYLOAD/overrides.env, NOT on the command
# line: argv is world-readable via /proc and `ps`, so an ACCESS_KEY passed as an
# argument would leak to every user on the box for the life of the process.
if [ -z "$ENV_NAME" ]; then
  if [ -n "$REPLICA" ]; then
    ENV_NAME="pseudoco-assistant-ec2-$REPLICA"
  else
    # Collision-free default derived from the instance id.
    TOK=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
          -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
    IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" \
          http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
    ENV_NAME="pseudoco-assistant-ec2-${IID##i-}"
    [ "$ENV_NAME" = "pseudoco-assistant-ec2-" ] && ENV_NAME="pseudoco-assistant-ec2-$(hostname -s)"
  fi
fi
log "deployment.environment = Agent stream = $ENV_NAME"

# One name for the box's O11y environment AND its Agent Observability Agent
# stream, stamped with this instance's id, so a later clone of this box (an AMI,
# a reused payload) is caught at start and renamed rather than silently merged
# with it (deploy/box_identity.py; run.sh / run-collector.sh call `ensure`).
# Runs BEFORE the override pass, so --set SPLUNK_AO_AGENT_STREAM=... or
# --set SPLUNK_AO_AGENT_STREAM_PER_THEME=True still wins.
python3 "$REPO/deploy/box_identity.py" assign --name "$ENV_NAME" --env-file "$REPO/.env" \
  || die "box identity: '$ENV_NAME' is not a usable environment / Agent stream name"

OVERRIDES=$(mktemp); chmod 600 "$OVERRIDES"
trap 'rm -f "$OVERRIDES"' EXIT
[ -f "$PAYLOAD/overrides.env" ] && cat "$PAYLOAD/overrides.env" >> "$OVERRIDES"
if [ ${#SETS[@]} -gt 0 ]; then
  printf '%s\n' "${SETS[@]}" >> "$OVERRIDES"
fi

python3 - "$REPO/.env" "$ENV_NAME" "$OVERRIDES" <<'PY'
import sys

path, envname, ovr_path = sys.argv[1], sys.argv[2], sys.argv[3]

# Load overrides: KEY=VALUE per line, blanks and #comments ignored. Later
# entries win, so a --set can deliberately beat a payload value.
overrides = {}
try:
    for raw in open(ovr_path):
        raw = raw.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, _, v = raw.partition("=")
        overrides[k.strip()] = v
except FileNotFoundError:
    pass


def rewrite_resource_attrs(value, envname):
    """Set deployment.environment inside the comma-separated attribute list,
    preserving every sibling attribute."""
    attrs, hit = [], False
    for pair in [p for p in value.split(",") if p.strip()]:
        k, _, _v = pair.partition("=")
        if k.strip() == "deployment.environment":
            attrs.append(f"deployment.environment={envname}")
            hit = True
        else:
            attrs.append(pair.strip())
    if not hit:
        attrs.insert(0, f"deployment.environment={envname}")
    return ",".join(attrs)


lines = open(path).read().splitlines(keepends=True)
out, applied, seen_ra = [], [], False

for line in lines:
    key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else None
    if key == "OTEL_RESOURCE_ATTRIBUTES":
        seen_ra = True
        new = rewrite_resource_attrs(line.split("=", 1)[1].strip(), envname)
        out.append(f"OTEL_RESOURCE_ATTRIBUTES={new}\n")
        applied.append(("deployment.environment", envname))
    elif key in overrides:
        out.append(f"{key}={overrides[key]}\n")
        applied.append((key, overrides.pop(key)))
    else:
        out.append(line)

# Keys not already present get appended.
if out and not out[-1].endswith("\n"):
    out[-1] += "\n"
if not seen_ra:
    out.append(f"OTEL_RESOURCE_ATTRIBUTES=deployment.environment={envname}\n")
    applied.append(("deployment.environment", envname))
for k, v in overrides.items():
    out.append(f"{k}={v}\n")
    applied.append((k, v))

open(path, "w").writelines(out)

# Report what changed, masking anything that looks like a credential.
SECRETISH = ("KEY", "TOKEN", "SECRET", "PASSWORD")
for k, v in applied:
    shown = "********" if any(s in k.upper() for s in SECRETISH) else v
    print(f"  {k} = {shown}")
PY
rm -f "$OVERRIDES"; trap - EXIT

# --- 9. models: pull every model .env references, build the poisoned one ---
# The model set is DERIVED FROM .env (OLLAMA_MODEL, OLLAMA_MODEL_INTERNAL, and
# any other OLLAMA_MODEL_* key) rather than hard-coded, so adding an internal
# agent to .env is enough — no bootstrap edit, no hand-pull on each replica.
log "Ollama models"
mapfile -t WANTED < <(
  grep -E '^OLLAMA_MODEL(_[A-Z0-9_]+)?=' "$REPO/.env" \
    | cut -d= -f2- | tr -d '"'\''' | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u
)
[ ${#WANTED[@]} -gt 0 ] || warn "no OLLAMA_MODEL* keys in .env — nothing to pull"

# The poisoned model is BUILT, never pulled: it does not exist in any registry.
# Its tag is whatever .env asks for; fall back to the conventional name.
POISONED_TAG=""
for m in "${WANTED[@]}"; do
  case "$m" in *poisoned*) POISONED_TAG="$m" ;; esac
done
[ -n "$POISONED_TAG" ] || POISONED_TAG="mistral-nemo:12b-poisoned"

# `ollama create` needs the FROM base resident first.
BASE=$(awk '/^[[:space:]]*FROM[[:space:]]+/{print $2; exit}' "$PAYLOAD/Modelfile.poisoned")
[ -n "$BASE" ] || die "no FROM line in $PAYLOAD/Modelfile.poisoned"
case "$BASE" in
  /*) die "Modelfile.poisoned has a blob path as its FROM ($BASE), not a tag.
      Re-export it on the Mac with an explicit base:
        sed -i '' \"s|^FROM .*|FROM mistral-nemo:12b|\" Modelfile.poisoned" ;;
esac

for m in "${WANTED[@]}" "$BASE"; do
  case "$m" in *poisoned*) continue ;; esac        # built below, not pullable
  log "ollama pull $m"
  ollama pull "$m"
done

log "ollama create $POISONED_TAG (from $BASE)"
install -m 644 "$PAYLOAD/Modelfile.poisoned" "$HOME/Modelfile.poisoned"
ollama create "$POISONED_TAG" -f "$HOME/Modelfile.poisoned"
ollama list

# The decisive GPU check. Backend logs can say CUDA while a specific model still
# lands on CPU (VRAM pressure, unsupported quant). `ollama ps` reports where the
# weights actually are, so warm one model and read the PROCESSOR column.
NIM_ALREADY_UP=false
if [ "$WITH_NIM" = true ] && curl -sf -o /dev/null http://localhost:8000/v1/health/ready 2>/dev/null; then
  # Idempotent re-deploy on a live NIM box: the NIM owns ~20 GB of the A10G, so
  # an Ollama warm-up would land split CPU/GPU and fail the placement gate for
  # no reason — the serving NIM IS the GPU proof. Skip the check.
  NIM_ALREADY_UP=true
  log "a NIM already serves on :8000 — skipping the Ollama placement check (the GPU is proven by the NIM)"
fi
if [ "$GPU" = true ] && [ "$NIM_ALREADY_UP" != true ]; then
  WARM="${WANTED[0]:-$BASE}"
  log "warming $WARM to confirm GPU placement"
  curl -sf http://localhost:11434/api/generate \
       -d "{\"model\":\"$WARM\",\"prompt\":\"hi\",\"stream\":false,\"keep_alive\":\"5m\"}" >/dev/null || \
    warn "warm-up request failed for $WARM"
  PLACEMENT=$(ollama ps 2>/dev/null | awk 'NR==2{for(i=1;i<=NF;i++) if($i ~ /%$/) {print $i" "$(i+1); exit}}')
  echo "  placement: ${PLACEMENT:-unknown}"
  # Order matters. Ollama reports a partial offload as "48%/52% CPU/GPU", which
  # contains "GPU" but means the model did NOT fit in VRAM and is running split
  # — nearly as slow as pure CPU. Test for any CPU share BEFORE accepting GPU.
  case "$PLACEMENT" in
    "100% GPU")
      log "confirmed: $WARM is fully resident on the GPU" ;;
    *CPU*)
      MSG="$WARM is not fully on the GPU (${PLACEMENT}).
      A CPU share means the model did not fit in VRAM, or the runner is CPU-only.
      Check VRAM:   nvidia-smi --query-gpu=memory.used,memory.total --format=csv
      Check runner: sudo journalctl -u ollama -n 100 --no-pager | grep -i cuda
      Check config: OLLAMA_MAX_LOADED_MODELS=$LOADED may be too many for this GPU"
      [ "$GPU_MODE" = "require" ] && die "$MSG" || warn "$MSG" ;;
    *GPU*)
      log "confirmed: $WARM is on the GPU (${PLACEMENT})" ;;
    *) warn "could not read model placement from 'ollama ps' — verify manually with: ollama ps" ;;
  esac
  nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader || true
  if [ "$WITH_NIM" = true ]; then
    # Hand the GPU back: the NIM starts in step 11 and cannot allocate next to
    # a resident 12B model. keep_alive=0 with an empty prompt unloads now.
    log "unloading $WARM so the NIM gets the GPU"
    curl -sf http://localhost:11434/api/generate \
         -d "{\"model\":\"$WARM\",\"keep_alive\":0}" >/dev/null || true
    for _ in $(seq 1 30); do
      [ "$(ollama ps 2>/dev/null | wc -l)" -le 1 ] && break
      sleep 1
    done
    if [ "$(ollama ps 2>/dev/null | wc -l)" -gt 1 ]; then
      MSG="Ollama still holds a model after unload; the NIM will not fit in VRAM. ollama ps:
$(ollama ps 2>/dev/null)"
      [ "$GPU_MODE" = "require" ] && die "$MSG" || warn "$MSG"
    fi
    echo "  VRAM after unload: $(nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader 2>/dev/null || echo unknown)"
  fi
fi

# --- 9b. Docker + NVIDIA Container Toolkit (local NIM and/or NemoClaw) ------
# The Deep Learning base AMI ships both; a plain Ubuntu box gets them here.
if [ "$WITH_NIM" = true ] || [ "$WITH_NEMOCLAW" = true ]; then
  log "docker + NVIDIA Container Toolkit"
  if ! command -v docker >/dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
  fi
  sudo usermod -aG docker "$(id -un)" || true
  if [ "$GPU" = true ] && ! sudo docker info 2>/dev/null | grep -q nvidia; then
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor --yes -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null
    apt_get update -y && apt_get install -y nvidia-container-toolkit
    sudo nvidia-ctk runtime configure --runtime=docker
    sudo systemctl restart docker
  fi
  sudo docker info >/dev/null || die "docker is not running"
fi
if [ "$WITH_NEMOCLAW" = true ]; then
  # NemoClaw's installer verifies the OpenShell binary with `strings` (binutils)
  # and needs Node >= 22.19 on PATH; the Deep Learning AMI ships neither.
  apt_get install -y binutils
  NODE_OK=false
  if command -v node >/dev/null; then
    NODE_V=$(node --version | sed 's/^v//'); NODE_MAJ=${NODE_V%%.*}; NODE_MIN=${NODE_V#*.}; NODE_MIN=${NODE_MIN%%.*}
    { [ "$NODE_MAJ" -gt 22 ] || { [ "$NODE_MAJ" -eq 22 ] && [ "$NODE_MIN" -ge 19 ]; }; } 2>/dev/null && NODE_OK=true
  fi
  if [ "$NODE_OK" != true ]; then
    log "Node.js 22 (NemoClaw needs >= 22.19; found ${NODE_V:-none})"
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    apt_get install -y nodejs
  fi
  node --version
fi

# --- 9c. local NVIDIA NIM (provider=nvidia = inference on THIS host) --------
if [ "$WITH_NIM" = true ]; then
  log "local NIM: $NIM_MODEL"
  # nvcr.io image pull needs an NGC key: from the installed .env (NGC_API_KEY=)
  # or the payload overrides — never from argv.
  NGC_API_KEY=$(grep -E '^NGC_API_KEY=' "$REPO/.env" "$PAYLOAD/overrides.env" 2>/dev/null | head -1 | cut -d= -f2- || true)
  [ -n "$NGC_API_KEY" ] || die "--with-nim needs NGC_API_KEY in .env (or the payload overrides) to pull nvcr.io/nim images"
  NIM_IMAGE="nvcr.io/nim/${NIM_MODEL}:latest"
  # Memory budget on a 22 GiB A10G (measured, replica 1, 2026-09-02). vLLM's
  # profile logs it: budget = 22.06 GiB x NIM_KVCACHE_PERCENT; weights 16.58 GiB;
  # activation peak = Nemotron Nano's hybrid-Mamba SSM state cache (pre-allocated
  # for NIM_MAX_NUM_SEQS, ~135 MB each — 33.75 GiB at the default 256!) + ~1.8
  # GiB; whatever is left is the KV cache, and zero left = "No available memory
  # for the cache blocks", restart loop, never ready. Context length barely
  # matters for this model (only a few attention layers). Defaults below leave
  # ~1.5 GiB of KV cache: 8 sequences (Ollama ran NUM_PARALLEL=4 on this demo),
  # 0.95 utilization, 8192 tokens. Override any of them in the environment.
  NIM_MAX_MODEL_LEN="${NIM_MAX_MODEL_LEN:-8192}"
  NIM_MAX_NUM_SEQS="${NIM_MAX_NUM_SEQS:-8}"
  NIM_KVCACHE_PERCENT="${NIM_KVCACHE_PERCENT:-0.95}"
  sudo install -m 600 -o root -g root /dev/null /etc/pseudoco-assistant-nim.env
  printf 'NGC_API_KEY=%s\nNIM_IMAGE=%s\nNIM_MAX_MODEL_LEN=%s\nNIM_MAX_NUM_SEQS=%s\nNIM_KVCACHE_PERCENT=%s\n' \
    "$NGC_API_KEY" "$NIM_IMAGE" "$NIM_MAX_MODEL_LEN" "$NIM_MAX_NUM_SEQS" "$NIM_KVCACHE_PERCENT" | sudo tee /etc/pseudoco-assistant-nim.env >/dev/null
  sudo mkdir -p /opt/nim-cache && sudo chown "$(id -u):$(id -g)" /opt/nim-cache
  printf '%s' "$NGC_API_KEY" | sg docker -c "docker login nvcr.io -u '\$oauthtoken' --password-stdin" >/dev/null \
    || die "docker login nvcr.io failed — is NGC_API_KEY valid?"
  # (AI_PROVIDER/NVIDIA_* were applied to .env in step 3/8 — see step 3.)
fi

# --- 10. systemd units ------------------------------------------------------
log "systemd units"
SVC_USER=$(id -un)

# A box bootstrapped before the 4.10.0 product rename runs this same stack
# under the old unit prefix. Retire those units first, or a re-bootstrap
# leaves two app services fighting over :8001 (and two collectors, two
# tunnels). Their /etc env files go with them — the blocks below rewrite the
# new ones from the payload. A box that never had them is untouched.
LEGACY_UNIT_PREFIX="demobot"
for u in app collector tunnel nim nemoclaw nemoclaw-forwarder; do
  legacy="$LEGACY_UNIT_PREFIX-$u"
  [ -f "/etc/systemd/system/$legacy.service" ] || continue
  log "retiring legacy unit $legacy (replaced by pseudoco-assistant-$u)"
  sudo systemctl disable --now "$legacy" 2>/dev/null || true
  sudo rm -f "/etc/systemd/system/$legacy.service" "/etc/$legacy.env"
done
sudo systemctl daemon-reload

if [ "$WITH_NIM" = true ]; then
  sudo tee /etc/systemd/system/pseudoco-assistant-nim.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant local NVIDIA NIM ($NIM_MODEL) on :8000
After=network-online.target docker.service
Requires=docker.service
Wants=network-online.target

[Service]
User=$SVC_USER
EnvironmentFile=/etc/pseudoco-assistant-nim.env
ExecStartPre=-/usr/bin/docker rm -f pseudoco-assistant-nim
ExecStart=/usr/bin/docker run --rm --name pseudoco-assistant-nim --gpus all --shm-size=16GB \\
  -e NGC_API_KEY -e NIM_MAX_MODEL_LEN -e NIM_MAX_NUM_SEQS -e NIM_KVCACHE_PERCENT -p 127.0.0.1:8000:8000 -v /opt/nim-cache:/opt/nim/.cache -u $(id -u) \${NIM_IMAGE}
ExecStop=/usr/bin/docker stop pseudoco-assistant-nim
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
fi

if [ "$WITH_NEMOCLAW" = true ]; then
  # The sandbox reaches PseudoCo Assistant at this host's private IP (run-nemoclaw.sh
  # derives it and trusts it with --trusted-private-host). Never 127.0.0.1 —
  # inside the sandbox that is the sandbox (every guard call refused, 2026-09-02).
  # NemoClaw guarantees nothing restarts after a reboot: this unit re-runs the
  # (idempotent) launcher, which starts the existing sandbox and re-applies the
  # guard policy; the forwarder unit tails the sandbox's OCSF denials.
  sudo install -m 600 -o root -g root /dev/null /etc/pseudoco-assistant-nemoclaw.env
  grep -E '^(ACCESS_KEY|NVIDIA_INFERENCE_API_KEY)=' "$REPO/.env" 2>/dev/null | sudo tee /etc/pseudoco-assistant-nemoclaw.env >/dev/null || true
  sudo tee /etc/systemd/system/pseudoco-assistant-nemoclaw.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant NemoClaw sandbox (OpenClaw in OpenShell, governed by /api/toolguard)
After=network-online.target docker.service pseudoco-assistant-app.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=$SVC_USER
WorkingDirectory=$REPO
EnvironmentFile=/etc/pseudoco-assistant-nemoclaw.env
Environment=PATH=$HOME/.nemoclaw/bin:$HOME/.local/bin:$REPO/venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/bin/bash $REPO/run-nemoclaw.sh --no-forwarder

[Install]
WantedBy=multi-user.target
UNIT
  sudo tee /etc/systemd/system/pseudoco-assistant-nemoclaw-forwarder.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant NemoClaw OCSF denial forwarder (-> /api/toolguard/nemoclaw/events)
After=pseudoco-assistant-nemoclaw.service pseudoco-assistant-app.service
Requires=pseudoco-assistant-nemoclaw.service

[Service]
User=$SVC_USER
WorkingDirectory=$REPO
EnvironmentFile=/etc/pseudoco-assistant-nemoclaw.env
Environment=PATH=$HOME/.nemoclaw/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$REPO/venv/bin/python $REPO/scripts/nemoclaw/ocsf_forwarder.py --sandbox pseudoco-assistant-nemoclaw --guard http://127.0.0.1:8001 --state $HOME/.demobot-nemoclaw
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
fi

sudo tee /etc/systemd/system/pseudoco-assistant-collector.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant OTel Collector (-> Splunk Observability Cloud + Agent Observability)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
WorkingDirectory=$REPO
ExecStart=$REPO/run-collector.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/pseudoco-assistant-app.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant app (uvicorn :8001)
After=network-online.target ollama.service pseudoco-assistant-collector.service
Wants=network-online.target

[Service]
User=$SVC_USER
WorkingDirectory=$REPO
Environment=PATH=$REPO/venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/bin/bash $REPO/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/pseudoco-assistant-tunnel.service >/dev/null <<UNIT
[Unit]
Description=PseudoCo Assistant Cloudflare named tunnel (medadvice replica)
After=network-online.target pseudoco-assistant-app.service
Wants=network-online.target

[Service]
User=$SVC_USER
ExecStart=/usr/bin/cloudflared --config $HOME/.cloudflared/config.yml tunnel run $TUNNEL_ID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload

# --- 11. start + verify ----------------------------------------------------
if [ "$START" != true ]; then
  echo; echo "BOOTSTRAP_OK (units installed, not started — --no-start)"
  exit 0
fi

if [ "$WITH_NIM" = true ]; then
  # The NIM is this box's chat provider, so it comes up BEFORE the app: the
  # app's startup catalog probe then sees a ready NIM instead of "NIM DOWN".
  # First start pulls the image (~10 GB) and the weights (~18 GB): allow 40 min.
  log "starting the local NIM (first start pulls the image + weights — 10-25 min)"
  sudo systemctl enable --now pseudoco-assistant-nim
  NIM_READY=false
  for i in $(seq 1 240); do
    if curl -sf -o /dev/null http://localhost:8000/v1/health/ready; then NIM_READY=true; break; fi
    [ $((i % 3)) -eq 0 ] && echo "  waiting for NIM ($((i * 10)) s) — $(sudo docker logs --tail 1 pseudoco-assistant-nim 2>/dev/null | cut -c1-110)"
    sleep 10
  done
  if [ "$NIM_READY" = true ]; then
    echo "NIM ready: $(curl -s http://localhost:8000/v1/models | head -c 200)"
  else
    warn "NIM not ready after 40 min — the stack starts anyway; the final verify will FAIL.
      Inspect: sudo journalctl -u pseudoco-assistant-nim -n 50 --no-pager ; sudo docker logs --tail 50 pseudoco-assistant-nim
      Re-run this bootstrap once the pull completes (idempotent; /opt/nim-cache persists)."
  fi
fi

log "starting services"
sudo systemctl enable --now pseudoco-assistant-collector pseudoco-assistant-app pseudoco-assistant-tunnel
# Collector must own :4317 before the app's first spans; units encode the
# ordering, this is just the settling time.
sleep 10

if [ "$WITH_NEMOCLAW" = true ]; then
  log "onboarding the NemoClaw sandbox (first run installs NemoClaw + builds the image)"
  # run-nemoclaw.sh needs the app answering (the tool guard is fail-closed) and
  # NVIDIA_INFERENCE_API_KEY in its ENVIRONMENT — it does not read .env for
  # that key. The first live run (2026-09-02) hit both: the app was still
  # starting 10 s after enable --now, and the key was only in the unit's
  # EnvironmentFile, so onboarding died before installing anything. Wait for
  # /health, then run it exactly as the unit does: with /etc/pseudoco-assistant-nemoclaw.env
  # exported, as the service user with the docker group active.
  for _ in $(seq 1 60); do
    curl -sf -o /dev/null http://localhost:8001/health && break
    sleep 5
  done
  curl -sf -o /dev/null http://localhost:8001/health || warn "app not answering on :8001 yet — NemoClaw onboarding will likely fail"
  set -a; # shellcheck disable=SC1091
  . <(sudo cat /etc/pseudoco-assistant-nemoclaw.env); set +a
  sg docker -c "cd '$REPO' && ./run-nemoclaw.sh --no-forwarder" \
    || warn "NemoClaw onboarding failed — see the output above; the policy layer still works without the runtime"
  unset NVIDIA_INFERENCE_API_KEY
  sudo systemctl enable pseudoco-assistant-nemoclaw pseudoco-assistant-nemoclaw-forwarder
  sudo systemctl start pseudoco-assistant-nemoclaw-forwarder || true
fi

log "verify"
rc=0
check() { c=$(curl -s -o /dev/null -w '%{http_code}' "$2" 2>/dev/null || echo 000)
          printf '  %-34s %s\n' "$1" "$c"; [ "$c" = "200" ] || rc=1; }
check "app      /health"        http://localhost:8001/health
check "ollama   /api/tags"      http://localhost:11434/api/tags
check "otelcol  :8888/metrics"  http://localhost:8888/metrics
if [ "$WITH_NIM" = true ]; then
  check "nim      /v1/health/ready" http://localhost:8000/v1/health/ready
  check "nim      /v1/models"       http://localhost:8000/v1/models
fi
if [ "$WITH_NEMOCLAW" = true ]; then
  # Onboarding is best-effort by design (the policy layer works without the
  # runtime), so these are informational, not gating.
  for u in pseudoco-assistant-nemoclaw pseudoco-assistant-nemoclaw-forwarder; do
    printf '  %-34s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null || true)"
  done
fi
HOSTN=$(awk '/hostname:/{print $3; exit}' "$HOME/.cloudflared/config.yml")
[ -n "$HOSTN" ] && check "public   https://$HOSTN" "https://$HOSTN/health"
[ "$GPU" = true ] && echo "  GPU memory: $(nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader 2>/dev/null || echo unknown)"

echo
if [ $rc -eq 0 ]; then
  echo "BOOTSTRAP_OK — replica live as deployment.environment=$ENV_NAME"
  echo
  echo "Confirm telemetry is landing under this replica's own environment:"
  echo "  cd $REPO && python3 tests/observability/check_o11y_metadata.py \\"
  echo "      us1 \"\$(grep '^O11Y_API=' .env | cut -d= -f2-)\" pseudoco-assistant $ENV_NAME"
  echo "  (verify_observability.sh hard-codes pseudoco-assistant-local, so it is wrong on a replica)"
else
  echo "BOOTSTRAP_INCOMPLETE — a health check failed. Logs:"
  echo "  journalctl -u pseudoco-assistant-app -u pseudoco-assistant-collector -u pseudoco-assistant-tunnel$([ "$WITH_NIM" = true ] && echo ' -u pseudoco-assistant-nim') -n 50 --no-pager"
  exit 1
fi
