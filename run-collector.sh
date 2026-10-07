#!/bin/bash
# Run a local OpenTelemetry Collector that forwards the app's OTLP telemetry to
# Splunk Observability Cloud (metrics via the signalfx exporter, traces via the
# Splunk OTLP/APM ingest). Reads SPLUNK_REALM + O11Y_INGEST from .env.
# Prefers the native ./bin/otelcol-contrib binary; falls back to podman/docker.
# Run this alongside ./run.sh.
set -euo pipefail
cd "$(dirname "$0")"

# Per-box identity before anything reads .env: on an EC2 box whose .env was
# stamped on another instance (cloned image / shared payload) this gives the box
# its own deployment.environment + Agent stream. No-op off EC2. See the script.
command -v python3 >/dev/null 2>&1 && python3 deploy/box_identity.py ensure --env-file .env || true

export SPLUNK_REALM=$(grep '^SPLUNK_REALM=' .env 2>/dev/null | cut -d= -f2- || true)
export O11Y_INGEST=$(grep '^O11Y_INGEST=' .env 2>/dev/null | cut -d= -f2- || true)
# Splunk Agent Observability — optional second trace destination (same O11y org).
export SPLUNK_AO_REALM=$(grep '^SPLUNK_AO_REALM=' .env 2>/dev/null | cut -d= -f2- || true)
export SPLUNK_AO_O11Y_TOKEN=$(grep '^SPLUNK_AO_O11Y_TOKEN=' .env 2>/dev/null | cut -d= -f2- || true)
export SPLUNK_AO_PROJECT=$(grep '^SPLUNK_AO_PROJECT=' .env 2>/dev/null | cut -d= -f2- || true)
export SPLUNK_AO_AGENT_STREAM=$(grep '^SPLUNK_AO_AGENT_STREAM=' .env 2>/dev/null | cut -d= -f2- || true)
# The SDK path defaults both to PseudoCo Assistant; keep the collector's headers identical.
export SPLUNK_AO_PROJECT="${SPLUNK_AO_PROJECT:-PseudoCo Assistant}"
export SPLUNK_AO_AGENT_STREAM="${SPLUNK_AO_AGENT_STREAM:-PseudoCo Assistant}"
# Logs — optional Splunk platform HEC destination (Splunk Observability Cloud
# has no log ingest on this org; see otel-collector-logs.yaml).
export SPLUNK_HEC_URL=$(grep '^SPLUNK_HEC_URL=' .env 2>/dev/null | cut -d= -f2- || true)
export SPLUNK_HEC_TOKEN=$(grep '^SPLUNK_HEC_TOKEN=' .env 2>/dev/null | cut -d= -f2- || true)
export SPLUNK_HEC_INDEX=$(grep '^SPLUNK_HEC_INDEX=' .env 2>/dev/null | cut -d= -f2- || true)

# The Agent Observability exporter + pipeline live in an overlay config that is
# layered on ONLY when the ingest token is present. Previously they were
# unconditional in the base config and the vars were exported even when empty,
# so a keyless deployment POSTed every gen_ai span — prompt and response content
# included — to the ingest endpoint with an empty token header, failing
# continuously and visibly only in the collector's own log.
CONFIGS=(--config otel-collector-config.yaml)
if [ -n "${SPLUNK_AO_O11Y_TOKEN:-}" ]; then
  CONFIGS+=(--config otel-collector-agent-obs.yaml)
  AGENT_OBS_STATE="on -> ingest.${SPLUNK_AO_REALM:-?}.observability.splunkcloud.com (project=${SPLUNK_AO_PROJECT}, agent stream=${SPLUNK_AO_AGENT_STREAM})"
else
  AGENT_OBS_STATE="OFF (no SPLUNK_AO_O11Y_TOKEN in .env)"
fi
# Same gating for the logs pipeline: no HEC credentials -> no logs pipeline at
# all, rather than a pipeline that queues and retries against an empty endpoint.
if [ -n "${SPLUNK_HEC_TOKEN:-}" ] && [ -n "${SPLUNK_HEC_URL:-}" ]; then
  CONFIGS+=(--config otel-collector-logs.yaml)
  LOGS_STATE="on -> ${SPLUNK_HEC_URL} (index=${SPLUNK_HEC_INDEX:-default})"
else
  LOGS_STATE="OFF (no SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN in .env)"
fi
if [ -z "${SPLUNK_REALM:-}" ] || [ -z "${O11Y_INGEST:-}" ]; then
  echo "ERROR: set SPLUNK_REALM and O11Y_INGEST in .env first." >&2
  exit 1
fi

echo "Starting OTel Collector (realm=$SPLUNK_REALM) -> Splunk Observability Cloud"
echo "Agent Observability trace fan-out: $AGENT_OBS_STATE"
echo "Logs -> Splunk platform HEC: $LOGS_STATE"
echo "Listening on :4317 (OTLP/gRPC) and :4318 (OTLP/HTTP). Ctrl+C to stop."

# Native binary (downloaded once by the setup; see README/skill).
if [ -x ./bin/otelcol-contrib ]; then
  exec ./bin/otelcol-contrib "${CONFIGS[@]}"
fi

# Fallback: containerized collector.
RUNTIME="$(command -v podman || command -v docker || true)"
if [ -z "$RUNTIME" ]; then
  echo "ERROR: ./bin/otelcol-contrib missing and no podman/docker available." >&2
  echo "Re-download the binary or start podman, then retry." >&2
  exit 1
fi
# Mount every config; pass the overlay only when SPLUNK_AO_O11Y_TOKEN is present,
# so the containerized path gates identically to the native one above.
CONTAINER_CONFIGS=(--config=/etc/otelcol-contrib/config.yaml)
[ -n "${SPLUNK_AO_O11Y_TOKEN:-}" ] && CONTAINER_CONFIGS+=(--config=/etc/otelcol-contrib/agent-obs.yaml)
if [ -n "${SPLUNK_HEC_TOKEN:-}" ] && [ -n "${SPLUNK_HEC_URL:-}" ]; then
  CONTAINER_CONFIGS+=(--config=/etc/otelcol-contrib/logs.yaml)
fi
exec "$RUNTIME" run --rm --name otel-collector \
  -p 4317:4317 -p 4318:4318 \
  -e SPLUNK_REALM -e O11Y_INGEST \
  -e SPLUNK_AO_REALM -e SPLUNK_AO_O11Y_TOKEN -e SPLUNK_AO_PROJECT -e SPLUNK_AO_AGENT_STREAM \
  -e SPLUNK_HEC_URL -e SPLUNK_HEC_TOKEN -e SPLUNK_HEC_INDEX \
  -v "$PWD/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -v "$PWD/otel-collector-agent-obs.yaml:/etc/otelcol-contrib/agent-obs.yaml:ro" \
  -v "$PWD/otel-collector-logs.yaml:/etc/otelcol-contrib/logs.yaml:ro" \
  docker.io/otel/opentelemetry-collector-contrib:latest \
  "${CONTAINER_CONFIGS[@]}"
