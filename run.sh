#!/bin/bash

# PseudoCo Assistant v4 - Quick Start Script
# Supports dual-environment deployment: Anthropic API (local) or AWS Bedrock (production)

echo "╔════════════════════════════════════════════════╗"
echo "║         PseudoCo Assistant v4 - Starting...            ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import fastapi" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    echo "✅ Dependencies installed"
fi

# Check for .env file
if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    echo "Please copy .env.example to .env and configure your settings"
    echo ""
    echo "Run: cp .env.example .env"
    echo "Then edit .env to add your API key"
    exit 1
fi

# Per-box identity (deploy/box_identity.py), before anything below reads .env:
# an EC2 box whose .env was stamped on another instance gets its own
# deployment.environment + Agent stream. No-op off EC2 and on a box that owns it.
python3 deploy/box_identity.py ensure --env-file .env || true

# Check AI provider configuration
AI_PROVIDER=$(grep "^AI_PROVIDER=" .env 2>/dev/null | cut -d'=' -f2)
if [ "$AI_PROVIDER" = "bedrock" ]; then
    echo "🔧 AI Provider: AWS Bedrock"
    # Check for AWS credentials
    if [ -z "$AWS_ACCESS_KEY_ID" ] && [ ! -f ~/.aws/credentials ]; then
        echo "⚠️  WARNING: AWS credentials not found"
        echo "Configure AWS CLI: aws configure"
        echo ""
    fi
elif [ "$AI_PROVIDER" = "anthropic" ] || [ -z "$AI_PROVIDER" ]; then
    echo "🔧 AI Provider: Anthropic API"
    # Check for Anthropic API key
    if ! grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null; then
        echo "⚠️  WARNING: ANTHROPIC_API_KEY not configured in .env"
        echo "The application will not work without a valid API key"
        echo ""
    fi
elif [ "$AI_PROVIDER" = "openai" ]; then
    echo "🔧 AI Provider: OpenAI-compatible API"
    # Check for OpenAI-compatible API key
    if ! grep -q "^OPENAI_API_KEY=." .env 2>/dev/null || grep -q "OPENAI_API_KEY=your_" .env 2>/dev/null; then
        echo "⚠️  WARNING: OPENAI_API_KEY not configured in .env"
        echo "The application will not work without a valid API key"
        echo ""
    fi
elif [ "$AI_PROVIDER" = "nvidia" ]; then
    echo "🔧 AI Provider: NVIDIA NIM (local container on this host)"
    # provider=nvidia is local inference only: preflight the loopback NIM the
    # same way the ollama branch preflights its daemon. Warn, don't block.
    NIM_URL=$(grep "^NVIDIA_BASE_URL=" .env 2>/dev/null | cut -d'=' -f2)
    NIM_URL=${NIM_URL:-http://localhost:8000/v1}
    NIM_MODEL=$(grep "^NVIDIA_MODEL=" .env 2>/dev/null | cut -d'=' -f2)
    NIM_MODEL=${NIM_MODEL:-nvidia/nvidia-nemotron-nano-9b-v2}
    case "$NIM_URL" in
        http://localhost*|http://127.*|http://\[::1\]*) ;;
        *)  echo "⚠️  WARNING: NVIDIA_BASE_URL=$NIM_URL is not on this host"
            echo "    provider=nvidia is local inference only — the app will refuse it."
            echo "" ;;
    esac
    if ! curl -s -o /dev/null -w '%{http_code}' "$NIM_URL/health/ready" 2>/dev/null | grep -q '^200$'; then
        echo "⚠️  WARNING: no NIM answering $NIM_URL/health/ready"
        echo "    Start one on this GPU host (deploy/ec2/ec2-bootstrap.sh --with-nim, or"
        echo "    docker run --gpus all -p 8000:8000 nvcr.io/nim/$NIM_MODEL:latest)"
        echo ""
    else
        echo "✅ NIM ready at $NIM_URL (model '$NIM_MODEL')"
    fi
elif [ "$AI_PROVIDER" = "ollama" ]; then
    echo "🔧 AI Provider: Ollama (local uncensored model)"
    # Preflight the local Ollama daemon: warn (don't block) if it's down or the
    # configured model isn't pulled, so the operator gets an actionable message
    # instead of a cryptic connection error on the first chat turn.
    OLLAMA_URL=$(grep "^OLLAMA_BASE_URL=" .env 2>/dev/null | cut -d'=' -f2)
    OLLAMA_URL=${OLLAMA_URL:-http://localhost:11434}
    OLLAMA_MODEL=$(grep "^OLLAMA_MODEL=" .env 2>/dev/null | cut -d'=' -f2)
    OLLAMA_MODEL=${OLLAMA_MODEL:-mistral-nemo:12b}
    if ! curl -s -o /dev/null -w '%{http_code}' "$OLLAMA_URL/api/tags" 2>/dev/null | grep -q '^200$'; then
        echo "⚠️  WARNING: Ollama not reachable at $OLLAMA_URL"
        echo "    Start it:  ollama serve"
        echo "    Pull it:   ollama pull $OLLAMA_MODEL"
        echo ""
    elif ! curl -s "$OLLAMA_URL/api/tags" 2>/dev/null | grep -q "\"$OLLAMA_MODEL\""; then
        echo "⚠️  WARNING: model '$OLLAMA_MODEL' not pulled in Ollama"
        echo "    Pull it:   ollama pull $OLLAMA_MODEL"
        echo ""
    else
        echo "✅ Ollama up at $OLLAMA_URL and model '$OLLAMA_MODEL' present"
    fi
else
    echo "⚠️  WARNING: Unknown AI_PROVIDER: $AI_PROVIDER"
    echo "Valid options: anthropic, bedrock, openai, ollama, nvidia"
    echo ""
fi

# Create logs directory
mkdir -p logs

# What this box can run (GPU / container runtime / local NIM / NemoClaw) — the
# same probe the UI uses to grey out options that cannot work here.
python -m backend.host_capabilities 2>/dev/null || true

echo ""
echo "Starting PseudoCo Assistant v4..."
echo ""
echo "Access the application at:"
echo "  📱 Chat Interface:    http://localhost:8001/app"
echo "  📊 Admin Dashboard:   http://localhost:8001/admin-ui"
echo "  📋 Governance Logs:   http://localhost:8001/governance-ui"
echo "  📚 API Docs:          http://localhost:8001/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Splunk Agent Observability — export SPLUNK_AO_* from .env so the app's SDK path
# (backend/agent_observability.py) sees the realm/token/project/agent stream, and
# AGENT_CONTROL_* for the Agent Control guardrail. No-op if absent (backend.config
# loads .env too; this keeps the wrapper-launched process identical).
while IFS='=' read -r _k _v; do
    case "$_k" in SPLUNK_AO_*|AGENT_CONTROL_*) export "$_k=$_v" ;; esac
done < <(grep -E '^(SPLUNK_AO_|AGENT_CONTROL_)' .env 2>/dev/null)

# Run the application.
# If Splunk telemetry is configured (OTEL_EXPORTER_OTLP_ENDPOINT in .env), export
# the OTEL_* vars into the environment and launch under the OpenTelemetry
# auto-instrumentation wrapper, so LangChain + FastAPI spans and GenAI metrics
# export over OTLP to the local collector (start it with ./run-collector.sh).
# Otherwise run the app plainly.
if grep -q '^OTEL_EXPORTER_OTLP_ENDPOINT=.' .env 2>/dev/null; then
    while IFS='=' read -r _k _v; do
        case "$_k" in OTEL_*) export "$_k=$_v" ;; esac
    done < <(grep -E '^OTEL_' .env)
    # The preview Splunk LangChain instrumentor mis-reports the model as "unknown"
    # and emits no AgentInvocation for create_react_agent. We emit the GenAI
    # Agent/LLM entities ourselves with accurate data (backend/telemetry/otel.py),
    # so disable the auto langchain instrumentor to avoid duplicate/unknown-model
    # emission. FastAPI instrumentation stays on for APM/HTTP traces.
    export OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=langchain
    echo "📡 Telemetry ON -> OTLP $OTEL_EXPORTER_OTLP_ENDPOINT (service=$OTEL_SERVICE_NAME)"
    exec opentelemetry-instrument python -m backend.main
else
    exec python -m backend.main
fi
