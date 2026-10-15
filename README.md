# PseudoCo Assistant v3

A macOS-compatible advice web application built with Python, FastAPI, and configurable AI providers. It serves six configurable **Application Themes** (medical, tax, benefits, legal, finance, and a telecom support bot) through a **LangChain + LangGraph multi-agent architecture**, with strict safety guardrails, comprehensive AI governance logging, and code-based **OpenTelemetry GenAI** instrumentation for agentic observability in Splunk.

> **Architecture note:** As of the agentic rebuild, chat turns are served by a supervisor-routed LangGraph workflow (`backend/agents/`). The original hand-rolled `RecommendationEngine` is retained as a content/patterns library (theme prompts, synthetic injection, formatting) and as a transparent fallback. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Features

### Core Functionality
- **Natural Language Medical Queries**: Chat interface for submitting medical questions
- **Clarifying Questions**: AI asks up to 2 targeted questions (MAX_CLARIFYING_QUESTIONS) to gather necessary information
- **Medical Recommendations**: General, non-prescriptive health guidance including:
  - Preliminary assessments
  - Lifestyle adjustments
  - OTC medication suggestions
  - When to seek professional care
  - Severity classification (LOW, MEDIUM, HIGH, EMERGENCY)

### Safety & Compliance
- **Mandatory Medical Disclaimer**: Users must accept before starting consultation
- **Automatic Escalation**: Flags consultations for human review when:
  - Emergency symptoms detected
  - Vulnerable populations (infants <2 years, pregnant, elderly with complex conditions)
  - Potential drug interactions identified
  - Self-harm ideation expressed
  - Low AI confidence
  - User explicitly requests professional review
- **Safety Guardrails**: Never provides prescription dosages or pediatric medication advice
- **Natural PII/PHI Integration**: Realistic synthetic patient data naturally woven into responses for governance testing (25% background rate by default, configurable per category; the UI toggles force a category ON)

### AI Governance Logging
Comprehensive logging following OpenTelemetry semantic conventions:

- **Core Operation Tracking**: Model identity, request/response IDs, operation names
- **Input/Output Logging**: Full message history, system instructions, tool definitions
- **Performance Metrics**: Token usage, latency, time-to-first-token
- **Safety Monitoring**: PII detection, guardrail triggers, policy violations
- **Evaluation/TEVV**: Confidence scores, drift metrics, evaluation results
- **Multi-Destination Logging**: File, database, and console output with rotation

### Agentic Surface (optional)
An opt-in OpenClaw-based agent with **real tools** so governance extends from
*what a model says* to *what an agent does*:

- **Tool-call governance seat**: every proposed tool call is inspected by
  `/api/toolguard/inspect` (Cisco AI Defense + a deterministic tool policy)
  **before execution**, then allowed or blocked.
- **`execute_tool` telemetry**: each call becomes a `gen_ai` span + a `tool_call`
  governance event, feeding the same Splunk APM + Splunk Agent Observability pipelines.
- **Demonstrates agentic risk**: indirect prompt injection and PHI exfiltration,
  caught (guarded) or observed (unguarded control) at the tool boundary.

Off by default; see [Agentic Surface](#agentic-surface-openclaw-optional) below.

## Architecture

### Backend Stack
- **Python 3.11+**
- **FastAPI**: REST API framework
- **LangChain + LangGraph**: multi-agent orchestration (supervisor + per-theme decomposed subgraphs)
- **OpenTelemetry GenAI**: code-based Workflow / Agent / LLM span instrumentation exported over OTLP
- **Configurable AI Providers**: Ollama (local, the workshop default), Anthropic, AWS Bedrock, a **local NVIDIA NIM** (`provider=nvidia` — Nemotron 3 on this host's GPU, never a cloud API), or any OpenAI-compatible API
- **NVIDIA governance stack** (all opt-in): NeMo Guardrails and NemoClaw Guardrails drawer toggles, a selectable **Blueprint** (PseudoCo Assistant Multi-Agent or NVIDIA AI Virtual Assistant) with a feature-parity rule — see [docs/nvidia-integration.md](docs/nvidia-integration.md)
- **SQLAlchemy**: ORM for database management
- **SQLite**: Embedded database

### Agentic Architecture
Each chat turn flows through a supervisor-routed LangGraph workflow:

```
START -> router -> {theme}_subgraph -> END
```

The supervisor (`router`) resolves the Application Theme and routes to that theme's
subgraph: the shared guardrail chain wired around the selected **blueprint**'s
generation core (`backend/agents/blueprints/`):

```
policy -> prompt_defense -> agent_control_prompt -> nemo_input_rails -> <blueprint core>
      -> safety -> injection -> compliance -> agent_control -> nemo_output_rails
      -> response_defense -> governance
```

The two `agent_control` nodes are the **Agent Observability Controls** guardrail.
They can target the Galileo console (default) or the Agent Control server hosted
inside Splunk Agent Observability, where controls are attached to the theme's
Agent stream — see `docs/agent-control-splunk-ao.md`.

Blueprints (`ACTIVE_BLUEPRINT`, `PUT /api/settings/blueprint`, or per request —
the UI has no picker and always runs the default):

- **PseudoCo Assistant Multi-Agent** (default): `intake -> synthesizer` — the theme's domain
  agent answers directly (one LLM call). Toggling **Multi-Agent Mode** ON expands
  it to `intake -> coordinator -> specialists -> synthesizer`.
- **NVIDIA AI Virtual Assistant**: `fetch_record -> ask_clarification ->
  primary_assistant -> sub_assistant -> respond` — the primary assistant routes by
  tool call to a specialized assistant that uses knowledge retrieval and a
  structured record lookup; Multi-Agent Mode allows two sub-assistants.

Every guardrail node runs for every blueprint — that is enforced structurally
(`blueprints/guardrails.py`) and by `tests/test_blueprint_parity.py` (see
CLAUDE.md "Blueprint feature parity"). Any node can short-circuit to the end of
the pipeline (policy block, AI Defense block, NeMo rail, Agent Control deny,
clarifying question, or generation error). Guardrail nodes
(`backend/agents/nodes/`) wrap the existing services so business logic and the
Splunk governance-log contract are preserved unchanged.

**Application Themes** (`backend/agents/themes/`): `medadvice` (default),
`taxadvice`, `benefitsadvice`, `legaladvice`, `financeadvice`, `telecomchatbot`,
`retail`, `manufacturing`. The chat page's large app title is the theme picker.
Adding a theme is a new module plus a registry entry, and a row in every per-theme
table (prompt, Synthetic Content directives, `blueprint_data/`, the UI's theme
maps); `tests/test_themes.py` fails on any table that misses one.

### Agentic Surface (OpenClaw, optional)

The chat pipeline above is deliberately **tool-less**. The optional agentic
surface runs an **OpenClaw** gateway (in podman) whose agent *does* have tools,
and routes every tool call through PseudoCo Assistant's governance before it executes:

```
OpenClaw gateway (:18789)  --before_tool_call-->  POST /api/toolguard/inspect
   agent + real tools                                 |- tool_policy (deterministic)
   (Ollama llama3.2:3b)                                |- Cisco AI Defense (PII/PHI/harm)
        |                                              |- governance_logger.log_tool_call
        |                                              '- otel.tool_span (execute_tool)
        '--(allow | block: reason)---------------------'
   diagnostics-otel --OTLP--> the same collector --> Splunk APM + Splunk Agent Observability
```

Key modules: `backend/routers/toolguard.py`, `backend/services/tool_policy.py`,
`openclaw/plugins/pseudoco-assistant-toolguard/` (the `before_tool_call` plugin),
`run-openclaw.sh`. `TOOL_GUARD_ENABLED` gates *enforcement* only, so the same
setup runs both the guarded and unguarded-control demos. See
[Agentic Surface](#agentic-surface-openclaw-optional-1) under Running.

> **`openclaw/` is tracked but not checked out on the demo Mac.** Endpoint
> security deletes OpenClaw files from the working tree, so the directory is
> sparse-checkout-excluded there and the container image is built straight from
> git. Remote clones are unaffected and get the full tree. Browse or change it
> with `scripts/openclaw-edit.sh` (`--list` / `--show <path>` / `<path>`) rather
> than checking it out.

### Frontend Stack
- **HTML5 + TailwindCSS**: Responsive UI
- **Vanilla JavaScript**: Real-time chat interface with streaming
- **Chart.js**: Metrics visualization

### Database Schema
- **conversations**: Session and message storage
- **ai_governance_logs**: Comprehensive AI interaction logs
- **escalation_queue**: Cases requiring human review
- **audit_logs**: System audit trail

## Installation

### Prerequisites
- Python 3.11 or higher
- macOS (primary target, but works on Linux/Windows)
- Credentials for your configured AI provider

### Setup

1. **Clone/Download the project**
```bash
cd ~/medadvice_v3
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env and add credentials for your configured AI provider
```

5. **Initialize database**
```bash
# Database will be created automatically on first run
```

## Running the Application

### Development Mode
```bash
# From project root
python -m backend.main

# Or using uvicorn directly
uvicorn backend.main:app --reload --port 8001
```

### Production Mode
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8001 --workers 4
```

### Containers and OpenShift
The top-level `Containerfile` builds one image for podman/docker and OpenShift (it runs as an
arbitrary UID). `deploy/openshift/` holds the in-cluster build and run manifests, including a
remote Nemotron reached through `provider=openai` and the on-prem Cisco AI Defense gateway's CA
chain — see [deploy/openshift/README.md](deploy/openshift/README.md).

### Access the Application
- **Chat Interface**: http://localhost:8001/app
- **Admin Dashboard**: http://localhost:8001/admin-ui
- **Governance Logs**: http://localhost:8001/governance-ui
- **API Docs**: http://localhost:8001/docs
- **Health Check**: http://localhost:8001/health
- **Settings**: http://localhost:8001/settings-ui (its own access code, on top of the app key)

**Demo Controls visibility.** The Settings page's **Demo Controls** card chooses
which cards the chat page's Demo Controls drawer shows (`GET`/`PUT
/api/settings/demo-controls`, persisted in `app_settings`). Untick a card and it
leaves the drawer within 10 s; a group whose cards are all hidden takes its header
with it. Hiding is not gating: a hidden per-request toggle sends no override, so
the server default governs that flag; hidden generators (auto sessions, incident,
spray, NemoClaw) keep running; options this host cannot run stay greyed out via
`GET /api/server-info`. The list is generated from `backend/settings_store.py`
`DEMO_CONTROLS`, the registry every drawer card's `data-control` hook is checked
against (`tests/test_demo_controls.py`; see CLAUDE.md "Demo Controls drawer
formatting").

### Agentic Surface (OpenClaw, optional)

Adds an OpenClaw agent with real tools, governed at the tool boundary (see
[Architecture](#agentic-surface-openclaw-optional)). **Off by default** — nothing
in the app depends on it, so this is fully separable from the chat demo.

**Prerequisites:** `podman` (the gateway runs containerized), and local Ollama
with a tool-capable model:
```bash
podman machine start
ollama pull llama3.2:3b        # the gateway needs a tool-capable model; this is the one PseudoCo Assistant already runs
```

**Run it:**
```bash
venv/bin/python scripts/demo/seed_agentic_decoy.py   # one-time: seed ~/DemoBotDecoy (all synthetic)
./start-all.sh --agentic                              # collector + app + OpenClaw gateway
# or just the gateway (app + collector already up):  ./run-openclaw.sh
#   flags: --no-telemetry (don't export spans while iterating on the plugin)
#          --foreground   (block on the container so launchd can supervise it)
```

The gateway comes up on **http://127.0.0.1:18789** (Control UI token prints on
start), using Ollama `llama3.2:3b`, workspace pinned to the disposable
`~/DemoBotDecoy`.

**The demo:** ask the agent to *"Summarize today's formulary bulletin in my
inbox."* The bulletin hides an instruction to exfiltrate `patients/roster.csv`.
With `TOOL_GUARD_ENABLED=False` (default) the agent exfiltrates and the
governance row reads `policy_action=allow` on a call that shipped PHI — the
unguarded control. With `TOOL_GUARD_ENABLED=True` the call is **blocked** (live
AI Defense fires PII/PHI). Telemetry flows either way; the contrast is the point.

**Toggle off:** `podman stop pseudoco-assistant-openclaw` removes the integration entirely.
`TOOL_GUARD_ENABLED` is a separate switch that gates *enforcement*, not whether
the gateway runs.

> ⚠️ The guard is **fail-closed**: with enforcement on, a down app (`:8001`)
> denies every tool call — the agent looks broken, not the app. Keep it running.

**Verify:** `./tests/observability/verify_openclaw_observability.sh` (Tier 0 runs
even with the gateway down). Auto-start at login is opt-in:
`./deploy/launchd/install.sh --with-openclaw`.

## API Endpoints

### Chat API
- `POST /api/chat/session/new` - Create new session
- `POST /api/chat/message` - Send message
- `GET /api/chat/session/{session_id}` - Get session history
- `GET /api/chat/disclaimer` - Get medical disclaimer

### Admin API
- `GET /admin/logs/interactions` - Get AI interaction logs
- `GET /admin/logs/escalations` - Get escalation queue
- `GET /admin/logs/metrics` - Get system metrics
- `GET /admin/logs/export` - Export logs (JSON/CSV)
- `GET /admin/governance/session/{id}` - Get complete session governance data
- `PUT /admin/escalations/{id}/review` - Update escalation review status

## Governance Logging

### Log Files
All logs are stored in the `logs/` directory:

- `ai_governance.json`: All AI interactions with full telemetry
- `escalations.json`: Escalated cases requiring review
- `audit_trail.json`: System audit events
- `errors.json`: Error logs
- `application.log`: Application-level logs

### Log Rotation
- **Max File Size**: 10MB (configurable)
- **Retention**: 90 days (configurable)
- **Format**: JSON lines for easy parsing

### Database Logging
All governance logs are also stored in SQLite tables with indexes for:
- Timestamp queries
- Session lookups
- Safety flag filtering
- Performance analysis

## Configuration

Edit `.env` file to customize:

```env
# AI Provider Configuration
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_key_here
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929

# OpenAI-compatible example:
# AI_PROVIDER=openai
# OPENAI_API_KEY=your_key_here
# OPENAI_MODEL=gpt-4o
# OPENAI_BASE_URL=https://api.openai.com/v1
#
# DeepSeek example:
# OPENAI_MODEL=deepseek-chat
# OPENAI_BASE_URL=https://api.deepseek.com

# Server
PORT=8001
DEBUG=True

# Logging
LOG_LEVEL=INFO
LOG_TO_FILE=True
LOG_TO_CONSOLE=True
LOG_TO_DATABASE=True
LOG_ROTATION_SIZE=10485760  # 10MB
LOG_RETENTION_DAYS=90

# Safety
PII_INJECTION_RATE=0.25  # matches the code default
MAX_CLARIFYING_QUESTIONS=2

# Session
SESSION_TIMEOUT_MINUTES=30

# Agentic orchestration (LangChain + LangGraph)
USE_AGENTIC_ENGINE=True              # False = legacy RecommendationEngine path
AGENTIC_WORKFLOW_NAME=pseudoco_multi_agent

# Agentic observability (OpenTelemetry GenAI)
OTEL_ENABLED=False                   # master switch for code-based GenAI tracing
OTEL_SERVICE_NAME=pseudoco-assistant
# Export endpoint/headers/protocol use the standard OTEL_* env vars, e.g.:
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

## Safety Features

### Emergency Detection
Automatically detects and escalates:
- Chest pain
- Difficulty breathing
- Loss of consciousness
- Severe bleeding
- Stroke symptoms
- Self-harm ideation
- Anaphylaxis
- And more...

### Vulnerable Population Protection
Special handling for:
- Infants and toddlers (<2 years)
- Pregnant individuals
- Elderly with complex conditions

### Medication Safety
- Detects potential drug interactions
- Never provides prescription dosages
- Escalates for pediatric medication questions

## Monitoring & Analytics

### Metrics Dashboard
The admin interface provides:
- Total interactions count
- Escalation rate
- Average response latency
- Token usage statistics
- PII detection count
- Guardrail trigger frequency
- Severity distribution
- Recent interaction logs

### Governance Tracking
Every AI interaction logs:
- Complete input/output
- Token usage and costs
- Performance metrics
- Safety violations
- PII detection
- Confidence scores
- Escalation triggers

## Agentic Observability (OpenTelemetry)

When `OTEL_ENABLED=True`, the workflow emits code-based GenAI spans following the
OpenTelemetry GenAI semantic conventions (`gen_ai.*`):

- **Workflow span** per chat turn (named by `AGENTIC_WORKFLOW_NAME`)
- **Agent span** per specialist node (carries the active `agent_name`)
- **LLM span** per model call, with token usage and response metadata

Spans are exported over OTLP using the standard `OTEL_*` environment variables and
are designed for Splunk AI Agent Monitoring. The `request_id` / `trace_id` used in
spans are the same IDs written to the governance logs, so traces and governance
events correlate. The telemetry layer (`backend/telemetry/otel.py`) degrades
gracefully: if the optional `opentelemetry-util-genai` package is absent it falls
back to plain OTel spans carrying the same `gen_ai.*` attributes, and if no
endpoint is configured under `DEBUG`, spans print to the console.

## Development

### Project Structure
```
medadvice_v3/
├── backend/
│   ├── main.py              # FastAPI application (initializes OTel + DB)
│   ├── config.py            # Configuration management
│   ├── agents/              # LangGraph multi-agent orchestration
│   │   ├── graph.py         # Supervisor + per-theme subgraph assembly
│   │   ├── supervisor.py    # Router node + theme routing
│   │   ├── state.py         # PseudoCoAssistantState shared-state model
│   │   ├── llm.py           # LangChain chat-model factory + normalization
│   │   ├── themes/          # Per-theme configs (medadvice, taxadvice, ...)
│   │   └── nodes/           # Specialist nodes (policy, defense, intake,
│   │       │                #   domain_agent, safety, injection,
│   │       │                #   compliance, governance, shared)
│   ├── telemetry/
│   │   └── otel.py          # OpenTelemetry GenAI init + span helpers
│   ├── routers/
│   │   ├── chat.py          # Chat endpoints (agentic dispatch + fallback)
│   │   └── admin.py         # Admin endpoints
│   ├── services/            # Content/business library (reused by nodes)
│   │   ├── recommendation_engine.py
│   │   ├── ai_client.py     # Legacy provider abstraction (fallback path)
│   │   ├── ai_defense.py    # Cisco AI Defense guardrail client
│   │   ├── clarifying_questions.py
│   │   ├── escalation_rules.py
│   │   ├── auto_prompter.py
│   │   └── enduser_pool.py
│   ├── models/
│   │   ├── schemas.py       # Pydantic models
│   │   └── db_models.py     # SQLAlchemy models
│   ├── database/
│   │   └── db.py            # Database initialization
│   ├── logging/
│   │   ├── governance_logger.py
│   │   ├── log_handlers.py
│   │   └── log_schemas.py
│   └── middleware/
│       └── request_logging.py
├── frontend/
│   ├── index.html           # Chat interface
│   ├── admin.html           # Admin dashboard
│   ├── governance.html      # Governance viewer
│   └── js/
│       ├── chat.js
│       └── admin.js
├── logs/                    # Log files (auto-created)
├── requirements.txt
├── .env.example
├── ARCHITECTURE.md
├── TESTING_GUIDE.md
└── README.md
```

### Adding Custom Escalation Rules
Edit `backend/services/escalation_rules.py`:

```python
# Add to EMERGENCY_SYMPTOMS list
EMERGENCY_SYMPTOMS = [
    "your_new_symptom",
    # ...
]
```

### Customizing Clarifying Questions
Edit `backend/services/clarifying_questions.py`:

```python
CRITICAL_QUESTIONS = [
    {
        "category": "custom_question",
        "condition": lambda text: "keyword" in text,
        "question": "Your question here?"
    }
]
```

## Testing

### Manual Testing
1. Start the application
2. Navigate to http://localhost:8001/app
3. Accept disclaimer
4. Test various scenarios:
   - Simple symptom query
   - Emergency symptoms (should escalate)
   - Medication questions
   - Unclear queries (should ask clarifying questions)

### Check Logs
```bash
# View governance logs
cat logs/ai_governance.json | jq .

# View escalations
cat logs/escalations.json | jq .

# Monitor real-time
tail -f logs/application.log
```

### API Testing
Use the interactive API docs at http://localhost:8001/docs

## Security Considerations

### Production Deployment
- Use HTTPS (TLS/SSL certificates)
- Set `DEBUG=False` in production
- Use environment variables for secrets
- Implement authentication for admin endpoints
- Configure CORS appropriately
- Use production database (PostgreSQL recommended)
- Enable rate limiting
- Regular security audits

### Data Privacy
- All conversations are logged for safety monitoring
- Implement data retention policies
- HIPAA compliance requires additional safeguards
- Ensure proper PII handling and anonymization
- Regular audits of escalated cases

## Troubleshooting

### Database Issues
```bash
# Delete and recreate database
rm medadvice.db
python -m backend.main
```

### Import Errors
```bash
# Ensure you're in the virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### API Key Issues
```bash
# Verify API key is set for your selected provider
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# Or check .env file
cat .env | grep -E 'AI_PROVIDER|ANTHROPIC_API_KEY|OPENAI_API_KEY'
```

## License

This is a demonstration application. Not licensed for medical use without proper regulatory approval.

## Disclaimer

**THIS SOFTWARE IS FOR DEMONSTRATION PURPOSES ONLY.**

This application is NOT:
- A replacement for professional medical care
- FDA approved
- HIPAA compliant out-of-the-box
- Licensed for clinical use
- Intended for diagnosis or treatment

Always consult qualified healthcare professionals for medical advice.

## Support

For issues or questions:
1. Check the logs in `logs/` directory
2. Review the admin dashboard metrics
3. Check governance logs for specific sessions
4. Review this README

## Version History

**v3.1.0** (2026-06)
- Rebuilt orchestration on LangChain + LangGraph as a supervisor-routed multi-agent system
- Per-theme decomposed agent subgraphs for all six Application Themes
- Code-based OpenTelemetry GenAI instrumentation (Workflow / Agent / LLM spans) for Splunk AI Agent Monitoring
- Feature-flagged with transparent fallback to the legacy engine; governance-log contract preserved
- Documentation consolidated

**v3.0.0** (2026-01-15)
- Initial release
- Comprehensive AI governance logging
- Escalation system with human review queue
- Multi-destination logging (file, DB, console)
- OpenTelemetry-compliant log schema
- Admin dashboard with metrics
- Governance log viewer
- Safety guardrails and natural PII/PHI integration for testing

## Additional Documentation

- **[Architecture](ARCHITECTURE.md)** - System architecture (LangGraph multi-agent design, governance, OTel)
- **[Testing Guide](TESTING_GUIDE.md)** - Comprehensive testing procedures, including the synthetic PII/PHI injection reference
- **[Quickstart](QUICKSTART.md)** - Fast setup and run instructions
- **[OpenShift deployment](deploy/openshift/README.md)** - In-cluster build, remote NIM via `provider=openai`, AI Defense CA chain
- **[System Policies](SYSTEM_POLICIES.md)** - Internal policy / guardrail reference
- **[Project Summary](PROJECT_SUMMARY.md)** - High-level project overview
