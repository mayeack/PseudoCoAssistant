# PseudoCo Assistant v3 - System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                             │
├─────────────────────────────────────────────────────────────────┤
│  Chat UI          Admin Dashboard       Governance Viewer        │
│  (index.html)     (admin.html)          (governance.html)        │
└────────────┬──────────────┬──────────────────┬──────────────────┘
             │              │                  │
             └──────────────┴──────────────────┘
                            │
                    ┌───────▼────────┐
                    │   NGINX/LB     │ (Optional)
                    └───────┬────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                     API GATEWAY LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│                         FastAPI                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Chat Router │  │ Admin Router │  │ Health Check │          │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘          │
│         │                  │                                      │
│    ┌────▼──────────────────▼────┐                               │
│    │  Request Logging Middleware │                               │
│    └────────────┬────────────────┘                               │
└─────────────────┼──────────────────────────────────────────────┘
                  │
┌─────────────────▼─────────────────────────────────────────────┐
│              AGENTIC ORCHESTRATION LAYER (LangGraph)           │
├───────────────────────────────────────────────────────────────┤
│   START ─▶ router (supervisor) ─▶ {theme}_subgraph ─▶ END      │
│                                                                 │
│   Per-theme pipeline = shared guardrail chain around the        │
│   selected BLUEPRINT core (backend/agents/blueprints):          │
│   policy ▶ prompt_defense ▶ nemo_input_rails ▶ <core> ▶ safety  │
│     ▶ injection ▶ compliance ▶ agent_control ▶ nemo_output_rails│
│     ▶ response_defense ▶ governance                             │
│   cores: pseudoco_multi_agent (intake ▶ [coordinator ▶           │
│          specialists] ▶ synthesizer) | nvidia_virtual_assistant │
│          (fetch_record ▶ ask_clarification ▶ primary_assistant  │
│           ▶ sub_assistant ▶ respond)                            │
│   (any node may short-circuit to END: policy/AIDefense/NeMo/    │
│    Agent Control block, clarifying question, generation error)  │
│                                                                 │
│   Themes: medadvice · taxadvice · benefitsadvice · legaladvice  │
│           · financeadvice · telecomchatbot · retail             │
│           · manufacturing                                       │
└───────────────────────────────┬───────────────────────────────┘
                                 │ nodes delegate to ▼
┌─────────────────▼─────────────────────────────────────────────┐
│              SERVICE / CONTENT LIBRARY                         │
├───────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐     │
│  │  RecommendationEngine (content + patterns library)    │     │
│  │  • Theme prompts  • Response formatting               │     │
│  │  • PII / toxic / hallucination injection (testing)    │     │
│  │  • Severity normalization  • AI Defense block copy    │     │
│  └────────┬─────────────────────────────────────────────┘     │
│           │                                                     │
│  ┌────────▼──────────────┐  ┌─────────────────────────┐      │
│  │ Clarifying Questions   │  │  Escalation Rules       │      │
│  │ Service                │  │  Engine                 │      │
│  │ • Question Selection   │  │  • Emergency Detection  │      │
│  │ • Context Analysis     │  │  • Vulnerability Check  │      │
│  │ • Info Extraction      │  │  • Risk Assessment      │      │
│  └────────────────────────┘  └─────────────────────────┘      │
│  ┌────────────────────────┐  ┌─────────────────────────┐      │
│  │ AI Defense Client       │  │ LangChain LLM Factory   │      │
│  │ (prompt/response guard) │  │ (Anthropic/Bedrock/     │      │
│  │                         │  │  OpenAI-compatible)     │      │
│  └────────────────────────┘  └─────────────────────────┘      │
└───────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                   GOVERNANCE LAYER                             │
├───────────────────────────────────────────────────────────────┤
│                    Governance Logger                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Log Request │  │ Log Response│  │Log Escalation│          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘           │
│         │                 │                 │                  │
│         └─────────────────┴─────────────────┘                  │
│                           │                                     │
│              ┌────────────▼───────────────┐                    │
│              │   Multi-Destination Writer │                    │
│              └────┬───────┬───────┬───────┘                    │
│                   │       │       │                            │
└───────────────────┼───────┼───────┼────────────────────────────┘
                    │       │       │
        ┌───────────▼──┐ ┌──▼───┐ ┌▼─────────┐
        │  File Logs   │ │  DB  │ │ Console  │
        │              │ │      │ │          │
        │ • governance │ │Tables│ │  stdout  │
        │ • escalation │ │      │ │          │
        │ • audit      │ │      │ │          │
        │ • errors     │ │      │ │          │
        └──────────────┘ └──────┘ └──────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                     DATA LAYER                                 │
├───────────────────────────────────────────────────────────────┤
│                      SQLite Database                           │
│  ┌────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ conversations  │  │ ai_governance_   │  │ escalation_  │  │
│  │                │  │ logs             │  │ queue        │  │
│  └────────────────┘  └──────────────────┘  └──────────────┘  │
│  ┌────────────────┐                                           │
│  │ audit_logs     │                                           │
│  └────────────────┘                                           │
└───────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                  EXTERNAL SERVICES                             │
├───────────────────────────────────────────────────────────────┤
│        Anthropic API / AWS Bedrock / OpenAI-Compatible APIs    │
│        Claude, Bedrock-hosted models, OpenAI, DeepSeek, etc.   │
└───────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Client Layer

#### Chat Interface (`index.html`)
- Single-page application
- Real-time message streaming
- Color-coded message types
- Session management
- Disclaimer acceptance

#### Admin Dashboard (`admin.html`)
- Real-time metrics visualization
- Escalation queue management
- Interaction log viewer
- Chart.js integration
- CSV/JSON export

#### Governance Viewer (`governance.html`)
- Session-specific governance data
- Complete audit trail
- PII/safety flag visualization
- Escalation details
- Performance metrics

### 2. API Gateway Layer

#### FastAPI Application
- RESTful API endpoints
- Automatic OpenAPI documentation
- Request validation (Pydantic)
- CORS middleware
- Static file serving

#### Middleware
- Request logging
- Error handling
- Request ID injection
- Performance monitoring

### 3. Agentic Orchestration Layer (LangGraph)

The chat turn is served by a supervisor-routed LangGraph workflow
(`backend/agents/`). It replaces the monolithic `process_message()` pipeline with a
graph of small, independently observable nodes.

**Topology:**
```
START -> router -> {theme}_subgraph -> END
```

**Per-theme decomposed pipeline** (`build_theme_subgraph`):
```
policy -> prompt_defense -> intake -> domain(theme) -> safety
      -> injection -> compliance -> response_defense -> governance
```

**Components:**
- **Supervisor / Router** (`supervisor.py`): sets correlation IDs (`request_id`,
  `trace_id`), resolves the Application Theme, logs the input event, and routes to
  the matching theme subgraph via a conditional edge.
- **Shared state** (`state.py`): `PseudoCoAssistantState` `TypedDict` carries the turn's
  inputs, intermediate agent outputs, LLM usage, safety/injection flags, and the
  final `result` dict between nodes.
- **Specialist nodes** (`nodes/`): each node wraps an existing service so the
  business logic and governance contract are unchanged:
  - `policy` - internal policy block check
  - `prompt_defense` / `response_defense` - Cisco AI Defense guardrail
  - `intake` - clarifying questions
  - `domain` - theme LLM call (built per theme by `make_domain_agent`)
  - `safety` - escalation-rule evaluation
  - `injection` - synthetic PII / toxic / hallucination injection (testing)
  - `compliance` - final display formatting
  - `governance` - emits the Splunk governance log events
- **Themes** (`themes/`): `medadvice` (default), `taxadvice`, `benefitsadvice`,
  `legaladvice`, `financeadvice`, `telecomchatbot`, `retail`, `manufacturing`. Each is
  a `ThemeConfig` sourcing its prompt/patterns from the content library;
  `telecomchatbot` and `retail` are conversational (free-text `reply`).
- **LLM factory** (`llm.py`): builds `ChatAnthropic` / `ChatBedrockConverse` /
  `ChatOpenAI` from `settings.ai_provider` and normalizes responses (text, usage,
  metadata) for the governance logger.

Any node may set `terminal` to short-circuit the remaining pipeline straight to
the subgraph's `END` (policy block, AI Defense block, clarifying question, or
generation error).

**Feature flag & fallback:** `settings.use_agentic_engine` gates the workflow in
`routers/chat.py`. If the agentic dependencies are missing or the graph fails to
build, the request transparently falls back to
`RecommendationEngine.process_message`. Both paths return an identically-shaped
result and emit the same governance events.

### 4. Service / Content Library

#### Recommendation Engine
**Role:** Retained as the content/patterns library and the legacy fallback engine.
The agentic nodes delegate to it for theme prompts, response formatting, synthetic
injection patterns, severity normalization, and AI Defense block copy, keeping a
single source of truth.

**Key Functions:**
- `process_message()` - Legacy single-call entry point (fallback path)
- `_generate_recommendation()` - AI provider call (fallback path)
- `_format_recommendation()` - Response formatting, including the theme's EMERGENCY banner (reused by the `synthesizer` node)

#### Clarifying Questions Service
**Responsibilities:**
- Determines when to ask questions
- Selects appropriate questions
- Tracks questions asked
- Extracts user information

**Logic:**
- Maximum 3 questions per session
- Priority: Critical > Important
- Context-aware question selection
- Redundancy prevention

#### Escalation Rules Engine
**Responsibilities:**
- Evaluates escalation criteria
- Detects emergency symptoms
- Identifies vulnerable populations
- Assesses risk factors

**Triggers:**
- Emergency symptoms (chest pain, etc.)
- Age risk (infants, elderly)
- Pregnancy
- Multiple medications
- Self-harm ideation
- Low AI confidence
- User request

### 5. Governance Layer

#### Governance Logger
**Responsibilities:**
- Comprehensive AI interaction logging
- OpenTelemetry-compliant schemas
- Multi-destination writing
- Real-time monitoring

**Log Types:**
1. **Request Logs**
   - Input messages
   - Request parameters
   - Timestamp

2. **Response Logs**
   - Output messages
   - Token usage
   - Performance metrics
   - Safety flags

3. **Decision Logs**
   - Clarifying question decisions
   - Escalation triggers
   - Severity assessments

4. **Error Logs**
   - Exception details
   - Stack traces
   - Context information

5. **Escalation Logs**
   - Escalation reason
   - Conversation history
   - User demographics
   - Symptoms
   - Review status

6. **Audit Logs**
   - User actions
   - System events
   - Admin activities

#### Log Handlers
- **File Handler**: Rotated JSON logs
- **Database Handler**: Structured storage
- **Console Handler**: Real-time monitoring

### 6. Data Layer

#### Database Schema

**conversations**
```sql
- id (PK)
- session_id (UNIQUE, INDEXED)
- created_at (INDEXED)
- updated_at
- disclaimer_accepted
- final_severity
- escalated (INDEXED)
- messages (JSON)
- metadata (JSON)
```

**ai_governance_logs**
```sql
- id (PK)
- session_id (INDEXED)
- request_id (INDEXED)
- trace_id (INDEXED)
- timestamp (INDEXED)
- operation_name
- request_model
- response_model
- input_messages (JSON)
- output_messages (JSON)
- usage_input_tokens
- usage_output_tokens
- usage_output_tokens_cached
- usage_output_tokens_uncached
- usage_total_tokens
- pii_detected (INDEXED)
- safety_violated (INDEXED)
- guardrail_triggered (INDEXED)
- [50+ fields following OTel spec]
```

**escalation_queue**
```sql
- id (PK)
- escalation_id (UNIQUE, INDEXED)
- session_id (INDEXED)
- timestamp (INDEXED)
- severity (INDEXED)
- reason
- conversation_history (JSON)
- symptoms (JSON)
- review_status (INDEXED)
- reviewer_id
- review_notes
```

**audit_logs**
```sql
- id (PK)
- audit_id (UNIQUE, INDEXED)
- session_id (INDEXED)
- timestamp (INDEXED)
- action (INDEXED)
- actor
- details (JSON)
- ip_address
```

### 7. External Services

#### AI Provider APIs
- Providers: Anthropic, AWS Bedrock, or OpenAI-compatible APIs
- Example models: `claude-sonnet-4-5-20250929`, `anthropic.claude-3-sonnet-20240229-v1:0`, `gpt-4o`, `deepseek-chat`
- Max tokens: 2048
- Temperature: 0.7
- System prompt: Medical guidance rules
- Streaming: Supported (not implemented)

## Data Flow

### Normal Query Flow (Agentic)

```
1. User enters message
   ↓
2. Frontend sends POST /api/chat/message
   ↓
3. Request Logging Middleware logs request
   ↓
4. Chat Router validates input and dispatches the turn
   (settings.use_agentic_engine → LangGraph workflow; else legacy engine)
   ↓
5. Workflow span opens; router sets request_id/trace_id, resolves theme,
   logs the input event, and routes to the {theme}_subgraph
   ↓
6. policy            → internal policy block? ── yes → END (blocked)
   ↓
7. prompt_defense    → AI Defense flags prompt? ── yes → END (blocked)
   ↓
8. intake            → clarifying question needed? ── yes → END (question)
   ↓
9. domain(theme)     → LLM call (Agent + LLM spans); parse assessment,
                       guidance, severity, token usage
                       (single-agent default; with the "Multi-Agent Mode"
                       toggle ON — multi_agent_mode=true — this step expands
                       to coordinator → specialists → synthesizer, each with
                       its own Agent span)
   ↓
10. safety           → Escalation Rules evaluate; flag case if needed
   ↓
11. injection        → synthetic PII / toxic / hallucination (testing)
   ↓
12. compliance       → format final display text
   ↓
13. response_defense → AI Defense flags response? ── yes → END (blocked)
   ↓
14. governance       → log response (+ escalation) to file/DB/console,
                       reusing request_id/trace_id for log↔trace correlation
   ↓
15. Update conversation in database; return result to frontend
   ↓
16. Frontend displays message with color coding
```

### Escalation Flow

```
1. Escalation triggered by rules
   ↓
2. Create escalation record
   ↓
3. Extract symptoms from conversation
   ↓
4. Extract user demographics
   ↓
5. Governance Logger logs escalation
   ↓
6. Write to escalation_queue table
   ↓
7. Write to escalations.json file
   ↓
8. Add escalation badge to response
   ↓
9. Flag visible in Admin Dashboard
   ↓
10. Human reviewer can view and update status
```

## Security Architecture

### Authentication (Not Implemented)
For production, add:
- JWT tokens for API access
- OAuth2 for admin endpoints
- Role-based access control
- API rate limiting

### Data Protection
- Environment variables for secrets
- No credentials in code
- Secure session management
- Input validation (Pydantic)

### Compliance Considerations
- HIPAA: Additional safeguards needed
- GDPR: Data retention policies
- FDA: Not approved for medical use
- Regular security audits

## Scalability Considerations

### Current Limitations
- SQLite (single file database)
- In-memory session storage
- Single process

### Production Scaling

**Horizontal Scaling:**
```
Load Balancer
     │
     ├─ App Instance 1
     ├─ App Instance 2
     └─ App Instance N
         │
    Shared Database
    (PostgreSQL)
         │
    Redis Cache
    (Sessions)
```

**Improvements Needed:**
1. PostgreSQL instead of SQLite
2. Redis for session storage
3. Message queue for async processing
4. CDN for static assets
5. Separate logging service
6. Database connection pooling

## Monitoring & Observability

### Metrics Collected
- Total interactions
- Escalation rate
- Average latency
- Token usage
- PII detection count
- Guardrail trigger count
- Error rate
- Response time percentiles

### Agentic Tracing (OpenTelemetry GenAI)
Code-based GenAI instrumentation lives in `backend/telemetry/otel.py` and is
enabled with `settings.otel_enabled`. Per chat turn it emits:
- **Workflow span** (named by `settings.agentic_workflow_name`)
- **Agent span** per specialist node (carries `agent_name`)
- **LLM span** per model call (token usage + response metadata)

Spans follow the OTel GenAI semantic conventions (`gen_ai.*`) and export over OTLP
using the standard `OTEL_*` environment variables, targeting Splunk AI Agent
Monitoring. The `request_id` / `trace_id` are shared with the governance logs so
traces and governance events correlate. The layer degrades gracefully: it falls
back to plain OTel spans when `opentelemetry-util-genai` is unavailable, and prints
spans to the console when no endpoint is configured under `DEBUG`.

### Log Aggregation
For production:
- Splunk/ELK stack for log aggregation
- Prometheus for metrics
- Grafana for visualization
- OpenTelemetry for distributed tracing

### Alerting
Suggested alerts:
- High escalation rate (>20%)
- High PII detection (>10%)
- High latency (>5s)
- Error rate spike
- Database connection failures

## Performance Characteristics

### Expected Latency
- Database query: <10ms
- AI provider call: 1-3s
- Total request: 1-5s
- File logging: <5ms

### Throughput
- Current: ~100 requests/minute
- With scaling: 1000+ requests/minute

### Resource Usage
- Memory: ~200MB base
- CPU: Low (mostly I/O bound)
- Disk: Grows with logs/database

## Technology Stack Summary

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | HTML/CSS/JS | User interface |
| CSS Framework | TailwindCSS | Styling |
| Charts | Chart.js | Visualization |
| API Framework | FastAPI | REST API |
| Orchestration | LangChain + LangGraph | Multi-agent workflow |
| Observability | OpenTelemetry GenAI | Workflow/Agent/LLM tracing |
| ORM | SQLAlchemy | Database access |
| Database | SQLite | Data persistence |
| AI | Anthropic, Bedrock, OpenAI-compatible APIs | LLM responses |
| Validation | Pydantic | Data validation |
| Server | Uvicorn | ASGI server |
| Python | 3.11+ | Runtime |

## Deployment Architecture

### Development
```
Local Machine
  └─ Python venv
     └─ Uvicorn (single worker)
        └─ SQLite database
```

### Production (Recommended)
```
Docker Container
  └─ Gunicorn + Uvicorn workers
     ├─ PostgreSQL (external)
     ├─ Redis (sessions)
     └─ S3 (log storage)
```

## Future Enhancements

1. **Real-time Streaming**: WebSocket support for streaming responses
2. **Multi-modal**: Image upload for symptom photos
3. **Voice Input**: Speech-to-text integration
4. **Multi-language**: i18n support
5. **Mobile Apps**: React Native apps
6. **Advanced Analytics**: ML-based drift detection
7. **A/B Testing**: Prompt optimization
8. **Integration**: EHR system integration
9. **Advanced Auth**: SSO, MFA
10. **Caching**: Response caching for common queries
