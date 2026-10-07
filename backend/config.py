from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os
from pathlib import Path

# Manually load .env file as a workaround.
# Mirrors python-dotenv semantics: an already-exported real environment variable
# wins over the .env value (so `export ANTHROPIC_API_KEY=…` in the shell is not
# clobbered by a placeholder in .env), surrounding single/double quotes are
# stripped, and an unquoted trailing ` # comment` is dropped.
def _strip_env_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]  # quoted value: keep verbatim, no comment stripping
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):]
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                if key and key not in os.environ:
                    os.environ[key] = _strip_env_value(value)

# Use custom CA bundle that includes corporate proxy CAs (e.g. Cisco Secure Access)
_ca_bundle = Path(__file__).parent.parent / "ca-bundle.pem"
if _ca_bundle.exists():
    os.environ.setdefault("SSL_CERT_FILE", str(_ca_bundle))
    os.environ.setdefault("REQUESTS_CA_BUNDLE", str(_ca_bundle))

class Settings(BaseSettings):
    # AI Provider Selection (supports multiple providers)
    # "anthropic" = Direct Anthropic API (local development)
    # "bedrock" = AWS Bedrock (production on AWS)
    # "openai" = OpenAI-compatible APIs (OpenAI, DeepSeek, etc.)
    # "nvidia" = a local NVIDIA NIM container on this host (never the cloud API)
    ai_provider: str = "anthropic"

    # Anthropic API Configuration (used when ai_provider="anthropic")
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5-20250929"

    # AWS Bedrock Configuration (used when ai_provider="bedrock")
    aws_region: str = "us-east-1"
    # Cross-region inference profile ID. The previous default,
    # anthropic.claude-3-sonnet-20240229-v1:0, reached end-of-life on Bedrock in
    # July 2025 — selecting bedrock with the shipped default failed on the first
    # turn with a model-not-available error.
    # Exact availability is account- and region-specific; list what you can call
    # with:  aws bedrock list-inference-profiles --region $AWS_REGION
    bedrock_model_id: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

    # OpenAI-compatible API Configuration (used when ai_provider="openai")
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_reasoning: bool = False

    # NVIDIA NIM Configuration (used when ai_provider="nvidia")
    # provider=nvidia is LOCAL inference, always: a NIM (NVIDIA Inference
    # Microservice) container serving an OpenAI-compatible API on THIS host. It
    # is never the hosted API catalog (build.nvidia.com) — that is a cloud call,
    # and this provider exists to demonstrate on-box GPU inference. The base URL
    # must be loopback (enforced by backend/nvidia_nim.py wherever it is set); a
    # remote GPU box runs its own PseudoCo Assistant replica against its own NIM.
    nvidia_base_url: str = "http://localhost:8000/v1"
    # Model id the local NIM serves. A NIM serves exactly one model, so switching
    # models means running a different NIM image (deploy/ec2/ec2-bootstrap.sh
    # --with-nim <image>). nvidia-nemotron-nano-9b-v2 fits one A10G 24 GB
    # (g5.xlarge); nemotron-3-super-120b-a12b needs 8x H100-80GB.
    nvidia_model: str = "nvidia/nvidia-nemotron-nano-9b-v2"
    # Optional bearer token when the NIM was started behind an API-key gate.
    # Empty = none (a placeholder is sent because the openai client refuses an
    # empty key, and an unauthenticated NIM ignores it).
    nvidia_api_key: str = ""
    # Nemotron 3 reasoning ("thinking") mode. The models default it ON, which
    # spends tokens and latency and can wrap the JSON answer contract in a
    # trace, so PseudoCo Assistant sends chat_template_kwargs.enable_thinking=False unless
    # this is turned on.
    nvidia_reasoning: bool = False
    # top_p NVIDIA recommends for Nemotron 3 across tasks (temperature stays the
    # per-agent value each node chooses).
    nvidia_top_p: float = 0.95
    # NIM images offered in the model dropdown even before the local NIM is
    # reachable, each with what it takes to run: "<model id>|<GPU label>|<min
    # VRAM MB per GPU>|<GPU count>". The per-GPU floor is what the card
    # REPORTS (an A10G/L4 "24 GB" reports ~23 GB; an H100-80GB ~81.5 GB), not
    # its marketing size, so a matching box is not greyed out by rounding.
    nvidia_featured_models: str = (
        "nvidia/nvidia-nemotron-nano-9b-v2|1x A10G / L4 24 GB|22000|1,"
        "nvidia/nemotron-3-super-120b-a12b|8x H100-80GB|76000|8"
    )

    # Ollama Configuration (used when ai_provider="ollama")
    # Local, UNCENSORED open-source model served by a local `ollama serve` daemon
    # and called via langchain-ollama's ChatOllama. Workshop intent: an unaligned
    # model that WILL emit unsafe/toxic/PII output so the external guardrails
    # (Cisco AI Defense, Splunk Observability Cloud, Agent Observability) demonstrably catch it. ChatOllama
    # populates usage_metadata natively, so the telemetry/governance token
    # contract is identical to the cloud providers.
    ollama_model: str = "mistral-nemo:12b"
    ollama_base_url: str = "http://localhost:11434"
    # Context window passed to Ollama (num_ctx); 8192 fits the theme system prompt
    # plus the governance input directives with headroom.
    ollama_num_ctx: int = 8192
    # How long Ollama keeps the model resident after a call (passed to ChatOllama
    # as keep_alive). Without this the 5GB model unloads on its 5-minute default
    # and the next turn pays a cold reload. "30m" / "-1" (never) / seconds.
    ollama_keep_alive: str = "30m"
    # Model the NON-user-facing internal agents (coordinator + specialists) run on
    # when ai_provider="ollama". Kept on the CLEAN base so that selecting a
    # tampered/poisoned model as `ollama_model` only affects the user-facing
    # synthesizer — the internal calls stay fast and on-task. See
    # backend/agents/nodes/coordinator.py + specialists.py.
    ollama_model_internal: str = "mistral-nemo:12b"
    # Pre-load the Ollama model weights + compile the agent graph on startup (in
    # a background thread) so the first user turn never pays the multi-second
    # cold start. Disabled by the test suite, which stubs the LLM boundary.
    prewarm_llm: bool = True

    # Application
    app_name: str = "PseudoCo Assistant v4"
    app_version: str = "4.12.2"
    environment: str = "development"  # "development" or "production"
    debug: bool = True

    # Server
    host: str = "0.0.0.0"
    port: int = 8001

    # Identity of the box serving this instance, shown in the UI footer so a
    # multi-server deployment (Mac vs EC2 vs …) is distinguishable at a glance.
    # Empty = fall back to the OS hostname. Set SERVER_HOSTNAME in .env for a
    # friendlier label (e.g. "prod-us-east-1").
    server_hostname: str = ""

    # Public access gate. When set, every request (except /health) must send
    # this value as the HTTP Basic Auth password. Empty = gate disabled (local
    # dev). Supply via .env only — never hardcode.
    access_key: str = ""

    # Browser origins allowed to call this API cross-origin, comma-separated.
    # The UI is served same-origin by this very app, so it needs NO entry here —
    # this exists for an external browser client. Empty = no cross-origin access
    # (the safe default). Never set "*": these responses are credentialed
    # (cookie / Basic auth), and wildcard-plus-credentials is exactly the
    # combination browsers reject and attackers enjoy.
    cors_origins: str = ""

    @property
    def cors_origins_list(self) -> list:
        """Configured origins, plus this instance's own localhost origin."""
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        for own in (f"http://localhost:{self.port}", f"http://127.0.0.1:{self.port}"):
            if own not in origins:
                origins.append(own)
        return origins

    # Database (SQLite for local, PostgreSQL for AWS)
    database_url: str = "sqlite:///./medadvice.db"

    # Logging
    log_level: str = "INFO"
    log_to_file: bool = True
    log_to_console: bool = True
    log_to_database: bool = True
    log_rotation_size: int = 10485760  # 10MB
    log_retention_days: int = 90

    # Safety
    pii_injection_rate: float = 0.25  # 25% of responses will include synthetic PII/PHI
    toxic_injection_rate: float = 0.25  # 25% of responses will include toxic content
    hallucination_injection_rate: float = 0.25  # 25% of responses will include hallucinated content
    authority_injection_rate: float = 0.25  # 25% of responses will include outside-of-authority content
    require_disclaimer_acceptance: bool = True
    # 2, not 3: ClarifyingQuestionsService hardcoded 2 ("reduced from 3 to
    # minimize unnecessary questions") and never read this setting, so the
    # documented 3 was never the real limit. Keeping the shipped behavior and
    # making the setting actually drive it.
    max_clarifying_questions: int = 2
    # Appointment scheduling (docs/scheduling.md): the IANA zone used to render
    # slot labels when the browser does not send its own (client_tz). Slots are
    # stored as naive UTC like every other timestamp.
    scheduling_default_timezone: str = "America/New_York"

    # Cisco AI Defense (Inspection API - runtime policy review of user prompts)
    # https://developer.cisco.com/docs/ai-defense-inspection/
    # Master switch: when False the per-request toggle is ignored and no prompt
    # is ever sent off-box, regardless of the UI toggle state.
    ai_defense_enabled: bool = False
    # Inspection API key generated in the AI Defense UI when you create an
    # "API" connection. Sent in the X-Cisco-AI-Defense-API-Key header. Never
    # hardcode this - supply it via the environment / .env, or the Settings page's
    # "Cisco AI Defense" card (settings_store.set_integration_creds, which persists
    # to the local SQLite blob and applies without a restart).
    ai_defense_api_key: str = ""
    # Regional deployment of your AI Defense tenant. Drives the base URL:
    #   us -> https://us.api.inspect.aidefense.security.cisco.com
    #   eu -> https://eu.api.inspect.aidefense.security.cisco.com
    #   ap -> https://ap.api.inspect.aidefense.security.cisco.com
    ai_defense_region: str = "us"
    # Optional full base-URL override (takes precedence over region) for private
    # / hybrid deployments. Example: https://us.api.inspect.aidefense.security.cisco.com
    ai_defense_endpoint: str = ""
    # Inspection request timeout in seconds (httpx: per connect/read/write, not
    # a total). Kept generous: a timeout is an inspection error, so under
    # fail-closed a merely slow call blocks a benign turn.
    ai_defense_timeout: float = 30.0
    # Behavior when the Inspection API errors or returns a malformed response.
    # False = fail closed (block the prompt) — the documented secure default.
    # True  = fail open (allow the prompt through).
    ai_defense_fail_open: bool = False
    # Comma-separated list of AI Defense guardrails to enable explicitly on every
    # Inspection API call (sent as config.enabled_rules). Passing rules in the
    # request applies them directly instead of relying on the SCC-configured
    # policy, so enforcement is self-contained and direction-independent.
    # Rule names must match the API enum exactly. Leave empty to fall back to the
    # connection's UI-configured policy (config: {}).
    # Valid: Code Detection, Harassment, Hate Speech, PCI, PHI, PII,
    #        Prompt Injection, Profanity, Sexual Content & Exploitation,
    #        Social Division & Polarization, Violence & Public Safety Threats
    ai_defense_enabled_rules: str = (
        "PII,PHI,PCI,Harassment,Hate Speech,Profanity,"
        "Sexual Content & Exploitation,Violence & Public Safety Threats,"
        "Social Division & Polarization,Prompt Injection,Code Detection"
    )
    # Response-direction guardrails. The rules above are appropriate for the
    # *prompt* (user input); the model's *output* is a different risk surface, so
    # the response inspection enforces its own set. Prompt Injection and Code
    # Detection are prompt-direction concerns and are intentionally dropped here
    # (a response that quotes code is not itself an attack), leaving the
    # content-leak / content-harm guardrails that matter for generated output.
    ai_defense_response_enabled_rules: str = (
        "PII,PHI,PCI,Harassment,Hate Speech,Profanity,"
        "Sexual Content & Exploitation,Violence & Public Safety Threats"
    )
    # Custom AI Defense guardrail that flags PseudoCo Assistant exceeding its authority —
    # recommending a prescription-only (non-OTC) medication, dosage, or procedure.
    # This is NOT a Cisco standard rule: it must be created as a custom guardrail
    # on the AI Defense connection (SCC policy, enforced on the response/output
    # direction). When set, the name is appended to the response-direction
    # enabled_rules so connections that accept config.enabled_rules enforce it
    # directly. IMPORTANT: leave empty unless the guardrail actually exists on the
    # connection — sending an unknown rule name to a connection that accepts
    # enabled_rules can error and (fail-closed) block every response. On a
    # connection that already has an SCC policy bound, enabled_rules are ignored
    # entirely and enforcement comes from that console-configured policy.
    ai_defense_prescription_guardrail: str = ""

    # Session
    session_timeout_minutes: int = 30

    # -------------------------------------------------------------------------
    # Agentic tool guard (OpenClaw surface -> /api/toolguard/inspect)
    # -------------------------------------------------------------------------
    # The OpenClaw gateway's pseudoco-assistant-toolguard plugin submits every proposed
    # agent tool call here before execution. Evaluation always runs (policy +
    # optional AI Defense) so telemetry/governance stay honest either way;
    # tool_guard_enabled only controls whether a "block" verdict actually
    # denies the call. False = observe-only (the unguarded control run).
    tool_guard_enabled: bool = False
    # Comma-separated CONTAINER-side workspace roots the agent's file paths
    # must stay inside (the decoy workspace as the gateway container sees it).
    # Empty = containment check disabled.
    tool_guard_workspace_roots: str = "/home/node/.openclaw/workspace,/tmp"
    # Tools capable of side effects (exec / write / egress / channel actions).
    # Sensitive calls are escalated to AI Defense; benign ones short-circuit
    # locally so the guard adds no latency to reads.
    tool_guard_sensitive_tools: str = (
        "exec,bash,process,write,edit,apply_patch,web_fetch,browser,"
        "message,canvas,nodes,cron,gateway,sessions_spawn"
    )
    # Egress allowlist for URLs found in tool arguments (host or host:port).
    # Empty = deny-by-default: every egress host is unapproved.
    tool_guard_egress_allow_hosts: str = ""
    # Submit rendered sensitive/suspicious calls to Cisco AI Defense (when the
    # inspection client is configured). Error handling honors the existing
    # ai_defense_fail_open policy — there is deliberately no second flag.
    tool_guard_ai_defense: bool = True
    # Bound on the rendered tool-call text stored in governance events and
    # submitted to AI Defense. NOT a bound on what the policy checks read —
    # those run over the untruncated render (see services/tool_policy.py), and a
    # call too large to render fully is force-escalated to AI Defense.
    tool_guard_max_arg_chars: int = 4000

    # -------------------------------------------------------------------------
    # NemoClaw Guardrails (the "NemoClaw Guardrails" drawer toggle)
    # -------------------------------------------------------------------------
    # NVIDIA NemoClaw governs an OpenClaw agent with an OpenShell sandbox policy
    # (deny-by-default network egress, filesystem scopes, process rules, local-
    # only inference routing). PseudoCo Assistant evaluates its copy of that policy
    # (guardrails/nemoclaw/policy.yaml) on every agent tool call the gateway
    # submits to /api/toolguard/inspect — the policy layer — and, on a host that
    # runs the real NemoClaw runtime (run-nemoclaw.sh), also ingests the
    # sandbox's own OCSF denials. Unlike tool_guard_enabled, this toggle IS the
    # enforcement switch: ON = a NemoClaw policy block denies the call. Persisted
    # by the drawer toggle (settings_store), so .env only seeds the default.
    nemoclaw_guardrails_enabled: bool = False
    nemoclaw_policy_path: str = "guardrails/nemoclaw/policy.yaml"
    # Also run a NeMo Guardrails input rail over sensitive/suspicious tool calls
    # (NemoClaw pairs OpenShell policy with NeMo rails). Needs the NeMo master
    # switch on; otherwise silently skipped.
    nemoclaw_use_nemo_rails: bool = True

    # -------------------------------------------------------------------------
    # Agent Control ("Agent Observability Controls" -> runtime guardrail)
    # -------------------------------------------------------------------------
    # Galileo's Agent Control server evaluates each agent step against the
    # Controls defined centrally in the Galileo console (Controls dashboard) and
    # returns deny / steer / observe. PseudoCo Assistant submits the generated response as
    # a post-stage ``llm`` step, so a matching deny control (e.g.
    # "PseudoCoAssistant-block-hallucinated-output", which fails a response whose Galileo
    # Correctness score is below threshold) withholds the answer.
    #
    # Master switch: when False the per-request toggle is ignored and no step is
    # ever submitted, regardless of the UI toggle state. Credentials come from
    # AGENT_CONTROL_API_KEY / AGENT_CONTROL_CONSOLE_URL (the former GALILEO_*
    # names are honored with a deprecation warning) — with no API key the client
    # is a no-op. Trace logging is a separate integration (SPLUNK_AO_*, see
    # backend/agent_observability.py); these settings keep their names because
    # dashboards and detectors key on them.
    galileo_agent_control_enabled: bool = True
    # Agent Control server base URL. The multitenant deployment mirrors the
    # console host (console.multitenant… -> agent-control.multitenant…).
    galileo_agent_control_url: str = (
        "https://agent-control.multitenant.galileocloud.io"
    )
    # Agent + step identity registered with the server (POST /agents/initAgent).
    # Controls are attached to this agent name; the server's effective control
    # set for an evaluation is resolved from it. Must be >=10 chars, lowercase
    # [a-z0-9:_-] per the Agent Control contract.
    galileo_agent_control_agent_name: str = "pseudoco-assistant-agent"
    galileo_agent_control_step_name: str = "pseudoco-assistant-llm"
    # Evaluation request timeout in seconds. Server-side controls that call a
    # Luna scorer (correctness, PII, …) are an LLM-judge round-trip, so this is
    # deliberately looser than the AI Defense inspection timeout.
    galileo_agent_control_timeout: float = 25.0
    # Which transport evaluates the controls.
    #   auto   = prefer the server (POST /api/v1/evaluation) and fall back to
    #            client-side when the deployment cannot mint a runtime token
    #   server = server only (an unavailable runtime token means no verdict)
    #   client = always evaluate in-process
    # Client-side execution mirrors an Agent Control ``execution: "sdk"`` control:
    # PseudoCo Assistant reads the agent's control definitions from the management API and
    # runs their Luna conditions itself via the console API's /scorers/invoke, so
    # enforcement does not depend on the org's runtime-token grant.
    galileo_agent_control_execution: str = "auto"
    # How long a fetched set of control definitions is reused before refetching.
    # Definitions change rarely; refetching per turn would add a round-trip to
    # every response.
    galileo_agent_control_refresh_seconds: float = 300.0
    # Behavior when the Agent Control server errors, is unreachable, or cannot
    # mint a runtime token. True = fail open (release the response, log the
    # error) — the default, because this is an observability-first control
    # surface layered *after* the internal policy engine and Cisco AI Defense.
    # False = fail closed (withhold the response), matching AI Defense's
    # posture; only sensible once runtime enforcement is verified working.
    galileo_agent_control_fail_open: bool = True
    # Which Agent Control server the guardrail talks to:
    #   galileo   = the standalone Galileo console + agent-control server above
    #               (API key -> console JWT -> runtime token), the default;
    #   splunk_ao = the Agent Control server hosted INSIDE Splunk Observability
    #               Cloud's Agent Observability
    #               (https://app.<realm>.observability.splunkcloud.com/ao/agent-control),
    #               authenticated with an O11y API token sent as X-SF-Token.
    #               Controls are authored in the Agent Observability Controls UI
    #               and attached to an Agent stream; the guardrail binds each turn
    #               to the SAME stream the turn is logged to
    #               (backend/agent_observability._stream_for), so a control
    #               attached to "TelecomChatbot" governs telecom turns.
    galileo_agent_control_backend: str = "galileo"
    # Which stages run: "post" (judge the answer), "pre" (screen the prompt) or
    # "pre,post". Empty = the backend's default — post only on galileo (its
    # console controls are post-scoped), pre,post on splunk_ao.
    galileo_agent_control_stages: str = ""
    # splunk_ao backend only. URL override (empty = derived from SPLUNK_AO_REALM);
    # the target type the AO gateway binds stream-attached controls under; the
    # step name the UI controls are scoped to (shown as type llm + this name).
    # Target type is "log_stream" — the splunk-ao SDK's own constant. Splunk's
    # how-to says "agent_stream", but the us1 gateway answers every call bound to
    # that type with 502 AUTH_UPSTREAM_REJECTED (verified 2026-09-23: controls
    # GET, attachment filter and runtime-token exchange), while log_stream
    # mints a runtime token and resolves the stream's bindings.
    splunk_ao_control_url: str = ""
    splunk_ao_control_target_type: str = "log_stream"
    splunk_ao_control_step_name: str = "complete_chat"

    # -------------------------------------------------------------------------
    # NVIDIA NeMo Guardrails (the "NeMo Guardrails" drawer toggle)
    # -------------------------------------------------------------------------
    # In-process nemoguardrails (core package only — never the [server] extra,
    # which drags starlette past the fastapi 0.109 pin). Input rails run after
    # Cisco AI Defense's prompt inspection; output rails run after
    # Agent Control and BEFORE AI Defense's response inspection, so Cisco stays
    # the last word on output. The judge is PseudoCo Assistant's ACTIVE chat model
    # (self-check rails), so this works on every provider with no cloud call;
    # NemoGuard content-safety is an optional SECOND local NIM.
    #
    # Master switch: when False the per-request toggle is ignored and no rail
    # ever runs, regardless of the UI toggle state.
    nemo_guardrails_enabled: bool = False
    # Which rails to activate, comma-separated. self_check_input /
    # self_check_output are NeMo's built-in LLM self-checks (prompts in
    # guardrails/nemo/prompts.yml); overreach is PseudoCo Assistant's prescriptive-
    # overreach output rail, the NeMo counterpart of the AI Defense custom
    # guardrail (a prescription-only drug / dosage / binding position).
    nemo_guardrails_rails: str = "self_check_input,self_check_output,overreach"
    # Optional NemoGuard content-safety NIM on THIS host (loopback, like the
    # inference NIM), e.g. http://localhost:8001/v1. Empty = the content-safety
    # rails are not loaded (an 8B guard NIM does not co-reside with the 9B
    # inference NIM on one A10G).
    nemo_guardrails_content_safety_url: str = ""
    nemo_guardrails_content_safety_model: str = "nvidia/llama-3.1-nemoguard-8b-content-safety"
    # Behavior when the rails cannot produce a verdict (judge error, bad
    # config). True = fail open (release the turn, log) — the default, because
    # this layer sits between the internal policy engine and Cisco AI Defense.
    nemo_guardrails_fail_open: bool = True
    # Output cap for the judge calls (a Yes/No answer needs very few tokens).
    nemo_guardrails_judge_max_tokens: int = 64

    # -------------------------------------------------------------------------
    # Agentic orchestration (LangChain + LangGraph)
    # -------------------------------------------------------------------------
    # When True, /api/chat/message is served by the LangGraph multi-agent
    # workflow (backend/agents). When the agentic dependencies are unavailable
    # or the graph fails to build, the router transparently falls back to the
    # legacy RecommendationEngine so the service keeps running.
    use_agentic_engine: bool = True
    # Name promoted to the OTel GenAI Workflow span (AI Agent Monitoring groups
    # traces by this workflow name in Splunk Observability Cloud). Since the
    # blueprints, each blueprint carries its own workflow_name; this remains
    # the fallback for callers that predate them.
    agentic_workflow_name: str = "pseudoco_multi_agent"
    # Which agentic architecture serves chat turns by default. There is no
    # picker in the UI, so this (or a per-request override) is the only way to
    # leave it. Keys: pseudoco_multi_agent (the shipped architecture) |
    # nvidia_virtual_assistant (the NVIDIA AI Virtual Assistant blueprint). A
    # request may override it with ChatRequest.blueprint. Every guardrail /
    # toggle / governance field is shared by all blueprints (CLAUDE.md
    # "Blueprint feature parity").
    active_blueprint: str = "pseudoco_multi_agent"
    # NVIDIA AI Virtual Assistant blueprint knobs.
    # How the primary assistant routes to sub-assistants: auto = native tool
    # calling when the provider supports it (anthropic/openai/bedrock/nvidia),
    # otherwise a JSON tool-call plan (Ollama models without a tools template);
    # tools | json force one.
    blueprint_routing: str = "auto"
    # LOCAL embedding endpoint for the blueprint's knowledge retrieval (an
    # OpenAI-compatible /v1/embeddings on this host, e.g. a
    # llama-nemotron-embed-1b-v2 NIM). Empty = keyword retrieval (no model).
    blueprint_embed_url: str = ""
    blueprint_embed_model: str = "nvidia/llama-nemotron-embed-1b-v2"

    # -------------------------------------------------------------------------
    # Agentic observability (OpenTelemetry GenAI -> Splunk Observability Cloud)
    # -------------------------------------------------------------------------
    # Master switch for code-based GenAI tracing. Export endpoint, headers, and
    # protocol are read from the standard OTEL_* environment variables
    # (e.g. OTEL_EXPORTER_OTLP_ENDPOINT). When no endpoint is configured and
    # debug is on, spans are printed to the console.
    otel_enabled: bool = False
    otel_service_name: str = "pseudoco-assistant"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @property
    def ai_defense_chat_inspect_url(self) -> str:
        """Full URL of the AI Defense Chat Inspection endpoint.

        Grounded on the documented contract:
        POST {base}/api/v1/inspect/chat where base is the regional host
        https://{region}.api.inspect.aidefense.security.cisco.com.
        An explicit ai_defense_endpoint override wins when provided.
        """
        base = (self.ai_defense_endpoint or "").strip().rstrip("/")
        if not base:
            region = (self.ai_defense_region or "us").strip().lower()
            base = f"https://{region}.api.inspect.aidefense.security.cisco.com"
        return f"{base}/api/v1/inspect/chat"

    @property
    def ai_defense_rule_config(self) -> list[dict]:
        """Parsed enabled_rules for the Inspection API config block.

        Returns a list of ``{"rule_name": <name>}`` dicts built from
        ``ai_defense_enabled_rules``. Empty/whitespace entries are dropped. An
        empty result means callers should send ``config: {}`` and fall back to
        the connection's UI-configured policy.
        """
        return [
            {"rule_name": name}
            for name in (
                part.strip() for part in (self.ai_defense_enabled_rules or "").split(",")
            )
            if name
        ]

    @property
    def ai_defense_response_rule_config(self) -> list[dict]:
        """Parsed enabled_rules for the *response*-direction inspection.

        Built from ``ai_defense_response_enabled_rules`` plus the custom
        ``ai_defense_prescription_guardrail`` (when configured), as
        ``{"rule_name": <name>}`` dicts. An empty result means callers should
        send ``config: {}`` and defer to the connection's UI-configured policy.
        """
        names = [
            part.strip()
            for part in (self.ai_defense_response_enabled_rules or "").split(",")
        ]
        prescription = (self.ai_defense_prescription_guardrail or "").strip()
        if prescription:
            names.append(prescription)
        return [{"rule_name": name} for name in names if name]

    @property
    def tool_guard_sensitive_tools_set(self) -> set:
        """Lowercased set parsed from ``tool_guard_sensitive_tools``."""
        return {
            name.strip().lower()
            for name in (self.tool_guard_sensitive_tools or "").split(",")
            if name.strip()
        }

    @property
    def tool_guard_egress_hosts_set(self) -> set:
        """Lowercased host[:port] allowlist parsed from
        ``tool_guard_egress_allow_hosts``. Empty set = deny all egress."""
        return {
            host.strip().lower()
            for host in (self.tool_guard_egress_allow_hosts or "").split(",")
            if host.strip()
        }

    @property
    def tool_guard_workspace_roots_list(self) -> list[str]:
        """Normalized workspace roots parsed from ``tool_guard_workspace_roots``
        (trailing slashes stripped; empty entries dropped)."""
        return [
            root.strip().rstrip("/") or "/"
            for root in (self.tool_guard_workspace_roots or "").split(",")
            if root.strip()
        ]

# Global settings instance
settings = Settings()

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
DATABASE_DIR = BASE_DIR

# Ensure directories exist
LOGS_DIR.mkdir(exist_ok=True)
