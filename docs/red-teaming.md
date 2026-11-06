# AI Defense AI Red Teaming against PseudoCo Assistant

Cisco AI Defense **AI Red Teaming** (Security Cloud Control → AI Defense → AI Red
Teaming) sends a library of attack prompts to a *target* and scores the answers.
This page covers the endpoint that target points at and how to configure it.

## Why a separate endpoint

A red-teaming target is a URL plus a JSON request template. The only thing AI
Defense fills into that template is `{{prompt}}`. The UI's own validator rejects
a template without it and knows no other placeholder.

`POST /api/chat/message` needs a `session_id` and replays that session's whole
history to the model on every turn. A template can only hold a fixed
`session_id`, so every attack in a run would pile into one conversation. Each
attack would then see all the earlier ones, and the prompt would keep growing.

`POST /api/chat/completions` removes that problem. It is stateless and
OpenAI-compatible:

- **Every call is a brand-new session** with its own uuid, persisted and
  governed like any chat session.
- `messages` is an OpenAI-style list. The **last message is the turn** and must
  be a non-empty `user` message. Earlier `user` / `assistant` messages become
  the session's history, in order. That is how a multi-turn attack reaches the
  model.
- `system`, `developer` and `tool` messages are **dropped**. The app's own
  system prompt is part of what is under test, so a caller cannot replace it.
- The turn is exactly the `/api/chat/message` turn: same shared chain,
  guardrails, governance events, Splunk HEC / Agent Observability / APM
  telemetry and DB rows. Calling the endpoint counts as accepting the
  disclaimer.
- The answer is `choices[0].message.content`. A turn a guardrail blocks still
  returns **200**, with the block banner as the content, which is what the chat
  UI would show. The red team scores that text.

```json
POST /api/chat/completions
{
  "messages": [{"role": "user", "content": "..."}],
  "theme": "medadvice",
  "ai_defense_review": false
}

200
{
  "id": "chatcmpl-…",
  "object": "chat.completion",
  "model": "pseudoco-assistant",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "…"}, "finish_reason": "stop"}],
  "pseudoco_assistant_turn": {"session_id": "…", "type": "recommendation", "severity": "LOW", "escalated": false}
}
```

`content` may also be a list of OpenAI content parts. Only the `text` parts are
read. `model`, `temperature`, `max_tokens` and other OpenAI parameters are
accepted and ignored. `stream: true` gets 400.

### Guardrail state rides in the body

Every `ChatRequest` flag is also a field here, with the same meaning and the
same default: `theme`, `ai_defense_review`, `internal_policy_review`,
`agent_control_review`, `nemo_guardrails_review`, `multi_agent_mode`, the four
`force_*_injection` flags and `blueprint`. Put them in the request template as
constants. `tests/test_chat_completions.py` fails if a new `ChatRequest` flag
is not carried over.

| Run | Template constants |
|---|---|
| Unprotected baseline | `"ai_defense_review": false` |
| AI Defense runtime protection on | `"ai_defense_review": true` |
| Another theme | `"theme": "retail"` (any theme key) |

An unset flag means the server default. For API callers that is **off** for
AI Defense review, so a template that leaves it out runs unprotected.

## Authentication

The endpoint sits behind the app's access key like every other route. Besides
the login cookie and HTTP Basic (`curl -u x:$ACCESS_KEY`), the gate accepts the
raw key in an **`X-Access-Key`** header. That matches the target's "API Token"
setting, which is a header name plus a value.

## Configuring the target

AI Red Teaming → **Add component → Add target**:

1. **Target details.** Name: `PseudoCo Assistant - MedAdvice (pseudocoassistant.com)`.
   Target type: **Agent**. Modality: **Text**.
2. **Connection settings.**
   - Provider: **Custom Endpoint**. Data plane: **Cisco AI Defense SaaS**.
   - Model endpoint URL: `https://pseudocoassistant.com/api/chat/completions`
     (or another box's public URL). The red team calls it from Cisco's cloud,
     so it has to be the public tunnel, not localhost.
   - Enable endpoint streaming: **off**.
   - API provider: **OpenAI**. That prefills the multi-turn
     `message_request_config` (`messages` / `role` / `content`) that this
     endpoint speaks.
   - Request body template (baseline):
     ```json
     {"messages": [{"role": "user", "content": "{{prompt}}"}], "theme": "medadvice", "ai_defense_review": false}
     ```
   - Path to model response: `choices[0].message.content`
   - Authentication: **API Token**. Key `X-Access-Key`, value = the box's
     `ACCESS_KEY`. Paste it yourself; it is a secret.
3. **Advanced settings** and **Summary**, then save. Run **Test connection**
   before a full run.

Then **Start red teaming**, pick the target and a profile.

## What a run costs and where it lands

- Every attack is a real governed turn. It writes a conversation row and a
  governance event (Splunk `gen_ai:json`). It sends a trace to the theme's
  Agent Observability stream and spans to APM. Expect the Governance Logs page
  and the MedAdvice stream to fill with attack traffic during a run.
- The Mac runs the local Ollama model by default (`mistral-nemo:12b`): no API
  cost, but roughly 20–30 s per single-agent turn, and parallel attacks queue
  on the one local model. A large profile takes hours. With
  `multi_agent_mode: true` each turn makes several model calls and takes
  longer still.
- The tunnel and the app have to stay up for the whole run.

## Keeping it fresh

The skill `ai-defense-red-team-and-inventory`
(`.claude/skills/ai-defense-red-team-and-inventory/`) drives red teaming and
the AI Inventory scan through the AI Defense API with the PseudoCo org's
Management key. A desktop scheduled task runs its `refresh.py refresh` at
07:00 on the 5th of every month. One refresh does four things:

1. It re-scans `main` with `cisco-aibom` and uploads the result to AI
   Inventory. If `main` hasn't moved, it re-uploads the last report instead.
2. It starts a Quick Start run (1,998 prompts) against the "with AI Defense"
   target and waits for it, about 2 h.
3. It compares the run with the previous run on that target.
4. It writes a summary to `~/.ai-defense-refresh/reports/<date>/`.

The unprotected baseline is opt-in (`--targets protected,baseline`). With
every prompt reaching the local model, it runs past 10 h and hits Cisco's
per-attack deadline.
