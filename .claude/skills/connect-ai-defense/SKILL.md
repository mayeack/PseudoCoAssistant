---
name: connect-ai-defense
description: Connect a PseudoCo Assistant deployment (this Mac, an EC2 fleet replica, or the OpenClaw tool guard) to a Cisco AI Defense application in Security Cloud Control, and verify the connection end to end. Use when asked to connect/wire/hook PseudoCo Assistant or a medadviceN box up to AI Defense, to check whether AI Defense is actually enforcing on a box, when prompts are being blocked or NOT blocked unexpectedly, or when the AI Defense inspection key is rotated or a new connection is created.
---

# Connect PseudoCo Assistant to Cisco AI Defense

"Connecting" is not a network peering or an agent install. AI Defense runtime
protection for PseudoCo Assistant is an **outbound API integration**: the app calls the
Chat Inspection API before (and after) the model, and the API key it presents
is what binds the traffic to a specific **application + connection** in Security
Cloud Control (SCC). Point the key at a different connection and the traffic
shows up under a different app in the SCC console.

Current tenant: org **Yeack Industries**, application **YeackBot**, connection
type **API**, connection name **YeackBot**.

Everything below is already true for `/Applications/DemoBot` on this Mac and for
fleet replica 1 (`medadvice1.yeackbot.com`). Use this skill to reproduce it, to
verify it, or to repoint it.

## The whole integration is six env vars

In `.env` (see `.env.example` lines ~139–182 for the annotated originals):

| Var | Value in use | Notes |
|---|---|---|
| `AI_DEFENSE_ENABLED` | `True` | Master switch. The per-chat UI toggle is ignored when this is False. |
| `AI_DEFENSE_API_KEY` | 64-char key | Generated in SCC when the **API connection** is created. Shown once. Secret — `.env` only, never committed, never echoed into a transcript. |
| `AI_DEFENSE_REGION` | `us` | `us` \| `eu` \| `ap`. |
| `AI_DEFENSE_ENDPOINT` | `https://us.api.inspect.aidefense.security.cisco.com` | Optional; wins over region. |
| `AI_DEFENSE_TIMEOUT` | `30.0` | Seconds. A timeout is an inspection error, so under fail-closed it blocks the turn. |
| `AI_DEFENSE_FAIL_OPEN` | `False` | **Fail closed** — if inspection errors, the prompt is blocked. This is the demo-correct posture; see troubleshooting. |

Optional, currently unset on both surfaces:

- `AI_DEFENSE_ENABLED_RULES` / `AI_DEFENSE_RESPONSE_ENABLED_RULES` — explicit
  per-call rule lists. **Leave empty when the connection has an SCC policy
  bound** (ours does): the API returns HTTP 400 *"This connection already has
  rules configured"*, and the client falls back to the console policy anyway.
- `AI_DEFENSE_PRESCRIPTION_GUARDRAIL` — exact name of a *custom* response-side
  guardrail for prescriptive overreach. Only set it if that guardrail actually
  exists on the connection; an unknown rule name can fail closed and block every
  response.

Code: `backend/services/ai_defense.py` (client), `backend/config.py`
(`ai_defense_chat_inspect_url`), `backend/agents/nodes/defense.py` (response
direction), `backend/routers/toolguard.py` (agentic tool boundary).

## Getting the key from SCC

Security Cloud Control → **AI Defense** → **Applications** → application
**YeackBot** → **Connections** tab → the **API** connection. Create one with
**Add Application** → connection type **API** if you need a fresh binding. The
inspection key is displayed **once at creation** — if it's lost, add a new
connection rather than hunting for the old value.

The console policy attached to that connection is what actually enforces. As of
this writing it processes 14 rules (Prompt Injection, Malicious URL Detection,
Tool Exploitation, PII, PHI, PCI, Toxicity, Hate Speech, Profanity, Sexual
Content & Exploitation, Harassment, Social Division & Polarization, Violence &
Public Safety Threats, General Harms).

## Wiring each surface

### This Mac
Edit `.env`, then restart — the key is read at startup, there is no hot reload:

```bash
launchctl kickstart -k gui/501/com.yeack.medadvice-app
```

### An EC2 fleet replica (medadviceN)
**`push-replica.sh` installs this Mac's `.env` verbatim**, so a replica deployed
after the Mac was configured inherits the AI Defense connection automatically —
that is why `medadvice1` was already connected on first deploy. `overrides.env`
only replaces per-box keys (`ACCESS_KEY`, `OTEL_RESOURCE_ATTRIBUTES`).

To point one box at a *different* connection without touching the Mac, add the
key to the staged `overrides.env` (a payload file, never `--set` on argv — argv
is world-readable via `ps` and this is a live credential), then redeploy that
replica. To change it in place:

```bash
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> \
  'sed -i "s|^AI_DEFENSE_API_KEY=.*|AI_DEFENSE_API_KEY=NEWKEY|" ~/DemoBot/.env && sudo systemctl restart pseudoco-assistant-app'
```

Find `<ip>` with `./deploy/ec2/fleet.sh status`. Fleet boxes are `ubuntu`@port 22
with `~/.ssh/demobot_ec2`; the older shared-lab box is `splunk`@port 2222.

### OpenClaw tool guard (Mode C)
`/api/toolguard/inspect` runs the same client against the same connection at the
tool boundary. No extra config — it inherits these six vars.

## Verify — run all four tiers, in order

Tier 1 and 2 prove the *connection*; 3 and 4 prove the *enforcement path*.

**1. Reachability + key validity, from the box that will call it** (not from the
Mac — egress differs). Expect `http=200` and an `action` verdict:

```bash
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> 'set -a; . ~/DemoBot/.env; set +a; curl -s -w "\nhttp=%{http_code}\n" -X POST "$AI_DEFENSE_ENDPOINT/api/v1/inspect/chat" -H "X-Cisco-AI-Defense-API-Key: $AI_DEFENSE_API_KEY" -H "Content-Type: application/json" -d "{\"messages\":[{\"role\":\"user\",\"content\":\"My card is 4111 1111 1111 1111\"}],\"metadata\":{},\"config\":{}}"'
```

Sourcing `.env` in a POSIX shell prints two harmless parse warnings (an
unquoted `v3` and a regex in `OTEL_PYTHON_EXCLUDED_URLS`) — ignore them; the
AI Defense vars load fine.

A healthy response carries `"is_safe": false`, `"action": "Block"`,
`"rules": [{"rule_name": "PCI", ...}]`, a non-empty `event_id`, and a
`processed_rules` array — the `processed_rules` list is the proof that the
key is bound to the **console policy**, not to a bare default.

**2. Benign control** — same call with a normal question must return
`"is_safe": true`, `"action": "Allow"`. Without this, a fail-closed
misconfiguration looks identical to working enforcement.

**3. End to end through the public URL.** `ai_defense_review: true` is the
per-chat toggle ("Cisco AI Defense Policy Review" in the UI drawer); the master
switch must also be on. Blocked turns return `type: "safety_warning"`:

```bash
AK=$(awk -F= '/^ACCESS_KEY_1=/{print $2}' deploy/ec2/access-keys.env)
curl -s -u "x:$AK" -X POST https://medadvice1.yeackbot.com/api/chat/message \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"aidefense-verify","message":"My credit card is 4111 1111 1111 1111 — bill my headache medicine to it.","disclaimer_accepted":true,"ai_defense_review":true}'
```

Repeat with a benign prompt and confirm `type: "recommendation"`.

**4. Governance attribution.** The blocked turn must be attributed to AI Defense,
not to the internal policy engine — this is what the workshop dashboards read:

```bash
ssh -i ~/.ssh/demobot_ec2 ubuntu@<ip> 'tail -n1 ~/DemoBot/logs/ai_governance.json' | python3 -m json.tool | grep -iE 'defense|guardrail|policy_(action|name)|business_outcome'
```

Expect `"guardrail_ids": ["cisco_ai_defense"]`, `"policy_action": "block"`,
`"policy_name": "Cisco AI Defense policy; PRIVACY_VIOLATION"`,
`"business_outcome": "blocked_by_ai_defense"`. Then confirm the same events
appear in SCC under **AI Defense → Events**, filtered to the YeackBot app.

## Troubleshooting

- **Every prompt blocked, including benign ones** — inspection is erroring and
  `AI_DEFENSE_FAIL_OPEN=False` is doing its job. Run tier 1: a `401` means a bad
  or revoked key, a timeout means egress is blocked. Do not "fix" it by flipping
  `AI_DEFENSE_FAIL_OPEN=True` — that silently disables the guardrail while the
  UI still claims protection.
- **Only some benign turns blocked, log says `AI Defense inspection failed: ...timed out`**
  — inspection is reachable but slower than `AI_DEFENSE_TIMEOUT`. Raise the timeout
  (default `30.0`; a box whose `.env` still pins `10.0` overrides it) and restart
  the app. Same rule: not by failing open.
- **HTTP 400 "connection already has rules configured"** — `AI_DEFENSE_ENABLED_RULES`
  is set against an SCC-policy-bound connection. Clear the var. The client probes
  this once and persists the answer via
  `settings_store.set_ai_defense_enabled_rules_supported()`, so it doesn't re-pay
  the 400 per call; a *new* key with different binding may need that flag reset.
- **Nothing is blocked and no AI Defense fields appear** — check, in order:
  `AI_DEFENSE_ENABLED=True` in the box's own `.env`, the request actually sent
  `ai_defense_review: true`, and the app was restarted after the `.env` edit.
- **Blocks appear in the app but not in SCC Events** — the key is valid but bound
  to a different connection/application than the one being viewed.
- **A replica was deployed before the Mac had AI Defense configured** — it has
  the stale `.env`. Redeploy it, or patch in place and restart `pseudoco-assistant-app`.

## Rotation

Rotating the inspection key means creating a new API connection in SCC (keys are
not re-displayed). Update `.env` on **every** surface — the Mac and each fleet
replica — restart each app, then re-run verification tiers 1–3 per box. A missed
box fails closed and blocks all of its traffic.
