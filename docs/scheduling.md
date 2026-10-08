# Appointment scheduling

PseudoCo Assistant can offer, book, list, reschedule and cancel appointments from the chat,
**verticalized per Application Theme** — a clinician follow-up visit for MedAdvice, a
tax-preparer meeting (Saturdays included) for TaxAdvice, a two-hour technician arrival
window for TelecomChatbot. Bookings are persisted, visible on the **My Appointments**
page, and every mutation is a governed action (an `execute_tool` span and a `tool_call`
governance event), so the feature doubles as a demo of an agent taking a real,
auditable action.

## Principle: deterministic scheduling, LLM voice

Nothing structured is ever parsed out of model text. The suggested times, the user's
intent, the booking itself and the clickable options come from code
(`backend/services/scheduling.py`); the model only writes conversational wording.

| Piece | Where |
|---|---|
| Per-theme vertical (`SchedulingProfile`) | `backend/agents/themes/<theme>.py` → `ThemeConfig.scheduling` |
| Slots, labels, intent parser, offer policy, store | `backend/services/scheduling.py` |
| Pipeline nodes (`scheduling_intake`, `scheduling`) | `backend/agents/nodes/scheduling.py`, wired in `blueprints/guardrails.py` |
| Persistence | `Appointment` in `backend/models/db_models.py` (`appointments` table; created by `init_db`, no migration) |
| Chat contract | `ChatRequest.client_id / client_tz / scheduling_action`, `ChatResponse.scheduling` |
| Chips in the chat | `frontend/js/chat.js` `attachSchedulingActions` |
| My Appointments page + API | `frontend/appointments.html`, `frontend/js/appointments.js`, `backend/routers/appointments.py` |

## Where it runs in the pipeline

```
START → policy → prompt_defense → nemo_input_rails → scheduling_intake → <core>
<core exit> → safety → injection → scheduling → compliance → agent_control
            → nemo_output_rails → response_defense → governance → END
```

Both nodes are in the **shared** guardrail chain, so both blueprints get scheduling by
construction (CLAUDE.md "Blueprint feature parity").

- **`scheduling_intake`** (last PRE node; deterministic, no model, never terminal):
  resolves the browser (`client_id`) and its zone, parses the turn's scheduling action
  (a chip's structured `scheduling_action` wins over the typed-text parser), loads the
  client's appointments, generates candidate slots, and writes the prompt directive the
  domain agent will see.
- **`scheduling`** (POST node between `injection` and `compliance`): executes the
  action, decides whether to offer on an answer turn, appends the deterministic
  scheduling copy to `final_message` and leaves the structured payload. Placed there so
  the text is part of the logged `response_text` and is still screened by Agent
  Observability Controls, NeMo output rails and Cisco AI Defense.

### Multi-Agent Mode

- **On:** the POST node runs as the **`{theme}_scheduling_agent`** — its own
  AgentInvocation span, a short model call for the wording (the internal Ollama model,
  160 tokens), an `agent_trace` entry with role `scheduling`, tokens summed onto the
  turn. Bookings execute under that span. The domain agent only acknowledges a
  scheduling request (hand-off directive) and the domain specialists are skipped on
  scheduling turns (`_route_after_intake`; the NVIDIA primary assistant routes to no
  sub-assistant).
- **Off:** no separate agent. On a scheduling turn the domain agent receives the full
  scheduling context in its prompt and writes the reply itself; the node executes the
  action and appends template copy only when the model omitted the key fact (e.g. the
  slot label), so nothing is said twice. The offer on an answer turn is deterministic
  copy in both modes (on Ollama the answer is a JSON contract and appended prose is
  parsed away, so the node adds the offer after parsing).

Shared-chain touches on scheduling turns: `clarify.intake_node` asks no clarifying
question, `safety_node` skips the escalation rules (an earlier emergency already
escalated on its own turn; "see a doctor" phrasing must not flag a booking), and the
clarifier does not count the offer's "?" toward its question budget.

## Offer policy

The offer is never bolted onto an answer. After the **first** non-clarifying reply of a
session (clarifying turns never reach the POST chain) the assistant asks, in its **own
bubble**, whether the answer resolved the concern — two chips, *Yes, that resolved it*
/ *No, I still have concerns* (copy per theme). **No** brings the offer with the time
chips; **Yes** closes warmly with no offer. The check is skipped when the theme excludes
that severity — MedAdvice never asks on an EMERGENCY answer. It is asked again on later
recommendation/escalation turns only when the severity is in the theme's
`offer_on_severities` (MedAdvice: MEDIUM/HIGH; Telecom: HIGH+), never once the client
has an upcoming appointment (the first answer says so instead), and never after an
explicit decline in the session. Prior checks, declines and bookings are read from the
persisted `metadata.scheduling` of earlier assistant messages, so the policy survives
restarts and Show Recent reloads. Scheduling copy on an answer turn — the check, the
already-booked note — rides in the payload's `message` and is rendered as its **own
green chat bubble**; the answer text itself is never touched. (The check is fixed copy
in both modes — a yes/no prompt must not depend on a model's phrasing — so the
scheduling agent phrases what follows it, not the check itself.)

## Identity and time

- The **browser** owns its bookings: `frontend/js/chat.js` keeps a stable
  `medadvice_client_id` in localStorage and sends it as `client_id` on every request.
  It is a partition key, **not authorization** — every visitor shares one access key.
  The agent still asks what **name** to put on the booking (display only, remembered
  from the client's latest appointment).
- Slots are synthetic and unlimited: the next N after `now + lead time` inside the
  theme's business hours, paged forward by "More times". No calendar, no conflicts.
- Storage is naive UTC like every other timestamp; labels are rendered in the client's
  IANA zone (`client_tz`, stdlib `zoneinfo`), falling back to
  `SCHEDULING_DEFAULT_TIMEZONE` (`.env`, default `America/New_York`).

## Per-theme verticals

| theme | appointment / provider | slot | hours | first offer | re-offer |
|---|---|---|---|---|---|
| medadvice | follow-up visit / a clinician | 20 min | Mon–Fri 8–17 | not on EMERGENCY | MEDIUM, HIGH |
| financeadvice | consultation / a financial advisor | 45 min | Mon–Fri 9–17 | always | MEDIUM+ |
| legaladvice | consultation / an attorney | 30 min | Mon–Fri 9–17 | always | MEDIUM+ |
| taxadvice | meeting / a tax preparer | 30 min | Mon–Sat 9–18 | always | MEDIUM+ |
| benefitsadvice | session / a benefits counselor | 30 min | Mon–Fri 9–16 | always | MEDIUM+ |
| telecomchatbot | technician visit / a field technician | 2-hour arrival windows | Mon–Sat 8–18 | always | HIGH+ |
| retail | in-store appointment / a product specialist | 30 min | Mon–Sun 10–20 | not on EMERGENCY | MEDIUM, HIGH |
| manufacturing | maintenance visit / a maintenance technician | 60 min | Mon–Sat 6–18 | not on EMERGENCY | MEDIUM, HIGH |

Add a theme's vertical by defining `SCHEDULING = SchedulingProfile(...)` in its module
and passing `scheduling=SCHEDULING` to its `ThemeConfig`; a theme without one gets
`DEFAULT_PROFILE`.

## The chat contract

Request (`POST /api/chat/message` and `/message/stream`):

```json
{ "client_id": "b3e1…", "client_tz": "America/New_York",
  "scheduling_action": {"action": "book", "slot_id": "20260907T1200Z", "appointment_id": null, "page": 0} }
```

`action` ∈ `resolved | not_resolved | book | accept | more_times | decline | list | cancel |
reschedule | choose_slot | clarify_slot`.

### Reading what the user asked for

A typed reply only books when it resolves to **exactly one** offered slot — an ordinal
("the second one"), or a day/time that matches one. **A named day is binding:** "Saturday
at 8am" never books Friday 8:00 AM because the clock happens to match. Anything else
(a day with several slots, a time not on offer, a day the theme doesn't book) becomes
`clarify_slot`: the assistant says what it thinks they meant and shows the closest
bookable times as buttons. When the theme doesn't book that day at all it says so —
"I don't have Saturday availability — follow-up visits are booked Monday to Friday" —
and offers the nearest times instead. The clock parser is deliberately strict: am/pm, a
colon, or a leading "at" is required, so "it's been 2 days" is not a request for 2:00.

Response — `scheduling` on `ChatResponse` **and** the SSE `final` frame (and persisted as
the assistant message's `metadata.scheduling`, returned by `GET /api/chat/session/{id}`):

```json
{ "state": "offered", "theme": "medadvice", "appointment_noun": "follow-up visit",
  "page": 0, "more_available": true,
  "slots": [{"slot_id": "20260907T1200Z", "start_utc": "2026-09-07T12:00:00", "end_utc": "…",
             "label": "Mon Sep 7, 8:00 AM", "day": "Mon Sep 7", "time": "8:00 AM"}],
  "pending": null, "appointments": [], "appointment": null,
  "actions": [{"action": "book", "slot_id": "20260907T1200Z", "text": "Mon Sep 7, 8:00 AM"},
              {"action": "more_times", "page": 1, "text": "More times"},
              {"action": "decline", "text": "No thanks"}] }
```

`state` ∈ `check_resolved | resolved | offered | choosing | clarify_slot | awaiting_name |
booked | listed | cancelled | rescheduled | declined | already_booked | rescheduling |
unavailable`; `message` (set for `check_resolved`) is a follow-up the UI renders as its
own assistant bubble, with the chips under it. `actions` is the
whole chip contract: the backend decides which chips exist and their (verticalized)
labels; the UI renders them generically and sends a click back as `scheduling_action`
with a readable user bubble ("Book Mon Sep 7, 8:00 AM").

## Governance and telemetry

- Bookings: `schedule_appointment`, `reschedule_appointment`, `cancel_appointment`
  `tool_call` governance events (`agent_surface=scheduling`, decision `allow`) + an
  `execute_tool` span — the tool-guard shape, so they appear beside chat turns in the
  Governance Logs page, SQLite and Splunk.
- Multi-Agent Mode: `invoke_agent {theme}_scheduling_agent` + its `chat` LLM span; the
  agent appears in `agent_trace` → Splunk Agent Observability.
- The My Appointments page's cancel/reschedule log `appointment_cancelled` /
  `appointment_rescheduled` audit events (actor `user`).
- No new turn-level governance field; SSE stage frames for both nodes come for free.

## My Appointments page and API

`/appointments-ui` lists **this browser's** appointments (same-origin, same
`medadvice_client_id`), with Upcoming / Cancelled / All filters, local times, and
Cancel; rescheduling happens in the chat. API (`backend/routers/appointments.py`, gated
by the access key like everything else):

- `GET /api/appointments?client_id=&status=scheduled|cancelled|all&theme=&tz=&limit=`
- `GET /api/appointments/{id}?client_id=`
- `PUT /api/appointments/{id}` body `{client_id, status: "cancelled"}` or
  `{client_id, start_utc: "<naive UTC ISO>"}` (a body model — bare scalars would bind as
  required query params).

## Testing

- `venv/bin/python tests/test_scheduling.py` — slots (fixed clock, weekend/lead
  rollover, paging, windows, DST), intent parsing, offer policy, the store on a temp DB,
  and both nodes in both modes with the LLM/logger/store stubbed.
- `tests/test_blueprint_parity.py` — `scheduling_offer` / `scheduling_book` /
  `scheduling_list` scenarios must produce the same `scheduling.state` and agent set in
  every blueprint.
- `tests/test_api.py` — the contract end to end through the API (offer on both
  endpoints, book → name → booked, the appointments API and page).
- `./tests/run_all.sh` runs everything; `./tests/observability/verify_observability.sh`
  after any pipeline change.
