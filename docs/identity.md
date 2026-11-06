# Identity: Duo sign-in and the Identity Risk Gate (Lab 5)

Lab 5, "Verify: Cisco Identity Intelligence", makes four claims. This page is
the app side of two of them:

- PseudoCo Assistant knows who is signed in, and refuses a compromised
  identity before the model runs.
- When a response agent disables the account in Duo, the app ends that
  identity's session.

Everything here is **inert unless `DUO_ENABLED`**. With it off, Labs 0-4
behave exactly as before. The only additive differences are an `identity_risk`
stage frame on every turn, which the UI hides on anonymous turns, and the
identity fields on the events of a signed-in turn.

There is no identity broker. Each instance holds its own Duo and Cisco
Identity Intelligence (CII) credentials in `.env` for the workshop's lifetime,
and they are rotated afterwards (plan section 12.1).

## The pieces

| Piece | Where | What it does |
|---|---|---|
| Sign-in | `backend/routers/identity_auth.py`, `backend/services/identity_signin.py` | Duo Universal Prompt (`duo_universal`), with usernames limited to `IDENTITY_ALLOWED_USERS` |
| Session | `backend/services/identity_store.py`, table `identity_sessions` | Stores the sha256 of a random cookie. Sessions can be revoked (kept as tombstones) and unblocked (`unblocked_at`) |
| Middleware | `backend/middleware/identity.py` | Resolves the cookie, refuses expired or revoked sessions, and runs the **revocation pull** |
| Status lookup | `backend/services/identity_lookup.py` | Reads Duo Admin API status and CII trust level and failing checks. Read-only, cached, never raises |
| Decision | `backend/services/identity_gate.py` | The pure `decide()` |
| Gate node | `backend/agents/nodes/identity.py` (`identity_risk`) | `PRE_NODES[1]` in the shared chain. The legacy engine calls the same function |

## Where a verified identity comes from

The only source is the identity middleware's `request.state.identity`: a
frozen snapshot of a valid session, which never includes the cookie. The chat
router passes it to the turn as `identity_session`, a parameter of `run_turn`,
`build_initial_state` and the legacy `process_message`.

There is no `ChatRequest` or `ChatCompletionRequest` field for it and no Demo
Controls card, so no client can switch the gate off.

On a signed-in turn, `enduser_id` is the username. The spray can still aim at
any username through `enduser_id`, but those turns have no session, so the
gate skips them and AI Defense still screens them.

## The Identity Risk Gate

`identity_risk` runs at `PRE_NODES[1]`: after `attachment_intake` has reduced
the document to metadata, and before `policy`. A refused turn therefore stops
before any screen or model.

1. **No identity session:** the node returns `{}` before any span, log or
   lookup.
2. **Lookup** (`identity_lookup.lookup`):
   - **Duo Admin API.** `GET /admin/v1/users?username=` with the read-only
     **PseudoCo Lab: Status** keys. Requests use Duo's HMAC-SHA512 signing
     (signature version 5, checked against known answers from `duo_client`
     5.7.0). It returns the account status (active, bypass, disabled,
     locked out, pending deletion) and the account's email.
   - **CII.** An OAuth client-credentials token from `CII_TOKEN_URL`, cached
     until five minutes before it expires. Then the one GraphQL query
     `CII_END_USER_QUERY` against `CII_API_URL`:
     `getEndUser(login)` → `endUserDetails { failingChecks endUserTrustScore { levelOfTrust } }`.
     CII's login is the email, so the email Duo returned is the login.
   - **CII is asked even while Duo can't answer.** The last email Duo gave
     for each username is kept beyond the 10 s cache (an email doesn't change
     with the account's status), so a Duo outage or throttle never hides a
     CII block. If no email is known yet, CII is not asked, and the lookup
     says so (`unavailable`, error `no_login`), never `not_found`.
   - **Limits.** Each call allows 3 s to connect and 5 s per read, and runs
     off the event loop. Each source's answer is cached per user for
     `IDENTITY_STATUS_TTL_SECONDS` (10 s), failures included.
   - **Failures.** Errors are reduced to fixed codes such as `timeout`,
     `http_503` or `stat_40103`. They never include a URL, key, token or
     response body.
3. **Decision** (`identity_gate.decide`, pure). The gate **allows** the turn
   (a `QUESTIONABLE` user too; the badge shows it) unless one of these is
   true, which **blocks** it:
   - The Duo account is disabled, locked out or pending deletion, or Duo has
     no such user.
   - The trust level is `UNTRUSTED`.
   - The user currently fails **MFA Flood** or **Impossible Travel**.
4. **Fail open (A3).** If either source could not answer, the turn is allowed
   with `identity_check="unavailable"` on the event, and the badge shows a
   neutral "status unavailable".
   - With `IDENTITY_FAIL_OPEN=false`, the turn is refused with a neutral
     "could not be verified" banner instead.
   - A block based on what *was* learned always applies. A disabled Duo
     account is blocked even while CII is down, and a CII block holds while
     Duo is down.
   - "No such user" is an answer, not an outage. A user CII has no record
     of yet, such as a new participant account, gets `identity_check="ok"`
     and, with nothing against it, is allowed. The badge shows no trust
     level for it.

### The block event

A block writes one `log_response`, in the same shape as the internal policy
block:

| Field | Value |
|---|---|
| `guardrail_ids` | `["cisco_identity_intelligence"]` |
| `policy_blocked`, `guardrail_triggered`, `safety_violated` | `true` |
| `safety_categories` | `["compromised_identity"]`, or `["identity_unverified"]` for a fail-closed block |
| `severity` | `HIGH`, or `MEDIUM` for a fail-closed block. Never `EMERGENCY` |
| tokens | zero: no model ran |
| `input_messages` | the typed message only. The gate screens no text, so no document text is on the event, and the banner never says the document was screened |
| `theme`, `workflow_name`, `blueprint`, `attachment` | as on every other event of the turn |
| `response_text` | `⚠️ POLICY BLOCKED (Cisco Identity Intelligence)` |

A block writes no escalation event and is never tagged "injection", which
Lab 4's correlation keys on.

The executive overlay maps the block to:
- `policy_name`: "Cisco Identity Intelligence identity risk"
- `business_outcome`: `blocked_compromised_identity`
- `prompt_category`: `compromised_identity`

### Identity fields on the events of a signed-in turn

| Field | When |
|---|---|
| `identity_verified=true`, `identity_source="duo"` | every event of a signed-in turn |
| `identity_override=true` | every event of an Unblock me session |
| `identity_risk` (`allow` / `block`, the real verdict), `identity_check` (`ok` / `unavailable`) | every event once the gate has run |
| `identity_risk_reasons`, `identity_duo_status`, `identity_trust_level`, `identity_failing_checks` | when known |

All of these fields are absent on an anonymous turn. `enduser_id` and `user`
are not promoted to HEC indexed fields.

## Revocation: pull (A4)

On a valid session's request, the middleware reads the user's Duo status,
cached for 10 s and run in the threadpool. If Duo says `disabled`, the
middleware:
- revokes the session there and then, keeping it as a tombstone, and ends
  its Unblock me override
- writes `identity_session_revoked` (reason `duo_disabled`, actor `duo`)
- answers that request `403 identity_session_revoked`, or `303 /login/duo?revoked=1` for a page

Other cases:
- **`locked out`** only blocks turns, through the gate.
- **Duo unreachable:** nothing happens.
- **Unblock me turned on for a gate block, or before any block:** revoked
  like any other session. A disabled account ends the session, and Unblock
  me can then bring it back.
- **A session Unblock me brought back from that revocation:** left alone
  while Duo keeps the account disabled. Once Duo reports the account
  enabled again, that is forgotten, so a new disable ends the session again.

The chat page polls every 10 s, so the banner appears within about 10-20 s.

`POST /auth/duo/start` refuses a persona that Duo reports disabled. Duo would
also refuse it at the prompt.

A tombstone is refused everywhere except:
- the sign-in and sign-out routes
- three identity APIs, which reach it as `request.state.identity_revoked`
  (never as an identity):
  - `GET /api/identity/me`, which answers `{"signed_in": false, "revoked": true, "username", "revoked_reason"}`
  - `POST /api/identity/unblock`
  - `POST /api/identity/reblock`

## Unblock me (A4 note)

When a block or a revocation happens, the banner explains it and shows an
**Unblock me** toggle. The sign-in page offers the same for a revoked session.

- **On** (`POST /api/identity/unblock`):
  - Sets `unblocked_at` on this identity session and clears its tombstone.
    A cleared tombstone's reason is kept as `unblock_cleared`.
  - Writes `identity_unblocked`. `user` is who overrode, and
    `details.cleared` is the revocation reason it cleared.
  - From then on the gate lets this session's turns through. Every event
    still carries the real `identity_risk` verdict plus
    `identity_override=true`.
  - It doesn't stop a Duo disable from ending the session. Only an override
    that brought the session back from a Duo revocation keeps the
    revocation pull off it, and only while Duo keeps the account disabled
    (see Revocation above).
- **Off** (`POST /api/identity/reblock`):
  - Clears the override and writes `identity_reblocked`.
  - The next turn is gated again, and a Duo-disabled account's session is
    revoked again on its next request.
- **Never touches Duo or CII.** The Duo account stays disabled, so the
  containment evidence stays intact for the debrief.
- **Per identity session.** The override ends when the session ends (sign
  out, sign in again, expiry, or a revocation). It is never a Demo Controls
  card or a request field.
- **Cross-site requests are refused.** `next=/app`, and nothing else, turns
  the answer into a redirect for the sign-in page's form.

## Duo application → configuration

| Duo / CII application | Permissions | `.env` keys | Used by |
|---|---|---|---|
| **PseudoCo Lab: Sign-in** (Web SDK) | n/a | `DUO_CLIENT_ID`, `DUO_CLIENT_SECRET`, `DUO_API_HOST` | sign-in (`identity_signin`) |
| **PseudoCo Lab: Status (read-only)** (Admin API) | *Grant read resource* only | `DUO_ADMIN_IKEY`, `DUO_ADMIN_SKEY` (+ `DUO_API_HOST`) | the gate, the revocation pull, the sign-in disabled check |
| **CII API client** (CII → Integrations → Add API Client, "Copy all") | read-only use | `CII_CLIENT_ID`, `CII_CLIENT_SECRET`, `CII_TOKEN_URL`, `CII_API_URL` | the gate (trust level, failing checks) |
| PseudoCo Provisioner, PseudoCo VPN | write / Auth API | never on a box | Mac-side tooling only |

| Other key | Default | Meaning |
|---|---|---|
| `DUO_ENABLED` | `false` | master switch |
| `PUBLIC_BASE_URL` | empty | the instance's https name; the only source of the Duo redirect URI |
| `IDENTITY_ALLOWED_USERS` | empty | usernames this instance accepts at sign-in |
| `IDENTITY_SESSION_TTL_MINUTES` | `720` | session lifetime |
| `IDENTITY_STATUS_TTL_SECONDS` | `10` | lookup cache |
| `IDENTITY_FAIL_OPEN` | `true` | A3: allow when a lookup cannot answer |

Every value lives in `.env` only, never in `settings_store`, because anyone
with the room access key can rewrite those.

## Tests

- `tests/test_identity_gate.py` covers:
  - the signer, checked against known answers
  - the lookup through fakes, including token refresh, caching and failures,
    CII asked with the remembered email while Duo is down, and a user CII
    doesn't know
  - `decide()`
  - both engines
  - the revocation pull
  - Unblock me, including that a Duo disable still ends an unblocked session
    unless the override brought it back from that revocation
  - the store's cache generation
  - the rules
- `tests/test_blueprint_parity.py` runs these scenarios through both
  blueprints:
  - `identity_anonymous`
  - `identity_allowed`
  - `identity_blocked`: AI Defense is never called, and no tokens are used
  - `identity_document_blocked`: extraction runs, nothing is screened, and
    no document text is on the event
  - `identity_unavailable_fail_open`
  - `identity_spray_actor`
  - `identity_unblocked`
  - `identity_blocked_duo_down`: Duo can't answer, CII still blocks
- `tests/test_identity_sessions.py` and `tests/test_duo_signin.py` cover
  sessions and sign-in.
