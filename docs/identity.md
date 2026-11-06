# Identity: Duo sign-in and the Identity Risk Gate (Lab 5)

Lab 5, "Verify: Cisco Identity Intelligence", makes four claims. This page is
the app side of two of them:

- PseudoCo Assistant knows who is signed in, and refuses a compromised
  identity before the model runs.
- When a response agent disables the account in Duo, the app ends that
  identity's session.

Everything here is **inert unless `DUO_ENABLED`**. With it off, Labs 0-4
behave exactly as before, and the chat page sends no identity request. The
only differences are additive (plan section 5 lists them for the Labs 0-4
regression):

- an `identity_risk` stage frame on every turn, which the UI hides on
  anonymous turns;
- `identity_session: false` and the closed `gated.duo_signin` gate (with its
  reason) in `GET /api/server-info`, so the Settings page's host capabilities
  show a grey "Duo sign-in: unavailable" chip, as they do for NIM and
  NemoClaw on a box without them;
- `enduser.id` and `client.address` on the workflow span, from both graph
  call sites. It is a GenAI span, so with `SPLUNK_AO_O11Y_TOKEN` set the
  collector's Agent Observability overlay carries the client address there
  too; the HTTP server span (`net.peer.ip`) and the governance events'
  `client_address` already carried it;
- an indexed `enduser_id` column on `audit_logs`, filled from each audit
  event's `enduser_id` (the `session_started` event already carried one);
- every log record's text cut to 64 KB before it is redacted
  (`backend/logging/redaction.py` `MAX_SCAN_CHARS`), with a
  ` [TRUNCATED: N more characters]` marker. A longer console line, such as
  the console-only governance JSON of a very long chat message, is therefore
  no longer valid JSON. The governance JSONL files, the database and HEC are
  written directly, not through a log record, and are never cut;
- the identity fields on the events of a signed-in turn.

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
     with the account's status), so once Duo has answered for a user, a Duo
     outage or throttle never hides that user's CII block. The email lives
     in memory only: after a restart, or while Duo refuses the Status keys,
     no email is known yet, CII is not asked, and the lookup says so
     (`unavailable`, error `no_login`), never `not_found`. `lab5-setup
     status` runs this lookup for the room's victim on each box, and fails a
     box that cannot ask Duo or CII.
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
     "could not be verified" banner instead, and the chat page's banner says
     IDENTITY NOT VERIFIED, never that a risk was reported.
   - A block based on what *was* learned always applies. A disabled Duo
     account is blocked even while CII is down, and a CII block holds while
     Duo is down.
   - "No such user" is an answer, not an outage. A user CII has no record
     of yet, such as a new participant account, gets `identity_check="ok"`
     and, with nothing against it, is allowed. The badge shows no trust
     level for it.
   - CII's "no such user" is read from the answer's shape, never from the
     wording of just any error: `getEndUser` is null (or `data` is null
     because that field failed), and any error is about `getEndUser` itself
     (`path: ["getEndUser"]`), says the user was not found, and carries no
     other code. A request-level error (no `data`), an error elsewhere or
     without a path, or a nested failure is `unavailable`, so it can never
     pass for a clean check.

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
| `response_text` | `⚠️ POLICY BLOCKED (Cisco Identity Intelligence)`, or `⚠️ IDENTITY NOT VERIFIED (Cisco Identity Intelligence)` for a fail-closed block |

A block writes no escalation event and is never tagged "injection", which
Lab 4's correlation keys on.

The executive overlay maps the block to:
- `policy_name`: "Cisco Identity Intelligence identity risk"
- `business_outcome`: `blocked_compromised_identity`
- `prompt_category`: `compromised_identity`

A fail-closed block knows nothing against the identity, so it is never
counted as a compromised one: "Cisco Identity Intelligence identity
verification", `blocked_identity_unverified` and `identity_unverified`.

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

A revocation is atomic: `identity_store.revoke` is one
`UPDATE ... WHERE revoked_at IS NULL`, and only the call that changed the row
writes the event. Two requests whose pulls race make one tombstone and one
`identity_session_revoked`, never two.

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

## Sign-in safeguards

- **The allowlist, then the rate limit.** `POST /auth/duo/start` checks
  `IDENTITY_ALLOWED_USERS` before it takes a rate slot (30 starts per
  username per 5 minutes, never per IP). A name that is not on the list never
  enters the rate table, and a full table evicts the least recently used name,
  one at a time and never all at once. A flood of made-up names therefore
  can't reset a real user's spent budget.
- **What a refused start records.** `POST /auth/duo/start` checks the
  `duo_signin` gate first, so with Duo sign-in off it writes no identity
  event at all. An `identity_signin_failure` names the user only once the
  name has matched `IDENTITY_ALLOWED_USERS`: anything else typed into the
  Username box (a passcode, a bypass code, a password) is never written to an
  event, the database or a log. A refusal that takes no rate slot (a
  cross-site post, a malformed or unlisted name) is audited at most once per
  reason and name every 5 minutes, so no loop of posts can flood the audit
  trail or pin forged failures on a persona.
- **Same-origin posts only.** The sign-in start, sign-out and Unblock me
  refuse a post that another site's page sent, by its `Origin`. The sign-in
  page's referrer policy is `same-origin` (header and `<meta>`), never
  `no-referrer`: under `no-referrer` a browser sends `Origin: null` on the
  page's own form posts, and every one of them would be refused. `Origin:
  null` passes only with `Sec-Fetch-Site: same-origin`, which no page can
  set. `GET /logout` ends the identity session only on a navigation the
  browser says came from this origin or from the address bar
  (`Sec-Fetch-Site` `same-origin` or `none`, or no Fetch Metadata at all). A
  link on another site, another lab instance included, still signs the
  browser out of the room key, and leaves the identity session and any
  tombstone alone.
- **Duo's health, on a timer.** A passing health check opens the
  `duo_signin` gate, and only three failed checks in a row close it again,
  so one failed check on the timer never does. The check runs on a daemon
  thread at startup, then every 5 minutes (every minute while it fails). It
  never runs on the event loop, and never starts while the previous check is
  still waiting for Duo.
- **The gate governs starting a sign-in, never finishing one.** Only
  `POST /auth/duo/start`, the sign-in page's Continue button and the chat
  page's "Sign in with Duo" link read it. A sign-in that is already at Duo
  finishes at `/auth/duo/callback` even if the gate closed meanwhile: the
  code exchange is attempted, and a Duo failure there is a fixed error
  (`duo_unavailable`, `duo_refused`, ...). Only `DUO_ENABLED` being off
  refuses the callback up front.
- **TLS to Duo.** When `REQUESTS_CA_BUNDLE` (or else `CURL_CA_BUNDLE`) names
  a file, Duo is verified against that bundle, as every other outbound client
  is. `backend.config` points both at the checkout's `ca-bundle.pem` when it
  exists, which is what a TLS-inspecting proxy needs. Verification stays on,
  but duo_universal's certificate pinning is then off. With no bundle
  configured, duo_universal's own pinned bundle is kept. The health check's
  log line says which one was used.
- **Bounded Duo calls.** duo_universal 2.3.1 sets no timeout on its HTTP
  calls and has no setting for one. Its requests therefore get a 5 s connect
  and 10 s read timeout, and every call has a deadline (10 s for the code
  exchange, 15 s for a health check). At the deadline the call's slot (four
  at once) is given back even if Duo never answers, and the call is abandoned
  on its daemon thread.
- **Nothing secret in a log, at any level.** At `LOG_LEVEL=DEBUG` urllib3
  logs every request line with its query string, and the token exchange sends
  Duo's code and the `client_assertion` JWT (signed with `DUO_CLIENT_SECRET`)
  that way. `backend/logging/redaction.py` redacts every log record as it
  is created, child loggers included, by pattern only. Every logger loses
  the values of credential query parameters (`duo_code`, `code`, `state`,
  `client_assertion`, `assertion`, `access_token`, ...), `Authorization`,
  `Cookie`, `Set-Cookie` and `X-Access-Key` values, the app's own cookies,
  Bearer credentials, anything shaped like a JWT, and the exact values of
  `DUO_CLIENT_SECRET`, `DUO_ADMIN_SKEY`, `CII_CLIENT_SECRET` and
  `ACCESS_KEY`. urllib3, requests, httpx, httpcore, duo_universal and the
  identity modules also lose every query value and token and secret pairs.
  Nothing is registered at run time, so no request can make a string (a
  username, say) vanish from later log lines. The configured secrets are
  compiled once at startup and again only when one of them changes, and the
  record factory takes no lock. The callback's own query is also redacted
  in uvicorn's access log, and `run.sh` keeps the callback out of spans.
- **Inert in the browser too.** The chat page asks `GET /api/identity/me`
  only while `gated.duo_signin` is open, while `GET /api/server-info` reports
  that this browser holds a session (`identity_session`), or while the page
  already shows one. With `DUO_ENABLED` off it sends no request for it. The
  "Sign in with Duo" link is re-evaluated on every `/api/server-info` poll,
  so it goes away as soon as the gate closes.

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
- `tests/test_identity_sessions.py` covers sessions, including two
  revocations racing (one tombstone, one event).
- `tests/test_duo_signin.py` covers sign-in, and the safeguards above:
  - a real sign-in through duo_universal, requests and urllib3 at DEBUG
    against a local fake Duo, with no code, JWT, cookie or secret in any log
    line (httpx and httpcore too)
  - redaction by pattern only: a username sent as Duo's code is never
    blanked from later lines, nothing is compiled per record, and a log call
    made while redacting never waits on a lock
  - the allowlist before the rate limit, and least-recently-used eviction
  - what a refused start records (never the typed text, no event with Duo
    sign-in off, one per reason and name per window), the sign-in page's
    `same-origin` referrer policy, and `GET /logout` from another site
  - a hung call giving its slot back, and the health check not stacking
  - the gate closing only after three failed checks in a row, the timer
    reopening it, and a callback finishing while it is closed
  - the CA bundle rule
  - `identity_session` in `/api/server-info`
  - the real `chat.js` run in node: no `/api/identity/me` with Duo off, and
    the "Sign in with Duo" link following the gate on every poll
