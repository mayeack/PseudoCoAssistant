# Lab 5 facilitator runbook: Verify with Cisco Identity Intelligence

**For:** Splunk Show deliveries set up with `lab5-setup` from your Mac. **Tools:** `deploy/lab5/README.md`. **Design:** `docs/identity-intelligence-lab-plan.md`, a planning note kept outside the repository (a fresh clone does not have it). You do not need it: "Terms used here", below, defines every spike, decision, plan section and date this runbook and the README rely on.

Lab 5 makes four claims:
1. Identity Intelligence (CII) catches a takeover of a PseudoCo employee account and drops its trust level.
2. PseudoCo Assistant knows who is signed in and refuses a compromised identity before the model runs.
3. Splunk joins CII's failed checks with Cisco AI Defense blocks for the same user.
4. A response agent disables the account in Duo, and that ends its PseudoCo Assistant session.

Everything here runs from your Mac. There is no broker and nothing in AWS. Secrets stay in your Keychain, and state lives in `~/.pseudoco-lab5/`. Commands below start at the repository root, and `py` stands for the tool's venv, `~/.pseudoco-lab5/venv/bin/python`.

> **Still open.** S1, how the victim's failed checks reach a room stack that only exists from T-1, is still marked for discussion. This runbook does not pick a path. See "The victim's takeover" and "Open questions".

## Once, before the first delivery

**Duo console (you):**
- Licence and seats. You need a seat for your own account, each persona, and every participant account from the last 14 days. Disabled accounts still hold a seat until they are deleted.
- A second Owner, as break-glass.
- *Identity Intelligence → SSO Access*: Duo Administrator SSO on, so you can open CII with full admin.
- *Grant write resource* **off** in CII.
- Lockout **auto-revert** on (about 15 minutes), so one person's typos never lock an account for the day.
- The **PseudoCo Lab: Sign-in** policy (plan 4.4) allows **bypass code + hardware token** and no other method: tick *Bypass code* and *Hardware tokens* under its authentication methods. Each handout card carries both: the room personas' bypass codes and the participant's HOTP passcodes. Without hardware tokens Duo refuses every participant, and without bypass codes every persona sign-in. `deploy/lab5/README.md` ("Duo applications") has the rest of the policy.

**Your Mac:**
1. Create the tool's venv and add the Keychain items. `deploy/lab5/README.md` lists every item, including the Mac-only Provisioner and VPN keys.
2. Once spike S1 says how Duo geolocates addresses, put real home and foreign addresses in `scripts/identity/personas.yaml`. Until then the scripts refuse to send any sign-in.
3. Run `py scripts/identity/provision_personas.py` to create the cast: the PseudoCo Workforce group, the users and one HOTP token each. The trusted personas need CII exclusions from Impossible Travel, MFA Flood, *A Bypass Code Was Used To Successfully Sign In* and *Users Sharing Authenticators*, but CII cannot exclude a user from a check ahead of time. *Exclude a user* is a triage action on a failing row: open the check, find the persona among its failing users, and pick *Exclude* from the row's … menu, for the longest time frame offered. None of these four checks has a user list in its settings: Impossible Travel's ignore list holds network providers, and MFA Flood has only thresholds (5 failures in 2 minutes). So exclude each trusted persona from a check the first time it fails it. The likely first is *A Bypass Code Was Used*, after the first sign-ins with a persona's bypass code from a handout card. The daily self-check is the cue: it fails, with a notification, any trusted persona that fails a check. Run *Collect Now* on the Duo integration first if you want CII to see the sign-ins sooner. Whether that check lowers a trusted persona's trust level before the exclusion is for spikes S2/S5/S6 to show; the gate's own CII blocks are only MFA Flood, Impossible Travel and `UNTRUSTED`.
4. **User access, in the Duo Admin Panel** (*Applications*, the application, *User access*). The tools cannot set or check it. `deploy/lab5/README.md` ("Duo applications") has the reasons.
   - **PseudoCo Lab: Sign-in**: *Enable only for permitted groups*, with **PseudoCo Workforce** and **CII Read-Only**. The personas are in the first group, and every participant account is in the second.
   - **PseudoCo VPN**: *Enable only for permitted groups*, with **PseudoCo Workforce** only. Only the persona scripts sign in through it.

   Plan section 4.2 limits every lab app to PseudoCo Workforce. That was written before the participant accounts: Sign-in limited that way refuses every participant, so no attendee can sign in to their own instance. Never add a participant account to PseudoCo Workforce to get around it.
5. Run `deploy/launchd/install-lab5.sh` from the main checkout. It installs the daily `lab5-setup expire` (08:15) and the persona baseline plus self-check (09:20).
6. After spikes S1, S2 and S7 pass, at least 4 weeks before the first delivery, set `baseline.enabled: true` in `personas.yaml`. From then on every persona signs in once a day. If anything is wrong, the self-check raises a macOS notification: a failed sign-in, a missing Keychain secret or counter, a disabled or locked-out persona, or a trusted persona failing a CII check. So does a run that crashes or cannot load `personas.yaml`, and the launchd wrapper (`deploy/launchd/run-lab5-job.sh`) notifies when the job cannot start at all, for example after a Python upgrade breaks the tool's venv: re-create it as `deploy/lab5/README.md` says.
7. **T-18 gate:** `py scripts/identity/persona_activity.py selfcheck --gate`. Every persona must be out of "Unknown". If one is not, the delivery date moves.

Long trips with the Mac shut down stop the baseline. A few missed days are fine. A missed week before a delivery is not, and the self-check fails after three days without a sign-in. A shut-down Mac runs nothing and notifies nothing, so run `py scripts/identity/persona_activity.py selfcheck` by hand when you are back.

## The victim's takeover

The scripted takeover is `py scripts/identity/persona_activity.py takeover --victim <room victim>`:
1. a sign-in from the victim's home;
2. 5 to 9 wrong passcodes from the next foreign address within 2 minutes, under the lockout limit of 10;
3. a success from that same address on a new device.

Then click *Collect Now* on CII's Duo integration, because there is no API for it. The run's record under `~/.pseudoco-lab5/personas/takeovers/` is the takeover time. Every room gets its own victim. Keep the room's fallback untouched. A victim needs about 8 days before its next takeover, and the script refuses one sooner unless you pass `--force`.

**When to run it depends on S1.** The options in plan 12.4, in their order:
1. at T-2, then CII's *Send notification* once the room stack's input exists;
2. a Near Time takeover at T-1;
3. a labelled backfill.

Never put synthetic events in a room stack. If the victim's failures do not show up, move the room to its fallback (`room.fallback` in the workshop file, then re-run `lab5-setup up`) and take that one over.

For the live replay, one victim has Duo Mobile on a facilitator phone (`replay_device: true`). `persona_activity.py replay --victim <it>` sends a short push flood, and you **deny** each push on stage. Never approve one, and never send it from an in-app button.

## T-1: the Show boxes arrive

1. Copy `deploy/lab5/workshop.example.yaml` for this delivery and fill in:
   - a new `workshop` name (a date helps);
   - the room stack's `stack.hec_url`;
   - `room.victim` and `room.fallback`;
   - one `boxes` row per box;
   - `participants.cii_url`, the link printed on the handouts;
   - `bypass_codes.valid_hours` (default 12): the persona bypass codes that `up` puts on the cards stop working that many hours after `up` runs. If you run `up` the day before, raise it to reach the end of lab day.
2. `deploy/lab5/lab5-setup check <workshop.yaml>`. Every box should say **ready, nothing to upgrade**, and every participant account and card `PLAN`. It changes nothing. A room persona that is missing in Duo, not active there (bypass status or disabled), in a Duo group whose status is Bypass or Disabled, or near Duo's 100 bypass codes fails every card here, and `up` would issue no persona codes. For a persona that is not active, run `py scripts/identity/provision_personas.py --reset --only <persona>`; for one in such a group, take it out of the group or set the group Active in the Admin Panel. Bypass status and bypass groups are never acceptable (plan 4.3): Duo then skips the second factor for that persona, so anyone with an instance's access key could sign in as it. A locked-out persona needs no reset: Duo unlocks it on its own in about 15 minutes, and meanwhile its cards are `PARTIAL` (the other personas' codes go on); retry `lab5-setup handouts <workshop.yaml> --only N` after that.
3. `deploy/lab5/lab5-setup up <workshop.yaml>`. The boxes get their Lab 5 keys, tunnel and DNS name, HEC host and restart. Their CII access is one 24 h token that `up` mints on your Mac (S16); the CII API client never leaves the Mac. Then every box that came up gets its participant account `l5-<workshop>-<nn>`, its card gets the team's bypass codes for the room's victim and each trusted persona, and the handout is written.
4. **Temporary passwords.** `up` prints an Admin Panel link per account. Open each one, click *Create temporary password* (valid 30 days) and write it on that participant's card. The Admin API cannot set passwords. While you are in the Admin Panel, check that **PseudoCo Lab: Sign-in** still admits **CII Read-Only** (step 4 of "Once, before the first delivery") and that its policy still allows bypass code + hardware token. `up` reminds you, because it cannot check either.
5. Print `~/.pseudoco-lab5/workshops/<workshop>/handout.html` and cut the cards apart.
6. `deploy/lab5/lab5-setup status <workshop.yaml>`. Every box should be green. Participants show "no password yet" until they sign in to CII and set their own. Each room persona shows its Duo status, and each card's persona codes show how long they have left. Each box's `victim` row runs its own Identity Risk Gate on the room's victim: a `FAIL` there means the box cannot ask Duo or CII (a stale Status key, say), and must be fixed before lab day. A `WARN` is expected until the takeover's failures reach CII.

A box that `up` refused is reported with the reason. Fix it, then re-run with `--only <n>`. A re-run keeps the accounts and their cards. A card whose persona codes failed (a Duo error, say) is named in the `RESULT` line, and a re-run of `up` finishes it. Passcodes are shown only once, so for a lost card use `up --only <n> --reissue-passcodes` (the old passcodes stop working), then `handouts --only <n> --revoke`. That puts fresh persona codes on the card and deletes the lost card's.

## Lab day

**Before attendees sit down (T-0):**
- `deploy/lab5/lab5-setup cii-token <workshop.yaml>`. The CII token `up` pushed the day before runs out during the lab (a token lasts 24 h). This pushes a fresh one to every box with less than 20 h left and restarts those boxes. It mints one token, of the API client's 6 an hour (S16).
- `lab5-setup status` again. Every tunnel should be healthy, `duo_signin` not gated, every box's `CII token` row `OK`, and every box's `victim` row `OK`: its gate blocks the room's victim. If the cards' persona codes expire before the lab ends, run `deploy/lab5/lab5-setup handouts <workshop.yaml>` and print the cards again, with the temporary passwords copied over. The old codes stay valid until they expire, unless you add `--revoke`.
- `persona_activity.py selfcheck`. The trusted personas should pass. The room's victim should fail MFA Flood and Impossible Travel in CII.
- In the Admin Panel, *Users → Clear all step-ups*.
- In each instance's Demo Controls, turn **Trigger Demo Incident** off. Its synthetic incident would crowd the room stack.

**Handing out the cards.** Each attendee gets one card: their instance URL and access key, their participant account, its passcodes and the temporary password. Say these out loud:
- **Get off VPN.** Sign in from the venue network. A VPN exit far from the room makes your own sign-ins, and any shared persona's, look like Impossible Travel.
- **Use each passcode once, in order.** Skipping ahead works, but the codes before it then stop working.
- **The persona codes are your team's.** To sign in as the room's victim or a trusted persona, choose *Sign in with Duo* with that persona's username, then *Other options* and *Bypass Code* in Duo, and enter the code from the card. Each code allows a few sign-ins (5 by default) until the time printed on the card.
- **Privacy.** Read-only users in Identity Intelligence see every identity in the tenant, with emails and sign-in IP addresses, including each other's. They cannot change anything.

**5.1, the Identity Intelligence walkthrough.** You drive it on screen through Administrator SSO. Attendees follow along with their own read-only sign-in: their email, the temporary password and a passcode, then a password of their own.
- Show the posture overview and the persona cast.
- Then open the victim's page: its trust level has dropped, and it fails MFA Flood and Impossible Travel. The times line up with the takeover record.

Don't mention Trust Monitor: it left the Admin Panel in July 2026.

**5.2, your instance.** Tell attendees: "Open your instance's https URL from the card, enter the access key and pick your industry." The https name is a new origin, and browser storage is per origin. The industry and the Demo Controls start from their defaults there, and **Cisco AI Defense starts off**, so turn on what the lab step asks for. Then *Sign in with Duo* with the participant account and a passcode, and the identity badge shows who is signed in. With the card's persona codes they can also sign in as a trusted persona or as the room's victim, whose turns the Identity Risk Gate refuses (claim 2).

**The spray step.** On the Prompt Injection Spray card:
- set **Attacker identity** to the room's victim;
- set **Other actors** to **0**.

That way the AI Defense blocks in the room stack belong to the victim alone, and the Lab 5 join finds one user.

**When to cue containment.** Cue it only after the room has seen two things: the Identity Risk Gate refusing the victim (claim 2), and the Splunk finding that joins CII's failed checks with AI Defense blocks (claim 3). The detection fires while the latest block is under 5 minutes old, so wait until every team has its finding. Then the response agent disables the victim in Duo (claim 4), and the victim's PseudoCo Assistant sessions end within 10 to 20 seconds with a banner.
- The victim is shared by the whole room, so disable it once. From then on `lab5-setup status` shows the victim as contained, and `up` and `handouts` leave its codes off the cards while the trusted personas' codes go on as before. Keep it disabled through the debrief; `provision_personas.py --reset` re-enables it after the workshop.
- **Unblock me** in the banner restores an attendee's session for the rest of the lab. It never re-enables the Duo account, so the evidence stays intact for the debrief.

## After the workshop, in this order

1. `deploy/lab5/lab5-setup down <workshop.yaml>`. On each reachable box it reverts the Lab 5 keys and the HEC host. Then it deletes the tunnels and DNS records. A box Show has already destroyed fails the run, which is expected: nothing is left on it. Then it deletes the persona bypass codes it recorded for each card. Codes whose ids it does not know (it could not tell them apart from another room's, or Duo's answer to their create was lost) stop at their `valid_secs`, and its last line says until when.
2. Rotate the credentials the boxes held: the Web SDK secret and the read-only Status Admin API key (I1). The CII API client never left your Mac, and the boxes' CII token expires on its own within 24 h.
3. The room stack: run its Lab 5 teardown on the TA side, and confirm CII's webhook target is gone before the stack is destroyed.
4. Personas: `py scripts/identity/provision_personas.py --reset`. It re-enables and unlocks the contained victim and resyncs every HOTP token. Then *Clear all step-ups* and CII *Reset Feedback*. The trusted personas' exclusions stay.
5. Participant accounts: nothing to do. `expire` disables them at day 7 and deletes them, with their tokens, at day 14. `deploy/lab5/lab5-setup expire --dry-run` shows the schedule. Delete the handout files now.
6. The room's victim now waits about 8 days before it can be taken over again.

## Open questions

- **S1** (marked for discussion): how the victim's `FAILED_CHECK` reaches a stack that only exists from T-1. It decides when the takeover runs.
- **A persona's bypass code in the Universal Prompt.** Each persona also has a hardware token (script-only), which Duo may offer first. Attendees pick *Other options*, then *Bypass Code*. A code typed into the wrong method counts as a failed attempt toward the lockout. Check the flow in the dry run.
- **Spike S15** has not run. It should prove three things: that API group membership grants CII Read-Only, that a password plus an HOTP passcode reaches CII, and what disabling does to a live CII session.
- **The room checks in `status`** (the victim's events in the stack) wait on the S1 decision. The per-box check that each box's gate blocks the victim is in `status` already.

## Terms used here

**Dates.** T is the first Lab 5 delivery, and T-*n* is *n* days before it. T-18 is the persona trust gate (every persona out of "Unknown", or the date moves). T-2 is the earliest takeover (S1's first option). T-1 is when the Show boxes arrive and `lab5-setup up` runs. T-0 is lab day.

**Spikes** are one-off tests on the Duo tenant, with the spike persona `nina.osei`. The baseline starts only after S1, S2 and S7 pass.
- **S1, the spike:** does the Auth API's `ipaddr` reach `access_device.ip` and its GeoIP in Duo's authentication log, and does CII use it? Until it answers, `personas.yaml` holds no real addresses and the scripts refuse to sign in.
- **S1, the decision:** how the victim's failed checks reach a room stack that only exists from T-1. The options, tried in order: CII's *Send notification* after a T-2 takeover, a Near Time takeover at T-1, a labelled backfill. Still open.
- **S2:** does Impossible Travel fire on Auth API sign-ins, does a new `hostname` count as a new device, and do two venue addresses trip it?
- **S5, S6:** how a persona's trust moves over time, and the exact check names CII returns (they confirm the `getEndUser` query and the check IDs). On 2026-11-06, S5 captured CII's answer for a login it has no record of: an error (`getEndUser`, `errorType` `"404"`, `"Not Found"`, `data` null). Both copies of the rule and `tests/fixtures/cii_end_user_answers.json` now match it exactly, so a new participant account reads as "not in CII yet". If a later spike sees a different answer, replace that exact answer in the table and both copies before the workshop, or every new participant account reads as "status unavailable".
- **S7:** how Duo encodes an API-created HOTP secret (hex or base32), and how far ahead of its counter it accepts a passcode.
- **S15:** that group membership set through the API grants CII Read-Only, that a password plus an HOTP passcode reaches CII, and what disabling does to a live CII session.
- **S16** (ran 2026-11-07): CII's token endpoint gives an API client 6 tokens a clock hour (HTTP 429, `x-ratelimit-limit: 6`, reset on the hour). A token lasts 24 h, and minting one does not end the earlier ones. So a box never mints: `lab5-setup` mints one token on your Mac and pushes it, and the gate uses it until it expires. Still open: whether the 6 are per API client or per tenant (a second API client would show it).

**Decisions** (2026-11-05):
- **A1:** one participant account per instance, disabled after 7 days and deleted after 14.
- **A3:** the Identity Risk Gate fails open: if Duo or CII cannot answer, the turn is allowed and the event says `identity_check="unavailable"`.
- **A4:** revocation is pulled from Duo by each instance, plus an **Unblock me** toggle in the banner.
- **I1:** Duo only, no broker and no AWS. Each box holds the Duo Web SDK keys and a read-only Status Admin API key for the workshop, which are rotated afterwards, and a 24 h CII access token minted on your Mac (S16), which expires on its own.
- **I4:** one setup command on your Mac, which never overwrites another lab's settings.
- **I5:** no code upgrade at setup. The Show template is re-baked on the release instead (12.6).

**Plan sections the tools cite:**
- **4.2:** which groups each lab app admits (see "Duo applications" in `deploy/lab5/README.md`; Sign-in also admits CII Read-Only).
- **4.3:** the persona cast. Every room gets its own victim and an untouched fallback, the handouts carry per-team bypass codes, and no persona ever gets bypass status or a bypass group.
- **4.4:** the Sign-in policy (bypass code + hardware token) and the scripted policy, and lockout auto-revert, which unlocks an account after about 15 minutes.
- **4.5:** the persona activity: the daily baseline sign-ins, the self-check, the T-18 gate, the takeover and the replay.
- **4.6:** the per-delivery preflight and the ordered teardown, as in this runbook.
- **12.1** to **12.4:** the app's configuration, the participant accounts, `lab5-setup`, and the research behind them, as `docs/identity.md` and `deploy/lab5/README.md` describe them.
- **12.5:** the build order: one 4.23.0 release, tested on the dev copy (port 8011, `l5-dev.pseudocoassistant.com`), whose `.env` holds the Lab 5 keys (so the test suites isolate themselves from it).
- **12.6:** the Show template checklist ("Show template" in `deploy/lab5/README.md`).
- **PR-1** to **PR-3:** the plan's three app changes, shipped together as 4.23.0: the identity groundwork, the Duo sign-in, and the Identity Risk Gate with Duo-driven revocation.

## Quick reference

| When | Command |
|---|---|
| once | `py scripts/identity/provision_personas.py` (`--status`, `--dry-run`) |
| once | Admin Panel User access: Sign-in admits PseudoCo Workforce and CII Read-Only; VPN admits PseudoCo Workforce |
| once | Admin Panel: the PseudoCo Lab: Sign-in policy allows bypass code + hardware token |
| once | `deploy/launchd/install-lab5.sh` |
| daily (launchd) | `persona_activity.py baseline`, then the self-check; `lab5-setup expire` |
| T-18 | `py scripts/identity/persona_activity.py selfcheck --gate` |
| takeover (per S1) | `py scripts/identity/persona_activity.py takeover --victim <victim>`, then *Collect Now* |
| T-1 | `lab5-setup check`, `up`, the temporary passwords, the handout, `status` |
| T-0 | `lab5-setup cii-token`, `lab5-setup status`, `persona_activity.py selfcheck`, *Clear all step-ups*; `lab5-setup handouts` if the cards' persona codes run out before the lab ends |
| lost card | `lab5-setup up --only <n> --reissue-passcodes`, then `lab5-setup handouts --only <n> --revoke` |
| after | `lab5-setup down` (it also deletes the recorded persona bypass codes); rotate the box credentials; `provision_personas.py --reset` |
