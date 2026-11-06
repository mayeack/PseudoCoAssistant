# Lab 5 facilitator runbook: Verify with Cisco Identity Intelligence

**For:** Splunk Show deliveries set up with `lab5-setup` from your Mac. **Design:** `docs/identity-intelligence-lab-plan.md` section 12 (sections 4.3–4.6 and 9 for the background). **Tools:** `deploy/lab5/README.md`.

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
- The lab Sign-in policy must accept **hardware-token passcodes**. Participant handouts carry HOTP passcodes, not bypass codes (plan 12.4), so a "bypass code only" policy would refuse them.

**Your Mac:**
1. Create the tool's venv and add the Keychain items. `deploy/lab5/README.md` lists every item, including the Mac-only Provisioner and VPN keys.
2. Once spike S1 says how Duo geolocates addresses, put real home and foreign addresses in `scripts/identity/personas.yaml`. Until then the scripts refuse to send any sign-in.
3. Run `py scripts/identity/provision_personas.py` to create the cast: the PseudoCo Workforce group, the users and one HOTP token each. In CII, add the trusted personas' exclusions (Impossible Travel, MFA Flood, *A Bypass Code Was Used*, *Users Sharing Authenticators*).
4. Run `deploy/launchd/install-lab5.sh` from the main checkout. It installs the daily `lab5-setup expire` (08:15) and the persona baseline plus self-check (09:20).
5. After spikes S1, S2 and S7 pass, at least 4 weeks before the first delivery, set `baseline.enabled: true` in `personas.yaml`. From then on every persona signs in once a day. If anything is wrong, the self-check raises a macOS notification: a failed sign-in, a missing Keychain secret or counter, a disabled or locked-out persona, or a trusted persona failing a CII check.
6. **T-18 gate:** `py scripts/identity/persona_activity.py selfcheck --gate`. Every persona must be out of "Unknown". If one is not, the delivery date moves.

Long trips with the Mac shut down stop the baseline. A few missed days are fine. A missed week before a delivery is not, and the self-check fails after three days without a sign-in.

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
   - `participants.cii_url`, the link printed on the handouts.
2. `deploy/lab5/lab5-setup check <workshop.yaml>`. Every box should say **ready, nothing to upgrade**, and every participant account `PLAN`. It changes nothing.
3. `deploy/lab5/lab5-setup up <workshop.yaml>`. The boxes get their Lab 5 keys, tunnel and DNS name, HEC host and restart. Then every box that came up gets its participant account `l5-<workshop>-<nn>`, and the handout is written.
4. **Temporary passwords.** `up` prints an Admin Panel link per account. Open each one, click *Create temporary password* (valid 30 days) and write it on that participant's card. The Admin API cannot set passwords.
5. Print `~/.pseudoco-lab5/workshops/<workshop>/handout.html` and cut the cards apart.
6. `deploy/lab5/lab5-setup status <workshop.yaml>`. Every box should be green. Participants show "no password yet" until they sign in to CII and set their own.

A box that `up` refused is reported with the reason. Fix it, then re-run with `--only <n>`. A re-run keeps the accounts and their cards. Passcodes are shown only once, so for a lost card use `up --only <n> --reissue-passcodes` (the old passcodes stop working).

## Lab day

**Before attendees sit down (T-0):**
- `lab5-setup status` again. Every tunnel should be healthy and `duo_signin` not gated.
- `persona_activity.py selfcheck`. The trusted personas should pass. The room's victim should fail MFA Flood and Impossible Travel in CII.
- In the Admin Panel, *Users → Clear all step-ups*.
- In each instance's Demo Controls, turn **Trigger Demo Incident** off. Its synthetic incident would crowd the room stack.

**Handing out the cards.** Each attendee gets one card: their instance URL and access key, their participant account, its passcodes and the temporary password. Say these out loud:
- **Get off VPN.** Sign in from the venue network. A VPN exit far from the room makes your own sign-ins, and any shared persona's, look like Impossible Travel.
- **Use each passcode once, in order.** Skipping ahead works, but the codes before it then stop working.
- **Privacy.** Read-only users in Identity Intelligence see every identity in the tenant, with emails and sign-in IP addresses, including each other's. They cannot change anything.

**5.1, the Identity Intelligence walkthrough.** You drive it on screen through Administrator SSO. Attendees follow along with their own read-only sign-in: their email, the temporary password and a passcode, then a password of their own.
- Show the posture overview and the persona cast.
- Then open the victim's page: its trust level has dropped, and it fails MFA Flood and Impossible Travel. The times line up with the takeover record.

Don't mention Trust Monitor: it left the Admin Panel in July 2026.

**5.2, your instance.** Tell attendees: "Open your instance's https URL from the card, enter the access key and pick your industry." The https name is a new origin, and browser storage is per origin. The industry and the Demo Controls start from their defaults there, and **Cisco AI Defense starts off**, so turn on what the lab step asks for. Then *Sign in with Duo* with the participant account and a passcode, and the identity badge shows who is signed in.

**The spray step.** On the Prompt Injection Spray card:
- set **Attacker identity** to the room's victim;
- set **Other actors** to **0**.

That way the AI Defense blocks in the room stack belong to the victim alone, and the Lab 5 join finds one user.

**When to cue containment.** Cue it only after the room has seen two things: the Identity Risk Gate refusing the victim (claim 2), and the Splunk finding that joins CII's failed checks with AI Defense blocks (claim 3). The detection fires while the latest block is under 5 minutes old, so wait until every team has its finding. Then the response agent disables the victim in Duo (claim 4), and the victim's PseudoCo Assistant sessions end within 10 to 20 seconds with a banner.
- The victim is shared by the whole room, so disable it once.
- **Unblock me** in the banner restores an attendee's session for the rest of the lab. It never re-enables the Duo account, so the evidence stays intact for the debrief.

## After the workshop, in this order

1. `deploy/lab5/lab5-setup down <workshop.yaml>`. On each reachable box it reverts the Lab 5 keys and the HEC host. Then it deletes the tunnels and DNS records. A box Show has already destroyed fails the run, which is expected: nothing is left on it.
2. Rotate the credentials the boxes held: the Web SDK secret, the read-only Status Admin API key and the CII API client (I1).
3. The room stack: run its Lab 5 teardown on the TA side, and confirm CII's webhook target is gone before the stack is destroyed.
4. Personas: `py scripts/identity/provision_personas.py --reset`. It re-enables and unlocks the contained victim and resyncs every HOTP token. Then *Clear all step-ups* and CII *Reset Feedback*. The trusted personas' exclusions stay.
5. Participant accounts: nothing to do. `expire` disables them at day 7 and deletes them, with their tokens, at day 14. `deploy/lab5/lab5-setup expire --dry-run` shows the schedule. Delete the handout files now.
6. The room's victim now waits about 8 days before it can be taken over again.

## Open questions

- **S1** (marked for discussion): how the victim's `FAILED_CHECK` reaches a stack that only exists from T-1. It decides when the takeover runs.
- **How attendees sign in as the victim or a trusted persona.** Section 4.3 gave teams bypass codes for the personas. Section 12.4 gave participant accounts HOTP passcodes instead, and the persona HOTP codes are for the scripts only. The tools build no persona bypass codes until this is decided.
- **Spike S15** has not run. It should prove three things: that API group membership grants CII Read-Only, that a password plus an HOTP passcode reaches CII, and what disabling does to a live CII session.
- **The victim checks in `status`** (victim blocked on each box, victim failing in CII, its events in the stack) arrive with the identity gate and the S1 decision.

## Quick reference

| When | Command |
|---|---|
| once | `py scripts/identity/provision_personas.py` (`--status`, `--dry-run`) |
| once | `deploy/launchd/install-lab5.sh` |
| daily (launchd) | `persona_activity.py baseline`, then the self-check; `lab5-setup expire` |
| T-18 | `py scripts/identity/persona_activity.py selfcheck --gate` |
| takeover (per S1) | `py scripts/identity/persona_activity.py takeover --victim <victim>`, then *Collect Now* |
| T-1 | `lab5-setup check`, `up`, the temporary passwords, the handout, `status` |
| T-0 | `lab5-setup status`, `persona_activity.py selfcheck`, *Clear all step-ups* |
| after | `lab5-setup down`; rotate the box credentials; `provision_personas.py --reset` |
