# lab5-setup: Show boxes in, Lab 5 out

`lab5-setup` turns the Splunk Show boxes of one workshop into Lab 5 ("Verify: Cisco Identity Intelligence") instances, and puts them back afterwards. It runs on the facilitator's Mac. The design is section 12.3 of `docs/identity-intelligence-lab-plan.md`, a planning note kept outside the repository; section 12.1 lists the keys it writes. The plan sections, spikes (S1, S7, ...) and decisions (I1, I5, ...) cited here are defined in "Terms used here" in `docs/identity-lab-facilitator.md`, so this README does not need the plan.

There is no broker and no AWS. Secrets come from the Mac's Keychain. What `up` created is recorded under `~/.pseudoco-lab5/`. Everything else lives on the boxes, in Duo and in Cloudflare.

The same Mac runs the persona scripts (`scripts/identity/`, below) and two daily launchd jobs (`deploy/launchd/install-lab5.sh`). The lab-day runbook is `docs/identity-lab-facilitator.md`.

## Commands

```
deploy/lab5/lab5-setup check  workshop.yaml   # read-only: what up would change
deploy/lab5/lab5-setup up     workshop.yaml   # make every box a Lab 5 instance
deploy/lab5/lab5-setup status workshop.yaml   # per-box preflight + Cloudflare state
deploy/lab5/lab5-setup handouts workshop.yaml # a fresh batch of persona bypass codes on every card
deploy/lab5/lab5-setup down   workshop.yaml   # delete tunnels + DNS + recorded bypass codes, revert the keys
deploy/lab5/lab5-setup expire [workshop.yaml] # participant accounts: disable at day 7, delete at day 14
```

`--only 1,3` limits a run (`expire` excepted) to some instance numbers. `--restart` makes `up` or `down` restart the app even when `.env` did not change. `--reissue-passcodes` makes `up` replace each participant's HOTP token and print new passcodes. `--dry-run` makes `expire` list what it would do. `--revoke` makes `handouts` also delete the persona bypass codes of each card's earlier batches, for a lost card.

| Command | What it does |
|---|---|
| `check` | Connects to each box and reads its version, `.env` and HEC destinations. Prints the exact `.env` diff, the HEC host change, the tunnel and DNS plan, and a verdict per box. A box that `up` would accept says **ready, nothing to upgrade**. It also says what `up` would do for each participant account and for the persona bypass codes on its card, and fails each card whose codes `up` would refuse. It changes nothing on the boxes, in Cloudflare or in Duo. |
| `up` | Runs each box in parallel, in this order: version check, backup, Lab 5 `.env` keys, tunnel and DNS, HEC host, restart, preflight. Any refusal happens before the first change. Then it creates a participant account for each box that came up, puts the room personas' bypass codes on its card, and writes the handout. |
| `status` | Checks each box's tunnel health, DNS record, connector unit and `.env` drift, whether the box's own Identity Risk Gate blocks the room's victim (see below), then runs the preflight. It also lists `l5-<workshop>-*` tunnels and DNS records that no box record owns, each participant account's state and age, each room persona's Duo status, and how long each card's persona bypass codes have left. |
| `handouts` | Puts a fresh batch of persona bypass codes on each handout card (or `--only` some), for lab-day morning or a lost card. It touches no box, tunnel or participant account, and asks for no SSH password. The codes it replaces stay valid until they expire, unless `--revoke` deletes them. |
| `down` | Removes the connector, reverts the Lab 5 keys and the HEC host on every reachable box, then deletes the DNS records and tunnels that `up` recorded. A box it cannot reach or cannot finish fails the run, and the last line says how to re-run it. Running it twice is safe: the second run changes nothing. Then it deletes the persona bypass codes recorded for each card, and its last line says until when any code it could not delete stays valid. |
| `expire` | Day 7: disables each participant account. Day 14: deletes it and its HOTP token, which frees the Duo seat. Without a workshop file it covers every workshop, which is how the daily launchd job runs it. It is idempotent and never touches a persona or a bypass code. |

Exit codes: `0` means every box, participant account and card is fine. `1` means at least one box, account or card's bypass codes failed or was refused; its report says why. `2` means a usage, configuration or Keychain error, or a Duo prerequisite such as the CII Read-Only group is missing. A Duo error, or a handout lock that times out, while a card's bypass codes are issued or deleted fails that card (`1`), never the run: the others go on, and `up` still prints its result, the handout and the reminders.

## One-time setup on the Mac

1. Install the tool's dependencies (paramiko, PyYAML and duo_client) into their own venv. The wrapper, the persona scripts' launchd job and `install-lab5.sh` all use that venv. Keep them out of the app's venv: paramiko pulls in `cryptography`, and `tests/test_attachments.py` relies on the app's venv lacking it.

   ```
   python3 -m venv ~/.pseudoco-lab5/venv
   ~/.pseudoco-lab5/venv/bin/pip install -r deploy/lab5/requirements.txt
   ```

2. Put the credentials in the login Keychain. Nothing here should be typed after `-w`: `security` then prompts for the value, so it stays out of your shell history.

   ```
   security add-generic-password -s pseudoco-lab5-duo-websdk-client-secret -a "$USER" -w
   ```

| Keychain item | `.env` key | Source |
|---|---|---|
| `pseudoco-lab5-cloudflare` | (none) | Cloudflare API token `pseudoco-lab5-instances`: Tunnel edit + `pseudocoassistant.com` DNS edit |
| `pseudoco-lab5-duo-websdk-client-id` | `DUO_CLIENT_ID` | Web SDK app **PseudoCo Lab: Sign-in** |
| `pseudoco-lab5-duo-websdk-client-secret` | `DUO_CLIENT_SECRET` | same app |
| `pseudoco-lab5-duo-websdk-api-host` | `DUO_API_HOST` | same app |
| `pseudoco-lab5-duo-status-ikey` | `DUO_ADMIN_IKEY` | Admin API app **PseudoCo Lab: Status (read-only)** |
| `pseudoco-lab5-duo-status-skey` | `DUO_ADMIN_SKEY` | same app |
| `pseudoco-lab5-cii-client-id` | `CII_CLIENT_ID` | the CII API client's "Copy all" |
| `pseudoco-lab5-cii-client-secret` | `CII_CLIENT_SECRET` | same |
| `pseudoco-lab5-cii-token-url` | `CII_TOKEN_URL` | same |
| `pseudoco-lab5-cii-api-url` | `CII_API_URL` | same |
| your choice, per room | (none) | the room stack's HEC token. Optional: only its last 4 characters are compared with the box's destination. |
| `pseudoco-lab5-duo-provisioner-ikey` | (none, Mac only) | Admin API app **PseudoCo Provisioner** (Grant resource read + write): participant accounts and the persona cast. It never leaves the Mac. |
| `pseudoco-lab5-duo-provisioner-skey` | (none, Mac only) | same app |
| `pseudoco-lab5-duo-api-host` | (none, Mac only) | the tenant's API hostname, the same on every Duo application page. If it is missing, `pseudoco-lab5-duo-websdk-api-host` is used. |
| `pseudoco-lab5-duo-vpn-ikey` | (none, Mac only) | Auth API app **PseudoCo VPN**: the persona sign-ins (`persona_activity.py`) |
| `pseudoco-lab5-duo-vpn-skey` | (none, Mac only) | same app |
| `pseudoco-lab5-hotp-<persona>` | (none, Mac only) | written by `provision_personas.py`, one per persona. You never add these by hand. |

The names of the first table's items are defaults. A workshop file can rename any of them under `keychain:`. The Mac-only items have fixed names.

## Duo applications: who may sign in

Duo checks an application's **User access** before an instance sees who signed in. A new application admits no one until it is set (plan 4.2). Only the Admin Panel can set or check it here: reading or changing an application needs the Admin API's *Grant applications* permission, which neither the Provisioner nor the Status app has. Set it once, after `provision_personas.py` has created PseudoCo Workforce (*Applications*, then the application, then *User access*):

| Application | User access | Who signs in through it |
|---|---|---|
| **PseudoCo Lab: Sign-in** (Web SDK) | *Enable only for permitted groups*: **PseudoCo Workforce** and **CII Read-Only** | everyone an instance's `IDENTITY_ALLOWED_USERS` names: the trusted personas and the room's victim (PseudoCo Workforce), and the instance's participant account (CII Read-Only, which `up` adds every participant account to) |
| **PseudoCo VPN** (Auth API) | *Enable only for permitted groups*: **PseudoCo Workforce** only | the persona scripts |
| **PseudoCo Provisioner**, **PseudoCo Lab: Status** (Admin API) | nothing to set | no one: they are API keys, for the Mac and for the boxes |

**The Sign-in policy.** PseudoCo Lab: Sign-in also gets its own policy (plan 4.4), applied to that application only, so the global policy stays as it is. Its authentication methods are **bypass code + hardware token** and nothing else: tick *Bypass code* and *Hardware tokens*, and untick every other method. Every handout card needs both. Its persona lines are bypass codes (see "Persona bypass codes"), and the participant's passcodes come from a hardware (HOTP) token. Without hardware tokens, Duo refuses every participant; without bypass codes, every persona sign-in. The rest of 4.4 stands: New User policy deny, Verified Push off, remembered devices off, risk-based factor selection off. No tool here creates or checks the policy. If it is ever scripted through Policies v2, `allowed_auth_list` is `bypass` and `hardware-token`, and every other method goes in `blocked_auth_list`, because Duo allows a method that is in neither list.

Plan section 4.2 limits every lab app to PseudoCo Workforce. That predates the participant accounts (12.2): a Sign-in app limited that way refuses every participant at the Universal Prompt, so no attendee can sign in to their own instance. Participant accounts never need PseudoCo Workforce. If someone adds one to it anyway, it is still a participant: `expire` disables and deletes it on schedule, and its `status` and `expire` rows say it is in the group. `up` repeats the Sign-in requirement after the participant accounts, because the tools cannot check it.

## The workshop file

Copy `deploy/lab5/workshop.example.yaml`, one per delivery. It holds no secrets: only names, addresses and Keychain item names.

- `workshop` names the delivery. Box *nn* becomes tunnel `l5-<workshop>-<nn>` and host `l5-<workshop>-<nn>.pseudocoassistant.com`. Use a new name each time, because the tool refuses to take over a tunnel or record it did not create.
- `stack.hec_url` is the room's Splunk stack. `up` looks for the box's existing destination with that URL.
- `room.victim` goes on every box's `IDENTITY_ALLOWED_USERS`, together with the trusted personas and that box's participant account. To swap to `room.fallback`, change `victim` and re-run `up`. Every room needs its own victim (plan 4.3): `check`, `up` and `handouts` refuse a victim that another workshop on this Mac still holds, because one room's containment would end the other room's victim sessions and void its codes. A workshop holds a persona while attendees can still reach one of its boxes (a tunnel or DNS record not deleted) whose app admits it, or while Duo may still hold working bypass codes for it from that workshop's cards. Both are read from what the boxes and cards hold, never from the victim its workshop file names now: during a swap to `room.fallback` (one that `check` only previewed, or that `up` finished on some boxes only), the boxes still on the old victim keep holding it, and so do the old victim's codes until they expire or are deleted. While that room is still running (attendees can reach one of its boxes, and `down` has not started on it), the refusal offers `handouts --revoke` with that workshop's file for those codes, because `down` would end the room. It touches no box, but it deletes every earlier code on the cards that file lists, the batch the room's teams hold now included, and puts fresh ones on them: their persona sign-ins fail until the new cards are printed and handed out. It is offered only where it clears those codes: that workshop's file names another victim and turns participant accounts and bypass codes on (as its last `check`, `up`, `status` or `down` recorded), and its handout has a card for each card that holds them. Otherwise the refusal offers `down` and says why `handouts --revoke` would not do. Once that room has started `down` (a box whose `.env` it reverted, or one it could not reach), the refusal offers `down` again, even while a tunnel or DNS record it failed to delete is still there: a re-run retries every delete that failed. `down` deletes the boxes' tunnels and DNS records and the recorded codes, from this Mac, even for a box Show has destroyed, so a revert still pending on such a box never holds the victim. What `down` cannot clear is a code whose id this tool never learned (a create whose answer was lost, or a batch recorded without ids): those only expire. The refusal names what holds the victim and the steps that clear all of it together. A record it cannot read (or one holding a field this tool did not write) counts as holding the victim until it is restored, or for a participant record, until any code it can hold has expired.
- `participants:` is optional. `enabled` (default `true`) creates one participant account per box. `cii_url` is the Identity Intelligence sign-in link printed on the handout. `email_domain` defaults to `zone`. Turn the accounts off for a dry run that should use no Duo seats.
- `bypass_codes:` is optional (see "Persona bypass codes"). `count` (default 1, at most 10) is the codes per persona per box, `reuse_count` (default 5, at most 20) the sign-ins each code allows, and `valid_hours` (default 12, at most 72) how long a batch lasts from the moment it is issued. `enabled: false` puts no persona codes on the cards. The codes ride on the participant handout, so they need `participants.enabled`.
- `personas_file` is the persona cast. It defaults to `scripts/identity/personas.yaml`. `expire` never touches a persona, and `up` only gives the room's personas their bypass codes: no persona is ever changed, disabled or deleted.
- `boxes` has one row per Show box: `instance` and `host`. Port `2222`, user `splunk`, checkout `/home/splunk/DemoBot`, unit `demobot-app` and app port `8001` come from `defaults:`.
- `identity:` is optional and overrides the 12.1 defaults. The app reads these values as numbers and a boolean when it starts, so a value like `12h` would stop it from starting. The tool therefore checks them before it connects to anything, and refuses the file otherwise:
  - `session_ttl_minutes`: a whole number from 1 to 10080 (7 days), the range the app uses;
  - `status_ttl_seconds`: a whole number from 0 to 3600;
  - `fail_open`: `true` or `false`.

## What `up` does to a box

1. **Version check.** The box's `/health` must report at least `required_version` (default 4.22.0). There is no code upgrade (I5). A box below that is refused with "the Show template needs that release (12.6)". It also checks `sudo -n`, `cloudflared` and the app unit, and that exactly one HEC destination sends to the room stack.
2. **Backup.** `.env` (byte for byte) and `medadvice.db` (SQLite online backup, safe while the app writes) go to `~/.pseudoco-lab5/backups/<workshop>-<UTC stamp>-<random>/` on the box, mode 0600 in a 0700 directory. Each run gets a new directory.
3. **Lab 5 keys.** Only the keys of the 12.1 table change, `PUBLIC_BASE_URL` and `HEC_HOST` included. The first live line of a key is replaced in place, and a missing key is appended. Every other line keeps its bytes, comments, quoting and line endings. The file is written atomically, with its mode kept. If the file changed since it was read, nothing is written.
4. **Tunnel and DNS.** These are created through the Cloudflare API:
   - a remotely managed tunnel `l5-<workshop>-<nn>`, with ingress `<host> -> http://localhost:8001`;
   - a proxied CNAME `<host> -> <tunnel-id>.cfargotunnel.com`.

   `cloudflared` runs as `pseudoco-assistant-lab5-tunnel.service`. Its token sits in `/etc/pseudoco-assistant/lab5-tunnel.env` (root, 0600) and reaches cloudflared as `TUNNEL_TOKEN`, never on a command line.
5. **HEC host.** The tool reads the destination through the box's Settings API, authenticated with the box's own `ACCESS_KEY`. It sends a `PUT` that carries only `host`, then reads the destination back and checks that every other field is unchanged. The other labs' destinations are never touched.
6. **Restart.** `sudo systemctl restart demobot-app`, only when `.env` changed. If the app does not answer `/health` within 120 s, `up` puts back the `.env` this run started from, restarts the app again and fails the box, so Labs 0–4 keep running. Fix the cause (the box's `journalctl -u demobot-app` says what it is), then re-run `up`.
7. **Preflight**, through the public name:
   - the name resolves;
   - `https://<host>/health` reports at least the required release;
   - `/api/server-info` shows `gated.duo_signin` enabled. If it is not, the gate's own reason is printed.

The app's API is reached through an SSH-forwarded connection to the box's `127.0.0.1:8001`, so the access key never crosses the Show box's plain-http port.

After the boxes, `up` creates a **participant account** for each box that came up (see "Participant accounts" below). Step 3 already put that account's username on the box's `IDENTITY_ALLOWED_USERS`, because the name is fixed. Then it puts the room personas' bypass codes on each card (see "Persona bypass codes").

## What `down` puts back

- The connector unit and its token file are stopped and removed. The tool only removes a unit that carries its own marker comment.
- Each Lab 5 key is put back the way the first `up` found it. A replaced line goes back in place, and an appended key is removed. Lines outside the Lab 5 keys stay as they are now, even if another lab changed them during the workshop.
  - The state directory never stores a credential. A credential that existed before `up` is restored from the box's first backup.
  - A box with no record of `up` gets every Lab 5 key that holds a value removed, which is the app default and the template state.
- `.env` backups that hold Lab 5 credentials (made by a re-run of `up`) are deleted. The first backup is kept.
- The app restarts if `.env` changed, and `down` waits for it to answer `/health`.
- The destination's host then goes back to its prior value, through the restarted app. If someone changed it after `up`, it is left alone, with a warning. If the destination no longer exists, there is nothing to revert.
- The DNS record and tunnel that `up` recorded are deleted, even when the box itself is unreachable. Anything named `l5-<workshop>-*` that the tool did not create is only reported.
- A box that `down` cannot reach (a wrong password, a changed host key, a timeout) or cannot finish (for example, the app does not answer, so the HEC host stays) fails the run with exit 1:
  - its report says what is still on the box, and the run ends with a `NEXT:` line that names the `--only` re-run;
  - its record keeps a pending revert, which `status` shows, until a `down` finishes on the box;
  - if Show has already destroyed the box, the failure is expected: nothing is left on it to revert.
  - an SSH session lost partway (paramiko's `SSHException`, an `EOFError`) is the same: the box fails, its revert stays pending, and its DNS record and tunnel are still deleted.

**The victim check (`status`).** On each box, `status` runs the gate's own lookup and decision for `room.victim` with the box's venv, code and `.env` (`<checkout>/venv/bin/python -I -`, the script on stdin): the Duo Status keys and the CII API client that `up` wrote there. It is read-only (a Duo Admin API GET, a CII token and query) and prints only fixed codes. `FAIL` when the box cannot ask Duo or CII about the victim (for example a stale `pseudoco-lab5-duo-status-skey`: Duo answers 401, no email is known, and CII is not asked), because with `IDENTITY_FAIL_OPEN` on the gate would then let the victim chat and nothing else would say so; `FAIL` too when Duo has no such user or the release has no gate. `WARN` while the gate would let the victim chat (before the takeover, CII does not show it failing yet). `OK` when the gate blocks it: a contained victim (disabled in Duo) too, and a block on what a partial answer did say (CII still rating the victim `UNTRUSTED`, with an error elsewhere in its answer), whose row also names what did not answer in full. A Duo lockout alone is never `OK`: Duo unlocks the account on its own in about 15 minutes and the gate then decides without it, so a victim blocked only by a lockout is `WARN`, or `FAIL` when the box cannot ask Duo or CII. A `cii graphql_error` means CII gave the box's API client a token and then answered with an error, so the client's ID and secret are right; the row carries only the code. One that stays is the API client's role or scopes in CII (it must be able to read end users: a refused permission, scope or role is an error, never "no such user"), or an answer spikes S5/S6 pin: a query the tenant rejects, or CII's answer for a login it has no record of. `persona_activity.py selfcheck` on the Mac asks CII with the same API client and prints CII's own message. A `cii bad_response` is an answer in a shape the gate cannot read: one that stays means the query does not match the tenant (spikes S5/S6). By lab day (T-0) the row must be `OK`.

Participant accounts stay until `expire` disables them at day 7 and deletes them at day 14. `down` also deletes the persona bypass codes it recorded for each card (see "Persona bypass codes"). Any it could not tell apart from another room's stop at their `valid_secs`, and the last line of `down` says when. Rotate the Duo and CII credentials after the workshop (I1).

## Participant accounts (plan 12.2)

`up` creates one Duo account per box that came up, with the Admin API app PseudoCo Provisioner:

- **Username** `l5-<workshop>-<nn>`, **email** `l5-<workshop>-<nn>@pseudocoassistant.com` (the zone, or `participants.email_domain`). Identity Intelligence matches users by email.
- **Notes**: `lab5-setup participant; workshop=<workshop>; instance=<nn>; created=<UTC time>`.
- **Groups**: **`l5-<workshop>`**, created on the first `up`, then **CII Read-Only**, which gives Duo SSO into Identity Intelligence as read-only. The workshop group goes first because it is the third marker `expire` needs: a run stopped between the two adds leaves an account `expire` still disables and deletes, never one in CII Read-Only that it would leave alone. `up` refuses to start if Duo has no CII Read-Only group. CII Read-Only is also the group that gets the account through the Sign-in app, whose User access must admit it (see "Duo applications" above). Never PseudoCo Workforce: that is the persona cast's group.
- **Its own HOTP token** (type h6, serial = the username), created through the API and attached. `up` computes the token's first 10 passcodes for the handout and then discards the secret, so the passcodes cannot be printed again. `--reissue-passcodes` replaces the token, and the old passcodes stop working.
- The account stays **active** and MFA-required. It never gets bypass status or bypass codes of its own: the bypass codes on its card are the room personas'.

An account with the participant's name that `up` did not create (its notes lack the marker, or name another workshop) is left alone, and that box's participant fails the run. A re-run keeps existing accounts and their handout cards, and finishes an account that an earlier run left half made.

**The handout** is `~/.pseudoco-lab5/workshops/<workshop>/handout.html`, a printable card per instance, plus `handout.csv` with the same rows. Both are 0600. A card holds the instance URL, the box's access key, the username, the email, a blank for the temporary password, the 10 passcodes in order and the sign-in steps. Below them are the team's persona bypass codes (see "Persona bypass codes"). It also tells the participant that other read-only users can see their sign-ins and IP address. A card leaves the handout once its account is disabled. Delete the files after the workshop. They are the only place the tool writes a participant's sign-in details or a persona's bypass code.

**The password is a console step.** The Admin API cannot set a Duo Directory password. `up` prints each account's Admin Panel link. Open each one and click **Create temporary password** (valid 30 days), then write it on that participant's card. The token is attached first, because that flow expects an enrolled device. The participant signs in with the temporary password and a passcode, then sets their own password. `status` shows who has done so (`has_password`).

**`status`** prints one row per account: its Duo status, whether its token is attached and whether it has a password, plus its age and the dates it is disabled and deleted. A missing or locked-out account fails the run. For a locked-out account, unlock it in the Admin Panel and turn on lockout auto-revert.

**`expire`** lists every Duo user whose name starts with `l5-` and acts only when all three markers match: the `l5-<workshop>-<nn>` username, the notes marker naming that same workshop and instance, and membership of `l5-<workshop>`. It never acts on a persona: a username in `scripts/identity/personas.yaml`, or a user whose notes carry the persona marker. `personas.yaml` refuses `l5-` names, so a persona can never carry the participant markers. Membership of PseudoCo Workforce does not make an account a persona: a participant account that someone added to that group is still disabled and deleted on schedule, so its seat is freed, and its row says it is in the group. Age is counted from Duo's own `created` time, or from the notes if that is missing.

- At day 7 it sets `status=disabled`. That denies sign-in and invalidates remembered devices, though an open CII tab may last until CII's idle timeout.
- At day 14 it deletes the account's HOTP token, then the account. Deleting through the API is immediate and permanent and skips Duo's Trash. That is why it needs all three markers, and why `--dry-run` exists. If the token cannot be deleted, the account is kept for the next run.
- Everything else, such as a user without the markers, is listed as left alone. One exception is reported as a failure, so the daily run notifies: an account with the participant name and the notes marker for that same workshop and instance, but not in `l5-<workshop>` (a run stopped between creating it and adding it to its groups). `expire` still leaves it alone, and its row says how to finish it: re-run `up --only <n>` for that workshop, or delete it in the Admin Panel. `status` names it the same way.
- It writes a run log to `~/.pseudoco-lab5/runs/`. A failed run raises a macOS notification and exits 1; one that cannot reach Duo exits 2, and one that crashes re-raises after its notification, so the traceback lands in `logs/launchd-lab5-expire.log`. A job that cannot start at all (`LAB5_PYTHON` missing, or its venv broken by a Python upgrade) can notify from no Python: the launchd jobs therefore run through `deploy/launchd/run-lab5-job.sh`, which raises the notification itself and exits 2. An account left half made by an interrupted `up` (see below) also fails the run, so the daily job notifies.

**Seats.** Disabled users still hold a Duo seat. Only deletion frees one. You need seats for your own account, the persona cast and every participant account from the last 14 days. Each seat also covers up to 5 CII identities.

**What this relies on.** These facts come from the research in plan section 12.4 (Duo Admin API docs of 2026-11-04 and CII docs, checked 2026-11-05). This stage also checked the Admin and Auth API pages read-only.

- `POST /admin/v1/users` takes `username`, `email`, `realname`, `notes` and `status`.
- The user object carries `created`, `groups`, `tokens` and `has_password`. `has_password` is true when the user has a Duo Directory password.
- `POST /admin/v1/users/{id}/groups` takes `group_id`. `POST /admin/v1/groups` returns error 40003 when the name is already taken.
- `POST /admin/v1/tokens` takes `type=h6`, `serial` (up to 128 characters), `secret` and `counter`. The page does not say how the secret is encoded. The tools send hex, and spike S7 settles it (personas.yaml `hotp.secret_encoding`).
- `DELETE /admin/v1/tokens/{id}` returns 200 whether or not the token existed. `DELETE /admin/v1/users/{id}` is immediate and permanent, and the page does not say that it removes the user's tokens. That is why `expire` deletes the token first.
- Spike S15 (group membership grants CII Read-Only; a password plus an HOTP passcode reaches CII; what disabling does to a live CII session) has not run yet.

## Persona bypass codes (plan 4.3)

Attendees also sign in to their instance as the room's victim and as the trusted personas: every instance's `IDENTITY_ALLOWED_USERS` names them. The personas' HOTP tokens stay script-only, because HOTP accepts only codes ahead of Duo's counter, so a second consumer would break the baseline. Their cards carry bypass codes instead. The participant account itself never gets one (12.4).

**What `up` issues.** After the participant accounts, each card gets one small batch for its team, that is, for its box. The batch has codes for `room.victim` and for each `room.trusted` persona. The fallback victim and the participant accounts get none.

- `count` codes per persona (default 1), each good for `reuse_count` sign-ins (default 5), until `valid_hours` after it was issued (default 12). Those are Duo's `count`, `reuse_count` and `valid_secs`, and the tool always sends all three. Duo's own defaults, unlimited uses and no expiry, are never used.
- `preserve_existing=true`, always. The trusted personas are shared by every box and by other rooms, and Duo's default clears every code the user already has.
- Only the cast's personas get codes: a user `scripts/identity/personas.yaml` lists in that role (victim, or spike for a dry run; trusted) whose Duo notes carry the persona marker. A workshop file that names anyone else as the victim or a trusted persona is refused before anything changes. A Duo user with a persona's name but without the marker gets nothing, and that run issues no codes at all.
- Only while each room persona is **active** in Duo. Plan 4.3 forbids bypass status: Duo then skips the second factor for that persona, so anyone with an instance's access key could sign in as it. A room persona in bypass status, disabled or in any other status but active (or locked out, below) stops every card's batch: `check`, `up` and `handouts` fail each card (a card that keeps a valid batch included) and name the persona, its status and the fix, `scripts/identity/provision_personas.py --reset --only <persona>`. The tools never change a persona's status themselves. The same goes for a room persona in any Duo group whose status is not Active: plan 4.3 forbids a bypass group as it forbids bypass status, and Duo lets no member of a disabled group sign in. The fix is in the Admin Panel: take the persona out of that group, or set the group Active. `status` shows each room persona's Duo status and groups.
- One exception: the room's victim once the lab has contained it, that is, disabled in Duo after this workshop gave it codes. `check`, `up`, `handouts` and `status` then say it is contained, leave its codes off the cards and go on with the trusted personas' codes. Nothing asks for a reset before the debrief: `provision_personas.py --reset` runs after the workshop. A victim that is disabled before the workshop gave it any code was left so by an earlier delivery, and fails every card with the reset as the fix.
- A locked-out room persona is the other exception, because a lockout is temporary: Duo unlocks it on its own in about 15 minutes (lockout auto-revert, plan 4.4). So nothing asks for a reset mid-lab. Its row says it is locked out, unlocks on its own, and to retry `lab5-setup handouts <workshop.yaml> --only N` after that. A card issued meanwhile gets the other personas' codes and is reported `PARTIAL`, not failed (exit 0, named in `RESULT`). A card that keeps a valid batch keeps the persona's code, which works again once Duo unlocks it. A locked-out persona in a Bypass or Disabled group still stops every card.
- Per-team batches limit how far one team can burn another's codes. Each code signs in only its own persona.
- A re-run of `up` keeps a card's batch while it is valid and names the same personas. It issues a new one when the batch has expired, when `down` revoked its codes, when `room.victim` or `room.trusted` changed, or when `bypass_codes.count`, `reuse_count` or `valid_hours` changed. The report names what changed, for example `reuse_count 5 -> 3`.
- **When a batch stops.** Duo counts `valid_secs` from when it makes each code, so a card's time is taken after its last create returned, rounded up to the minute the card prints. It is never earlier than any of its codes' own expiry, however long the run takes.

**The card** lists each persona with its code, then the steps: *Sign in with Duo* with the persona's username, then *Other options*, *Bypass Code* in Duo. It also says how many sign-ins each code allows and when the batch expires, in UTC. The codes exist only in the 0600 handout. They are registered with the redactor, so they never reach the output, the run log or the state directory. The participant record (`participants/<nn>.json`) keeps when each batch was issued, when it expires, for whom and the ids of its codes, but never a code. `status` shows how long each card's batch has left, fails a card whose batch has expired or whose codes `down` revoked, and warns about one issued with other settings than the workshop file's. The card also carries its batch's id in the record (`bypass_batch`, not a secret), which is how a revocation reaches it.

**`lab5-setup handouts workshop.yaml [--only N] [--revoke]`** puts a fresh batch on each card, for lab-day morning or a lost card. It touches no box, tunnel or participant account, and asks for no SSH password. Print the changed cards again. The codes it replaces stay valid until they expire. For a lost card, `handouts --only N --revoke` also deletes the codes of that card's earlier batches (see "Revocation"), but only once the card carries its new batch and the participant record has it. A card whose new batch failed keeps its earlier codes, and the handout line names only the cards that really changed. If `up` runs the day before the lab, either raise `valid_hours` so the batch covers the end of lab day, or run `handouts` that morning (then copy the temporary passwords onto the new cards). `up --reissue-passcodes` keeps a card's persona codes: it replaces only the participant's token.

**Duo's limit.** Duo keeps at most 100 bypass codes per user, and a trusted persona collects one batch per box from every room until they expire. Before it issues anything, `up` (and `handouts`) counts each persona's unexpired codes, other rooms' included. If the run would cross 100, it issues nothing and names the persona. With `count: 1`, each issue takes one code per box from each persona.

**One card at a time.** A Duo error while a card's codes are issued, or the handout's lock timing out while the card is written, fails that card only. A Duo call that gets no usable answer (a timeout, a TLS error, an answer cut off or not JSON) counts as a Duo error, and its message never repeats the answer. The other cards go on, and `up` still prints its `RESULT` line with the failed cards, the handout path, the temporary-password links and the Sign-in reminders. `handouts` and `down` likewise print their `RESULT`. The exit code is `1`. A card that got only part of its batch keeps its earlier codes, and the codes Duo did issue are recorded as an incomplete batch, which `down` and `handouts --revoke` delete. Re-run to finish the card. If a create gets no usable answer (a timeout, an answer cut off, a 5xx such as a gateway's 502, 503 or 504, or a body that is not the codes), Duo may still have made the codes, which are then on no card. The tool does not look for them, because no listing can tell them from another room's codes for the same shared persona. The batch records that persona's ids as unknown for the card, and the row says, whatever the cause: "Duo's answer was lost; any codes it made expire at <time> and cannot be revoked by this tool". That time carries 5 minutes more (`LOST_MARGIN_S`), for a create Duo finishes after the tool stopped waiting. No error says Duo could not be reached: the request may have gone out before its answer was lost.

**Revocation: `down` and `handouts --revoke`.** Duo's Admin API deletes a code only by its id (`DELETE /admin/v1/bypass_codes/{id}`). The create call returns only the code strings, not their ids, and a code carries no label or notes. So the tool lists the persona's `bypass_code_id`s just before and after each create that returns its codes. Exactly `count` new ids are this batch's, and the participant record keeps them. Any other difference means another room issued codes for the same persona in between (or a lost create's codes landed late), and a second listing that fails tells nothing either. Then the record keeps that persona's ids as unknown for the card, and the row says when its codes expire: for those codes, as for a lost create's, `valid_secs` is the cutoff. `down` deletes the recorded ids of every batch its cards had, and `handouts --only N --revoke` deletes those of card N's earlier batches. Each id is deleted only while Duo still lists it under the persona it was recorded for, so another room's codes and the codes a persona never got from this tool are never touched. A code that was used up, expired or deleted already counts as gone. A delete Duo refuses fails that card, keeps its ids, and a re-run of `down` finishes it. A batch whose codes `down` deleted is marked revoked in the record: the card still shows those codes, but `check`, `status` and `up` treat it as having none, so a later `up` (after `down --only N`, say) issues the card a fresh batch and names it for printing. A participant record that cannot be read (not JSON, not a JSON object, or unreadable) fails that card's revocation, never the run, and `down`'s last line then names it instead of saying every batch was deleted. `expire` deletes no bypass code. `valid_hours` is capped at 72, so a code whose id is unknown is dead long before `expire` disables a participant at day 7. The last line of `down` says until when any code it could not delete stays valid, and names each card and persona whose code ids are unknown, with when those codes expire. While there are any, it never says every batch was deleted. `handouts --revoke` names them the same way.

**Policy and CII.** The Sign-in policy must allow bypass codes as well as hardware tokens (see "Duo applications"). The trusted personas' CII exclusions include *A Bypass Code Was Used To Successfully Sign In* (plan 4.3), so attendees' sign-ins never fail them. The victim has no exclusion, so its bypass sign-ins add that check to the ones it already fails.

**What this relies on** (the Admin API page, checked read-only on 2026-11-05 and 2026-11-06):

- `POST /admin/v1/users/{id}/bypass_codes` takes `count` (at most 10 per call), `reuse_count` (default 1, and 0 means unlimited), `valid_secs` (default 0, which means the codes never expire) and `preserve_existing` (default false, which clears the user's other codes). It returns the codes as strings, without ids. It needs *Grant resource - Write*, which the Provisioner app has. A user holds at most 100 codes.
- `GET /admin/v1/users/{id}/bypass_codes` returns `bypass_code_id`, `created`, `expiration`, `reuse_count` and `admin_email`, never the code. It is paged (`limit` 100 by default, at most 500), and the client reads every page.
- `DELETE /admin/v1/bypass_codes/{id}` takes no parameters and needs *Grant resource - Write*. It answers 200 when it deleted the code and 404 when there is no such code.
- A user's `status` is `active`, `bypass` (Duo skips secondary authentication), `disabled`, `locked out` or `pending deletion`.
- `GET /admin/v1/users/{id}/groups` lists the user's groups (paged), each with `group_id`, `name` and `status`. A group's `status` is Active, Bypass (its members skip secondary authentication) or Disabled (they cannot authenticate). The table writes these capitalized and the examples in lower case, so the tool compares them case-insensitively.
- In the Universal Prompt, a bypass code is entered through *Other options*, *Bypass Code* (Duo's end-user guide).

## Persona scripts (`scripts/identity/`)

The cast is `scripts/identity/personas.yaml`: 3 trusted personas, the victims (an active victim plus an untouched fallback per concurrent room), and the spike persona, which becomes the dry-run victim. A test pins every name as disjoint from the app's synthetic end users and from the synthetic-PII name pools and records of all 8 themes. Run both scripts with the tool's venv: `~/.pseudoco-lab5/venv/bin/python scripts/identity/<script> ...`.

| Command | What it does |
|---|---|
| `provision_personas.py [--dry-run]` | Creates what is missing: the **PseudoCo Workforce** group, each user (API-created, email on `pseudocoassistant.com`, a persona notes marker), and one HOTP token each. The token's secret goes into the Keychain first, through `security -i` on stdin and never in argv. Its counter starts at 0 in `~/.pseudoco-lab5/personas/hotp/`. When it creates the group, it prints the User access each lab app needs (see "Duo applications"). |
| `provision_personas.py --status` | Read-only: each persona's Duo status, its token, its Keychain secret (present or missing, never the value), its counter and its last baseline success. |
| `provision_personas.py --reset [--only U,...]` | Re-enables and unlocks (`status=active`), then resyncs each HOTP token to the Mac's counter with three codes. Afterwards, clear all step-ups in the Admin Panel and run CII Reset Feedback, which have no API. |
| `provision_personas.py --teardown --yes` | Deletes the cast's users and tokens, their Keychain secrets and their counters. Without `--yes` it only lists what it would delete. It keeps the group, because the User access of PseudoCo VPN and PseudoCo Lab: Sign-in names it. |
| `persona_activity.py baseline` | One successful passcode sign-in per persona from its home address and device, at random points in `baseline.jitter_minutes`, then the self-check. It does nothing while `baseline.enabled` is false. It refuses documentation addresses, so set real ones once spike S1 says how Duo geolocates them. A rejected passcode is never retried. |
| `persona_activity.py takeover --victim U` | A home sign-in, then 5 to 9 wrong passcodes from the next foreign address within MFA Flood's 2 minutes (under the lockout limit of 10), then a success from that address with the attacker's device. It refuses a trusted persona, a victim that preauth does not accept, and a victim taken over in the last 8 days unless you pass `--force`. Its record in `personas/takeovers/` is the takeover time. When to run it depends on the S1 decision. |
| `persona_activity.py replay --victim U` | A short push flood, 5 pushes by default and never more than 9, to the one victim with `replay_device: true` (Duo Mobile on a facilitator phone). The facilitator denies each push. An approved push fails the run. |
| `persona_activity.py selfcheck [--gate]` | For each persona: the last sign-in and its age, the Keychain secret and counter, Duo preauth, and CII trust and failing checks (`getEndUser` on the email). A trusted persona that fails a check or drops below Neutral is a failure. `--gate` is the T-18 gate, where Unknown trust also fails. Any failure raises a macOS notification and exits 1. |

Every sign-in sends `ipaddr` and `hostname` and never `client_supports_verified_push`. Each HOTP code is reserved under a file lock before it is sent, so two runs never use the same counter value. Nothing else may use these codes: HOTP accepts only codes ahead of Duo's counter.

## Daily jobs (launchd)

`deploy/launchd/install-lab5.sh` installs two user agents with this checkout's paths. It never touches the app's own agents.

| Agent | When | Runs |
|---|---|---|
| `com.yeack.pseudoco-assistant-lab5-expire` | daily 08:15 | `deploy/launchd/run-lab5-job.sh expire` → `deploy/lab5/lab5_setup.py expire` |
| `com.yeack.pseudoco-assistant-lab5-baseline` | daily 09:20 | `deploy/launchd/run-lab5-job.sh baseline` → `scripts/identity/persona_activity.py baseline`, then the self-check |

Both run through `run-lab5-job.sh`, with `LAB5_PYTHON` (default `~/.pseudoco-lab5/venv/bin/python`) and no fallback. To reproduce a failed run by hand, run that same command (`deploy/launchd/run-lab5-job.sh expire`), not `deploy/lab5/lab5-setup expire`: `lab5-setup` falls back to `python3` on `PATH` and checks for paramiko, so it can succeed or refuse where the job does not.

Use `--only expire|baseline` to install one, `--uninstall` to remove them and `--print` to see the rendered plists. A run missed while the Mac sleeps happens when it wakes. Nothing runs while the Mac is shut down, so a week away before a delivery shows up as a self-check failure. Logs go to `logs/launchd-lab5-*.log` and to the run logs under `~/.pseudoco-lab5/`. Install from the main checkout, not a worktree.

## Secrets

- SSH passwords are asked once per box per run with `getpass`. Pressing Enter reuses the previous box's password. They are never stored.
- Keychain values reach a box only as file content: `.env` over SFTP, and the tunnel token on the stdin of a `sudo` file write. They never appear in a command line, a URL, the output or the run log.
- Output shows credentials by their last 4 characters only. All output, mirrored to `~/.pseudoco-lab5/workshops/<workshop>/runs/*.log`, passes through a redactor that holds every secret the run read.
- `~/.pseudoco-lab5/workshops/<workshop>/` holds the per-box records (`boxes/<nn>.json`: tunnel and DNS ids, the non-secret baseline, backup paths, and the usernames the box's app may admit, which the victim check across workshops reads) and `known_hosts`. Directories are 0700 and files 0600.
- Host keys are trusted on first use, per workshop. Show reuses IP addresses, so `~/.ssh/known_hosts` is not consulted. A box that later presents a different key is refused.

## Show template (12.6)

A box from the template must pass `lab5-setup check` with **ready, nothing to upgrade**. That means:

- the release tag is at least `required_version`;
- `cloudflared` is installed, with no tunnel and no token;
- every `DUO_*`, `CII_*`, `IDENTITY_*` and `PUBLIC_BASE_URL` key is empty;
- the HEC destination for the room stack is in `medadvice.db`.

An `APP_VERSION` line left in the template's `.env` overrides what `/health` reports. Keep it equal to the tag, or remove it. `check` names it when it explains a version refusal.

## Tests

`tests/test_lab5_participants.py` and `tests/test_identity_personas.py` cover the participant accounts, `expire`, the persona scripts and the launchd templates. They run against an in-memory Duo, CII and Keychain (`tests/lab5_fakes.py`), and pin the following:

- `up` creates the accounts with all three markers and a handout whose passcodes Duo accepts;
- `expire` acts only on fully marked accounts, at day 7 and day 14, and never on a persona, while a participant account that is also in PseudoCo Workforce is still expired; a half-made account (no workshop group) is left alone but fails the run, and `up` adds the workshop group before CII Read-Only;
- the persona tool, the README and the runbook say which groups each lab app admits: Sign-in admits CII Read-Only too, and no text limits every lab app to PseudoCo Workforce;
- `up` puts one batch of persona bypass codes per box on its card: to the cast's victim and trusted personas only, with `reuse_count` 5, `valid_secs` from `valid_hours` and `preserve_existing=true`. Duo accepts the codes up to their uses and until `valid_secs`, while no code reaches the output, a log or the state, and no persona HOTP code is read or printed;
- a re-run keeps a valid batch and reissues one whose `count`, `reuse_count` or `valid_hours` changed, `handouts` issues a fresh one and touches nothing else, and a run that would pass Duo's 100-code limit issues nothing;
- a room persona in bypass status or disabled stops every card's batch in `check`, `up` and `handouts`, and `status` shows each persona's Duo status; a locked-out one gets no reset advice, and its cards get the other personas' codes and are partial, not failed;
- a create without a usable answer (a timeout before or after Duo made the codes, an answer cut off, a 502, 503 or 504, a malformed 200) is never listed again: its persona's ids are unknown for that card, and its row says, in one wording, when any codes it made expire and that the tool cannot revoke them. `down` and `handouts --revoke` delete none of them, nor another room's codes for that persona, nor a late commit's; they say when those codes expire, and `down` never claims every batch was deleted;
- a Duo error or a handout lock timeout fails only its card: `up` still finishes, exits 1 and records a partial batch as incomplete;
- a batch `down` deleted is dead on its card: `status` and `check` say so and `up` issues a fresh one; an unreadable participant record fails its card in `down` and never lets it say every batch was deleted; a card's time is taken after its last create;
- each batch records exactly the ids Duo lists as new around a create that returned its codes, and unknown ids when another room's create makes that ambiguous; `down` and `handouts --revoke` delete exactly the recorded ones, and `expire` deletes none;
- the Sign-in policy is described as bypass code + hardware token everywhere, and nothing asks for a policy with bypass codes alone;
- each secret reaches Duo once, in a POST body, and the Keychain only on stdin;
- the cast is disjoint from the app's synthetic users and synthetic PII;
- the takeover stays within MFA Flood's window and under the lockout limit.

`tests/test_lab5_setup.py` runs every box command against fakes only: in-memory Show boxes, an in-memory Cloudflare API behind the real client, and a fake `security`. It pins the following:

- `up` on a box with Labs 0–4 settings keeps every other `.env` line and every other destination field;
- `check` changes nothing;
- `down` restores the original bytes, and a second `down` is a no-op;
- a `down` that cannot reach or finish a box exits 1, keeps it pending, and a re-run finishes it; a lost SSH session (`SSHException`, `EOFError`) is a box failure like any other;
- `status` runs the victim check on each box and fails a box whose own gate cannot verify the victim;
- `check`, `up` and `handouts` refuse a victim another workshop on this Mac still holds (a reachable box that admits it, or live codes from its cards), mid-swap and with unreadable records too, and say which steps clear it;
- `identity:` values the app could not start with are refused, and an app that does not come back after `up` gets its `.env` rolled back;
- `check` renders its diff on long and repetitive `.env` files, `.env.example` included;
- no secret reaches argv, a URL, the output, the run log or the state directory.

It is registered in `tests/run_all.sh` and runs with the app's venv: it never imports paramiko, and it fails if anything does.
