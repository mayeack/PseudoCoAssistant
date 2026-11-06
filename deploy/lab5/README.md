# lab5-setup: Show boxes in, Lab 5 out

`lab5-setup` turns the Splunk Show boxes of one workshop into Lab 5 ("Verify: Cisco Identity Intelligence") instances, and puts them back afterwards. It runs on the facilitator's Mac. The design is section 12.3 of `docs/identity-intelligence-lab-plan.md`; section 12.1 lists the keys it writes.

There is no broker and no AWS. Secrets come from the Mac's Keychain. What `up` created is recorded under `~/.pseudoco-lab5/`. Everything else lives on the boxes, in Duo and in Cloudflare.

The same Mac runs the persona scripts (`scripts/identity/`, below) and two daily launchd jobs (`deploy/launchd/install-lab5.sh`). The lab-day runbook is `docs/identity-lab-facilitator.md`.

## Commands

```
deploy/lab5/lab5-setup check  workshop.yaml   # read-only: what up would change
deploy/lab5/lab5-setup up     workshop.yaml   # make every box a Lab 5 instance
deploy/lab5/lab5-setup status workshop.yaml   # per-box preflight + Cloudflare state
deploy/lab5/lab5-setup down   workshop.yaml   # delete tunnels + DNS, revert the keys
deploy/lab5/lab5-setup expire [workshop.yaml] # participant accounts: disable at day 7, delete at day 14
```

`--only 1,3` limits a run to some instance numbers. `--restart` makes `up` or `down` restart the app even when `.env` did not change. `--reissue-passcodes` makes `up` replace each participant's HOTP token and print new passcodes. `--dry-run` makes `expire` list what it would do.

| Command | What it does |
|---|---|
| `check` | Connects to each box and reads its version, `.env` and HEC destinations. Prints the exact `.env` diff, the HEC host change, the tunnel and DNS plan, and a verdict per box. A box that `up` would accept says **ready, nothing to upgrade**. It also says what `up` would do for each participant account. It changes nothing on the boxes, in Cloudflare or in Duo. |
| `up` | Runs each box in parallel, in this order: version check, backup, Lab 5 `.env` keys, tunnel and DNS, HEC host, restart, preflight. Any refusal happens before the first change. Then it creates a participant account for each box that came up and writes the handout. |
| `status` | Checks each box's tunnel health, DNS record, connector unit and `.env` drift, then runs the preflight. It also lists `l5-<workshop>-*` tunnels and DNS records that no box record owns, and each participant account's state and age. |
| `down` | Removes the connector, reverts the Lab 5 keys and the HEC host on every reachable box, then deletes the DNS records and tunnels that `up` recorded. A box it cannot reach or cannot finish fails the run, and the last line says how to re-run it. Running it twice is safe: the second run changes nothing. |
| `expire` | Day 7: disables each participant account. Day 14: deletes it and its HOTP token, which frees the Duo seat. Without a workshop file it covers every workshop, which is how the daily launchd job runs it. It is idempotent and never touches a persona. |

Exit codes: `0` means every box and participant account is fine. `1` means at least one box or account failed or was refused; its report says why. `2` means a usage, configuration or Keychain error, or a Duo prerequisite such as the CII Read-Only group is missing.

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

## The workshop file

Copy `deploy/lab5/workshop.example.yaml`, one per delivery. It holds no secrets: only names, addresses and Keychain item names.

- `workshop` names the delivery. Box *nn* becomes tunnel `l5-<workshop>-<nn>` and host `l5-<workshop>-<nn>.pseudocoassistant.com`. Use a new name each time, because the tool refuses to take over a tunnel or record it did not create.
- `stack.hec_url` is the room's Splunk stack. `up` looks for the box's existing destination with that URL.
- `room.victim` goes on every box's `IDENTITY_ALLOWED_USERS`, together with the trusted personas and that box's participant account. To swap to `room.fallback`, change `victim` and re-run `up`.
- `participants:` is optional. `enabled` (default `true`) creates one participant account per box. `cii_url` is the Identity Intelligence sign-in link printed on the handout. `email_domain` defaults to `zone`. Turn the accounts off for a dry run that should use no Duo seats.
- `personas_file` is the persona cast that `up` and `expire` never touch. It defaults to `scripts/identity/personas.yaml`.
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

After the boxes, `up` creates a **participant account** for each box that came up (see "Participant accounts" below). Step 3 already put that account's username on the box's `IDENTITY_ALLOWED_USERS`, because the name is fixed.

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

Participant accounts stay until `expire` disables them at day 7 and deletes them at day 14. Rotate the Duo and CII credentials after the workshop (I1).

## Participant accounts (plan 12.2)

`up` creates one Duo account per box that came up, with the Admin API app PseudoCo Provisioner:

- **Username** `l5-<workshop>-<nn>`, **email** `l5-<workshop>-<nn>@pseudocoassistant.com` (the zone, or `participants.email_domain`). Identity Intelligence matches users by email.
- **Notes**: `lab5-setup participant; workshop=<workshop>; instance=<nn>; created=<UTC time>`.
- **Groups**: **CII Read-Only**, which gives Duo SSO into Identity Intelligence as read-only, and **`l5-<workshop>`**, created on the first `up`. `up` refuses to start if Duo has no CII Read-Only group.
- **Its own HOTP token** (type h6, serial = the username), created through the API and attached. `up` computes the token's first 10 passcodes for the handout and then discards the secret, so the passcodes cannot be printed again. `--reissue-passcodes` replaces the token, and the old passcodes stop working.
- The account stays **active** and MFA-required. It never gets bypass status or bypass codes.

An account with the participant's name that `up` did not create (its notes lack the marker, or name another workshop) is left alone, and that box's participant fails the run. A re-run keeps existing accounts and their handout cards, and finishes an account that an earlier run left half made.

**The handout** is `~/.pseudoco-lab5/workshops/<workshop>/handout.html`, a printable card per instance, plus `handout.csv` with the same rows. Both are 0600. A card holds the instance URL, the box's access key, the username, the email, a blank for the temporary password, the 10 passcodes in order and the sign-in steps. It also tells the participant that other read-only users can see their sign-ins and IP address. A card leaves the handout once its account is disabled. Delete the files after the workshop. They are the only place the tool writes a participant's sign-in details.

**The password is a console step.** The Admin API cannot set a Duo Directory password. `up` prints each account's Admin Panel link. Open each one and click **Create temporary password** (valid 30 days), then write it on that participant's card. The token is attached first, because that flow expects an enrolled device. The participant signs in with the temporary password and a passcode, then sets their own password. `status` shows who has done so (`has_password`).

**`status`** prints one row per account: its Duo status, whether its token is attached and whether it has a password, plus its age and the dates it is disabled and deleted. A missing or locked-out account fails the run. For a locked-out account, unlock it in the Admin Panel and turn on lockout auto-revert.

**`expire`** lists every Duo user whose name starts with `l5-` and acts only when all three markers match: the `l5-<workshop>-<nn>` username, the notes marker naming that same workshop and instance, and membership of `l5-<workshop>`. It never acts on a user in the persona group, on a user whose notes carry the persona marker, or on a username in `scripts/identity/personas.yaml`. Age is counted from Duo's own `created` time, or from the notes if that is missing.

- At day 7 it sets `status=disabled`. That denies sign-in and invalidates remembered devices, though an open CII tab may last until CII's idle timeout.
- At day 14 it deletes the account's HOTP token, then the account. Deleting through the API is immediate and permanent and skips Duo's Trash. That is why it needs all three markers, and why `--dry-run` exists. If the token cannot be deleted, the account is kept for the next run.
- Everything else, such as a user without the markers, is listed as left alone.
- It writes a run log to `~/.pseudoco-lab5/runs/`. A failed run raises a macOS notification and exits 1.

**Seats.** Disabled users still hold a Duo seat. Only deletion frees one. You need seats for your own account, the persona cast and every participant account from the last 14 days. Each seat also covers up to 5 CII identities.

**What this relies on.** These facts come from the research in plan section 12.4 (Duo Admin API docs of 2026-11-04 and CII docs, checked 2026-11-05). This stage also checked the Admin and Auth API pages read-only.

- `POST /admin/v1/users` takes `username`, `email`, `realname`, `notes` and `status`.
- The user object carries `created`, `groups`, `tokens` and `has_password`. `has_password` is true when the user has a Duo Directory password.
- `POST /admin/v1/users/{id}/groups` takes `group_id`. `POST /admin/v1/groups` returns error 40003 when the name is already taken.
- `POST /admin/v1/tokens` takes `type=h6`, `serial` (up to 128 characters), `secret` and `counter`. The page does not say how the secret is encoded. The tools send hex, and spike S7 settles it (personas.yaml `hotp.secret_encoding`).
- `DELETE /admin/v1/tokens/{id}` returns 200 whether or not the token existed. `DELETE /admin/v1/users/{id}` is immediate and permanent, and the page does not say that it removes the user's tokens. That is why `expire` deletes the token first.
- Spike S15 (group membership grants CII Read-Only; a password plus an HOTP passcode reaches CII; what disabling does to a live CII session) has not run yet.

## Persona scripts (`scripts/identity/`)

The cast is `scripts/identity/personas.yaml`: 3 trusted personas, the victims (an active victim plus an untouched fallback per concurrent room), and the spike persona, which becomes the dry-run victim. A test pins every name as disjoint from the app's synthetic end users and from the synthetic-PII name pools and records of all 8 themes. Run both scripts with the tool's venv: `~/.pseudoco-lab5/venv/bin/python scripts/identity/<script> ...`.

| Command | What it does |
|---|---|
| `provision_personas.py [--dry-run]` | Creates what is missing: the **PseudoCo Workforce** group, each user (API-created, email on `pseudocoassistant.com`, a persona notes marker), and one HOTP token each. The token's secret goes into the Keychain first, through `security -i` on stdin and never in argv. Its counter starts at 0 in `~/.pseudoco-lab5/personas/hotp/`. |
| `provision_personas.py --status` | Read-only: each persona's Duo status, its token, its Keychain secret (present or missing, never the value), its counter and its last baseline success. |
| `provision_personas.py --reset [--only U,...]` | Re-enables and unlocks (`status=active`), then resyncs each HOTP token to the Mac's counter with three codes. Afterwards, clear all step-ups in the Admin Panel and run CII Reset Feedback, which have no API. |
| `provision_personas.py --teardown --yes` | Deletes the cast's users and tokens, their Keychain secrets and their counters. Without `--yes` it only lists what it would delete. It keeps the group, because every lab app is limited to it. |
| `persona_activity.py baseline` | One successful passcode sign-in per persona from its home address and device, at random points in `baseline.jitter_minutes`, then the self-check. It does nothing while `baseline.enabled` is false. It refuses documentation addresses, so set real ones once spike S1 says how Duo geolocates them. A rejected passcode is never retried. |
| `persona_activity.py takeover --victim U` | A home sign-in, then 5 to 9 wrong passcodes from the next foreign address within MFA Flood's 2 minutes (under the lockout limit of 10), then a success from that address with the attacker's device. It refuses a trusted persona, a victim that preauth does not accept, and a victim taken over in the last 8 days unless you pass `--force`. Its record in `personas/takeovers/` is the takeover time. When to run it depends on the S1 decision. |
| `persona_activity.py replay --victim U` | A short push flood, 5 pushes by default and never more than 9, to the one victim with `replay_device: true` (Duo Mobile on a facilitator phone). The facilitator denies each push. An approved push fails the run. |
| `persona_activity.py selfcheck [--gate]` | For each persona: the last sign-in and its age, the Keychain secret and counter, Duo preauth, and CII trust and failing checks (`getEndUser` on the email). A trusted persona that fails a check or drops below Neutral is a failure. `--gate` is the T-18 gate, where Unknown trust also fails. Any failure raises a macOS notification and exits 1. |

Every sign-in sends `ipaddr` and `hostname` and never `client_supports_verified_push`. Each HOTP code is reserved under a file lock before it is sent, so two runs never use the same counter value. Nothing else may use these codes: HOTP accepts only codes ahead of Duo's counter.

## Daily jobs (launchd)

`deploy/launchd/install-lab5.sh` installs two user agents with this checkout's paths. It never touches the app's own agents.

| Agent | When | Runs |
|---|---|---|
| `com.yeack.pseudoco-assistant-lab5-expire` | daily 08:15 | `deploy/lab5/lab5-setup expire` |
| `com.yeack.pseudoco-assistant-lab5-baseline` | daily 09:20 | `scripts/identity/persona_activity.py baseline`, then the self-check |

Use `--only expire|baseline` to install one, `--uninstall` to remove them and `--print` to see the rendered plists. A run missed while the Mac sleeps happens when it wakes. Nothing runs while the Mac is shut down, so a week away before a delivery shows up as a self-check failure. Logs go to `logs/launchd-lab5-*.log` and to the run logs under `~/.pseudoco-lab5/`. Install from the main checkout, not a worktree.

## Secrets

- SSH passwords are asked once per box per run with `getpass`. Pressing Enter reuses the previous box's password. They are never stored.
- Keychain values reach a box only as file content: `.env` over SFTP, and the tunnel token on the stdin of a `sudo` file write. They never appear in a command line, a URL, the output or the run log.
- Output shows credentials by their last 4 characters only. All output, mirrored to `~/.pseudoco-lab5/workshops/<workshop>/runs/*.log`, passes through a redactor that holds every secret the run read.
- `~/.pseudoco-lab5/workshops/<workshop>/` holds the per-box records (`boxes/<nn>.json`: tunnel and DNS ids, the non-secret baseline, backup paths) and `known_hosts`. Directories are 0700 and files 0600.
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
- `expire` acts only on fully marked accounts, at day 7 and day 14, and never on a persona;
- each secret reaches Duo once, in a POST body, and the Keychain only on stdin;
- the cast is disjoint from the app's synthetic users and synthetic PII;
- the takeover stays within MFA Flood's window and under the lockout limit.

`tests/test_lab5_setup.py` runs every box command against fakes only: in-memory Show boxes, an in-memory Cloudflare API behind the real client, and a fake `security`. It pins the following:

- `up` on a box with Labs 0–4 settings keeps every other `.env` line and every other destination field;
- `check` changes nothing;
- `down` restores the original bytes, and a second `down` is a no-op;
- a `down` that cannot reach or finish a box exits 1, keeps it pending, and a re-run finishes it;
- `identity:` values the app could not start with are refused, and an app that does not come back after `up` gets its `.env` rolled back;
- `check` renders its diff on long and repetitive `.env` files, `.env.example` included;
- no secret reaches argv, a URL, the output, the run log or the state directory.

It is registered in `tests/run_all.sh` and runs with the app's venv: it never imports paramiko, and it fails if anything does.
