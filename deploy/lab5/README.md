# lab5-setup: Show boxes in, Lab 5 out

`lab5-setup` turns the Splunk Show boxes of one workshop into Lab 5 ("Verify: Cisco Identity Intelligence") instances, and puts them back afterwards. It runs on the facilitator's Mac. The design is section 12.3 of `docs/identity-intelligence-lab-plan.md`; section 12.1 lists the keys it writes.

There is no broker and no AWS. Secrets come from the Mac's Keychain. What `up` created is recorded under `~/.pseudoco-lab5/`. Everything else lives on the boxes, in Duo and in Cloudflare.

## Commands

```
deploy/lab5/lab5-setup check  workshop.yaml   # read-only: what up would change
deploy/lab5/lab5-setup up     workshop.yaml   # make every box a Lab 5 instance
deploy/lab5/lab5-setup status workshop.yaml   # per-box preflight + Cloudflare state
deploy/lab5/lab5-setup down   workshop.yaml   # delete tunnels + DNS, revert the keys
```

`--only 1,3` limits a run to some instance numbers. `--restart` makes `up` or `down` restart the app even when `.env` did not change.

| Command | What it does |
|---|---|
| `check` | Connects to each box and reads its version, `.env` and HEC destinations. Prints the exact `.env` diff, the HEC host change, the tunnel and DNS plan, and a verdict per box. A box that `up` would accept says **ready, nothing to upgrade**. It changes nothing on the boxes or in Cloudflare. |
| `up` | Runs each box in parallel, in this order: version check, backup, Lab 5 `.env` keys, tunnel and DNS, HEC host, restart, preflight. Any refusal happens before the first change. |
| `status` | Checks each box's tunnel health, DNS record, connector unit and `.env` drift, then runs the preflight. It also lists `l5-<workshop>-*` tunnels and DNS records that no box record owns. |
| `down` | Removes the connector, reverts the Lab 5 keys and the HEC host on every reachable box, then deletes the DNS records and tunnels that `up` recorded. A box it cannot reach or cannot finish fails the run, and the last line says how to re-run it. Running it twice is safe: the second run changes nothing. |
| `expire` | Not built yet. It comes with the participant accounts (12.2). |

Exit codes: `0` means every box is fine. `1` means at least one box failed or was refused; its report says why. `2` means a usage, configuration or Keychain error.

## One-time setup on the Mac

1. Install the tool's two dependencies (paramiko and PyYAML) into their own venv. The wrapper finds that venv by itself. Keep them out of the app's venv: paramiko pulls in `cryptography`, and `tests/test_attachments.py` relies on the app's venv lacking it.

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

The names are defaults. A workshop file can rename any of them under `keychain:`.

## The workshop file

Copy `deploy/lab5/workshop.example.yaml`, one per delivery. It holds no secrets: only names, addresses and Keychain item names.

- `workshop` names the delivery. Box *nn* becomes tunnel `l5-<workshop>-<nn>` and host `l5-<workshop>-<nn>.pseudocoassistant.com`. Use a new name each time, because the tool refuses to take over a tunnel or record it did not create.
- `stack.hec_url` is the room's Splunk stack. `up` looks for the box's existing destination with that URL.
- `room.victim` goes on every box's `IDENTITY_ALLOWED_USERS`, together with the trusted personas. To swap to `room.fallback`, change `victim` and re-run `up`.
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

Participant accounts and the handout sheet are the next stage (12.2). `up` already has the hook for them, and `IDENTITY_ALLOWED_USERS` will gain each box's participant account then.

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

Participant accounts stay until `expire` disables them (next stage). Rotate the Duo and CII credentials after the workshop (I1).

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

`tests/test_lab5_setup.py` runs every command against fakes only: in-memory Show boxes, an in-memory Cloudflare API behind the real client, and a fake `security`. It pins the following:

- `up` on a box with Labs 0–4 settings keeps every other `.env` line and every other destination field;
- `check` changes nothing;
- `down` restores the original bytes, and a second `down` is a no-op;
- a `down` that cannot reach or finish a box exits 1, keeps it pending, and a re-run finishes it;
- `identity:` values the app could not start with are refused, and an app that does not come back after `up` gets its `.env` rolled back;
- `check` renders its diff on long and repetitive `.env` files, `.env.example` included;
- no secret reaches argv, a URL, the output, the run log or the state directory.

It is registered in `tests/run_all.sh` and runs with the app's venv: it never imports paramiko, and it fails if anything does.
