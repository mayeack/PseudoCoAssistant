# launchd service definitions (macOS)

Per-user **LaunchAgents** that keep the PseudoCo Assistant stack running across logout-free
reboots and sleep/wake, with auto-restart on crash (`KeepAlive`). These are copies
of what gets installed under `~/Library/LaunchAgents/`.

| Plist | Runs | Listens / serves |
|-------|------|------------------|
| `com.yeack.medadvice-collector.plist` | `run-collector.sh` (OTel collector) | OTLP `:4317`/`:4318` → Splunk O11y + Agent Observability |
| `com.yeack.medadvice-app.plist` | `run.sh` (FastAPI app) | `0.0.0.0:8001` |
| `com.yeack.medadvice-tunnel.plist` | `cloudflared tunnel run medadvice` | public `https://medadvice.yeackbot.com` |
| `com.yeack.ollama-env.plist` | `launchctl setenv OLLAMA_*` (one-shot) | sets `OLLAMA_KEEP_ALIVE=30m` + `OLLAMA_MAX_LOADED_MODELS=2` for the GUI session |

> `com.yeack.ollama-env.plist` is a **one-shot** (`KeepAlive=false`) — it exits after
> setting the vars, so `launchctl print` shows it "exited". That is expected. Install it
> (and set the vars for the current session) with `../../setup-ollama-env.sh`, then restart
> Ollama.app once so the menu-bar daemon inherits them. These vars are read by `ollama
> serve`, not by the app.

> The plists in this directory are **templates**: they contain `__PSEUDOCO_ASSISTANT_DIR__`,
> `__HOME__`, and `__CLOUDFLARED__` placeholders instead of hardcoded absolute
> paths, so they work regardless of where you cloned the repo. `install.sh` fills
> in the real values for your checkout. launchd bakes absolute paths into the
> installed copies, so **re-run `install.sh` after moving or renaming the repo**
> (the same is true of `venv/` — see the root README's "moved/renamed the folder"
> note). The tunnel credentials live in `~/.cloudflared/` and are **not** in this repo.

## Install / load

```bash
./deploy/launchd/install.sh
```

This substitutes the placeholders for your checkout's real paths, writes the
plists to `~/Library/LaunchAgents/`, and bootstraps them. It installs the
**collector** and **app** agents; it adds the **tunnel** agent only if you've
already set up a named tunnel (`~/.cloudflared/config.yml` exists, via
`../../setup-named-tunnel.sh`). Re-run it any time to reinstall/refresh.

## Status / restart / uninstall

```bash
UID_N=$(id -u)
launchctl print    gui/$UID_N/com.yeack.medadvice-app        # status + pid
launchctl kickstart -k gui/$UID_N/com.yeack.medadvice-tunnel # restart (e.g. after upgrading cloudflared)
launchctl bootout  gui/$UID_N/com.yeack.medadvice-collector  # stop + unload
```

Logs: `logs/launchd-app.log`, `logs/launchd-collector.log` (in-repo, gitignored),
and `~/.cloudflared/medadvice-tunnel.log`.

## Lab 5 facilitator jobs (separate installer)

Two daily one-shot agents for the Lab 5 facilitator's Mac. `install.sh` never installs them, and `install-lab5.sh` never touches the app's agents:

| Plist | Runs | When |
|-------|------|------|
| `com.yeack.pseudoco-assistant-lab5-expire.plist` | `deploy/lab5/lab5-setup expire`: participant accounts disabled at day 7, deleted at day 14 | daily 08:15 |
| `com.yeack.pseudoco-assistant-lab5-baseline.plist` | `scripts/identity/persona_activity.py baseline`, then the persona self-check (macOS notification on a problem) | daily 09:20 |

```bash
./deploy/launchd/install-lab5.sh                 # both (needs the Lab 5 tool venv, deploy/lab5/README.md)
./deploy/launchd/install-lab5.sh --only expire   # or --only baseline
./deploy/launchd/install-lab5.sh --print         # show the rendered plists, install nothing
./deploy/launchd/install-lab5.sh --uninstall
```

They use the same placeholders, plus `__LAB5_PYTHON__` (default `~/.pseudoco-lab5/venv/bin/python`). Both run only `StartCalendarInterval`: a run missed while the Mac sleeps happens on wake, and nothing runs while it is shut down. The baseline does nothing until `scripts/identity/personas.yaml` has `baseline.enabled: true`. Logs: `logs/launchd-lab5-*.log` and the run logs under `~/.pseudoco-lab5/`.

> Scope: a LaunchAgent runs only while the user is logged in — correct for a laptop
> demo. For boot-before-login startup, install the tunnel as a system LaunchDaemon
> with `sudo cloudflared service install` instead.
