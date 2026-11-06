#!/bin/bash
# Install the Lab 5 facilitator jobs as launchd user agents, with every path
# filled in for THIS checkout (same template scheme as install.sh). Idempotent.
# It never touches the app, collector or tunnel agents: install.sh owns those.
#
#   ./deploy/launchd/install-lab5.sh                  # both jobs
#   ./deploy/launchd/install-lab5.sh --only expire    # daily `lab5-setup expire` (08:15)
#   ./deploy/launchd/install-lab5.sh --only baseline  # daily persona baseline + self-check (09:20)
#   ./deploy/launchd/install-lab5.sh --uninstall      # bootout + remove both
#   ./deploy/launchd/install-lab5.sh --print          # show the rendered plists, install nothing
#
# Both run with the Lab 5 tool venv (LAB5_PYTHON, default
# ~/.pseudoco-lab5/venv/bin/python; see deploy/lab5/README.md) and read their
# Duo keys from the login Keychain. The baseline does nothing until
# scripts/identity/personas.yaml has baseline.enabled: true (after spikes S1,
# S2 and S7), so installing it early is harmless.
set -euo pipefail

ONLY=""
UNINSTALL=false
PRINT=false
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=true; shift ;;
    --print) PRINT=true; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done
case "$ONLY" in
  "") jobs=(expire baseline) ;;
  expire|baseline) jobs=("$ONLY") ;;
  *) echo "--only takes expire or baseline" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$HOME/Library/LaunchAgents"
UID_N="$(id -u)"
LAB5_PYTHON="${LAB5_PYTHON:-$HOME/.pseudoco-lab5/venv/bin/python}"

render() {
  sed -e "s|__PSEUDOCO_ASSISTANT_DIR__|$REPO|g" \
      -e "s|__HOME__|$HOME|g" \
      -e "s|__LAB5_PYTHON__|$LAB5_PYTHON|g" \
      "$REPO/deploy/launchd/com.yeack.pseudoco-assistant-lab5-$1.plist"
}

if [ "$PRINT" = true ]; then
  for job in "${jobs[@]}"; do render "$job"; done
  exit 0
fi

if [ "$UNINSTALL" = true ]; then
  for job in "${jobs[@]}"; do
    label="com.yeack.pseudoco-assistant-lab5-$job"
    launchctl bootout "gui/$UID_N/$label" 2>/dev/null || true
    rm -f "$DEST/$label.plist"
    echo "  removed  $label"
  done
  exit 0
fi

case "$REPO" in
  */.claude/worktrees/*)
    echo "warning: $REPO is a worktree; the agents would run its copy of the scripts and break when it is" >&2
    echo "         removed. Install from the main checkout once the branch is merged." >&2 ;;
esac
if ! "$LAB5_PYTHON" -c "import duo_client, yaml" >/dev/null 2>&1; then
  echo "error: $LAB5_PYTHON lacks the Lab 5 tool's dependencies. One-time setup:" >&2
  echo "  python3 -m venv ~/.pseudoco-lab5/venv && ~/.pseudoco-lab5/venv/bin/pip install -r $REPO/deploy/lab5/requirements.txt" >&2
  exit 2
fi
mkdir -p "$DEST" "$REPO/logs"

for job in "${jobs[@]}"; do
  label="com.yeack.pseudoco-assistant-lab5-$job"
  dst="$DEST/$label.plist"
  render "$job" > "$dst"
  plutil -lint "$dst" >/dev/null
  # bootout is asynchronous: retry bootstrap briefly, as install.sh does.
  launchctl bootout "gui/$UID_N/$label" 2>/dev/null || true
  ok=""
  for _ in 1 2 3 4 5 6 7 8; do
    if launchctl bootstrap "gui/$UID_N" "$dst" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  if [ -n "$ok" ]; then
    echo "  installed + bootstrapped  $label"
  else
    echo "  FAILED to bootstrap $label (try: launchctl bootstrap gui/$UID_N $dst)" >&2
  fi
done

echo
echo "Run one now:   launchctl kickstart gui/$UID_N/com.yeack.pseudoco-assistant-lab5-${jobs[0]}"
echo "Logs:          $REPO/logs/launchd-lab5-*.log, and ~/.pseudoco-lab5/ (runs/, personas/runs/)"
echo "They run daily at login-session time only: a sleeping Mac catches up when it wakes; a shut-down Mac does not."
