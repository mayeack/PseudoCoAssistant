#!/bin/bash
# The Lab 5 launchd jobs' entry point (com.yeack.pseudoco-assistant-lab5-*.plist,
# installed by install-lab5.sh):
#
#   run-lab5-job.sh expire     deploy/lab5/lab5_setup.py expire
#   run-lab5-job.sh baseline   scripts/identity/persona_activity.py baseline
#
# Each job raises its own macOS notification when a run fails or crashes. This
# wrapper raises one when the job cannot start at all, which nothing in Python
# can report: LAB5_PYTHON missing, or its venv broken or lacking duo_client /
# PyYAML (a Homebrew Python upgrade or cleanup breaks a venv). It then exits 2,
# and logs/launchd-lab5-<job>.log says why. LAB5_PYTHON defaults to the tool's
# venv, ~/.pseudoco-lab5/venv/bin/python.
set -uo pipefail
job="${1:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
case "$job" in
  expire)   script="$repo/deploy/lab5/lab5_setup.py" ;;
  baseline) script="$repo/scripts/identity/persona_activity.py" ;;
  *) echo "usage: $0 expire|baseline" >&2; exit 2 ;;
esac
py="${LAB5_PYTHON:-$HOME/.pseudoco-lab5/venv/bin/python}"

notify() {
  # Best effort, like lab5_common.desktop_notify: never fails the job, and the
  # text is a fixed summary that carries no secret.
  command -v osascript >/dev/null 2>&1 || return 0
  osascript -e "display notification \"$1\" with title \"Lab 5 $job\"" >/dev/null 2>&1 || true
}

if [ ! -x "$py" ] || ! "$py" -c "import duo_client, yaml" >/dev/null 2>&1; then
  echo "run-lab5-job: $job did not run: $py is missing or lacks duo_client/PyYAML. One-time setup:" >&2
  echo "  python3 -m venv ~/.pseudoco-lab5/venv && ~/.pseudoco-lab5/venv/bin/pip install -r $repo/deploy/lab5/requirements.txt" >&2
  notify "did not run: the Lab 5 venv is missing or broken; see logs/launchd-lab5-$job.log"
  exit 2
fi
exec "$py" "$script" "$job"
