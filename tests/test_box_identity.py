"""Per-box identity: one deployment.environment + Agent stream per box.

An AI Trust dry run had three boxes reporting into one environment
(``demobot-ec2-1``) and one Agent stream: their ``.env`` came from the same
source and nothing tied it to the instance. deploy/box_identity.py assigns one
name to both and stamps the EC2 instance id; ``ensure`` (run.sh,
run-collector.sh) renames a box whose ``.env`` was stamped on another instance.

Stdlib only, no network (the instance id is injected), so it runs anywhere:
    venv/bin/python tests/test_box_identity.py
"""
from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "box_identity.py"
_spec = importlib.util.spec_from_file_location("box_identity", SCRIPT)
bi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bi)

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


CLONED_ENV = [
    "AI_PROVIDER=ollama\n",
    "OTEL_RESOURCE_ATTRIBUTES=deployment.environment=demobot-ec2-1,host.team=lab\n",
    "SPLUNK_AO_PROJECT=PseudoCo Assistant\n",
    "SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant\n",
    "# SPLUNK_AO_AGENT_STREAM=commented out stays commented\n",
]


def test_assign() -> None:
    print("== assign: one name, both places, stamped ==")
    out = bi.assign(list(CLONED_ENV), "pseudoco-assistant-lab-2", "i-0abc")
    check("deployment.environment set", bi.environment_of(out) == "pseudoco-assistant-lab-2")
    check("sibling resource attributes kept",
          bi.get_value(out, "OTEL_RESOURCE_ATTRIBUTES")
          == "deployment.environment=pseudoco-assistant-lab-2,host.team=lab")
    check("Agent stream = the same name", bi.get_value(out, "SPLUNK_AO_AGENT_STREAM") == "pseudoco-assistant-lab-2")
    check("per-theme streams pinned off (every turn lands in the box's stream)",
          bi.get_value(out, "SPLUNK_AO_AGENT_STREAM_PER_THEME") == "False")
    check("stamped with the instance id", bi.get_value(out, "PSEUDOCO_ASSISTANT_BOX_ID") == "i-0abc")
    check("project untouched", bi.get_value(out, "SPLUNK_AO_PROJECT") == "PseudoCo Assistant")
    check("comments untouched", "# SPLUNK_AO_AGENT_STREAM=commented out stays commented\n" in out)
    check("no duplicate live keys",
          sum(1 for line in out if line.startswith("SPLUNK_AO_AGENT_STREAM=")) == 1)
    fresh = bi.assign(["AI_PROVIDER=ollama"], "lab-3", None)
    check("missing keys are appended (no trailing-newline glue)",
          fresh[0] == "AI_PROVIDER=ollama\n" and bi.environment_of(fresh) == "lab-3")
    check("no box id -> no stamp", bi.get_value(fresh, "PSEUDOCO_ASSISTANT_BOX_ID") is None)
    for bad in ("", "has space", "a,b", "a=b", "-lead", "x" * 64):
        try:
            bi.assign(list(CLONED_ENV), bad, "i-0abc")
            ok = False
        except ValueError:
            ok = True
        check(f"rejects unusable name {bad[:12]!r}", ok)


def test_ensure() -> None:
    print("== ensure: start-time clone detection ==")
    lines, what = bi.ensure(list(CLONED_ENV), None)
    check("off EC2: nothing changes", lines == CLONED_ENV and what.startswith("skip"))

    adopted, what = bi.ensure(list(CLONED_ENV), "i-0aaa")
    check("unstamped: adopts the current name (no rename of a working box)",
          bi.environment_of(adopted) == "demobot-ec2-1"
          and bi.get_value(adopted, "PSEUDOCO_ASSISTANT_BOX_ID") == "i-0aaa", what)

    same, what = bi.ensure(list(adopted), "i-0aaa")
    check("stamped for this box: nothing changes", same == adopted and what.startswith("ok"))

    clone, what = bi.ensure(list(adopted), "i-0bbb")
    check("stamped for ANOTHER box: derives this box's own name",
          bi.environment_of(clone) == "pseudoco-assistant-ec2-0bbb", what)
    check("clone: Agent stream follows the new name",
          bi.get_value(clone, "SPLUNK_AO_AGENT_STREAM") == "pseudoco-assistant-ec2-0bbb")
    check("clone: re-stamped for this box", bi.get_value(clone, "PSEUDOCO_ASSISTANT_BOX_ID") == "i-0bbb")
    check("clone message names both instances", "i-0aaa" in what and "i-0bbb" in what, what)

    clone2, _ = bi.ensure(list(adopted), "i-0ccc")
    check("two clones of one box end up with different names",
          bi.environment_of(clone) != bi.environment_of(clone2))
    check("derived name matches ec2-bootstrap.sh's fallback",
          bi.name_for_instance("i-0123456789abcdef0") == "pseudoco-assistant-ec2-0123456789abcdef0")


def test_cli() -> None:
    print("== CLI: assign / ensure / show on a real file ==")
    with tempfile.TemporaryDirectory() as tmp:
        env = Path(tmp) / ".env"
        env.write_text("".join(CLONED_ENV))
        os.chmod(env, 0o600)
        run = lambda *a: subprocess.run([sys.executable, str(SCRIPT), *a, "--env-file", str(env)],  # noqa: E731
                                        capture_output=True, text=True)
        r = run("assign", "--name", "lab-1", "--box-id", "i-0aaa")
        check("assign exits 0", r.returncode == 0, r.stderr)
        check("assign wrote the file", "deployment.environment=lab-1" in env.read_text())
        check(".env keeps its 0600 mode (it holds every secret)", stat.S_IMODE(env.stat().st_mode) == 0o600)
        r = run("ensure", "--box-id", "i-0bbb")
        check("ensure exits 0 and renames a clone",
              r.returncode == 0 and "SPLUNK_AO_AGENT_STREAM=pseudoco-assistant-ec2-0bbb" in env.read_text(),
              r.stdout + r.stderr)
        r = run("assign", "--name", "bad name", "--box-id", "i-0bbb")
        check("assign refuses a bad name with a non-zero exit", r.returncode != 0)
        r = run("show", "--box-id", "i-0zzz")
        check("show reports a cloned .env", "cloned" in r.stdout, r.stdout)
        missing = subprocess.run([sys.executable, str(SCRIPT), "ensure", "--env-file", str(Path(tmp) / "nope")],
                                 capture_output=True, text=True)
        check("ensure never fails a start (missing .env -> exit 0)", missing.returncode == 0)


def test_wiring() -> None:
    print("== wiring: launchers + bootstrap ==")
    for launcher in ("run.sh", "run-collector.sh"):
        text = (ROOT / launcher).read_text()
        hook = text.find("deploy/box_identity.py ensure")
        first_read = text.find("grep '^") if launcher == "run-collector.sh" else text.find('grep "^AI_PROVIDER')
        check(f"{launcher} runs ensure", hook != -1)
        check(f"{launcher} runs ensure before it first reads .env", -1 < hook < first_read)
    boot = (ROOT / "deploy" / "ec2" / "ec2-bootstrap.sh").read_text()
    a = boot.find("box_identity.py\" assign --name \"$ENV_NAME\"")
    o = boot.find('python3 - "$REPO/.env" "$ENV_NAME" "$OVERRIDES"')
    check("bootstrap assigns the box name", a != -1)
    check("bootstrap assigns BEFORE the override pass (so --set still wins)", -1 < a < o)


def main() -> int:
    for fn in (test_assign, test_ensure, test_cli, test_wiring):
        fn()
    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
        return 1
    print("All box-identity checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
