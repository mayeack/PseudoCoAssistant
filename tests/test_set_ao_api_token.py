"""scripts/set_ao_api_token.py writes the sessions API token into .env safely.

Offline: a fake Agent Observability API on 127.0.0.1 answers the live check,
the .env and the settings store are temp files. Pins that the token is never
printed, nothing is written unless every check passes (including the SDK's own
project lookup, so another org's token is refused), redirects are refused
without forwarding the token, the write touches only SPLUNK_AO_O11Y_API_TOKEN,
keeps edits made while the prompt was open, and keeps the file's mode.

Run:  venv/bin/python tests/test_set_ao_api_token.py   (stdlib only)
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "set_ao_api_token.py"

GOOD = "GoodTokenAbCdEfGh1234"
NO_ROLE = "PlainApiTokenNoRole99"
INGEST = "IngestTokenXyZ0987654"
SAVED = "SavedControlTok555777"
OTHER_ORG = "OtherOrgToken00000001"
REDIRECT = "RedirectingToken00002"
HTML = "HtmlSigninPageToken03"
PROJECT = "PseudoCo Assistant"

_failures: list[str] = []
_seen_on_redirect_target: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


class FakeAO(BaseHTTPRequestHandler):
    """GET /ao/api/projects?project_name=&type=gen_ai, like the splunk-ao SDK."""

    def _send(self, code, body=b"", ctype="application/json", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        tok = self.headers.get("X-SF-Token")
        if url.path == "/elsewhere":
            _seen_on_redirect_target.append(tok or "")
            return self._send(200, b"[]")
        q = urllib.parse.parse_qs(url.query)
        if url.path != "/ao/api/projects" or q.get("type") != ["gen_ai"]:
            return self._send(404)
        if tok == REDIRECT:
            return self._send(302, headers=[("Location", f"http://127.0.0.1:{self.server.server_address[1]}/elsewhere")])
        if tok == HTML:
            return self._send(200, b"<html>Sign in</html>", "text/html")
        if tok == NO_ROLE:
            return self._send(403, b'{"error_code": 8508}')
        if tok == OTHER_ORG:
            return self._send(200, b"[]")
        if tok in (GOOD, SAVED):
            names = q.get("project_name", [])
            return self._send(200, json.dumps([{"name": n, "type": "gen_ai"} for n in names
                                               if n == PROJECT]).encode())
        return self._send(401)

    def log_message(self, *a):
        pass


ENV = (
    "AI_PROVIDER=ollama\n"
    "O11Y_INGEST=" + INGEST + "\n"
    "SPLUNK_AO_REALM=us1\n"
    "SPLUNK_AO_O11Y_TOKEN=" + INGEST + "\n"
    "SPLUNK_AO_PROJECT=" + PROJECT + "\n"
    "SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant\n"
    "# SPLUNK_AO_O11Y_API_TOKEN=commented example stays\n"
    "ACCESS_KEY=keep-me\n"
)


def load_module():
    spec = importlib.util.spec_from_file_location("set_ao_api_token", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    srv = HTTPServer(("127.0.0.1", 0), FakeAO)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    api = f"http://127.0.0.1:{srv.server_address[1]}/ao/api"

    with tempfile.TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        env = tmpd / ".env"

        def reset(text=ENV, mode=0o600):
            if env.is_symlink():
                env.unlink()
            env.write_text(text)
            os.chmod(env, mode)
            for b in tmpd.glob(".env.bak.*"):
                b.unlink()

        def run(args, stdin="", env_file=env):
            return subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env_file),
                                   "--api-base", api, *args],
                                  input=stdin, capture_output=True, text=True)

        def backups():
            return list(tmpd.glob(".env.bak.*"))

        def live(text):
            return [ln for ln in text.splitlines() if "SPLUNK_AO_O11Y_API_TOKEN=" in ln
                    and not ln.lstrip().startswith("#")]

        print("== happy path ==")
        reset()
        r = run(["--stdin"], stdin=GOOD + "\n")
        text = env.read_text()
        check("exit 0", r.returncode == 0, r.stderr)
        check("token written once", text.count(f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\n") == 1)
        check("placed with the other SPLUNK_AO_* keys",
              text.index("SPLUNK_AO_AGENT_STREAM=") < text.index(f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}")
              < text.index("# SPLUNK_AO_O11Y_API_TOKEN="))
        check("every other line byte-identical", text.replace(f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\n", "") == ENV)
        check("token never printed", GOOD not in r.stdout + r.stderr, r.stdout)
        check("prints only a fingerprint", "ending …1234" in r.stdout, r.stdout)
        check("the SDK's project lookup found the project", f"project '{PROJECT}' found" in r.stdout, r.stdout)
        check(".env keeps mode 0600", stat.S_IMODE(env.stat().st_mode) == 0o600)
        b = backups()
        check("one backup, mode 0600, holds the old .env",
              len(b) == 1 and stat.S_IMODE(b[0].stat().st_mode) == 0o600 and b[0].read_text() == ENV)
        check("no temp file left behind", not [p for p in tmpd.iterdir() if ".tmp." in p.name])
        check("prints the restart command", "restart" in r.stdout)
        r = run(["--stdin"], stdin=GOOD)
        check("same token again: nothing to write, no new backup",
              "nothing to write" in r.stdout and len(backups()) == 1, r.stdout)

        print("== the 'already holds' check reads .env like run.sh ==")
        for label, extra in (
            ("duplicate lines (one stale)", f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\nSPLUNK_AO_O11Y_API_TOKEN=stale\n"),
            ("two identical lines", f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\nSPLUNK_AO_O11Y_API_TOKEN={GOOD}\n"),
            ("a CRLF line", f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\r\n"),
            ("a quoted value", f'SPLUNK_AO_O11Y_API_TOKEN="{GOOD}"\n'),
            ("an export line", f"export SPLUNK_AO_O11Y_API_TOKEN=old\n"),
        ):
            reset(ENV + extra)
            r = run(["--stdin"], stdin=GOOD)
            check(f"{label}: rewritten to exactly one bare line",
                  r.returncode == 0 and live(env.read_text()) == [f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}"],
                  repr(live(env.read_text())) + r.stderr)

        print("== refusals write nothing ==")
        for label, stdin, args, want in (
            ("403 (no Agent Observability role)", NO_ROLE, ["--stdin"], "403"),
            ("401 (unknown token)", "UnknownToken12345678", ["--stdin"], "401"),
            ("another org's token (project missing)", OTHER_ORG, ["--stdin"], "does not exist in its org"),
            ("a redirect (token not followed)", REDIRECT, ["--stdin"], "HTTP 302"),
            ("a non-JSON 200 (sign-in page)", HTML, ["--stdin"], "non-JSON"),
            ("the ingest token", INGEST, ["--stdin", "--no-verify"], "ingest token"),
            ("empty input", "\n", ["--stdin"], "no token"),
            ("whitespace inside", "abc def ghi jkl mnop", ["--stdin"], "does not look"),
            ("a trailing '=' (run.sh would drop it)", GOOD + "=", ["--stdin"], "does not look"),
            ("too short", "short", ["--stdin"], "does not look"),
            ("piped stdin without --stdin", GOOD, [], "not a terminal"),
        ):
            reset()
            r = run(args, stdin=stdin)
            check(f"{label}: exit 1 with a reason", r.returncode == 1 and want in r.stderr,
                  (r.stdout + r.stderr)[-300:])
            check(f"{label}: .env untouched, no backup", env.read_text() == ENV and not backups())
            s = stdin.strip()
            check(f"{label}: token not echoed", not s or s not in r.stdout + r.stderr)
        check("the redirect target never received the token", REDIRECT not in _seen_on_redirect_target,
              str(_seen_on_redirect_target))

        reset()
        r = run(["--stdin", "--allow-new-project"], stdin=OTHER_ORG)
        check("--allow-new-project accepts a project-less org", r.returncode == 0
              and f"SPLUNK_AO_O11Y_API_TOKEN={OTHER_ORG}\n" in env.read_text(), r.stderr)
        reset(ENV.replace("SPLUNK_AO_REALM=us1\n", "SPLUNK_REALM=eu0\n"))
        r = run(["--stdin"], stdin=GOOD)
        check("no SPLUNK_AO_REALM: refuses (no fallback to SPLUNK_REALM), writes nothing",
              r.returncode == 1 and "SPLUNK_AO_REALM" in r.stderr and GOOD not in env.read_text(), r.stderr)
        reset()
        r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env), "--stdin",
                            "--api-base", "http://127.0.0.1:9/ao/api"], input=GOOD,
                           capture_output=True, text=True)
        check("unreachable API: refuses, writes nothing",
              r.returncode == 1 and env.read_text() == ENV and "could not reach" in r.stderr, r.stderr)
        r = run(["--stdin", "--no-verify"], stdin=f'"{GOOD}"')
        check("--no-verify writes without the check; surrounding quotes stripped",
              r.returncode == 0 and f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\n" in env.read_text(), r.stderr)
        reset()
        r = run(["--stdin", "--dry-run"], stdin=GOOD)
        check("--dry-run checks and writes nothing",
              r.returncode == 0 and "would write" in r.stdout and env.read_text() == ENV and not backups(),
              r.stdout + r.stderr)

        print("== --from-settings ==")
        db = tmpd / "store.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE app_settings (id INTEGER PRIMARY KEY, data TEXT)")
        con.execute("INSERT INTO app_settings (data) VALUES (?)", (json.dumps(
            {"integration_creds": {"agent_observability": {"splunk_ao_control_token": SAVED}}}),))
        con.commit()
        con.close()
        reset(ENV + f"DATABASE_URL=sqlite:///{db}\n")
        r = run(["--from-settings"])
        check("copies the saved control token, verified, unprinted",
              r.returncode == 0 and f"SPLUNK_AO_O11Y_API_TOKEN={SAVED}\n" in env.read_text()
              and SAVED not in r.stdout + r.stderr, r.stdout + r.stderr)
        reset(ENV + f"DATABASE_URL=sqlite:///{tmpd / 'missing.db'}\n")
        r = run(["--from-settings"])
        check("missing settings store: clear refusal", r.returncode == 1 and "not found" in r.stderr, r.stderr)

        print("== symlinked .env ==")
        real = tmpd / "real.env"
        real.write_text(ENV)
        os.chmod(real, 0o600)
        link = tmpd / "link.env"
        link.symlink_to(real)
        r = run(["--stdin"], stdin=GOOD, env_file=link)
        check("the target is updated and the link kept",
              r.returncode == 0 and link.is_symlink() and f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\n" in real.read_text(),
              r.stderr)

        print("== in-process: realm source, stale snapshot ==")
        mod = load_module()
        reset()
        seen = {}

        def fake_verify(token, api_base, project, allow_new_project, env_dir=None):
            seen.update(api_base=api_base, project=project)
            return "accepted (stub)"
        mod.verify = fake_verify
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(GOOD)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = mod.main(["--env-file", str(env), "--stdin"])
        finally:
            sys.stdin = old_stdin
        check("production URL is built from SPLUNK_AO_REALM",
              rc == 0 and seen.get("api_base") == "https://app.us1.observability.splunkcloud.com/ao/api", str(seen))
        check("the project checked is SPLUNK_AO_PROJECT", seen.get("project") == PROJECT, str(seen))

        reset()
        edited = ENV.replace("ACCESS_KEY=keep-me", "ACCESS_KEY=edited-while-waiting")

        def slow_read(args, env_path, lines):
            env_path.write_text(edited)          # a Settings-page save while the prompt is open
            return GOOD
        mod.read_token = slow_read
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = mod.main(["--env-file", str(env)])
        text = env.read_text()
        check("an edit made while waiting is kept (no stale-snapshot write)",
              rc == 0 and "ACCESS_KEY=edited-while-waiting" in text
              and f"SPLUNK_AO_O11Y_API_TOKEN={GOOD}\n" in text, text)

        reset()

        def realm_change(args, env_path, lines):
            env_path.write_text(ENV.replace("SPLUNK_AO_REALM=us1", "SPLUNK_AO_REALM=eu0"))
            return GOOD
        mod.read_token = realm_change
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = mod.main(["--env-file", str(env)])
        check("a realm change while waiting aborts the write",
              rc == 1 and GOOD not in env.read_text())

        print("== misc ==")
        r = run(["--stdin"], stdin=GOOD, env_file=tmpd / "nope.env")
        check("missing .env: refusal, exit 1", r.returncode == 1 and "not found" in r.stderr)
        r = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        check("--help explains the token kind", "agent_observability_admin" in r.stdout)
    srv.shutdown()

    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
        return 1
    print("All set_ao_api_token checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
