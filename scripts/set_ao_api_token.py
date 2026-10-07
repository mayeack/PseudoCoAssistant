#!/usr/bin/env python3
"""Write the Agent Observability sessions API token into .env, safely.

SPLUNK_AO_O11Y_API_TOKEN is the Observability Cloud API token the splunk-ao SDK
uses to group chat turns into Agent Observability sessions (the Session level of
the AO views and evaluators). It must be an API token with the
agent_observability_admin role, from the same org as SPLUNK_AO_O11Y_TOKEN: the
ingest token gets 401 from that API and a plain API token gets 403.

    python3 scripts/set_ao_api_token.py                    # paste it at a hidden prompt
    pbpaste | python3 scripts/set_ao_api_token.py --stdin  # or pipe it in
    python3 scripts/set_ao_api_token.py --from-settings    # reuse the AO control token
                                                           # saved on the Settings page
    python3 scripts/set_ao_api_token.py --dry-run          # check only, write nothing
    python3 scripts/set_ao_api_token.py --restart          # ...and restart the app after

Nothing is written unless every step passes:
  1. read the token from the prompt, --stdin or the Settings store (never argv:
     argv is visible to every user through `ps`);
  2. reject a malformed value and the box's own ingest token;
  3. make the call the SDK makes, against SPLUNK_AO_REALM (the only realm the
     app reads): GET https://app.<realm>.observability.splunkcloud.com/ao/api/projects
     ?project_name=<SPLUNK_AO_PROJECT>&type=gen_ai — 200 with that project means
     the token works in this box's org (401 = not a valid token for the realm,
     403 = no Agent Observability role, an empty list = a different org or a
     project not created yet: --allow-new-project). Redirects are refused and
     the token is never forwarded. Skip with --no-verify;
  4. re-read .env (so an edit made while the prompt was open is kept), back it
     up to .env.bak.ao-api-token.<timestamp> (0600, gitignored);
  5. set SPLUNK_AO_O11Y_API_TOKEN as one live line, everything else
     byte-identical, by an atomic rename that keeps the file's mode and owner.

The token is never printed — only its length and last four characters. The app
reads .env at start, so restart it afterwards (--restart does that).
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import re
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List, Optional

KEY = "SPLUNK_AO_O11Y_API_TOKEN"
INGEST_KEYS = ("SPLUNK_AO_O11Y_TOKEN", "O11Y_INGEST")
DEFAULT_PROJECT = "PseudoCo Assistant"          # backend/agent_observability.py _DEFAULT_PROJECT
ROOT = Path(__file__).resolve().parents[1]
# O11y org tokens are URL-safe base64 without padding. No '=' (run.sh reads .env
# with IFS='=', which drops a trailing one), no whitespace, quotes or '#' (they
# would corrupt the line or be cut short by a dotenv parser).
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{16,512}$")
_REALM_RE = re.compile(r"^[a-z0-9-]{2,32}$")
_MAC_LABEL = "com.yeack.medadvice-app"
_LINUX_UNITS = ("pseudoco-assistant-app", "demobot-app")


class Abort(Exception):
    """A user-facing refusal: printed without a traceback."""


def fingerprint(token: str) -> str:
    return f"{len(token)} chars, ending …{token[-4:]}"


# --------------------------------------------------------------------------- .env
def _key_of(line: str) -> Optional[str]:
    if "=" not in line or line.lstrip().startswith("#"):
        return None
    key = line.split("=", 1)[0].strip()
    return key[len("export "):].strip() if key.startswith("export ") else key


def raw_values(lines: List[str], key: str) -> List[str]:
    """Every live value of KEY, verbatim (text after the first '=', newline only
    removed) — what run.sh's `IFS='=' read` sees, before its own trimming."""
    return [line.split("=", 1)[1].rstrip("\n") for line in lines if _key_of(line) == key]


def get_value(lines: List[str], key: str) -> Optional[str]:
    """The value the app ends up with: the LAST live line wins for python-dotenv
    and for run.sh's export loop alike. Quotes and surrounding blanks removed."""
    values = raw_values(lines, key)
    if not values:
        return None
    value = values[-1].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def already_holds(lines: List[str], key: str, token: str) -> bool:
    """True only for exactly one live line that is byte-for-byte KEY=<token>."""
    live = [line for line in lines if _key_of(line) == key]
    return live == [f"{key}={token}\n"]


def set_value(lines: List[str], key: str, value: str) -> List[str]:
    """One live KEY=VALUE line: replace the first (an `export` form included),
    drop the rest; if absent, place it after the last live SPLUNK_AO_* line."""
    out: List[str] = []
    done = False
    for line in lines:
        if _key_of(line) == key:
            if not done:
                out.append(f"{key}={value}\n")
                done = True
            continue
        out.append(line)
    if done:
        return out
    anchor = max((i for i, line in enumerate(out) if (_key_of(line) or "").startswith("SPLUNK_AO_")),
                 default=None)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    if anchor is None:
        out.append(f"{key}={value}\n")
    else:
        out.insert(anchor + 1, f"{key}={value}\n")
    return out


def _match_owner(fd: int, st: os.stat_result) -> None:
    """Run under sudo, hand the file to .env's owner — a root-owned 0600 .env is
    unreadable by the service user the app runs as."""
    if os.geteuid() == 0 and (st.st_uid, st.st_gid) != (0, 0):
        os.fchown(fd, st.st_uid, st.st_gid)


def write_atomic(path: Path, lines: List[str]) -> None:
    st = path.stat()
    # Prefix covered by .gitignore's `.env.bak.*`: the temp file holds every secret.
    fd, tmp = tempfile.mkstemp(prefix=".env.bak.tmp.", dir=str(path.parent))
    try:
        os.fchmod(fd, st.st_mode & 0o777)
        _match_owner(fd, st)
        with os.fdopen(fd, "w") as fh:
            fh.writelines(lines)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def backup(path: Path, content: bytes) -> Path:
    dest = path.with_name(f"{path.name}.bak.ao-api-token.{time.strftime('%Y%m%d%H%M%S')}")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        _match_owner(out.fileno(), path.stat())
        out.write(content)
    return dest


# --------------------------------------------------------------------------- token sources
def token_from_settings(env_path: Path, lines: List[str]) -> str:
    """The Agent Control token saved on the Settings page (Splunk Agent
    Observability > "AO control token (splunk_ao)") — an O11y API token with
    the agent_observability_admin role, i.e. exactly the kind sessions need."""
    url = get_value(lines, "DATABASE_URL") or "sqlite:///./medadvice.db"
    if not url.startswith("sqlite:///"):
        raise Abort("--from-settings reads the SQLite settings store; DATABASE_URL is not SQLite")
    db = Path(url[len("sqlite:///"):])
    if not db.is_absolute():
        db = env_path.parent / db
    if not db.exists():
        raise Abort(f"settings store not found: {db}")
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            row = con.execute("SELECT data FROM app_settings LIMIT 1").fetchone()
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise Abort(f"cannot read the settings store ({exc})")
    try:
        data = json.loads(row[0]) if row and row[0] else {}
    except (TypeError, ValueError):
        data = {}
    token = (((data.get("integration_creds") or {}).get("agent_observability") or {})
             .get("splunk_ao_control_token") or "").strip()
    if not token:
        raise Abort("no AO control token is saved on the Settings page; paste the token instead")
    return token


def read_token(args, env_path: Path, lines: List[str]) -> str:
    if args.from_settings:
        return token_from_settings(env_path, lines)
    if args.stdin:
        print("reading the token from stdin", file=sys.stderr)
        return sys.stdin.read()
    if not sys.stdin.isatty():
        raise Abort("stdin is not a terminal, so there is no hidden prompt. Pipe the token with "
                    "--stdin, or over ssh use `ssh -t` to get a terminal")
    return getpass.getpass("Paste the Agent Observability API token (input hidden): ")


def check_shape(token: str, lines: List[str]) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        token = token[1:-1].strip()
    if not token:
        raise Abort("no token given")
    if not _TOKEN_RE.match(token):
        raise Abort("that does not look like an Observability Cloud token "
                    "(expected 16-512 of A-Z a-z 0-9 . _ ~ -)")
    for k in INGEST_KEYS:
        if token in {v.strip().strip("'\"") for v in raw_values(lines, k)}:
            raise Abort(f"that is this box's ingest token ({k}); the sessions API rejects it "
                        "with 401. Create an API token with the agent_observability_admin role.")
    return token


# --------------------------------------------------------------------------- live check
def _ssl_context(env_dir: Optional[Path] = None) -> ssl.SSLContext:
    """Same trust as the app: SSL_CERT_FILE if set, else the checkout's
    ca-bundle.pem (backend/config.py points SSL_CERT_FILE at it) — next to the
    script or next to the .env, so a copy run from elsewhere still finds it —
    else the system store."""
    candidates = [os.environ.get("SSL_CERT_FILE"), str(ROOT / "ca-bundle.pem")]
    if env_dir is not None:
        candidates.append(str(env_dir / "ca-bundle.pem"))
    for cafile in candidates:
        if cafile and Path(cafile).is_file():
            return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 30x is a failure here, never followed: following it could hand the token
    to whatever host the Location names and count a sign-in page as a pass."""

    def redirect_request(self, *args, **kwargs):
        return None


def verify(token: str, api_base: str, project: str, allow_new_project: bool,
           env_dir: Optional[Path] = None) -> str:
    query = urllib.parse.urlencode({"project_name": project, "type": "gen_ai"})
    req = urllib.request.Request(f"{api_base}/projects?{query}", headers={"Accept": "application/json"})
    req.add_unredirected_header("X-SF-Token", token)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=_ssl_context(env_dir)))
    try:
        with opener.open(req, timeout=20) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise Abort(f"rejected (401) by {api_base}: not a valid token for this realm — "
                        "an ingest token, an expired or deleted token, or another realm's token")
        if exc.code == 403:
            raise Abort(f"rejected (403) by {api_base}: a valid token without Agent "
                        "Observability access — give it the agent_observability_admin role")
        raise Abort(f"unexpected HTTP {exc.code} from {api_base}; nothing written "
                    "(re-run with --no-verify to write it anyway)")
    except (urllib.error.URLError, OSError) as exc:
        raise Abort(f"could not reach {api_base} ({getattr(exc, 'reason', exc)}); nothing written "
                    "(re-run with --no-verify to write it anyway)")
    try:
        payload = json.loads(body)
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        payload = payload.get("projects") or payload.get("data") or payload.get("items")
    if not isinstance(payload, list):
        raise Abort(f"unexpected (non-JSON) answer from {api_base}, e.g. a proxy or sign-in page; "
                    "nothing written (re-run with --no-verify to write it anyway)")
    if any(isinstance(p, dict) and p.get("name") == project for p in payload):
        return f"accepted (200); project '{project}' found in this token's org"
    if allow_new_project:
        return (f"accepted (200); project '{project}' does not exist yet — the SDK will create it "
                "in this token's org (--allow-new-project)")
    raise Abort(f"the token works, but project '{project}' does not exist in its org. Either the "
                "token is from a different org than SPLUNK_AO_O11Y_TOKEN (sessions would go there "
                "while traces go to the ingest org), or this box has never ingested a turn. "
                "Nothing written; re-run with --allow-new-project if it is the right org")


# --------------------------------------------------------------------------- restart
def restart_hint() -> str:
    if platform.system() == "Darwin":
        return f"launchctl kickstart -k gui/{os.getuid()}/{_MAC_LABEL}"
    return "sudo systemctl restart pseudoco-assistant-app   # demobot-app on a pre-4.10 box"


def restart_app() -> str:
    if platform.system() == "Darwin":
        target = f"gui/{os.getuid()}/{_MAC_LABEL}"
        if subprocess.run(["launchctl", "print", target], capture_output=True).returncode != 0:
            raise Abort(f"launchd job {_MAC_LABEL} is not loaded")
        subprocess.run(["launchctl", "kickstart", "-k", target], check=True)
        return _MAC_LABEL
    for unit in _LINUX_UNITS:
        if subprocess.run(["systemctl", "cat", f"{unit}.service"], capture_output=True).returncode == 0:
            subprocess.run(["sudo", "systemctl", "restart", unit], check=True)
            return unit
    raise Abort("no pseudoco-assistant-app / demobot-app unit found")


# --------------------------------------------------------------------------- main
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 epilog=__doc__.split("\n\n", 1)[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file", type=Path, default=ROOT / ".env")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--stdin", action="store_true", help="read the token from stdin (piped)")
    src.add_argument("--from-settings", action="store_true",
                     help="reuse the AO control token saved on the Settings page")
    ap.add_argument("--allow-new-project", action="store_true",
                    help="accept a token whose org has no SPLUNK_AO_PROJECT yet")
    ap.add_argument("--no-verify", action="store_true", help="skip the live check")
    ap.add_argument("--dry-run", action="store_true", help="check everything, write nothing")
    ap.add_argument("--restart", action="store_true", help="restart the app afterwards")
    ap.add_argument("--api-base", help=argparse.SUPPRESS)   # tests: a local fake AO API
    args = ap.parse_args(argv)

    written = False
    try:
        env_path = args.env_file
        if not env_path.is_file():
            raise Abort(f"{env_path} not found (copy .env.example to .env first)")
        if env_path.is_symlink():
            print(f"{env_path} is a symlink; updating its target {env_path.resolve()}")
        env_path = env_path.resolve()
        owner = env_path.stat().st_uid
        if os.geteuid() not in (0, owner):
            raise Abort(f"run this as the owner of {env_path} (uid {owner})")
        lines = env_path.read_text().splitlines(keepends=True)

        realm = get_value(lines, "SPLUNK_AO_REALM")
        if not get_value(lines, "SPLUNK_AO_O11Y_TOKEN") or not realm:
            print("warning: SPLUNK_AO_O11Y_TOKEN / SPLUNK_AO_REALM are not both set, so Agent "
                  "Observability is off on this box and the app will not use this token yet",
                  file=sys.stderr)

        token = check_shape(read_token(args, env_path, lines), lines)
        print(f"token: {fingerprint(token)}")

        project = get_value(lines, "SPLUNK_AO_PROJECT") or DEFAULT_PROJECT
        if args.no_verify:
            print("live check: skipped (--no-verify)")
        else:
            if not realm or not _REALM_RE.match(realm):
                raise Abort("cannot check the token: SPLUNK_AO_REALM is missing or invalid in .env "
                            "(it is the only realm the app uses). Set it, or use --no-verify")
            api_base = args.api_base or f"https://app.{realm}.observability.splunkcloud.com/ao/api"
            print(f"live check: {verify(token, api_base, project, args.allow_new_project, env_path.parent)}")

        # Re-read: the prompt may have been open for minutes. Keep any edit made
        # meanwhile (a Settings-page save rewrites .env), and abort if the realm
        # or project the check was made against changed under us.
        content = env_path.read_bytes()
        fresh = content.decode().splitlines(keepends=True)
        if (get_value(fresh, "SPLUNK_AO_REALM"), get_value(fresh, "SPLUNK_AO_PROJECT") or DEFAULT_PROJECT) \
                != (realm, project):
            raise Abort(".env's SPLUNK_AO_REALM / SPLUNK_AO_PROJECT changed while waiting; re-run")
        check_shape(token, fresh)

        if already_holds(fresh, KEY, token):
            print(f"{KEY} already holds this token in {env_path}; nothing to write")
        elif args.dry_run:
            print(f"dry run: would write {KEY} to {env_path}")
        else:
            saved = backup(env_path, content)
            write_atomic(env_path, set_value(fresh, KEY, token))
            written = True
            print(f"wrote {KEY} to {env_path} (backup: {saved.name})")
            if env_path.stat().st_mode & 0o077:
                print(f"note: {env_path.name} is readable by other users; consider chmod 600")

        if args.dry_run:
            return 0
        if args.restart:
            try:
                print(f"restarted {restart_app()}")
            except (Abort, subprocess.CalledProcessError, OSError) as exc:
                print(f"error: {KEY} is {'written' if written else 'in place'}, but the restart "
                      f"failed ({exc}). Restart the app yourself:\n  {restart_hint()}", file=sys.stderr)
                return 2
        else:
            print(f"next: restart the app so it reads the new value:\n  {restart_hint()}")
        return 0
    except Abort as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        if written:
            print(f"\ninterrupted after {KEY} was written; restart the app yourself:\n  {restart_hint()}",
                  file=sys.stderr)
        else:
            print("\naborted; nothing written", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
