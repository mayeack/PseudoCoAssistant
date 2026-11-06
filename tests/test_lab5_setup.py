"""lab5-setup (deploy/lab5/lab5_setup.py) against fakes only.

No real SSH, Cloudflare, Duo, CII or Keychain: a FakeWorld holds in-memory
Show boxes (files, systemd units, the app's Settings API), an in-memory
Cloudflare API behind the tool's real HTTP client, and a fake `security`.
The https preflight is routed through the fake chain DNS record -> tunnel ->
connector token on the box -> the box's app, so it only passes when `up`
really wired all of it.

What it pins (plan 12.3, the I4 note and the secrets rule):
  * `up` on a box with Labs 0-4 settings leaves every non-Lab-5 .env line and
    every other HEC destination field unchanged;
  * `check` changes nothing anywhere;
  * `down` restores the box and deletes exactly what `up` created, and a
    second `down` does nothing;
  * no secret ever reaches argv (Keychain or box commands), a URL, the
    output, the run log or the state directory.

Run:  .venv/bin/python tests/test_lab5_setup.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LAB5 = ROOT / "deploy" / "lab5"
sys.path.insert(0, str(LAB5))
import lab5_setup as ls  # noqa: E402  (imports cleanly without paramiko/PyYAML)
import lab5_envfile as envfile  # noqa: E402
import lab5_remote as remote  # noqa: E402
from lab5_cloudflare import CloudflareAPI  # noqa: E402
from lab5_common import Lab5Error  # noqa: E402

_failures: List[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# --------------------------------------------------------------------------- secrets
SECRETS = {
    "pseudoco-lab5-cloudflare": "cf-api-token-Zq81mN0pL4vT7xR2",
    "pseudoco-lab5-duo-websdk-client-id": "DIWEBSDKCLIENTID0001",
    "pseudoco-lab5-duo-websdk-client-secret": "websdk-secret-9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "pseudoco-lab5-duo-websdk-api-host": "api-xxxxxxxx.duosecurity.com",
    "pseudoco-lab5-duo-status-ikey": "DIADMINSTATUSIKEY002",
    "pseudoco-lab5-duo-status-skey": "admin-skey-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "pseudoco-lab5-cii-client-id": "cii-client-id-77aa",
    "pseudoco-lab5-cii-client-secret": "cii-secret-QWERTY-1234567890-zxcvb",
    "pseudoco-lab5-cii-token-url": "https://login.oort.io/oauth/token",
    "pseudoco-lab5-cii-api-url": "https://api.oort.io/graphql",
    "pseudoco-lab5-hec-acme": "11111111-2222-3333-4444-roomhectoken9",
}
SSH_PASSWORD = "Sh0w-workshop-pw!"
ACCESS_KEYS = {"01": "box1-access-key-7c1d9e", "02": "box2-access-key-4b2f0a"}
NON_SECRET_ITEMS = {"pseudoco-lab5-duo-websdk-api-host", "pseudoco-lab5-cii-token-url",
                    "pseudoco-lab5-cii-api-url"}
OTHER_LAB_SECRETS = ["aid-key-OTHERLAB-5555", "ao-token-OTHERLAB-6666", "showhec-OTHERLAB-7777"]


def all_secrets(world: "FakeWorld") -> List[str]:
    vals = [v for k, v in SECRETS.items() if k not in NON_SECRET_ITEMS]
    vals += [SSH_PASSWORD, *ACCESS_KEYS.values(), *OTHER_LAB_SECRETS]
    vals += [t["token"] for t in world.cf.tunnels.values()]
    vals += [t["secret"] for t in world.cf.tunnels.values()]
    return vals


class FakeSecurity:
    """Stands in for /usr/bin/security; records argv."""

    def __init__(self) -> None:
        self.calls: List[List[str]] = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        item = argv[argv.index("-s") + 1]
        if item in SECRETS:
            return subprocess.CompletedProcess(argv, 0, SECRETS[item] + "\n", "")
        return subprocess.CompletedProcess(argv, 44, "", "The specified item could not be found in the keychain.\n")


# --------------------------------------------------------------------------- a Show box
LABS_0_4_ENV = (
    "# PseudoCo Assistant .env (Show image)\n"
    "APP_VERSION=4.22.0\n"
    "AI_PROVIDER=ollama\n"
    "OLLAMA_MODEL=llama3.1:8b\n"
    f"AI_DEFENSE_API_KEY={OTHER_LAB_SECRETS[0]}\n"
    "AI_DEFENSE_ENABLED=true\n"
    "OTEL_RESOURCE_ATTRIBUTES=deployment.environment=show-box-1,host.team=lab\r\n"
    f"SPLUNK_AO_O11Y_TOKEN='{OTHER_LAB_SECRETS[1]}'\n"
    "SPLUNK_AO_AGENT_STREAM=PseudoCo Assistant # lab 3\n"
    "\n"
    "# --- identity (12.6: empty on the template) ---\n"
    "PUBLIC_BASE_URL=\n"
    "# DUO_ENABLED=false\n"
    "EXTRA_BYTES=caf\xc3\xa9\x0cform-feed\n"
    "ACCESS_KEY={access_key}\n"
)


def labs_env(nn: str) -> bytes:
    return LABS_0_4_ENV.replace("{access_key}", ACCESS_KEYS[nn]).encode("latin-1")


def room_destination() -> Dict[str, Any]:
    return {"id": "show-stack", "name": "Show stack", "enabled": True,
            "url": "https://http-inputs-acme.splunkcloud.com:443/services/collector/event",
            "token": SECRETS["pseudoco-lab5-hec-acme"], "verify_tls": True, "index": "gen_ai_log",
            "source": "medadvice", "sourcetype": "gen_ai:json", "host": "medadvice",
            "sourcetype_map": {"audit": "gen_ai:json"}, "batch_size": 50, "flush_interval_s": 1.5,
            "queue_max": 5000, "request_timeout_s": 10.0, "max_retries": 3}


def lab2_destination() -> Dict[str, Any]:
    return {"id": "lab2-es", "name": "Lab 2 ES", "enabled": True, "url": "https://es.example.net:8088",
            "token": OTHER_LAB_SECRETS[2], "verify_tls": False, "index": "lab2", "source": "medadvice",
            "sourcetype": "gen_ai:json", "host": "medadvice", "sourcetype_map": {}, "batch_size": 100,
            "flush_interval_s": 2.0, "queue_max": 10000, "request_timeout_s": 10.0, "max_retries": 3}


def mask(dest: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in dest.items() if k != "token"}
    out["token_present"] = bool(dest.get("token"))
    out["token_last4"] = (dest.get("token") or "")[-4:]
    return out


READ_ONLY = ("printf", "true", "command -v", "systemctl cat", "systemctl is-active", "sha256sum",
             "grep", "test")


class FakeBox:
    """An in-memory Show box: files, systemd units and the app's API."""

    def __init__(self, world: "FakeWorld", nn: str, version: str = "4.22.0") -> None:
        self.world, self.nn, self.version = world, nn, version
        self.files: Dict[str, Tuple[bytes, int]] = {
            "/home/splunk/DemoBot/.env": (labs_env(nn), 0o600),
            "/home/splunk/DemoBot/backend/config.py": (f'    app_version: str = "{version}"\n'.encode(), 0o644),
            "/home/splunk/DemoBot/medadvice.db": (b"SQLite format 3\x00 box " + nn.encode(), 0o644),
        }
        self.destinations = [room_destination(), lab2_destination()]
        self.units = {"demobot-app": "active", "demobot-collector": "active"}
        self.enabled = {"demobot-app", "demobot-collector"}
        self.has_cloudflared = True
        self.sudo_ok = True
        self.app_up = True
        self.commands: List[Tuple[List[str], bool, Optional[bytes]]] = []
        self.mutations: List[str] = []
        self.restarts = 0
        self.http_log: List[Tuple[str, str, Dict[str, str]]] = []
        self._load_running_env()

    # what the running app read at its last start
    def _load_running_env(self) -> None:
        lines = envfile.split_lines(envfile.decode(self.files["/home/splunk/DemoBot/.env"][0]))
        self.running = {k: envfile.get(lines, k) for k in ("ACCESS_KEY", "DUO_ENABLED", "PUBLIC_BASE_URL")}

    # ---- the transport surface lab5_setup uses
    notes: List[str] = []

    def read_file(self, path: str) -> Optional[bytes]:
        entry = self.files.get(path)
        return entry[0] if entry else None

    def file_mode(self, path: str) -> Optional[int]:
        entry = self.files.get(path)
        return entry[1] if entry else None

    def write_file_atomic(self, path: str, data: bytes, mode: int = 0o600) -> None:
        self.mutations.append(f"write {path}")
        self.files[path] = (bytes(data), mode)

    def run(self, argv, stdin=None, sudo=False, timeout=120.0, check=False):
        argv = list(argv)
        self.commands.append((argv, sudo, stdin))
        res = self._dispatch(argv, stdin, sudo)
        if check and res.rc != 0:
            raise Lab5Error(f"`{' '.join(argv[:3])}` exited {res.rc}")
        return res

    def _dispatch(self, argv, stdin, sudo) -> remote.CmdResult:
        R = remote.CmdResult
        joined = " ".join(argv)
        if argv[:2] == ["sh", "-c"] and "printf %s" in argv[2]:
            return R(0, "/home/splunk")
        if argv == ["true"]:
            return R(0 if sudo and self.sudo_ok else 1)
        if argv[:2] == ["sh", "-c"] and "command -v cloudflared" in argv[2]:
            return R(0, "/usr/bin/cloudflared\n") if self.has_cloudflared else R(1)
        if argv[:2] == ["systemctl", "cat"]:
            return R(0 if argv[2] in self.units else 1)
        if argv[:2] == ["systemctl", "is-enabled"]:
            on = argv[2] in self.enabled
            return R(0 if on else 1, "enabled\n" if on else "disabled\n")
        if argv[:2] == ["systemctl", "is-active"]:
            st = self.units.get(argv[2], "inactive")
            return R(0 if st == "active" else 3, st + "\n")
        if argv[0] == "sha256sum":
            entry = self.files.get(argv[1])
            return R(0, f"{hashlib.sha256(entry[0]).hexdigest()}  {argv[1]}\n") if entry else R(1)
        if argv[:2] == ["grep", "-q"]:
            entry = self.files.get(argv[3])
            return R(0 if entry and argv[2].encode() in entry[0] else 1)
        if argv[:2] == ["test", "-e"]:
            return R(0 if argv[2] in self.files else 1)
        # ---- everything below changes the box
        self.mutations.append(joined if not stdin else f"{joined} <stdin>")
        if argv[:2] == ["sh", "-c"] and argv[3:4] == ["lab5-mkdir"]:
            return R(0)
        if argv[:3] == ["python3", "-I", "-"]:
            src, dst = argv[3], argv[4]
            self.files[dst] = (self.files[src][0], 0o600)
            return R(0)
        if argv[:2] == ["sh", "-c"] and argv[3] == "lab5-write":
            if not sudo:
                return R(1, "", "permission denied")
            self.files[argv[4]] = (stdin, int(argv[5], 8))
            return R(0)
        if argv[0] == "rm":
            for path in argv[2:]:
                self.files.pop(path, None)
            return R(0)
        if argv[0] == "systemctl":
            verb = argv[1]
            unit = argv[-1]
            if verb == "daemon-reload":
                return R(0)
            if verb == "enable":
                self.enabled.add(unit)
                return R(0)
            if verb == "restart":
                if unit == "demobot-app":
                    self.restarts += 1
                    self._load_running_env()
                else:
                    self.units[unit] = "active" if remote.UNIT_PATH in self.files else "failed"
                return R(0)
            if verb == "disable":
                self.units.pop(unit, None)
                self.enabled.discard(unit)
                return R(0)
        raise AssertionError(f"unexpected command on fake box: {argv}")

    def http(self, method, path, headers=None, body=None, port=8001, timeout=20.0):
        headers = headers or {}
        self.http_log.append((method, path, dict(headers)))
        if method != "GET":
            self.mutations.append(f"http {method} {path}")
        status, payload = self.app(method, path, headers, body)
        return remote.HttpResult(status=status, body=json.dumps(payload).encode())

    def app(self, method, path, headers, body) -> Tuple[int, Any]:
        if not self.app_up:
            raise Lab5Error("the app is not answering")
        if path == "/health":
            return 200, {"status": "healthy", "version": self.version}
        if headers.get("X-Access-Key") != self.running["ACCESS_KEY"]:
            return 401, {"detail": "unauthorized"}
        if path == "/api/server-info":
            enabled = self.running["DUO_ENABLED"] == "true" and (self.running["PUBLIC_BASE_URL"] or "").startswith("https://")
            gate = {"enabled": enabled, "reason": "" if enabled else "Duo sign-in is disabled (DUO_ENABLED)"}
            gated = {"pdf_attachments": {"enabled": True, "reason": ""}}
            if ls.version_at_least(self.version, "4.22.0"):
                gated["duo_signin"] = gate
            return 200, {"version": self.version, "gated": gated}
        if path == "/api/hec/destinations" and method == "GET":
            return 200, {"destinations": [mask(d) for d in self.destinations]}
        m = re.match(r"^/api/hec/destinations/([^/]+)$", path)
        if m:
            dest = next((d for d in self.destinations if d["id"] == m.group(1)), None)
            if dest is None:
                return 404, {"detail": "destination not found"}
            if method == "PUT":
                for k, v in json.loads(body or b"{}").items():   # exclude_unset patch
                    if k != "id":
                        dest[k] = v
            return 200, mask(dest)
        return 404, {"detail": "not found"}

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- Cloudflare
class FakeCloudflare:
    """The handful of API v4 endpoints lab5-setup calls, in memory."""

    ZONE, ACCOUNT = "zone-pc", "acct-pc"

    def __init__(self, world: "FakeWorld") -> None:
        self.world = world
        self.tunnels: Dict[str, Dict[str, Any]] = {}
        self.records: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, str, Dict[str, str]]] = []
        self.fail_create = False

    @property
    def mutations(self) -> List[Tuple[str, str]]:
        return [(m, u) for m, u, _ in self.calls if m != "GET"]

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers)))
        if headers.get("Authorization") != f"Bearer {SECRETS['pseudoco-lab5-cloudflare']}":
            return 403, json.dumps({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}).encode()
        parts = urlsplit(url)
        path = parts.path.replace("/client/v4", "")
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        data = json.loads(body) if body else {}
        status, result = self.route(method, path, q, data)
        if status >= 300:
            return status, json.dumps({"success": False, "errors": [{"code": 1003, "message": result}]}).encode()
        return status, json.dumps({"success": True, "errors": [], "result": result}).encode()

    def _live(self):
        return [t for t in self.tunnels.values() if not t["deleted_at"]]

    def tunnel_view(self, t):
        out = {k: v for k, v in t.items() if k not in ("token", "secret", "config")}
        out["status"] = "healthy" if self.world.connector_for(t["id"]) else "inactive"
        return out

    def route(self, method, path, q, data):
        acct = f"/accounts/{self.ACCOUNT}/cfd_tunnel"
        zone = f"/zones/{self.ZONE}/dns_records"
        if path == "/zones" and method == "GET":
            return 200, ([{"id": self.ZONE, "name": q.get("name"), "account": {"id": self.ACCOUNT}}]
                         if q.get("name") == "pseudocoassistant.com" else [])
        if path == acct and method == "GET":
            live = self._live()
            if "name" in q:
                live = [t for t in live if t["name"] == q["name"]]
            if "include_prefix" in q:
                live = [t for t in live if t["name"].startswith(q["include_prefix"])]
            return 200, [self.tunnel_view(t) for t in live]
        if path == acct and method == "POST":
            if self.fail_create:
                return 500, "internal error"
            tid = str(uuid.uuid4())
            t = {"id": tid, "name": data["name"], "deleted_at": None, "config_src": data.get("config_src"),
                 "token": f"eyJ-tunnel-token-{uuid.uuid4().hex}", "secret": f"tunnel-secret-{uuid.uuid4().hex}",
                 "config": {}}
            self.tunnels[tid] = t
            return 200, dict(self.tunnel_view(t), token=t["token"],
                             credentials_file={"TunnelID": tid, "TunnelSecret": t["secret"]})
        m = re.match(rf"^{acct}/([^/]+)(/token|/configurations|/connections)?$", path)
        if m:
            t = self.tunnels.get(m.group(1))
            if t is None:
                return 404, "tunnel not found"
            sub = m.group(2) or ""
            if sub == "/token" and method == "GET":
                return 200, t["token"]
            if sub == "/configurations":
                if method == "PUT":
                    t["config"] = data["config"]
                    return 200, {"config": t["config"]}
                return 200, {"config": t["config"]}
            if sub == "/connections" and method == "DELETE":
                return 200, None
            if sub == "" and method == "GET":
                return 200, dict(self.tunnel_view(t), deleted_at=t["deleted_at"])
            if sub == "" and method == "DELETE":
                if t["deleted_at"]:
                    return 404, "tunnel already deleted"
                t["deleted_at"] = "2026-11-05T00:00:00Z"
                return 200, self.tunnel_view(t)
        if path == zone and method == "GET":
            recs = list(self.records.values())
            if "name.exact" in q:
                recs = [r for r in recs if r["name"] == q["name.exact"]]
            if "name.startswith" in q:
                recs = [r for r in recs if r["name"].startswith(q["name.startswith"])]
            return 200, recs
        if path == zone and method == "POST":
            rid = uuid.uuid4().hex
            self.records[rid] = dict(data, id=rid)
            return 200, self.records[rid]
        m = re.match(rf"^{zone}/([^/]+)$", path)
        if m:
            r = self.records.get(m.group(1))
            if r is None:
                return 404, "record not found"
            if method == "GET":
                return 200, r
            if method == "PATCH":
                r.update(data)
                return 200, r
            if method == "DELETE":
                del self.records[m.group(1)]
                return 200, {"id": m.group(1)}
        return 400, f"unexpected {method} {path}"


# --------------------------------------------------------------------------- the world
class FakeWorld:
    def __init__(self, versions=("4.22.0", "4.22.0")) -> None:
        self.cf = FakeCloudflare(self)
        self.boxes = {f"{i + 1:02d}": FakeBox(self, f"{i + 1:02d}", v) for i, v in enumerate(versions)}
        self.security = FakeSecurity()
        self.connects: List[Tuple[str, str]] = []
        self.prompts: List[str] = []
        self.https_log: List[Tuple[str, str, Dict[str, str]]] = []

    def connector_for(self, tunnel_id: str) -> Optional[FakeBox]:
        t = self.cf.tunnels.get(tunnel_id)
        if not t or t["deleted_at"]:
            return None
        for box in self.boxes.values():
            env = box.files.get(remote.TOKEN_ENV_PATH)
            unit = box.files.get(remote.UNIT_PATH)
            if (env and unit and box.units.get(remote.UNIT_NAME) == "active"
                    and f"TUNNEL_TOKEN={t['token']}\n".encode() in env[0]):
                return box
        return None

    # deps
    def connect(self, box_spec, password, ctx):
        self.connects.append((box_spec.nn, password))
        if password != SSH_PASSWORD:
            raise Lab5Error(f"SSH password rejected for {box_spec.ssh_label}")
        box = self.boxes.get(box_spec.nn)
        if box is None:
            raise Lab5Error(f"cannot reach {box_spec.ssh_label} over SSH (timeout)")
        return box

    def resolve(self, host: str) -> List[str]:
        if any(r["name"] == host for r in self.cf.records.values()):
            return ["104.21.0.10"]
        raise OSError("nodename nor servname provided")

    def https(self, method: str, url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
        self.https_log.append((method, url, dict(headers)))
        parts = urlsplit(url)
        rec = next((r for r in self.cf.records.values() if r["name"] == parts.hostname), None)
        if rec is None:
            raise Lab5Error("unreachable (gaierror)")
        tid = rec["content"].split(".")[0]
        t = self.cf.tunnels.get(tid)
        ingress = (t or {}).get("config", {}).get("ingress", [])
        if not rec.get("proxied") or not t or not ingress or ingress[0].get("hostname") != parts.hostname:
            return 530, b"error code: 1033"
        box = self.connector_for(tid)
        if box is None:
            return 530, b"error code: 1033"
        status, payload = box.app(method, parts.path, headers, None)
        return status, json.dumps(payload).encode()

    def prompt(self, text: str) -> str:
        self.prompts.append(text)
        return SSH_PASSWORD if len(self.prompts) == 1 else ""   # Enter = same as previous

    def deps(self, state_root: Path, out: io.StringIO) -> "ls.Deps":
        return ls.Deps(connect=self.connect, cloudflare_transport=self.cf, keychain_runner=self.security,
                       https=self.https, resolve=self.resolve, prompt=self.prompt, state_root=state_root,
                       out=out, sleep=lambda s: None, app_wait_s=0.0, preflight_wait_s=0.0)


WORKSHOP_YAML = """
workshop: acme
required_version: "4.22.0"
stack:
  hec_url: https://http-inputs-acme.splunkcloud.com/services/collector
  hec_token_item: pseudoco-lab5-hec-acme
room:
  victim: avery.kim
  fallback: jordan.reyes
boxes:
  - instance: 1
    host: 198.51.100.1
  - instance: 2
    host: 198.51.100.2
# The box side only: tests/test_lab5_participants.py drives the accounts (12.2).
participants:
  enabled: false
"""


def run_cli(world: FakeWorld, tmp: Path, *argv: str) -> Tuple[int, str]:
    yaml_path = tmp / "workshop.yaml"
    if not yaml_path.exists():
        yaml_path.write_text(WORKSHOP_YAML)
    out = io.StringIO()
    world.prompts.clear()
    rc = ls.main([*argv[:1], str(yaml_path), *argv[1:]], deps=world.deps(tmp / "state", out))
    return rc, out.getvalue()


# =========================================================================== tests
def test_envfile() -> None:
    print("== .env merge: Lab 5 keys only, every other byte kept ==")
    text = envfile.decode(labs_env("01"))
    values = {"PUBLIC_BASE_URL": "https://l5-acme-01.pseudocoassistant.com", "DUO_ENABLED": "true",
              "DUO_CLIENT_SECRET": "s3cr3t-value-abcdef", "IDENTITY_ALLOWED_USERS": "a.b,c.d",
              "HEC_HOST": "l5-acme-01.pseudocoassistant.com"}
    plan = envfile.plan_up(text, values)
    check("other lines identical, in order (CRLF, quotes, comments, non-UTF-8 bytes, form feed)",
          envfile.other_lines(plan.new_text) == envfile.other_lines(text))
    check("the commented-out # DUO_ENABLED line is left alone", "# DUO_ENABLED=false\n" in plan.new_text)
    check("PUBLIC_BASE_URL replaced in place",
          envfile.split_lines(plan.new_text)[11] == "PUBLIC_BASE_URL=https://l5-acme-01.pseudocoassistant.com\n")
    check("bytes round-trip", envfile.encode(envfile.decode(labs_env("01"))) == labs_env("01"))
    again = envfile.plan_up(plan.new_text, values)
    check("idempotent: a second plan changes nothing", not again.changed)
    diff = plan.diff()
    check("diff masks credentials", "s3cr3t-value-abcdef" not in diff and "<...cdef>" in diff, diff)
    check("diff never shows another lab's line",
          not any(s in diff for s in OTHER_LAB_SECRETS + ["AI_PROVIDER", "ACCESS_KEY", "OTEL_"]), diff)
    revert = envfile.plan_revert(plan.new_text, envfile.baseline_of(text))
    check("revert restores the original bytes", revert.new_text == text)
    base = envfile.baseline_of(text.replace("PUBLIC_BASE_URL=\n", "PUBLIC_BASE_URL=\nDUO_CLIENT_SECRET=old-secret-zz\n"))
    check("a prior credential is recorded as present, never by value",
          base["DUO_CLIENT_SECRET"] == {"present": True, "secret": True} and "old-secret" not in json.dumps(base))
    check("unsafe values are single-quoted", envfile.render("K", "a b#c") == "K='a b#c'")
    try:
        envfile.render("K", "it's")
        ok = False
    except Lab5Error:
        ok = True
    check("a value .env cannot carry is refused", ok)
    no_nl = envfile.plan_up("A=1\nB=2", {"HEC_HOST": "h"})
    check("missing final newline: added, flagged", no_nl.new_text == "A=1\nB=2\nHEC_HOST=h\n" and no_nl.eol_added)


def test_check_is_read_only() -> None:
    print("== check: reads and plans, changes nothing ==")
    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "check")
        check("check exits 0", rc == 0, out)
        check("both boxes ready", out.count("ready, nothing to upgrade") == 2, out)
        check("no box changed", all(not b.mutations for b in world.boxes.values()),
              str([b.mutations for b in world.boxes.values()]))
        check("nothing changed in Cloudflare", not world.cf.mutations, str(world.cf.mutations))
        check("no box record written", not list((Path(tmp) / "state" / "workshops" / "acme" / "boxes").glob("*.json")))
        check("prints the masked .env diff", "+DUO_CLIENT_SECRET=<...9a0>" in out or "+DUO_CLIENT_SECRET=<...b1a0>" in out, out)
        check("prints the HEC host plan", "host 'medadvice' -> 'l5-acme-01.pseudocoassistant.com'" in out, out)
        check("password asked once per box, Enter reuses", len(world.prompts) == 2 and "Enter" in world.prompts[1])
        leaked = [s for s in all_secrets(world) if s in out]
        check("no secret in the output", not leaked, str(leaked))


def _snapshot(box: FakeBox) -> Dict[str, Any]:
    return {"env": box.files["/home/splunk/DemoBot/.env"][0], "dests": json.loads(json.dumps(box.destinations))}


def test_up_status_down() -> None:
    print("== up on a Labs 0-4 box, then status, then down twice ==")
    world = FakeWorld()
    before = {nn: _snapshot(b) for nn, b in world.boxes.items()}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rc, out = run_cli(world, tmp, "up")
        check("up exits 0", rc == 0, out)
        for nn, box in world.boxes.items():
            host = f"l5-acme-{nn}.pseudocoassistant.com"
            new_env = envfile.decode(box.files["/home/splunk/DemoBot/.env"][0])
            old_env = envfile.decode(before[nn]["env"])
            check(f"[{nn}] every non-Lab-5 .env line unchanged, byte-for-byte",
                  envfile.other_lines(new_env) == envfile.other_lines(old_env))
            lines = envfile.split_lines(new_env)
            check(f"[{nn}] Lab 5 keys set", envfile.get(lines, "DUO_ENABLED") == "true"
                  and envfile.get(lines, "PUBLIC_BASE_URL") == f"https://{host}"
                  and envfile.get(lines, "HEC_HOST") == host
                  and envfile.get(lines, "DUO_ADMIN_SKEY") == SECRETS["pseudoco-lab5-duo-status-skey"]
                  and envfile.get(lines, "IDENTITY_ALLOWED_USERS") == "marcus.bell,elena.sousa,grace.lin,avery.kim")
            check(f"[{nn}] .env keeps 0600", box.files["/home/splunk/DemoBot/.env"][1] == 0o600)
            room_before = next(d for d in before[nn]["dests"] if d["id"] == "show-stack")
            room_after = next(d for d in box.destinations if d["id"] == "show-stack")
            check(f"[{nn}] HEC destination: host stamped", room_after["host"] == host)
            check(f"[{nn}] HEC destination: every other field unchanged (token, url, index, ...)",
                  {k: v for k, v in room_after.items() if k != "host"}
                  == {k: v for k, v in room_before.items() if k != "host"})
            check(f"[{nn}] the other lab's destination untouched",
                  next(d for d in box.destinations if d["id"] == "lab2-es") == lab2_destination())
            backups = [p for p in box.files if "/.pseudoco-lab5/backups/acme-" in p]
            env_bk = [p for p in backups if p.endswith("/.env")]
            check(f"[{nn}] .env and medadvice.db backed up first", len(backups) == 2 and env_bk
                  and box.files[env_bk[0]][0] == before[nn]["env"] and box.files[env_bk[0]][1] == 0o600)
            first_write = next(i for i, m in enumerate(box.mutations) if m.startswith("write /home/splunk/DemoBot/.env"))
            check(f"[{nn}] backup happened before the .env write",
                  any(m.startswith("python3") for m in box.mutations[:first_write]))
            unit = box.files[remote.UNIT_PATH][0].decode()
            tok = box.files[remote.TOKEN_ENV_PATH]
            check(f"[{nn}] connector: token in a 0600 file, never in the unit",
                  tok[1] == 0o600 and b"TUNNEL_TOKEN=eyJ" in tok[0] and "eyJ" not in unit
                  and "ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run\n" in unit)
            check(f"[{nn}] app restarted once", box.restarts == 1)
        check("preflight passed through the public name", out.count("not gated") == 2
              and "https://l5-acme-01.pseudocoassistant.com/health 4.22.0" in out, out)
        check("one tunnel and one proxied CNAME per box",
              len(world.cf._live()) == 2 and len(world.cf.records) == 2
              and all(r["proxied"] and r["content"].endswith(".cfargotunnel.com") for r in world.cf.records.values()))
        check("ingress -> http://localhost:8001",
              all(t["config"]["ingress"][0]["service"] == "http://localhost:8001" for t in world.cf._live()))

        # a second up is a no-op apart from its backup
        mutations_before = {nn: len(b.mutations) for nn, b in world.boxes.items()}
        cf_before = len(world.cf.mutations)
        rc, out2 = run_cli(world, tmp, "up")
        new_box_mutations = [m for nn, b in world.boxes.items() for m in b.mutations[mutations_before[nn]:]]
        check("second up exits 0", rc == 0, out2)
        check("second up: only the new backup is written",
              all("backups" in m or m.startswith("python3") for m in new_box_mutations), str(new_box_mutations))
        check("second up: no Cloudflare change", len(world.cf.mutations) == cf_before)
        check("second up: no restart", all(b.restarts == 1 for b in world.boxes.values()))

        rc, out3 = run_cli(world, tmp, "status")
        check("status exits 0", rc == 0, out3)
        check("status: tunnels healthy, connector active", out3.count(": healthy") == 2
              and out3.count(f"{remote.UNIT_NAME}: active") == 2, out3)

        secrets_all = all_secrets(world)
        state_text = "".join(p.read_text() for p in (tmp / "state").rglob("*") if p.is_file())

        rc, out4 = run_cli(world, tmp, "down")
        check("down exits 0", rc == 0, out4)
        for nn, box in world.boxes.items():
            check(f"[{nn}] down: .env byte-identical to before up",
                  box.files["/home/splunk/DemoBot/.env"][0] == before[nn]["env"])
            check(f"[{nn}] down: HEC destinations back exactly", box.destinations == before[nn]["dests"])
            check(f"[{nn}] down: connector unit and token file removed",
                  remote.UNIT_PATH not in box.files and remote.TOKEN_ENV_PATH not in box.files)
            env_backups = sorted(p for p in box.files if p.endswith("/.env") and "backups" in p)
            check(f"[{nn}] down: backups holding Lab 5 credentials removed, the baseline kept",
                  len(env_backups) == 1 and box.files[env_backups[0]][0] == before[nn]["env"], str(env_backups))
            check(f"[{nn}] down: app restarted", box.restarts == 2)
        check("down: tunnels and DNS records deleted", not world.cf._live() and not world.cf.records)

        snap = {nn: (dict(b.files), json.dumps(b.destinations), len(b.mutations)) for nn, b in world.boxes.items()}
        cf_before = len(world.cf.mutations)
        rc, out5 = run_cli(world, tmp, "down")
        check("second down exits 0", rc == 0, out5)
        check("second down changes nothing on the boxes",
              all(snap[nn] == (dict(b.files), json.dumps(b.destinations), len(b.mutations))
                  for nn, b in world.boxes.items()), out5)
        check("second down changes nothing in Cloudflare", len(world.cf.mutations) == cf_before)
        check("second down says so", out5.count("already deleted") >= 4 and "CHANGED" not in out5, out5)

        logs = "".join(p.read_text() for p in (tmp / "state").rglob("*.log"))
        everything = out + out2 + out3 + out4 + out5 + logs
        leaked = [s for s in secrets_all if s in everything]
        check("no secret in any output or run log", not leaked, str(leaked))
        leaked = [s for s in secrets_all if s in state_text]
        check("no secret in the state directory", not leaked, str(leaked))
        modes = {p.name: stat.S_IMODE(p.stat().st_mode) for p in (tmp / "state").rglob("*")}
        check("state directory is private (dirs 0700, files 0600)",
              all(m in (0o700, 0o600) for m in modes.values()), str(modes))
        argv_text = json.dumps([c for c in world.security.calls])
        argv_text += json.dumps([cmd for b in world.boxes.values() for cmd, _, _ in b.commands])
        argv_text += json.dumps([remote.remote_command(cmd, sudo) for b in world.boxes.values()
                                 for cmd, sudo, _ in b.commands])
        argv_text += json.dumps([u for _, u, _ in world.cf.calls] + [u for _, u, _ in world.https_log])
        leaked = [s for s in secrets_all if s in argv_text]
        check("no secret in any argv (Keychain, box commands) or URL", not leaked, str(leaked))
        check("Keychain read by item name only", all(c[:2] == ["security", "find-generic-password"]
                                                      and c[-1] == "-w" for c in world.security.calls))
        stdin_with_token = [stdin for b in world.boxes.values() for cmd, sudo, stdin in b.commands
                            if stdin and b"TUNNEL_TOKEN" in stdin]
        check("the tunnel token reached the box only as stdin of a sudo file write",
              len(stdin_with_token) == 2)


def test_refusals() -> None:
    print("== refusals: old release, no room destination, unrecorded tunnel ==")
    world = FakeWorld(versions=("4.21.0", "4.22.0"))
    world.boxes["02"].destinations = [lab2_destination()]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "up")
        check("up exits 1 when a box is refused", rc == 1, out)
        check("old release: names the template", "the Show template needs that release (12.6)" in out, out)
        check("no room destination: refused, never repointed", "never adds or repoints one" in out, out)
        check("refused boxes are untouched", all(not b.mutations for b in world.boxes.values()))
        check("nothing created in Cloudflare", not world.cf.mutations, str(world.cf.mutations))
    world = FakeWorld()
    world.cf.route("POST", f"/accounts/{FakeCloudflare.ACCOUNT}/cfd_tunnel", {}, {"name": "l5-acme-02"})
    world.cf.calls.clear()
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "up", "--only", "2")
        check("an unrecorded tunnel with the box's name is a conflict", rc == 1 and "no record of `up` creating it" in out, out)
        check("conflict: nothing changed", not world.boxes["02"].mutations and not world.cf.mutations)
        rc, out = run_cli(world, Path(tmp), "status", "--only", "2")
        check("status lists it as an orphan, left alone", "orphan" in out and "l5-acme-02" in out, out)


def test_down_without_record() -> None:
    print("== down with no record of up ==")
    world = FakeWorld()
    box = world.boxes["01"]
    env = envfile.decode(box.files["/home/splunk/DemoBot/.env"][0]) + "DUO_ENABLED=true\nDUO_CLIENT_SECRET=leftover-secret-xyz\n"
    box.files["/home/splunk/DemoBot/.env"] = (envfile.encode(env), 0o600)
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "down", "--only", "1")
        text = envfile.decode(box.files["/home/splunk/DemoBot/.env"][0])
        check("down exits 0", rc == 0, out)
        check("Lab 5 keys holding a value are removed", "DUO_ENABLED=true" not in text and "leftover" not in text)
        check("empty template keys stay", "PUBLIC_BASE_URL=\n" in text)
        check("other lines untouched", envfile.other_lines(text) == envfile.other_lines(env))
        check("nothing deleted in Cloudflare", not world.cf.mutations)


def test_preflight_gate_and_unreachable() -> None:
    print("== preflight reports the duo_signin gate; down survives an unreachable box ==")
    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_cli(world, tmp, "up")
        box = world.boxes["01"]
        box.running["DUO_ENABLED"] = "false"            # the app restarted with Duo off
        rc, out = run_cli(world, tmp, "status", "--only", "1")
        check("status fails on a gated duo_signin, with the reason", rc == 1 and "Duo sign-in is disabled" in out, out)
        del world.boxes["02"]                             # Show already destroyed box 02
        rc, out = run_cli(world, tmp, "down")
        check("down: an unreachable box FAILs the run (exit 1), never 'ok'",
              rc == 1 and "RESULT: down: 1 ok, 1 failed (box 02)" in out, out)
        check("down: it says what was not reverted and how to finish",
              "Nothing on the box was reverted" in out and "--only 2" in out and "NEXT: re-run" in out, out)
        check("down: the reachable box is still reverted",
              box.files["/home/splunk/DemoBot/.env"][0] == labs_env("01") and remote.UNIT_PATH not in box.files)
        check("down: its tunnel and DNS record are still deleted", not world.cf._live() and not world.cf.records)
        rec = json.loads((tmp / "state/workshops/acme/boxes/02.json").read_text())
        check("down: the record keeps a pending revert for the skipped box", bool(rec.get("revert_pending")), str(rec))
        rec1 = json.loads((tmp / "state/workshops/acme/boxes/01.json").read_text())
        check("down: none for the box it finished", "revert_pending" not in rec1, str(rec1))
        rc, out = run_cli(world, tmp, "status", "--only", "2")
        check("status names the skipped box's pending down, not 'run up'",
              "an earlier down could not revert this box" in out and "deleted by down" in out
              and "no tunnel recorded" not in out, out)


def test_failed_up_resumes() -> None:
    print("== an up that fails after the .env write restarts the app on the next run ==")
    world = FakeWorld()
    world.cf.fail_create = True
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rc, out = run_cli(world, tmp, "up", "--only", "1")
        box = world.boxes["01"]
        check("up fails on the Cloudflare error", rc == 1 and "HTTP 500" in out, out)
        check(".env was written but the app not restarted yet",
              b"DUO_ENABLED=true" in box.files["/home/splunk/DemoBot/.env"][0] and box.restarts == 0)
        world.cf.fail_create = False
        rc, out = run_cli(world, tmp, "up", "--only", "1")
        check("the re-run succeeds", rc == 0, out)
        check("the re-run restarts the app although .env no longer changes", box.restarts == 1, out)
        check("and the preflight sees Duo sign-in on", "not gated" in out, out)


def test_wrong_password_and_cli() -> None:
    print("== CLI edges ==")
    world = FakeWorld()
    world.prompt = lambda text: "wrong-password-123"
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "check")
        check("a rejected SSH password fails the box, not the run", rc == 1 and "SSH password rejected" in out, out)
        check("the wrong password is not echoed", "wrong-password-123" not in out)
        out_io = io.StringIO()
        rc = ls.main(["expire", str(Path(tmp) / "workshop.yaml")], deps=world.deps(Path(tmp) / "state", out_io))
        check("expire without the Provisioner keys exits 2 and names the Keychain item",
              rc == 2 and "pseudoco-lab5-duo-provisioner-ikey" in out_io.getvalue(), out_io.getvalue())
    for bad, why in ((WORKSHOP_YAML.replace("workshop: acme", "workshop: Acme_1"), "bad workshop name"),
                     (WORKSHOP_YAML.replace("https://http-inputs", "http://http-inputs"), "http HEC URL"),
                     (WORKSHOP_YAML.replace("instance: 2", "instance: 1"), "duplicate instance")):
        import yaml
        try:
            ls.workshop_from_dict(yaml.safe_load(bad))
            ok = False
        except Lab5Error:
            ok = True
        check(f"workshop.yaml rejected: {why}", ok)


def test_example_yaml() -> None:
    print("== workshop.example.yaml ==")
    ws = ls.load_workshop(LAB5 / "workshop.example.yaml")
    check("loads and validates", ws.name == "acme-1105" and len(ws.boxes) == 2)
    check("defaults apply to every box", all(b.port == 2222 and b.user == "splunk"
                                             and b.checkout == "/home/splunk/DemoBot" for b in ws.boxes))
    check("hostname is single-label under the zone", ws.hostname(ws.boxes[0]) == "l5-acme-1105-01.pseudocoassistant.com")
    check("Keychain defaults are the pseudoco-lab5-* items",
          ws.keychain["DUO_CLIENT_SECRET"] == "pseudoco-lab5-duo-websdk-client-secret"
          and ws.cloudflare_item == "pseudoco-lab5-cloudflare")


def test_cloudflare_client() -> None:
    print("== Cloudflare client: token only in the Authorization header ==")
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append((method, url, headers, body))
        if url.endswith("/token"):
            return 200, json.dumps({"success": True, "result": "eyJ-tok"}).encode()
        return 403, json.dumps({"success": False, "errors": [{"code": 9109, "message": "Unauthorized"}]}).encode()

    api = CloudflareAPI("cf-secret-token-123456", transport=transport)
    try:
        api.zone("pseudocoassistant.com")
        msg = ""
    except Lab5Error as exc:
        msg = str(exc)
    check("API errors surface the code, not the token", "9109" in msg and "cf-secret" not in msg, msg)
    check("token never in a URL", all("cf-secret" not in url for _, url, _, _ in calls))
    check("token in the Authorization header", calls[0][2]["Authorization"] == "Bearer cf-secret-token-123456")
    check("tunnel token read from the token endpoint", api.tunnel_token("a", "t") == "eyJ-tok")


def test_remote_helpers() -> None:
    print("== remote helpers ==")
    check("argv is quoted, sudo is non-interactive",
          remote.remote_command(["systemctl", "restart", "demobot app"], sudo=True)
          == "sudo -n -- systemctl restart 'demobot app'")
    raw = (b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: application/json\r\n\r\n"
           b"4\r\n{\"a\"\r\n3\r\n: 1\r\n1\r\n}\r\n0\r\n\r\n")
    check("chunked replies are decoded", remote.parse_http_response(raw).json() == {"a": 1})
    raw = b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\n\r\n{}"
    check("status and length", remote.parse_http_response(raw).status == 401)
    unit = remote.unit_text("/usr/bin/cloudflared", "acme", "01", "l5-acme-01")
    check("unit carries the ownership marker and no token", remote.UNIT_MARKER in unit and "TUNNEL_TOKEN=" not in unit)
    check("HEC URLs compare like the app normalizes them",
          ls.normalize_hec_url("https://H.example.com:443/services/collector")
          == ls.normalize_hec_url("https://h.example.com/services/collector/event"))
    try:
        remote.build_http_request("GET", "/x", 8001, {"X-Access-Key": "a\r\nInjected: 1"}, None)
        ok = False
    except Lab5Error:
        ok = True
    check("header injection refused", ok)


def _host(box: FakeBox) -> str:
    return next(d["host"] for d in box.destinations if d["id"] == "show-stack")


def test_down_failures_are_failures() -> None:
    print("== down: a box it could not finish FAILs, stays pending, and a re-run finishes it ==")
    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_cli(world, tmp, "up")
        good_prompt = world.prompt
        world.prompt = lambda text: "typo-password-1"     # mistyped, or box 02's differs
        rc, out = run_cli(world, tmp, "down")
        check("wrong SSH password: down exits 1, no box 'ok'", rc == 1 and "0 ok, 2 failed" in out, out)
        check("wrong SSH password: nothing on the boxes changed",
              all(b.files["/home/splunk/DemoBot/.env"][0] != labs_env(nn) and remote.UNIT_PATH in b.files
                  for nn, b in world.boxes.items()))
        world.prompt = good_prompt
        rc, out = run_cli(world, tmp, "down")
        check("the re-run with the right password exits 0 and says it is finishing a revert",
              rc == 0 and out.count("finishing the revert an earlier down could not") == 2, out)
        check("the re-run restores every box",
              all(b.files["/home/splunk/DemoBot/.env"][0] == labs_env(nn) and _host(b) == "medadvice"
                  and remote.UNIT_PATH not in b.files for nn, b in world.boxes.items()))
        recs = [json.loads((tmp / f"state/workshops/acme/boxes/{nn}.json").read_text()) for nn in ("01", "02")]
        check("the pending marker is cleared", all("revert_pending" not in r for r in recs), str(recs))

    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_cli(world, tmp, "up", "--only", "1")
        box = world.boxes["01"]
        real_app = box.app

        def broken_settings(method, path, headers, body):
            if path.startswith("/api/hec/destinations"):
                return 500, {"detail": "internal error"}
            return real_app(method, path, headers, body)

        box.app = broken_settings
        rc, out = run_cli(world, tmp, "down", "--only", "1")
        check("HEC host not revertible: down exits 1 and names the host the room still sees",
              rc == 1 and "HEC host of destination show-stack not reverted" in out
              and "l5-acme-01.pseudocoassistant.com" in out, out)
        rec = json.loads((tmp / "state/workshops/acme/boxes/01.json").read_text())
        check("HEC host not revertible: still recorded as to revert",
              rec["hec"]["reverted"] is False and rec.get("revert_pending"), str(rec))
        box.app = real_app
        rc, out = run_cli(world, tmp, "down", "--only", "1")
        check("the re-run reverts the HEC host and exits 0", rc == 0 and _host(box) == "medadvice", out)

    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_cli(world, tmp, "up", "--only", "1")
        box = world.boxes["01"]
        box.app_up = False                                # e.g. it crashed after up
        real_dispatch = box._dispatch

        def restart_brings_it_back(argv, stdin, sudo):
            res = real_dispatch(argv, stdin, sudo)
            if argv[:2] == ["systemctl", "restart"] and argv[-1] == "demobot-app":
                box.app_up = True
            return res

        box._dispatch = restart_brings_it_back
        rc, out = run_cli(world, tmp, "down", "--only", "1")
        check("app down before down: the restart brings it back and the HEC host is reverted after it",
              rc == 0 and _host(box) == "medadvice" and box.files["/home/splunk/DemoBot/.env"][0] == labs_env("01"),
              out)

    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_cli(world, tmp, "up", "--only", "1")
        world.boxes["01"].destinations = [lab2_destination()]   # someone deleted the room destination
        rc, out = run_cli(world, tmp, "down", "--only", "1")
        check("a destination deleted since up is a warning, not a failure",
              rc == 0 and "no longer exists; nothing to revert" in out, out)


class StrictBox(FakeBox):
    """Its app refuses to start when `refuse(env lines)` says so, as pydantic
    does on a value it cannot parse."""

    refuse = staticmethod(lambda lines: False)

    def _load_running_env(self) -> None:
        super()._load_running_env()
        lines = envfile.split_lines(envfile.decode(self.files["/home/splunk/DemoBot/.env"][0]))
        self.app_up = not self.refuse(lines)


def test_identity_values_and_rollback() -> None:
    print("== identity: values the app cannot start with are refused; an app that does not come back is rolled back ==")
    import yaml
    good = yaml.safe_load(WORKSHOP_YAML)
    for bad, why in (({"session_ttl_minutes": "12h"}, "a TTL with a unit"),
                     ({"session_ttl_minutes": 1.5}, "a fractional TTL"),
                     ({"session_ttl_minutes": True}, "a bool for a number"),
                     ({"session_ttl_minutes": 0}, "a TTL below the app's 1 minute"),
                     ({"session_ttl_minutes": 20000}, "a TTL above the app's 7 days"),
                     ({"status_ttl_seconds": -1}, "a negative status TTL"),
                     ({"status_ttl_seconds": "²"}, "a non-ASCII digit"),
                     ({"fail_open": "maybe"}, "fail_open that is not a bool"),
                     ({"fail_open": 1}, "fail_open as a number"),
                     ({"session_ttl": 600}, "an unknown key"),
                     ("720", "identity that is not a mapping")):
        try:
            ls.workshop_from_dict(dict(good, identity=bad))
            ok = False
        except Lab5Error:
            ok = True
        check(f"identity rejected: {why}", ok)
    ws = ls.workshop_from_dict(dict(good, identity={"session_ttl_minutes": "600", "status_ttl_seconds": 0,
                                                    "fail_open": "False"}))
    check("identity values are normalized for .env",
          ws.identity == {"IDENTITY_SESSION_TTL_MINUTES": "600", "IDENTITY_STATUS_TTL_SECONDS": "0",
                          "IDENTITY_FAIL_OPEN": "false"}, str(ws.identity))
    try:
        ls.workshop_from_dict(dict(good, zone="pseudoco assistant.com"))
        ok = False
    except Lab5Error:
        ok = True
    check("zone rejected unless it is a DNS name", ok)

    world = FakeWorld()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "workshop.yaml").write_text(WORKSHOP_YAML + "identity:\n  session_ttl_minutes: 12h\n")
        rc, out = run_cli(world, tmp, "check")
        check("check refuses the bad value before connecting", rc == 2 and "session_ttl_minutes" in out
              and not world.connects, out)
        rc, out = run_cli(world, tmp, "up")
        check("up refuses it too and changes nothing", rc == 2 and all(not b.mutations for b in world.boxes.values())
              and not world.cf.mutations, out)

    world = FakeWorld()
    world.boxes = {nn: StrictBox(world, nn) for nn in ("01", "02")}
    StrictBox.refuse = staticmethod(lambda lines: envfile.get(lines, "DUO_ENABLED") == "true")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            rc, out = run_cli(world, tmp, "up")
            check("app does not start with the Lab 5 keys: up exits 1", rc == 1, out)
            check("its .env is rolled back byte-for-byte and the app answers again",
                  all(b.files["/home/splunk/DemoBot/.env"][0] == labs_env(nn) and b.app_up and b.restarts == 2
                      for nn, b in world.boxes.items()), out)
            check("the report says it rolled back and what to do",
                  out.count("rolled back to the .env this run started from") == 2 and "then re-run up" in out, out)
            StrictBox.refuse = staticmethod(lambda lines: False)    # the cause is fixed
            rc, out = run_cli(world, tmp, "up")
            check("the re-run of up is not blocked and succeeds", rc == 0 and out.count("not gated") == 2, out)
    finally:
        StrictBox.refuse = staticmethod(lambda lines: False)


def test_diff_on_long_env() -> None:
    print("== check's .env diff on long and repetitive files ==")
    vals = {"PUBLIC_BASE_URL": "https://l5-acme-01.pseudocoassistant.com", "DUO_ENABLED": "true",
            "DUO_CLIENT_SECRET": "s3cr3t-value-abcdef", "HEC_HOST": "l5-acme-01.pseudocoassistant.com"}
    filler = "".join(f"# setting {i}\nOTHER_{i}=v{i}\n\n" for i in range(80))
    example = ROOT / ".env.example"
    cases = {
        "240-line file, the empty key then a trailing blank line (difflib autojunk)": filler + "PUBLIC_BASE_URL=\n\n",
        "a duplicate key between blank lines (difflib pairs the wrong blank line)":
            "DUO_ENABLED=false\n\nDUO_ENABLED=false\n\n\n",
        "the same between bare '#' lines": "# a\nDUO_ENABLED=false\n#\nDUO_ENABLED=false\n#\n#\n",
    }
    if example.exists():
        cases[".env.example plus the 12.6 empty key and a blank line"] = example.read_text() + "PUBLIC_BASE_URL=\n\n"
    for name, text in cases.items():
        plan = envfile.plan_up(text, vals)
        try:
            diff = plan.diff()
        except Lab5Error as exc:
            diff = f"RAISED {exc}"
        rows = [r for r in diff.splitlines() if r[:1] in "+-" and not r.startswith(("---", "+++"))]
        check(f"{name}: diff renders, only Lab 5 rows",
              rows and all(envfile.key_of(r[1:]) in envfile.LAB5_KEYS for r in rows)
              and envfile.other_lines(plan.new_text) == envfile.other_lines(text), diff)
        check(f"{name}: one + row per key set or added, credentials masked",
              sum(r.startswith("+") for r in rows) == len([c for c in plan.changes if c.action != "dedupe"])
              and "s3cr3t-value-abcdef" not in diff, diff)
    plan = envfile.plan_up("A=1\nPUBLIC_BASE_URL=\nB=2\nDUO_ENABLED=false\nDUO_ENABLED=x\nC=3", vals)
    check("hunk headers match a unified diff",
          plan.diff().splitlines()[2:] == ["@@ -2 +2 @@", "-PUBLIC_BASE_URL=(empty)",
                                           "+PUBLIC_BASE_URL=https://l5-acme-01.pseudocoassistant.com",
                                           "@@ -4,2 +4 @@", "-DUO_ENABLED=false", "-DUO_ENABLED=x", "+DUO_ENABLED=true",
                                           "@@ -6,0 +6,2 @@", "+DUO_CLIENT_SECRET=<...cdef>",
                                           "+HEC_HOST=l5-acme-01.pseudocoassistant.com",
                                           "(the file's last line gains its missing final newline)"], plan.diff())

    world = FakeWorld()
    box = world.boxes["01"]
    long_env = labs_env("01").decode("latin-1").replace("PUBLIC_BASE_URL=\n", "") + filler + "PUBLIC_BASE_URL=\n\n"
    box.files["/home/splunk/DemoBot/.env"] = (long_env.encode("latin-1"), 0o600)
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run_cli(world, Path(tmp), "check", "--only", "1")
        check("check on a long template .env: ready, with the diff, and agrees with up",
              rc == 0 and "ready, nothing to upgrade" in out and "+PUBLIC_BASE_URL=https://" in out, out)


def main() -> int:
    for test in (test_envfile, test_check_is_read_only, test_up_status_down, test_refusals,
                 test_down_without_record, test_preflight_gate_and_unreachable, test_failed_up_resumes,
                 test_wrong_password_and_cli, test_down_failures_are_failures, test_identity_values_and_rollback,
                 test_diff_on_long_env,
                 test_example_yaml, test_cloudflare_client, test_remote_helpers):
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(f"{test.__name__} raised {type(exc).__name__}", False, str(exc))
    print("== lazy imports ==")
    check("the suite ran without importing paramiko (the app venv must not need it)", "paramiko" not in sys.modules)
    print(f"\n{len(_failures)} failure(s)" if _failures else "\nALL PASS")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
