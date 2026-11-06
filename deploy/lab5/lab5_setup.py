#!/usr/bin/env python3
"""lab5-setup: turn Splunk Show boxes into Lab 5 instances, and back.

    lab5-setup check  workshop.yaml   read-only: what `up` would change, per box
    lab5-setup up     workshop.yaml   version check, backup, Lab 5 .env keys,
                                      tunnel + DNS, HEC host, restart, preflight
    lab5-setup status workshop.yaml   per-box preflight and Cloudflare state
    lab5-setup down   workshop.yaml   delete the workshop's tunnels and DNS
                                      records, revert the Lab 5 keys

Design: docs/identity-intelligence-lab-plan.md section 12.3 (and 12.1 for the
keys); operator guide: deploy/lab5/README.md. Runs on the facilitator's Mac.
There is no broker and no AWS: secrets come from the Mac's Keychain, what `up`
created is recorded under ~/.pseudoco-lab5/, and everything else lives in the
boxes, Duo and Cloudflare.

Rules it keeps (I4, I5 and the secrets rule):
  * only the Lab 5 keys change; every other .env line stays byte-for-byte, and
    the HEC host is merged into the existing destination (only `host` is sent);
  * .env and medadvice.db are backed up first, on the box, timestamped;
  * no code upgrade: a box below the required release is refused;
  * SSH passwords are asked once per box per run and never stored; Keychain
    values reach a box only as file content over SSH, never in argv or output.
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import secrets
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab5_envfile as envfile  # noqa: E402
from lab5_cloudflare import CloudflareAPI, urllib_transport  # noqa: E402
from lab5_common import (Keychain, Lab5Error, Redactor, Reporter, StateStore, last4,  # noqa: E402
                         parse_version, utc_now, utc_stamp, version_at_least)
import lab5_remote as remote  # noqa: E402

DEFAULT_ZONE = "pseudocoassistant.com"
DEFAULT_REQUIRED_VERSION = "4.22.0"     # 12.6: the first tag with PR-1/PR-2, at least v4.22.0
DEFAULT_TRUSTED = ("marcus.bell", "elena.sousa", "grace.lin")   # 4.3 cast
CLOUDFLARE_ITEM = "pseudoco-lab5-cloudflare"
# .env key -> Keychain item (service name). workshop.yaml `keychain:` overrides any of them.
DEFAULT_KEYCHAIN: Dict[str, str] = {
    "DUO_CLIENT_ID": "pseudoco-lab5-duo-websdk-client-id",
    "DUO_CLIENT_SECRET": "pseudoco-lab5-duo-websdk-client-secret",
    "DUO_API_HOST": "pseudoco-lab5-duo-websdk-api-host",
    "DUO_ADMIN_IKEY": "pseudoco-lab5-duo-status-ikey",
    "DUO_ADMIN_SKEY": "pseudoco-lab5-duo-status-skey",
    "CII_CLIENT_ID": "pseudoco-lab5-cii-client-id",
    "CII_CLIENT_SECRET": "pseudoco-lab5-cii-client-secret",
    "CII_TOKEN_URL": "pseudoco-lab5-cii-token-url",
    "CII_API_URL": "pseudoco-lab5-cii-api-url",
}
IDENTITY_KEYS = {"session_ttl_minutes": "IDENTITY_SESSION_TTL_MINUTES",
                 "status_ttl_seconds": "IDENTITY_STATUS_TTL_SECONDS",
                 "fail_open": "IDENTITY_FAIL_OPEN"}
# Lab 5 credentials whose presence in a leftover backup is scrubbed by `down`.
SECRET_KEYS = ("DUO_CLIENT_SECRET", "DUO_ADMIN_SKEY", "CII_CLIENT_SECRET")

_WORKSHOP_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?$")
_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


# =========================================================================== config
@dataclass
class BoxSpec:
    instance: int
    host: str
    port: int = 2222
    user: str = "splunk"
    checkout: str = "/home/splunk/DemoBot"
    app_unit: str = "demobot-app"
    app_port: int = 8001

    @property
    def nn(self) -> str:
        return f"{self.instance:02d}"

    @property
    def ssh_label(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"


@dataclass
class Workshop:
    name: str
    hec_url: str
    victim: str
    boxes: List[BoxSpec]
    zone: str = DEFAULT_ZONE
    required_version: str = DEFAULT_REQUIRED_VERSION
    hec_token_item: str = ""
    fallback: str = ""
    trusted: List[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED))
    identity: Dict[str, str] = field(default_factory=dict)
    keychain: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_KEYCHAIN))
    cloudflare_item: str = CLOUDFLARE_ITEM
    account_id: str = ""
    zone_id: str = ""
    tunnel_protocol: str = ""
    concurrency: int = 4

    def tunnel_name(self, box: BoxSpec) -> str:
        return f"l5-{self.name}-{box.nn}"

    def hostname(self, box: BoxSpec) -> str:
        return f"{self.tunnel_name(box)}.{self.zone}"


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise Lab5Error(f"workshop.yaml: {msg}")


def workshop_from_dict(doc: Dict[str, Any]) -> Workshop:
    _require(isinstance(doc, dict), "the top level must be a mapping")
    name = str(doc.get("workshop") or "")
    _require(bool(_WORKSHOP_RE.match(name)),
             "`workshop` must be lowercase letters, digits and '-', at most 50 characters "
             "(it becomes the l5-<workshop>-<nn> hostname label)")
    stack = doc.get("stack") or {}
    room = doc.get("room") or {}
    hec_url = str(stack.get("hec_url") or "")
    _require(hec_url.lower().startswith("https://"), "`stack.hec_url` must be the room stack's https HEC URL")
    victim = str(room.get("victim") or "")
    _require(bool(_USER_RE.match(victim)), "`room.victim` must be a persona username")
    trusted = [str(u) for u in (room.get("trusted") or DEFAULT_TRUSTED)]
    fallback = str(room.get("fallback") or "")
    for user in trusted + ([fallback] if fallback else []):
        _require(bool(_USER_RE.match(user)), f"persona username {user!r} is not valid")
    _require(victim not in trusted, "the victim cannot also be a trusted persona")

    defaults = doc.get("defaults") or {}
    boxes: List[BoxSpec] = []
    for row in doc.get("boxes") or []:
        _require(isinstance(row, dict) and "instance" in row and "host" in row,
                 "every `boxes` row needs `instance` and `host`")
        spec = BoxSpec(instance=int(row["instance"]), host=str(row["host"]))
        for attr in ("port", "user", "checkout", "app_unit", "app_port"):
            value = row.get(attr, defaults.get(attr))
            if value is not None:
                setattr(spec, attr, int(value) if attr in ("port", "app_port") else str(value))
        _require(1 <= spec.instance <= 99, f"instance {spec.instance} must be 1-99")
        boxes.append(spec)
    _require(bool(boxes), "list at least one box under `boxes`")
    numbers = [b.instance for b in boxes]
    _require(len(numbers) == len(set(numbers)), "instance numbers must be unique")

    keychain = dict(DEFAULT_KEYCHAIN)
    overrides = dict(doc.get("keychain") or {})
    cloudflare_item = str(overrides.pop("cloudflare", CLOUDFLARE_ITEM))
    for key, item in overrides.items():
        _require(key in DEFAULT_KEYCHAIN, f"`keychain.{key}` is not a Lab 5 credential key")
        keychain[key] = str(item)

    identity: Dict[str, str] = {}
    for yaml_key, env_key in IDENTITY_KEYS.items():
        value = (doc.get("identity") or {}).get(yaml_key)
        if value is not None:
            identity[env_key] = ("true" if value else "false") if isinstance(value, bool) else str(value)

    cloudflare = doc.get("cloudflare") or {}
    required = str(doc.get("required_version") or DEFAULT_REQUIRED_VERSION)
    _require(parse_version(required) is not None, "`required_version` must look like 4.22.0")
    protocol = str(cloudflare.get("tunnel_protocol") or "")
    _require(protocol in ("", "auto", "http2", "quic"), "`cloudflare.tunnel_protocol` is auto, http2 or quic")
    return Workshop(
        name=name, hec_url=hec_url, victim=victim, boxes=sorted(boxes, key=lambda b: b.instance),
        zone=str(doc.get("zone") or DEFAULT_ZONE), required_version=required,
        hec_token_item=str(stack.get("hec_token_item") or ""), fallback=fallback, trusted=trusted,
        identity=identity, keychain=keychain, cloudflare_item=cloudflare_item,
        account_id=str(cloudflare.get("account_id") or ""), zone_id=str(cloudflare.get("zone_id") or ""),
        tunnel_protocol="" if protocol == "auto" else protocol,
        concurrency=max(1, int(doc.get("concurrency") or 4)),
    )


def load_workshop(path: Path) -> Workshop:
    try:
        import yaml  # lazy: deploy/lab5/requirements.txt
    except ImportError:
        raise Lab5Error("PyYAML is not installed: pip install -r deploy/lab5/requirements.txt")
    try:
        doc = yaml.safe_load(Path(path).read_text())
    except OSError as exc:
        raise Lab5Error(f"cannot read {path}: {exc.strerror}")
    return workshop_from_dict(doc or {})


def normalize_hec_url(url: str) -> str:
    """Same rule as backend/hec/client.normalize_hec_url, so a destination
    entered as https://host:8088 matches the room's .../services/collector/event."""
    from urllib.parse import urlsplit
    parts = urlsplit((url or "").strip())
    path = parts.path.rstrip("/")
    if not path:
        path = "/services/collector/event"
    elif path.endswith("/services/collector"):
        path += "/event"
    netloc = parts.netloc.lower()
    if netloc.endswith(":443"):
        netloc = netloc[:-4]
    return f"{parts.scheme.lower()}://{netloc}{path}"


# =========================================================================== hooks
# Participant accounts (12.2) and `expire` land in the next stage. These are
# the seams they plug into; today they add nothing and say so.
def participant_username(ws: Workshop, box: BoxSpec) -> Optional[str]:
    """This instance's participant account, once 12.2 creates them."""
    return None


def allowed_users(ws: Workshop, box: BoxSpec) -> List[str]:
    """IDENTITY_ALLOWED_USERS: trusted personas, the room's victim and this
    instance's participant account (12.1). The fallback victim is not on it:
    swapping victims is an edit of `room.victim` and a re-run of `up`."""
    users = list(ws.trusted) + [ws.victim]
    participant = participant_username(ws, box)
    if participant:
        users.append(participant)
    return list(dict.fromkeys(users))


def create_participants(ctx: "Ctx", reports: List["BoxReport"]) -> None:
    ctx.out.line("participant accounts + handout: not built yet (next stage, 12.2); nothing created")


def victim_blocked(ctx: "Ctx", box: BoxSpec, app: Optional[remote.AppClient]) -> Tuple[str, str]:
    return "SKIP", "victim-blocked self-check arrives with the identity gate (next stage)"


def room_checks(ctx: "Ctx") -> List[Tuple[str, str, str]]:
    return [("SKIP", "room", "victim failing in CII / its events in the stack: next stage")]


# =========================================================================== runtime
@dataclass
class BoxReport:
    box: BoxSpec
    hostname: str
    steps: List[Tuple[str, str, str]] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.steps.append((status, name, detail))

    def block(self, reason: str) -> None:
        self.blockers.append(reason)
        self.add("FAIL", "blocked", reason)

    @property
    def failed(self) -> bool:
        return any(status == "FAIL" for status, _, _ in self.steps)

    def render(self) -> str:
        lines = [f"== box {self.box.nn}  {self.box.ssh_label} -> {self.hostname} =="]
        for status, name, detail in self.steps:
            lines.append(f"  {status:<8} {name:<12} {detail}".rstrip())
        for block in self.extra:
            lines.extend("      " + row for row in block.splitlines())
        return "\n".join(lines)


@dataclass
class Facts:
    home: str = ""
    env_text: Optional[str] = None
    env_mode: Optional[int] = None
    access_key: str = ""
    health_version: Optional[str] = None
    code_version: Optional[str] = None
    env_pin: Optional[str] = None
    db_path: str = ""
    app: Optional[remote.AppClient] = None
    dest: Optional[Dict[str, Any]] = None
    cloudflared: Optional[str] = None


@dataclass
class Ctx:
    ws: Workshop
    state: StateStore
    keychain: Keychain
    redactor: Redactor
    out: Reporter
    connect: Callable[[BoxSpec, str], Any]
    https: Callable[[str, str, Dict[str, str]], Tuple[int, bytes]]
    resolve: Callable[[str], List[str]]
    passwords: Dict[str, str] = field(default_factory=dict)
    creds: Dict[str, str] = field(default_factory=dict)
    cloudflare: Optional[CloudflareAPI] = None
    zone_id: str = ""
    account_id: str = ""
    sleep: Callable[[float], None] = time.sleep
    app_wait_s: float = 120.0
    preflight_wait_s: float = 150.0
    force_restart: bool = False


def lab5_values(ws: Workshop, box: BoxSpec, creds: Dict[str, str]) -> Dict[str, str]:
    """Every Lab 5 key `up` writes for this box (12.1)."""
    host = ws.hostname(box)
    values = {"PUBLIC_BASE_URL": f"https://{host}", "DUO_ENABLED": "true"}
    values.update({key: creds[key] for key in DEFAULT_KEYCHAIN})
    values["IDENTITY_ALLOWED_USERS"] = ",".join(allowed_users(ws, box))
    values.update(ws.identity)
    values["HEC_HOST"] = host
    return values


def _code_version(config_py: Optional[bytes]) -> Optional[str]:
    m = re.search(rb'app_version:\s*str\s*=\s*"([^"]+)"', config_py or b"")
    return m.group(1).decode() if m else None


def _db_path(checkout: str, env_lines: List[str]) -> str:
    url = envfile.get(env_lines, "DATABASE_URL") or "sqlite:///./medadvice.db"
    if not url.startswith("sqlite:///"):
        return ""
    path = url[len("sqlite:///"):]
    if path.startswith("/"):
        return path
    return f"{checkout}/{path[2:] if path.startswith('./') else path}"


def inspect_box(ctx: Ctx, rem: Any, box: BoxSpec, rep: BoxReport, full: bool = True) -> Facts:
    """Read-only facts about one box. Anything that makes `up` unsafe is a
    blocker on the report; nothing here changes the box."""
    ws, facts = ctx.ws, Facts()
    facts.home = rem.run(["sh", "-c", 'printf %s "$HOME"']).out.strip() or f"/home/{box.user}"
    env_path = f"{box.checkout}/.env"
    raw = rem.read_file(env_path)
    if raw is None:
        rep.block(f"{env_path} not found (is `checkout` right for this box?)")
        return facts
    facts.env_text = envfile.decode(raw)
    facts.env_mode = rem.file_mode(env_path)
    lines = envfile.split_lines(facts.env_text)
    facts.access_key = envfile.get(lines, "ACCESS_KEY") or ""
    ctx.redactor.add(facts.access_key)
    facts.env_pin = envfile.get(lines, "APP_VERSION")
    facts.db_path = _db_path(box.checkout, lines)
    facts.code_version = _code_version(rem.read_file(f"{box.checkout}/backend/config.py"))
    facts.app = remote.AppClient(rem, facts.access_key, box.app_port)

    try:
        facts.health_version = str(facts.app.health().get("version") or "")
    except Lab5Error as exc:
        rep.block(f"the app does not answer /health on the box ({exc})")
        return facts
    need = ws.required_version
    if version_at_least(facts.health_version, need):
        rep.add("OK", "version", f"/health {facts.health_version} (code {facts.code_version or '?'}) >= {need}")
    else:
        why = ""
        if facts.code_version and version_at_least(facts.code_version, need):
            why = (f"; the code is {facts.code_version}, so the running app is stale or .env pins "
                   f"APP_VERSION={facts.env_pin}")
        rep.block(f"the box runs {facts.health_version or '?'}{why}. Lab 5 needs {need} or later, and "
                  f"`up` never upgrades code (I5): the Show template needs that release (12.6)")
    if not full:
        return facts

    if rem.run(["true"], sudo=True).rc != 0:
        rep.block(f"`sudo -n` does not work for {box.user}; Show boxes are expected to have passwordless sudo")
    facts.cloudflared = remote.find_cloudflared(rem)
    if not facts.cloudflared:
        rep.block("cloudflared is not installed; the Show template installs it, without a tunnel (12.6)")
    if rem.run(["systemctl", "cat", box.app_unit]).rc != 0:
        rep.block(f"systemd unit {box.app_unit} not found")

    try:
        dests = facts.app.destinations()
    except Lab5Error as exc:
        rep.block(f"cannot read HEC destinations through the Settings API ({exc})")
        return facts
    want = normalize_hec_url(ws.hec_url)
    matching = [d for d in dests if d.get("url") and normalize_hec_url(str(d["url"])) == want]
    if not matching:
        seen = ", ".join(sorted({str(d.get("url") or "(no url)") for d in dests})) or "none"
        rep.block(f"no HEC destination on the box sends to the room stack {ws.hec_url} (it has: {seen}); "
                  "`up` only merges the host into an existing destination, it never adds or repoints one")
    elif len(matching) > 1:
        rep.block("several HEC destinations send to the room stack ("
                  + ", ".join(str(d.get("id")) for d in matching) + "); keep one")
    else:
        facts.dest = matching[0]
        if not facts.dest.get("enabled"):
            rep.add("WARN", "HEC", f"destination {facts.dest.get('id')} is disabled")
        if ws.hec_token_item:
            token = ctx.keychain.get(ws.hec_token_item)
            box_last4 = str(facts.dest.get("token_last4") or "")
            if not token:
                rep.add("WARN", "HEC", f"Keychain item {ws.hec_token_item} is missing; token not compared")
            elif box_last4 != token[-4:]:
                rep.add("WARN", "HEC", f"destination token ends {box_last4 or '(none)'}, the room's HEC token "
                                       f"({ws.hec_token_item}) ends {token[-4:]}")
    return facts


def cloudflare_view(ctx: Ctx, box: BoxSpec, record: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only: what exists in Cloudflare for this box, and what `up` would do."""
    ws, cf = ctx.ws, ctx.cloudflare
    name, fqdn = ws.tunnel_name(box), ws.hostname(box)
    view: Dict[str, Any] = {"tunnel_id": "", "tunnel_action": "create", "dns_id": "",
                            "dns_action": "create", "conflicts": []}
    rec_t = record.get("tunnel") or {}
    if rec_t.get("id") and not rec_t.get("deleted"):
        if cf.get_tunnel(ctx.account_id, rec_t["id"]):
            view.update(tunnel_id=rec_t["id"], tunnel_action="reuse")
    if view["tunnel_action"] == "create":
        found = cf.find_tunnels(ctx.account_id, name)
        if found:
            view["conflicts"].append(
                f"tunnel {name} ({found[0].get('id')}) exists in Cloudflare but {ctx.state.dir} has no "
                "record of `up` creating it; delete it (Zero Trust > Networks > Tunnels) or restore the record")
    rec_d = record.get("dns") or {}
    if rec_d.get("id") and not rec_d.get("deleted"):
        current = cf.get_record(ctx.zone_id, rec_d["id"])
        if current:
            target = f"{view['tunnel_id']}.cfargotunnel.com"
            ok = view["tunnel_id"] and current.get("content") == target and current.get("proxied")
            view.update(dns_id=rec_d["id"], dns_action="ok" if ok else "update")
    if view["dns_action"] == "create":
        found = cf.find_records(ctx.zone_id, fqdn)
        if found:
            view["conflicts"].append(
                f"DNS record {fqdn} exists but {ctx.state.dir} has no record of `up` creating it; "
                "delete it in the dashboard or restore the record")
    return view


def check_box(ctx: Ctx, box: BoxSpec) -> BoxReport:
    """`check`: everything `up` would read and decide, changing nothing."""
    ws = ctx.ws
    rep = BoxReport(box, ws.hostname(box))
    record = ctx.state.load_box(box.nn)
    try:
        rem = ctx.connect(box, ctx.passwords.get(box.nn, ""))
    except Lab5Error as exc:
        rep.add("FAIL", "ssh", str(exc))
        return rep
    try:
        for note in getattr(rem, "notes", []):
            rep.add("OK", "host key", note)
        facts = inspect_box(ctx, rem, box, rep)
        if facts.env_text is not None:
            plan = envfile.plan_up(facts.env_text, lab5_values(ws, box, ctx.creds))
            if plan.changed:
                rep.add("PLAN", ".env", f"{len(plan.changes)} Lab 5 change(s) below; every other line stays byte-for-byte")
                rep.extra.append(plan.diff(f"{box.checkout}/.env"))
            else:
                rep.add("OK", ".env", "the Lab 5 keys already match workshop.yaml")
        if facts.dest:
            old = facts.dest.get("host")
            if old == rep.hostname:
                rep.add("OK", "HEC host", f"destination {facts.dest.get('id')} already stamps {old}")
            else:
                rep.add("PLAN", "HEC host", f"destination {facts.dest.get('id')}: host {old!r} -> "
                                            f"{rep.hostname!r}; every other field stays as it is")
        rep.add("PLAN", "backup", f".env and {facts.db_path or 'medadvice.db'} -> "
                                  f"{facts.home}/.pseudoco-lab5/backups/{ws.name}-<UTC stamp>/")
        view = cloudflare_view(ctx, box, record)
        for conflict in view["conflicts"]:
            rep.block(conflict)
        rep.add("PLAN" if view["tunnel_action"] == "create" else "OK", "tunnel",
                f"{view['tunnel_action']} {ws.tunnel_name(box)} -> http://localhost:{box.app_port}")
        rep.add("PLAN" if view["dns_action"] != "ok" else "OK", "dns",
                f"{view['dns_action']} proxied CNAME {rep.hostname}")
        if facts.cloudflared:
            present = remote.connector_present(rem)
            rep.add("OK" if present else "PLAN", "connector",
                    f"{remote.UNIT_NAME} {'installed' if present else 'to install'} ({facts.cloudflared})")
        if rep.blockers:
            rep.add("FAIL", "verdict", "not ready: " + "; ".join(rep.blockers))
        else:
            rep.add("OK", "verdict", "ready, nothing to upgrade")
    except Lab5Error as exc:
        rep.add("FAIL", "check", str(exc))
    finally:
        rem.close()
    return rep


# =========================================================================== up
def new_record(ws: Workshop, box: BoxSpec) -> Dict[str, Any]:
    return {"workshop": ws.name, "instance": box.instance, "hostname": ws.hostname(box),
            "tunnel_name": ws.tunnel_name(box), "created_at": utc_now(), "backups": [], "history": []}


def make_backup(ctx: Ctx, rem: Any, box: BoxSpec, facts: Facts, rep: BoxReport) -> Dict[str, str]:
    # Unique per run, created with mkdir (not -p) so an existing backup is never reused.
    bdir = f"{facts.home}/.pseudoco-lab5/backups/{ctx.ws.name}-{utc_stamp()}-{secrets.token_hex(3)}"
    rem.run(["sh", "-c", 'umask 077 && mkdir -p "$(dirname "$1")" && mkdir "$1"', "lab5-mkdir", bdir], check=True)
    rem.write_file_atomic(f"{bdir}/.env", envfile.encode(facts.env_text or ""), 0o600)
    backup = {"at": utc_now(), "dir": bdir, "env": f"{bdir}/.env", "db": ""}
    if facts.db_path and rem.file_mode(facts.db_path) is not None:
        argv, script = remote.backup_db_command(facts.db_path, f"{bdir}/medadvice.db")
        res = rem.run(argv, stdin=script)
        if res.rc != 0:
            raise Lab5Error(f"backing up {facts.db_path} failed: {res.err.strip()[-200:]}")
        backup["db"] = f"{bdir}/medadvice.db"
    else:
        rep.add("WARN", "backup", f"no database at {facts.db_path or '(DATABASE_URL is not sqlite)'}")
    rep.add("CHANGED", "backup", f".env{' + ' + Path(facts.db_path).name if backup['db'] else ''} -> {bdir}/")
    return backup


def _write_env(rem: Any, box: BoxSpec, facts: Facts, new_text: str) -> None:
    env_path = f"{box.checkout}/.env"
    current = rem.read_file(env_path)
    if current is None or envfile.decode(current) != facts.env_text:
        raise Lab5Error(f"{env_path} changed on the box while lab5-setup was running; nothing written, re-run")
    rem.write_file_atomic(env_path, envfile.encode(new_text), facts.env_mode or 0o600)


def apply_env(ctx: Ctx, rem: Any, box: BoxSpec, facts: Facts, record: Dict[str, Any],
              backup: Dict[str, str], rep: BoxReport) -> bool:
    plan = envfile.plan_up(facts.env_text or "", lab5_values(ctx.ws, box, ctx.creds))
    env_rec = record.get("env") or {}
    if not env_rec.get("baseline") or env_rec.get("reverted"):
        # The baseline is the box BEFORE the first `up`; a re-run keeps it.
        record["env"] = {"baseline": envfile.baseline_of(facts.env_text or ""),
                         "baseline_backup": backup["env"], "recorded_at": utc_now(), "reverted": False}
        ctx.state.save_box(box.nn, record)
    if not plan.changed:
        rep.add("OK", ".env", "the Lab 5 keys already match workshop.yaml")
        return False
    _write_env(rem, box, facts, plan.new_text)
    rep.add("CHANGED", ".env", ", ".join(f"{c.action} {c.key}" for c in plan.changes)
            + "; every other line unchanged")
    return True


def _ingress_ok(ingress: List[Dict[str, Any]], hostname: str, service: str) -> bool:
    return (len(ingress) >= 2 and ingress[0].get("hostname") == hostname
            and ingress[0].get("service") == service and "hostname" not in ingress[-1])


def apply_tunnel(ctx: Ctx, rem: Any, box: BoxSpec, facts: Facts, record: Dict[str, Any],
                 view: Dict[str, Any], rep: BoxReport) -> None:
    ws, cf = ctx.ws, ctx.cloudflare
    name, fqdn = ws.tunnel_name(box), ws.hostname(box)
    tunnel_id = view["tunnel_id"]
    if tunnel_id:
        rep.add("OK", "tunnel", f"{name} ({tunnel_id})")
    else:
        tunnel_id = cf.create_tunnel(ctx.account_id, name)
        record["tunnel"] = {"id": tunnel_id, "name": name, "created_at": utc_now(), "deleted": False}
        ctx.state.save_box(box.nn, record)       # recorded before anything else can fail
        rep.add("CHANGED", "tunnel", f"created {name} ({tunnel_id})")
    service = f"http://localhost:{box.app_port}"
    if _ingress_ok(cf.tunnel_ingress(ctx.account_id, tunnel_id), fqdn, service):
        rep.add("OK", "ingress", f"{fqdn} -> {service}")
    else:
        cf.set_tunnel_ingress(ctx.account_id, tunnel_id, fqdn, service)
        rep.add("CHANGED", "ingress", f"{fqdn} -> {service}")
    token = cf.tunnel_token(ctx.account_id, tunnel_id)
    ctx.redactor.add(token)
    changed = remote.connector_install(rem, facts.cloudflared or "/usr/bin/cloudflared", ws.name, box.nn,
                                       name, token, ws.tunnel_protocol)
    record["connector"] = {"unit": remote.UNIT_NAME, "token_file": remote.TOKEN_ENV_PATH, "installed": True}
    ctx.state.save_box(box.nn, record)
    rep.add("CHANGED" if changed else "OK", "connector",
            f"{remote.UNIT_NAME} active" + (f" ({', '.join(changed)})" if changed else ""))
    target = f"{tunnel_id}.cfargotunnel.com"
    if view["dns_id"] and view["dns_action"] == "ok":
        rep.add("OK", "dns", f"{fqdn} -> {target} (proxied)")
    elif view["dns_id"]:
        cf.update_cname(ctx.zone_id, view["dns_id"], target)
        rep.add("CHANGED", "dns", f"{fqdn} -> {target} (proxied)")
    else:
        record_id = cf.create_cname(ctx.zone_id, fqdn, target, f"lab5-setup workshop={ws.name} box={box.nn}")
        record["dns"] = {"id": record_id, "name": fqdn, "created_at": utc_now(), "deleted": False}
        ctx.state.save_box(box.nn, record)
        rep.add("CHANGED", "dns", f"created {fqdn} -> {target} (proxied)")


def apply_hec_host(ctx: Ctx, box: BoxSpec, facts: Facts, record: Dict[str, Any], rep: BoxReport) -> bool:
    dest, app, want = facts.dest or {}, facts.app, rep.hostname
    dest_id, old = str(dest.get("id")), dest.get("host")
    hec = record.get("hec") or {}
    if not hec.get("destination_id") or hec.get("reverted"):
        record["hec"] = {"destination_id": dest_id, "prior_host": old, "set_host": want, "reverted": False}
        ctx.state.save_box(box.nn, record)
    if old == want:
        rep.add("OK", "HEC host", f"destination {dest_id} already stamps {want}")
        return False
    app.set_destination_host(dest_id, want)
    after = app.destination(dest_id)
    drift = sorted(k for k in set(dest) | set(after) if k != "host" and dest.get(k) != after.get(k))
    if after.get("host") != want:
        raise Lab5Error(f"destination {dest_id} did not take the new host")
    if drift:
        rep.add("FAIL", "HEC host", f"destination {dest_id}: fields other than host changed: {', '.join(drift)}")
    else:
        rep.add("CHANGED", "HEC host", f"destination {dest_id}: {old!r} -> {want!r}; every other field unchanged")
    return True


def restart_app(ctx: Ctx, rem: Any, box: BoxSpec, app: remote.AppClient, rep: BoxReport) -> None:
    rem.run(["systemctl", "restart", box.app_unit], sudo=True, check=True)
    deadline = time.monotonic() + ctx.app_wait_s
    while True:
        try:
            version = app.health().get("version")
            rep.add("CHANGED", "restart", f"{box.app_unit} restarted; local /health {version}")
            return
        except Lab5Error:
            if time.monotonic() >= deadline:
                raise Lab5Error(f"{box.app_unit} did not answer /health within {int(ctx.app_wait_s)} s "
                                "of the restart; see `journalctl -u` on the box")
            ctx.sleep(2.0)


def _preflight_once(ctx: Ctx, box: BoxSpec, host: str, key: Optional[str]) -> List[Tuple[str, str, str]]:
    need = ctx.ws.required_version
    try:
        addrs = ctx.resolve(host)
    except OSError:
        addrs = []
    if not addrs:
        return [("FAIL", "dns", f"{host} does not resolve from this Mac yet")]
    rows = [("OK", "dns", f"{host} -> {', '.join(addrs[:2])}")]
    try:
        status, body = ctx.https("GET", f"https://{host}/health", {})
        version = str(json.loads(body or b"{}").get("version") or "") if status == 200 else ""
        if status != 200:
            rows.append(("FAIL", "https", f"https://{host}/health: HTTP {status}"))
        elif not version_at_least(version, need):
            rows.append(("FAIL", "https", f"/health reports {version or '?'}, below {need}: "
                                          f"the Show template needs {need} or later (12.6)"))
        else:
            rows.append(("OK", "https", f"https://{host}/health {version}"))
    except (Lab5Error, ValueError) as exc:
        rows.append(("FAIL", "https", f"https://{host}/health: {exc}"))
        return rows
    if key is None:
        rows.append(("SKIP", "duo_signin", "needs the box's ACCESS_KEY (SSH was not available)"))
        return rows
    try:
        status, body = ctx.https("GET", f"https://{host}/api/server-info",
                                 {"X-Access-Key": key} if key else {})
        gate = (json.loads(body or b"{}").get("gated") or {}).get("duo_signin") if status == 200 else None
        if status != 200:
            rows.append(("FAIL", "duo_signin", f"/api/server-info: HTTP {status}"))
        elif gate is None:
            rows.append(("FAIL", "duo_signin", f"/api/server-info has no gated.duo_signin: this release has "
                                               f"no Duo sign-in; the Show template needs {need} (12.6)"))
        elif not gate.get("enabled"):
            rows.append(("FAIL", "duo_signin", f"gated: {gate.get('reason') or 'no reason given'}"))
        else:
            rows.append(("OK", "duo_signin", "not gated"))
    except (Lab5Error, ValueError) as exc:
        rows.append(("FAIL", "duo_signin", f"/api/server-info: {exc}"))
    return rows


def preflight(ctx: Ctx, box: BoxSpec, key: Optional[str], rep: BoxReport, wait: bool) -> None:
    """12.3 preflight, through the public name: DNS resolves, https /health
    is at least the required release, and gated.duo_signin is enabled."""
    deadline = time.monotonic() + (ctx.preflight_wait_s if wait else 0)
    while True:
        rows = _preflight_once(ctx, box, rep.hostname, key)
        if all(status != "FAIL" for status, _, _ in rows) or time.monotonic() >= deadline:
            break
        ctx.sleep(5.0)
    for row in rows:
        rep.add(*row)


def up_box(ctx: Ctx, box: BoxSpec) -> BoxReport:
    ws = ctx.ws
    rep = BoxReport(box, ws.hostname(box))
    record = ctx.state.load_box(box.nn) or new_record(ws, box)
    record["ssh"] = {"host": box.host, "port": box.port, "user": box.user}
    try:
        rem = ctx.connect(box, ctx.passwords.get(box.nn, ""))
    except Lab5Error as exc:
        rep.add("FAIL", "ssh", str(exc))
        return rep
    try:
        for note in getattr(rem, "notes", []):
            rep.add("OK", "host key", note)
        facts = inspect_box(ctx, rem, box, rep)
        view = cloudflare_view(ctx, box, record) if not rep.blockers else {"conflicts": []}
        for conflict in view["conflicts"]:
            rep.block(conflict)
        if rep.blockers:
            rep.add("FAIL", "up", "refused before changing anything on this box")
            return rep
        backup = make_backup(ctx, rem, box, facts, rep)
        record.setdefault("backups", []).append(backup)
        ctx.state.save_box(box.nn, record)
        if apply_env(ctx, rem, box, facts, record, backup, rep):
            record["restart_pending"] = True      # survives a failure below: the next run restarts
            ctx.state.save_box(box.nn, record)
        apply_tunnel(ctx, rem, box, facts, record, view, rep)
        apply_hec_host(ctx, box, facts, record, rep)
        if record.get("restart_pending") or ctx.force_restart:
            restart_app(ctx, rem, box, facts.app, rep)
            record["restart_pending"] = False
            ctx.state.save_box(box.nn, record)
        else:
            rep.add("OK", "restart", "not needed: .env unchanged (--restart forces one)")
        preflight(ctx, box, facts.access_key, rep, wait=True)
    except Lab5Error as exc:
        rep.add("FAIL", "up", str(exc))
    finally:
        rem.close()
        if record.get("tunnel") or record.get("env") or record.get("backups"):
            record.setdefault("history", []).append({"at": utc_now(), "command": "up", "ok": not rep.failed})
            ctx.state.save_box(box.nn, record)
    return rep


# =========================================================================== status
def status_box(ctx: Ctx, box: BoxSpec) -> BoxReport:
    ws, cf = ctx.ws, ctx.cloudflare
    rep = BoxReport(box, ws.hostname(box))
    record = ctx.state.load_box(box.nn)
    rec_t, rec_d = record.get("tunnel") or {}, record.get("dns") or {}
    if rec_t.get("id") and not rec_t.get("deleted"):
        tunnel = cf.get_tunnel(ctx.account_id, rec_t["id"])
        state = (tunnel or {}).get("status") or "missing"
        rep.add("OK" if state == "healthy" else "FAIL", "tunnel", f"{rec_t.get('name')} ({rec_t['id']}): {state}")
    else:
        rep.add("FAIL", "tunnel", "no tunnel recorded for this box (run up)")
    if rec_d.get("id") and not rec_d.get("deleted"):
        dns = cf.get_record(ctx.zone_id, rec_d["id"])
        ok = dns and dns.get("content") == f"{rec_t.get('id')}.cfargotunnel.com" and dns.get("proxied")
        rep.add("OK" if ok else "FAIL", "dns record", f"{rep.hostname} -> {(dns or {}).get('content', 'missing')}")
    key: Optional[str] = None
    try:
        rem = ctx.connect(box, ctx.passwords.get(box.nn, ""))
    except Lab5Error as exc:
        rep.add("WARN", "ssh", str(exc))
        rem = None
    if rem is not None:
        try:
            facts = inspect_box(ctx, rem, box, rep, full=False)
            key = facts.access_key
            if facts.env_text is not None:
                plan = envfile.plan_up(facts.env_text, lab5_values(ws, box, ctx.creds))
                rep.add("WARN" if plan.changed else "OK", ".env",
                        f"{len(plan.changes)} Lab 5 key(s) differ from workshop.yaml (re-run up)"
                        if plan.changed else "the Lab 5 keys match workshop.yaml")
            active = rem.run(["systemctl", "is-active", remote.UNIT_NAME]).out.strip()
            rep.add("OK" if active == "active" else "FAIL", "connector", f"{remote.UNIT_NAME}: {active or 'unknown'}")
            dests = facts.app.destinations() if facts.app and facts.health_version else []
            hosts = [str(d.get("host")) for d in dests
                     if d.get("url") and normalize_hec_url(str(d["url"])) == normalize_hec_url(ws.hec_url)]
            rep.add("OK" if hosts == [rep.hostname] else "WARN", "HEC host", ", ".join(hosts) or "no room destination")
            v_status, v_detail = victim_blocked(ctx, box, facts.app)
            rep.add(v_status, "victim", v_detail)
        except Lab5Error as exc:
            rep.add("FAIL", "status", str(exc))
        finally:
            rem.close()
    preflight(ctx, box, key, rep, wait=False)
    return rep


# =========================================================================== down
def _no_record_baseline(text: str) -> Dict[str, Dict[str, object]]:
    """No record of `up`: keep a Lab 5 key that is absent or empty (the 12.6
    template state) and remove one that holds a value."""
    lines = envfile.split_lines(text)
    out: Dict[str, Dict[str, object]] = {}
    for key in envfile.LAB5_KEYS:
        live = [line for line in lines if envfile.key_of(line) == key]
        out[key] = ({"present": True, "line": live[0]} if live and not envfile.value_of(live[0])
                    else {"present": False})
    return out


def _holds_lab5_secret(text: str) -> bool:
    lines = envfile.split_lines(text)
    return any(envfile.get(lines, key) for key in SECRET_KEYS)


def down_box(ctx: Ctx, box: BoxSpec) -> BoxReport:
    ws, cf = ctx.ws, ctx.cloudflare
    rep = BoxReport(box, ws.hostname(box))
    record = ctx.state.load_box(box.nn)
    had_record = bool(record)
    try:
        rem = ctx.connect(box, ctx.passwords.get(box.nn, ""))
    except Lab5Error as exc:
        rep.add("WARN", "ssh", f"{exc}: the box's .env, HEC host and connector are left as they are")
        rem = None
    if rem is not None:
        try:
            _down_on_box(ctx, rem, box, record, rep)
        except Lab5Error as exc:
            rep.add("FAIL", "box", str(exc))
        finally:
            rem.close()
    rec_d = record.get("dns") or {}
    if rec_d.get("id") and not rec_d.get("deleted"):
        gone = cf.delete_record(ctx.zone_id, rec_d["id"])
        rec_d.update(deleted=True, deleted_at=utc_now())
        ctx.state.save_box(box.nn, record)
        rep.add("CHANGED" if gone else "OK", "dns", f"{rec_d.get('name')} {'deleted' if gone else 'already gone'}")
    else:
        rep.add("OK", "dns", "nothing recorded to delete" if not rec_d else "already deleted")
    rec_t = record.get("tunnel") or {}
    if rec_t.get("id") and not rec_t.get("deleted"):
        gone = cf.delete_tunnel(ctx.account_id, rec_t["id"])
        rec_t.update(deleted=True, deleted_at=utc_now())
        ctx.state.save_box(box.nn, record)
        rep.add("CHANGED" if gone else "OK", "tunnel", f"{rec_t.get('name')} {'deleted' if gone else 'already gone'}")
    else:
        rep.add("OK", "tunnel", "nothing recorded to delete" if not rec_t else "already deleted")
    if had_record:
        record.setdefault("history", []).append({"at": utc_now(), "command": "down", "ok": not rep.failed})
        ctx.state.save_box(box.nn, record)
    return rep


def _down_on_box(ctx: Ctx, rem: Any, box: BoxSpec, record: Dict[str, Any], rep: BoxReport) -> None:
    removed = remote.connector_remove(rem)
    rep.add("CHANGED" if removed else "OK", "connector",
            f"removed {' and '.join(removed)}" if removed else "not installed")
    if record.get("connector"):
        record["connector"]["installed"] = False
    env_path = f"{box.checkout}/.env"
    raw = rem.read_file(env_path)
    facts = Facts(env_text=envfile.decode(raw) if raw is not None else None, env_mode=rem.file_mode(env_path))
    env_rec = record.get("env") or {}
    env_changed = False
    if facts.env_text is None:
        rep.add("WARN", ".env", f"{env_path} not found")
    else:
        baseline = env_rec.get("baseline") or _no_record_baseline(facts.env_text)
        backup_text = None
        if any(entry.get("secret") for entry in baseline.values()) and env_rec.get("baseline_backup"):
            data = rem.read_file(env_rec["baseline_backup"])
            backup_text = envfile.decode(data) if data is not None else None
        plan = envfile.plan_revert(facts.env_text, baseline, backup_text)
        for warning in plan.warnings:
            rep.add("WARN", ".env", warning)
        if plan.changed:
            _write_env(rem, box, facts, plan.new_text)
            env_changed = True
            if record:
                record["restart_pending"] = True
                ctx.state.save_box(box.nn, record)
            rep.add("CHANGED", ".env", "reverted " + ", ".join(sorted({c.key for c in plan.changes}))
                    + ("" if env_rec else " (no record of up: Lab 5 keys holding a value were removed)"))
        else:
            rep.add("OK", ".env", "the Lab 5 keys are already reverted")
        if env_rec:
            env_rec["reverted"] = True
            ctx.state.save_box(box.nn, record)
    hec = record.get("hec") or {}
    key = envfile.get(envfile.split_lines(facts.env_text or ""), "ACCESS_KEY") or ""
    ctx.redactor.add(key)
    if hec.get("destination_id") and not hec.get("reverted"):
        app = remote.AppClient(rem, key, box.app_port)
        dest_id = hec["destination_id"]
        try:
            current = app.destination(dest_id).get("host")
        except Lab5Error as exc:
            rep.add("WARN", "HEC host", f"destination {dest_id}: {exc}; left as it is")
        else:
            if current == hec.get("set_host"):
                app.set_destination_host(dest_id, str(hec.get("prior_host") or ""))
                rep.add("CHANGED", "HEC host", f"destination {dest_id}: {current!r} -> {hec.get('prior_host')!r}")
            elif current == hec.get("prior_host"):
                rep.add("OK", "HEC host", f"destination {dest_id} already back to {current!r}")
            else:
                rep.add("WARN", "HEC host", f"destination {dest_id} now says {current!r}, set after up; left as it is")
            hec["reverted"] = True
            ctx.state.save_box(box.nn, record)
    else:
        rep.add("OK", "HEC host", "already reverted" if hec else "no record of up setting it")
    scrubbed = []
    for backup in record.get("backups") or []:
        path = backup.get("env")
        if not path or path == env_rec.get("baseline_backup") or backup.get("scrubbed"):
            continue
        data = rem.read_file(path)
        if data is not None and _holds_lab5_secret(envfile.decode(data)):
            rem.run(["rm", "-f", path], check=True)
            backup["scrubbed"] = True
            scrubbed.append(path)
    if scrubbed:
        ctx.state.save_box(box.nn, record)
        rep.add("CHANGED", "backups", f"removed {len(scrubbed)} .env backup(s) that held Lab 5 credentials")
    if env_changed or record.get("restart_pending") or ctx.force_restart:
        rem.run(["systemctl", "restart", box.app_unit], sudo=True, check=True)
        rep.add("CHANGED", "restart", f"{box.app_unit} restarted")
        if record:
            record["restart_pending"] = False
            ctx.state.save_box(box.nn, record)


def workshop_orphans(ctx: Ctx) -> List[str]:
    """Tunnels and DNS records named for this workshop that no box record
    owns. Reported, never deleted: `down` deletes only what `up` recorded."""
    ws, cf = ctx.ws, ctx.cloudflare
    owned_t, owned_d = set(), set()
    for nn in ctx.state.recorded_boxes():
        rec = ctx.state.load_box(nn)
        if not (rec.get("tunnel") or {}).get("deleted"):
            owned_t.add((rec.get("tunnel") or {}).get("id"))
        if not (rec.get("dns") or {}).get("deleted"):
            owned_d.add((rec.get("dns") or {}).get("id"))
    pattern = re.compile(rf"^l5-{re.escape(ws.name)}-\d{{2}}(\.|$)")
    rows = [f"tunnel {t.get('name')} ({t.get('id')}) is not recorded here; left alone"
            for t in cf.tunnels_with_prefix(ctx.account_id, f"l5-{ws.name}-")
            if pattern.match(str(t.get("name") or "")) and t.get("id") not in owned_t]
    rows += [f"DNS record {r.get('name')} ({r.get('id')}) is not recorded here; left alone"
             for r in cf.records_with_prefix(ctx.zone_id, f"l5-{ws.name}-")
             if pattern.match(str(r.get("name") or "")) and r.get("id") not in owned_d]
    return rows


# =========================================================================== cli
@dataclass
class Deps:
    """Every outside effect, so the tests can swap in fakes."""
    connect: Optional[Callable[..., Any]] = None              # (box, password, ctx) -> box session
    cloudflare_transport: Callable[..., Tuple[int, bytes]] = urllib_transport
    keychain_runner: Optional[Callable[..., Any]] = None
    https: Optional[Callable[[str, str, Dict[str, str]], Tuple[int, bytes]]] = None
    resolve: Optional[Callable[[str], List[str]]] = None
    prompt: Callable[[str], str] = getpass.getpass
    state_root: Optional[Path] = None
    out: Any = None
    sleep: Callable[[float], None] = time.sleep
    app_wait_s: float = 120.0
    preflight_wait_s: float = 150.0


def _resolve(host: str) -> List[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})


def _https(method: str, url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
    return urllib_transport(method, url, dict(headers, **{"User-Agent": "lab5-setup"}), None, 20.0)


def ask_passwords(boxes: Sequence[BoxSpec], prompt: Callable[[str], str], redactor: Redactor) -> Dict[str, str]:
    """Once per box, before any work starts (the boxes then run in parallel).
    Enter reuses the previous box's password: Show often sets one per workshop."""
    passwords: Dict[str, str] = {}
    previous = ""
    for box in boxes:
        hint = " [Enter: same as the previous box]" if previous else ""
        password = prompt(f"SSH password for {box.ssh_label} (box {box.nn}){hint}: ") or previous
        if not password:
            raise Lab5Error(f"no SSH password given for box {box.nn}")
        redactor.add(password)
        passwords[box.nn] = previous = password
    return passwords


def load_creds(ctx: Ctx) -> None:
    for key, item in ctx.ws.keychain.items():
        ctx.creds[key] = ctx.keychain.require(item, key, secret=key in envfile.MASKED_KEYS)
    shown = ", ".join(f"{key} {last4(ctx.creds[key])}" for key in sorted(envfile.MASKED_KEYS))
    ctx.out.line(f"Keychain: {len(ctx.creds)} Lab 5 values read ({shown})")


def connect_cloudflare(ctx: Ctx, transport: Callable[..., Tuple[int, bytes]]) -> None:
    ws = ctx.ws
    token = ctx.keychain.require(ws.cloudflare_item, "Cloudflare API token: Tunnel edit + DNS edit")
    ctx.cloudflare = CloudflareAPI(token, transport=transport)
    if ws.zone_id and ws.account_id:
        ctx.zone_id, ctx.account_id = ws.zone_id, ws.account_id
    else:
        zone_id, account_id = ctx.cloudflare.zone(ws.zone)
        ctx.zone_id, ctx.account_id = ws.zone_id or zone_id, ws.account_id or account_id
    if not ctx.account_id:
        raise Lab5Error("could not tell the Cloudflare account from the zone; set cloudflare.account_id")
    saved = ctx.state.load_workshop()
    saved.update(workshop=ws.name, zone=ws.zone, zone_id=ctx.zone_id, account_id=ctx.account_id)
    ctx.state.save_workshop(saved)
    ctx.out.line(f"Cloudflare: zone {ws.zone} ({ctx.zone_id}), token {last4(token)}")


def run_parallel(ctx: Ctx, boxes: Sequence[BoxSpec], fn: Callable[[Ctx, BoxSpec], BoxReport]) -> List[BoxReport]:
    def guarded(box: BoxSpec) -> BoxReport:
        try:
            return fn(ctx, box)
        except Lab5Error as exc:
            rep = BoxReport(box, ctx.ws.hostname(box))
            rep.add("FAIL", fn.__name__.replace("_box", ""), str(exc))
            return rep
        except Exception as exc:  # noqa: BLE001 - one box never takes the others down
            rep = BoxReport(box, ctx.ws.hostname(box))
            rep.add("FAIL", "error", f"unexpected {type(exc).__name__}: {exc}")
            return rep

    reports: Dict[str, BoxReport] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(ctx.ws.concurrency, len(boxes)))) as pool:
        for rep in pool.map(guarded, boxes):
            reports[rep.box.nn] = rep
            ctx.out.line(rep.render())
    return [reports[b.nn] for b in boxes]


COMMANDS = {"check": check_box, "up": up_box, "status": status_box, "down": down_box}
NEXT_STAGE = {"expire": "disables participant accounts older than 7 days (12.2, 12.3)"}


def main(argv: Optional[Sequence[str]] = None, deps: Optional[Deps] = None) -> int:
    deps = deps or Deps()
    ap = argparse.ArgumentParser(prog="lab5-setup", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("command", choices=sorted(list(COMMANDS) + list(NEXT_STAGE)))
    ap.add_argument("workshop_yaml", type=Path)
    ap.add_argument("--only", default="", help="comma list of instance numbers, e.g. 1,3")
    ap.add_argument("--restart", action="store_true", help="up/down: restart the app even if .env is unchanged")
    args = ap.parse_args(argv)
    out = deps.out or sys.stdout
    if args.command in NEXT_STAGE:
        print(f"lab5-setup {args.command}: not built yet (next stage): {NEXT_STAGE[args.command]}", file=out)
        return 2

    redactor = Redactor()
    try:
        ws = load_workshop(args.workshop_yaml)
    except Lab5Error as exc:
        print(f"lab5-setup: {exc}", file=out)
        return 2
    boxes = ws.boxes
    if args.only:
        try:
            wanted = {int(n) for n in args.only.split(",") if n.strip()}
        except ValueError:
            print(f"lab5-setup: --only takes instance numbers, e.g. 1,3", file=out)
            return 2
        boxes = [b for b in ws.boxes if b.instance in wanted]
        if not boxes:
            print(f"lab5-setup: --only {args.only} matches no box in {args.workshop_yaml}", file=out)
            return 2
    state = StateStore(deps.state_root or StateStore.default_root(), ws.name)
    state.ensure()
    reporter = Reporter(redactor, out=out, log_path=state.run_log(args.command))
    ctx = Ctx(ws=ws, state=state, keychain=Keychain(redactor, deps.keychain_runner) if deps.keychain_runner
              else Keychain(redactor), redactor=redactor, out=reporter,
              connect=lambda box, pw: (deps.connect(box, pw, ctx) if deps.connect else remote.ParamikoBox(
                  box.host, box.port, box.user, pw, remote.KnownHosts(state.known_hosts), redactor)),
              https=deps.https or _https, resolve=deps.resolve or _resolve, sleep=deps.sleep,
              app_wait_s=deps.app_wait_s, preflight_wait_s=deps.preflight_wait_s, force_restart=args.restart)
    try:
        reporter.line(f"lab5-setup {args.command}: workshop {ws.name}, {len(boxes)} box(es), "
                      f"required release {ws.required_version}, state {state.dir}")
        if args.command in ("check", "up", "status"):
            load_creds(ctx)                 # local first: a missing item fails before any network call
        connect_cloudflare(ctx, deps.cloudflare_transport)
        ctx.passwords = ask_passwords(boxes, deps.prompt, redactor)
        reports = run_parallel(ctx, boxes, COMMANDS[args.command])
        if args.command == "up" and not any(r.failed for r in reports):
            create_participants(ctx, reports)
        if args.command == "status":
            for status, name, detail in room_checks(ctx):
                reporter.line(f"  {status:<8} {name:<12} {detail}")
        if args.command in ("status", "down"):
            for row in workshop_orphans(ctx):
                reporter.line(f"  WARN     orphan       {row}")
        failed = [r.box.nn for r in reports if r.failed]
        reporter.line(f"RESULT: {args.command}: {len(reports) - len(failed)} ok, {len(failed)} failed"
                      + (f" (box {', '.join(failed)})" if failed else ""))
        return 1 if failed else 0
    except Lab5Error as exc:
        reporter.line(f"lab5-setup: {exc}")
        return 2
    finally:
        reporter.close()


if __name__ == "__main__":
    sys.exit(main())
