#!/usr/bin/env python3
"""Per-box identity for a PseudoCo Assistant box: one name for its O11y
environment and its Agent Observability Agent stream.

Every box that reports into a shared Observability Cloud org needs its own
``deployment.environment`` (how APM and the GenAI metrics tell boxes apart) and
its own Agent stream (how Agent Observability does). Both live in ``.env``, and
``.env`` travels: a box built from another box's image, or handed the same
payload, inherits that box's names and its telemetry silently merges with it —
an AI Trust dry run had three boxes reporting into one ``demobot-ec2-1``.

This script keeps the two names in step and ties them to the instance:

  assign --name NAME   set deployment.environment and SPLUNK_AO_AGENT_STREAM to
                       NAME, pin per-theme streams off (so every turn of the box
                       lands in that one stream), and stamp the box's EC2
                       instance id into PSEUDOCO_ASSISTANT_BOX_ID.
  ensure               run at every start (run.sh, run-collector.sh). On EC2,
                       if the stamp names a DIFFERENT instance the .env was
                       cloned, so derive a fresh name from this instance's id
                       (pseudoco-assistant-ec2-<id>) and assign it. A missing
                       stamp is adopted as-is: the name may be hand-set, and
                       renaming a working box would split its history. Off EC2
                       (a Mac, a container) it does nothing.
  show                 print the box's identity and whether the .env is cloned.

Stdlib only, so the collector launcher can run it with the system python3; it
never prints a secret and ``ensure`` always exits 0 so it cannot block a start.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

STAMP_KEY = "PSEUDOCO_ASSISTANT_BOX_ID"
RESOURCE_ATTRS_KEY = "OTEL_RESOURCE_ATTRIBUTES"
STREAM_KEY = "SPLUNK_AO_AGENT_STREAM"
PER_THEME_KEY = "SPLUNK_AO_AGENT_STREAM_PER_THEME"
ENV_ATTR = "deployment.environment"
EC2_NAME_PREFIX = "pseudoco-assistant-ec2-"

# A deployment.environment rides inside the comma-separated OTEL_RESOURCE_ATTRIBUTES
# list, so it cannot contain "," or "="; the same name is the Agent stream.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_IMDS = "http://169.254.169.254/latest"


# --------------------------------------------------------------------------- box
def _looks_like_ec2() -> bool:
    """Cheap local check before touching the network: Nitro instances report
    'Amazon EC2' as the DMI vendor, Xen ones an 'ec2' hypervisor uuid. Off
    Linux (the Mac) none of these files exist and the answer is an instant no."""
    for path in ("/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/bios_vendor",
                 "/sys/hypervisor/uuid"):
        try:
            value = Path(path).read_text().strip().lower()
        except OSError:
            continue
        if "amazon" in value or value.startswith("ec2"):
            return True
    return False


def ec2_instance_id(timeout: float = 1.0) -> Optional[str]:
    """This instance's id via IMDSv2, or None off EC2 / when IMDS is unreachable."""
    if not _looks_like_ec2():
        return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # IMDS is never proxied
    try:
        req = urllib.request.Request(f"{_IMDS}/api/token", method="PUT",
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        token = opener.open(req, timeout=timeout).read().decode().strip()
        req = urllib.request.Request(f"{_IMDS}/meta-data/instance-id",
                                     headers={"X-aws-ec2-metadata-token": token})
        iid = opener.open(req, timeout=timeout).read().decode().strip()
    except Exception:  # noqa: BLE001 - no IMDS means "not an EC2 box" here
        return None
    return iid if iid.startswith("i-") else None


def name_for_instance(instance_id: str) -> str:
    """The derived name for an unnamed box — what ec2-bootstrap.sh falls back to."""
    return EC2_NAME_PREFIX + instance_id[2:] if instance_id.startswith("i-") else EC2_NAME_PREFIX + instance_id


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name or ""))


# --------------------------------------------------------------------------- .env
def _key_of(line: str) -> Optional[str]:
    if "=" not in line or line.lstrip().startswith("#"):
        return None
    return line.split("=", 1)[0].strip()


def get_value(lines: List[str], key: str) -> Optional[str]:
    """First live KEY=VALUE — what the launchers' ``grep '^KEY=' | cut`` reads."""
    for line in lines:
        if _key_of(line) == key:
            return line.split("=", 1)[1].rstrip("\n").strip()
    return None


def set_value(lines: List[str], key: str, value: str) -> List[str]:
    """Replace the first live KEY= line (dropping any later duplicates, which
    would make the shell readers return two lines) or append it."""
    out, done = [], False
    for line in lines:
        if _key_of(line) == key:
            if not done:
                out.append(f"{key}={value}\n")
                done = True
            continue
        out.append(line)
    if not done:
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
        out.append(f"{key}={value}\n")
    return out


def environment_of(lines: List[str]) -> Optional[str]:
    for pair in (get_value(lines, RESOURCE_ATTRS_KEY) or "").split(","):
        k, _, v = pair.partition("=")
        if k.strip() == ENV_ATTR:
            return v.strip() or None
    return None


def with_environment(resource_attrs: Optional[str], name: str) -> str:
    """Set deployment.environment inside the attribute list, keeping its siblings."""
    attrs, hit = [], False
    for pair in [p for p in (resource_attrs or "").split(",") if p.strip()]:
        k, _, _ = pair.partition("=")
        if k.strip() == ENV_ATTR:
            attrs.append(f"{ENV_ATTR}={name}")
            hit = True
        else:
            attrs.append(pair.strip())
    if not hit:
        attrs.insert(0, f"{ENV_ATTR}={name}")
    return ",".join(attrs)


def assign(lines: List[str], name: str, box_id: Optional[str]) -> List[str]:
    """One name for the box's environment and Agent stream, stamped to the box."""
    if not valid_name(name):
        raise ValueError(f"invalid box name {name!r}: use letters, digits, '.', '_' or '-' "
                         "(no spaces, ',' or '='), at most 63 characters")
    lines = set_value(lines, RESOURCE_ATTRS_KEY,
                      with_environment(get_value(lines, RESOURCE_ATTRS_KEY), name))
    lines = set_value(lines, STREAM_KEY, name)
    lines = set_value(lines, PER_THEME_KEY, "False")
    if box_id:
        lines = set_value(lines, STAMP_KEY, box_id)
    return lines


def ensure(lines: List[str], box_id: Optional[str]) -> Tuple[List[str], str]:
    """Start-time check. Returns the (possibly unchanged) lines and what happened."""
    if not box_id:
        return lines, "skip: not an EC2 instance"
    stamp = get_value(lines, STAMP_KEY)
    if stamp == box_id:
        return lines, f"ok: {environment_of(lines) or '(no deployment.environment)'}"
    if not stamp:
        return (set_value(lines, STAMP_KEY, box_id),
                f"adopted: {environment_of(lines) or '(no deployment.environment)'} now belongs "
                f"to {box_id} (run `{Path(__file__).name} assign --name NAME` if another box shares it)")
    name = name_for_instance(box_id)
    return (assign(lines, name, box_id),
            f"cloned .env (stamped for {stamp}, running on {box_id}): "
            f"deployment.environment and Agent stream are now {name}")


def write_atomic(path: Path, lines: List[str]) -> None:
    """Replace .env in one rename (run.sh and run-collector.sh may both run this
    at boot), keeping its permissions — it holds every secret on the box."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(prefix=".env.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.writelines(lines)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- cli
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("show", "ensure", "assign"))
    ap.add_argument("--env-file", default=".env", type=Path)
    ap.add_argument("--name", help="assign: the box's environment + Agent stream name")
    ap.add_argument("--box-id", help=argparse.SUPPRESS)   # tests / non-EC2 hosts: skip IMDS
    args = ap.parse_args(argv)

    tag = "box identity:"
    if not args.env_file.exists():
        print(f"{tag} {args.env_file} not found", file=sys.stderr)
        return 0 if args.command == "ensure" else 2
    lines = args.env_file.read_text().splitlines(keepends=True)
    box_id = args.box_id or ec2_instance_id()

    if args.command == "show":
        stamp = get_value(lines, STAMP_KEY)
        print(f"deployment.environment = {environment_of(lines) or '(unset)'}")
        print(f"Agent stream           = {get_value(lines, STREAM_KEY) or '(unset)'}"
              f"  (per-theme streams: {get_value(lines, PER_THEME_KEY) or 'True (default)'})")
        print(f"stamped for            = {stamp or '(unstamped)'}")
        print(f"this box               = {box_id or '(not an EC2 instance)'}")
        if box_id and stamp and stamp != box_id:
            print("STATUS: cloned .env — the next start (or `ensure`) renames this box")
        return 0

    if args.command == "assign":
        if not args.name:
            ap.error("assign needs --name")
        try:
            new = assign(lines, args.name, box_id)
        except ValueError as exc:
            print(f"{tag} {exc}", file=sys.stderr)
            return 2
        write_atomic(args.env_file, new)
        print(f"{tag} deployment.environment and Agent stream = {args.name}"
              + (f" (stamped for {box_id})" if box_id else " (not an EC2 instance: unstamped)")
              + "; restart the collector and the app to apply")
        return 0

    # ensure: never fail a start over identity
    try:
        new, what = ensure(lines, box_id)
        if new != lines:
            write_atomic(args.env_file, new)
        print(f"{tag} {what}")
    except Exception as exc:  # noqa: BLE001
        print(f"{tag} check skipped ({type(exc).__name__}: {exc})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
