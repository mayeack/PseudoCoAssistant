"""Shared plumbing for lab5-setup: output that never carries a secret, the
Keychain reader, version compare and the Mac-side state directory.

Stdlib only. Nothing here talks to a box, Duo, CII or Cloudflare.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, TextIO, Tuple

STATE_ENV = "PSEUDOCO_LAB5_STATE_DIR"
DEFAULT_STATE_DIR = Path.home() / ".pseudoco-lab5"


class Lab5Error(Exception):
    """A refusal or failure with a message meant for the facilitator."""


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- versions
_VERSION_RE = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)")


def parse_version(text: Optional[str]) -> Optional[Tuple[int, int, int]]:
    m = _VERSION_RE.match(text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def version_at_least(have: Optional[str], need: str) -> bool:
    h, n = parse_version(have), parse_version(need)
    return bool(h and n and h >= n)


# --------------------------------------------------------------------------- secrets
class Redactor:
    """Every secret the run touches is registered here, and every line of
    output passes through ``scrub`` before it reaches the terminal or the run
    log. The commands never format a secret on purpose; this is the net under
    that rule."""

    MIN_LEN = 6   # shorter strings would scrub ordinary words

    def __init__(self) -> None:
        self._values: set = set()
        self._lock = threading.Lock()

    def add(self, value: Optional[str]) -> None:
        if value and len(value) >= self.MIN_LEN:
            with self._lock:
                self._values.add(value)

    def scrub(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for v in values:
            if v in text:
                text = text.replace(v, "<redacted>")
        return text


def last4(value: Optional[str]) -> str:
    return f"...{value[-4:]}" if value and len(value) >= 8 else "(short)"


class Reporter:
    """Thread-safe output: one prefixed line at a time, scrubbed, mirrored to
    the run log in the state directory."""

    def __init__(self, redactor: Redactor, out: TextIO = None, log_path: Optional[Path] = None) -> None:
        self.redactor = redactor
        self.out = out or sys.stdout
        self._lock = threading.Lock()
        self._log = None
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._log = os.fdopen(fd, "a")

    def line(self, text: str = "", prefix: str = "") -> None:
        text = self.redactor.scrub(text)
        rendered = "\n".join(f"{prefix}{part}" for part in text.split("\n")) if prefix else text
        with self._lock:
            print(rendered, file=self.out, flush=True)
            if self._log:
                self._log.write(rendered + "\n")
                self._log.flush()

    def close(self) -> None:
        if self._log:
            self._log.close()
            self._log = None


# --------------------------------------------------------------------------- keychain
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess"]


def _run_security(argv: Sequence[str]) -> "subprocess.CompletedProcess":
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=60)


class Keychain:
    """Reads generic passwords from the macOS login Keychain.

    ``security find-generic-password -s ITEM -w`` puts only the item NAME on
    the command line; the value comes back on stdout through a pipe. Values
    are registered with the redactor as soon as they are read."""

    def __init__(self, redactor: Redactor, runner: Runner = _run_security, account: str = "") -> None:
        self.redactor = redactor
        self._runner = runner
        self._account = account
        self._cache: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

    def get(self, item: str, secret: bool = True) -> Optional[str]:
        """``secret=False`` only for values that are not credentials (an API
        host, a token URL), so they can be shown in a diff."""
        with self._lock:
            if item in self._cache:
                if secret:
                    self.redactor.add(self._cache[item])
                return self._cache[item]
        argv = ["security", "find-generic-password", "-s", item]
        if self._account:
            argv += ["-a", self._account]
        argv.append("-w")
        try:
            proc = self._runner(argv)
        except (OSError, subprocess.SubprocessError):
            value = None
        else:
            value = proc.stdout.rstrip("\n") if proc.returncode == 0 else None
        value = value or None
        if secret:
            self.redactor.add(value)
        with self._lock:
            self._cache[item] = value
        return value

    def require(self, item: str, what: str, secret: bool = True) -> str:
        value = self.get(item, secret=secret)
        if not value:
            raise Lab5Error(f"Keychain item '{item}' ({what}) is missing or empty. Add it with: "
                            f"security add-generic-password -s {item} -a \"$USER\" -w   "
                            "(no value after -w: security prompts for it, so it stays out of your shell history)")
        return value


# --------------------------------------------------------------------------- state
def _write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class StateStore:
    """``~/.pseudoco-lab5/workshops/<workshop>/``: what ``up`` created, so
    ``down`` deletes exactly that. One JSON file per box (each box's worker
    thread writes only its own), 0700 directories, 0600 files. It never holds
    a secret: no token, password or key value, only ids, names and the
    non-secret prior values ``down`` restores."""

    def __init__(self, root: Path, workshop: str) -> None:
        self.root = Path(root)
        self.dir = self.root / "workshops" / workshop
        self._lock = threading.Lock()

    @classmethod
    def default_root(cls) -> Path:
        return Path(os.environ.get(STATE_ENV) or DEFAULT_STATE_DIR).expanduser()

    def ensure(self) -> None:
        for d in (self.root, self.root / "workshops", self.dir, self.dir / "boxes", self.dir / "runs"):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(d, 0o700)

    @property
    def known_hosts(self) -> Path:
        return self.dir / "known_hosts"

    def run_log(self, command: str) -> Path:
        return self.dir / "runs" / f"{utc_stamp()}-{command}.log"

    def _box_path(self, nn: str) -> Path:
        return self.dir / "boxes" / f"{nn}.json"

    def load_box(self, nn: str) -> Dict[str, Any]:
        path = self._box_path(nn)
        if not path.exists():
            return {}
        return json.loads(path.read_text())

    def save_box(self, nn: str, record: Dict[str, Any]) -> None:
        self.ensure()
        with self._lock:
            _write_json_atomic(self._box_path(nn), record)

    def load_workshop(self) -> Dict[str, Any]:
        path = self.dir / "workshop.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def save_workshop(self, data: Dict[str, Any]) -> None:
        self.ensure()
        with self._lock:
            _write_json_atomic(self.dir / "workshop.json", data)

    def recorded_boxes(self) -> List[str]:
        d = self.dir / "boxes"
        return sorted(p.stem for p in d.glob("*.json")) if d.exists() else []


def any_in(haystack: str, needles: Iterable[str]) -> bool:
    return any(n and n in haystack for n in needles)
