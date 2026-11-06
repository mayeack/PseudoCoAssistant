"""Shared plumbing for lab5-setup and the persona scripts: output that never
carries a secret, the Keychain, version compare, the Mac-side state
directory, a file lock and a desktop notification.

Stdlib only. Nothing here talks to a box, Duo, CII or Cloudflare.
"""
from __future__ import annotations

import fcntl
import getpass
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, TextIO, Tuple

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


StdinRunner = Callable[[Sequence[str], str], "subprocess.CompletedProcess"]


def _run_security_stdin(argv: Sequence[str], stdin: str) -> "subprocess.CompletedProcess":
    return subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=60)


# What `security -i` accepts as one bare word: no quoting is ever needed, so a
# value can never break out of its argument.
_KEYCHAIN_WORD = re.compile(r"^[A-Za-z0-9._@+=-]{1,256}$")


class Keychain:
    """Reads (and, for the persona HOTP secrets, writes) generic passwords in
    the macOS login Keychain.

    ``security find-generic-password -s ITEM -w`` puts only the item NAME on
    the command line; the value comes back on stdout through a pipe. A write
    goes through ``security -i``, which reads its command from stdin, so the
    value never appears in argv either. Values are registered with the
    redactor as soon as they are read or written."""

    def __init__(self, redactor: Redactor, runner: Runner = _run_security, account: str = "",
                 stdin_runner: StdinRunner = _run_security_stdin) -> None:
        self.redactor = redactor
        self._runner = runner
        self._stdin_runner = stdin_runner
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

    def store(self, item: str, value: str) -> None:
        """Create or replace ITEM with VALUE, then read it back. Only words
        that need no quoting are accepted (the HOTP secrets are hex or base32)."""
        account = self._account or getpass.getuser()
        for word, what in ((item, "item name"), (account, "account"), (value, "value")):
            if not _KEYCHAIN_WORD.match(word or ""):
                raise Lab5Error(f"refusing to write Keychain {what} that needs quoting ({item})")
        self.redactor.add(value)
        command = f"add-generic-password -U -s {item} -a {account} -w {value}\n"
        try:
            proc = self._stdin_runner(["security", "-i"], command)
        except (OSError, subprocess.SubprocessError) as exc:
            raise Lab5Error(f"could not write Keychain item '{item}': {type(exc).__name__}")
        with self._lock:
            self._cache.pop(item, None)
        if proc.returncode != 0 or self.get(item) != value:
            # Never echo security's output: it may repeat the command line.
            raise Lab5Error(f"writing Keychain item '{item}' did not take (security exited {proc.returncode})")

    def delete(self, item: str) -> bool:
        """Remove ITEM. True if it existed."""
        argv = ["security", "delete-generic-password", "-s", item]
        if self._account:
            argv += ["-a", self._account]
        try:
            proc = self._runner(argv)
        except (OSError, subprocess.SubprocessError):
            return False
        with self._lock:
            self._cache.pop(item, None)
        return proc.returncode == 0


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


def write_json_private(path: Path, data: Dict[str, Any]) -> None:
    """Atomic 0600 JSON write in a 0700 directory (no secrets go in these)."""
    _write_json_atomic(Path(path), data)


def read_json(path: Path) -> Dict[str, Any]:
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else {}


def private_dir(path: Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


@contextmanager
def file_lock(path: Path, timeout_s: float = 30.0) -> Iterator[None]:
    """An exclusive ``flock`` on PATH (created 0600), so two runs (a launchd
    job and a manual one) never use the same HOTP counter value."""
    import time
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Lab5Error(f"{path} is locked by another run; try again when it finishes")
                time.sleep(0.2)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


Notifier = Callable[[str, str], None]


def _applescript_text(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def desktop_notify(title: str, message: str) -> None:
    """A macOS notification for the launchd jobs (there is no one watching
    their output). Best effort: a failure here never fails the job. The text
    is a summary and never carries a secret."""
    script = f"display notification {_applescript_text(message[:200])} with title {_applescript_text(title[:80])}"
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass
