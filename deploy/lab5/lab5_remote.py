"""Talking to one Show box: SSH (paramiko, password), files over SFTP, the
app's own API through an SSH-forwarded channel, and the cloudflared unit.

Secrets reach a box only as file content (SFTP, or ``cat`` reading stdin
under ``sudo``), never in a remote command line: every ``run`` takes an argv
list, and the tests assert no secret is ever in one. The app API is reached
at 127.0.0.1:<app_port> through a ``direct-tcpip`` channel, so the box's
ACCESS_KEY travels inside SSH, not over the Show box's plain-http port.

paramiko is imported lazily (deploy/lab5/requirements.txt), so the app's test
suite can load this module with the app's venv.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import shlex
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lab5_common import Lab5Error, Redactor

UNIT_NAME = "pseudoco-assistant-lab5-tunnel.service"
UNIT_PATH = f"/etc/systemd/system/{UNIT_NAME}"
TOKEN_ENV_PATH = "/etc/pseudoco-assistant/lab5-tunnel.env"
UNIT_MARKER = "# managed by lab5-setup"


@dataclass
class CmdResult:
    rc: int
    out: str = ""
    err: str = ""


@dataclass
class HttpResult:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8") or "null")


def remote_command(argv: List[str], sudo: bool = False) -> str:
    """The exact string sent to the box: quoted argv, ``sudo -n`` when asked
    (Show boxes have passwordless sudo; -n fails instead of prompting)."""
    return " ".join(shlex.quote(a) for a in ((["sudo", "-n", "--"] if sudo else []) + list(argv)))


# --------------------------------------------------------------------------- http
def build_http_request(method: str, path: str, port: int, headers: Optional[Dict[str, str]],
                       body: Optional[bytes]) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}", "Connection: close",
             "Accept: application/json", "User-Agent: lab5-setup"]
    for k, v in (headers or {}).items():
        if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
            raise Lab5Error("refusing a header with a line break")
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b"")


def parse_http_response(data: bytes) -> HttpResult:
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        raise Lab5Error("the app closed the connection without a complete HTTP response")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError):
        raise Lab5Error("the app sent an unreadable HTTP status line")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    body = rest
    if "chunked" in headers.get("transfer-encoding", "").lower():
        out, buf = b"", rest
        while buf:
            size_line, _, buf = buf.partition(b"\r\n")
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            out, buf = out + buf[:size], buf[size + 2:]
        body = out
    elif "content-length" in headers:
        body = rest[: int(headers["content-length"])]
    return HttpResult(status=status, headers=headers, body=body)


# --------------------------------------------------------------------------- host keys
class KnownHosts:
    """Trust on first use, per workshop: the first contact records the box's
    host key in the workshop's state directory, and every later run (status,
    down) refuses a different key. Show reuses IP addresses across workshops,
    so ~/.ssh/known_hosts is deliberately not consulted."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def load_into(self, host_keys) -> None:
        with self._lock:
            if self.path.exists():
                host_keys.load(str(self.path))

    def record(self, hostname: str, key) -> None:
        import paramiko  # noqa: WPS433 - lazy, see module docstring

        with self._lock:
            keys = paramiko.HostKeys()
            if self.path.exists():
                keys.load(str(self.path))
            keys.add(hostname, key.get_name(), key)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            keys.save(str(self.path))
            self.path.chmod(0o600)


def _recording_policy(known: KnownHosts, notes: List[str]):
    import paramiko

    class _Policy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):  # noqa: D401
            known.record(hostname, key)
            client.get_host_keys().add(hostname, key.get_name(), key)
            notes.append(f"first contact: recorded {key.get_name()} host key "
                         f"{hashlib.sha256(key.asbytes()).hexdigest()[:16]} for {hostname}")

    return _Policy()


# --------------------------------------------------------------------------- the box
class ParamikoBox:
    """One SSH connection to a Show box, password auth only."""

    def __init__(self, host: str, port: int, user: str, password: str, known: KnownHosts,
                 redactor: Redactor, connect_timeout: float = 20.0) -> None:
        import paramiko

        self.host, self.port, self.user = host, port, user
        self.notes: List[str] = []
        redactor.add(password)
        self._client = paramiko.SSHClient()
        known.load_into(self._client.get_host_keys())
        self._client.set_missing_host_key_policy(_recording_policy(known, self.notes))
        try:
            self._client.connect(host, port=port, username=user, password=password,
                                 timeout=connect_timeout, banner_timeout=connect_timeout,
                                 auth_timeout=connect_timeout, allow_agent=False, look_for_keys=False)
        except paramiko.BadHostKeyException:
            raise Lab5Error(f"{host}:{port} presented a DIFFERENT host key from the one recorded at "
                            f"first contact ({known.path}); refusing. If Show rebuilt the box, delete "
                            "its line from that file and re-run.")
        except paramiko.AuthenticationException:
            raise Lab5Error(f"SSH password rejected for {user}@{host}:{port}")
        except (OSError, paramiko.SSHException) as exc:
            raise Lab5Error(f"cannot reach {user}@{host}:{port} over SSH ({type(exc).__name__})")
        self._sftp = None

    # files ------------------------------------------------------------------
    def _sftp_client(self):
        if self._sftp is None:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def read_file(self, path: str) -> Optional[bytes]:
        try:
            with self._sftp_client().open(path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return None
        except IOError as exc:
            if getattr(exc, "errno", None) == 2:
                return None
            raise Lab5Error(f"cannot read {path} on the box ({type(exc).__name__})")

    def file_mode(self, path: str) -> Optional[int]:
        import stat as _stat
        try:
            st = self._sftp_client().lstat(path)
        except IOError:
            return None
        if _stat.S_ISLNK(st.st_mode):
            raise Lab5Error(f"{path} is a symlink; lab5-setup edits only a regular file")
        return _stat.S_IMODE(st.st_mode)

    def write_file_atomic(self, path: str, data: bytes, mode: int = 0o600) -> None:
        """Write a temp file beside ``path`` (mode set before any byte is
        written), then rename it over ``path`` in one step."""
        sftp = self._sftp_client()
        directory, _, name = path.rpartition("/")
        tmp = f"{directory}/.{name}.lab5-{secrets.token_hex(4)}"
        try:
            with sftp.open(tmp, "wb") as fh:
                fh.chmod(mode)
                fh.write(data)
            sftp.posix_rename(tmp, path)
        except Exception as exc:  # noqa: BLE001
            try:
                sftp.remove(tmp)
            except Exception:  # noqa: BLE001
                pass
            raise Lab5Error(f"cannot write {path} on the box ({type(exc).__name__})")

    def mkdir_private(self, path: str) -> None:
        self.run(["mkdir", "-p", "-m", "700", path], check=True)

    # commands ---------------------------------------------------------------
    def run(self, argv: List[str], stdin: Optional[bytes] = None, sudo: bool = False,
            timeout: float = 120.0, check: bool = False) -> CmdResult:
        cmd = remote_command(argv, sudo=sudo)
        try:
            chan_in, chan_out, chan_err = self._client.exec_command(cmd, timeout=timeout)
            if stdin:
                chan_in.write(stdin)
                chan_in.flush()
            chan_in.channel.shutdown_write()
            out = chan_out.read().decode("utf-8", "replace")
            err = chan_err.read().decode("utf-8", "replace")
            rc = chan_out.channel.recv_exit_status()
        except (socket.timeout, OSError) as exc:
            raise Lab5Error(f"`{argv[0]}` on the box failed ({type(exc).__name__})")
        result = CmdResult(rc=rc, out=out, err=err)
        if check and rc != 0:
            raise Lab5Error(f"`{' '.join(argv[:3])}` on the box exited {rc}: {err.strip()[:200]}")
        return result

    # the app's API through SSH ---------------------------------------------
    def http(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
             body: Optional[bytes] = None, port: int = 8001, timeout: float = 20.0) -> HttpResult:
        try:
            chan = self._client.get_transport().open_channel(
                "direct-tcpip", ("127.0.0.1", port), ("127.0.0.1", 0), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            raise Lab5Error(f"no forwarded connection to the box's 127.0.0.1:{port} ({type(exc).__name__}): "
                            "the app is down, or the box's sshd forbids TCP forwarding")
        try:
            chan.settimeout(timeout)
            chan.sendall(build_http_request(method, path, port, headers, body))
            chunks = []
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except (socket.timeout, OSError) as exc:
            raise Lab5Error(f"{method} {path} on the box timed out ({type(exc).__name__})")
        finally:
            chan.close()
        return parse_http_response(b"".join(chunks))

    def close(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.close()
        finally:
            self._client.close()


# --------------------------------------------------------------------------- app API
class AppClient:
    """The box's own PseudoCo Assistant API, authenticated with the box's own
    ACCESS_KEY (read from its .env over SSH)."""

    def __init__(self, box, access_key: str, port: int) -> None:
        self.box, self.port = box, port
        self._headers = {"X-Access-Key": access_key} if access_key else {}

    def _call(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None,
              auth: bool = True) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        headers = dict(self._headers) if auth else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        res = self.box.http(method, path, headers=headers, body=body, port=self.port)
        if res.status == 401:
            raise Lab5Error(f"{method} {path}: 401, the box rejected its own ACCESS_KEY")
        if not 200 <= res.status < 300:
            raise Lab5Error(f"{method} {path}: HTTP {res.status}")
        try:
            return res.json()
        except ValueError:
            raise Lab5Error(f"{method} {path}: the reply is not JSON")

    def health(self) -> Dict[str, Any]:
        return self._call("GET", "/health", auth=False)

    def server_info(self) -> Dict[str, Any]:
        return self._call("GET", "/api/server-info")

    def destinations(self) -> List[Dict[str, Any]]:
        return list((self._call("GET", "/api/hec/destinations") or {}).get("destinations") or [])

    def destination(self, dest_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/hec/destinations/{dest_id}")

    def set_destination_host(self, dest_id: str, host: str) -> Dict[str, Any]:
        """PUT with ONLY ``host``: the API applies exclude_unset patches, so
        the stored record keeps every other field, its token included."""
        return self._call("PUT", f"/api/hec/destinations/{dest_id}", {"host": host})


# --------------------------------------------------------------------------- cloudflared
def unit_text(cloudflared: str, workshop: str, nn: str, tunnel_name: str) -> str:
    return (f"{UNIT_MARKER} (workshop={workshop}, box={nn}); `lab5-setup down` removes it.\n"
            "# The tunnel token is in the EnvironmentFile (0600, root), never on this command line.\n"
            "[Unit]\n"
            f"Description=PseudoCo Assistant Lab 5 tunnel {tunnel_name} (cloudflared)\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=notify\n"
            f"EnvironmentFile={TOKEN_ENV_PATH}\n"
            f"ExecStart={cloudflared} --no-autoupdate tunnel run\n"
            "Restart=on-failure\nRestartSec=5s\nTimeoutStartSec=0\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def token_env_text(token: str, protocol: str = "") -> str:
    text = f"TUNNEL_TOKEN={token}\n"
    if protocol:
        text += f"TUNNEL_TRANSPORT_PROTOCOL={protocol}\n"
    return text


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def remote_sha256(box, path: str) -> Optional[str]:
    res = box.run(["sha256sum", path], sudo=True)
    return res.out.split()[0] if res.rc == 0 and res.out.split() else None


def write_root_file(box, path: str, data: bytes, mode: str) -> None:
    """Root-owned file from stdin: the content never appears in argv."""
    script = ('umask 077 && mkdir -p "$(dirname "$1")" && cat > "$1.lab5-tmp" && '
              'chmod "$2" "$1.lab5-tmp" && chown root:root "$1.lab5-tmp" && mv -f "$1.lab5-tmp" "$1"')
    box.run(["sh", "-c", script, "lab5-write", path, mode], stdin=data, sudo=True, check=True)


def find_cloudflared(box) -> Optional[str]:
    res = box.run(["sh", "-c", "command -v cloudflared || ls /usr/local/bin/cloudflared /usr/bin/cloudflared 2>/dev/null"])
    for line in res.out.splitlines():
        if line.startswith("/"):
            return line.strip()
    return None


def connector_install(box, cloudflared: str, workshop: str, nn: str, tunnel_name: str,
                      token: str, protocol: str = "") -> List[str]:
    """Install or refresh the connector unit. Returns what changed."""
    changed: List[str] = []
    unit = unit_text(cloudflared, workshop, nn, tunnel_name).encode()
    env = token_env_text(token, protocol).encode()
    if remote_sha256(box, TOKEN_ENV_PATH) != _sha256(env):
        write_root_file(box, TOKEN_ENV_PATH, env, "600")
        changed.append("token file")
    if remote_sha256(box, UNIT_PATH) != _sha256(unit):
        write_root_file(box, UNIT_PATH, unit, "644")
        changed.append("unit")
        box.run(["systemctl", "daemon-reload"], sudo=True, check=True)
    if box.run(["systemctl", "is-enabled", UNIT_NAME]).out.strip() != "enabled":
        box.run(["systemctl", "enable", UNIT_NAME], sudo=True, check=True)
    if changed or box.run(["systemctl", "is-active", UNIT_NAME]).out.strip() != "active":
        box.run(["systemctl", "restart", UNIT_NAME], sudo=True, check=True)
        changed.append("restarted")
    for _ in range(10):
        if box.run(["systemctl", "is-active", UNIT_NAME]).out.strip() == "active":
            return changed
        time.sleep(1.5)
    raise Lab5Error(f"{UNIT_NAME} did not become active; see `sudo journalctl -u {UNIT_NAME}` on the box")


def connector_present(box) -> bool:
    res = box.run(["grep", "-q", UNIT_MARKER, UNIT_PATH], sudo=True)
    return res.rc == 0


def connector_remove(box) -> List[str]:
    """Stop and remove the unit and its token file, if this tool made them."""
    removed: List[str] = []
    if connector_present(box):
        box.run(["systemctl", "disable", "--now", UNIT_NAME], sudo=True)
        box.run(["rm", "-f", UNIT_PATH], sudo=True, check=True)
        box.run(["systemctl", "daemon-reload"], sudo=True)
        removed.append("unit")
    if box.run(["test", "-e", TOKEN_ENV_PATH], sudo=True).rc == 0:
        box.run(["rm", "-f", TOKEN_ENV_PATH], sudo=True, check=True)
        removed.append("token file")
    return removed


def backup_db_command(src: str, dst: str) -> Tuple[List[str], bytes]:
    """sqlite3's online backup API (a consistent copy while the app writes),
    run by the box's system python3 with the script on stdin."""
    script = (b"import os, sqlite3, sys\n"
              b"src, dst = sys.argv[1], sys.argv[2]\n"
              b"fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)\n"
              b"a = sqlite3.connect('file:' + src + '?mode=ro', uri=True); b = sqlite3.connect(dst)\n"
              b"a.backup(b); b.close(); a.close()\n")
    return ["python3", "-I", "-", src, dst], script
