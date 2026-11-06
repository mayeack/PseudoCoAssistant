"""The Lab 5 persona cast (plan 4.3, 4.5) as data, plus its Mac-side state.

``scripts/identity/personas.yaml`` is the single source. It is read by
``provision_personas.py`` and ``persona_activity.py`` (scripts/identity/) and by
``lab5-setup expire``, which must never touch a persona.

State lives under ``~/.pseudoco-lab5/personas/`` (0700 directories, 0600 files):

* ``hotp/<username>.json``: the next HOTP counter to use, changed only under
  an exclusive lock on ``hotp/<username>.lock``. A code is reserved (the
  counter written +1) before it is sent, so no counter value is ever used
  twice, even by a crashed run. The HOTP secret itself is in the Keychain.
* ``runs/``, ``takeovers/``, ``selfcheck/``: what each run did and when. The
  takeover record is the source of the takeover time (plan 12.4, S1 path 3).

None of these files holds a secret.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from lab5_common import Lab5Error, file_lock, private_dir, read_json, utc_now, write_json_private

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CAST = REPO / "scripts" / "identity" / "personas.yaml"
ROLES = ("trusted", "victim", "spike")
PERSONA_NOTES_MARKER = "lab5 persona"
_USER_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})$")


@dataclass
class Place:
    ipaddr: str
    hostname: str


@dataclass
class Persona:
    username: str
    name: str
    role: str
    home: Place
    replay_device: bool = False

    @property
    def first(self) -> str:
        return self.name.split()[0]

    @property
    def last(self) -> str:
        return self.name.split()[-1]


@dataclass
class Cast:
    personas: List[Persona]
    email_domain: str = "pseudocoassistant.com"
    group: str = "PseudoCo Workforce"
    secret_encoding: str = "hex"
    keychain_prefix: str = "pseudoco-lab5-hotp-"
    baseline_enabled: bool = False
    jitter_minutes: int = 0
    takeover_attempts: Tuple[int, int] = (5, 9)
    takeover_spacing_s: float = 10.0
    reuse_days: int = 8
    foreign: List[Place] = field(default_factory=list)
    replay_pushes: int = 5
    cii_query: str = ""

    def get(self, username: str) -> Persona:
        for p in self.personas:
            if p.username == username:
                return p
        raise Lab5Error(f"{username!r} is not in the persona cast (scripts/identity/personas.yaml)")

    def email(self, p: Persona) -> str:
        return f"{p.username}@{self.email_domain}"

    def keychain_item(self, p: Persona) -> str:
        return f"{self.keychain_prefix}{p.username}"

    @staticmethod
    def token_serial(p: Persona) -> str:
        return f"pseudoco-persona-{p.username}"

    @property
    def usernames(self) -> List[str]:
        return [p.username for p in self.personas]

    def with_role(self, *roles: str) -> List[Persona]:
        return [p for p in self.personas if p.role in roles]


def persona_notes(p: Persona) -> str:
    return f"{PERSONA_NOTES_MARKER} (scripts/identity/provision_personas.py); role={p.role}; created={utc_now()}"


def is_persona_notes(notes: Optional[str]) -> bool:
    return str(notes or "").startswith(PERSONA_NOTES_MARKER)


def require_public(place: Place, what: str) -> None:
    """Real sign-ins need addresses Duo can geolocate (spike S1). The cast
    ships with documentation addresses (TEST-NET), which this refuses."""
    try:
        addr = ipaddress.ip_address(place.ipaddr)
    except ValueError:
        raise Lab5Error(f"{what}: {place.ipaddr!r} is not an IP address")
    if not addr.is_global:
        raise Lab5Error(f"{what}: {place.ipaddr} is not a public address (the cast ships with documentation "
                        "addresses); set a real one in scripts/identity/personas.yaml once spike S1 says how "
                        "Duo geolocates them")


def _place(doc: Any, what: str) -> Place:
    if not isinstance(doc, dict) or not doc.get("ipaddr") or not doc.get("hostname"):
        raise Lab5Error(f"personas.yaml: {what} needs ipaddr and hostname")
    place = Place(str(doc["ipaddr"]), str(doc["hostname"]))
    try:
        ipaddress.ip_address(place.ipaddr)
    except ValueError:
        raise Lab5Error(f"personas.yaml: {what}: {place.ipaddr!r} is not an IP address")
    if not _HOSTNAME_RE.match(place.hostname):
        raise Lab5Error(f"personas.yaml: {what}: hostname {place.hostname!r} is not a device name")
    return place


def cast_from_dict(doc: Dict[str, Any]) -> Cast:
    if not isinstance(doc, dict):
        raise Lab5Error("personas.yaml: the top level must be a mapping")
    personas: List[Persona] = []
    for row in doc.get("personas") or []:
        username = str((row or {}).get("username") or "")
        if not _USER_RE.match(username) or username.startswith("l5-"):
            raise Lab5Error(f"personas.yaml: {username!r} is not a persona username (l5- is reserved for "
                            "participant accounts)")
        name = str(row.get("name") or "")
        if len(name.split()) < 2:
            raise Lab5Error(f"personas.yaml: {username} needs a first and last name")
        role = str(row.get("role") or "")
        if role not in ROLES:
            raise Lab5Error(f"personas.yaml: {username}: role must be one of {', '.join(ROLES)}")
        personas.append(Persona(username, name, role, _place(row.get("home"), f"{username}.home"),
                                bool(row.get("replay_device"))))
    names = [p.username for p in personas]
    if len(names) != len(set(names)):
        raise Lab5Error("personas.yaml: usernames must be unique")
    if not any(p.role == "trusted" for p in personas) or not any(p.role == "victim" for p in personas):
        raise Lab5Error("personas.yaml: the cast needs trusted personas and victims")
    if sum(p.replay_device for p in personas) > 1:
        raise Lab5Error("personas.yaml: at most one persona has replay_device (one phone per victim, "
                        "or CII fails Users Sharing Authenticators)")
    hotp = doc.get("hotp") or {}
    baseline = doc.get("baseline") or {}
    takeover = doc.get("takeover") or {}
    attempts = takeover.get("attempts") or [5, 9]
    try:
        low, high = int(attempts[0]), int(attempts[1])
    except (TypeError, ValueError, IndexError):
        raise Lab5Error("personas.yaml: takeover.attempts is [min, max]")
    if not 5 <= low <= high <= 9:
        raise Lab5Error("personas.yaml: takeover.attempts must stay within 5-9: at least MFA Flood's 5, "
                        "under the lockout limit of 10")
    spacing = float(takeover.get("spacing_seconds", 10))
    if spacing * (high - 1) > 110:
        raise Lab5Error("personas.yaml: takeover.spacing_seconds puts the bad passcodes outside MFA Flood's "
                        "2-minute window")
    pushes = int((doc.get("replay") or {}).get("pushes", 5))
    if not 1 <= pushes <= 9:
        raise Lab5Error("personas.yaml: replay.pushes must be 1-9 (under the lockout limit of 10)")
    encoding = str(hotp.get("secret_encoding") or "hex")
    if encoding not in ("hex", "base32"):
        raise Lab5Error("personas.yaml: hotp.secret_encoding is hex or base32 (spike S7)")
    prefix = str(hotp.get("keychain_prefix") or "pseudoco-lab5-hotp-")
    if not re.match(r"^[a-z0-9.-]+-$", prefix):
        raise Lab5Error("personas.yaml: hotp.keychain_prefix must end in '-'")
    return Cast(
        personas=personas,
        email_domain=str(doc.get("email_domain") or "pseudocoassistant.com"),
        group=str(doc.get("group") or "PseudoCo Workforce"),
        secret_encoding=encoding, keychain_prefix=prefix,
        baseline_enabled=bool(baseline.get("enabled")),
        jitter_minutes=max(0, int(baseline.get("jitter_minutes") or 0)),
        takeover_attempts=(low, high), takeover_spacing_s=spacing,
        reuse_days=int(takeover.get("reuse_days", 8)),
        foreign=[_place(f, f"takeover.foreign[{i}]") for i, f in enumerate(takeover.get("foreign") or [])],
        replay_pushes=pushes,
        cii_query=str((doc.get("cii") or {}).get("end_user_query") or ""),
    )


def load_cast(path: Optional[Path] = None) -> Cast:
    path = Path(path or DEFAULT_CAST)
    try:
        import yaml  # lazy: deploy/lab5/requirements.txt
    except ImportError:
        raise Lab5Error("PyYAML is not installed: pip install -r deploy/lab5/requirements.txt")
    try:
        doc = yaml.safe_load(path.read_text())
    except OSError as exc:
        raise Lab5Error(f"cannot read the persona cast {path}: {exc.strerror}")
    return cast_from_dict(doc or {})


# =========================================================================== state
class PersonaState:
    """``~/.pseudoco-lab5/personas/``. See the module docstring."""

    def __init__(self, root: Path) -> None:
        self.dir = Path(root) / "personas"

    def _hotp(self, username: str, suffix: str) -> Path:
        return self.dir / "hotp" / f"{username}{suffix}"

    def counter(self, username: str) -> Optional[Dict[str, Any]]:
        path = self._hotp(username, ".json")
        return read_json(path) if path.exists() else None

    def init_counter(self, username: str, token_id: str, counter: int = 0) -> None:
        with file_lock(self._hotp(username, ".lock")):
            write_json_private(self._hotp(username, ".json"),
                               {"next": int(counter), "token_id": token_id, "updated_at": utc_now()})

    def reserve(self, username: str, count: int = 1) -> int:
        """Reserve ``count`` consecutive counter values; returns the first."""
        with file_lock(self._hotp(username, ".lock")):
            rec = read_json(self._hotp(username, ".json"))
            if "next" not in rec:
                raise Lab5Error(f"no HOTP counter for {username}: run provision_personas.py first")
            first = int(rec["next"])
            rec.update(next=first + count, updated_at=utc_now())
            write_json_private(self._hotp(username, ".json"), rec)
            return first

    def forget(self, username: str) -> None:
        for suffix in (".json", ".lock"):
            path = self._hotp(username, suffix)
            if path.exists():
                path.unlink()

    def record(self, kind: str, name: str, data: Dict[str, Any]) -> Path:
        path = private_dir(self.dir / kind) / f"{name}.json"
        write_json_private(path, data)
        return path

    def records(self, kind: str) -> List[Dict[str, Any]]:
        d = self.dir / kind
        return [read_json(p) for p in sorted(d.glob("*.json"))] if d.exists() else []

    def last(self) -> Dict[str, Any]:
        return read_json(self.dir / "last.json")

    def update_last(self, username: str, **fields: Any) -> None:
        with file_lock(self.dir / "last.lock"):
            data = read_json(self.dir / "last.json")
            data.setdefault(username, {}).update(fields)
            write_json_private(self.dir / "last.json", data)


def persona_tokens(values: Sequence[str]) -> List[str]:
    """Lower-cased name parts of a username or a display name."""
    return [t for t in re.split(r"[\s._@-]+", " ".join(values).lower()) if t]
