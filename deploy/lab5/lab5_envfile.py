"""Key-by-key ``.env`` edits for lab5-setup (12.3, the I4 rule).

``up`` changes only the Lab 5 keys and leaves every other line byte-for-byte:
the text is split on ``\\n`` only (never ``str.splitlines``, which also splits
on form feeds and Unicode separators) and decoded with ``surrogateescape``, so
any byte that is not part of a Lab 5 line survives the round trip unchanged.

The first live line of a key is replaced in place (a line that already holds
the wanted value is kept as it is), later duplicates of that key are dropped,
and a missing key is appended. ``down`` reverts to the baseline recorded at the
first ``up``: a prior line goes back where the key is now, an appended key is
removed. Pure functions, no I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lab5_common import Lab5Error, last4

# The 12.1 table, PUBLIC_BASE_URL and HEC_HOST included: the only keys lab5-setup owns.
LAB5_KEYS: Tuple[str, ...] = (
    "PUBLIC_BASE_URL",
    "DUO_ENABLED",
    "DUO_CLIENT_ID", "DUO_CLIENT_SECRET", "DUO_API_HOST",
    "DUO_ADMIN_IKEY", "DUO_ADMIN_SKEY",
    "CII_CLIENT_ID", "CII_CLIENT_SECRET", "CII_TOKEN_URL", "CII_API_URL",
    "IDENTITY_ALLOWED_USERS",
    "IDENTITY_SESSION_TTL_MINUTES", "IDENTITY_STATUS_TTL_SECONDS", "IDENTITY_FAIL_OPEN",
    "HEC_HOST",
)
# Credentials: shown only as their last 4 characters, and their prior values are
# never written to the Mac's state directory.
MASKED_KEYS = frozenset({
    "DUO_CLIENT_ID", "DUO_CLIENT_SECRET", "DUO_ADMIN_IKEY", "DUO_ADMIN_SKEY",
    "CII_CLIENT_ID", "CII_CLIENT_SECRET",
})

ENCODING = "utf-8"
_LINE_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(.*)$", re.S)
_SAFE_RE = re.compile(r"^[A-Za-z0-9_./:@%+,=~-]*$")


def decode(data: bytes) -> str:
    return data.decode(ENCODING, errors="surrogateescape")


def encode(text: str) -> bytes:
    return text.encode(ENCODING, errors="surrogateescape")


def split_lines(text: str) -> List[str]:
    """Lines with their own ``\\n`` (a ``\\r`` stays part of the line)."""
    return re.findall(r"[^\n]*\n|[^\n]+$", text)


def key_of(line: str) -> Optional[str]:
    stripped = line.lstrip(" \t")
    if not stripped or stripped.startswith("#"):
        return None
    m = _LINE_RE.match(line.rstrip("\n").rstrip("\r"))
    return m.group(1) if m else None


def value_of(line: str) -> str:
    """The value the way python-dotenv (the app's reader) sees it."""
    m = _LINE_RE.match(line.rstrip("\n").rstrip("\r"))
    raw = (m.group(2) if m else "").strip()
    if raw[:1] == "'":
        end = raw.find("'", 1)
        return raw[1:end] if end > 0 else raw[1:]
    if raw[:1] == '"':
        out, i = [], 1
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw):
                out.append({"n": "\n", "t": "\t"}.get(raw[i + 1], raw[i + 1]))
                i += 2
                continue
            if ch == '"':
                break
            out.append(ch)
            i += 1
        return "".join(out)
    hash_at = raw.find(" #")
    return raw[:hash_at].rstrip() if hash_at >= 0 else raw


def get(lines: List[str], key: str) -> Optional[str]:
    """Last live value: python-dotenv lets a later duplicate win."""
    found = None
    for line in lines:
        if key_of(line) == key:
            found = value_of(line)
    return found


def render(key: str, value: str) -> str:
    if "\n" in value or "\r" in value:
        raise Lab5Error(f"{key}: a value with a line break cannot go in .env")
    if _SAFE_RE.match(value):
        return f"{key}={value}"
    if "'" not in value:
        return f"{key}='{value}'"
    raise Lab5Error(f"{key}: the value holds characters .env cannot carry safely (a single quote)")


def _terminator(line: str) -> str:
    return "\n" if line.endswith("\n") else ""


def display(key: str, value: Optional[str]) -> str:
    if value is None:
        return "(absent)"
    if key in MASKED_KEYS and value:
        return f"<{last4(value)}>"
    return value if value else "(empty)"


# --------------------------------------------------------------------------- plans
@dataclass
class KeyChange:
    key: str
    action: str            # add | change | remove | dedupe
    old: Optional[str]     # display form, never a credential
    new: Optional[str]


@dataclass
class EnvPlan:
    old_text: str
    new_text: str
    changes: List[KeyChange] = field(default_factory=list)
    eol_added: bool = False
    warnings: List[str] = field(default_factory=list)
    # Every line in file order, as _apply handled it: (old line, new line),
    # (old line, None) for a removed line, (None, new line) for an added one.
    edits: List[Tuple[Optional[str], Optional[str]]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.new_text != self.old_text

    def diff(self, path: str = ".env") -> str:
        """Zero-context unified diff of the Lab 5 lines, credentials masked.

        Rendered from the plan's own edits, never re-derived by a diff
        algorithm: difflib's matcher can pair an unchanged line with the wrong
        copy of itself (blank lines in a long file, a duplicate key between
        blank lines) and report it as changed. A line outside the Lab 5 keys
        is never printed: if an edit ever touched one, that is a bug and the
        plan is refused instead."""
        hunks: List[Tuple[int, int, List[str], List[str]]] = []
        old_no = new_no = 0
        for old, new in self.edits:
            if old is not None and new is not None and _masked(old) == _masked(new):
                old_no, new_no = old_no + 1, new_no + 1
                continue
            for line in (old, new):
                if line is not None and key_of(line) not in LAB5_KEYS:
                    raise Lab5Error("internal error: a non-Lab-5 .env line would change; refusing")
            last = hunks[-1] if hunks else None
            if not last or last[0] + len(last[2]) != old_no or last[1] + len(last[3]) != new_no:
                hunks.append((old_no, new_no, [], []))
            if old is not None:
                hunks[-1][2].append("-" + _masked(old))
                old_no += 1
            if new is not None:
                hunks[-1][3].append("+" + _masked(new))
                new_no += 1
        if not hunks:
            return ""
        out = [f"--- {path} (box)", f"+++ {path} (after)"]
        for old_start, new_start, minus, plus in hunks:
            out.append(f"@@ -{_range(old_start, len(minus))} +{_range(new_start, len(plus))} @@")
            out.extend(minus + plus)
        if self.eol_added:
            out.append("(the file's last line gains its missing final newline)")
        return "\n".join(out)


def _range(start: int, length: int) -> str:
    """A unified-diff range: 1-based, and an empty one names the line before it."""
    if length == 1:
        return str(start + 1)
    return f"{start + 1 if length else start},{length}"


def _masked(line: str) -> str:
    key = key_of(line)
    if key is None or key not in LAB5_KEYS:
        # Compared by identity only; never rendered (see EnvPlan.diff).
        return "\x00" + line.rstrip("\n")
    return f"{key}={display(key, value_of(line))}"


def baseline_of(text: str) -> Dict[str, Dict[str, object]]:
    """What each Lab 5 key looked like before the first ``up``, without any
    credential: a raw line is kept only when it carries no secret."""
    lines = split_lines(text)
    out: Dict[str, Dict[str, object]] = {}
    for key in LAB5_KEYS:
        live = [line for line in lines if key_of(line) == key]
        if not live:
            out[key] = {"present": False}
            continue
        entry: Dict[str, object] = {"present": True}
        if key in MASKED_KEYS and value_of(live[0]):
            entry["secret"] = True
        else:
            entry["line"] = live[0]
        if len(live) > 1:
            entry["duplicates"] = len(live) - 1
        out[key] = entry
    return out


# A target per key: ("set", value) | ("raw", line) | ("absent", None)
Target = Tuple[str, Optional[str]]


def _apply(text: str, targets: Dict[str, Target]) -> EnvPlan:
    for key in targets:
        if key not in LAB5_KEYS:
            raise Lab5Error(f"internal error: {key} is not a Lab 5 key")
    lines = split_lines(text)
    out: List[str] = []
    # (old line or None, index of its line in `out` or None), turned into
    # EnvPlan.edits once `out` is final (the last line may still gain "\n").
    placed: List[Tuple[Optional[str], Optional[int]]] = []

    def emit(old: Optional[str], new: Optional[str]) -> None:
        if new is not None:
            out.append(new)
        placed.append((old, len(out) - 1 if new is not None else None))

    seen: Dict[str, bool] = {}
    changes: List[KeyChange] = []
    for line in lines:
        key = key_of(line)
        if key not in targets:
            emit(line, line)
            continue
        kind, payload = targets[key]
        if seen.get(key):
            changes.append(KeyChange(key, "dedupe", display(key, value_of(line)), None))
            emit(line, None)
            continue
        seen[key] = True
        old_value = value_of(line)
        if kind == "absent":
            changes.append(KeyChange(key, "remove", display(key, old_value), None))
            emit(line, None)
            continue
        if kind == "raw":
            body = payload.rstrip("\n")
            if body != line.rstrip("\n"):
                changes.append(KeyChange(key, "change", display(key, old_value), display(key, value_of(payload))))
            emit(line, body + _terminator(line))   # the line keeps its own terminator
            continue
        if old_value == payload:
            emit(line, line)          # already right: keep the line exactly as written
            continue
        changes.append(KeyChange(key, "change", display(key, old_value), display(key, payload)))
        emit(line, render(key, payload) + (_terminator(line) or ""))
    eol_added = False
    for key, (kind, payload) in targets.items():
        if seen.get(key) or kind == "absent":
            continue
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
            eol_added = True
        if kind == "raw":
            new_line = payload if payload.endswith("\n") else payload + "\n"
            changes.append(KeyChange(key, "add", None, display(key, value_of(payload))))
        else:
            new_line = render(key, payload) + "\n"
            changes.append(KeyChange(key, "add", None, display(key, payload)))
        emit(None, new_line)
    edits = [(old, out[i] if i is not None else None) for old, i in placed]
    return EnvPlan(old_text=text, new_text="".join(out), changes=changes, eol_added=eol_added, edits=edits)


def plan_up(text: str, values: Dict[str, str]) -> EnvPlan:
    """Set each Lab 5 key in ``values``; every other line stays as it is."""
    return _apply(text, {k: ("set", v) for k, v in values.items()})


def plan_revert(text: str, baseline: Optional[Dict[str, Dict[str, object]]],
                backup_text: Optional[str] = None) -> EnvPlan:
    """Put each Lab 5 key back the way the first ``up`` found it. With no
    baseline (no record of ``up`` for this box) every Lab 5 key is removed,
    which is the app default: the 12.6 template leaves them all empty."""
    targets: Dict[str, Target] = {}
    warnings: List[str] = []
    backup_lines = split_lines(backup_text) if backup_text is not None else None
    for key in LAB5_KEYS:
        entry = (baseline or {}).get(key)
        if not entry or not entry.get("present"):
            targets[key] = ("absent", None)
        elif "line" in entry:
            targets[key] = ("raw", str(entry["line"]))
        else:
            prior = [line for line in (backup_lines or []) if key_of(line) == key]
            if prior:
                targets[key] = ("raw", prior[0])
            else:
                targets[key] = ("absent", None)
                warnings.append(f"{key} held a value before Lab 5 and its backup is gone: removed instead")
    plan = _apply(text, targets)
    plan.warnings.extend(warnings)
    return plan


def lab5_lines_only(text: str) -> List[str]:
    return [line for line in split_lines(text) if key_of(line) in LAB5_KEYS]


def other_lines(text: str) -> List[str]:
    """Every line that is not a live Lab 5 line, in order (what I4 protects)."""
    return [line for line in split_lines(text) if key_of(line) not in LAB5_KEYS]
