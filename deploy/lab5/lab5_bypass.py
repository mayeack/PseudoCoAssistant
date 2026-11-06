"""Persona bypass codes on the handout (plan 4.3): one small batch per team.

Attendees sign in to their PseudoCo Assistant instance as the room's victim and
as the trusted personas (all on its IDENTITY_ALLOWED_USERS) with bypass codes.
The personas' own HOTP tokens stay script-only (4.3): HOTP accepts only codes
ahead of Duo's counter, so a second consumer would break the baseline. This
module never reads their secrets or computes their passcodes.

* **Per team, i.e. per box.** Each instance's handout card gets its own batch
  for the victim and every trusted persona in workshop.yaml: ``count`` codes
  per persona (default 1), each good for ``reuse_count`` sign-ins (default 5)
  until ``valid_hours`` after it was issued (default 12). Per-team batches
  limit how far one team can burn another's codes.
* **preserve_existing=true**, always: the trusted personas are shared by every
  box of the room and by other rooms, and Duo's default clears every code the
  user already has. Duo keeps at most 100 codes per user, so the headroom is
  checked before the first code of a run is issued.
* **Only the cast's personas.** A batch goes only to a user that personas.yaml
  lists with the matching role (victim, or spike for a dry run; trusted) and
  whose Duo notes carry the persona marker: never a participant account, an
  administrator, or whoever a typo in workshop.yaml names.
* **The card is the only copy.** The codes are registered with the redactor
  and written to the 0600 handout, nowhere else. The participant record keeps
  when each batch was issued and when it expires, never a code.

**valid_secs is the cutoff: nothing invalidates them early.** ``down`` and
``expire`` leave them alone. Duo's create call returns only the code strings,
without their ids, and a bypass code carries no label or notes, so the tool
cannot tell its own codes from another room's on a shared trusted persona:
``DELETE /admin/v1/bypass_codes/{id}`` needs the id, diffing the user's code
list around each create races with every other room issuing codes for the
same persona, and clearing a user's codes (preserve_existing=false) ends
every other room's too. ``valid_hours``
is capped at 72, so every batch is dead long before ``expire`` disables a
participant at day 7.

``up`` issues a batch for each card that has none, whose batch has expired, or
whose batch names other personas (the victim was swapped); otherwise it keeps
it. ``lab5-setup handouts`` always issues a fresh batch (lab-day morning, or a
lost card); the codes it replaces stay valid until they expire.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lab5_participants as participants
from lab5_common import Lab5Error, Redactor, read_json, write_json_private
from lab5_duo import BYPASS_LIMIT, BYPASS_PER_REQUEST, AdminAPI, DuoError
from lab5_personas import Cast, is_persona_notes

HOUR = 3600
WARN_HOURS = 2.0                       # `status` warns when a batch has less left than this
VICTIM_ROLES = ("victim", "spike")     # spike: the dry-run victim, on a test stack only (plan 8)
CAST_FILE = "scripts/identity/personas.yaml"
# workshop.yaml `bypass_codes:` (lab5_setup refuses anything else before it connects)
RANGES = {"count": (1, BYPASS_PER_REQUEST, "codes per persona per box"),
          "reuse_count": (1, 20, "sign-ins per code"),
          "valid_hours": (1, 72, "hours")}

Row = Tuple[str, str, str]
Persona = Tuple[str, str]              # (role on the card: victim | trusted, username)
Entry = Tuple[str, str, List[str]]     # (role, username, codes)


@dataclass(frozen=True)
class Settings:
    enabled: bool = True
    count: int = 1                     # codes per persona per box
    reuse_count: int = 5               # sign-ins per code
    valid_hours: int = 12              # from the time the batch is issued: cover lab day

    @property
    def valid_secs(self) -> int:
        return self.valid_hours * HOUR


def room_personas(victim: str, trusted: Sequence[str], cast: Cast) -> List[Persona]:
    """The room's victim, then its trusted personas, each checked against the cast."""
    roles = {p.username: p.role for p in cast.personas}
    if roles.get(victim) not in VICTIM_ROLES:
        raise _not_in_cast("room.victim", victim, roles.get(victim), "a victim")
    out: List[Persona] = [("victim", victim)]
    for name in dict.fromkeys(trusted):
        if roles.get(name) != "trusted":
            raise _not_in_cast("room.trusted", name, roles.get(name), "a trusted persona")
        out.append(("trusted", name))
    return out


def _not_in_cast(key: str, name: str, role: Optional[str], want: str) -> Lab5Error:
    if not role:
        return Lab5Error(f"workshop.yaml: {key} {name!r} is not in the persona cast ({CAST_FILE}): lab5-setup "
                         "gives bypass codes to the cast's personas and to no one else")
    return Lab5Error(f"workshop.yaml: {key} {name!r} is a {role} in the persona cast ({CAST_FILE}), not {want}: "
                     "a persona gets its bypass codes in its own role or not at all")


def describe(personas: Sequence[Persona], settings: Settings) -> str:
    names = ", ".join(f"{name} (victim)" if role == "victim" else name for role, name in personas)
    each = "1 code" if settings.count == 1 else f"{settings.count} codes"
    return f"{each} each for {names}; {settings.reuse_count} sign-ins per code"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


# =========================================================================== cards
@dataclass
class Batch:
    entries: List[Entry]
    valid_until: Optional[float]

    @property
    def personas(self) -> List[Persona]:
        return [(role, name) for role, name, _ in self.entries]


def card_batch(card: Optional[Dict[str, str]]) -> Optional[Batch]:
    entries = participants.decode_bypass((card or {}).get("bypass"))
    if not entries:
        return None
    return Batch(entries, participants.parse_time((card or {}).get("bypass_valid_until") or ""))


def _state(batch: Optional[Batch], personas: Sequence[Persona], now: float) -> str:
    if batch is None:
        return "none"
    if set(batch.personas) != set(personas):
        return "other"
    if batch.valid_until is None or batch.valid_until <= now:
        return "expired"
    return "valid"


WHY = {"none": "no persona codes on its card yet", "other": "its codes are for other personas",
       "expired": "its codes have expired", "fresh": "a fresh batch"}


# =========================================================================== Duo
def persona_users(admin: AdminAPI, personas: Sequence[Persona]) -> Tuple[Dict[str, Dict[str, Any]], List[Row]]:
    """Each room persona's Duo user, looked up once. Returns (users by name,
    report rows). A FAIL row means no code may be issued to that name."""
    users: Dict[str, Dict[str, Any]] = {}
    rows: List[Row] = []
    for _, name in personas:
        user = admin.user_by_name(name)
        if not user:
            rows.append(("FAIL", name, "missing in Duo: run scripts/identity/provision_personas.py, then re-run"))
        elif not is_persona_notes(user.get("notes")):
            rows.append(("FAIL", name, "exists in Duo without the persona notes marker: not the cast's persona, so it "
                                       "gets no bypass code; left alone"))
        else:
            users[name] = user
            status = str(user.get("status") or "")
            if status != "active":
                rows.append(("WARN", name, f"{status or 'no status'} in Duo: its codes work once it is active again "
                                           "(provision_personas.py --reset)"))
    return users, rows


def headroom_rows(admin: AdminAPI, users: Dict[str, Dict[str, Any]], needed: int, now: float) -> List[Row]:
    """FAIL rows for personas that would pass Duo's 100-code limit. Codes
    that have not expired count, the other rooms' included."""
    rows: List[Row] = []
    for name, user in users.items():
        held = 0
        for meta in admin.user_bypass_codes(str(user["user_id"])):
            try:
                expires = float(meta.get("expiration") or 0)
            except (TypeError, ValueError):
                expires = 0.0
            held += 1 if not expires or expires > now else 0
        if held + needed > BYPASS_LIMIT:
            rows.append(("FAIL", name, f"holds {held} unexpired bypass code(s) and this run needs {needed} more: Duo "
                                       f"keeps at most {BYPASS_LIMIT} per user, other rooms' codes on a shared persona "
                                       "included. They free up as they expire; or issue fewer (bypass_codes.count, "
                                       "--only)"))
    return rows


def _record(env: participants.Env, nn: str, now: float, settings: Settings, entries: Sequence[Entry],
            complete: bool) -> None:
    """The participant record keeps every batch's times (never a code), so
    `down` can say when the last one stops working after the handout is gone."""
    path = env.record_path(nn)
    rec = read_json(path)
    rec.setdefault("bypass_batches", []).append({
        "issued_at": _iso(now), "valid_until": _iso(now + settings.valid_secs),
        "personas": [name for _, name, _ in entries], "codes_each": settings.count,
        "reuse_count": settings.reuse_count, "complete": complete})
    write_json_private(path, rec)


def _why_failed(exc: Lab5Error) -> str:
    text = str(exc)
    if isinstance(exc, DuoError) and exc.status == 400:
        text += f" (Duo keeps at most {BYPASS_LIMIT} bypass codes per user)"
    return text


# =========================================================================== commands
def issue(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona], settings: Settings,
          redactor: Redactor, force: bool) -> Tuple[List[Row], int]:
    """`up` (force=False) and `handouts` (force=True): a batch for each card
    that needs one. Returns (report rows, cards left without the batch they
    needed)."""
    now = env.now()
    handout = env.handout()
    cards = handout.load()
    rows: List[Row] = []
    todo: List[Tuple[str, str, Optional[Batch], str]] = []
    failed = 0
    for nn in numbers:
        name, label = participants.username(env.workshop, nn), f"instance {nn}"
        card = cards.get(name)
        if card is None:
            if force:
                failed += 1
                rows.append(("FAIL", label, f"no handout card for {name}: `up` makes it with the participant account"))
            else:
                rows.append(("SKIP", label, f"no handout card for {name} (see its participant row)"))
            continue
        batch = card_batch(card)
        state = _state(batch, personas, now)
        if state == "valid" and not force:
            rows.append(("OK", label, f"kept: valid until {participants.minute(batch.valid_until)}; "
                                      "`lab5-setup handouts` issues a fresh batch"))
            continue
        todo.append((nn, name, batch, WHY["fresh" if force else state]))
    if not todo:
        return rows, failed

    users, checks = persona_users(env.admin, personas)
    blocked = [r for r in checks if r[0] == "FAIL"]
    if not blocked:
        blocked = headroom_rows(env.admin, users, settings.count * len(todo), now)
        checks += blocked
    if blocked:
        rows += [("FAIL", f"instance {nn}", "no bypass codes issued: see the persona row(s) above")
                 for nn, _, _, _ in todo]
        return checks + rows, failed + len(todo)

    for nn, name, old, why in todo:
        label, entries = f"instance {nn}", []
        try:
            for role, persona in personas:
                codes = env.admin.create_bypass_codes(str(users[persona]["user_id"]), settings.count,
                                                      settings.reuse_count, settings.valid_secs)
                for code in codes:
                    redactor.add(code)
                entries.append((role, persona, codes))
        except Lab5Error as exc:
            failed += 1
            if entries:
                _record(env, nn, now, settings, entries, complete=False)
            rows.append(("FAIL", label, f"bypass codes not issued: {_why_failed(exc)}. The card keeps "
                                        f"{'its earlier codes' if old else 'no persona codes'}; re-run"))
            continue
        until = now + settings.valid_secs
        written = handout.update(name, {"bypass": participants.encode_bypass(entries), "bypass_issued_at": _iso(now),
                                        "bypass_valid_until": _iso(until), "bypass_reuse": str(settings.reuse_count)})
        _record(env, nn, now, settings, entries, complete=written)
        if not written:
            failed += 1
            rows.append(("FAIL", label, "its card left the handout while the codes were issued; re-run"))
            continue
        rows.append(("CHANGED", label, f"{why}: {describe(personas, settings)}, valid until "
                                       f"{participants.minute(until)}"))
    return checks + rows, failed


def plan_rows(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona],
              settings: Settings) -> List[Row]:
    """`check`: what `up` would do with each card's persona codes. Read-only."""
    now = env.now()
    users, checks = persona_users(env.admin, personas)
    cards = env.handout().load()
    rows: List[Row] = []
    for nn in numbers:
        batch = card_batch(cards.get(participants.username(env.workshop, nn)))
        state = _state(batch, personas, now)
        if state == "valid":
            rows.append(("OK", f"instance {nn}", f"kept: valid until {participants.minute(batch.valid_until)}"))
            continue
        rows.append(("PLAN", f"instance {nn}", f"{WHY[state]}: issue {describe(personas, settings)}, valid "
                                               f"{settings.valid_hours} h from then"))
    todo = sum(1 for r in rows if r[0] == "PLAN")
    if todo and not any(r[0] == "FAIL" for r in checks):
        checks += headroom_rows(env.admin, users, settings.count * todo, now)
    return checks + rows


def status_rows(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona]) -> List[Row]:
    """`status`: each card's batch, from the handout (no Duo call)."""
    now = env.now()
    cards = env.handout().load()
    rows: List[Row] = []
    for nn in numbers:
        name, label = participants.username(env.workshop, nn), f"instance {nn}"
        card = cards.get(name)
        fix = f"`lab5-setup handouts <workshop.yaml> --only {int(nn)}` issues new ones; print the card again"
        if card is None:
            rows.append(("SKIP", label, f"no handout card for {name}"))
            continue
        batch = card_batch(card)
        state = _state(batch, personas, now)
        if state == "none":
            rows.append(("FAIL", label, f"no persona bypass codes on its card: {fix}"))
        elif state == "other":
            have = ", ".join(n for _, n in batch.personas)
            want = ", ".join(n for _, n in personas)
            rows.append(("FAIL", label, f"its codes are for {have}, but workshop.yaml names {want}: re-run up"))
        elif state == "expired":
            when = participants.minute(batch.valid_until) if batch.valid_until else "an unknown time"
            rows.append(("FAIL", label, f"expired at {when}: {fix}"))
        else:
            left = (batch.valid_until - now) / HOUR
            rows.append(("WARN" if left < WARN_HOURS else "OK", label,
                         f"valid until {participants.minute(batch.valid_until)} ({left:.1f} h left) for "
                         + ", ".join(f"{n} (victim)" if r == "victim" else n for r, n in batch.personas)))
    return rows


def latest_expiry(root: Path, workshop: str) -> Optional[float]:
    """When the last batch this workshop issued stops working, from the
    participant records (they outlive the handout)."""
    latest: Optional[float] = None
    folder = Path(root) / "workshops" / workshop / "participants"
    for path in sorted(folder.glob("*.json")) if folder.exists() else []:
        for batch in read_json(path).get("bypass_batches") or []:
            until = participants.parse_time(str(batch.get("valid_until") or ""))
            if until is not None and (latest is None or until > latest):
                latest = until
    return latest


def down_note(root: Path, workshop: str, now: float) -> Optional[str]:
    """`down` deletes no bypass code: valid_secs is the cutoff (see the module docstring)."""
    latest = latest_expiry(root, workshop)
    if latest is None:
        return None
    if latest <= now:
        return f"Persona bypass codes: every batch this workshop issued expired by {participants.minute(latest)}"
    return (f"Persona bypass codes are not deleted: valid_secs is their cutoff, and the last batch stops working at "
            f"{participants.minute(latest)}. Duo returns no id for a code it creates, so lab5-setup cannot tell "
            "this workshop's codes from another room's on a shared persona (deploy/lab5/README.md, Persona bypass "
            "codes)")
