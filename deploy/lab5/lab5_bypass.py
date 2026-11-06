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
* **Only the cast's personas, and only while they are active.** A batch goes
  only to a user that personas.yaml lists with the matching role (victim, or
  spike for a dry run; trusted) and whose Duo notes carry the persona marker:
  never a participant account, an administrator, or whoever a typo in
  workshop.yaml names. A room persona whose Duo status is anything but
  ``active`` stops every card's batch: bypass status (plan 4.3 forbids it: Duo
  skips the second factor, so anyone with an instance's access key could sign
  in as it), disabled, locked out. ``check``, ``up`` and ``handouts`` fail
  each card and name the persona; ``status`` shows each persona's Duo status.
* **The card is the only copy.** The codes are registered with the redactor
  and written to the 0600 handout, nowhere else. The participant record keeps
  when each batch was issued, when it expires and the ids of its codes, never
  a code.
* **One card's failure is that card's.** A Duo error, or the handout's lock
  timing out, fails that card and the run goes on; a partial batch is
  recorded as incomplete, with the ids of the codes it did issue.

**Revocation.** Duo's create call returns only the code strings, without
their ids. So each create is bracketed by two listings of the persona's
bypass_code ids: exactly ``count`` new ids are this batch's and go in the
participant record. Any other difference (another room issued codes for the
same persona in between) records none for that persona: those codes stop only
at ``valid_secs``. ``down`` and ``handouts --revoke`` delete the recorded ids
with ``DELETE /admin/v1/bypass_codes/{id}``, and only ids that are still listed
under the persona they were recorded for. ``valid_hours`` is capped at 72, so
an untracked batch is dead long before ``expire`` disables a participant at
day 7.

``up`` issues a batch for each card that has none, whose batch has expired,
whose batch names other personas (the victim was swapped), or whose batch was
issued with other settings (count, reuse_count, valid_hours); otherwise it
keeps it. ``lab5-setup handouts`` always issues a fresh batch (lab-day
morning, or a lost card); with ``--revoke`` it also deletes the codes of the
card's earlier batches.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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
# A room persona must be `active` in Duo to get codes (plan 4.3); the reason for each other status.
STATUS_WHY = {
    "bypass": "is in bypass status in Duo, which plan 4.3 forbids: Duo skips the second factor for it, so anyone "
              "with an instance's access key could sign in as it",
    "disabled": "is disabled in Duo, so none of its bypass codes work",
    "locked out": "is locked out in Duo, so none of its bypass codes work",
}
RESET = "scripts/identity/provision_personas.py --reset --only {name}"

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
    issued_at: Optional[float] = None
    reuse: Optional[int] = None

    @property
    def personas(self) -> List[Persona]:
        return [(role, name) for role, name, _ in self.entries]

    @property
    def hours(self) -> Optional[int]:
        """The valid_hours it was issued with, from the card's two times."""
        if self.issued_at is None or self.valid_until is None:
            return None
        return int(round((self.valid_until - self.issued_at) / HOUR))


def card_batch(card: Optional[Dict[str, str]]) -> Optional[Batch]:
    card = card or {}
    entries = participants.decode_bypass(card.get("bypass"))
    if not entries:
        return None
    reuse = str(card.get("bypass_reuse") or "").strip()
    return Batch(entries, participants.parse_time(card.get("bypass_valid_until") or ""),
                 participants.parse_time(card.get("bypass_issued_at") or ""),
                 int(reuse) if reuse.isdigit() else None)


def setting_changes(batch: Batch, settings: Settings) -> List[str]:
    """How the settings a card's batch was issued with differ from workshop.yaml's."""
    out: List[str] = []
    counts = sorted({len(codes) for _, _, codes in batch.entries})
    if counts != [settings.count]:
        out.append(f"count {'/'.join(str(c) for c in counts)} -> {settings.count}")
    if batch.reuse != settings.reuse_count:
        out.append(f"reuse_count {'?' if batch.reuse is None else batch.reuse} -> {settings.reuse_count}")
    if batch.hours != settings.valid_hours:
        out.append(f"valid_hours {'?' if batch.hours is None else batch.hours} -> {settings.valid_hours}")
    return out


def _state(batch: Optional[Batch], personas: Sequence[Persona], settings: Settings, now: float) -> str:
    if batch is None:
        return "none"
    if set(batch.personas) != set(personas):
        return "other"
    if batch.valid_until is None or batch.valid_until <= now:
        return "expired"
    if setting_changes(batch, settings):
        return "settings"
    return "valid"


WHY = {"none": "no persona codes on its card yet", "other": "its codes are for other personas",
       "expired": "its codes have expired", "fresh": "a fresh batch"}


def why(state: str, batch: Optional[Batch], settings: Settings) -> str:
    """Why a card gets a new batch, as `check`, `up` and `handouts` say it."""
    if state == "settings" and batch is not None:
        return f"its codes were issued with other settings ({', '.join(setting_changes(batch, settings))})"
    return WHY[state]


# =========================================================================== Duo
def persona_users(admin: AdminAPI, personas: Sequence[Persona]) -> Tuple[Dict[str, Dict[str, Any]], List[Row]]:
    """Each room persona's Duo user and status, looked up once. Returns (the
    usable users by name, one report row per persona). A FAIL row means no
    code may be issued to that name, so no card gets a batch in that run."""
    users: Dict[str, Dict[str, Any]] = {}
    rows: List[Row] = []
    for role, name in personas:
        try:
            user = admin.user_by_name(name)
        except DuoError as exc:
            rows.append(("FAIL", name, f"cannot be read from Duo ({exc}); re-run"))
            continue
        if not user:
            rows.append(("FAIL", name, "missing in Duo: run scripts/identity/provision_personas.py, then re-run"))
            continue
        if not is_persona_notes(user.get("notes")):
            rows.append(("FAIL", name, "exists in Duo without the persona notes marker: not the cast's persona, so it "
                                       "gets no bypass code; left alone"))
            continue
        status = str(user.get("status") or "")
        if status != "active":
            reason = STATUS_WHY.get(status, f"is {status or 'without a status'} in Duo, not active")
            rows.append(("FAIL", name, f"{reason}. No card gets bypass codes while a room persona is not active: "
                                       f"set it active ({RESET.format(name=name)}), then re-run"))
            continue
        users[name] = user
        rows.append(("OK", name, f"active in Duo ({'the room victim' if role == 'victim' else 'trusted'})"))
    return users, rows


def _code_ids(admin: AdminAPI, user_id: str) -> Set[str]:
    return {str(c.get("bypass_code_id")) for c in admin.user_bypass_codes(user_id) if c.get("bypass_code_id")}


def headroom_rows(admin: AdminAPI, users: Dict[str, Dict[str, Any]], needed: int, now: float) -> List[Row]:
    """FAIL rows for personas that would pass Duo's 100-code limit. Codes
    that have not expired count, the other rooms' included."""
    rows: List[Row] = []
    for name, user in users.items():
        try:
            listed = admin.user_bypass_codes(str(user["user_id"]))
        except DuoError as exc:
            rows.append(("FAIL", name, f"its bypass codes cannot be listed ({exc}); re-run"))
            continue
        held = 0
        for meta in listed:
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
            tracked: Dict[str, Tuple[str, List[str]]], untracked: Sequence[str], complete: bool) -> str:
    """The participant record keeps every batch's times and the ids of its
    codes (never a code), so `down` and `handouts --revoke` can delete them
    and `down` can say when an untracked one stops working after the handout
    is gone. Returns the batch's id in the record."""
    path = env.record_path(nn)
    rec = read_json(path)
    batch_id = secrets.token_hex(4)
    rec.setdefault("bypass_batches", []).append({
        "id": batch_id, "issued_at": _iso(now), "valid_until": _iso(now + settings.valid_secs),
        "personas": [name for _, name, _ in entries], "codes_each": settings.count,
        "reuse_count": settings.reuse_count, "valid_hours": settings.valid_hours, "complete": complete,
        "codes": [{"persona": name, "user_id": uid, "ids": ids} for name, (uid, ids) in tracked.items()],
        "untracked": list(untracked)})
    write_json_private(path, rec)
    return batch_id


def _why_failed(exc: Lab5Error) -> str:
    text = str(exc)
    if isinstance(exc, DuoError) and exc.status == 400:
        text += f" (Duo keeps at most {BYPASS_LIMIT} bypass codes per user)"
    return text


# =========================================================================== commands
def _blocked(checks: Sequence[Row]) -> List[str]:
    return [name for status, name, _ in checks if status == "FAIL"]


def issue(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona], settings: Settings,
          redactor: Redactor, force: bool, revoke: bool = False) -> Tuple[List[Row], List[str]]:
    """`up` (force=False) and `handouts` (force=True; revoke=True for
    --revoke): a batch for each card that needs one. A Duo error or a handout
    lock that times out fails that card only. Returns (report rows, the
    instance numbers whose card did not end up as it should)."""
    now = env.now()
    handout = env.handout()
    cards = handout.load()
    rows: List[Row] = []
    failed: List[str] = []
    todo: List[Tuple[str, str, Optional[Batch], str]] = []
    kept: List[Tuple[str, Batch]] = []
    for nn in numbers:
        name, label = participants.username(env.workshop, nn), f"instance {nn}"
        card = cards.get(name)
        if card is None:
            if force:
                failed.append(nn)
                rows.append(("FAIL", label, f"no handout card for {name}: `up` makes it with the participant account"))
            else:
                rows.append(("SKIP", label, f"no handout card for {name} (see its participant row)"))
            continue
        batch = card_batch(card)
        state = _state(batch, personas, settings, now)
        if state == "valid" and not force:
            kept.append((nn, batch))
        else:
            todo.append((nn, name, batch, why("fresh" if force else state, batch, settings)))

    checks: List[Row] = []
    issued: Dict[str, str] = {}
    if todo or kept:
        users, checks = persona_users(env.admin, personas)
        blocked = _blocked(checks)
        for nn, batch in kept:
            until = participants.minute(batch.valid_until)
            if blocked:
                failed.append(nn)
                rows.append(("FAIL", f"instance {nn}", f"keeps its batch (valid until {until}), but "
                                                       f"{', '.join(blocked)} must be fixed: see the persona "
                                                       "row(s) above"))
            else:
                rows.append(("OK", f"instance {nn}", f"kept: valid until {until}; `lab5-setup handouts` issues a "
                                                     "fresh batch"))
        if todo and not blocked:
            room = headroom_rows(env.admin, users, settings.count * len(todo), now)
            checks += room
            blocked = _blocked(room)
        for nn, name, old, reason in todo:
            if blocked:
                failed.append(nn)
                rows.append(("FAIL", f"instance {nn}", "no bypass codes issued: see the persona row(s) above. The card "
                                                       f"keeps {'its earlier codes' if old else 'no persona codes'}"))
                continue
            row, batch_id = _issue_card(env, nn, name, personas, users, settings, redactor, handout, now, old, reason)
            rows.append(row)
            if row[0] == "FAIL":
                failed.append(nn)
            if batch_id:
                issued[nn] = batch_id
    if revoke:
        listed: Dict[str, Optional[Set[str]]] = {}
        for nn in numbers:
            more, ok = _revoke_guarded(env, nn, now, issued.get(nn), listed, "its earlier batch(es)")
            rows += more
            if not ok and nn not in failed:
                failed.append(nn)
    return checks + rows, failed


def _issue_card(env: participants.Env, nn: str, name: str, personas: Sequence[Persona],
                users: Dict[str, Dict[str, Any]], settings: Settings, redactor: Redactor,
                handout: participants.Handout, now: float, old: Optional[Batch],
                reason: str) -> Tuple[Row, Optional[str]]:
    """One card's batch. Returns its report row and, once the card carries the
    batch, the batch's id in the participant record."""
    label = f"instance {nn}"
    entries: List[Entry] = []
    tracked: Dict[str, Tuple[str, List[str]]] = {}
    untracked: List[str] = []
    error = ""
    for role, persona in personas:
        uid = str(users[persona]["user_id"])
        try:
            before = _code_ids(env.admin, uid)
            codes = env.admin.create_bypass_codes(uid, settings.count, settings.reuse_count, settings.valid_secs)
        except Lab5Error as exc:
            error = f"bypass codes not issued for {persona}: {_why_failed(exc)}"
            break
        for code in codes:
            redactor.add(code)
        entries.append((role, persona, codes))
        try:
            new = sorted(_code_ids(env.admin, uid) - before)
        except Lab5Error:
            new = []
        if len(new) == settings.count:      # exactly this batch's: anything else is ambiguous
            tracked[persona] = (uid, new)
        else:
            untracked.append(persona)
    until = now + settings.valid_secs
    written = False
    if not error:
        try:
            written = handout.update(name, {"bypass": participants.encode_bypass(entries),
                                            "bypass_issued_at": _iso(now), "bypass_valid_until": _iso(until),
                                            "bypass_reuse": str(settings.reuse_count)})
            if not written:
                error = "its card left the handout while the codes were issued"
        except (Lab5Error, OSError) as exc:
            error = f"the handout was not written ({exc})"
    batch_id: Optional[str] = None
    unrecorded = ""
    if entries:
        try:
            batch_id = _record(env, nn, now, settings, entries, tracked, untracked, complete=written)
        except (Lab5Error, OSError, ValueError) as exc:     # ValueError: an unreadable record
            unrecorded = (f"; its participant record was not written ({exc}), so down cannot delete these codes: "
                          f"they stop working at {participants.minute(until)}")
    keeps = f"The card keeps {'its earlier codes' if old else 'no persona codes'}"
    if error:
        partial = ""
        if entries and batch_id:
            made = sum(len(codes) for _, _, codes in entries)
            partial = (f". The {made} code(s) issued before that ({', '.join(p for _, p, _ in entries)}) are recorded "
                       "as an incomplete batch, which down and handouts --revoke delete")
        return ("FAIL", label, f"{error}. {keeps}{partial}{unrecorded}; re-run"), None
    done = f"{reason}: {describe(personas, settings)}, valid until {participants.minute(until)}"
    if unrecorded:
        return ("FAIL", label, done + unrecorded), None
    loose = (f"; the ids of {', '.join(untracked)}'s codes could not be told apart from another room's, so down "
             "leaves those to valid_secs" if untracked else "")
    return ("CHANGED", label, done + loose), batch_id


# =========================================================================== revocation
def _record_path(root: Path, workshop: str, nn: str) -> Path:
    return Path(root) / "workshops" / workshop / "participants" / f"{nn}.json"


def _listed(admin: AdminAPI, user_id: str) -> Optional[Set[str]]:
    """A persona's current bypass code ids, or None when Duo has no such user
    (deleting a user deletes its codes)."""
    try:
        return _code_ids(admin, user_id)
    except DuoError as exc:
        if exc.status == 404:
            return None
        raise


def _revoke_card(env: participants.Env, nn: str, now: float, keep: Optional[str],
                 listed: Dict[str, Optional[Set[str]]], scope: str) -> Tuple[List[Row], bool]:
    """Delete the recorded code ids of this card's batches (all but ``keep``),
    each only while it is still listed under the persona it was recorded for.
    ``listed`` caches those listings across cards. Returns (rows, all done)."""
    label = f"instance {nn}"
    path = env.record_path(nn)
    rec = read_json(path)
    batches = [b for b in rec.get("bypass_batches") or [] if not (keep and b.get("id") == keep)]
    deleted = gone = 0
    errors: List[str] = []
    loose: List[str] = []
    touched = False
    for batch in batches:
        until = participants.parse_time(str(batch.get("valid_until") or ""))
        issued = participants.parse_time(str(batch.get("issued_at") or ""))
        when = participants.minute(issued) if issued else "at an unknown time"
        if until is not None and until > now:
            if "codes" not in batch:
                loose.append(f"the batch issued {when} has no recorded code ids, so it was not deleted: it stops "
                             f"working at {participants.minute(until)} (valid_secs)")
            elif batch.get("untracked"):
                loose.append(f"{', '.join(batch['untracked'])}: the codes of the batch issued {when} could not be told "
                             "apart from another room's, so they were not deleted: they stop working at "
                             f"{participants.minute(until)} (valid_secs)")
        for entry in batch.get("codes") or []:
            ids = [str(i) for i in entry.get("ids") or []]
            if not ids:
                continue
            touched = True
            uid = str(entry.get("user_id") or "")
            try:
                if uid not in listed:
                    listed[uid] = _listed(env.admin, uid)
            except DuoError as exc:
                errors.append(f"{entry.get('persona')}: {exc}")
                continue
            live = listed[uid]
            left: List[str] = []
            for code_id in ids:
                if live is None or code_id not in live:
                    gone += 1                    # used up, expired or deleted already
                    continue
                try:
                    if env.admin.delete_bypass_code(code_id):
                        deleted += 1
                    else:
                        gone += 1
                    live.discard(code_id)
                except DuoError as exc:
                    left.append(code_id)
                    errors.append(f"{entry.get('persona')}: {exc}")
            entry["ids"] = left
        if batch.get("codes") and not any(e.get("ids") for e in batch["codes"]) and not batch.get("revoked_at"):
            batch["revoked_at"] = _iso(now)
    if touched:
        write_json_private(path, rec)
    rows: List[Row] = []
    if errors:
        left_n = sum(len(e.get("ids") or []) for b in batches for e in b.get("codes") or [])
        rows.append(("FAIL", label, f"deleted {deleted} bypass code(s) of {scope}; {left_n} not deleted "
                                    f"({errors[0]}): re-run to delete them"))
    elif deleted:
        rows.append(("CHANGED", label, f"deleted {deleted} bypass code(s) of {scope}"
                                       + (f"; {gone} more were used up, expired or deleted already" if gone else "")))
    elif gone:
        rows.append(("OK", label, f"the {gone} recorded bypass code(s) of {scope} were used up, expired or deleted "
                                  "already"))
    elif not loose:
        rows.append(("OK", label, f"no recorded bypass code of {scope} to delete"))
    rows += [("WARN", label, text) for text in loose]
    return rows, not errors


def _revoke_guarded(env: participants.Env, nn: str, now: float, keep: Optional[str],
                    listed: Dict[str, Optional[Set[str]]], scope: str) -> Tuple[List[Row], bool]:
    try:
        return _revoke_card(env, nn, now, keep, listed, scope)
    except (Lab5Error, OSError, ValueError) as exc:
        return [("FAIL", f"instance {nn}", f"the bypass codes of {scope} were not deleted ({exc}): re-run")], False


def pending(root: Path, workshop: str, numbers: Sequence[str]) -> List[str]:
    """The instances whose participant record still lists code ids to delete."""
    out: List[str] = []
    for nn in numbers:
        try:
            rec = read_json(_record_path(root, workshop, nn))
        except ValueError:
            out.append(nn)                       # unreadable: revoke() reports it
            continue
        if any(e.get("ids") for b in rec.get("bypass_batches") or [] for e in b.get("codes") or []):
            out.append(nn)
    return out


def revoke(env: participants.Env, numbers: Sequence[str]) -> Tuple[List[Row], List[str]]:
    """`down`: delete the recorded code ids of every batch these cards had.
    Returns (rows, the instance numbers whose codes were not all deleted)."""
    now = env.now()
    listed: Dict[str, Optional[Set[str]]] = {}
    rows: List[Row] = []
    failed: List[str] = []
    for nn in numbers:
        more, ok = _revoke_guarded(env, nn, now, None, listed, "its batch(es)")
        rows += more
        if not ok:
            failed.append(nn)
    return rows, failed


def down_note(root: Path, workshop: str, now: float, numbers: Sequence[str]) -> Optional[str]:
    """`down`'s last word on these cards' persona bypass codes, once it has
    deleted what it could: when the last one it could not delete stops."""
    latest: Optional[float] = None
    seen = False
    for nn in numbers:
        try:
            batches = read_json(_record_path(root, workshop, nn)).get("bypass_batches") or []
        except ValueError:
            continue
        for batch in batches:
            seen = True
            until = participants.parse_time(str(batch.get("valid_until") or ""))
            if until is None or until <= now:
                continue
            if ("codes" not in batch or batch.get("untracked")
                    or any(e.get("ids") for e in batch.get("codes") or [])):
                latest = until if latest is None or until > latest else latest
    if not seen:
        return None
    if latest is None:
        return "Persona bypass codes: every batch these cards had is deleted or has expired"
    return (f"Persona bypass codes that lab5-setup could not delete stay valid until {participants.minute(latest)}: "
            "valid_secs is their cutoff (deploy/lab5/README.md, Persona bypass codes)")


# =========================================================================== check / status
def plan_rows(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona],
              settings: Settings) -> List[Row]:
    """`check`: what `up` would do with each card's persona codes. Read-only.
    A card `up` would refuse is a FAIL row, so `check` fails as `up` would."""
    now = env.now()
    users, checks = persona_users(env.admin, personas)
    blocked = _blocked(checks)
    cards = env.handout().load()
    rows: List[Row] = []
    todo = 0
    for nn in numbers:
        batch = card_batch(cards.get(participants.username(env.workshop, nn)))
        state = _state(batch, personas, settings, now)
        label = f"instance {nn}"
        if state == "valid":
            until = participants.minute(batch.valid_until)
            if blocked:
                rows.append(("FAIL", label, f"kept: valid until {until}, but {', '.join(blocked)} must be fixed: "
                                            "see the persona row(s) above"))
            else:
                rows.append(("OK", label, f"kept: valid until {until}"))
            continue
        plan = (f"{why(state, batch, settings)}: issue {describe(personas, settings)}, valid "
                f"{settings.valid_hours} h from then")
        if blocked:
            rows.append(("FAIL", label, f"{plan}; up issues none until the persona row(s) above are fixed"))
        else:
            todo += 1
            rows.append(("PLAN", label, plan))
    if todo and not blocked:
        room = headroom_rows(env.admin, users, settings.count * todo, now)
        checks += room
        if _blocked(room):
            rows = [("FAIL", label, f"{detail}; up issues none until the persona row(s) above are fixed")
                    if status == "PLAN" else (status, label, detail) for status, label, detail in rows]
    return checks + rows


def status_rows(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona],
                settings: Settings) -> List[Row]:
    """`status`: each room persona's Duo status, then each card's batch (from the handout)."""
    now = env.now()
    _, checks = persona_users(env.admin, personas)
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
        state = _state(batch, personas, settings, now)
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
            detail = (f"valid until {participants.minute(batch.valid_until)} ({left:.1f} h left) for "
                      + ", ".join(f"{n} (victim)" if r == "victim" else n for r, n in batch.personas))
            if state == "settings":
                rows.append(("WARN", label, f"{detail}; issued with other settings than workshop.yaml's "
                                            f"({', '.join(setting_changes(batch, settings))}): re-run up"))
            else:
                rows.append(("WARN" if left < WARN_HOURS else "OK", label, detail))
    return checks + rows
