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
  in as it), disabled. So does one in any Duo group that is not Active
  (``GET /admin/v1/users/{id}/groups``): plan 4.3 forbids a bypass group too,
  and Duo lets no member of a disabled group sign in. ``check``, ``up`` and
  ``handouts`` fail each card and name the persona; ``status`` shows each
  persona's Duo status and groups.
* **Locked out is temporary.** Duo unlocks a locked-out persona on its own in
  about 15 minutes (lockout auto-revert, plan 4.4), so it gets no reset advice
  mid-lab: a card issued meanwhile carries the other personas' codes and is
  reported partial, not failed, with ``handouts --only N`` to retry once it is
  unlocked. Its groups still refuse every card as above.
* **A contained victim is skipped, not refused.** The lab ends with the room
  disabling its victim in Duo (claim 4). Once this workshop has given the
  victim codes, a disabled victim is that containment: its codes are left off
  every card, the other personas' codes go on, and nothing asks for a reset
  before the debrief (provision_personas.py --reset runs after the workshop).
  A victim that is disabled before the workshop gave it any code was left so
  by an earlier delivery, and is refused like any persona that is not active.
* **The card is the only copy.** The codes are registered with the redactor
  and written to the 0600 handout, nowhere else. The participant record keeps
  when each batch was issued, when it expires and the ids of its codes, never
  a code.
* **One card's failure is that card's.** A Duo error (lab5_duo turns every
  transport failure into one), or the handout's lock timing out, fails that
  card and the run goes on; a partial batch is recorded as incomplete, with
  the ids of the codes it did issue.

**Revocation.** Duo's create call returns only the code strings, without
their ids. So each create that returns its codes is bracketed by two listings
of the persona's bypass_code ids: exactly ``count`` new ids are this batch's
and go in the participant record. Any other difference (another room issued
codes for the same persona in between), or a second listing that fails,
records that persona's ids as ``unknown`` for the card. So does a create
without a usable answer (lost or cut off, a 5xx, a malformed body): Duo may
have made its codes, which are then on no card, and no listing can tell them
from another room's codes for the same shared persona, so the tool never looks
for them. Its row says "Duo's answer was lost; any codes it made expire at
<time> and cannot be revoked by this tool", whatever the cause. ``down`` and
``handouts --revoke`` delete the recorded ids with
``DELETE /admin/v1/bypass_codes/{id}``, and only ids that are still listed
under the persona they were recorded for; for an unknown entry they say when
its codes expire, and ``down`` never says every batch was deleted.
``valid_hours`` is capped at 72, so an unknown entry is dead long before
``expire`` disables a participant at day 7. A batch whose codes ``down``
deleted gets ``revoked_at`` in the record, and a card whose batch has it is
treated as having no working codes: ``up`` issues a fresh batch for it, and
``check`` and ``status`` say why (the card itself still shows the codes that
were printed). A participant record that cannot be read (not JSON, not a JSON
object, unreadable) fails that card's revocation and keeps ``down`` from
saying every batch was deleted; it never stops the run.

**When a batch stops.** Duo counts ``valid_secs`` from when it makes each
code, so a card's (and the record's) ``valid_until`` is taken after the last
create of the card returned, rounded up to the minute the reports print: never
earlier than any of its codes' own expiry. A create whose answer was lost gets
``LOST_MARGIN_S`` more, for a create Duo finishes after the tool stopped
waiting for it.

``up`` issues a batch for each card that has none, whose batch has expired,
whose batch names other personas (the victim was swapped), or whose batch was
issued with other settings (count, reuse_count, valid_hours); otherwise it
keeps it. ``lab5-setup handouts`` always issues a fresh batch (lab-day
morning, or a lost card); with ``--revoke`` it also deletes the codes of the
card's earlier batches, but only once the card carries its new batch and the
record has it: a card whose new batch failed keeps its earlier codes, and
only the cards that really changed are named for printing.
"""
from __future__ import annotations

import math
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import lab5_participants as participants
from lab5_common import Lab5Error, Redactor, read_json, write_json_private
from lab5_duo import BYPASS_LIMIT, BYPASS_PER_REQUEST, AdminAPI, DuoError, group_status
from lab5_personas import Cast, is_persona_notes

HOUR = 3600
WARN_HOURS = 2.0                       # `status` warns when a batch has less left than this
# A create whose answer was lost (a timeout, a gateway 5xx) may still be
# finished by Duo after the tool stopped waiting: its codes' time gets this
# margin on top (they are on no card, so a later time only delays down's
# "every batch is deleted or has expired").
LOST_MARGIN_S = 300
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
# ... and every Duo group it is in must be Active: a group's status applies to its members (lab5_duo.group_status).
GROUP_WHY = {
    "bypass": "plan 4.3 forbids a bypass group as it forbids bypass status: Duo skips the second factor for the "
              "group's members, so anyone with an instance's access key could sign in as it",
    "disabled": "Duo lets no member of a disabled group sign in, so none of its bypass codes would work",
}
GROUP_FIX = ("take it out of the group, or set the group Active, in the Duo Admin Panel (the tools never change a "
             "persona's groups), then re-run")
# The room's victim, disabled in Duo after this workshop gave it codes: the lab's containment (claim 4).
CONTAINED = ("contained: disabled in Duo after this workshop gave it bypass codes, which is the lab's containment. Its "
             "codes are left off the cards (those already on them no longer work) and the other personas' codes go "
             "on. Keep it disabled through the debrief, and reset it after the workshop ({reset})")
NOT_CONTAINED = ("; this workshop has given it no bypass code yet, so this is not the lab's containment: an earlier "
                 "delivery left it disabled")
# A room persona locked out by failed sign-ins: lockout auto-reverts in about 15 minutes (plan 4.4), so no reset.
LOCKED = ("is locked out in Duo (too many failed sign-ins). Duo unlocks it on its own in about 15 minutes (lockout "
          "auto-revert, plan 4.4), so it needs no reset. Until then none of its bypass codes work and it gets no new "
          "one: a card issued now goes without its codes (partial), and the other personas' codes go on. Retry "
          "`lab5-setup handouts <workshop.yaml> --only N` for those cards once it is unlocked (if it stays locked out, "
          "auto-revert is off: unlock it in the Admin Panel)")
# A create without a usable answer (lost or cut off, a 5xx, a malformed body), whatever the cause: one wording.
LOST = "Duo's answer was lost; any codes it made expire at {until} and cannot be revoked by this tool"
# down and handouts --revoke, for a persona whose codes in a batch have no recorded ids (unknown).
UNKNOWN_IDS = ("{persona} (batch issued {when}): this tool does not know the ids of its codes from that batch, so it "
               "deleted none; any such code expires at {until}")

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


def _when(ts: Optional[float]) -> str:
    return participants.minute(ts) if ts is not None else "an unknown time"


# =========================================================================== cards
@dataclass
class Batch:
    entries: List[Entry]
    valid_until: Optional[float]
    issued_at: Optional[float] = None
    reuse: Optional[int] = None
    revoked_at: Optional[float] = None   # `down` deleted its codes (the participant record says so)
    batch_id: str = ""                   # its id in the participant record (the card's bypass_batch)

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
                 int(reuse) if reuse.isdigit() else None, batch_id=str(card.get("bypass_batch") or ""))


def _read_record(path: Path) -> Dict[str, Any]:
    """A participant record. ValueError when it is not JSON or not a JSON
    object, OSError when it cannot be read: the caller reports that card."""
    rec = read_json(path)
    if not isinstance(rec, dict):
        raise ValueError(f"{Path(path).name} is not a participant record (a JSON object)")
    return rec


def _batches(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A record's batches (the record's own dicts: changes to them are kept)."""
    batches = rec.get("bypass_batches")
    return [b for b in batches if isinstance(b, dict)] if isinstance(batches, list) else []


def _entries(batch: Dict[str, Any]) -> List[Dict[str, Any]]:
    codes = batch.get("codes")
    return [e for e in codes if isinstance(e, dict)] if isinstance(codes, list) else []


def revoked_at(env: participants.Env, nn: str, batch: Batch) -> Optional[float]:
    """When `down` deleted the codes of the recorded batch a card carries (its
    ``bypass_batch`` id; a card written without one, by its issue time and
    the latest batch issued then). None: not revoked, or not known (an
    unreadable record)."""
    try:
        rec = _read_record(env.record_path(nn))
    except (ValueError, OSError):
        return None
    batches = _batches(rec)
    if batch.batch_id:
        mine = [b for b in batches if str(b.get("id") or "") == batch.batch_id]
    else:
        mine = [b for b in batches if batch.issued_at is not None
                and participants.parse_time(str(b.get("issued_at") or "")) == batch.issued_at][-1:]
    return participants.parse_time(str(mine[-1].get("revoked_at") or "")) if mine else None


def card_batch_of(env: participants.Env, nn: str, card: Optional[Dict[str, str]]) -> Optional[Batch]:
    """A card's batch, marked revoked when `down` deleted its codes: the card
    still shows them, but none works."""
    batch = card_batch(card)
    if batch is not None:
        batch.revoked_at = revoked_at(env, nn, batch)
    return batch


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


def _state(batch: Optional[Batch], personas: Sequence[Persona], settings: Settings, now: float,
           absent: Sequence[str] = ()) -> str:
    """A card's batch against the personas it should cover. A persona that
    gets no code in this run (``absent``: the contained victim, a locked-out
    persona) counts on neither side: a batch issued before, with its codes,
    still covers the room, and so does one issued meanwhile, without them
    (missing() tells that partial one apart)."""
    if batch is None:
        return "none"
    if ({p for p in batch.personas if p[1] not in absent}
            != {p for p in personas if p[1] not in absent}):
        return "other"
    if batch.valid_until is None or batch.valid_until <= now:
        return "expired"
    if batch.revoked_at is not None:
        return "revoked"
    if setting_changes(batch, settings):
        return "settings"
    return "valid"


def missing(batch: Optional[Batch], locked: Sequence[str]) -> List[str]:
    """The locked-out personas a card's batch has no codes for: that card is
    partial until a batch issued after they unlock covers them."""
    have = {name for _, name in batch.personas} if batch else set()
    return [name for name in locked if name not in have]


def _partial_note(nn: str, names: Sequence[str]) -> str:
    return (f"none for {', '.join(names)}, locked out in Duo (see its row above): partial. Retry `lab5-setup handouts "
            f"<workshop.yaml> --only {int(nn)}` once it is unlocked (about 15 minutes), then print the card again")


WHY = {"none": "no persona codes on its card yet", "other": "its codes are for other personas",
       "expired": "its codes have expired", "fresh": "a fresh batch",
       "revoked": "`lab5-setup down` revoked its codes, so none on the card works"}


def why(state: str, batch: Optional[Batch], settings: Settings) -> str:
    """Why a card gets a new batch, as `check`, `up` and `handouts` say it."""
    if state == "settings" and batch is not None:
        return f"its codes were issued with other settings ({', '.join(setting_changes(batch, settings))})"
    return WHY[state]


# =========================================================================== Duo
def persona_users(admin: AdminAPI, personas: Sequence[Persona], victim_issued: bool = False
                  ) -> Tuple[Dict[str, Dict[str, Any]], List[Row], List[str], List[str]]:
    """Each room persona's Duo user, status and groups, looked up once.
    ``victim_issued``: this workshop has given the room's victim codes
    (victim_had_codes), so a disabled victim is the lab's containment.

    Returns (the users that get codes, by name; one report row per persona;
    the contained victim, if any; the locked-out personas). A FAIL row means
    no code may be issued to that name, so no card gets a batch in that run.
    The contained victim gets a SKIP row: no code, and no reset before the
    debrief. A locked-out persona (in Active groups only) gets a WARN row: no
    code in this run, no reset (Duo unlocks it on its own, plan 4.4), and the
    cards issued meanwhile are partial."""
    users: Dict[str, Dict[str, Any]] = {}
    rows: List[Row] = []
    contained: List[str] = []
    locked: List[str] = []
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
        status = str(user.get("status") or "").strip().lower()
        held = role == "victim" and status == "disabled" and victim_issued
        lockout = status == "locked out"     # temporary: its groups still decide whether the cards are refused
        if status != "active" and not held and not lockout:
            reason = STATUS_WHY.get(status, f"is {status or 'without a status'} in Duo, not active")
            if role == "victim" and status == "disabled":
                reason += NOT_CONTAINED
            rows.append(("FAIL", name, f"{reason}. No card gets bypass codes while a room persona is not active: "
                                       f"set it active ({RESET.format(name=name)}), then re-run"))
            continue
        try:
            groups = admin.user_groups(str(user["user_id"]))
        except DuoError as exc:
            rows.append(("FAIL", name, f"its Duo groups cannot be read ({exc}); re-run"))
            continue
        # A disabled group changes nothing for a victim that is disabled already; a bypass group would undo it.
        bad = [g for g in groups if group_status(g) != "active" and not (held and group_status(g) == "disabled")]
        if bad:
            rows.append(("FAIL", name, _group_failure(bad)))
            continue
        if held:
            contained.append(name)
            rows.append(("SKIP", name, CONTAINED.format(reset=RESET.format(name=name))))
            continue
        if lockout:
            locked.append(name)
            rows.append(("WARN", name, LOCKED))
            continue
        users[name] = user
        named = ", ".join(str(g.get("name") or g.get("group_id") or "?") for g in groups)
        rows.append(("OK", name, f"active in Duo ({'the room victim' if role == 'victim' else 'trusted'}); "
                                 + (f"its Duo groups are Active: {named}" if groups else "in no Duo group")))
    return users, rows, contained, locked


def _group_failure(bad: Sequence[Dict[str, Any]]) -> str:
    """The FAIL row of a persona in Duo groups that are not Active."""
    named = ", ".join(f"{g.get('name') or g.get('group_id') or '?'} (status {g.get('status') or 'missing'})"
                      for g in bad)
    kinds = {group_status(g) for g in bad}
    why = [GROUP_WHY[k] for k in ("bypass", "disabled") if k in kinds]
    if kinds - set(GROUP_WHY):
        why.append("a group lab5-setup cannot see as Active might bypass or block its members")
    return (f"is in Duo group {named}: {'; '.join(why)}. No card gets bypass codes while a room persona is in a group "
            f"that is not Active: {GROUP_FIX}")


def victim_had_codes(env: participants.Env, personas: Sequence[Persona]) -> bool:
    """Has this workshop given the room's victim bypass codes (a batch in any
    participant record names it)? Only then can a disabled victim be the
    lab's containment: before its first code, the lab has not reached it."""
    victim = next((name for role, name in personas if role == "victim"), "")
    folder = env.ws_dir / "participants"
    if not victim or not folder.is_dir():
        return False
    for path in sorted(folder.glob("*.json")):
        try:
            rec = read_json(path)
        except (ValueError, OSError):
            continue
        batches = rec.get("bypass_batches") if isinstance(rec, dict) else None
        if any(isinstance(b, dict) and victim in (b.get("personas") or []) for b in batches or []):
            return True
    return False


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


def _record(env: participants.Env, nn: str, now: float, until: float, settings: Settings, entries: Sequence[Entry],
            tracked: Dict[str, Tuple[str, List[str]]], unknown: Sequence[Dict[str, str]], complete: bool,
            batch_id: str) -> str:
    """The participant record keeps every batch's times and the ids of its
    codes (never a code), so `down` and `handouts --revoke` can delete them.
    ``unknown``: one entry (persona, user_id, until) per create whose code
    ids this tool does not know, so `down` can say when they expire after the
    handout is gone. Returns the batch's id in the record."""
    path = env.record_path(nn)
    rec = _read_record(path)
    if not isinstance(rec.get("bypass_batches"), list):
        rec["bypass_batches"] = []
    rec["bypass_batches"].append({
        "id": batch_id, "issued_at": _iso(now), "valid_until": _iso(until),
        "personas": [name for _, name, _ in entries], "codes_each": settings.count,
        "reuse_count": settings.reuse_count, "valid_hours": settings.valid_hours, "complete": complete,
        "codes": [{"persona": name, "user_id": uid, "ids": ids} for name, (uid, ids) in tracked.items()],
        "unknown": [dict(entry) for entry in unknown]})
    write_json_private(path, rec)
    return batch_id


def _expiry(env: participants.Env, settings: Settings, lost: bool = False) -> float:
    """When the codes of the creates that have ended by now stop working: Duo
    counts valid_secs from when it made each code, which is by the time its
    answer came back. Rounded up to the minute the reports print, so the time
    is never earlier than the codes' own. A create whose answer was lost
    (``lost``) may be finished by Duo after the tool stopped waiting, so it
    gets ``LOST_MARGIN_S`` more."""
    return math.ceil((env.now() + settings.valid_secs + (LOST_MARGIN_S if lost else 0)) / 60.0) * 60.0


def _unknown(persona: str, uid: str, expires: float) -> Dict[str, str]:
    """A record entry for a create whose code ids this tool does not know."""
    return {"persona": persona, "user_id": uid, "until": _iso(expires)}


def _unknown_entries(batch: Dict[str, Any]) -> List[Tuple[str, Optional[float]]]:
    """(persona, when its codes expire) for each create of a recorded batch
    whose code ids this tool does not know. A record written before each
    entry carried its own time names only the persona (``unknown``, or
    ``untracked`` for an ambiguous listing): those expire with the batch."""
    batch_until = participants.parse_time(str(batch.get("valid_until") or ""))
    out: List[Tuple[str, Optional[float]]] = []
    for item in list(batch.get("unknown") or []) + list(batch.get("untracked") or []):
        if isinstance(item, dict):
            out.append((str(item.get("persona") or "?"),
                        participants.parse_time(str(item.get("until") or "")) or batch_until))
        else:
            out.append((str(item), batch_until))
    return out


def _why_failed(exc: Lab5Error) -> str:
    text = str(exc)
    if isinstance(exc, DuoError) and exc.status == 400:
        text += f" (Duo keeps at most {BYPASS_LIMIT} bypass codes per user)"
    return text


# =========================================================================== commands
def _blocked(checks: Sequence[Row]) -> List[str]:
    return [name for status, name, _ in checks if status == "FAIL"]


@dataclass
class Issued:
    """What issue() did: the report rows, the instance numbers whose card did
    not end up as it should, those whose card now carries a new batch (print
    them again), and those whose batch lacks a locked-out persona's codes
    (partial, not failed: retry handouts once it is unlocked)."""
    rows: List[Row]
    failed: List[str]
    changed: List[str]
    partial: List[str] = field(default_factory=list)


@dataclass
class _CardResult:
    row: Row
    batch_id: Optional[str] = None    # set once the card carries the batch and the participant record has it
    written: bool = False             # the card carries the new batch


def issue(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona], settings: Settings,
          redactor: Redactor, force: bool, revoke: bool = False) -> Issued:
    """`up` (force=False) and `handouts` (force=True; revoke=True for
    --revoke): a batch for each card that needs one. A Duo error or a handout
    lock that times out fails that card only. --revoke deletes a card's
    earlier codes only once its new batch is on the card and recorded."""
    now = env.now()
    handout = env.handout()
    cards = handout.load()
    rows: List[Row] = []
    failed: List[str] = []
    changed: List[str] = []
    present: List[Tuple[str, str, Optional[Batch]]] = []
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
        present.append((nn, name, card_batch_of(env, nn, card)))

    checks: List[Row] = []
    issued: Dict[str, str] = {}
    partial: List[str] = []
    if present:
        users, checks, contained, locked = persona_users(env.admin, personas, victim_had_codes(env, personas))
        blocked = _blocked(checks)
        absent = contained + locked
        wanted = [p for p in personas if p[1] not in absent]
        todo: List[Tuple[str, str, Optional[Batch], str]] = []
        kept: List[Tuple[str, Batch]] = []
        for nn, name, batch in present:
            state = _state(batch, wanted, settings, now, absent)
            if state == "valid" and not force:
                kept.append((nn, batch))
            else:
                todo.append((nn, name, batch, why("fresh" if force else state, batch, settings)))
        for nn, batch in kept:
            until = participants.minute(batch.valid_until)
            if blocked:
                failed.append(nn)
                rows.append(("FAIL", f"instance {nn}", f"keeps its batch (valid until {until}), but "
                                                       f"{', '.join(blocked)} must be fixed: see the persona "
                                                       "row(s) above"))
            elif missing(batch, locked):        # issued during the lockout: still partial
                partial.append(nn)
                rows.append(("PARTIAL", f"instance {nn}", f"kept: valid until {until}; "
                                                          + _partial_note(nn, missing(batch, locked))))
            else:
                rows.append(("OK", f"instance {nn}", f"kept: valid until {until}; `lab5-setup handouts` issues a "
                                                     "fresh batch"))
        if todo and not blocked and wanted:
            room = headroom_rows(env.admin, users, settings.count * len(todo), now)
            checks += room
            blocked = _blocked(room)
        for nn, name, old, reason in todo:
            if blocked or not wanted:           # not wanted: every room persona is locked out or contained
                failed.append(nn)
                rows.append(("FAIL", f"instance {nn}", "no bypass codes issued: see the persona row(s) above. The card "
                                                       f"keeps {'its earlier codes' if old else 'no persona codes'}"))
                continue
            done = _issue_card(env, nn, name, wanted, users, settings, redactor, handout, now, old, reason, contained,
                               locked)
            rows.append(done.row)
            if done.row[0] == "FAIL":
                failed.append(nn)
            elif done.row[0] == "PARTIAL":
                partial.append(nn)
            if done.written:
                changed.append(nn)
            if done.batch_id:
                issued[nn] = done.batch_id
    if revoke:
        listed: Dict[str, Optional[Set[str]]] = {}
        for nn, _, _ in present:
            if nn not in issued:
                # Until the card carries a new batch that its record has, the earlier codes may be the only
                # ones on it that work.
                rows.append(("SKIP", f"instance {nn}", "--revoke deleted none of its earlier codes, because its new "
                                                       "batch was not issued and recorded (see above): re-run "
                                                       f"`lab5-setup handouts <workshop.yaml> --only {int(nn)} "
                                                       "--revoke`"))
                continue
            more, ok = _revoke_guarded(env, nn, now, issued[nn], listed, "its earlier batch(es)")
            rows += more
            if not ok and nn not in failed:
                failed.append(nn)
    return Issued(checks + rows, failed, changed, partial)


def _issue_card(env: participants.Env, nn: str, name: str, personas: Sequence[Persona],
                users: Dict[str, Dict[str, Any]], settings: Settings, redactor: Redactor,
                handout: participants.Handout, now: float, old: Optional[Batch],
                reason: str, contained: Sequence[str] = (), locked: Sequence[str] = ()) -> _CardResult:
    """One card's batch for ``personas`` (the room's, less a contained victim
    and any locked-out persona, which makes the card partial).

    Only a create that returned its codes gets ids: exactly ``count`` new
    ones between the listings just before and after it. Any other
    difference, a second listing that fails, or a create without a usable
    answer records that persona's ids as unknown for this card. After a lost
    answer nothing is listed again: a listing cannot tell the codes Duo may
    have made from another room's codes for the same shared persona."""
    label = f"instance {nn}"
    entries: List[Entry] = []
    tracked: Dict[str, Tuple[str, List[str]]] = {}
    unknown: List[Dict[str, str]] = []
    notes: List[str] = []              # why codes Duo made for this card cannot be revoked by this tool
    error = ""
    for role, persona in personas:
        uid = str(users[persona]["user_id"])
        try:
            before = _code_ids(env.admin, uid)
        except Lab5Error as exc:
            error = f"bypass codes not issued for {persona}: {_why_failed(exc)}"
            break
        try:
            codes = env.admin.create_bypass_codes(uid, settings.count, settings.reuse_count, settings.valid_secs)
        except Lab5Error as exc:
            if not _answer_lost(exc):
                error = f"bypass codes not issued for {persona}: {_why_failed(exc)}"
                break
            expires = _expiry(env, settings, lost=True)
            unknown.append(_unknown(persona, uid, expires))
            error = f"no bypass code for {persona} reached the card: {LOST.format(until=participants.minute(expires))}"
            break
        for code in codes:
            redactor.add(code)
        entries.append((role, persona, codes))
        try:
            new = sorted(_code_ids(env.admin, uid) - before)
            why = "could not be told apart from another room's"
        except Lab5Error as exc:
            new, why = [], f"could not be listed after they were made ({exc})"
        if len(new) == settings.count:      # exactly this batch's: anything else is ambiguous
            tracked[persona] = (uid, new)
        else:
            expires = _expiry(env, settings)
            unknown.append(_unknown(persona, uid, expires))
            notes.append(f"the ids of {persona}'s codes {why}, so this tool cannot revoke them: they expire at "
                         f"{participants.minute(expires)}")
    # Taken once every create of the card has returned: no code on it outlives the card's time.
    until = _expiry(env, settings)
    new_id = secrets.token_hex(4)        # the batch's id in the record, and on the card
    written = False
    if not error:
        try:
            written = handout.update(name, {"bypass": participants.encode_bypass(entries),
                                            "bypass_issued_at": _iso(now), "bypass_valid_until": _iso(until),
                                            "bypass_reuse": str(settings.reuse_count), "bypass_batch": new_id})
            if not written:
                error = "its card left the handout while the codes were issued"
        except (Lab5Error, OSError, ValueError) as exc:
            error = f"the handout was not written ({exc})"
    batch_id: Optional[str] = None
    unrecorded = ""
    if entries or unknown:     # a create without a usable answer may have made codes that are on no card
        try:
            batch_id = _record(env, nn, now, until, settings, entries, tracked, unknown, complete=written,
                               batch_id=new_id)
        except (Lab5Error, OSError, ValueError) as exc:     # ValueError: an unreadable record
            unrecorded = (f"; its participant record was not written ({exc}), so down cannot delete these codes: "
                          f"they stop working at {participants.minute(until)}")
    keeps = f"The card keeps {'its earlier codes' if old else 'no persona codes'}"
    loose = "".join(f"; {note}" for note in notes)
    if error:
        incomplete = ""
        if tracked and batch_id:
            made = sum(len(ids) for _, ids in tracked.values())
            incomplete = (f". The {made} code(s) issued before that ({', '.join(tracked)}) are recorded as an "
                          "incomplete batch, which down and handouts --revoke delete")
        return _CardResult(("FAIL", label, f"{error}. {keeps}{incomplete}{loose}{unrecorded}; re-run"))
    done = f"{reason}: {describe(personas, settings)}, valid until {participants.minute(until)}"
    if contained:
        done += f"; none for {', '.join(contained)}, which is contained (see its row above)"
    if locked:
        done += "; " + _partial_note(nn, locked)
    if unrecorded:
        return _CardResult(("FAIL", label, done + loose + unrecorded), written=True)
    return _CardResult(("PARTIAL" if locked else "CHANGED", label, done + loose), batch_id, written=True)


def _answer_lost(exc: Lab5Error) -> bool:
    """A create without a usable answer (lab5_duo: lost or cut off, not the
    JSON Duo documents, a 5xx) may have made its codes. A refusal from Duo
    (4xx), or a check before the call, made none."""
    return isinstance(exc, DuoError) and exc.lost


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
    rec = _read_record(path)
    batches = [b for b in _batches(rec) if not (keep and b.get("id") == keep)]
    deleted = gone = 0
    errors: List[str] = []
    loose: List[str] = []
    touched = False
    for batch in batches:
        until = participants.parse_time(str(batch.get("valid_until") or ""))
        issued = participants.parse_time(str(batch.get("issued_at") or ""))
        when = participants.minute(issued) if issued else "at an unknown time"
        if until is not None and until > now and "codes" not in batch:
            loose.append(f"the batch issued {when} has no recorded code ids, so it was not deleted: it stops "
                         f"working at {participants.minute(until)} (valid_secs)")
        for persona, expires in _unknown_entries(batch):      # never deleted: say when they stop working
            if expires is None or expires > now:
                loose.append(UNKNOWN_IDS.format(persona=persona, when=when, until=_when(expires)))
        deleted_before = deleted
        for entry in _entries(batch):
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
        # Any of its codes deleted now, or none of its recorded ids left: the card
        # that carries this batch has no working codes any more (card_batch_of).
        if (_entries(batch) and not batch.get("revoked_at")
                and (deleted > deleted_before or not any(e.get("ids") for e in _entries(batch)))):
            batch["revoked_at"] = _iso(now)
            touched = True
    if touched:
        write_json_private(path, rec)
    rows: List[Row] = []
    if errors:
        left_n = sum(len(e.get("ids") or []) for b in batches for e in _entries(b))
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
    """The instances whose participant record still lists code ids to delete,
    or cannot be read (not JSON, not an object, unreadable): revoke() reports
    each of those as not deleted."""
    out: List[str] = []
    for nn in numbers:
        try:
            rec = _read_record(_record_path(root, workshop, nn))
        except (ValueError, OSError):
            out.append(nn)
            continue
        if any(e.get("ids") for b in _batches(rec) for e in _entries(b)):
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
    deleted what it could: when the last one it could not delete stops. The
    codes of an unknown entry (no recorded ids) are never deleted, so with
    one it never says every batch was deleted: it names each one still valid
    and when its codes expire."""
    latest: Optional[float] = None
    seen = unknown_seen = False
    unknown: List[str] = []              # "<persona> on instance <nn>, until <time>": unknown ids, still valid
    unreadable: List[str] = []           # instances whose record cannot be read: nothing known about their codes
    for nn in numbers:
        path = _record_path(root, workshop, nn)
        try:
            batches = _batches(_read_record(path))
        except (ValueError, OSError):
            if path.exists():
                unreadable.append(nn)
            continue
        for batch in batches:
            seen = True
            until = participants.parse_time(str(batch.get("valid_until") or ""))
            if (until is not None and until > now
                    and ("codes" not in batch or any(e.get("ids") for e in batch.get("codes") or []))):
                latest = until if latest is None or until > latest else latest
            for persona, expires in _unknown_entries(batch):
                unknown_seen = True
                if expires is not None and expires <= now:
                    continue
                unknown.append(f"{persona} on instance {nn}, until {_when(expires)}")
                if expires is not None:
                    latest = expires if latest is None or expires > latest else latest
    if unreadable:
        # Never "every batch is deleted": nothing is known about these cards' codes.
        return (f"Persona bypass codes: the participant record of instance {', '.join(unreadable)} cannot be read, "
                "so lab5-setup cannot say whether its codes were deleted. Any it issued stop working at most "
                f"{RANGES['valid_hours'][1]} hours (bypass_codes.valid_hours) after they were issued; restore the "
                f"record under {Path(root) / 'workshops' / workshop / 'participants'} and re-run down to delete them")
    if not seen:
        return None
    if latest is None and not unknown:
        if unknown_seen:
            return ("Persona bypass codes: none of these cards' codes is still valid: the recorded ones are deleted or "
                    "have expired, and so have those whose ids lab5-setup did not know")
        return "Persona bypass codes: every batch these cards had is deleted or has expired"
    return (f"Persona bypass codes that lab5-setup could not delete stay valid until {_when(latest)}: valid_secs is "
            "their cutoff (deploy/lab5/README.md, Persona bypass codes)"
            + (". Not every code was deleted: lab5-setup does not know the ids of these, so it could not delete "
               f"them: {'; '.join(unknown)}" if unknown else ""))


# =========================================================================== check / status
def plan_rows(env: participants.Env, numbers: Sequence[str], personas: Sequence[Persona],
              settings: Settings) -> List[Row]:
    """`check`: what `up` would do with each card's persona codes. Read-only.
    A card `up` would refuse is a FAIL row, so `check` fails as `up` would."""
    now = env.now()
    users, checks, contained, locked = persona_users(env.admin, personas, victim_had_codes(env, personas))
    blocked = _blocked(checks)
    absent = contained + locked
    wanted = [p for p in personas if p[1] not in absent]
    cards = env.handout().load()
    rows: List[Row] = []
    todo = 0
    for nn in numbers:
        batch = card_batch_of(env, nn, cards.get(participants.username(env.workshop, nn)))
        state = _state(batch, wanted, settings, now, absent)
        label = f"instance {nn}"
        if state == "valid":
            until = participants.minute(batch.valid_until)
            if blocked:
                rows.append(("FAIL", label, f"kept: valid until {until}, but {', '.join(blocked)} must be fixed: "
                                            "see the persona row(s) above"))
            elif missing(batch, locked):
                rows.append(("PARTIAL", label, f"kept: valid until {until}; {_partial_note(nn, missing(batch, locked))}"))
            else:
                rows.append(("OK", label, f"kept: valid until {until}"))
            continue
        plan = (f"{why(state, batch, settings)}: issue {describe(wanted, settings)}, valid "
                f"{settings.valid_hours} h from then"
                + (f"; none for {', '.join(contained)}, which is contained" if contained else "")
                + (f"; {_partial_note(nn, locked)}" if locked else ""))
        if blocked or not wanted:
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
    """`status`: each room persona's Duo status and groups, then each card's batch (from the handout)."""
    now = env.now()
    _, checks, contained, locked = persona_users(env.admin, personas, victim_had_codes(env, personas))
    absent = contained + locked
    wanted = [p for p in personas if p[1] not in absent]
    cards = env.handout().load()
    rows: List[Row] = []
    for nn in numbers:
        name, label = participants.username(env.workshop, nn), f"instance {nn}"
        card = cards.get(name)
        fix = f"`lab5-setup handouts <workshop.yaml> --only {int(nn)}` issues new ones; print the card again"
        if card is None:
            rows.append(("SKIP", label, f"no handout card for {name}"))
            continue
        batch = card_batch_of(env, nn, card)
        state = _state(batch, wanted, settings, now, absent)
        if state == "none":
            rows.append(("FAIL", label, f"no persona bypass codes on its card: {fix}"))
        elif state == "revoked":
            rows.append(("FAIL", label, f"`lab5-setup down` revoked its codes at {participants.minute(batch.revoked_at)}, "
                                        f"so none on the card works: up or {fix}"))
        elif state == "other":
            have = ", ".join(n for _, n in batch.personas)
            want = (", ".join(n for _, n in wanted) + (f" ({', '.join(contained)} is contained)" if contained else "")
                    + (f" ({', '.join(locked)} is locked out)" if locked else ""))
            rows.append(("FAIL", label, f"its codes are for {have}, but workshop.yaml names {want}: re-run up"))
        elif state == "expired":
            when = participants.minute(batch.valid_until) if batch.valid_until else "an unknown time"
            rows.append(("FAIL", label, f"expired at {when}: {fix}"))
        else:
            left = (batch.valid_until - now) / HOUR
            notes = [("victim" if r == "victim" else "")
                     + (", contained: its code no longer works" if n in contained else "")
                     + (", locked out: its code works again once Duo unlocks it" if n in locked else "")
                     for r, n in batch.personas]
            detail = (f"valid until {participants.minute(batch.valid_until)} ({left:.1f} h left) for "
                      + ", ".join(f"{n} ({note.lstrip(', ')})" if note else n
                                  for (_, n), note in zip(batch.personas, notes)))
            if missing(batch, locked):
                rows.append(("PARTIAL", label, f"{detail}; {_partial_note(nn, missing(batch, locked))}"))
            elif state == "settings":
                rows.append(("WARN", label, f"{detail}; issued with other settings than workshop.yaml's "
                                            f"({', '.join(setting_changes(batch, settings))}): re-run up"))
            else:
                rows.append(("WARN" if left < WARN_HOURS else "OK", label, detail))
    return checks + rows
