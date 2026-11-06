"""Participant accounts (plan 12.2, 12.4): one Duo account per Lab 5 instance.

``l5-<workshop>-<nn>`` (email ``l5-<workshop>-<nn>@<zone>``; CII matches users
by email) is created by ``lab5-setup up`` with the Admin API app **PseudoCo
Provisioner**, in **CII Read-Only** (Duo SSO into Identity Intelligence) and
the per-workshop group ``l5-<workshop>``, with notes recording the workshop,
the instance and the creation time. Its own API-created HOTP token is
attached, the token's first 10 passcodes go on the handout, and the secret is
discarded. The account itself never gets a bypass code (12.4); its card also
carries the room personas' bypass codes for that team (lab5_bypass, plan 4.3).

The Admin API cannot set a Duo Directory password: after ``up`` the
facilitator opens each account (the links are printed) and clicks *Create
temporary password*; ``status`` shows who has a password (``has_password``).

``expire`` (daily from launchd): day 7 disables, day 14 deletes the account and
its token, which frees the Duo seat. It acts only on accounts that carry all
three markers -- the ``l5-<workshop>-<nn>`` username, the notes marker naming
that same workshop and instance, and membership of ``l5-<workshop>`` -- and
never on a persona (a name in the cast, or persona notes). A participant that
someone also put in the persona group is still a participant: see ownership().

Participants sign in to their instance through the Web SDK app **PseudoCo
Lab: Sign-in**, whose User access must admit **CII Read-Only** besides the
persona group (deploy/lab5/README.md, "Duo applications"); the Provisioner app
cannot read or set it.

Files (no secret except in the handout): ``workshops/<ws>/participants/<nn>.json``
records ids and times; ``workshops/<ws>/handout.csv`` and ``handout.html`` (0600)
are the sign-in sheet: instance URL, access key, username, passcodes and the
team's persona bypass codes.
"""
from __future__ import annotations

import csv
import html
import io
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from lab5_common import Lab5Error, file_lock, private_dir, read_json, utc_now, write_json_private
from lab5_duo import (AdminAPI, DuoError, admin_panel_url, assigned_elsewhere, encode_secret, group_names, hotp,
                      new_hotp_secret)
from lab5_personas import Cast, is_persona_notes

MARKER = "lab5-setup participant"
CII_READ_ONLY = "CII Read-Only"
SIGNIN_APP = "PseudoCo Lab: Sign-in"     # the Web SDK app (12.1): its User access must admit CII_READ_ONLY
DISABLE_DAYS = 7
DELETE_DAYS = 14
PASSCODES = 10
DAY = 86400.0

USERNAME_RE = re.compile(r"^l5-(?P<workshop>[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?)-(?P<nn>[0-9]{2})$")
_NOTES_RE = re.compile(r"^lab5-setup participant; workshop=(?P<workshop>[a-z0-9-]+); "
                       r"instance=(?P<nn>[0-9]{2}); created=(?P<created>\S+)$")

Row = Tuple[str, str, str]


def username(workshop: str, nn: str) -> str:
    return f"l5-{workshop}-{nn}"


def group_name(workshop: str) -> str:
    return f"l5-{workshop}"


def notes_for(workshop: str, nn: str, created: str) -> str:
    return f"{MARKER}; workshop={workshop}; instance={nn}; created={created}"


def parse_notes(notes: Optional[str]) -> Optional[Dict[str, str]]:
    m = _NOTES_RE.match(str(notes or "").strip())
    return m.groupdict() if m else None


def _parse_time(text: str) -> Optional[float]:
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.timestamp()


def created_at(user: Dict[str, Any]) -> Optional[float]:
    """Duo's own ``created`` (server-set) wins; the notes' time is the fallback."""
    created = user.get("created")
    if isinstance(created, (int, float)) and not isinstance(created, bool) and created > 0:
        return float(created)
    parsed = parse_notes(user.get("notes"))
    return _parse_time(parsed["created"]) if parsed else None


def day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def minute(ts: float) -> str:
    """A time as printed on the cards and in the reports: UTC, to the minute."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def age_text(seconds: float) -> str:
    return f"{max(0.0, seconds) / DAY:.1f} d"


def ownership(user: Dict[str, Any], personas: Set[str], persona_group: str,
              require_group: bool = True) -> Tuple[Optional[Dict[str, str]], str]:
    """``(markers, "")`` when lab5-setup created this account, else ``(None, why)``.

    A persona is a name in the cast or a user whose notes carry the persona
    marker; personas.yaml reserves ``l5-`` for participants, so neither ever
    matches a participant. Membership of the persona group does not make an
    account a persona: anyone can add a participant to it in the Admin Panel
    (say, to get it past a Sign-in app limited to that group), and it is
    still disabled and deleted on schedule, or its seat is never freed.
    ``markers["persona_group"]`` names the group then, for the report."""
    name = str(user.get("username") or "")
    m = USERNAME_RE.match(name)
    if not m:
        return None, "not an l5-<workshop>-<nn> username"
    if name in personas or is_persona_notes(user.get("notes")):
        return None, "it is a persona"
    notes = parse_notes(user.get("notes"))
    if not notes:
        return None, "its notes do not carry the lab5-setup participant marker"
    if notes["workshop"] != m.group("workshop") or notes["nn"] != m.group("nn"):
        return None, "its notes name another workshop or instance"
    groups = group_names(user)
    if require_group and group_name(m.group("workshop")) not in groups:
        return None, f"it is not in group {group_name(m.group('workshop'))}"
    return {"workshop": m.group("workshop"), "nn": m.group("nn"), "created": notes["created"],
            "persona_group": persona_group if persona_group in groups else ""}, ""


def persona_group_note(markers: Dict[str, str]) -> str:
    """The report's note on a participant someone added to the persona group."""
    group = markers.get("persona_group")
    return (f"; also in {group}, which no participant needs ({SIGNIN_APP} admits participants through "
            f"{CII_READ_ONLY})" if group else "")


# =========================================================================== handout
# The persona bypass codes of a card (lab5_bypass, plan 4.3): ``bypass`` holds
# "role:username=code[,code]" words, e.g. "victim:avery.kim=407176182
# trusted:marcus.bell=016931781"; the next three say when they were issued,
# when they expire and how many sign-ins each code allows; ``bypass_batch``
# is the batch's id in the participant record (not a secret), so `down`'s
# revocation of that batch is seen on the card.
BYPASS_FIELDS = ["bypass", "bypass_issued_at", "bypass_valid_until", "bypass_reuse", "bypass_batch"]
FIELDS = ["instance", "url", "access_key", "username", "email", "passcodes", "issued_at", "disable_on", "delete_on",
          "cii_url"] + BYPASS_FIELDS
_BYPASS_WORD_RE = re.compile(r"^(?P<role>victim|trusted):(?P<user>[a-z][a-z0-9._-]{0,63})="
                             r"(?P<codes>[0-9]{6,20}(?:,[0-9]{6,20})*)$")


def encode_bypass(entries: Iterable[Tuple[str, str, Sequence[str]]]) -> str:
    return " ".join(f"{role}:{user}={','.join(codes)}" for role, user, codes in entries)


def decode_bypass(text: Optional[str]) -> List[Tuple[str, str, List[str]]]:
    """``[(role, username, codes)]`` from a card's ``bypass`` field."""
    out: List[Tuple[str, str, List[str]]] = []
    for word in str(text or "").split():
        m = _BYPASS_WORD_RE.match(word)
        if m:
            out.append((m.group("role"), m.group("user"), m.group("codes").split(",")))
    return out


def parse_time(text: str) -> Optional[float]:
    return _parse_time(text) if text else None


def _write_private(path: Path, text: str) -> None:
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Handout:
    """The workshop's sign-in sheet: ``handout.csv`` (the source, also good
    for a mail merge) and ``handout.html`` (one printable card per instance).
    Both 0600. A card leaves the sheet once its account is disabled. Every
    change re-reads the sheet under a lock, so `up`, `handouts` and the daily
    `expire` never undo each other's cards."""

    def __init__(self, ws_dir: Path, workshop: str, cii_url: str = "") -> None:
        self.dir, self.workshop, self.cii_url = Path(ws_dir), workshop, cii_url
        self.csv_path = self.dir / "handout.csv"
        self.html_path = self.dir / "handout.html"

    def _lock(self):
        return file_lock(self.dir / ".handout.lock")

    def load(self) -> Dict[str, Dict[str, str]]:
        if not self.csv_path.exists():
            return {}
        with self.csv_path.open(newline="") as fh:
            return {row["username"]: row for row in csv.DictReader(fh)}

    def save(self, rows: Dict[str, Dict[str, str]]) -> None:
        if not rows:
            for path in (self.csv_path, self.html_path):
                if path.exists():
                    path.unlink()
            return
        ordered = sorted(rows.values(), key=lambda r: r["instance"])
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in ordered:
            writer.writerow({k: row.get(k, "") for k in FIELDS})
        _write_private(self.csv_path, buf.getvalue())
        _write_private(self.html_path, self.render(ordered))

    def upsert(self, row: Dict[str, str]) -> None:
        with self._lock():
            rows = self.load()
            rows[row["username"]] = row
            self.save(rows)

    def update(self, name: str, fields: Dict[str, str]) -> bool:
        """Change some fields of one card. False if it has no card."""
        with self._lock():
            rows = self.load()
            if name not in rows:
                return False
            rows[name].update(fields)
            self.save(rows)
            return True

    def remove(self, name: str) -> bool:
        if not self.csv_path.exists():
            return False
        with self._lock():
            rows = self.load()
            if rows.pop(name, None) is None:
                return False
            self.save(rows)
            return True

    @staticmethod
    def _personas(r: Dict[str, str]) -> str:
        """The card's persona bypass codes (plan 4.3), or nothing."""
        entries = decode_bypass(r.get("bypass"))
        if not entries:
            return ""
        e = html.escape
        rows = "".join(f'<tr><th>{"Room victim" if role == "victim" else "Trusted"}</th>'
                       f'<td><code>{e(user)}</code></td><td>{" ".join(f"<code>{e(c)}</code>" for c in codes)}</td></tr>'
                       for role, user, codes in entries)
        until = parse_time(r.get("bypass_valid_until") or "")
        uses = r.get("bypass_reuse") or ""
        terms = " ".join(filter(None, [f"is good for {e(uses)} sign-ins" if uses else "",
                                       f"until {e(minute(until))}" if until else ""]))
        return f"""<p class="label">Personas: your team's bypass codes</p>
<table class="personas"><tbody>{rows}</tbody></table>
<p class="fine">To sign in as one of them, choose <b>Sign in with Duo</b> with its username; in Duo, choose
<b>Other options</b>, then <b>Bypass Code</b>, and enter its code. Each code {terms or "works a few times"}.
Only your team has these codes: keep it that way.</p>
"""

    def render(self, rows: Sequence[Dict[str, str]]) -> str:
        e = html.escape
        cards = []
        for r in rows:
            link = r.get("cii_url") or self.cii_url     # kept per card: expire re-renders without workshop.yaml
            cii = (f'<a href="{e(link)}">{e(link)}</a>' if link
                   else "the Identity Intelligence link your facilitator gives you")
            codes = "".join(f"<li><code>{e(c)}</code></li>" for c in r["passcodes"].split())
            cards.append(f"""<section class="card">
<header><span class="eyebrow">PseudoCo Assistant &middot; Lab 5 &middot; {e(self.workshop)}</span>
<h2>Instance {e(r['instance'])}</h2></header>
<dl>
<dt>Your instance</dt><dd><a href="{e(r['url'])}">{e(r['url'])}</a></dd>
<dt>Access key</dt><dd><code>{e(r['access_key'])}</code></dd>
<dt>Duo username</dt><dd><code>{e(r['username'])}</code></dd>
<dt>Email</dt><dd><code>{e(r['email'])}</code></dd>
<dt>Temporary password</dt><dd class="blank">your facilitator writes it here</dd>
</dl>
<ol class="steps">
<li>Open your instance, enter the access key, and pick your industry on the first visit.</li>
<li>Choose <b>Sign in with Duo</b>: your Duo username, then the next unused passcode below.</li>
<li>Identity Intelligence (read-only): open {cii}, sign in with your email, the temporary
password and the next passcode, then set a password of your own.</li>
</ol>
<p class="label">Passcodes: use each one once, in order</p>
<ol class="codes">{codes}</ol>
{self._personas(r)}<p class="fine">This account is disabled on {e(r['disable_on'])} and deleted on {e(r['delete_on'])}.
Other participants with read-only access to Identity Intelligence can see this account's sign-ins,
including the IP address you sign in from.</p>
</section>""")
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab 5 handout: {e(self.workshop)}</title>
<style>
:root{{--bg:#ffffff;--fg:#1c1e21;--muted:#5c6370;--border:#c9ced4;--code:#f2f4f6}}
@media (prefers-color-scheme: dark){{:root{{--bg:#14171a;--fg:#e6e8ea;--muted:#9aa3ad;--border:#3a4148;--code:#1f252b}}}}
*{{box-sizing:border-box}}
body{{margin:0;padding:1.5rem 1rem 3rem;background:var(--bg);color:var(--fg);
 font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
main{{max-width:44rem;margin:0 auto;display:grid;gap:1.25rem}}
.note{{color:var(--muted);font-size:.85rem}}
.card{{border:1px dashed var(--border);border-radius:10px;padding:1rem 1.25rem;break-inside:avoid;page-break-inside:avoid}}
.eyebrow{{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}}
h2{{margin:.2rem 0 .6rem;font-size:1.3rem}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:.25rem .9rem;margin:0 0 .6rem}}
dt{{color:var(--muted)}} dd{{margin:0;overflow-wrap:anywhere}}
.blank{{border-bottom:1px solid var(--border);color:var(--muted);font-size:.8rem;min-height:1.6rem}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);padding:.05em .35em;border-radius:4px}}
.steps{{margin:.4rem 0;padding-left:1.3rem}}
.label{{margin:.6rem 0 .2rem;font-weight:600}}
.codes{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.3rem 1rem;margin:0;padding-left:1.6rem;font-size:1.05rem}}
.fine{{color:var(--muted);font-size:.78rem;margin:.6rem 0 0}}
.personas{{border-collapse:collapse;margin:0;font-size:1rem}}
.personas th{{text-align:left;font-weight:500;color:var(--muted);padding:.15rem 1rem .15rem 0;white-space:nowrap}}
.personas td{{padding:.15rem 1rem .15rem 0;overflow-wrap:anywhere}}
@media (max-width:480px){{.codes{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
@media print{{body{{padding:0}} .note{{display:none}} .card{{margin-bottom:1rem}}}}
</style></head>
<body><main>
<p class="note">Lab 5 handout for workshop {e(self.workshop)}: {len(rows)} card(s). It holds sign-in secrets:
print it, cut the cards apart, and delete this file after the workshop.</p>
{chr(10).join(cards)}
</main></body></html>
"""


# =========================================================================== env
@dataclass
class Env:
    admin: AdminAPI
    line: Callable[[str], None]
    root: Path                        # ~/.pseudoco-lab5
    workshop: str
    email_domain: str
    personas: Set[str]
    persona_group: str
    cii_url: str = ""
    secret_encoding: str = "hex"
    now: Callable[[], float] = None   # type: ignore[assignment]
    groups: Dict[str, str] = field(default_factory=dict)   # name -> group_id
    cast: Optional[Cast] = None       # the persona cast, with roles (lab5_bypass)

    @property
    def ws_dir(self) -> Path:
        return self.root / "workshops" / self.workshop

    def record_path(self, nn: str) -> Path:
        return self.ws_dir / "participants" / f"{nn}.json"

    def handout(self) -> Handout:
        return Handout(self.ws_dir, self.workshop, self.cii_url)


def preflight(env: Env, create_missing: bool) -> None:
    """The groups `up` needs. CII Read-Only is created by Identity
    Intelligence itself; the per-workshop group is created when missing."""
    cii = env.admin.group_by_name(CII_READ_ONLY)
    if not cii:
        raise Lab5Error(f"Duo has no '{CII_READ_ONLY}' group: Identity Intelligence creates it when it is "
                        "provisioned (plan 2); participant accounts need it for Duo SSO into CII")
    env.groups[CII_READ_ONLY] = str(cii["group_id"])
    wanted = group_name(env.workshop)
    group = env.admin.group_by_name(wanted)
    if group:
        env.groups[wanted] = str(group["group_id"])
    elif create_missing:
        group = env.admin.create_group(wanted, f"{MARKER}s of workshop {env.workshop}, created by lab5-setup")
        env.groups[wanted] = str(group["group_id"])
        env.line(f"  CHANGED  group        created Duo group {wanted}")


def plan_rows(env: Env, numbers: Iterable[str]) -> List[Row]:
    """`check`: what `up` would do for each participant account. Read-only."""
    rows: List[Row] = []
    for nn in numbers:
        name = username(env.workshop, nn)
        user = env.admin.user_by_name(name)
        if not user:
            rows.append(("PLAN", name, f"create in {CII_READ_ONLY} + {group_name(env.workshop)}, attach a HOTP "
                                       f"token, put {PASSCODES} passcodes on the handout"))
            continue
        markers, why = ownership(user, env.personas, env.persona_group, require_group=False)
        if not markers or markers["workshop"] != env.workshop:
            rows.append(("FAIL", name, f"exists but lab5-setup did not create it for this workshop ({why or 'another workshop'}); "
                                       "use another workshop name"))
        else:
            rows.append(("OK", name, f"exists ({user.get('status')}); up keeps it"))
    return rows


def _save_record(env: Env, nn: str, **fields: Any) -> Dict[str, Any]:
    path = env.record_path(nn)
    rec = read_json(path)
    rec.update(fields)
    private_dir(path.parent)
    write_json_private(path, rec)
    return rec


def ensure(env: Env, nn: str, url: str, access_key: str, reissue: bool = False) -> Tuple[Row, Optional[str]]:
    """Create (or finish, or keep) this instance's participant account.
    Returns the report row and, while it has no password, its Admin Panel link."""
    now = env.now()
    name = username(env.workshop, nn)
    admin, handout = env.admin, env.handout()
    user = admin.user_by_name(name)
    if user:
        markers, why = ownership(user, env.personas, env.persona_group, require_group=False)
        if not markers or markers["workshop"] != env.workshop:
            return ("FAIL", name, f"an account with this name exists that lab5-setup did not create for "
                                  f"this workshop ({why or 'another workshop'}); left alone"), None
        if user.get("status") == "disabled":
            return ("FAIL", name, "exists and is disabled (expire runs at day 7); use a new workshop name"), None
        created = False
    else:
        stamp = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds")
        user = admin.create_user(name, f"{name}@{env.email_domain}", f"Lab 5 participant {nn} ({env.workshop})",
                                 notes_for(env.workshop, nn, stamp))
        created = True
        _save_record(env, nn, username=name, user_id=user.get("user_id"), email=f"{name}@{env.email_domain}",
                     created_at=stamp, workshop=env.workshop, instance=nn)
    user_id = str(user.get("user_id"))
    have = set(group_names(user))
    for group in (CII_READ_ONLY, group_name(env.workshop)):
        if group not in have:
            admin.add_user_group(user_id, env.groups[group])

    start = created_at(user) or now
    rows = handout.load()
    card = rows.get(name)
    mine = [t for t in admin.user_tokens(user_id) if t.get("serial") == name]
    if mine and card and not reissue:
        fresh = {"url": url, "access_key": access_key, "cii_url": env.cii_url}
        refreshed = any(card.get(k, "") != v for k, v in fresh.items())
        if refreshed:
            handout.update(name, fresh)
        row: Row = ("OK", name, "kept; its handout card keeps its passcodes"
                    + ("; its URL, access key or CII link refreshed" if refreshed else ""))
    elif mine and not reissue:
        return ("WARN", name, "has its token but no handout card (its passcodes were issued in an earlier run): "
                              "re-run up with --reissue-passcodes to replace its token"), (
            None if user.get("has_password") else _link(env, user))
    else:
        stale = list(mine)
        orphan = admin.token_by_serial(name)
        if orphan and all(t.get("token_id") != orphan.get("token_id") for t in stale):
            if assigned_elsewhere(orphan, user_id):
                return ("FAIL", name, f"a HOTP token with serial {name} belongs to another user; left alone"), None
            stale.append(orphan)          # created by a run that failed before attaching it
        for token in stale:
            admin.delete_token(str(token["token_id"]))
        secret = new_hotp_secret()
        token = admin.create_hotp_token(name, encode_secret(secret, env.secret_encoding), 0)
        try:
            admin.attach_token(user_id, str(token["token_id"]))
        except Lab5Error:
            try:
                admin.delete_token(str(token["token_id"]))
            except Lab5Error:
                pass
            raise
        codes = " ".join(hotp(secret, i) for i in range(PASSCODES))
        del secret
        # A reissued card keeps its persona bypass codes: they are the room
        # personas', not this token's, and `lab5-setup handouts` replaces them.
        kept = {k: card[k] for k in BYPASS_FIELDS if card and card.get(k)}
        handout.upsert(dict(kept, **{
            "instance": nn, "url": url, "access_key": access_key, "username": name,
            "email": f"{name}@{env.email_domain}", "passcodes": codes, "issued_at": utc_now(),
            "disable_on": day(start + DISABLE_DAYS * DAY), "delete_on": day(start + DELETE_DAYS * DAY),
            "cii_url": env.cii_url}))
        _save_record(env, nn, token_id=token.get("token_id"), token_serial=name, issued_at=utc_now())
        what = "created" if created else ("passcodes reissued" if (reissue or card) else "finished")
        row = ("CHANGED", name, f"{what}: {CII_READ_ONLY} + {group_name(env.workshop)}, HOTP token attached, "
                                f"{PASSCODES} passcodes on the handout")
    return row, (None if user.get("has_password") else _link(env, user))


def _link(env: Env, user: Dict[str, Any]) -> str:
    return admin_panel_url(env.admin.host, str(user.get("user_id") or ""))


def status_rows(env: Env, numbers: Iterable[str]) -> List[Row]:
    """`status`: each participant's state and age."""
    now = env.now()
    rows: List[Row] = []
    for nn in numbers:
        name = username(env.workshop, nn)
        user = env.admin.user_by_name(name)
        if not user:
            rows.append(("FAIL", name, "missing: up creates it"))
            continue
        markers, why = ownership(user, env.personas, env.persona_group)
        if not markers or markers["workshop"] != env.workshop:
            rows.append(("FAIL", name, f"not a lab5-setup participant account of this workshop ({why})"))
            continue
        start = created_at(user) or now
        when = (f"age {age_text(now - start)}; disabled {day(start + DISABLE_DAYS * DAY)}, deleted "
                f"{day(start + DELETE_DAYS * DAY)}{persona_group_note(markers)}")
        status = str(user.get("status") or "?")
        tokens = [t for t in (user.get("tokens") or []) if t.get("serial") == name]
        token = "token attached" if tokens else "NO token"
        if status == "disabled":
            rows.append(("OK", name, f"disabled (expired); {when}"))
        elif status == "locked out":
            rows.append(("FAIL", name, f"locked out: unlock it in the Admin Panel ({_link(env, user)}), and turn on "
                                       f"lockout auto-revert; {when}"))
        elif not tokens:
            rows.append(("FAIL", name, f"{status}, {token}: re-run up with --reissue-passcodes; {when}"))
        elif not user.get("has_password"):
            rows.append(("WARN", name, f"{status}, {token}, no password yet: Create temporary password at "
                                       f"{_link(env, user)}; {when}"))
        else:
            rows.append(("OK", name, f"{status}, {token}, password set; {when}"))
    return rows


# =========================================================================== expire
@dataclass
class Decision:
    user: Dict[str, Any]
    action: str            # disable | delete | none | skip
    detail: str
    workshop: str = ""
    nn: str = ""
    note: str = ""         # persona_group_note(), appended to the report line


def decide(user: Dict[str, Any], personas: Set[str], persona_group: str, now: float) -> Decision:
    markers, why = ownership(user, personas, persona_group)
    if not markers:
        return Decision(user, "skip", f"left alone: {why}")
    action, detail = _schedule(user, now)
    return Decision(user, action, detail, markers["workshop"], markers["nn"], persona_group_note(markers))


def _schedule(user: Dict[str, Any], now: float) -> Tuple[str, str]:
    """What day 7 and day 14 mean for an account lab5-setup created."""
    start = created_at(user)
    if start is None:
        return "skip", "left alone: no creation time"
    age = now - start
    status = str(user.get("status") or "")
    when = f"age {age_text(age)}"
    if status == "pending deletion":
        return "none", f"{when}; already in Duo's Trash"
    if age >= DELETE_DAYS * DAY:
        return "delete", f"{when}, past day {DELETE_DAYS}"
    if age >= DISABLE_DAYS * DAY:
        if status == "disabled":
            return "none", f"{when}; disabled, deleted on {day(start + DELETE_DAYS * DAY)}"
        return "disable", f"{when}, past day {DISABLE_DAYS}"
    return "none", f"{when}; {status}, disabled on {day(start + DISABLE_DAYS * DAY)}"


def expire(admin: AdminAPI, root: Path, personas: Set[str], persona_group: str, now: float,
           line: Callable[[str], None], workshop: str = "", dry_run: bool = False) -> Tuple[Dict[str, int], List[str]]:
    """Disable at day 7, delete at day 14. Returns (counts, failed usernames)."""
    counts = {"disabled": 0, "deleted": 0, "unchanged": 0, "skipped": 0}
    failed: List[str] = []
    candidates = [u for u in admin.users() if str(u.get("username") or "").startswith("l5-")]
    for user in sorted(candidates, key=lambda u: str(u.get("username"))):
        d = decide(user, personas, persona_group, now)
        name = str(user.get("username"))
        if workshop and d.workshop != workshop:
            continue
        if d.action == "skip":
            counts["skipped"] += 1
            line(f"  SKIP     {name:<24} {d.detail}{d.note}")
            continue
        if d.action == "none":
            counts["unchanged"] += 1
            line(f"  OK       {name:<24} {d.detail}{d.note}")
            continue
        if dry_run:
            line(f"  PLAN     {name:<24} {d.detail}: would {d.action} it"
                 + (" and its HOTP token" if d.action == "delete" else "") + d.note)
            continue
        try:
            if d.action == "disable":
                admin.set_status(str(user["user_id"]), "disabled")
                counts["disabled"] += 1
                line(f"  CHANGED  {name:<24} {d.detail}: disabled{d.note}")
                _mark(root, d, disabled_at=utc_now())
            else:
                gone = _delete(admin, user)
                counts["deleted"] += 1
                line(f"  CHANGED  {name:<24} {d.detail}: deleted with {gone} (the Duo seat is free){d.note}")
                _mark(root, d, deleted_at=utc_now())
            Handout(root / "workshops" / d.workshop, d.workshop).remove(name)
        except Lab5Error as exc:
            failed.append(name)
            line(f"  FAIL     {name:<24} {d.detail}: {exc}{d.note}")
    return counts, failed


def _delete(admin: AdminAPI, user: Dict[str, Any]) -> str:
    """Tokens first (only the one the tool created, serial == username), then
    the user: a failure leaves the user in place for tomorrow's run."""
    name, user_id = str(user["username"]), str(user["user_id"])
    tokens = [t for t in admin.user_tokens(user_id) if t.get("serial") == name]
    if not tokens:
        orphan = admin.token_by_serial(name)
        tokens = [orphan] if orphan and not assigned_elsewhere(orphan, user_id) else []
    for token in tokens:
        admin.delete_token(str(token["token_id"]))
    admin.delete_user(user_id)
    return f"{len(tokens)} HOTP token(s)" if tokens else "no HOTP token left"


def _mark(root: Path, d: Decision, **fields: Any) -> None:
    path = root / "workshops" / d.workshop / "participants" / f"{d.nn}.json"
    if path.exists():
        rec = read_json(path)
        rec.update(fields)
        write_json_private(path, rec)
