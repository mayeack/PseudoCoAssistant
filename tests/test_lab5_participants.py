"""lab5-setup participant accounts and `expire` (plan 12.2-12.4), against fakes only.

The Show boxes, Cloudflare and `security` are tests/test_lab5_setup.py's fakes;
Duo is tests/lab5_fakes.FakeDuo. Nothing reaches a real Duo, CII, Cloudflare,
SSH endpoint or Keychain.

What it pins:
  * `up` creates l5-<workshop>-<nn> per box: email on the zone, notes marker,
    CII Read-Only + l5-<workshop>, its own HOTP token; the box allowlists it;
    the handout (0600) has the URL, access key and 10 passcodes that Duo
    accepts; the secret is sent once, to POST /admin/v1/tokens, and kept
    nowhere; no passcode or access key reaches the output or the run log;
  * a re-run keeps the accounts and their cards; --reissue-passcodes replaces
    the token; an account lab5-setup did not create is never touched;
  * `status` shows each account's state and age; `check` changes nothing;
  * `expire` disables at day 7 and deletes user + token at day 14, is
    idempotent, honours --dry-run and the workshop filter, and never touches a
    persona (a cast name or persona notes) or an account missing any of the
    three markers; a participant someone also put in the persona group is
    still a participant, so its seat is still freed;
  * participants can sign in: `up` says the Sign-in app must admit CII
    Read-Only, and no doc or tool limits every lab app to the persona group;
  * persona bypass codes (plan 4.3): `up` puts one small batch per box on its
    card for the room's victim and each trusted persona (reuse_count 5,
    valid_secs from bypass_codes.valid_hours, preserve_existing=true), to the
    cast's personas only, never a participant; Duo accepts them, up to
    reuse_count sign-ins and until valid_secs; they reach no output, log or
    state file; the personas' HOTP tokens stay script-only; a re-run keeps a
    valid batch and reissues one whose count, reuse_count or valid_hours
    changed, `handouts` issues a fresh one; a room persona in bypass status
    or disabled stops every card's batch in check, up and handouts, and
    status shows each persona's Duo status; a locked-out one (temporary,
    plan 4.4) gets no reset advice: the other personas' codes go on and the
    card is partial, not failed, until handouts is retried; a Duo error or a
    handout lock that times out fails only its card, and up still prints its
    RESULT, the handout, the password links and the reminders (exit 1, not
    2), recording a partial batch as incomplete; each batch records the ids
    that Duo lists as new around a create that returned its codes (unknown
    when that is ambiguous), `down` and `handouts --revoke` delete exactly
    those, and `expire` none;
  * a create without a usable answer (a timeout before or after Duo made the
    codes, an answer cut off, a 502/503/504, a malformed 200) is never listed
    again: its persona's ids are unknown for that card, its row says, in one
    wording, when any codes it made expire and that the tool cannot revoke
    them, and `down` and `handouts --revoke` delete none of them (another
    room's codes for the same persona included, and a late commit's), say
    when they expire, and never claim every batch was deleted;
  * a room persona in a Duo group whose status is Bypass or Disabled (read
    with GET /admin/v1/users/{id}/groups, in either case) stops every card's
    batch like one that is not active, and `status` names the group;
  * `handouts --revoke` deletes a card's earlier codes only once its new
    batch is on the card and recorded: a card whose new batch failed keeps
    them, and only the cards that changed are named for printing;
  * a Duo call without a usable answer (IncompleteRead, TLS, timeout,
    unreadable JSON, a 5xx) is a lost DuoError that never repeats the answer
    or says Duo could not be reached, a 4xx refusal is not lost, and `up`,
    `handouts` and `down` still print their RESULT and closing lines;
  * the room's victim, disabled after this workshop gave it codes (the lab's
    containment), is skipped: the trusted personas' codes go on and nothing
    asks for a reset before the debrief; one disabled before its first code
    is refused with the reset;
  * the Sign-in policy allows bypass code + hardware token: `up`, the
    persona tool and the docs say so, and nothing says bypass code only.

Run:  .venv/bin/python tests/test_lab5_participants.py
"""
from __future__ import annotations

import io
import os
import re
import stat
import sys
import tempfile
import math
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "deploy" / "lab5"))
import test_lab5_setup as tls  # noqa: E402  (its fakes: boxes, Cloudflare, security)
import lab5_envfile as envfile  # noqa: E402
import lab5_participants as lp  # noqa: E402
import lab5_setup as ls  # noqa: E402
import lab5_duo as duo  # noqa: E402
import lab5_bypass as lb  # noqa: E402
from lab5_common import Lab5Error  # noqa: E402
from lab5_fakes import API_HOST, KEYCHAIN_SECRETS, PROVISIONER, Clock, DuoFailure, FakeDuo  # noqa: E402

check = tls.check
tls.SECRETS.update(KEYCHAIN_SECRETS)
DAY = 86400.0

YAML = tls.WORKSHOP_YAML.replace("participants:\n  enabled: false\n",
                                 "participants:\n  enabled: true\n  cii_url: https://ii.pseudoco.example/\n")
assert YAML != tls.WORKSHOP_YAML
# The default cast's room personas, as provision_personas.py leaves them in Duo
# (the workshop file names avery.kim as the victim and the default trusted three).
ROOM = (("avery.kim", "victim"), ("jordan.reyes", "victim"), ("marcus.bell", "trusted"),
        ("elena.sousa", "trusted"), ("grace.lin", "trusted"))
CARD_PERSONAS = ["avery.kim", "marcus.bell", "elena.sousa", "grace.lin"]


class Harness:
    def __init__(self, tmp: Path, personas: bool = True) -> None:
        self.tmp = tmp
        self.world = tls.FakeWorld()
        self.clock = Clock(time.time())
        self.duo = FakeDuo(self.clock)
        self.notes: List[Tuple[str, str]] = []
        (tmp / "workshop.yaml").write_text(YAML)
        if personas:
            for name, role in ROOM:
                self.duo.add_persona(name, role)

    @property
    def root(self) -> Path:
        return self.tmp / "state"

    def deps(self, out: io.StringIO) -> ls.Deps:
        d = self.world.deps(self.root, out)
        d.duo_transport = self.duo.transport
        d.now = self.clock
        d.notify = lambda title, msg: self.notes.append((title, msg))
        return d

    def run(self, *argv: str, yaml: bool = True) -> Tuple[int, str]:
        out = io.StringIO()
        self.world.prompts.clear()
        args = [argv[0]] + ([str(self.tmp / "workshop.yaml")] if yaml else []) + list(argv[1:])
        rc = ls.main(args, deps=self.deps(out))
        return rc, out.getvalue()

    def handout(self) -> Dict[str, Dict[str, str]]:
        return lp.Handout(self.root / "workshops" / "acme", "acme").load()


def secrets_sent(h: Harness) -> List[str]:
    vals = [v for k, v in KEYCHAIN_SECRETS.items() if "host" not in k and "url" not in k]
    vals += [t["secret_text"] for t in h.duo.tokens.values()]
    vals += list(tls.ACCESS_KEYS.values())
    for row in h.handout().values():
        vals += row["passcodes"].split()
    vals += h.duo.issued_codes                 # every persona bypass code Duo ever returned
    return vals


def card_codes(row: Dict[str, str]) -> Dict[str, List[str]]:
    """{persona: [codes]} on one handout card."""
    return {user: codes for _, user, codes in lp.decode_bypass(row.get("bypass"))}


def bypass_posts(h: Harness) -> List[Tuple[str, Dict[str, str]]]:
    return [(path, params) for _, method, path, params in h.duo.calls
            if method == "POST" and path.endswith("/bypass_codes")]


def text_of_logs(root: Path) -> str:
    return "\n".join(p.read_text(errors="replace") for p in root.rglob("*.log"))


# =========================================================================== tests
def test_up_creates_participants() -> None:
    print("== up: one participant account per box, allowlisted, on the handout ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        check("up exits 0", rc == 0, out)
        for nn in ("01", "02"):
            name = f"l5-acme-{nn}"
            user = h.duo.by_name(name)
            check(f"[{nn}] Duo user {name} created", user is not None, out)
            if not user:
                continue
            check(f"[{nn}] email on the zone (CII matches by email)", user["email"] == f"{name}@pseudocoassistant.com")
            notes = lp.parse_notes(user["notes"])
            check(f"[{nn}] notes record the workshop, instance and creation time",
                  bool(notes) and notes["workshop"] == "acme" and notes["nn"] == nn and notes["created"], user["notes"])
            groups = {g["name"] for g in user["groups"]}
            check(f"[{nn}] in CII Read-Only and l5-acme only", groups == {"CII Read-Only", "l5-acme"}, str(groups))
            check(f"[{nn}] stays active and MFA-required (never bypass)", user["status"] == "active")
            tokens = [h.duo.tokens[t] for t in user["tokens"]]
            check(f"[{nn}] its own HOTP token attached (serial = username)",
                  len(tokens) == 1 and tokens[0]["serial"] == name and tokens[0]["counter"] == 0)
            env = envfile.decode(h.world.boxes[nn].files["/home/splunk/DemoBot/.env"][0])
            allowed = (envfile.get(envfile.split_lines(env), "IDENTITY_ALLOWED_USERS") or "").split(",")
            check(f"[{nn}] the box allowlists its own participant, not the other box's",
                  name in allowed and f"l5-acme-{'02' if nn == '01' else '01'}" not in allowed, str(allowed))
        rows = h.handout()
        check("handout has one card per box", sorted(rows) == ["l5-acme-01", "l5-acme-02"], str(rows.keys()))
        for name, row in rows.items():
            nn = row["instance"]
            secret = h.duo.token_secret(name)
            codes = row["passcodes"].split()
            check(f"[{nn}] card: URL and the box's access key",
                  row["url"] == f"https://l5-acme-{nn}.pseudocoassistant.com" and row["access_key"] == tls.ACCESS_KEYS[nn])
            check(f"[{nn}] card: 10 passcodes = the token's first 10 HOTP codes",
                  codes == [duo.hotp(secret, i) for i in range(10)], str(codes))
            check(f"[{nn}] card: disable and delete dates at day 7 and 14",
                  row["disable_on"] == lp.day(h.clock() + 7 * DAY) and row["delete_on"] == lp.day(h.clock() + 14 * DAY))
        ws_dir = h.root / "workshops" / "acme"
        for path in (ws_dir / "handout.csv", ws_dir / "handout.html"):
            check(f"{path.name} is 0600", path.exists() and stat.S_IMODE(path.stat().st_mode) == 0o600)
        html_text = (ws_dir / "handout.html").read_text()
        check("handout.html: a card per instance, the CII link, the passcodes and the privacy note",
              html_text.count('class="card"') == 2 and "https://ii.pseudoco.example/" in html_text
              and rows["l5-acme-01"]["passcodes"].split()[0] in html_text and "IP address" in html_text)
        check("handout.html is self-contained (no external assets)",
              "<link" not in html_text and "<script" not in html_text and "src=" not in html_text)
        check("output prints the Admin Panel link per account for its temporary password",
              out.count(f"https://admin-xxxxxxxx.duosecurity.com/users/DU") == 2 and "Create temporary password" in out, out)
        check("up says the Sign-in app's User access must admit CII Read-Only (no tool can check it)",
              "app PseudoCo Lab: Sign-in, whose User access must admit CII Read-Only as well as PseudoCo Workforce"
              in out, out)
        # the passcodes work, and the secret went to Duo exactly once, in a POST body
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        first = rows["l5-acme-01"]["passcodes"].split()[0]
        check("Duo accepts the first passcode on the card",
              auth.auth_passcode("l5-acme-01", first, "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "allow")
        secret_calls = [(m, p) for _, m, p, params in h.duo.calls
                        if any(t["secret_text"] in params.values() for t in h.duo.tokens.values())]
        check("each HOTP secret is sent once, to POST /admin/v1/tokens",
              secret_calls == [("POST", "/admin/v1/tokens")] * 2, str(secret_calls))
        leaked = [s for s in secrets_sent(h) if s in out or s in text_of_logs(h.root)]
        check("no key, HOTP secret, passcode or access key in the output or run logs", not leaked, str(leaked))
        state_json = "\n".join(p.read_text() for p in h.root.rglob("*.json"))
        leaked = [s for s in secrets_sent(h) if s in state_json]
        check("no secret in the state JSON (only the handout carries sign-in details)", not leaked, str(leaked))
        argv = " ".join(" ".join(a) for a in h.world.security.calls)
        check("Keychain read by item name only", all(v not in argv for v in KEYCHAIN_SECRETS.values()
                                                       if "host" not in v), argv)

        # ---------------------------------------------------------- re-run
        before = (len(h.duo.users), len(h.duo.tokens), dict(rows))
        rc, out2 = h.run("up")
        check("second up exits 0", rc == 0, out2)
        check("second up: no new account or token", (len(h.duo.users), len(h.duo.tokens)) == before[:2])
        check("second up: the cards keep their passcodes", h.handout() == before[2])
        check("second up says the accounts are kept", out2.count("kept; its handout card keeps its passcodes") == 2, out2)

        # ---------------------------------------------------------- reissue
        old = h.handout()["l5-acme-02"]["passcodes"].split()
        rc, out3 = h.run("up", "--only", "2", "--reissue-passcodes")
        new = h.handout()["l5-acme-02"]["passcodes"].split()
        check("--reissue-passcodes: new passcodes for that box only",
              rc == 0 and new != old and h.handout()["l5-acme-01"] == before[2]["l5-acme-01"], out3)
        check("--reissue-passcodes: one token per account still",
              sorted(t["serial"] for t in h.duo.tokens.values() if t["serial"].startswith("l5-"))
              == ["l5-acme-01", "l5-acme-02"])
        check("--reissue-passcodes keeps the card's persona bypass codes (they are the personas', not the token's)",
              lp.decode_bypass(h.handout()["l5-acme-02"].get("bypass"))
              == lp.decode_bypass(before[2]["l5-acme-02"].get("bypass")) != [])
        check("--reissue-passcodes: an old passcode no longer works",
              auth.auth_passcode("l5-acme-02", old[1], "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "deny")

        # ---------------------------------------------------------- status
        h.duo.by_name("l5-acme-01")["has_password"] = True
        rc, out4 = h.run("status")
        check("status: a participant with a password is OK, with its age and dates",
              "l5-acme-01" in out4 and "password set; age 0.0 d" in out4, out4)
        check("status: one without a password shows the Admin Panel link",
              "no password yet: Create temporary password at https://admin-xxxxxxxx" in out4, out4)
        h.duo.by_name("l5-acme-02")["status"] = "locked out"
        rc, out5 = h.run("status")
        check("status: a locked-out participant fails the run", rc == 1 and "locked out: unlock it" in out5, out5)
        h.duo.by_name("l5-acme-02")["status"] = "active"
        workforce = h.duo.add_group("PseudoCo Workforce", "the persona cast")
        h.duo.by_name("l5-acme-01")["groups"].append(dict(workforce))
        rc, out6 = h.run("status")
        check("status: a participant someone also put in PseudoCo Workforce is still this workshop's participant, "
              "and its row says it is in that group",
              "password set; age 0.0 d" in out6 and "also in PseudoCo Workforce" in out6
              and "not a lab5-setup participant" not in out6, out6)


def tls_vpn() -> Tuple[str, str, str]:
    from lab5_fakes import VPN
    return VPN["ikey"], VPN["skey"], API_HOST


def test_check_and_refusals() -> None:
    print("== check is read-only; refusals ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("check")
        check("check exits 0 and plans both accounts", rc == 0 and out.count("PLAN     l5-acme-0") == 2, out)
        check("check changes nothing in Duo", not h.duo.mutations(), str(h.duo.mutations()))
        check("check writes no handout", not (h.root / "workshops" / "acme" / "handout.csv").exists())
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.groups.clear()
        rc, out = h.run("up")
        check("no CII Read-Only group: up exits 2 before touching a box",
              rc == 2 and "CII Read-Only" in out and all(not b.mutations for b in h.world.boxes.values()), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        squatter = h.duo.add_user("l5-acme-01", notes="made by hand", email="someone@example.net")
        rc, out = h.run("up")
        check("an l5- account lab5-setup did not create: that participant fails, the run exits 1",
              rc == 1 and "lab5-setup did not create" in out, out)
        check("... and the account is untouched",
              h.duo.users[squatter["user_id"]]["notes"] == "made by hand" and not squatter["groups"]
              and not squatter["tokens"])
        check("... while the other box's participant is created", h.duo.by_name("l5-acme-02") is not None)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        other = h.duo.add_user("someone.else")
        tok = h.duo._admin("POST", "/admin/v1/tokens", {"type": "h6", "serial": "l5-acme-01", "secret": "11" * 20,
                                                         "counter": "0"})
        other["tokens"].append(tok["token_id"])
        rc, out = h.run("up", "--only", "1")
        check("a token with the participant's serial held by another user: never deleted, that account fails",
              rc == 1 and tok["token_id"] in h.duo.tokens and "belongs to another user" in out, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.fail[("POST", "/admin/v1/users/")] = DuoFailure(500, 50000, "Internal error")
        rc, out = h.run("up", "--only", "1")
        check("a Duo error on one account fails the run (exit 1) and names it", rc == 1 and "l5-acme-01" in out
              and "FAIL" in out, out)
        del h.duo.fail[("POST", "/admin/v1/users/")]
        rc, out = h.run("up", "--only", "1")
        user = h.duo.by_name("l5-acme-01")
        check("the re-run finishes the half-made account (groups, token, card)",
              rc == 0 and user and {g["name"] for g in user["groups"]} == {"CII Read-Only", "l5-acme"}
              and len(user["tokens"]) == 1 and "l5-acme-01" in h.handout(), out)


def _seed_expire(h: Harness) -> Dict[str, str]:
    """Accounts expire must act on, and every kind it must leave alone."""
    now = h.clock()
    ids = {}
    mk = lambda name, ws, nn, days, groups, notes=None: h.duo.add_user(  # noqa: E731
        name, notes=notes if notes is not None else lp.notes_for(ws, nn, "2026-01-01T00:00:00+00:00"),
        groups=groups, created=now - days * DAY)
    ids["young"] = mk("l5-acme-01", "acme", "01", 3, ("CII Read-Only", "l5-acme"))["user_id"]
    ids["day8"] = mk("l5-acme-02", "acme", "02", 8, ("CII Read-Only", "l5-acme"))["user_id"]
    ids["day15"] = mk("l5-acme-03", "acme", "03", 15, ("CII Read-Only", "l5-acme"))["user_id"]
    ids["other_ws"] = mk("l5-globex-01", "globex", "01", 9, ("CII Read-Only", "l5-globex"))["user_id"]
    # a participant someone also added to the persona group (say, to get it past a Sign-in app
    # limited to that group): still a participant, so expire still frees its seat
    ids["persona_grp"] = mk("l5-acme-08", "acme", "08", 30, ("CII Read-Only", "l5-acme", "PseudoCo Workforce"))["user_id"]
    # left alone, whatever their age
    ids["no_marker"] = mk("l5-acme-04", "acme", "04", 30, ("CII Read-Only", "l5-acme"), notes="hand-made")["user_id"]
    ids["no_group"] = mk("l5-acme-05", "acme", "05", 30, ("CII Read-Only",))["user_id"]
    ids["wrong_nn"] = mk("l5-acme-06", "acme", "07", 30, ("CII Read-Only", "l5-acme"))["user_id"]
    ids["persona_notes"] = mk("l5-acme-09", "acme", "09", 30, ("CII Read-Only", "l5-acme", "PseudoCo Workforce"),
                              notes="lab5 persona (scripts/identity/provision_personas.py); role=victim")["user_id"]
    persona = h.duo.by_name("avery.kim") or h.duo.add_persona("avery.kim", "victim")
    persona["created"] = int(now - 60 * DAY)
    ids["persona"] = persona["user_id"]
    ids["admin"] = h.duo.add_user("myeack", created=now - 90 * DAY)["user_id"]
    for key in ("day15",):
        uid = ids[key]
        name = h.duo.users[uid]["username"]
        tok = h.duo._admin("POST", "/admin/v1/tokens", {"type": "h6", "serial": name, "secret": "00" * 20,
                                                         "counter": "0"})
        h.duo.users[uid]["tokens"].append(tok["token_id"])
    return ids


def test_expire() -> None:
    print("== expire: day 7 disables, day 14 deletes, nothing else is touched ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        ids = _seed_expire(h)
        untouched = {k: dict(h.duo.users[ids[k]]) for k in ("no_marker", "no_group", "wrong_nn", "persona_notes",
                                                             "persona", "admin", "young")}
        # l5-acme-05 is half made (the name and notes markers, CII Read-Only, but not l5-acme): every run
        # leaves it alone and reports it as a failure, so the daily job notifies instead of skipping it forever.
        rc, out = h.run("expire", "--dry-run", yaml=False)
        check("--dry-run changes nothing (exit 1: the half-made account needs a hand)",
              rc == 1 and not h.duo.mutations(), out + str(h.duo.mutations()))
        check("--dry-run lists the plan", "would disable" in out and "would delete it and its HOTP token" in out, out)

        h.notes.clear()
        rc, out = h.run("expire", yaml=False)
        check("expire exits 1 for the half-made account alone, and notifies",
              rc == 1 and "1 failed" in out and h.notes and h.notes[-1][0] == "lab5-setup expire", out)
        check("day 8: disabled", h.duo.users[ids["day8"]]["status"] == "disabled", out)
        check("another workshop's day-9 account: disabled too (no workshop file = every workshop)",
              h.duo.users[ids["other_ws"]]["status"] == "disabled")
        check("day 15: user and its HOTP token deleted (the seat is free)",
              ids["day15"] not in h.duo.users and not any(t["serial"] == "l5-acme-03" for t in h.duo.tokens.values()))
        check("day 30 and also in PseudoCo Workforce: still a participant, deleted (the seat is free)",
              ids["persona_grp"] not in h.duo.users, out)
        check("... and its row says it was in the persona group",
              any("l5-acme-08" in l and "deleted" in l and "also in PseudoCo Workforce" in l for l in out.splitlines()),
              out)
        for key, before in untouched.items():
            check(f"left alone: {key}", h.duo.users.get(ids[key]) == before, str(h.duo.users.get(ids[key])))
        check("the persona is never even a candidate", "avery.kim" not in out)
        check("unmarked l5- accounts are reported as left alone, the half-made one as a failure with its fix",
              out.count("SKIP") == 3 and "it is a persona" in out and "another workshop or instance" in out
              and "participant marker" in out
              and any(l.split()[:2] == ["FAIL", "l5-acme-05"] and "half made" in l and "--only 5" in l
                      for l in out.splitlines()), out)
        check("the run log is written", any((h.root / "runs").glob("*-expire.log")))

        rc, out2 = h.run("expire", yaml=False)
        check("a second run the same day changes nothing", rc == 1 and "CHANGED" not in out2, out2)

        h.clock.advance_days(7)
        rc, out3 = h.run("expire", yaml=False)
        check("a week later: the day-8 account (now 15 days) is deleted",
              rc == 1 and ids["day8"] not in h.duo.users, out3)
        check("and the young one (now 10 days) is disabled", h.duo.users[ids["young"]]["status"] == "disabled", out3)
        for key in ("no_marker", "no_group", "wrong_nn", "persona_notes", "persona", "admin"):
            check(f"still left alone: {key}", h.duo.users.get(ids[key]) == untouched[key])
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        ids = _seed_expire(h)
        (Path(tmp) / "workshop.yaml").write_text(YAML.replace("workshop: acme", "workshop: globex"))
        rc, out = h.run("expire")
        check("with a workshop file: only that workshop's accounts",
              rc == 0 and h.duo.users[ids["other_ws"]]["status"] == "disabled"
              and h.duo.users[ids["day8"]]["status"] == "active" and ids["day15"] in h.duo.users, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        ids = _seed_expire(h)
        h.duo.fail[("DELETE", "/admin/v1/tokens/")] = DuoFailure(500, 50000, "Internal error")
        rc, out = h.run("expire", yaml=False)
        check("a token that cannot be deleted keeps its user for tomorrow, exit 1, and a notification",
              rc == 1 and ids["day15"] in h.duo.users and h.notes and "could not be expired" in h.notes[-1][1], out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        for item in ("pseudoco-lab5-duo-provisioner-ikey", "pseudoco-lab5-duo-provisioner-skey"):
            tls.SECRETS.pop(item)
        try:
            rc, out = h.run("expire", yaml=False)
        finally:
            tls.SECRETS.update(KEYCHAIN_SECRETS)
        check("missing Provisioner keys: exit 2, a notification, no Duo call",
              rc == 2 and h.notes and not h.duo.calls and "pseudoco-lab5-duo-provisioner-ikey" in out, out)


def test_expire_after_up_cleans_the_handout() -> None:
    print("== up, then expire at day 7 and 14: cards leave the handout, records follow ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        check("up exits 0", rc == 0, out)
        h.duo.by_name("l5-acme-02")["created"] += 2 * DAY        # made two days later (an `up --only 2`)
        h.clock.advance_days(7.01)
        rc, out = h.run("expire", yaml=False)
        html_path = h.root / "workshops" / "acme" / "handout.html"
        check("day 7 of the first: its card leaves, the other's stays with its CII link (no workshop file needed)",
              rc == 0 and h.duo.by_name("l5-acme-01")["status"] == "disabled" and sorted(h.handout()) == ["l5-acme-02"]
              and "https://ii.pseudoco.example/" in html_path.read_text(), out)
        h.clock.advance_days(2)
        rc, out = h.run("expire", yaml=False)
        check("day 7: both disabled", rc == 0 and all(h.duo.by_name(f"l5-acme-0{i}")["status"] == "disabled"
                                                      for i in (1, 2)), out)
        check("day 7: their cards leave the handout (the files go when empty)",
              not (h.root / "workshops" / "acme" / "handout.csv").exists()
              and not (h.root / "workshops" / "acme" / "handout.html").exists())
        rec = (h.root / "workshops" / "acme" / "participants" / "01.json").read_text()
        check("day 7: the record notes disabled_at", "disabled_at" in rec, rec)
        rc, out = h.run("status")
        check("status after day 7: disabled (expired), not a failure of the account",
              "disabled (expired)" in out, out)
        h.clock.advance_days(7)                                  # 16 and 14 days old
        rc, out = h.run("expire", yaml=False)
        check("day 14: both deleted with their tokens (the personas' tokens stay)",
              rc == 0 and h.duo.by_name("l5-acme-01") is None and h.duo.by_name("l5-acme-02") is None
              and all(t["serial"].startswith("pseudoco-persona-") for t in h.duo.tokens.values())
              and len(h.duo.tokens) == len(ROOM), out)
        rc, out = h.run("down")
        check("down says participant accounts are expire's job", "expire" in out, out)


def test_units() -> None:
    print("== naming, notes and decisions ==")
    m = lp.USERNAME_RE.match("l5-acme-1105-01")
    check("workshop names with digits and '-' parse", bool(m) and m.group("workshop") == "acme-1105"
          and m.group("nn") == "01")
    check("personas and admins are not participant names",
          not lp.USERNAME_RE.match("avery.kim") and not lp.USERNAME_RE.match("l5-acme-1"))
    notes = lp.notes_for("acme-1105", "03", "2026-11-05T10:00:00+00:00")
    check("notes round-trip", lp.parse_notes(notes) == {"workshop": "acme-1105", "nn": "03",
                                                        "created": "2026-11-05T10:00:00+00:00"})
    now = time.time()
    base = {"username": "l5-acme-01", "notes": lp.notes_for("acme", "01", "x"), "status": "active",
            "groups": [{"name": "CII Read-Only"}, {"name": "l5-acme"}]}
    for days, action in ((6.99, "none"), (7.0, "disable"), (13.99, "disable"), (14.0, "delete"), (40, "delete")):
        d = lp.decide(dict(base, created=now - days * DAY), set(), "PseudoCo Workforce", now)
        check(f"day {days}: {action}", d.action == action, d.detail)
    d = lp.decide(dict(base, created=now - 8 * DAY, status="disabled"), set(), "PseudoCo Workforce", now)
    check("already disabled at day 8: nothing to do", d.action == "none")
    d = lp.decide(dict(base, created=now - 30 * DAY, username="l5-acme-01"), {"l5-acme-01"}, "PseudoCo Workforce", now)
    check("a name in the persona cast is never acted on", d.action == "skip")
    d = lp.decide(dict(base, created=now - 30 * DAY, notes="lab5 persona (scripts/identity/provision_personas.py); "
                                                          "role=victim"), set(), "PseudoCo Workforce", now)
    check("persona notes are never acted on, whatever the name", d.action == "skip" and "persona" in d.detail, d.detail)
    in_group = dict(base, groups=base["groups"] + [{"name": "PseudoCo Workforce"}])
    d = lp.decide(dict(in_group, created=now - 8 * DAY), set(), "PseudoCo Workforce", now)
    check("a participant also in the persona group is still a participant: disabled at day 8, and noted",
          d.action == "disable" and "also in PseudoCo Workforce" in d.note, d.detail + d.note)
    d = lp.decide(dict(in_group, created=now - 15 * DAY), set(), "PseudoCo Workforce", now)
    check("... and deleted at day 15, which frees its seat", d.action == "delete", d.detail)
    d = lp.decide(dict(base, created=now - 8 * DAY), set(), "PseudoCo Workforce", now)
    check("no note for a participant outside the persona group", d.note == "", d.note)
    no_created = dict(base, notes=lp.notes_for("acme", "01", "2026-01-01T00:00:00+00:00"))
    d = lp.decide(no_created, set(), "PseudoCo Workforce", lp._parse_time("2026-01-09T00:00:00+00:00"))
    check("without Duo's created, the notes' time is used", d.action == "disable", d.detail)
    check("the Admin Panel link is derived from the API host",
          duo.admin_panel_url(API_HOST, "DUABC") == "https://admin-xxxxxxxx.duosecurity.com/users/DUABC")


def test_signin_user_access_docs() -> None:
    print("== the docs and tools say participants get through PseudoCo Lab: Sign-in (CII Read-Only) ==")
    stale = re.compile(r"every lab app is limited|limit every lab app to it|limited to this group")
    paths = ("deploy/lab5/README.md", "deploy/lab5/README.html", "docs/identity-lab-facilitator.md",
             "docs/identity-lab-facilitator.html", "scripts/identity/provision_personas.py",
             "scripts/identity/personas.yaml", "deploy/lab5/lab5_participants.py", "deploy/lab5/lab5_setup.py")
    for path in paths:
        text = (ROOT / path).read_text()
        check(f"{path}: never says every lab app is limited to the persona group", not stale.search(text),
              str(stale.findall(text)))
    for path in ("deploy/lab5/README.md", "docs/identity-lab-facilitator.md"):
        rows = [l for l in (ROOT / path).read_text().splitlines()
                if "PseudoCo Lab: Sign-in" in l and "permitted groups" in l]
        check(f"{path}: Sign-in's User access admits PseudoCo Workforce and CII Read-Only",
              bool(rows) and all("PseudoCo Workforce" in l and "CII Read-Only" in l for l in rows), str(rows))
        rows = [l for l in (ROOT / path).read_text().splitlines() if "PseudoCo VPN" in l and "permitted groups" in l]
        check(f"{path}: VPN's User access admits PseudoCo Workforce only",
              bool(rows) and all("PseudoCo Workforce" in l and "CII Read-Only" not in l for l in rows), str(rows))
    check("the group every participant account joins is the one Sign-in must admit",
          lp.CII_READ_ONLY == "CII Read-Only" and lp.SIGNIN_APP == "PseudoCo Lab: Sign-in")


def test_bypass_codes_on_the_handout() -> None:
    print("== persona bypass codes: one batch per box on its card; Duo takes them; nothing deletes them ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("check")
        check("check plans a batch per instance and changes nothing in Duo",
              rc == 0 and out.count("PLAN     instance 0") == 2 and not h.duo.mutations()
              and "1 code each for avery.kim (victim), marcus.bell, elena.sousa, grace.lin; 5 sign-ins per code" in out,
              out)
        token_counters = {t["serial"]: t["counter"] for t in h.duo.tokens.values()}

        rc, out = h.run("up")
        check("up exits 0", rc == 0, out)
        rows = h.handout()
        persona_ids = {h.duo.by_name(n)["user_id"]: n for n, _ in ROOM}
        posts = bypass_posts(h)
        check("one POST per persona per box: the victim and each trusted persona, nobody else",
              sorted(persona_ids[path.split("/")[4]] for path, _ in posts) == sorted(CARD_PERSONAS * 2),
              str(posts))
        check("every batch: count 1, reuse_count 5, valid_secs 12 h, preserve_existing true, Duo picks the codes",
              all(params == {"count": "1", "reuse_count": "5", "valid_secs": "43200", "preserve_existing": "true"}
                  for _, params in posts), str(posts))
        participant_ids = {h.duo.by_name(f"l5-acme-0{i}")["user_id"] for i in (1, 2)}
        check("no participant account gets a bypass code (12.4)",
              not any(path.split("/")[4] in participant_ids for path, _ in posts)
              and not any(h.duo.bypass.get(uid) for uid in participant_ids))
        check("jordan.reyes, the untouched fallback, gets none", not h.duo.live_codes("jordan.reyes"))
        cards = {row["instance"]: card_codes(row) for row in rows.values()}
        check("each card names the victim first, then the trusted personas, one code each",
              all(list(c) == CARD_PERSONAS and all(len(v) == 1 for v in c.values()) for c in cards.values()),
              str(cards))
        everything = [code for c in cards.values() for codes in c.values() for code in codes]
        check("per-team batches: no code is on two cards, and every card code is one Duo issued",
              len(everything) == len(set(everything)) == 8 and sorted(everything) == sorted(h.duo.issued_codes))
        check("trusted personas keep every box's batch (preserve_existing): 2 live codes each",
              all(len(h.duo.live_codes(n)) == 2 for n in CARD_PERSONAS))
        row1 = rows["l5-acme-01"]
        until1 = lp.parse_time(row1["bypass_valid_until"])
        check("the card says when they expire (12 h after its last create, rounded up to the minute: never earlier "
              "than a code's own expiry) and how many sign-ins each allows",
              row1["bypass_reuse"] == "5" and until1 % 60 == 0 and 0 <= until1 - (h.clock() + 43200) < 60
              and all(until1 >= c["expiration"] for cs in h.duo.bypass.values() for c in cs if c["expiration"]),
              str(row1))
        html_text = (h.root / "workshops" / "acme" / "handout.html").read_text()
        check("handout.html: the persona table, the codes, how to use them and until when",
              "Room victim" in html_text and "Trusted" in html_text and cards["01"]["marcus.bell"][0] in html_text
              and "Bypass Code" in html_text and "5 sign-ins" in html_text and " UTC" in html_text, html_text[-3000:])
        rec = lp.read_json(h.root / "workshops" / "acme" / "participants" / "01.json")
        check("the participant record keeps the batch's times and personas, never a code",
              rec.get("bypass_batches") and rec["bypass_batches"][0]["personas"] == CARD_PERSONAS
              and not any(code in json_dump(rec) for code in everything), str(rec))

        # ---------------------------------------------------------- the personas' HOTP tokens stay script-only
        argv = " ".join(" ".join(a) for a in h.world.security.calls)
        check("no persona HOTP secret is read from the Keychain", "pseudoco-lab5-hotp-" not in argv, argv)
        check("no persona token is read, resynced or changed",
              not any("resync" in path or "pseudoco-persona-" in str(params) for _, _, path, params in h.duo.calls)
              and {t["serial"]: t["counter"] for t in h.duo.tokens.values() if t["serial"].startswith("pseudoco-persona-")}
              == {k: v for k, v in token_counters.items() if k.startswith("pseudoco-persona-")})
        on_card = {nn: set(r["passcodes"].split()) | {c for codes in card_codes(r).values() for c in codes}
                   for nn, r in ((r["instance"], r) for r in rows.values())}
        expected = {r["instance"]: {duo.hotp(h.duo.token_secret(name), i) for i in range(10)}
                    | {c for codes in card_codes(r).values() for c in codes} for name, r in rows.items()}
        check("a card carries its participant's passcodes and its bypass codes, and no other code",
              on_card == expected and all(len(v) == 14 for v in on_card.values()), str(on_card))
        leaked = [s for s in secrets_sent(h) if s in out or s in text_of_logs(h.root)]
        check("no bypass code (or other secret) in the output or run logs", not leaked, str(leaked))
        state_json = "\n".join(p.read_text() for p in h.root.rglob("*.json"))
        check("no bypass code in the state JSON", not any(c in state_json for c in h.duo.issued_codes))

        # ---------------------------------------------------------- Duo takes them: reuse_count, per team
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        code1 = cards["01"]["marcus.bell"][0]
        results = [auth.auth_passcode("marcus.bell", code1, "198.51.100.200", "ATTENDEE-LAPTOP")["result"]
                   for _ in range(6)]
        check("Duo accepts a card's code 5 times (reuse_count), then refuses it",
              results == ["allow"] * 5 + ["deny"], str(results))
        check("... while team 02's code for the same persona still works (per-team batches)",
              auth.auth_passcode("marcus.bell", cards["02"]["marcus.bell"][0], "198.51.100.201",
                                 "ATTENDEE-LAPTOP2")["result"] == "allow")
        check("a code only signs in its own persona",
              auth.auth_passcode("elena.sousa", cards["02"]["avery.kim"][0], "198.51.100.201",
                                 "ATTENDEE-LAPTOP2")["result"] == "deny")

        # ---------------------------------------------------------- a re-run keeps a valid batch
        before = len(bypass_posts(h))
        rc, out2 = h.run("up")
        check("second up keeps both batches: no new code, the cards unchanged",
              rc == 0 and len(bypass_posts(h)) == before and h.handout() == rows
              and out2.count("kept: valid until") == 2, out2)
        rc, out3 = h.run("status")
        check("status: each batch OK with its time left",
              out3.count("OK       instance 0") == 2 and "h left) for avery.kim (victim), marcus.bell" in out3, out3)

        # ---------------------------------------------------------- valid_secs is the cutoff
        h.clock.t += 12 * 3600 + 1
        check("12 h later Duo refuses the codes: valid_secs is their cutoff",
              auth.auth_passcode("avery.kim", cards["02"]["avery.kim"][0], "198.51.100.201",
                                 "ATTENDEE-LAPTOP2")["result"] == "deny")
        h.clock.t += 60          # the cards' time is rounded up to the minute
        rc, out4 = h.run("status")
        check("status: expired batches fail the run and say how to issue new ones",
              rc == 1 and out4.count("expired at") == 2 and "lab5-setup handouts <workshop.yaml> --only 1" in out4, out4)
        rc, out5 = h.run("up")
        new_rows = h.handout()
        check("up after they expired issues a new batch for each card",
              rc == 0 and out5.count("its codes have expired: 1 code each") == 2
              and all(card_codes(new_rows[n]) != card_codes(rows[n]) for n in rows), out5)
        check("... and the new codes work",
              auth.auth_passcode("grace.lin", card_codes(new_rows["l5-acme-01"])["grace.lin"][0], "198.51.100.200",
                                 "ATTENDEE-LAPTOP")["result"] == "allow")

        # ---------------------------------------------------------- handouts: a fresh batch, nothing else
        snapshot = {"users": {u["username"]: (u["status"], len(u["tokens"])) for u in h.duo.users.values()},
                    "boxes": {nn: tls._snapshot(b) for nn, b in h.world.boxes.items()},
                    "connects": len(h.world.connects)}
        old1 = card_codes(new_rows["l5-acme-01"])
        calls = len(h.duo.calls)
        h.world.prompts.clear()
        rc, out6 = h.run("handouts", "--only", "1")
        after = h.handout()
        check("handouts --only 1: a fresh batch on card 01 only, exit 0",
              rc == 0 and card_codes(after["l5-acme-01"]) != old1
              and after["l5-acme-02"] == new_rows["l5-acme-02"] and "CHANGED  instance 01" in out6, out6)
        check("handouts asks for no SSH password and touches no box or participant account",
              not h.world.prompts and len(h.world.connects) == snapshot["connects"]
              and {nn: tls._snapshot(b) for nn, b in h.world.boxes.items()} == snapshot["boxes"]
              and {u["username"]: (u["status"], len(u["tokens"])) for u in h.duo.users.values()} == snapshot["users"])
        new_calls = h.duo.calls[calls:]
        check("handouts only looks the personas up and creates codes (no DELETE of anything)",
              all(m == "GET" or (m == "POST" and p.endswith("/bypass_codes")) for _, m, p, _ in new_calls)
              and not any(m == "DELETE" for _, m, _, _ in h.duo.calls), str(new_calls))
        check("the codes it replaced still work until they expire",
              auth.auth_passcode("elena.sousa", old1["elena.sousa"][0], "198.51.100.200",
                                 "ATTENDEE-LAPTOP")["result"] == "allow")
        leaked = [s for s in secrets_sent(h) if s in out6 or s in text_of_logs(h.root)]
        check("handouts prints and logs no code", not leaked, str(leaked))

        # ---------------------------------------------------------- expire deletes none; down deletes what was recorded
        other_room = h.duo.add_bypass(h.duo.by_name("marcus.bell")["user_id"])     # another room's code, same persona
        live = {n: len(h.duo.live_codes(n)) for n in CARD_PERSONAS}
        calls = len(h.duo.calls)
        rc, out8 = h.run("expire", yaml=False)
        check("expire touches no bypass code (and no persona)",
              rc == 0 and not any("bypass_codes" in p for _, _, p, _ in h.duo.calls[calls:])
              and {n: len(h.duo.live_codes(n)) for n in CARD_PERSONAS} == live
              and "nor is a bypass code" in out8, out8)
        recorded = {i for nn in ("01", "02") for b in lp.read_json(h.root / "workshops" / "acme" / "participants"
                                                                   / f"{nn}.json")["bypass_batches"]
                    for e in b["codes"] for i in e["ids"]}
        calls = len(h.duo.calls)
        rc, out7 = h.run("down")
        deletes = [p for _, m, p, _ in h.duo.calls[calls:] if m == "DELETE"]
        check("down deletes the codes it recorded, with DELETE /admin/v1/bypass_codes/{id}, and nothing else",
              rc == 0 and all(p.startswith("/admin/v1/bypass_codes/") for p in deletes)
              and {p.rsplit("/", 1)[1] for p in deletes} <= recorded and len(deletes) == 12, str(deletes) + out7)
        check("... so no card's code works any more",
              all(auth.auth_passcode(n, c, "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "deny"
                  for r in after.values() for n, codes in card_codes(r).items() for c in codes))
        check("... while the other room's code for the same persona is untouched",
              [c["bypass_code_id"] for c in h.duo.live_codes("marcus.bell")] == other_room)
        check("down says every batch is deleted or expired",
              "Persona bypass codes: every batch these cards had is deleted or has expired" in out7, out7)
        calls = len(h.duo.calls)
        rc, out9 = h.run("down")
        check("a second down has nothing recorded left: no Duo call",
              rc == 0 and len(h.duo.calls) == calls and "every batch these cards had is deleted" in out9, out9)


def test_bypass_victim_swap() -> None:
    print("== swapping the room's victim to its fallback: up re-issues the cards' codes ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        old = {n: card_codes(r) for n, r in h.handout().items()}
        (Path(tmp) / "workshop.yaml").write_text(YAML.replace("  victim: avery.kim\n", "  victim: jordan.reyes\n"))
        rc, out = h.run("status")
        check("status before the re-run: the cards' codes are for the old victim",
              rc == 1 and out.count("its codes are for avery.kim, marcus.bell") == 2, out)
        rc, out = h.run("up")
        rows = h.handout()
        check("up re-issues every card for the new victim and the trusted personas",
              rc == 0 and out.count("its codes are for other personas: 1 code each for jordan.reyes (victim)") == 2
              and all(list(card_codes(r)) == ["jordan.reyes", "marcus.bell", "elena.sousa", "grace.lin"]
                      for r in rows.values()), out)
        check("... and the box allowlists follow the victim",
              all("jordan.reyes" in (envfile.get(envfile.split_lines(envfile.decode(
                  b.files["/home/splunk/DemoBot/.env"][0])), "IDENTITY_ALLOWED_USERS") or "").split(",")
                  for b in h.world.boxes.values()))
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        check("the old victim's codes are left to expire (nothing deletes them), though no box allows it now",
              auth.auth_passcode("avery.kim", old["l5-acme-01"]["avery.kim"][0], "198.51.100.200",
                                 "ATTENDEE-LAPTOP")["result"] == "allow"
              and not any(m == "DELETE" for _, m, _, _ in h.duo.calls))


def json_dump(rec: Dict[str, Any]) -> str:
    import json
    return json.dumps(rec)


def test_bypass_refusals() -> None:
    print("== persona bypass codes: only the cast's personas, in range, within Duo's limits ==")
    for extra, why in (("room:\n  victim: grace.lin\n  trusted: [marcus.bell, elena.sousa]\n",
                        "a trusted persona as the victim"),
                       ("room:\n  victim: avery.kim\n  trusted: [marcus.bell, jordan.reyes]\n",
                        "a victim among the trusted"),
                       ("room:\n  victim: myeack\n", "a victim that is not in the cast")):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            text = YAML.replace("room:\n  victim: avery.kim\n  fallback: jordan.reyes\n", extra)
            assert text != YAML
            (Path(tmp) / "workshop.yaml").write_text(text)
            rc, out = h.run("up")
            check(f"up refuses {why} before any box or Duo change (exit 2)",
                  rc == 2 and "persona cast" in out and all(not b.mutations for b in h.world.boxes.values())
                  and not h.duo.mutations(), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        squat = h.duo.by_name("grace.lin")
        squat["notes"] = "someone's own account"
        rc, out = h.run("up")
        check("a Duo user named like a persona but without the persona marker: no code for anyone, exit 1",
              rc == 1 and "grace.lin" in out and "without the persona notes marker" in out and not bypass_posts(h)
              and out.count("no bypass codes issued") == 2, out)
        check("... while the boxes and the participant accounts are still set up",
              h.duo.by_name("l5-acme-01") and h.duo.by_name("l5-acme-02")
              and all(b.files.get(remote_unit()) for b in h.world.boxes.values()))
        squat["notes"] = "lab5 persona (scripts/identity/provision_personas.py); role=trusted"
        rc, out = h.run("up")
        check("once fixed, a re-run issues the codes onto the existing cards",
              rc == 0 and out.count("no persona codes on its card yet: 1 code each") == 2
              and all(card_codes(r) for r in h.handout().values()), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        del h.duo.users[h.duo.by_name("elena.sousa")["user_id"]]
        rc, out = h.run("check")
        check("check: a persona missing in Duo fails the check", rc == 1 and "elena.sousa" in out
              and "missing in Duo" in out, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        admin = duo.AdminAPI(h.duo.transport("admin", PROVISIONER["ikey"], PROVISIONER["skey"], API_HOST), API_HOST)
        marcus = h.duo.by_name("marcus.bell")["user_id"]
        for _ in range(10):
            admin.create_bypass_codes(marcus, 10, 5, 86400)        # 100 codes, kept by preserve_existing
        try:
            admin.create_bypass_codes(marcus, 1, 5, 60)
            refused = False
        except duo.DuoError as exc:
            refused = exc.status == 400
        check("the fake Duo models the 100-codes-per-user limit (a 101st is a 400)",
              refused and len(h.duo.live_codes("marcus.bell")) == 100)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        admin = duo.AdminAPI(h.duo.transport("admin", PROVISIONER["ikey"], PROVISIONER["skey"], API_HOST), API_HOST)
        marcus = h.duo.by_name("marcus.bell")["user_id"]
        for _ in range(9):
            admin.create_bypass_codes(marcus, 10, 5, 86400)        # another room's 90 codes, preserved
        admin.create_bypass_codes(marcus, 9, 5, 86400)
        calls = len(h.duo.calls)
        rc, out = h.run("up")
        check("a shared persona near Duo's 100-code limit: no code issued in that run, a clear reason, exit 1",
              rc == 1 and "holds 99 unexpired bypass code(s) and this run needs 2 more" in out
              and not bypass_posts_since(h, calls), out)
        check("... and the other room's codes are untouched", len(h.duo.live_codes("marcus.bell")) == 99)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        h.duo.fail[("POST", "/admin/v1/users/")] = DuoFailure(400, 40002, "Invalid request parameters")
        h.clock.t += 13 * 3600
        rc, out = h.run("handouts")
        check("a Duo refusal while issuing: that card keeps its earlier codes, the run exits 1 with Duo's limit as a "
              "hint", rc == 1 and "keeps its earlier codes" in out and "at most 100 bypass codes per user" in out
              and all(card_codes(r) for r in h.handout().values()), out)
        del h.duo.fail[("POST", "/admin/v1/users/")]
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        (Path(tmp) / "workshop.yaml").write_text(YAML + "bypass_codes:\n  enabled: false\n")
        rc, out = h.run("up")
        check("bypass_codes.enabled false: no code, no persona section on the cards", rc == 0 and not bypass_posts(h)
              and not any(card_codes(r) for r in h.handout().values())
              and "Room victim" not in (h.root / "workshops" / "acme" / "handout.html").read_text(), out)
        rc, out = h.run("handouts")
        check("... and handouts refuses (exit 2)", rc == 2 and "bypass_codes.enabled is false" in out, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        (Path(tmp) / "workshop.yaml").write_text(
            YAML + "bypass_codes:\n  count: 2\n  reuse_count: 3\n  valid_hours: 30\n")
        rc, out = h.run("handouts")
        check("handouts before up: no card to put codes on, every instance fails (exit 1)",
              rc == 1 and out.count("no handout card for l5-acme-0") == 2 and not bypass_posts(h), out)
        rc, out = h.run("up")
        posts = bypass_posts(h)
        check("bypass_codes settings reach Duo: count 2, reuse_count 3, valid_secs 30 h",
              rc == 0 and posts and all(p == {"count": "2", "reuse_count": "3", "valid_secs": "108000",
                                              "preserve_existing": "true"} for _, p in posts)
              and all(len(v) == 2 for r in h.handout().values() for v in card_codes(r).values()), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        (Path(tmp) / "workshop.yaml").write_text(tls.WORKSHOP_YAML)
        rc, out = h.run("handouts")
        check("participants.enabled false: handouts refuses (no handout exists)", rc == 2 and "no handout" in out, out)

    import yaml
    good = yaml.safe_load(YAML)
    for section, why in (({"valid_hours": 0}, "valid_hours 0 (never expires in Duo)"),
                         ({"valid_hours": 73}, "valid_hours past 72"),
                         ({"valid_hours": "12h"}, "valid_hours '12h'"),
                         ({"reuse_count": 0}, "reuse_count 0 (unlimited in Duo)"),
                         ({"count": 11}, "count 11 (Duo makes at most 10 per call)"),
                         ({"enabled": "yes"}, "enabled 'yes'"),
                         ({"valid_secs": 43200}, "an unknown key")):
        try:
            ls.workshop_from_dict(dict(good, bypass_codes=section))
            ok = False
        except Lab5Error:
            ok = True
        check(f"workshop.yaml bypass_codes refused: {why}", ok)
    ws = ls.workshop_from_dict(dict(good, bypass_codes={"valid_hours": "36", "reuse_count": 5}))
    check("bypass_codes: whole numbers (also as strings) are taken; defaults count 1, reuse 5, 12 h",
          ws.bypass_codes == lb.Settings(True, 1, 5, 36) and ls.workshop_from_dict(good).bypass_codes
          == lb.Settings(True, 1, 5, 12) and lb.Settings().valid_secs == 43200)
    ex = ls.load_workshop(ROOT / "deploy" / "lab5" / "workshop.example.yaml")
    check("workshop.example.yaml sets the documented defaults", ex.bypass_codes == lb.Settings(True, 1, 5, 12))

    admin = duo.AdminAPI(FakeDuo(Clock(time.time())).transport("admin", PROVISIONER["ikey"], PROVISIONER["skey"],
                                                                 API_HOST), API_HOST)
    for args, why in (((0, 5, 3600), "count 0"), ((11, 5, 3600), "count 11"), ((1, 0, 3600), "reuse_count 0"),
                      ((1, 5, 0), "valid_secs 0")):
        try:
            admin.create_bypass_codes("DU0000000001", *args)
            ok = False
        except duo.DuoError:
            ok = True
        check(f"AdminAPI.create_bypass_codes refuses {why} before calling Duo", ok)
    entries = [("victim", "avery.kim", ["123456789"]), ("trusted", "marcus.bell", ["234567890", "345678901"])]
    check("the card's bypass field round-trips", lp.decode_bypass(lp.encode_bypass(entries)) == entries)
    check("a malformed bypass word is ignored, never rendered",
          lp.decode_bypass("victim:avery.kim=12ab trusted:<b>x</b>=123456789 admin:me=123456789") == [])


def bypass_posts_since(h: Harness, start: int) -> List[Tuple[str, str]]:
    return [(m, p) for _, m, p, _ in h.duo.calls[start:] if m == "POST" and p.endswith("/bypass_codes")]


def remote_unit() -> str:
    import lab5_remote as remote
    return remote.UNIT_PATH


def test_old_handout_gets_codes() -> None:
    print("== a handout written before bypass codes existed: up adds them, the passcodes stay ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        (Path(tmp) / "workshop.yaml").write_text(YAML + "bypass_codes:\n  enabled: false\n")
        rc, out = h.run("up")
        csv_path = h.root / "workshops" / "acme" / "handout.csv"
        header, *body = csv_path.read_text().splitlines()
        old = ",".join(header.split(",")[:10])
        csv_path.write_text("\n".join([old] + [",".join(line.split(",")[:10]) for line in body]) + "\n")
        before = {n: r["passcodes"] for n, r in h.handout().items()}
        (Path(tmp) / "workshop.yaml").write_text(YAML)
        rc, out = h.run("up")
        rows = h.handout()
        check("an old ten-column handout loads, keeps its passcodes and gets the persona codes",
              rc == 0 and {n: r["passcodes"] for n, r in rows.items()} == before
              and all(list(card_codes(r)) == CARD_PERSONAS for r in rows.values()), out)


def record(h: Harness, nn: str) -> Dict[str, Any]:
    return lp.read_json(h.root / "workshops" / "acme" / "participants" / f"{nn}.json")


def code_value(h: Harness, code_id: str) -> str:
    return next((c["code"] for cs in h.duo.bypass.values() for c in cs if c["bypass_code_id"] == code_id), "")


def deletes_since(h: Harness, start: int) -> List[str]:
    return [p for _, m, p, _ in h.duo.calls[start:] if m == "DELETE"]


def test_bypass_persona_status() -> None:
    print("== a room persona that is not active in Duo (bypass, disabled): no batch, each card fails ==")
    for status, said in (("bypass", "is in bypass status in Duo"), ("disabled", "is disabled in Duo")):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            h.duo.by_name("marcus.bell")["status"] = status
            rc, out = h.run("check")
            row = [l for l in out.splitlines() if "marcus.bell " in l and l.lstrip().startswith("FAIL")]
            check(f"[{status}] check fails each card, names the persona and its Duo status, changes nothing",
                  rc == 1 and out.count("FAIL     instance 0") == 2 and row and said in row[0]
                  and "provision_personas.py --reset --only marcus.bell" in row[0] and not h.duo.mutations(), out)
            rc, out = h.run("up")
            check(f"[{status}] up issues no code to anyone and fails each card (exit 1, not 2)",
                  rc == 1 and not bypass_posts(h) and out.count("no bypass codes issued") == 2
                  and "RESULT: up: 2 ok, 0 failed; persona bypass codes failed on 2 card(s) (instance 01, 02)" in out,
                  out)
            check(f"[{status}] ... while the boxes, the accounts and the handout are still set up",
                  h.duo.by_name("l5-acme-01") and h.duo.by_name("l5-acme-02") and sorted(h.handout()) ==
                  ["l5-acme-01", "l5-acme-02"] and "Its policy (plan 4.4)" in out, out)
            check(f"[{status}] ... and the persona's status is left as it was (the tools never change a persona)",
                  h.duo.by_name("marcus.bell")["status"] == status)
            rc, out = h.run("status")
            rows = {l.split()[1]: l for l in out.splitlines() if l.split()[1:2] and l.split()[1] in CARD_PERSONAS}
            check(f"[{status}] status shows each room persona's Duo status, and fails on this one",
                  rc == 1 and "active in Duo (the room victim)" in rows.get("avery.kim", "")
                  and all("active in Duo (trusted)" in rows.get(n, "") for n in ("elena.sousa", "grace.lin"))
                  and rows.get("marcus.bell", "").lstrip().startswith("FAIL") and said in rows.get("marcus.bell", ""),
                  out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        posts = len(bypass_posts(h))
        h.duo.by_name("avery.kim")["status"] = "bypass"
        rc, out = h.run("up")
        check("a persona put in bypass status after its cards' batches were issued: up fails each kept card too",
              rc == 1 and out.count("keeps its batch (valid until") == 2 and "avery.kim must be fixed" in out
              and "is in bypass status in Duo" in out and len(bypass_posts(h)) == posts, out)
        rc, out = h.run("check")
        check("... and so does check", rc == 1 and out.count("FAIL     instance 0") == 2, out)
        h.duo.by_name("avery.kim")["status"] = "active"
        rc, out = h.run("up")
        check("once it is active again, up keeps the cards and exits 0",
              rc == 0 and out.count("kept: valid until") == 2, out)


def _up_finished(out: str) -> bool:
    """up's closing lines: the RESULT, the handout path, the password links and both Sign-in reminders."""
    return ("RESULT: up: 2 ok, 0 failed" in out and "handout: " in out and "Create temporary password" in out
            and out.count("https://admin-xxxxxxxx.duosecurity.com/users/DU") == 2
            and "whose User access must admit CII Read-Only" in out and "Its policy (plan 4.4)" in out)


def test_bypass_errors_are_per_card() -> None:
    print("== a Duo error or a handout lock timing out fails that card only; up still finishes (exit 1, not 2) ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        marcus = h.duo.by_name("marcus.bell")["user_id"]
        h.duo.fail[("GET", f"/admin/v1/users/{marcus}/bypass_codes")] = DuoFailure(500, 50000, "Internal error")
        rc, out = h.run("up")
        check("Duo cannot list a persona's codes: each card fails, up finishes and names them (exit 1)",
              rc == 1 and _up_finished(out) and out.count("FAIL     instance 0") == 2 and not bypass_posts(h)
              and "persona bypass codes failed on 2 card(s) (instance 01, 02)" in out, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        marcus, elena = (h.duo.by_name(n)["user_id"] for n in ("marcus.bell", "elena.sousa"))
        seen: List[str] = []

        def second_marcus(uid: str) -> None:      # Duo starts failing elena.sousa halfway through card 02
            seen.append(uid)
            if seen.count(marcus) == 2:
                h.duo.fail[("POST", f"/admin/v1/users/{elena}/bypass_codes")] = DuoFailure(500, 50000, "Internal error")
        h.duo.bypass_hooks.append(second_marcus)
        rc, out = h.run("up")
        cards = {r["instance"]: card_codes(r) for r in h.handout().values()}
        check("a Duo error (a 500) halfway through one card: that card fails, the other gets its batch, up finishes "
              "(exit 1)",
              rc == 1 and _up_finished(out) and list(cards["01"]) == CARD_PERSONAS and cards["02"] == {}
              and "persona bypass codes failed on 1 card(s) (instance 02)" in out
              and lost_row(h, "elena.sousa") in out, out)
        partial = record(h, "02")["bypass_batches"][-1]
        ids = [i for e in partial["codes"] for i in e["ids"]]
        check("... its partial batch is recorded as incomplete, with the ids of the 2 codes Duo did issue, and the "
              "500's persona as unknown (a 5xx may come after Duo acted)",
              partial["complete"] is False and partial["personas"] == ["avery.kim", "marcus.bell"] and len(ids) == 2
              and [u["persona"] for u in partial["unknown"]] == ["elena.sousa"]
              and "recorded as an incomplete batch" in out, str(partial))
        check("... and no code is printed or logged", not any(c in out or c in text_of_logs(h.root)
                                                                for c in h.duo.issued_codes))
        h.duo.fail.clear()
        rc, out = h.run("down", "--only", "2")
        check("down deletes the partial batch's codes, which are on no card",
              rc == 0 and all(code_value(h, i) == "" for i in ids) and "deleted 2 bypass code(s)" in out, out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        real = lp.Handout.update

        def locked(self, name, fields):           # the handout's lock times out for card 02's codes
            if name == "l5-acme-02" and "bypass" in fields:
                raise Lab5Error(f"{self.dir / '.handout.lock'} is locked by another run; try again when it finishes")
            return real(self, name, fields)
        lp.Handout.update = locked
        try:
            rc, out = h.run("up")
        finally:
            lp.Handout.update = real
        cards = {r["instance"]: card_codes(r) for r in h.handout().values()}
        check("the handout lock timing out for one card: that card fails, the other gets its batch, up finishes "
              "(exit 1, not 2)",
              rc == 1 and _up_finished(out) and list(cards["01"]) == CARD_PERSONAS and cards["02"] == {}
              and "is locked by another run" in out and "(instance 02)" in out, out)
        batch = record(h, "02")["bypass_batches"][-1]
        check("... its batch is recorded as incomplete, with all 4 code ids (so down can delete them)",
              batch["complete"] is False and sum(len(e["ids"]) for e in batch["codes"]) == 4, str(batch))
        check("... and its codes are printed and logged nowhere",
              not any(c in out or c in text_of_logs(h.root) for c in h.duo.issued_codes))
        rc, out = h.run("up")
        check("a re-run gives that card its batch", rc == 0 and list(card_codes(h.handout()["l5-acme-02"]))
              == CARD_PERSONAS, out)


def test_bypass_settings_change_reissues() -> None:
    print("== a change of count, reuse_count or valid_hours: up issues a new batch and says why ==")
    for extra, said, took in (
            ("bypass_codes:\n  count: 2\n", "count 1 -> 2",
             lambda h, r: all(len(v) == 2 for v in card_codes(r).values())),
            ("bypass_codes:\n  reuse_count: 3\n", "reuse_count 5 -> 3", lambda h, r: r["bypass_reuse"] == "3"),
            ("bypass_codes:\n  valid_hours: 30\n", "valid_hours 12 -> 30",
             lambda h, r: 0 <= lp.parse_time(r["bypass_valid_until"]) - (h.clock() + 30 * 3600) < 60)):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            rc, out = h.run("up")
            before = {n: card_codes(r) for n, r in h.handout().items()}
            (Path(tmp) / "workshop.yaml").write_text(YAML + extra)
            rc, out = h.run("status")
            check(f"[{said}] status warns that each card's batch was issued with other settings",
                  out.count("issued with other settings than workshop.yaml's") == 2 and said in out, out)
            rc, out = h.run("check")
            check(f"[{said}] check plans a new batch for each card and says which setting changed",
                  rc == 0 and out.count(f"its codes were issued with other settings ({said})") == 2
                  and out.count("PLAN     instance 0") == 2, out)
            posts = len(bypass_posts(h))
            rc, out = h.run("up")
            rows = h.handout()
            check(f"[{said}] up issues a new batch for each card, says why, and the cards carry the new setting",
                  rc == 0 and out.count(f"CHANGED  instance 0") == 2
                  and out.count(f"its codes were issued with other settings ({said})") == 2
                  and len(bypass_posts(h)) == posts + 8 and all(card_codes(r) != before[n] for n, r in rows.items())
                  and all(took(h, r) for r in rows.values()), out)
            rc, out = h.run("up")
            check(f"[{said}] a re-run with the same settings keeps both batches",
                  rc == 0 and out.count("kept: valid until") == 2, out)
    batch = lb.Batch([("victim", "avery.kim", ["123456789"])], 1000.0 + 12 * 3600, 1000.0, 5)
    check("settings that match change nothing; each setting that differs is named",
          lb.setting_changes(batch, lb.Settings()) == []
          and lb.setting_changes(batch, lb.Settings(True, 2, 3, 30))
          == ["count 1 -> 2", "reuse_count 5 -> 3", "valid_hours 12 -> 30"])
    check("a card without its issue time or use count is reissued (its settings cannot be told)",
          lb.setting_changes(lb.Batch(batch.entries, batch.valid_until), lb.Settings())
          == ["reuse_count ? -> 5", "valid_hours ? -> 12"])


def test_bypass_revocation() -> None:
    print("== revocation: each batch's code ids are recorded; down and handouts --revoke delete exactly those ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        rows = h.handout()
        for nn in ("01", "02"):
            batch = record(h, nn)["bypass_batches"][-1]
            held = {e["persona"]: sorted(code_value(h, i) for i in e["ids"]) for e in batch["codes"]}
            check(f"[{nn}] the record holds exactly the ids of the codes on its card, per persona",
                  held == {p: sorted(c) for p, c in card_codes(rows[f"l5-acme-{nn}"]).items()}
                  and batch["unknown"] == [] and batch["complete"] is True, str(batch))
        calls = h.duo.calls
        bracketed = all(i > 0 and calls[i - 1][1:3] == ("GET", p) and calls[i + 1][1:3] == ("GET", p)
                        for i, (_, m, p, _) in enumerate(calls) if m == "POST" and p.endswith("/bypass_codes"))
        check("every create is bracketed by two listings of that persona's bypass codes", bracketed)
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        old1, old2 = card_codes(rows["l5-acme-01"]), card_codes(rows["l5-acme-02"])
        other = h.duo.add_bypass(h.duo.by_name("marcus.bell")["user_id"])
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "1", "--revoke")
        new1 = card_codes(h.handout()["l5-acme-01"])
        deleted = [p.rsplit("/", 1)[1] for p in deletes_since(h, start)]
        check("handouts --only 1 --revoke: a fresh batch on card 01, and its earlier batch's 4 codes deleted",
              rc == 0 and new1 != old1 and len(deleted) == 4
              and all(p.startswith("/admin/v1/bypass_codes/") for p in deletes_since(h, start))
              and "deleted 4 bypass code(s) of its earlier batch(es)" in out, out)
        try_code = lambda n, c: auth.auth_passcode(n, c, "198.51.100.200", "ATTENDEE-LAPTOP")["result"]  # noqa: E731
        check("... the lost card's codes no longer work, the new card's do",
              all(try_code(n, c[0]) == "deny" for n, c in old1.items())
              and all(try_code(n, c[0]) == "allow" for n, c in new1.items()))
        check("... while card 02's codes and the other room's code for the same persona are untouched",
              all(try_code(n, c[0]) == "allow" for n, c in old2.items())
              and other[0] in [c["bypass_code_id"] for c in h.duo.live_codes("marcus.bell")])
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "2")
        check("handouts without --revoke deletes nothing", rc == 0 and not deletes_since(h, start), out)
        rc, out = h.run("up", "--revoke")
        check("--revoke is for handouts only (exit 2)", rc == 2 and "--revoke is for handouts" in out, out)

    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        marcus = h.duo.by_name("marcus.bell")["user_id"]
        theirs: List[str] = []
        h.duo.bypass_hooks.append(lambda uid: theirs.extend(h.duo.add_bypass(uid)) if uid == marcus and not theirs
                                  else None)     # another room's create lands between the two listings
        rc, out = h.run("up", "--only", "1")
        batch = record(h, "01")["bypass_batches"][-1]
        until = lp.minute(lp.parse_time(batch["unknown"][0]["until"])) if batch["unknown"] else "?"
        check("another room's create between the listings: that persona's ids are unknown, the others' are recorded",
              rc == 0 and [u["persona"] for u in batch["unknown"]] == ["marcus.bell"] and theirs
              and sorted(e["persona"] for e in batch["codes"]) == ["avery.kim", "elena.sousa", "grace.lin"]
              and "the ids of marcus.bell's codes could not be told apart from another room's, so this tool cannot "
                  f"revoke them: they expire at {until}" in out, str(batch) + out)
        mine = card_codes(h.handout()["l5-acme-01"])["marcus.bell"][0]
        rc, out = h.run("down", "--only", "1")
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        check("down deletes the tracked codes and leaves the ambiguous ones to valid_secs, saying until when",
              rc == 0 and "deleted 3 bypass code(s)" in out and theirs[0] in [c["bypass_code_id"] for c in
                                                                         h.duo.live_codes("marcus.bell")]
              and auth.auth_passcode("marcus.bell", mine, "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "allow"
              and "marcus.bell (batch issued " in out and f"any such code expires at {until}" in out
              and f"marcus.bell on instance 01, until {until}" in out
              and "every batch these cards had is deleted" not in out
              and "Persona bypass codes that lab5-setup could not delete stay valid until" in out, out)

    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        h.duo.fail[("DELETE", "/admin/v1/bypass_codes/")] = DuoFailure(500, 50000, "Internal error")
        rc, out = h.run("down")
        check("Duo refusing the DELETEs: down still reverts every box, exits 1, names the cards and keeps their ids",
              rc == 1 and "RESULT: down: 2 ok, 0 failed; persona bypass codes not deleted on 2 card(s) (instance 01, "
                          "02)" in out and lb.pending(h.root, "acme", ["01", "02"]) == ["01", "02"], out)
        del h.duo.fail[("DELETE", "/admin/v1/bypass_codes/")]
        for item in ("pseudoco-lab5-duo-provisioner-ikey", "pseudoco-lab5-duo-provisioner-skey"):
            tls.SECRETS.pop(item)
        try:
            rc, out = h.run("down")
        finally:
            tls.SECRETS.update(KEYCHAIN_SECRETS)
        check("no Provisioner keys in the Keychain: down says no code was deleted, exits 1, the boxes stay reverted",
              rc == 1 and "no bypass code deleted" in out and "RESULT: down: 2 ok, 0 failed" in out, out)
        rc, out = h.run("down")
        check("a re-run deletes them all", rc == 0 and out.count("deleted 4 bypass code(s)") == 2
              and lb.pending(h.root, "acme", ["01", "02"]) == [], out)
    admin = duo.AdminAPI(FakeDuo(Clock(time.time())).transport("admin", PROVISIONER["ikey"], PROVISIONER["skey"],
                                                                 API_HOST), API_HOST)
    check("AdminAPI.delete_bypass_code: a code Duo does not have is a 404, reported as already gone",
          admin.delete_bypass_code("DB0000009999") is False)


def persona_row(out: str, name: str) -> str:
    """The last report row of one room persona in this output."""
    rows = [l for l in out.splitlines()
            if l.split()[:1] in (["OK"], ["FAIL"], ["SKIP"], ["WARN"]) and l.split()[1:2] == [name]]
    return rows[-1] if rows else ""


def posted_users(h: Harness, start: int = 0) -> List[str]:
    """The usernames whose bypass codes were created since call ``start``."""
    ids = {u["user_id"]: u["username"] for u in h.duo.users.values()}
    return [ids.get(p.split("/")[4], "?") for _, m, p, _ in h.duo.calls[start:]
            if m == "POST" and p.endswith("/bypass_codes")]


def try_code(h: Harness, name: str, code: str) -> str:
    auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
    return auth.auth_passcode(name, code, "198.51.100.200", "ATTENDEE-LAPTOP")["result"]


def test_bypass_persona_groups() -> None:
    print("== a room persona in a Duo group that is not Active (Bypass, Disabled): no batch, each card fails ==")
    for status, said in (("Bypass", "plan 4.3 forbids a bypass group"),
                         ("Disabled", "Duo lets no member of a disabled group sign in")):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            group = h.duo.join_group("marcus.bell", "Lab Shortcuts", status)    # as Duo's table writes it
            rc, out = h.run("check")
            row = persona_row(out, "marcus.bell")
            check(f"[{status}] check fails each card and names the persona, the group and its status; changes nothing",
                  rc == 1 and row.startswith("  FAIL") and f"Lab Shortcuts (status {status})" in row and said in row
                  and "in the Duo Admin Panel" in row and out.count("FAIL     instance 0") == 2
                  and not h.duo.mutations(), out)
            listed = {p.split("/")[4] for _, m, p, _ in h.duo.calls
                      if m == "GET" and p.startswith("/admin/v1/users/") and p.endswith("/groups")}
            check(f"[{status}] ... each room persona's groups are read with GET /admin/v1/users/{{id}}/groups",
                  {h.duo.by_name(n)["user_id"] for n in CARD_PERSONAS} <= listed, str(listed))
            rc, out = h.run("up")
            check(f"[{status}] up issues no code to anyone and fails each card (exit 1, not 2)",
                  rc == 1 and not bypass_posts(h) and out.count("no bypass codes issued") == 2
                  and "RESULT: up: 2 ok, 0 failed; persona bypass codes failed on 2 card(s) (instance 01, 02)" in out,
                  out)
            rc, out = h.run("handouts")
            check(f"[{status}] handouts issues none either (exit 1)",
                  rc == 1 and not bypass_posts(h) and out.count("no bypass codes issued") == 2, out)
            rc, out = h.run("status")
            check(f"[{status}] status shows it: this persona fails with its group, the others list their Active groups",
                  rc == 1 and persona_row(out, "marcus.bell").startswith("  FAIL")
                  and "Lab Shortcuts" in persona_row(out, "marcus.bell")
                  and all("its Duo groups are Active: PseudoCo Workforce" in persona_row(out, n)
                          for n in ("avery.kim", "elena.sousa", "grace.lin")), out)
            check(f"[{status}] ... and the persona and the group are left as they were",
                  h.duo.by_name("marcus.bell")["status"] == "active" and group["status"] == status)
            group["status"] = "Active"
            rc, out = h.run("up")
            check(f"[{status}] once the group is Active again, up puts the codes on both cards (exit 0)",
                  rc == 0 and len(bypass_posts(h)) == 8
                  and all(list(card_codes(r)) == CARD_PERSONAS for r in h.handout().values()), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.group("PseudoCo Workforce")["status"] = "disabled"
        rc, out = h.run("check")
        check("the persona group itself disabled (lower case, as Duo's examples write it): every room persona fails",
              rc == 1 and all(persona_row(out, n).startswith("  FAIL")
                              and "PseudoCo Workforce (status disabled)" in persona_row(out, n)
                              for n in CARD_PERSONAS), out)
        h.duo.group("PseudoCo Workforce")["status"] = "active"
        elena = h.duo.by_name("elena.sousa")["user_id"]
        h.duo.fail[("GET", f"/admin/v1/users/{elena}/groups")] = DuoFailure(500, 50000, "Internal error")
        rc, out = h.run("up")
        check("Duo cannot list a persona's groups: that persona fails, no card gets codes, up still finishes (exit 1)",
              rc == 1 and "its Duo groups cannot be read" in persona_row(out, "elena.sousa")
              and not bypass_posts(h) and _up_finished(out), out)
    check("group_status reads Duo's documented values in either case",
          [duo.group_status(g) for g in ({"status": "Bypass"}, {"status": "active"}, {"status": " Disabled "}, {})]
          == ["bypass", "active", "disabled", ""])


def test_handouts_revoke_waits_for_the_new_batch() -> None:
    print("== handouts --revoke: a card's earlier codes go only once its new batch is on it and recorded ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        before = {r["instance"]: card_codes(r) for r in h.handout().values()}
        earlier = {nn: {i for b in record(h, nn)["bypass_batches"] for e in b["codes"] for i in e["ids"]}
                   for nn in ("01", "02")}
        marcus = h.duo.by_name("marcus.bell")["user_id"]
        creates: List[str] = []

        def refuse_card_01(uid: str) -> None:       # Duo refuses marcus.bell's code for card 01, then recovers
            creates.append(uid)
            if len(creates) == 1:
                h.duo.fail[("POST", f"/admin/v1/users/{marcus}/bypass_codes")] = DuoFailure(500, 50000, "Internal error")
            elif len(creates) == 2:
                h.duo.fail.clear()
        h.duo.bypass_hooks.append(refuse_card_01)
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--revoke")
        deleted = {p.rsplit("/", 1)[1] for p in deletes_since(h, start)}
        after = {r["instance"]: card_codes(r) for r in h.handout().values()}
        skipped = [l for l in out.splitlines() if l.split()[:3] == ["SKIP", "instance", "01"]]
        check("card 01's new batch fails: its card and its earlier codes stay, and --revoke says it deleted none",
              rc == 1 and after["01"] == before["01"] and not deleted & earlier["01"]
              and "keeps its earlier codes" in out and skipped and "--revoke deleted none" in skipped[0]
              and all(try_code(h, n, c[0]) == "allow" for n, c in before["01"].items()), out)
        check("... card 02 gets its new batch, and only then loses its earlier codes",
              earlier["02"] <= deleted and after["02"] != before["02"]
              and all(try_code(h, n, c[0]) == "deny" for n, c in before["02"].items())
              and all(try_code(h, n, c[0]) == "allow" for n, c in after["02"].items()), out)
        check("... the handout line names only the card that changed, and RESULT the one that failed",
              "print the changed card(s) again, instance 02. " in out
              and "RESULT: handouts: 1 card(s) ok, 1 failed (instance 01)" in out, out)
        partial = record(h, "01")["bypass_batches"][-1]
        check("... card 01's partial batch is recorded as incomplete, for a later --revoke or down",
              partial["complete"] is False and lb.pending(h.root, "acme", ["01"]) == ["01"], str(partial))

        real = lb._record

        def no_record(env, nn, *args, **kwargs):     # the new batch reaches card 01, its record cannot be written
            if nn == "01":
                raise OSError(28, "No space left on device")
            return real(env, nn, *args, **kwargs)
        lb._record = no_record
        try:
            start = len(h.duo.calls)
            rc, out = h.run("handouts", "--only", "1", "--revoke")
        finally:
            lb._record = real
        check("new batch on card 01 but not recorded: --revoke deletes nothing, and the card is named for printing",
              rc == 1 and not deletes_since(h, start) and card_codes(h.handout()["l5-acme-01"]) != before["01"]
              and "print the changed card(s) again, instance 01. " in out
              and "--revoke deleted none of its earlier codes" in out, out)

        h.duo.by_name("grace.lin")["status"] = "disabled"
        cards = h.handout()
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--revoke")
        check("a room persona not active: handouts --revoke deletes nothing, changes no card, names none to print",
              rc == 1 and not deletes_since(h, start) and h.handout() == cards
              and out.count("--revoke deleted none of its earlier codes") == 2
              and "no card changed, so there is nothing to print again" in out
              and "print the changed card" not in out, out)
        h.duo.by_name("grace.lin")["status"] = "active"
        rc, out = h.run("handouts", "--only", "1", "--revoke")
        check("fixed: a re-run puts a new batch on card 01, then deletes the 5 codes its earlier batches recorded",
              rc == 0 and "deleted 5 bypass code(s) of its earlier batch(es)" in out
              and all(try_code(h, n, c[0]) == "deny" for n, c in before["01"].items()), out)


class _Broken:
    """A duo_client stand-in whose every call fails as a transport can."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def json_api_call(self, method, path, params):
        raise self.exc

    def json_paging_api_call(self, method, path, params):
        raise self.exc
        yield  # a generator, as duo_client's is


def test_duo_transport_errors() -> None:
    print("== a Duo call without a usable answer is a DuoError; up, handouts and down still finish ==")
    import http.client
    import json
    import socket
    import ssl
    partial = b'["407176182", "0169'
    for exc in (http.client.IncompleteRead(partial, 20), http.client.RemoteDisconnected("Remote end closed"),
                ssl.SSLError(1, "[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC] decryption failed"),
                socket.timeout("timed out"), json.JSONDecodeError("Expecting value", partial.decode(), 0),
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
                AttributeError("'str' object has no attribute 'get'")):
        api = duo.AdminAPI(_Broken(exc), API_HOST)
        outcomes = []
        for call in (lambda: api.call("GET", "/admin/v1/users"), lambda: api.page("/admin/v1/users"),
                     lambda: api.create_bypass_codes("DU0000000001", 1, 5, 3600)):
            try:
                call()
                outcomes.append("returned")
            except duo.DuoError as err:
                outcomes.append("DuoError" if type(exc).__name__ in str(err) and "407176182" not in str(err)
                                else str(err))
            except Exception as err:  # noqa: BLE001
                outcomes.append(type(err).__name__)
        check(f"{type(exc).__name__}: call, page and create each raise a DuoError naming it, never the answer",
              outcomes == ["DuoError"] * 3, str(outcomes))
    bad = RuntimeError('Received bad response: {"stat": "OK", "response": ["407176182", "0169')
    bad.status, bad.reason, bad.data = 200, "OK", '{"stat": "OK", "response": ["407176182", "0169'
    try:
        duo.AdminAPI(_Broken(bad), API_HOST).create_bypass_codes("DU0000000001", 1, 5, 3600)
        said = "returned"
    except duo.DuoError as err:
        said = str(err)
    check("duo_client's 'bad response' (the body in its message) is a DuoError that never repeats the body",
          said.startswith("Duo POST") and "407176182" not in said and "not the JSON it documents" in said, said)
    dup = RuntimeError("Received 400 Duplicate resource")
    dup.status, dup.reason, dup.data = 400, "Bad Request", {"stat": "FAIL", "code": 40003,
                                                            "message": "Duplicate resource"}
    try:
        duo.AdminAPI(_Broken(dup), API_HOST).create_group("x", "y")
        got = None
    except duo.DuoError as err:
        got = (err.status, err.code)
    check("a refusal keeps Duo's status and code, also when duo_client leaves its body parsed",
          got == (400, 40003), str(got))

    def create_error(exc: BaseException) -> duo.DuoError:
        try:
            duo.AdminAPI(_Broken(exc), API_HOST).create_bypass_codes("DU0000000001", 1, 5, 3600)
        except duo.DuoError as err:
            return err
        raise AssertionError("create_bypass_codes returned")
    lost = [socket.timeout("timed out"), ConnectionResetError(54, "reset"), http.client.IncompleteRead(b"", 2),
            gateway_error(502), gateway_error(503), gateway_error(504), DuoFailure(500, 50000, "Internal error"),
            bad, json.JSONDecodeError("Expecting value", "", 0)]
    check("a create without a usable answer is a lost DuoError: a transport error, an answer cut off, a 5xx "
          "(a gateway's 502/503/504 included), an unreadable 200",
          all(create_error(exc).lost for exc in lost), str([(type(e).__name__, create_error(e).lost) for e in lost]))
    try:
        duo.AdminAPI(_Broken(AssertionError("never called")), API_HOST).create_bypass_codes("DU0000000001", 0, 5, 60)
        early = None
    except duo.DuoError as err:
        early = err
    check("a refusal (4xx) and a check made before the call are not lost: nothing was made",
          not create_error(DuoFailure(400, 40002, "Invalid request parameters")).lost
          and not create_error(DuoFailure(429, 42901, "Too Many Requests")).lost and early is not None
          and not early.lost)
    said = {}
    for method, call in (("GET", lambda api: api.page("/admin/v1/users")),
                         ("POST", lambda api: api.create_bypass_codes("DU0000000001", 1, 5, 3600)),
                         ("DELETE", lambda api: api.delete_bypass_code("DB0000000001"))):
        for exc in (socket.timeout("timed out"), ConnectionRefusedError(61, "refused"), ssl.SSLError(1, "x")):
            try:
                call(duo.AdminAPI(_Broken(exc), API_HOST))
            except duo.DuoError as err:
                said[(method, type(exc).__name__)] = str(err)
    check("no transport error says Duo could not be reached; one on a POST or DELETE says whether it took effect is "
          "unknown",
          len(said) == 9 and not any("cannot reach" in text for text in said.values())
          and all("whether the call took effect is unknown" in text for (m, _), text in said.items() if m != "GET")
          and all("no answer from Duo (" in text for (m, _), text in said.items() if m == "GET"), str(said))

    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        marcus, elena = (h.duo.by_name(n)["user_id"] for n in ("marcus.bell", "elena.sousa"))
        seen: List[str] = []

        def cut_off(uid: str) -> None:          # the answer to elena.sousa's create for card 02 is cut off
            seen.append(uid)
            if seen.count(marcus) == 2:
                h.duo.fail[("POST", f"/admin/v1/users/{elena}/bypass_codes")] = http.client.IncompleteRead(b'["1', 20)
        h.duo.bypass_hooks.append(cut_off)
        rc, out = h.run("up")
        batch = record(h, "02")["bypass_batches"][-1]
        check("up: an IncompleteRead halfway through card 02 fails that card only, and up prints its RESULT, the "
              "handout, the password links and the reminders (exit 1, no traceback)",
              rc == 1 and _up_finished(out) and lost_row(h, "elena.sousa") in out
              and "persona bypass codes failed on 1 card(s) (instance 02)" in out
              and list(card_codes(h.handout()["l5-acme-01"])) == CARD_PERSONAS, out)
        check("... and records what was issued: card 02's 2 codes, as an incomplete batch, and elena.sousa as unknown",
              batch["complete"] is False and sum(len(e["ids"]) for e in batch["codes"]) == 2
              and [u["persona"] for u in batch["unknown"]] == ["elena.sousa"], str(batch))

        h.duo.fail.clear()
        h.duo.fail[("GET", "/admin/v1/users")] = ssl.SSLError(1, "[SSL] record layer failure")
        rc, out = h.run("handouts")
        check("handouts: a TLS error reading the personas fails each card; the handout line and RESULT still print",
              rc == 1 and "no answer from Duo (SSLError)" in out and out.count("no bypass codes issued") == 2
              and "no card changed, so there is nothing to print again" in out
              and "RESULT: handouts: 0 card(s) ok, 2 failed (instance 01, 02)" in out, out)

        h.duo.fail.clear()
        h.duo.fail[("DELETE", "/admin/v1/bypass_codes/")] = http.client.IncompleteRead(b"", 2)
        real_route = h.world.cf.route

        def cut_listing(method, path, q, data):    # the orphan check's tunnel listing is cut off too
            if method == "GET" and "include_prefix" in q:
                raise http.client.IncompleteRead(b"", 10)
            return real_route(method, path, q, data)
        h.world.cf.route = cut_listing
        try:
            rc, out = h.run("down")
        finally:
            h.world.cf.route = real_route
        check("down: cut-off DELETE answers fail the cards and keep their ids; down still prints its RESULT (exit 1)",
              rc == 1 and "RESULT: down: 2 ok, 0 failed; persona bypass codes not deleted on 2 card(s) (instance 01, "
                          "02)" in out and lb.pending(h.root, "acme", ["01", "02"]) == ["01", "02"], out)
        check("... and a cut-off Cloudflare orphan listing is a WARN, not the end of down",
              "not looked for: Cloudflare did not answer (IncompleteRead)" in out, out)
        h.duo.fail.clear()
        h.duo.fail[("GET", "/admin/v1/users/")] = json.JSONDecodeError("Expecting value", "", 0)
        rc, out = h.run("down")
        check("down: unreadable listings fail the cards; RESULT still printed (exit 1)",
              rc == 1 and "(JSONDecodeError)" in out and "persona bypass codes not deleted on 2 card(s)" in out, out)
        h.duo.fail.clear()
        rc, out = h.run("down")
        check("... and a re-run deletes every recorded code, and names the cut-off create's codes instead of saying "
              "every batch is deleted",
              rc == 0 and lb.pending(h.root, "acme", ["01", "02"]) == []
              and "every batch these cards had is deleted" not in out
              and f"elena.sousa on instance 02, until {lost_until(h)}" in out, out)

    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.fail[("POST", "/admin/v1/groups")] = json.JSONDecodeError("Expecting value", "", 0)
        rc, out = h.run("up")
        check("up: an unreadable answer creating the workshop group fails the accounts, and up still prints the "
              "reminders and its RESULT (exit 1)",
              rc == 1 and "FAIL     groups" in out and "(JSONDecodeError)" in out
              and "RESULT: up: 2 ok, 0 failed; 2 participant account(s) failed" in out
              and "whose User access must admit CII Read-Only" in out and "Its policy (plan 4.4)" in out, out)
        h.duo.fail.clear()
        rc, out = h.run("up")
        check("... and a re-run creates the accounts and their cards", rc == 0 and _up_finished(out), out)


def test_contained_victim() -> None:
    print("== the room's victim disabled by the lab's containment: its codes are skipped, no reset before the debrief ==")
    trusted = ["marcus.bell", "elena.sousa", "grace.lin"]
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        before = {r["instance"]: card_codes(r) for r in h.handout().values()}
        h.duo.by_name("avery.kim")["status"] = "disabled"      # claim 4: the response agent disables the victim
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "1")
        row = persona_row(out, "avery.kim")
        new1 = card_codes(h.handout()["l5-acme-01"])
        check("handouts after the containment: the victim's row says it is contained, asks for a reset only after "
              "the workshop, and nothing says to set it active now (exit 0)",
              rc == 0 and row.startswith("  SKIP") and "contained" in row and "after the workshop" in row
              and "provision_personas.py --reset --only avery.kim" in row and "set it active" not in out, out)
        check("... card 01 gets a fresh batch for the trusted personas only, none for the victim; card 02 is untouched",
              list(new1) == trusted and posted_users(h, start) == trusted
              and "none for avery.kim, which is contained" in out
              and card_codes(h.handout()["l5-acme-02"]) == before["02"], out)
        check("... the new trusted codes work; the contained victim signs in with none of its codes",
              all(try_code(h, n, c[0]) == "allow" for n, c in new1.items())
              and try_code(h, "avery.kim", before["02"]["avery.kim"][0]) == "deny")
        start = len(h.duo.calls)
        rc, out = h.run("up")
        check("up after the containment keeps both cards (with or without the victim's code) and asks for no reset",
              rc == 0 and out.count("kept: valid until") == 2 and not posted_users(h, start)
              and "set it active" not in out and persona_row(out, "avery.kim").startswith("  SKIP"), out)
        rc, out = h.run("status")
        check("status shows the victim contained, and its dead code on card 02, without failing (exit 0)",
              rc == 0 and "contained" in persona_row(out, "avery.kim")
              and "avery.kim (victim, contained: its code no longer works)" in out, out)
        rc, out = h.run("check")
        check("check: the same, exit 0", rc == 0 and out.count("OK       instance 0") == 2, out)
        rc, out = h.run("handouts", "--only", "2", "--revoke")
        check("handouts --only 2 --revoke after the containment: trusted codes, its earlier 4 codes deleted",
              rc == 0 and list(card_codes(h.handout()["l5-acme-02"])) == trusted
              and "deleted 4 bypass code(s) of its earlier batch(es)" in out, out)
        h.duo.by_name("avery.kim")["status"] = "active"        # provision_personas.py --reset, after the workshop
        rc, out = h.run("up")
        check("after the reset, up gives both cards the victim's codes again",
              rc == 0 and out.count("its codes are for other personas") == 2
              and all(list(card_codes(r)) == CARD_PERSONAS for r in h.handout().values()), out)
        h.duo.by_name("avery.kim")["status"] = "disabled"
        h.duo.join_group("avery.kim", "Lab Shortcuts", "Bypass")
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "1")
        check("a contained victim in a bypass group still stops every card (plan 4.3)",
              rc == 1 and persona_row(out, "avery.kim").startswith("  FAIL")
              and "Lab Shortcuts (status Bypass)" in out and not posted_users(h, start), out)
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.by_name("avery.kim")["status"] = "disabled"      # left so by an earlier delivery
        rc, out = h.run("check")
        row = persona_row(out, "avery.kim")
        check("a victim disabled before this workshop gave it any code is not the containment: check fails each "
              "card and asks for the reset now",
              rc == 1 and row.startswith("  FAIL") and "not the lab's containment" in row
              and "set it active (scripts/identity/provision_personas.py --reset --only avery.kim)" in row
              and out.count("FAIL     instance 0") == 2, out)
        rc, out = h.run("up")
        check("... and up issues no code (exit 1)", rc == 1 and not bypass_posts(h), out)


def test_bypass_locked_out_is_temporary() -> None:
    print("== a locked-out room persona: no reset advice, the other codes go on, the card is partial (plan 4.4) ==")
    others = ["avery.kim", "elena.sousa", "grace.lin"]
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        before = {r["instance"]: card_codes(r) for r in h.handout().values()}
        h.duo.by_name("marcus.bell")["status"] = "locked out"      # an attendee's typos, mid-lab
        changes = len(h.duo.mutations())
        rc, out = h.run("check")
        row = persona_row(out, "marcus.bell")
        check("check: the locked-out persona is a WARN that says it unlocks on its own and to retry handouts, with "
              "no reset; the cards keep their batches (exit 0)",
              rc == 0 and row.startswith("  WARN") and "locked out in Duo" in row and "unlocks it on its own" in row
              and "about 15 minutes" in row and "lab5-setup handouts" in row and "--reset" not in out
              and out.count("OK       instance 0") == 2 and len(h.duo.mutations()) == changes, out)
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "1")
        new1 = card_codes(h.handout()["l5-acme-01"])
        partial = [l for l in out.splitlines() if l.split()[:3] == ["PARTIAL", "instance", "01"]]
        check("handouts --only 1: card 01 gets the other personas' codes, none for the locked-out one, and is "
              "reported partial, not failed (exit 0, no reset advice)",
              rc == 0 and list(new1) == others and posted_users(h, start) == others and partial
              and "none for marcus.bell, locked out in Duo" in partial[0] and "--only 1` once it is unlocked" in partial[0]
              and "--reset" not in out and "set it active" not in out
              and "RESULT: handouts: 0 card(s) ok, 0 failed; 1 partial (instance 01)" in out
              and card_codes(h.handout()["l5-acme-02"]) == before["02"], out)
        check("... the new codes work; the locked-out persona's code on card 02 is left on it",
              all(try_code(h, n, c[0]) == "allow" for n, c in new1.items())
              and "marcus.bell" in card_codes(h.handout()["l5-acme-02"]))
        start = len(h.duo.calls)
        rc, out = h.run("up")
        check("up while it is still locked out: no new code, card 01 kept but partial, card 02 kept, RESULT names "
              "the partial card (exit 0)",
              rc == 0 and not posted_users(h, start) and "PARTIAL  instance 01" in out
              and "OK       instance 02" in out
              and "persona bypass codes partial on 1 card(s) (instance 01)" in out and "--reset" not in out, out)
        rc, out = h.run("status")
        check("status: the persona is a WARN, card 01 partial, card 02's code for it works again once unlocked "
              "(exit 0)",
              rc == 0 and persona_row(out, "marcus.bell").startswith("  WARN") and "PARTIAL  instance 01" in out
              and "marcus.bell (locked out: its code works again once Duo unlocks it)" in out, out)
        h.duo.by_name("marcus.bell")["status"] = "active"          # auto-revert, about 15 minutes later
        rc, out = h.run("handouts", "--only", "1")
        check("once Duo unlocks it, a retried handouts --only 1 gives card 01 the whole room's codes (exit 0)",
              rc == 0 and list(card_codes(h.handout()["l5-acme-01"])) == CARD_PERSONAS
              and "CHANGED  instance 01" in out and "partial" not in out, out)
        h.duo.by_name("marcus.bell")["status"] = "locked out"
        h.duo.join_group("marcus.bell", "Lab Shortcuts", "Bypass")
        start = len(h.duo.calls)
        rc, out = h.run("handouts")
        check("a locked-out persona in a bypass group still stops every card (plan 4.3)",
              rc == 1 and persona_row(out, "marcus.bell").startswith("  FAIL")
              and "Lab Shortcuts (status Bypass)" in out and not posted_users(h, start)
              and out.count("no bypass codes issued") == 2, out)


def uid_of(h: Harness, name: str) -> str:
    return h.duo.by_name(name)["user_id"]


def recorded_ids(h: Harness, numbers: Tuple[str, ...] = ("01", "02")) -> List[str]:
    """Every bypass code id these cards' participant records keep."""
    return [i for nn in numbers for b in record(h, nn).get("bypass_batches") or [] for e in b.get("codes") or []
            for i in e.get("ids") or []]


def live_ids(h: Harness, name: str) -> List[str]:
    return [c["bypass_code_id"] for c in h.duo.live_codes(name)]


def relisted_after_post(h: Harness, path: str) -> bool:
    """Did the tool list this persona's codes again after its last create?"""
    last = max((i for i, (_, m, p, _) in enumerate(h.duo.calls) if m == "POST" and p == path), default=-1)
    return any(m == "GET" and p == path for _, m, p, _ in h.duo.calls[last + 1:])


def test_bypass_lost_create_answer() -> None:
    print("== a create without a usable answer: its persona's ids are unknown for the card, never listed again ==")
    import http.client
    import ssl

    def before_duo(exc: BaseException) -> Callable[[Harness, str], None]:
        """The create never reaches Duo (or Duo fails it): nothing is made."""
        return lambda h, path: h.duo.fail.__setitem__(("POST", path), exc)

    def after_duo(make: Callable[[], BaseException]) -> Callable[[Harness, str], None]:
        """Duo makes the code, then its answer is lost."""
        def arm(h: Harness, path: str) -> None:
            elena = uid_of(h, "elena.sousa")

            def hook(uid: str) -> None:
                if uid == elena:
                    raise make()
            h.duo.bypass_hooks.append(hook)
        return arm

    def not_the_codes(reshape: Callable[[List[str]], Any]) -> Callable[[Harness, str], None]:
        """Duo makes the code and answers 200, with JSON that is not the codes."""
        def arm(h: Harness, path: str) -> None:
            real = h.duo.handle

            def handle(kind: str, method: str, p: str, params: Dict[str, str]) -> Any:
                result = real(kind, method, p, params)
                return reshape(result) if (method, p) == ("POST", path) else result
            h.duo.handle = handle  # type: ignore[method-assign]
        return arm

    def bad_200() -> RuntimeError:     # duo_client's 200 whose body is not JSON: the body is in its message
        err = RuntimeError('Received bad response: {"stat": "OK", "response": ["40717')
        err.status, err.reason, err.data = 200, "OK", '{"stat": "OK", "response": ["40717'
        return err

    cases = (("a timeout before the request reached Duo", before_duo(socket_timeout()), False),
             ("a TLS error before the request reached Duo", before_duo(ssl.SSLError(1, "[SSL] handshake")), False),
             ("a 500 from Duo", before_duo(DuoFailure(500, 50000, "Internal error")), False),
             ("a timeout after Duo made the code", after_duo(socket_timeout), True),
             ("an answer cut off after Duo made the code",
              after_duo(lambda: http.client.IncompleteRead(b'["1', 20)), True),
             ("a 502 after Duo made the code", after_duo(lambda: gateway_error(502)), True),
             ("a 503 after Duo made the code", after_duo(lambda: gateway_error(503)), True),
             ("a 504 after Duo made the code", after_duo(lambda: gateway_error(504)), True),
             ("a malformed 200 (not JSON) after Duo made the code", after_duo(bad_200), True),
             ("a 200 whose JSON is not the codes", not_the_codes(lambda codes: {"codes": codes}), True),
             ("a 200 whose code is not numeric", not_the_codes(lambda codes: ["12ab"]), True))
    sentences: Dict[str, str] = {}
    for name, arm, made in cases:
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            elena = uid_of(h, "elena.sousa")
            path = f"/admin/v1/users/{elena}/bypass_codes"
            arm(h, path)
            rc, out = h.run("up", "--only", "1")
            h.duo.fail.clear()
            h.duo.bypass_hooks.clear()
            h.duo.__dict__.pop("handle", None)
            batch = record(h, "01")["bypass_batches"][-1]
            unknown = [u for u in batch.get("unknown") or [] if isinstance(u, dict)]
            until = lp.parse_time(str(unknown[0].get("until") or "")) if unknown else None
            row = next((l for l in out.splitlines() if l.split()[:3] == ["FAIL", "instance", "01"]), "")
            said = re.search(r"reached the card: (.*?)\. The card keeps", row)
            sentences[name] = re.sub(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC", "<time>", said.group(1) if said else row)
            check(f"[{name}] card 01 fails with the lost answer's one wording, never 'cannot reach'",
                  rc == 1 and lost_row(h, "elena.sousa") in out and "cannot reach" not in out
                  and "persona bypass codes failed on 1 card(s) (instance 01)" in out, out)
            check(f"[{name}] ... the tool lists nothing after the create, and records elena.sousa as unknown with "
                  "when its codes expire; the codes issued before it keep their ids",
                  not relisted_after_post(h, path)
                  and [(u.get("persona"), u.get("user_id")) for u in unknown] == [("elena.sousa", elena)]
                  and until == math.ceil((h.clock() + 12 * 3600 + lb.LOST_MARGIN_S) / 60.0) * 60.0
                  and [e["persona"] for e in batch["codes"]] == ["avery.kim", "marcus.bell"]
                  and "elena.sousa" not in batch["personas"] and batch["complete"] is False, str(batch))
            code = (h.duo.bypass.get(elena) or [{}])[-1] if made else {}
            check(f"[{name}] ... " + ("the code Duo made is attributed to no one, printed nowhere, and the time "
                                      "given is not before its own expiry" if made else "Duo made no code"),
                  (code.get("bypass_code_id") and code["bypass_code_id"] not in recorded_ids(h, ("01",))
                   and code["code"] not in out and code["code"] not in text_of_logs(h.root) and "40717" not in out
                   and until is not None and until >= code["expiration"]) if made
                  else not h.duo.live_codes("elena.sousa"), str(code))
            start = len(h.duo.calls)
            rc, out = h.run("down", "--only", "1")
            check(f"[{name}] down deletes the 2 recorded codes, none of elena.sousa's, says when those expire and "
                  "never claims every batch is deleted",
                  rc == 0 and "deleted 2 bypass code(s) of its batch(es)" in out and len(deletes_since(h, start)) == 2
                  and (not made or code["bypass_code_id"] in live_ids(h, "elena.sousa"))
                  and "elena.sousa (batch issued " in out and f"any such code expires at {lost_until(h)}" in out
                  and f"elena.sousa on instance 01, until {lost_until(h)}" in out
                  and "every batch these cards had is deleted" not in out, out)
    check("one wording for every lost answer, whatever the cause",
          set(sentences.values()) == {"Duo's answer was lost; any codes it made expire at <time> and cannot be revoked "
                                      "by this tool"}, str(sentences))

    print("== the cross-room race: our create never reaches Duo while another room issues the persona's codes ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        elena = uid_of(h, "elena.sousa")
        path = f"/admin/v1/users/{elena}/bypass_codes"
        theirs: List[str] = []

        def other_room(method: str, p: str) -> None:     # another room issues count codes for elena.sousa meanwhile
            if (method, p) == ("POST", path) and not theirs:
                theirs.extend(h.duo.add_bypass(elena, count=1, valid=12 * 3600))
        h.duo.call_hooks.append(other_room)
        h.duo.fail[("POST", path)] = socket_timeout()        # ours never reaches Duo
        rc, out = h.run("up", "--only", "1")
        h.duo.call_hooks.clear()
        h.duo.fail.clear()
        check("up: card 01 fails with the lost answer; elena.sousa is unknown and the other room's new code is "
              "attributed to no one (nothing is listed after the create)",
              rc == 1 and len(theirs) == 1 and lost_row(h, "elena.sousa") in out
              and [u.get("persona") for u in record(h, "01")["bypass_batches"][-1].get("unknown") or []
                   if isinstance(u, dict)] == ["elena.sousa"]
              and theirs[0] not in recorded_ids(h, ("01",)) and not relisted_after_post(h, path), out)
        theirs_code = code_value(h, theirs[0])
        start = len(h.duo.calls)
        rc, out = h.run("handouts", "--only", "1", "--revoke")
        check("handouts --only 1 --revoke: a new batch on card 01, the failed batch's 2 recorded codes deleted, "
              "elena.sousa's named with when they expire, and the other room's code untouched",
              rc == 0 and list(card_codes(h.handout()["l5-acme-01"])) == CARD_PERSONAS
              and "deleted 2 bypass code(s) of its earlier batch(es)" in out
              and f"any such code expires at {lost_until(h)}" in out
              and theirs[0] not in [p.rsplit("/", 1)[1] for p in deletes_since(h, start)]
              and try_code(h, "elena.sousa", theirs_code) == "allow", out)
        start = len(h.duo.calls)
        rc, out = h.run("down", "--only", "1")
        check("down: the 4 codes on card 01 deleted, none of the other room's; it says when elena.sousa's unknown "
              "codes expire and never claims every batch is deleted",
              rc == 0 and len(deletes_since(h, start)) == 4 and theirs[0] in live_ids(h, "elena.sousa")
              and try_code(h, "elena.sousa", theirs_code) == "allow"
              and f"elena.sousa on instance 01, until {lost_until(h)}" in out
              and "every batch these cards had is deleted" not in out, out)

    print("== a late commit: Duo makes a lost create's code later, during the next card's create ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        elena = uid_of(h, "elena.sousa")
        path = f"/admin/v1/users/{elena}/bypass_codes"
        posts: List[str] = []
        late: List[str] = []

        def time_out_first(method: str, p: str) -> None:     # card 01's create for elena.sousa: no answer in time
            if (method, p) == ("POST", path):
                posts.append(p)
                if len(posts) == 1:
                    h.duo.fail[("POST", path)] = socket_timeout()
                else:
                    h.duo.fail.pop(("POST", path), None)

        def commit_late(uid: str) -> None:                  # ... Duo commits it while card 02's create runs
            if uid == elena and not late:
                late.extend(h.duo.add_bypass(elena, count=1, valid=12 * 3600))
        h.duo.call_hooks.append(time_out_first)
        h.duo.bypass_hooks.append(commit_late)
        rc, out = h.run("up")
        h.duo.call_hooks.clear()
        h.duo.bypass_hooks.clear()
        b1, b2 = (record(h, nn)["bypass_batches"][-1] for nn in ("01", "02"))
        card2 = card_codes(h.handout()["l5-acme-02"])
        mine2 = next((c["bypass_code_id"] for c in h.duo.bypass[elena] if c["code"] == card2["elena.sousa"][0]), "")
        check("card 01 fails with the lost answer; card 02 gets its batch, but 2 new ids for elena.sousa, not 1, "
              "leave them unknown there too: neither the late code nor card 02's own is attributed",
              rc == 1 and len(late) == 1 and mine2 and lost_row(h, "elena.sousa") in out
              and "CHANGED  instance 02" in out
              and "the ids of elena.sousa's codes could not be told apart from another room's, so this tool cannot "
                  f"revoke them: they expire at {listed_until(h)}" in out
              and [u.get("persona") for u in b1.get("unknown") or [] if isinstance(u, dict)] == ["elena.sousa"]
              and [u.get("persona") for u in b2.get("unknown") or [] if isinstance(u, dict)] == ["elena.sousa"]
              and not {late[0], mine2} & set(recorded_ids(h)), str((b1, b2)) + out)
        start = len(h.duo.calls)
        rc, out = h.run("down")
        deleted = {p.rsplit("/", 1)[1] for p in deletes_since(h, start)}
        check("down: the 5 recorded codes deleted, neither elena.sousa code; it says when they expire on both cards "
              "and never claims every batch is deleted",
              rc == 0 and len(deleted) == 5 and not {late[0], mine2} & deleted
              and {late[0], mine2} <= set(live_ids(h, "elena.sousa"))
              and f"elena.sousa on instance 01, until {lost_until(h)}" in out
              and f"elena.sousa on instance 02, until {listed_until(h)}" in out
              and "every batch these cards had is deleted" not in out, out)

    print("== down once the unknown codes have expired: it still does not say every batch was deleted ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.fail[("POST", f"/admin/v1/users/{uid_of(h, 'elena.sousa')}/bypass_codes")] = socket_timeout()
        rc, out = h.run("up", "--only", "1")
        h.duo.fail.clear()
        h.clock.t += 12 * 3600 + lb.LOST_MARGIN_S + 120
        rc, out = h.run("down", "--only", "1")
        check("after valid_secs (and the lost answer's margin), down says nothing is still valid, including the "
              "codes whose ids it did not know",
              rc == 0 and "every batch these cards had is deleted" not in out
              and "none of these cards' codes is still valid" in out and "whose ids lab5-setup did not know" in out, out)


def socket_timeout() -> OSError:
    import socket
    return socket.timeout("timed out")


def gateway_error(status: int) -> RuntimeError:
    """duo_client's error for a gateway's 5xx: the body is the gateway's page, not Duo's JSON."""
    reason = {502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"}[status]
    err = RuntimeError(f"Received {status} {reason}")
    err.status, err.reason, err.data = status, reason, f"<html><body>{status} {reason}</body></html>".encode()
    return err


def lost_until(h: Harness) -> str:
    """When the codes of a create without a usable answer expire, as the rows print it: valid_hours (12) from
    the fake clock plus LOST_MARGIN_S (Duo may finish the create after the tool stopped waiting), rounded up to
    the minute so it is never before the codes' own expiry."""
    return lp.minute(math.ceil((h.clock() + 12 * 3600 + lb.LOST_MARGIN_S) / 60.0) * 60.0)


def listed_until(h: Harness) -> str:
    """When codes expire whose create returned but whose ids a listing could not tell apart: valid_hours (12)
    from the fake clock, rounded up to the minute (no lost-answer margin: the answer came back)."""
    return lp.minute(math.ceil((h.clock() + 12 * 3600) / 60.0) * 60.0)


def lost_row(h: Harness, persona: str) -> str:
    """A card's row for a create without a usable answer: one wording, whatever the cause."""
    return (f"no bypass code for {persona} reached the card: Duo's answer was lost; any codes it made expire at "
            f"{lost_until(h)} and cannot be revoked by this tool")


def test_signin_policy_docs() -> None:
    print("== the Sign-in policy allows bypass code + hardware token (plan 4.4) ==")
    sys.path.insert(0, str(ROOT / "scripts" / "identity"))
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        check("up says the Sign-in policy must allow bypass code + hardware token, and why",
              "Its policy (plan 4.4) must allow bypass code + hardware token" in out
              and "A policy without hardware tokens refuses every participant" in out, out)
    note = __import__("provision_personas").user_access_note("PseudoCo Workforce")
    check("provision_personas says it when it creates the persona group",
          "bypass code + hardware token" in note and "PseudoCo Lab: Sign-in admits PseudoCo Workforce and "
          "CII Read-Only" in note, note)
    stale = re.compile(r"bypass[ -]codes?[ -]only|methods: \*\*bypass code\*\*", re.I)
    for path in ("deploy/lab5/README.md", "deploy/lab5/README.html", "docs/identity-lab-facilitator.md",
                 "docs/identity-lab-facilitator.html", "deploy/lab5/lab5_setup.py", "deploy/lab5/lab5_bypass.py",
                 "scripts/identity/provision_personas.py", "deploy/lab5/workshop.example.yaml"):
        text = (ROOT / path).read_text()
        check(f"{path}: never asks for a bypass-code-only Sign-in policy", not stale.search(text),
              str(stale.findall(text)))
    for path in ("deploy/lab5/README.md", "docs/identity-lab-facilitator.md"):
        lines = [l for l in (ROOT / path).read_text().splitlines() if "bypass code + hardware token" in l]
        check(f"{path}: describes the Sign-in policy as bypass code + hardware token",
              any("PseudoCo Lab: Sign-in" in l or "Sign-in policy" in l for l in lines), str(lines))
    readme = (ROOT / "deploy" / "lab5" / "README.md").read_text().replace("`", "")
    check("README says how down and handouts --revoke find and delete the codes, and when valid_secs is the cutoff",
          "DELETE /admin/v1/bypass_codes/{id}" in readme and "returns only the code strings" in readme
          and "handouts --only N --revoke" in readme and "valid_secs is the cutoff" in readme
          and "before and after" in readme)
    runbook = (ROOT / "docs" / "identity-lab-facilitator.md").read_text()
    check("the runbook no longer leaves persona sign-in open",
          "The tools build no persona bypass codes until this is decided" not in runbook
          and "lab5-setup handouts" in runbook)


def _row(out: str, status: str, label: str) -> str:
    """The report line ``<status> <label> ...`` (empty when there is none)."""
    return next((line for line in out.splitlines() if line.split()[:3] == [status, *label.split()]), "")


def test_bypass_down_then_up() -> None:
    print("== down deletes a card's codes: status and check say so, and up issues a fresh batch ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        rc, out = h.run("up")
        dead = card_codes(h.handout()["l5-acme-01"])
        kept02 = card_codes(h.handout()["l5-acme-02"])
        rc, out = h.run("down", "--only", "1")
        check("down --only 1 deletes card 01's codes (the tool's own hint when a box's app is stuck)",
              rc == 0 and "deleted 4 bypass code(s)" in out
              and all(auth.auth_passcode(n, c[0], "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "deny"
                      for n, c in dead.items()), out)
        check("... and records when, on the batch the card carries",
              all(b.get("revoked_at") for b in record(h, "01")["bypass_batches"]), str(record(h, "01")))
        rc, out = h.run("status")
        row = _row(out, "FAIL", "instance 01")
        check("status after down: card 01 fails, its codes revoked (never 'valid until'), card 02 still OK",
              rc == 1 and "`lab5-setup down` revoked its codes at" in row and "print the card again" in row
              and _row(out, "OK", "instance 02"), out)
        rc, out = h.run("check")
        check("check: up would issue card 01 a fresh batch, and says why",
              "`lab5-setup down` revoked its codes, so none on the card works: issue" in _row(out, "PLAN", "instance 01"),
              out)
        posts = len(bypass_posts(h))
        rc, out = h.run("up", "--only", "1")
        fresh = card_codes(h.handout()["l5-acme-01"])
        check("up --only 1 issues card 01 a fresh batch (CHANGED: print it again), never keeps the dead one",
              rc == 0 and "`lab5-setup down` revoked its codes" in _row(out, "CHANGED", "instance 01")
              and len(bypass_posts(h)) == posts + 4 and fresh != dead and "kept: valid until" not in out, out)
        check("... whose codes work, while card 02's batch is untouched",
              all(auth.auth_passcode(n, c[0], "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "allow"
                  for n, c in fresh.items() if n != "avery.kim")
              and card_codes(h.handout()["l5-acme-02"]) == kept02)
        rc, out = h.run("status")
        check("status: card 01 is OK again", _row(out, "OK", "instance 01") and rc == 0, out)
        rc, out = h.run("down")
        rc, out = h.run("up")
        check("a full down then up: every card gets a fresh batch",
              rc == 0 and sum(1 for line in out.splitlines() if "`lab5-setup down` revoked its codes" in line) == 2,
              out)


def test_bypass_unreadable_record() -> None:
    print("== a participant record that cannot be read fails that card in down, never the run, never 'all deleted' ==")
    for name, damage in (("truncated", lambda path: path.write_text(path.read_text()[:40])),
                         ("a JSON array", lambda path: path.write_text("[]")),
                         ("unreadable (mode 000)", lambda path: os.chmod(path, 0))):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            rc, out = h.run("up")
            codes02 = card_codes(h.handout()["l5-acme-02"])
            path = h.root / "workshops" / "acme" / "participants" / "01.json"
            damage(path)
            try:
                rc, out = h.run("down")
            except Exception as exc:  # noqa: BLE001
                rc, out = -1, f"raised {type(exc).__name__}: {exc}"
            finally:
                os.chmod(path, 0o600)
            auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
            check(f"[{name}] down finishes: card 01 FAILs, card 02's codes are deleted, RESULT printed (exit 1)",
                  rc == 1 and _row(out, "FAIL", "instance 01") and "RESULT: down:" in out
                  and "persona bypass codes not deleted on 1 card(s) (instance 01)" in out
                  and all(auth.auth_passcode(n, c[0], "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "deny"
                          for n, c in codes02.items()), out)
            check(f"[{name}] ... and down never says every batch was deleted: it names the record it cannot read",
                  "every batch these cards had is deleted" not in out
                  and "the participant record of instance 01 cannot be read" in out, out)


def test_bypass_odd_record() -> None:
    print("== a participant record holding a batch this tool did not write: down reports it, never a traceback ==")
    import json
    for name, bad in (("ids that is a number", {"persona": "avery.kim", "user_id": "U1", "ids": 5}),
                      ("an entry that is a string", "DU1")):
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            rc, out = h.run("up")
            codes = card_codes(h.handout()["l5-acme-01"])
            path = h.root / "workshops" / "acme" / "participants" / "01.json"
            rec = json.loads(path.read_text())
            rec["bypass_batches"].insert(0, dict(rec["bypass_batches"][0], id="hand-edited", codes=[bad]))
            path.write_text(json.dumps(rec))
            try:
                rc, out = h.run("down")
            except Exception as exc:  # noqa: BLE001
                rc, out = -1, f"raised {type(exc).__name__}: {exc}"
            auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
            check(f"[{name}] down finishes (exit 1): the odd batch is named for fixing, the card's real batch is "
                  "still deleted",
                  rc == 1 and "RESULT: down:" in out and "which this tool did not write" in out
                  and f"fix {path}" in out
                  and all(auth.auth_passcode(n, c[0], "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "deny"
                          for n, c in codes.items()), out)
            check(f"[{name}] ... and down never says every batch was deleted",
                  "every batch these cards had is deleted" not in out
                  and "the participant record of instance 01 cannot be read" in out, out)


def test_victim_clash_codes_and_handouts() -> None:
    print("== another workshop still holding the victim: handouts refuses it too, and codes a swap left count ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        rc, out = h.run("up")
        other = Path(tmp) / "globex"
        other.mkdir()
        (other / "workshop.yaml").write_text(YAML.replace("workshop: acme", "workshop: globex")
                                             .replace("198.51.100.", "203.0.113."))

        def globex(command: str) -> Tuple[int, str]:
            out_io = io.StringIO()
            h.world.prompts.clear()
            return ls.main([command, str(other / "workshop.yaml")], deps=h.deps(out_io)), out_io.getvalue()

        posts = len(bypass_posts(h))
        rc, out = globex("handouts")
        check("globex handouts with acme's victim: refused (exit 2) before any Duo call, no code issued",
              rc == 2 and "room.victim avery.kim is still in use by workshop acme" in out
              and "room.fallback" in out and len(bypass_posts(h)) == posts, out)
        (Path(tmp) / "workshop.yaml").write_text(YAML.replace("  victim: avery.kim\n", "  victim: jordan.reyes\n")
                                                 .replace("  fallback: jordan.reyes\n", "  fallback: casey.wong\n"))
        rc, out = h.run("up")
        check("acme swaps to jordan.reyes on every box and card", rc == 0, out)
        rc, out = globex("check")
        check("...globex is still refused avery.kim: Duo holds the codes acme's old cards carried, and down can "
              "delete them (or they expire)",
              rc == 2 and "Duo still holds bypass codes for avery.kim from its cards" in out
              and "run `lab5-setup down` with acme's workshop file first, or wait until" in out
              and "still admit" not in out, out)
        rc, out = h.run("down")
        rc, out = globex("handouts")
        check("once acme has run down (its boxes gone, the recorded codes deleted), globex may take avery.kim",
              "is still in use by workshop" not in out, out)


def test_bypass_valid_until_after_creates() -> None:
    print("== a card's time is taken after its last create: never earlier than a code's own expiry ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        start = h.clock()
        h.duo.bypass_hooks.append(lambda uid: h.clock.sleep(20.0))      # every create takes 20 s
        rc, out = h.run("up")
        made = [c for cs in h.duo.bypass.values() for c in cs]
        rows = h.handout()
        untils = {r["instance"]: lp.parse_time(r["bypass_valid_until"]) for r in rows.values()}
        recorded = {nn: lp.parse_time(record(h, nn)["bypass_batches"][-1]["valid_until"]) for nn in ("01", "02")}
        own = {r["instance"]: max(c["expiration"] for c in made
                                  if c["code"] in {x for codes in card_codes(r).values() for x in codes})
               for r in rows.values()}
        last = max(c["expiration"] for c in made)
        check("with slow creates, each card's time (and its record's) is at or after its own codes' expiry",
              rc == 0 and len(made) == 8 and all(untils[nn] >= own[nn] for nn in own) and recorded == untils
              and untils["02"] > start + 12 * 3600 + 60, f"{untils} {own} {start}")
        h.duo.bypass_hooks.clear()
        h.duo.fail[("DELETE", "/admin/v1/bypass_codes/")] = DuoFailure(500, 50000, "Internal error")
        h.clock.t = last - 30               # past a start-of-run stamp, before the codes' own expiry
        rc, out = h.run("down")
        check("down while DELETEs fail and the codes are still live: it never says they have all expired",
              rc == 1 and any(h.duo.live_codes(n) for n in CARD_PERSONAS)
              and "every batch these cards had is deleted or has expired" not in out
              and "stay valid until" in out, out)


def test_half_made_participant() -> None:
    print("== a run stopped between creating an account and its groups: never in CII Read-Only alone, never silent ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        adds: List[str] = []

        def fail_second_add(method: str, path: str) -> None:      # the account's second group add: a 503
            if method == "POST" and re.fullmatch(r"/admin/v1/users/[^/]+/groups", path):
                adds.append(path)
                if len(adds) == 2:
                    h.duo.fail[("POST", path)] = DuoFailure(503, 50301, "Service unavailable")
        h.duo.call_hooks.append(fail_second_add)
        rc, out = h.run("up", "--only", "1")
        h.duo.call_hooks.clear()
        h.duo.fail.clear()
        user = h.duo.by_name("l5-acme-01")
        groups = {g["name"] for g in user["groups"]} if user else set()
        check("the workshop group is added first: stopped between the adds, the account is in l5-acme, never in "
              "CII Read-Only alone", rc == 1 and groups == {"l5-acme"}, f"{groups} {out}")
        h.clock.advance_days(15)
        rc, out = h.run("expire", yaml=False)
        check("...so it carries all three markers, and expire deletes it on schedule (the seat is freed)",
              rc == 0 and h.duo.by_name("l5-acme-01") is None, out)

    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.fail[("POST", "/admin/v1/users/")] = DuoFailure(503, 50301, "Service unavailable")
        real = h.duo.fail.pop(("POST", "/admin/v1/users/"))

        def fail_first_add(method: str, path: str) -> None:       # created, then every group add fails
            if method == "POST" and re.fullmatch(r"/admin/v1/users/[^/]+/groups", path):
                h.duo.fail[("POST", path)] = real
        h.duo.call_hooks.append(fail_first_add)
        rc, out = h.run("up", "--only", "1")
        h.duo.call_hooks.clear()
        h.duo.fail.clear()
        user = h.duo.by_name("l5-acme-01")
        check("an account left in no group (the first add failed)", rc == 1 and user is not None
              and not user["groups"], out)
        rc, out = h.run("status")
        row = next((line for line in out.splitlines() if line.split()[:2] == ["FAIL", "l5-acme-01"]), "")
        check("status names it half made and how to finish it", "half made" in row and "--only 1" in row, out)
        h.clock.advance_days(15)
        h.notes.clear()
        rc, out = h.run("expire", yaml=False)
        check("expire leaves it alone (it lacks a marker) but never silently: a FAIL row, exit 1, a notification",
              rc == 1 and h.duo.by_name("l5-acme-01") is not None and "half made" in out
              and h.notes and h.notes[-1][0] == "lab5-setup expire", out)
        h.clock.advance_days(-15)
        rc, out = h.run("up", "--only", "1")
        user = h.duo.by_name("l5-acme-01")
        check("a re-run of up finishes it (both groups)", rc == 0 and {g["name"] for g in user["groups"]}
              == {"l5-acme", "CII Read-Only"}, out)


def test_expire_crash_notifies() -> None:
    print("== expire, the daily job: a crash (not a Lab5Error) notifies before its traceback ==")
    with tempfile.TemporaryDirectory() as tmp:
        h = Harness(Path(tmp))
        h.duo.transport = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bug"))
        try:
            h.run("expire", yaml=False)
            raised = False
        except RuntimeError:
            raised = True
        check("a crash propagates (its traceback reaches the job's log) after a notification naming it",
              raised and h.notes and h.notes[-1][0] == "lab5-setup expire"
              and "crashed (RuntimeError)" in h.notes[-1][1], str(h.notes))


def test_docs_define_their_terms() -> None:
    print("== the runbook defines every spike, decision and plan section the docs and tools cite (the plan is not in "
          "git) ==")
    runbook = (ROOT / "docs" / "identity-lab-facilitator.md").read_text()
    try:
        terms = runbook[runbook.index("## Terms used here"):runbook.index("## Quick reference")]
    except ValueError:
        terms = ""
    defined = {t for span in re.findall(r"\*\*([^*]+)\*\*", terms) for t in re.findall(r"\b(S\d{1,2}|[AI]\d)\b", span)}
    texts = [runbook.replace(terms, ""), (ROOT / "deploy" / "lab5" / "README.md").read_text(),
             (ROOT / "docs" / "identity.md").read_text(), (ROOT / "scripts" / "identity" / "personas.yaml").read_text()]
    cited = {t for text in texts for t in re.findall(r"\b(S\d{1,2}|[AI]\d)\b", text)}
    check("every spike (S1, S7, ...) and decision (A3, I5, ...) the docs cite is defined in 'Terms used here'",
          terms and cited and cited <= defined, f"undefined: {sorted(cited - defined)}")

    # Every plan section or plan PR the docs and the Lab 5 code cite by number: "plan 2", "plan section 5",
    # "section 8", "(plan 12.5)", "PR-3", and the bare 4.2-4.6 / 12.1-12.6 the tools print.
    sources = [ROOT / "docs" / "identity.md", ROOT / "deploy" / "lab5" / "README.md",
               ROOT / "scripts" / "identity" / "personas.yaml", ROOT / "tests" / "identity_isolation.py",
               ROOT / "tests" / "run_all.sh", ROOT / "deploy" / "launchd" / "run-lab5-job.sh",
               ROOT / "deploy" / "launchd" / "install-lab5.sh", ROOT / "backend" / "agents" / "nodes" / "identity.py",
               ROOT / "backend" / "middleware" / "identity.py", ROOT / "backend" / "routers" / "identity_auth.py",
               ROOT / "tests" / "test_identity_gate.py", ROOT / "tests" / "test_duo_signin.py"]
    sources += sorted((ROOT / "deploy" / "lab5").glob("*.py")) + sorted((ROOT / "deploy" / "lab5").glob("*.yaml"))
    sources += sorted((ROOT / "scripts" / "identity").glob("*.py"))
    sources += sorted((ROOT / "backend" / "services").glob("identity_*.py"))
    explicit = re.compile(r"\bplan (?:section )?(\d+(?:\.\d+)?)\b|(?<!workshop )\bsection (\d+(?:\.\d+)?)\b"
                          r"|\b(PR-\d+)\b")
    bare = re.compile(r"\b(?:plan |section )?(4\.[2-6]|12\.[1-6])\b")
    found: Dict[str, List[str]] = {}
    for path in sources:
        text = runbook.replace(terms, "") if path.name == "identity-lab-facilitator.md" else path.read_text()
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in explicit.finditer(line):
                found.setdefault(next(g for g in match.groups() if g), []).append(
                    f"{path.relative_to(ROOT)}:{line_no}")
            for match in bare.finditer(line):
                found.setdefault(match.group(1), []).append(f"{path.relative_to(ROOT)}:{line_no}")
    for line_no, line in enumerate(runbook.replace(terms, "").splitlines(), 1):
        for match in list(explicit.finditer(line)) + list(bare.finditer(line)):
            found.setdefault(next(g for g in match.groups() if g), []).append(f"runbook:{line_no}")

    ranges = re.findall(r"\*\*([\w.-]+)\*\* to \*\*([\w.-]+):?\*\*", terms)

    def key(term):
        head, _, num = term.rpartition("-") if term.startswith("PR-") else ("", "", term)
        return head, tuple(int(x) for x in num.split("."))

    def is_defined(term: str) -> bool:
        if f"**{term}**" in terms or f"**{term}:**" in terms:
            return True
        return any(key(a)[0] == key(term)[0] and len(key(a)[1]) == len(key(term)[1]) and key(a) <= key(term) <= key(b)
                   for a, b in ranges)

    undefined = {term: where[:3] for term, where in sorted(found.items()) if not is_defined(term)}
    check("...and so is every plan section or plan PR the docs and the Lab 5 code cite, wherever and however they "
          "cite it", found and not undefined, str(undefined))
    check("...the explicit forms are read: 'plan 2', 'plan section 5', 'section 8', 'PR-3' and '(plan 12.5)'",
          [next(g for g in m.groups() if g) for m in explicit.finditer(
              "(plan 2) plan section 5, section 8; PR-3 (plan 12.5) workshop section 4.7")]
          == ["2", "5", "8", "PR-3", "12.5"])
    check("the docs say the plan is kept outside the repository, so nobody follows a link that is not there",
          "kept outside the repository" in runbook and "kept outside the repository" in texts[1])


def main() -> int:
    for test in (test_units, test_up_creates_participants, test_check_and_refusals, test_expire,
                 test_expire_after_up_cleans_the_handout, test_signin_user_access_docs,
                 test_bypass_codes_on_the_handout, test_bypass_victim_swap, test_bypass_refusals,
                 test_old_handout_gets_codes, test_bypass_persona_status, test_bypass_errors_are_per_card,
                 test_bypass_settings_change_reissues, test_bypass_revocation, test_bypass_persona_groups,
                 test_handouts_revoke_waits_for_the_new_batch, test_duo_transport_errors, test_contained_victim,
                 test_bypass_locked_out_is_temporary, test_bypass_lost_create_answer, test_signin_policy_docs,
                 test_bypass_down_then_up, test_bypass_unreadable_record, test_bypass_odd_record,
                 test_victim_clash_codes_and_handouts, test_bypass_valid_until_after_creates,
                 test_half_made_participant, test_expire_crash_notifies, test_docs_define_their_terms):
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(f"{test.__name__} raised {type(exc).__name__}", False, str(exc))
    print("== lazy imports ==")
    check("ran without importing paramiko or duo_client (the app venv has neither)",
          "paramiko" not in sys.modules and "duo_client" not in sys.modules)
    failures = tls._failures
    print(f"\n{len(failures)} failure(s)" if failures else "\nALL PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
