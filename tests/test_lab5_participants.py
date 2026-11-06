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
    changed, `handouts` issues a fresh one; a room persona in bypass status,
    disabled or locked out stops every card's batch in check, up and
    handouts, and status shows each persona's Duo status; a Duo error or a
    handout lock that times out fails only its card, and up still prints its
    RESULT, the handout, the password links and the reminders (exit 1, not
    2), recording a partial batch as incomplete; each batch records the ids
    that Duo lists as new around each create (none when that is ambiguous),
    `down` and `handouts --revoke` delete exactly those, and `expire` none;
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
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
        rc, out = h.run("expire", "--dry-run", yaml=False)
        check("--dry-run exits 0 and changes nothing", rc == 0 and not h.duo.mutations(), out + str(h.duo.mutations()))
        check("--dry-run lists the plan", "would disable" in out and "would delete it and its HOTP token" in out, out)

        rc, out = h.run("expire", yaml=False)
        check("expire exits 0", rc == 0, out)
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
        check("unmarked l5- accounts are reported as left alone",
              out.count("SKIP") == 4 and "it is a persona" in out and "not in group l5-acme" in out
              and "another workshop or instance" in out and "participant marker" in out, out)
        check("the run log is written", any((h.root / "runs").glob("*-expire.log")))

        rc, out2 = h.run("expire", yaml=False)
        check("a second run the same day changes nothing", rc == 0 and "CHANGED" not in out2, out2)

        h.clock.advance_days(7)
        rc, out3 = h.run("expire", yaml=False)
        check("a week later: the day-8 account (now 15 days) is deleted",
              rc == 0 and ids["day8"] not in h.duo.users, out3)
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
        check("the card says when they expire (12 h from now) and how many sign-ins each allows",
              row1["bypass_reuse"] == "5"
              and abs(lp.parse_time(row1["bypass_valid_until"]) - (h.clock() + 43200)) < 2, str(row1))
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
    print("== a room persona that is not active in Duo (bypass, disabled, locked out): no batch, each card fails ==")
    for status, said in (("bypass", "is in bypass status in Duo"), ("disabled", "is disabled in Duo"),
                         ("locked out", "is locked out in Duo")):
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
        check("a Duo error halfway through one card: that card fails, the other gets its batch, up finishes (exit 1)",
              rc == 1 and _up_finished(out) and list(cards["01"]) == CARD_PERSONAS and cards["02"] == {}
              and "persona bypass codes failed on 1 card(s) (instance 02)" in out
              and "bypass codes not issued for elena.sousa" in out, out)
        partial = record(h, "02")["bypass_batches"][-1]
        ids = [i for e in partial["codes"] for i in e["ids"]]
        check("... its partial batch is recorded as incomplete, with the ids of the 2 codes Duo did issue",
              partial["complete"] is False and partial["personas"] == ["avery.kim", "marcus.bell"] and len(ids) == 2
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
             lambda h, r: abs(lp.parse_time(r["bypass_valid_until"]) - (h.clock() + 30 * 3600)) < 2)):
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
                  and batch["untracked"] == [] and batch["complete"] is True, str(batch))
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
        check("another room's create between the listings: no id recorded for that persona, the others' are",
              rc == 0 and batch["untracked"] == ["marcus.bell"] and theirs
              and sorted(e["persona"] for e in batch["codes"]) == ["avery.kim", "elena.sousa", "grace.lin"]
              and "could not be told apart from another room's" in out, str(batch) + out)
        mine = card_codes(h.handout()["l5-acme-01"])["marcus.bell"][0]
        rc, out = h.run("down", "--only", "1")
        auth = duo.AuthAPI(h.duo.transport("auth", *tls_vpn()), API_HOST)
        check("down deletes the tracked codes and leaves the ambiguous ones to valid_secs, saying until when",
              rc == 0 and "deleted 3 bypass code(s)" in out and theirs[0] in [c["bypass_code_id"] for c in
                                                                         h.duo.live_codes("marcus.bell")]
              and auth.auth_passcode("marcus.bell", mine, "198.51.100.200", "ATTENDEE-LAPTOP")["result"] == "allow"
              and "marcus.bell: the codes of the batch issued" in out
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


def main() -> int:
    for test in (test_units, test_up_creates_participants, test_check_and_refusals, test_expire,
                 test_expire_after_up_cleans_the_handout, test_signin_user_access_docs,
                 test_bypass_codes_on_the_handout, test_bypass_victim_swap, test_bypass_refusals,
                 test_old_handout_gets_codes, test_bypass_persona_status, test_bypass_errors_are_per_card,
                 test_bypass_settings_change_reissues, test_bypass_revocation,
                 test_signin_policy_docs):
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
