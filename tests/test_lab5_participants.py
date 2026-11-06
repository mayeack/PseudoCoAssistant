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
    Read-Only, and no doc or tool limits every lab app to the persona group.

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
from lab5_fakes import API_HOST, KEYCHAIN_SECRETS, PROVISIONER, Clock, DuoFailure, FakeDuo  # noqa: E402

check = tls.check
tls.SECRETS.update(KEYCHAIN_SECRETS)
DAY = 86400.0

YAML = tls.WORKSHOP_YAML.replace("participants:\n  enabled: false\n",
                                 "participants:\n  enabled: true\n  cii_url: https://ii.pseudoco.example/\n")
assert YAML != tls.WORKSHOP_YAML


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.world = tls.FakeWorld()
        self.clock = Clock(time.time())
        self.duo = FakeDuo(self.clock)
        self.notes: List[Tuple[str, str]] = []
        (tmp / "workshop.yaml").write_text(YAML)

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
    return vals


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
        check("--reissue-passcodes: one token per account still", len(h.duo.tokens) == 2)
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
    ids["persona"] = h.duo.add_user("avery.kim", notes="lab5 persona (scripts/identity/provision_personas.py); "
                                    "role=victim", groups=("PseudoCo Workforce",), created=now - 60 * DAY)["user_id"]
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
        check("day 14: both deleted with their tokens", rc == 0 and h.duo.by_name("l5-acme-01") is None
              and h.duo.by_name("l5-acme-02") is None and not h.duo.tokens, out)
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


def main() -> int:
    for test in (test_units, test_up_creates_participants, test_check_and_refusals, test_expire,
                 test_expire_after_up_cleans_the_handout, test_signin_user_access_docs):
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
