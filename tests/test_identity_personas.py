"""The Lab 5 persona scripts (scripts/identity/) and launchd jobs, against fakes only.

Duo, the Keychain and CII are tests/lab5_fakes; no real Duo, CII or Keychain
item is ever read or written, and no launchd job is loaded.

What it pins (plan 4.3, 4.5, 12.4 and the secrets rule):
  * the cast is disjoint from the app's synthetic end users (ENDUSER_IDS,
    t.nguyen) and from the synthetic-PII name pools and records of all 8 themes;
  * provision_personas creates the group, users and HOTP tokens; each secret
    reaches the Keychain through `security -i` stdin, never argv; it is
    idempotent, and never touches a user without the persona marker; when it
    creates the group it says which lab apps admit it (VPN: only the group;
    Sign-in: the group and CII Read-Only, or no participant gets in);
  * baseline signs every persona in once from home with ipaddr + hostname
    (never client_supports_verified_push), with a locked counter; it does
    nothing while off and refuses documentation addresses;
  * takeover, replay, selfcheck, --reset and --teardown behave as 4.3/4.5 say;
  * the launchd templates render to valid plists that run the right commands.

Run:  .venv/bin/python tests/test_identity_personas.py
"""
from __future__ import annotations

import ast
import copy
import fcntl
import io
import json
import os
import random
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import plistlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "deploy" / "lab5"))
sys.path.insert(0, str(ROOT / "scripts" / "identity"))
sys.path.insert(0, str(ROOT))
import lab5_duo as duo  # noqa: E402
import lab5_cii as cii  # noqa: E402
import lab5_personas as lpers  # noqa: E402
from lab5_common import Keychain, Lab5Error, Redactor, file_lock  # noqa: E402
from lab5_fakes import API_HOST, CII, KEYCHAIN_SECRETS, Clock, FakeCII, FakeDuo, FakeKeychain  # noqa: E402
import cii_end_user_answers as cii_answers  # noqa: E402  (the shared table's coded errors, built as the gate's are)
import provision_personas as pp  # noqa: E402
import persona_activity as pa  # noqa: E402

_failures: List[str] = []


def check(name: str, cond: Any, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail[:1500]}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


PUBLIC = {"marcus.bell": "52.10.1.21", "elena.sousa": "52.10.1.22", "grace.lin": "52.10.1.23",
          "avery.kim": "52.10.1.31", "jordan.reyes": "52.10.1.32", "casey.wong": "52.10.1.33",
          "nina.osei": "52.10.1.41"}
FOREIGN = ["185.220.101.5", "185.220.101.6", "185.220.101.7"]


def test_cast(tmp: Path, enabled: bool = True, public: bool = True) -> Path:
    """The shipped cast with routable addresses (the real file ships
    documentation ones), the baseline switch, and one replay phone."""
    import yaml
    doc = yaml.safe_load((ROOT / "scripts" / "identity" / "personas.yaml").read_text())
    doc["baseline"]["enabled"] = enabled
    if public:
        for row in doc["personas"]:
            row["home"]["ipaddr"] = PUBLIC[row["username"]]
        for i, place in enumerate(doc["takeover"]["foreign"]):
            place["ipaddr"] = FOREIGN[i]
    for row in doc["personas"]:
        row["replay_device"] = row["username"] == "avery.kim"
    path = tmp / "personas.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    return path


class World:
    def __init__(self, tmp: Path, **cast_kw: Any) -> None:
        self.tmp = tmp
        self.clock = Clock(time.time())
        self.duo = FakeDuo(self.clock)
        self.keychain = FakeKeychain()
        self.cii = FakeCII()
        self.notes: List[Tuple[str, str]] = []
        self.cast_path = test_cast(tmp, **cast_kw)

    @property
    def root(self) -> Path:
        return self.tmp / "state"

    def pp(self, *argv: str) -> Tuple[int, str]:
        out = io.StringIO()
        deps = pp.Deps(keychain_runner=self.keychain.runner, keychain_stdin_runner=self.keychain.stdin_runner,
                       duo_transport=self.duo.transport, state_root=self.root, out=out)
        rc = pp.main([*argv, "--cast", str(self.cast_path)], deps=deps)
        return rc, out.getvalue()

    def pa(self, *argv: str) -> Tuple[int, str]:
        out = io.StringIO()
        deps = pa.Deps(keychain_runner=self.keychain.runner, keychain_stdin_runner=self.keychain.stdin_runner,
                       duo_transport=self.duo.transport, https=self.cii, state_root=self.root, out=out,
                       sleep=self.clock.sleep, now=self.clock, rng=random.Random(7),
                       notify=lambda title, msg: self.notes.append((title, msg)), lock_timeout_s=2.0)
        rc = pa.main([*argv, "--cast", str(self.cast_path)], deps=deps)
        return rc, out.getvalue()

    def auth_calls(self, path: str = "/auth/v2/auth") -> List[Dict[str, str]]:
        return [params for kind, method, p, params in self.duo.calls if p == path]

    def secrets(self) -> List[str]:
        vals = [v for k, v in KEYCHAIN_SECRETS.items() if "host" not in k and "url" not in k]
        vals += [v for k, v in self.keychain.items.items() if k.startswith("pseudoco-lab5-hotp-")]
        vals += [p["passcode"] for p in self.auth_calls() if p.get("passcode")]
        return vals

    def leaks(self) -> List[str]:
        text = "\n".join(p.read_text(errors="replace") for p in self.root.rglob("*") if p.is_file())
        argv = "\n".join(" ".join(a) for a in self.keychain.argv)
        return [s for s in self.secrets() if s in text or s in argv]


# =========================================================================== the cast
def _synthetic_pii_names() -> Tuple[set, set, set]:
    """(first/last name tokens, full names, email local parts) the app can
    put in front of a model or into an event, across all 8 themes."""
    from backend.services import ehr
    tokens, fulls, locals_ = set(), set(), set()
    for name in ehr._FIRST_NAMES + ehr._LAST_NAMES:
        tokens.add(name.lower())
    themes = sorted(ehr._RECORDS)
    for theme in themes:
        for rec in ehr._RECORDS[theme]:
            name = str(rec.fields.get("name") or "")
            fulls.add(name.lower())
            tokens.update(t.lower() for t in name.split())
            email = str(rec.fields.get("email") or "")
            if email:
                locals_.add(email.split("@")[0].lower())
    src = (ROOT / "backend" / "services" / "recommendation_engine.py").read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "SYNTHETIC_PII_PATTERNS" for t in node.targets):
            pools = ast.literal_eval(node.value)
            for profile in pools["patient_profiles"]:
                fulls.add(profile["name"].lower())
                tokens.update(t.lower() for t in profile["name"].split())
                locals_.add(profile["email"].split("@")[0].lower())
            for appt in pools.get("appointment_info", []):
                tokens.update(t.lower().strip(".") for t in appt["provider"].split() if t != "Dr.")
    return tokens, fulls, locals_, themes


def test_cast_is_disjoint() -> None:
    print("== the persona cast vs the app's synthetic users and synthetic PII (4.3) ==")
    cast = lpers.load_cast(lpers.DEFAULT_CAST)
    from backend.services.enduser_pool import ENDUSER_IDS
    pool = {u.lower() for u in ENDUSER_IDS}
    check("t.nguyen is in the synthetic end-user pool (the spray's default actor)", "t.nguyen" in pool)
    tokens, fulls, locals_, themes = _synthetic_pii_names()
    check("the synthetic-PII records cover all 8 themes", len(themes) == 8, str(themes))
    check("the name pools were found (EHR pools, records, SYNTHETIC_PII_PATTERNS)",
          {"mara", "delgado", "priya", "raman", "jennifer", "martinez"} <= tokens, str(sorted(tokens)[:20]))
    for p in cast.personas:
        first, last = p.first.lower(), p.last.lower()
        forms = {p.username, f"{first[0]}{last}", f"{first[0]}.{last}", f"{first}{last}", f"{first}.{last}"}
        check(f"{p.username}: not an ENDUSER_IDS user (nor {first[0]}{last} / {first[0]}.{last})",
              not forms & pool and p.username != "t.nguyen", str(forms & pool))
        check(f"{p.username}: neither name is in a synthetic-PII name pool or record",
              first not in tokens and last not in tokens, f"{first} {last}")
        check(f"{p.username}: not a synthetic-PII record's full name or email",
              p.name.lower() not in fulls and p.username not in locals_ and f"{first}{last}" not in locals_)
        check(f"{p.username}: email on pseudocoassistant.com, never an l5- name",
              cast.email(p).endswith("@pseudocoassistant.com") and not p.username.startswith("l5-"))
    check("the dropped Oct 30 names would have been caught", "priya" in tokens and "haddad" in tokens)
    check("the shipped cast: 3 trusted, victims, one spike persona, baseline off until the spike",
          len(cast.with_role("trusted")) == 3 and len(cast.with_role("victim")) >= 2
          and len(cast.with_role("spike")) == 1 and not cast.baseline_enabled)
    shipped = [p.home for p in cast.personas] + cast.foreign
    refused = 0
    for place in shipped:
        try:
            lpers.require_public(place, "x")
        except Lab5Error:
            refused += 1
    check("the shipped addresses are documentation ones, refused for real sign-ins until S1",
          refused == len(shipped), f"{refused}/{len(shipped)}")


def test_cast_validation() -> None:
    print("== personas.yaml validation ==")
    import yaml
    good = yaml.safe_load((ROOT / "scripts" / "identity" / "personas.yaml").read_text())
    bad_cases = [
        (lambda d: d["personas"].append(dict(d["personas"][0])), "duplicate username"),
        (lambda d: d["personas"][0].update(username="l5-acme-01"), "an l5- name"),
        (lambda d: d["personas"][0].update(role="admin"), "unknown role"),
        (lambda d: d["takeover"].update(attempts=[5, 10]), "attempts reaching the lockout limit"),
        (lambda d: d["takeover"].update(attempts=[3, 6]), "attempts under MFA Flood's 5"),
        (lambda d: d["takeover"].update(spacing_seconds=30), "failures outside 2 minutes"),
        (lambda d: d["replay"].update(pushes=12), "too many pushes"),
        (lambda d: [r.update(replay_device=True) for r in d["personas"][3:5]], "two replay phones"),
        (lambda d: d["hotp"].update(secret_encoding="base64"), "unknown secret encoding"),
    ]
    for mutate, why in bad_cases:
        doc = yaml.safe_load(yaml.safe_dump(good))
        mutate(doc)
        try:
            lpers.cast_from_dict(doc)
            ok = False
        except Lab5Error:
            ok = True
        check(f"refused: {why}", ok)


# =========================================================================== keychain
def test_keychain_store() -> None:
    print("== Keychain writes go through `security -i` stdin, never argv ==")
    kc = FakeKeychain({})
    k = Keychain(Redactor(), kc.runner, stdin_runner=kc.stdin_runner, account="lab")
    k.store("pseudoco-lab5-hotp-test", "00ff" * 10)
    check("stored and read back", kc.items.get("pseudoco-lab5-hotp-test") == "00ff" * 10)
    check("the value is never in argv", all("00ff" * 10 not in " ".join(a) for a in kc.argv), str(kc.argv))
    check("the value went on stdin", any("00ff" * 10 in s for s in kc.stdin))
    try:
        k.store("pseudoco-lab5-hotp-test", "has space; delete-generic-password")
        ok = False
    except Lab5Error as exc:
        ok = "quoting" in str(exc) and "delete-generic" not in str(exc)
    check("a value that would need quoting is refused, and not echoed", ok)
    check("delete removes the item", k.delete("pseudoco-lab5-hotp-test") and "pseudoco-lab5-hotp-test" not in kc.items)


# =========================================================================== provision
def test_provision() -> None:
    print("== provision_personas: group, users, HOTP tokens; idempotent; never a foreign user ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = World(Path(tmp))
        rc, out = w.pp("--dry-run")
        check("--dry-run exits 0 and changes nothing",
              rc == 0 and not w.duo.mutations() and not w.keychain.stdin, out)
        check("--dry-run plans the group and prints the User access it needs",
              "PLAN     group" in out and "PseudoCo Lab: Sign-in admits PseudoCo Workforce and CII Read-Only" in out, out)
        squatter = w.duo.add_user("casey.wong", notes="someone else's account")
        rc, out = w.pp()
        check("provision exits 1 because of the foreign casey.wong", rc == 1 and "left alone" in out, out)
        check("... which is untouched", w.duo.users[squatter["user_id"]]["notes"] == "someone else's account"
              and not w.duo.users[squatter["user_id"]]["tokens"] and not w.duo.users[squatter["user_id"]]["groups"])
        cast = lpers.load_cast(w.cast_path)
        check("group PseudoCo Workforce created", any(g["name"] == "PseudoCo Workforce" for g in w.duo.groups.values()))
        check("creating it says which lab apps admit whom: VPN only the cast, Sign-in the cast and the participants",
              "created PseudoCo Workforce" in out and "PseudoCo VPN admits only PseudoCo Workforce" in out
              and "PseudoCo Lab: Sign-in admits PseudoCo Workforce and CII Read-Only" in out
              and "every lab app" not in out, out)
        for p in cast.personas:
            if p.username == "casey.wong":
                continue
            user = w.duo.by_name(p.username)
            ok = (user and lpers.is_persona_notes(user["notes"]) and user["email"] == cast.email(p)
                  and user["firstname"] == p.first and user["lastname"] == p.last
                  and {g["name"] for g in user["groups"]} == {"PseudoCo Workforce"} and len(user["tokens"]) == 1)
            check(f"{p.username}: user, marker, email, names, group, one token", ok, str(user))
            token = w.duo.tokens[user["tokens"][0]] if user and user["tokens"] else {}
            item = cast.keychain_item(p)
            check(f"{p.username}: token serial and Keychain secret match what Duo holds",
                  token.get("serial") == cast.token_serial(p) and w.keychain.items.get(item) == token.get("secret_text")
                  and re.fullmatch(r"[0-9a-f]{40}", w.keychain.items.get(item, "")))
            counter = lpers.PersonaState(w.root).counter(p.username)
            check(f"{p.username}: counter file at 0", counter and counter["next"] == 0)
        hotp_dir = w.root / "personas" / "hotp"
        check("counter files 0600 in a 0700 directory",
              stat.S_IMODE(hotp_dir.stat().st_mode) == 0o700
              and all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in hotp_dir.iterdir()))
        before = len(w.duo.mutations())
        rc, out = w.pp("--only", "marcus.bell,avery.kim")
        check("a second run changes nothing", rc == 0 and len(w.duo.mutations()) == before and "CHANGED" not in out, out)
        check("no secret in argv, output, run logs or state", not w.leaks() and not any(s in out for s in w.secrets()),
              str(w.leaks()))


# =========================================================================== baseline
def provisioned(tmp: Path, **kw: Any) -> World:
    w = World(tmp, **kw)
    rc, out = w.pp()
    assert rc == 0, out
    return w


def test_baseline() -> None:
    print("== baseline: one sign-in per persona from home, then the self-check ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp), enabled=False)
        calls = len(w.duo.calls)
        rc, out = w.pa("baseline")
        check("baseline off: exits 0, says so, sends nothing", rc == 0 and "off in personas.yaml" in out
              and len(w.duo.calls) == calls, out)
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp), public=False)
        calls = len(w.duo.calls)
        rc, out = w.pa("baseline")
        check("documentation addresses: refused before any sign-in", rc == 2 and "not a public address" in out
              and len(w.duo.calls) == calls, out)
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        cast = lpers.load_cast(w.cast_path)
        for p in cast.personas:
            w.cii.users[cast.email(p)] = {"trust": "NEUTRAL" if p.role == "trusted" else "UNKNOWN"}
        rc, out = w.pa("baseline")
        auths = w.auth_calls()
        check("baseline exits 0 with every persona signed in", rc == 0 and out.count(": allow (allow)") == 7, out)
        check("one passcode sign-in per persona", sorted(a["username"] for a in auths) == sorted(cast.usernames))
        check("each from its home address and device, never verified-push",
              all(a["ipaddr"] == cast.get(a["username"]).home.ipaddr
                  and a["hostname"] == cast.get(a["username"]).home.hostname
                  and "client_supports_verified_push" not in a for a in auths))
        state = lpers.PersonaState(w.root)
        check("each counter moved to 1", all(state.counter(u)["next"] == 1 for u in cast.usernames))
        check("last.json records each success", all(state.last()[u].get("last_success") for u in cast.usernames))
        check("a run record is written", len(state.records("runs")) == 1)
        offsets = w.clock.slept
        check("jitter: the sign-ins spread within the window", sum(offsets) <= 40 * 60 and len(offsets) >= 1,
              str(offsets))
        check("the self-check ran after it, quietly", "selfcheck:" in out and not w.notes, out)
        rc, out = w.pa("baseline", "--only", "grace.lin", "--jitter-minutes", "0")
        check("a second day: the next counter value, accepted", rc == 0 and state.counter("grace.lin")["next"] == 2, out)
        check("no secret in output, argv, logs or state", not w.leaks() and not any(s in out for s in w.secrets()),
              str(w.leaks()))
        # a counter Duo is ahead of: denied, recorded, notified; never retried
        tok = next(t for t in w.duo.tokens.values() if t["serial"] == "pseudoco-persona-elena.sousa")
        tok["counter"] += 50
        n = len(w.auth_calls())
        rc, out = w.pa("baseline", "--only", "elena.sousa", "--jitter-minutes", "0")
        check("a rejected passcode: exit 1, one attempt only (no retry spraying), a notification",
              rc == 1 and len(w.auth_calls()) == n + 1 and w.notes, out)


def test_counter_lock() -> None:
    print("== the HOTP counter: one value per reservation, across threads ==")
    with tempfile.TemporaryDirectory() as tmp:
        state = lpers.PersonaState(Path(tmp))
        state.init_counter("grace.lin", "DH1", 0)
        got: List[int] = []
        lock = threading.Lock()

        def take() -> None:
            for _ in range(10):
                value = state.reserve("grace.lin")
                with lock:
                    got.append(value)

        threads = [threading.Thread(target=take) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("80 reservations, 80 distinct values, nothing skipped", sorted(got) == list(range(80)), str(sorted(got)[:10]))
        check("reserve(3) hands out three consecutive values", state.reserve("grace.lin", 3) == 80
              and state.counter("grace.lin")["next"] == 83)


# =========================================================================== takeover
def test_takeover() -> None:
    print("== takeover: home success, 5-9 wrong passcodes in 2 min from abroad, then a success there ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        cast = lpers.load_cast(w.cast_path)
        rc, out = w.pa("takeover", "--victim", "grace.lin")
        check("a trusted persona is refused", rc == 2 and "trusted persona" in out, out)
        n = len(w.duo.calls)
        rc, out = w.pa("takeover", "--victim", "avery.kim", "--dry-run")
        check("--dry-run sends nothing", rc == 0 and len(w.duo.calls) == n, out)
        w.clock.slept.clear()
        # The counter the wrong passcodes are drawn against: the one after step 1's sign-in.
        counter = int((lpers.PersonaState(w.root).counter("avery.kim") or {}).get("next", 0)) + 1
        rc, out = w.pa("takeover", "--victim", "avery.kim")
        check("takeover exits 0", rc == 0, out)
        auths = [a for a in w.auth_calls() if a["username"] == "avery.kim"]
        home, foreign = cast.get("avery.kim").home, cast.foreign[0]
        wrong = auths[1:-1]
        check("step 1: a success from home", auths[0]["ipaddr"] == home.ipaddr and auths[0]["hostname"] == home.hostname)
        check("step 2: 5-9 wrong passcodes, all from the foreign address and device",
              5 <= len(wrong) <= 9 and all(a["ipaddr"] == foreign.ipaddr and a["hostname"] == foreign.hostname
                                            for a in wrong), str(len(wrong)))
        secret = w.duo.token_secret("pseudoco-persona-avery.kim")
        # wrong_passcode keeps clear of every code within 200 counters either side
        # (wider than Duo's look-ahead); an older code is no risk, since Duo never
        # accepts a counter it has passed. A fixed 0..299 here matched a code from
        # outside that window about once in 1500 runs.
        valid = {duo.hotp(secret, c) for c in range(max(0, counter - 200), counter + 200)}
        check("the wrong passcodes are never a valid code within 200 counters of the persona's (wider than Duo's "
              "look-ahead)", all(a["passcode"] not in valid for a in wrong), f"counter {counter}")
        check("they fit in MFA Flood's 2 minutes", sum(w.clock.slept[:len(wrong) - 1]) < 120, str(w.clock.slept))
        steps = lpers.PersonaState(w.root).records("takeovers")[-1]["steps"]
        check("step 3: a success from the same foreign address and device",
              auths[-1]["ipaddr"] == foreign.ipaddr and auths[-1]["hostname"] == foreign.hostname
              and steps[0]["result"] == "allow" and steps[-1]["result"] == "allow"
              and all(st["result"] == "deny" for st in steps[1:-1]), str(steps))
        check("never locked out", w.duo.by_name("avery.kim")["status"] == "active")
        recs = lpers.PersonaState(w.root).records("takeovers")
        check("a takeover record with every step's time (the S1 backfill's takeover time)",
              len(recs) == 1 and recs[0]["ok"] and recs[0]["victim"] == "avery.kim"
              and len(recs[0]["steps"]) == len(auths) and all(s["at"] for s in recs[0]["steps"]), str(recs))
        check("it prints the Collect Now step and leaves the S1 path open", "Collect Now" in out and "S1" in out, out)
        rc, out = w.pa("takeover", "--victim", "avery.kim")
        check("a second takeover within 8 days is refused", rc == 2 and "days ago" in out, out)
        rc, out = w.pa("takeover", "--victim", "avery.kim", "--force")
        last = [a for a in w.auth_calls() if a["username"] == "avery.kim"][-1]
        check("--force allows it, from the next foreign address", rc == 0 and last["ipaddr"] == cast.foreign[1].ipaddr, out)
        w.duo.by_name("jordan.reyes")["status"] = "locked out"
        n = len(w.auth_calls())
        rc, out = w.pa("takeover", "--victim", "jordan.reyes")
        check("a locked-out victim: refused at preauth, nothing sent", rc == 2 and len(w.auth_calls()) == n, out)


def test_replay() -> None:
    print("== replay: a short push flood the facilitator denies ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        rc, out = w.pa("replay", "--victim", "jordan.reyes")
        check("a victim without the replay phone is refused", rc == 2 and "replay_device" in out, out)
        w.duo.by_name("avery.kim")["phone"] = True
        rc, out = w.pa("replay", "--victim", "avery.kim", "--pushes", "3")
        pushes = [a for a in w.auth_calls() if a.get("factor") == "push"]
        check("3 pushes, all denied: exit 0", rc == 0 and len(pushes) == 3 and out.count("deny") >= 3, out)
        check("pushes carry ipaddr and hostname, async", all(p["ipaddr"] and p["hostname"] and p["async"] == "1"
                                                             for p in pushes))
        w.duo.push_answer = "allow"
        rc, out = w.pa("replay", "--victim", "avery.kim", "--pushes", "1")
        check("an approved push is flagged: exit 1", rc == 1 and "APPROVED" in out, out)
        rc, out = w.pa("replay", "--victim", "avery.kim", "--pushes", "12")
        check("more than 9 pushes is refused", rc == 2, out)


# =========================================================================== selfcheck
def test_selfcheck() -> None:
    print("== selfcheck: sign-ins, HOTP state, Duo, CII trust; notifies on problems ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        cast = lpers.load_cast(w.cast_path)
        for p in cast.personas:
            w.cii.users[cast.email(p)] = {"trust": "NEUTRAL"}
        rc, out = w.pa("baseline", "--jitter-minutes", "0")
        check("all well: exit 0, no notification", rc == 0 and not w.notes, out)
        w.cii.users["marcus.bell@pseudocoassistant.com"] = {"trust": "QUESTIONABLE", "failing": ["MFA Flood"]}
        w.cii.users["casey.wong@pseudocoassistant.com"] = {"trust": "UNKNOWN"}
        rc, out = w.pa("selfcheck")
        check("a trusted persona failing a check: FAIL, exit 1, a notification",
              rc == 1 and "marcus.bell" in out and "MFA Flood" in out and w.notes, out)
        check("a victim still Unknown is only a warning", "WARN     casey.wong" in out, out)
        rc, out = w.pa("selfcheck", "--gate", "--only", "casey.wong")
        check("--gate (T-18): Unknown fails", rc == 1 and "FAIL     casey.wong" in out, out)
        w.cii.shape = "objects"
        rc, out = w.pa("selfcheck", "--only", "marcus.bell", "--no-notify")
        check("trust and checks as objects parse the same", "MFA Flood" in out and "QUESTIONABLE" in out, out)
        w.cii.graphql_error = "Field 'failingChecks' must have a selection of subfields"
        rc, out = w.pa("selfcheck", "--only", "grace.lin", "--no-notify")
        check("a query the schema rejects: a warning naming cii.end_user_query",
              rc == 0 and "cii.end_user_query" in out, out)
        w.cii.graphql_error = ""
        w.duo.by_name("jordan.reyes")["status"] = "locked out"
        rc, out = w.pa("selfcheck", "--only", "jordan.reyes", "--no-notify")
        check("a locked-out persona fails (preauth)", rc == 1 and "preauth" in out and "--reset" in out, out)
        w.clock.advance_days(4)
        rc, out = w.pa("selfcheck", "--only", "grace.lin", "--no-notify")
        check("no sign-in for 4 days: FAIL (is the launchd job running?)", rc == 1 and "launchd" in out, out)
        for item in ("pseudoco-lab5-cii-client-id",):
            w.keychain.items.pop(item)
        w.clock.t -= 4 * 86400
        rc, out = w.pa("selfcheck", "--only", "grace.lin", "--no-notify")
        check("CII keys missing: a warning, not a failure", rc == 0 and "trust not checked" in out, out)
        rc, out = w.pa("selfcheck", "--gate", "--only", "grace.lin", "--no-notify")
        check("... but a failure at the T-18 gate", rc == 1, out)
        latest = lpers.PersonaState(w.root).records("selfcheck")
        check("the latest self-check is recorded", latest and latest[-1]["rows"])
        check("no secret anywhere", not w.leaks(), str(w.leaks()))


# =========================================================================== reset / teardown
def test_reset_and_teardown() -> None:
    print("== --reset re-enables and resyncs; --teardown needs --yes and keeps the group ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        user = w.duo.by_name("jordan.reyes")
        user["status"] = "locked out"
        tok = next(t for t in w.duo.tokens.values() if t["serial"] == "pseudoco-persona-jordan.reyes")
        state = lpers.PersonaState(w.root)
        for _ in range(30):                        # the Mac ran ahead (codes Duo never saw)
            state.reserve("jordan.reyes")
        rc, out = w.pp("--reset", "--only", "jordan.reyes")
        check("--reset exits 0", rc == 0, out)
        check("locked out -> active", user["status"] == "active")
        check("the token is resynced to the Mac's counter (3 codes)", tok["counter"] == 33
              and state.counter("jordan.reyes")["next"] == 33, str(tok["counter"]))
        check("it reminds about step-ups and CII feedback (no API)", "Clear all step-ups" in out, out)
        rc, out = w.pa("baseline", "--only", "jordan.reyes", "--jitter-minutes", "0", "--no-selfcheck")
        check("the next sign-in is accepted", rc == 0, out)

        squatter = w.duo.add_user("someone.else", notes="not a persona")
        users_before, tokens_before = len(w.duo.users), len(w.duo.tokens)
        rc, out = w.pp("--teardown")
        check("--teardown without --yes: exit 1, nothing deleted",
              rc == 1 and len(w.duo.users) == users_before and len(w.duo.tokens) == tokens_before
              and "--yes" in out, out)
        rc, out = w.pp("--teardown", "--yes")
        cast = lpers.load_cast(w.cast_path)
        check("--teardown --yes: the cast's users and tokens are gone", rc == 0
              and not any(w.duo.by_name(u) for u in cast.usernames) and not w.duo.tokens, out)
        check("its Keychain secrets and counters are gone",
              not any(k.startswith("pseudoco-lab5-hotp-") for k in w.keychain.items)
              and not any((w.root / "personas" / "hotp").glob("*.json")))
        check("the group stays (the User access of the VPN and Sign-in apps names it)",
              any(g["name"] == "PseudoCo Workforce" for g in w.duo.groups.values()) and "kept" in out
              and "PseudoCo Lab: Sign-in" in out and "every lab app" not in out, out)
        check("a user outside the cast is untouched", w.duo.users.get(squatter["user_id"]) is not None)
        check("Keychain deletes name the item only", all(len(a) <= 6 for a in w.keychain.argv
                                                           if a[1:2] == ["delete-generic-password"]))


# =========================================================================== CII client
def test_cii_client() -> None:
    print("== CII client: client-credentials token in a JSON body, Bearer on the query ==")
    fake = FakeCII()
    fake.users["a@pseudocoassistant.com"] = {"trust": "neutral", "failing": ["Impossible Travel", "MFA Flood"]}
    client = cii.CIIClient(CII["client_id"], CII["client_secret"], CII["token_url"], CII["api_url"], fake)
    info = client.end_user("a@pseudocoassistant.com")
    client.end_user("b@pseudocoassistant.com")
    check("trust upper-cased, checks sorted", info == {"trust": "NEUTRAL", "found": True,
                                                       "failing_checks": ["Impossible Travel", "MFA Flood"]}, str(info))
    check("the token is fetched once per run", fake.token_requests == 1)
    check("the secret goes only in the token request's JSON body",
          all(CII["client_secret"] not in " ".join(h.values()) and CII["client_secret"] not in url
              for _, url, h, _ in fake.calls)
          and sum(CII["client_secret"] in str(body) for *_, body in fake.calls) == 1)
    check("a user CII does not know yet", client.end_user("b@pseudocoassistant.com")["found"] is False)

    # The published schema (docs.oort.io): getEndUser(login) -> endUserDetails
    # { failingChecks, endUserTrustScore { levelOfTrust } }. The app's gate asks
    # exactly that; the self-check must read what the gate reads.
    app_src = (ROOT / "backend" / "services" / "identity_lookup.py").read_text()
    app_query = next(ast.literal_eval(node.value) for node in ast.walk(ast.parse(app_src))
                     if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "CII_END_USER_QUERY"
                                                             for t in node.targets))

    def selection(query: str) -> str:
        text = " ".join(query.split())
        return text[text.index("getEndUser("):]

    check("the default query asks what the app's gate asks (getEndUser -> endUserDetails), operation name aside",
          selection(cii.END_USER_QUERY) == selection(app_query), f"{cii.END_USER_QUERY!r} vs {app_query!r}")

    # CII's "no such user" is one rule in two copies (the Mac's tool cannot
    # import the app). Pin them together: the rule's code, modulo names, so a
    # one-sided edit fails here even where the shared answers below do not
    # reach it. The rule reads no constant: it is the answer's shape alone.
    app_tree, mac_tree = ast.parse(app_src), ast.parse((ROOT / "deploy" / "lab5" / "lab5_cii.py").read_text())

    def function(tree, name):
        return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)

    def canonical(fn):
        """The function's body without its docstring, every name renamed by
        first use (so Mapping/dict and each side's own names compare equal)."""
        body = fn.body[1:] if (fn.body and isinstance(fn.body[0], ast.Expr)
                               and isinstance(fn.body[0].value, ast.Constant)) else fn.body
        names: Dict[str, str] = {}
        for a in fn.args.args:
            names.setdefault(a.arg, f"v{len(names)}")

        class Rename(ast.NodeTransformer):
            def visit_Name(self, node):
                return ast.Name(id=names.setdefault(node.id, f"v{len(names)}"), ctx=node.ctx)

        return ast.dump(ast.Module(body=[Rename().visit(copy.deepcopy(s)) for s in body], type_ignores=[]))

    pins = [
        ("the rule's code (_cii_not_found / not_found)", canonical(function(app_tree, "_cii_not_found")),
         canonical(function(mac_tree, "not_found"))),
    ]
    for what, app_value, mac_value in pins:
        check(f"CII 'no such user', {what}: the self-check's copy is the gate's (identity_lookup)",
              app_value == mac_value, f"{app_value!r} vs {mac_value!r}"[:400])

    # The pin above keeps the two copies the same; these keep them right for
    # every answer, not only for those the shared table lists (no table lists
    # every message or code a rule could key on). Each copy's first statement
    # returns False for an answer that carries an error, before anything else
    # reads it, so no rule after it, whatever it reads, makes an error "no
    # such user". The parsers make that answer only under the rule (the
    # gate's NOT_FOUND in _cii_parse's first statement, the Mac's found False
    # in parse_end_user's), and the checks after these pin the path to it.
    def docless(fn):
        return fn.body[1:] if (fn.body and isinstance(fn.body[0], ast.Expr)
                               and isinstance(fn.body[0].value, ast.Constant)
                               and isinstance(fn.body[0].value.value, str)) else fn.body

    def lone_return(node):
        """``node`` is an ``if`` with no else whose body is one return."""
        return (isinstance(node, ast.If) and not node.orelse and len(node.body) == 1
                and isinstance(node.body[0], ast.Return))

    def turns_away_errors(fn, exact):
        """fn starts with `if <exact>(<answer>): return True` (CII's own answer
        for a login it has no record of, matched exactly), and then with
        `if ... or <answer>.get("errors") not in (None, []) or ...: return
        False`: every other answer that carries an error is turned away there."""
        body = docless(fn)
        arg = fn.args.args[0].arg if fn.args.args else None
        if not arg or len(body) < 2 or not lone_return(body[0]) or not lone_return(body[1]):
            return False
        call, first_value, guard_value = body[0].test, body[0].body[0].value, body[1].body[0].value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == exact
                and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Name)
                and call.args[0].id == arg and isinstance(first_value, ast.Constant) and first_value.value is True
                and isinstance(guard_value, ast.Constant) and guard_value.value is False):
            return False
        test = body[1].test
        guard = ast.dump(ast.parse(f'{arg}.get("errors") not in (None, [])', mode="eval").body)
        return any(ast.dump(operand) == guard for operand in
                   (test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or) else [test]))

    def first_under(fn, rule):
        """fn's first statement when it is `if <rule>(<answer>): return ...`
        with no else, else None."""
        body = docless(fn)
        first = body[0] if body else None
        call = first.test if lone_return(first) else None
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == rule
                and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Name)
                and fn.args.args and call.args[0].id == fn.args.args[0].arg):
            return first
        return None

    def module_bindings(tree, name):
        """Where the module binds ``name``: a def or class, an assignment,
        an import, a loop, with, walrus or except target, anywhere in its own
        scope (its blocks included, function and class bodies not), and in a
        function that declares the name global. A decorator on the def counts
        too, since it rebinds the name to what it returns."""
        found = []

        def visit(node, in_scope):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if in_scope and child.name == name:
                        found.append(child)
                        found.extend(child.decorator_list)
                    if isinstance(child, ast.ClassDef):
                        visit(child, False)
                    else:
                        visit(child, any(isinstance(n, ast.Global) and name in n.names for n in ast.walk(child)))
                elif in_scope and isinstance(child, ast.Name) and child.id == name and not isinstance(child.ctx, ast.Load):
                    found.append(child)
                elif in_scope and isinstance(child, ast.alias) and (child.asname or child.name.split(".")[0]) == name:
                    found.append(child)
                elif in_scope and isinstance(child, ast.ExceptHandler) and child.name == name:
                    found.append(child)
                    visit(child, in_scope)
                else:
                    visit(child, in_scope)

        visit(tree, True)
        return found

    def bound_once(tree, name):
        """'' when the module binds ``name`` once, by an undecorated def at
        its top level, so nothing in it rebinds or wraps that function; else
        the lines that bind it."""
        found = module_bindings(tree, name)
        if len(found) == 1 and isinstance(found[0], ast.FunctionDef) and found[0] in tree.body:
            return ""
        return f"{name} is bound at line(s) {', '.join(str(getattr(n, 'lineno', '?')) for n in found) or 'none'}"

    # The one error that is "no such user": CII's own answer for a login it has
    # no record of (spike S5, 2026-11-06), matched exactly. Its constant is the
    # same in both copies and is the table's captured answer, each error's
    # locations aside; its matcher is the same code in both; neither is rebound.
    table = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())
    live = next(c["body"] for c in table["cases"] if c["name"].startswith(
        "CII's answer for a login it has no record of, as the live API gave it"))
    captured = {**live, "errors": [{k: v for k, v in e.items() if k != "locations"} for e in live["errors"]]}

    def constant(tree, name):
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
        return ast.literal_eval(node.value)

    exact = (("the gate's", app_tree, "_cii_not_found", "_cii_unknown_login", "CII_UNKNOWN_LOGIN_ANSWER"),
             ("the self-check's", mac_tree, "not_found", "unknown_login", "UNKNOWN_LOGIN_ANSWER"))
    check("CII 'no such user', the one error that is it: CII's own answer for a login it has no record of, the same "
          "constant in both copies and the table's live answer (spike S5), each error's locations aside; the same "
          "matcher code in both, which compares the whole answer with that constant",
          all(constant(tree, const) == captured for _, tree, _, _, const in exact)
          and canonical(function(app_tree, "_cii_unknown_login")) == canonical(function(mac_tree, "unknown_login"))
          and all(any(isinstance(n, ast.Name) and n.id == const for n in ast.walk(function(tree, matcher)))
                  for _, tree, _, matcher, const in exact)
          and all(len(module_bindings(tree, const)) == 1 and not bound_once(tree, matcher)
                  for _, tree, _, matcher, const in exact), json.dumps(captured))
    for label, tree, name, matcher, _ in exact:
        fn = function(tree, name)
        rebound = bound_once(tree, name)
        check(f"CII 'no such user', {label} copy ({name}): its first statement is the exact match ({matcher}) and "
              "its second returns False for every other answer that carries an error (errors not absent, null or "
              "[]), so no rule after them, whatever it reads, makes an error 'no such user'; and nothing in its "
              "module rebinds or wraps it",
              turns_away_errors(fn, matcher) and not rebound,
              rebound or "; ".join(ast.unparse(st) for st in docless(fn)[:2]) or f"{name} is empty")

    app_fns = {n.name: n for n in app_tree.body if isinstance(n, ast.FunctionDef)}
    under_rule = first_under(app_fns["_cii_parse"], "_cii_not_found")
    inside = {id(n) for n in ast.walk(under_rule)} if under_rule else set()
    stray = []
    for top in app_tree.body:
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)) and top.name.startswith(("_duo", "duo_")):
            continue  # Duo's own "no such user" (an empty users list), not CII's
        if isinstance(top, ast.Assign) and any(
                (isinstance(t, ast.Name) and t.id == "ANSWERED")
                or (isinstance(t, ast.Tuple) and any(isinstance(e, ast.Name) and e.id == "NOT_FOUND" for e in t.elts))
                for t in top.targets):
            continue  # the constant itself, and the states that are answers
        stray += [f"line {n.lineno}" for n in ast.walk(top) if id(n) not in inside and (
            (isinstance(n, ast.Name) and n.id == "NOT_FOUND")
            or (isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "not_found"))]
    check("the gate: CII's 'no such user' (NOT_FOUND) comes only from the rule, in _cii_parse's first statement "
          "(if _cii_not_found(body): return ...); identity_lookup names NOT_FOUND nowhere else but where it is "
          "defined, in ANSWERED and in Duo's half (_duo_*, duo_*)",
          under_rule is not None and not bound_once(app_tree, "_cii_parse") and not stray
          and any(isinstance(n, ast.Name) and n.id == "NOT_FOUND" for n in ast.walk(under_rule)),
          ", ".join(stray) or "_cii_parse does not start with `if _cii_not_found(body): return ...`")

    mac_fns = {n.name: n for n in mac_tree.body if isinstance(n, ast.FunctionDef)}
    under_copy = first_under(mac_fns["parse_end_user"], "not_found")
    inside = {id(n) for n in ast.walk(under_copy)} if under_copy else set()
    ruled, stray = [], []
    lab5_cii_path = ROOT / "deploy" / "lab5" / "lab5_cii.py"
    for path in sorted((ROOT / "deploy" / "lab5").glob("*.py")) + sorted((ROOT / "scripts" / "identity").glob("*.py")):
        tree = mac_tree if path == lab5_cii_path else ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                values = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == "found"]
            elif isinstance(node, ast.keyword) and node.arg == "found":
                values = [node.value]
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                values = [None if isinstance(node, ast.AugAssign) else node.value for t in targets
                          if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                          and t.slice.value == "found"]
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "setdefault" and node.args and isinstance(node.args[0], ast.Constant)
                  and node.args[0].value == "found"):
                values = [node.args[1] if len(node.args) > 1 else None]
            else:
                values = []
            for value in values:
                if id(node) in inside:
                    ruled.append(value)
                elif not (isinstance(value, ast.Constant) and value.value is True):
                    stray.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    check("the self-check: the one found False the Mac's tools (deploy/lab5, scripts/identity) write, in a dict, "
          "by keyword, by item assignment or setdefault, is parse_end_user's first statement, under its copy of the "
          "rule (if not_found(doc): return ...); every other found they write is True (the row itself is checked "
          "end to end in test_no_cii_failure_is_not_in_cii_yet)",
          under_copy is not None and not bound_once(mac_tree, "parse_end_user") and not stray and len(ruled) == 1
          and isinstance(ruled[0], ast.Constant) and ruled[0].value is False,
          ", ".join(stray) or "parse_end_user does not start with `if not_found(doc): return {... found: False}`")

    # What reaches the rule is CII's own answer, and nothing on the way reads
    # or rewrites it: _cii_fetch hands the parser the JSON of the response
    # _cii_query got, and the Mac's client hands parse_end_user what the
    # transport sent. (The statuses, token failures and errors those paths
    # meet are checked end to end in tests/test_identity_gate.py
    # test_no_cii_failure_is_no_such_user and test_no_cii_failure_is_not_in_cii_yet here.)
    def callee(call):
        return (call.func.id if isinstance(call.func, ast.Name)
                else call.func.attr if isinstance(call.func, ast.Attribute) else None)

    def only_from(fn, var, source):
        """Every binding of ``var`` in fn is an assignment of a call to ``source``."""
        stores = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == var and not isinstance(n.ctx, ast.Load)]
        assigns = [a for a in ast.walk(fn) if isinstance(a, ast.Assign)
                   and any(s in list(ast.walk(t)) for t in a.targets for s in stores)]
        return bool(stores) and len(assigns) == len(stores) and all(
            isinstance(a.value, ast.Call) and callee(a.value) == source for a in assigns)

    def read_once_by(fn, var, sink):
        """fn reads ``var`` once, inside a call to ``sink`` that it returns."""
        loads = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == var and isinstance(n.ctx, ast.Load)]
        sinks = [r.value for r in ast.walk(fn) if isinstance(r, ast.Return) and isinstance(r.value, ast.Call)
                 and callee(r.value) == sink]
        return len(loads) == 1 and any(loads[0] in list(ast.walk(c)) for c in sinks)

    fetch = app_fns["_cii_fetch"]
    calls = [c for c in ast.walk(fetch) if isinstance(c, ast.Call) and callee(c) == "_cii_parse"]
    check("the gate: _cii_fetch hands _cii_parse CII's answer untouched (body only from response.json(), read only "
          "as _cii_parse's argument, response only from _cii_query), so nothing before the rule rewrites it",
          len(calls) == 1 and only_from(fetch, "body", "json") and read_once_by(fetch, "body", "_cii_parse")
          and only_from(fetch, "response", "_cii_query"), ast.unparse(fetch)[-400:])

    def errors_guard_at(fn, test_src):
        """The index of fn's top-level ``if <test_src>:``, or None."""
        want = ast.dump(ast.parse(test_src, mode="eval").body)
        return next((i for i, st in enumerate(fn.body) if isinstance(st, ast.If) and ast.dump(st.test) == want), None)

    parse = app_fns["_cii_parse"]
    at = errors_guard_at(parse, f'{parse.args.args[0].arg}.get("errors") not in (None, [])')
    before = docless(parse)[1:at - (len(parse.body) - len(docless(parse)))] if at is not None else []
    early = [r for st in before for r in ast.walk(st) if isinstance(r, ast.Return)
             and not (isinstance(r.value, ast.Call) and callee(r.value) == "_unavailable")]
    guard = parse.body[at].body if at is not None else []
    keeps = (len(guard) == 1 and isinstance(guard[0], ast.Return) and isinstance(guard[0].value, ast.Dict)
             and guard[0].value.keys[:1] == [None] and isinstance(guard[0].value.values[0], ast.Call)
             and callee(guard[0].value.values[0]) == "_unavailable"
             and not any(isinstance(k, ast.Constant) and k.value == "state" for k in guard[0].value.keys))
    check("the gate: _cii_parse returns nothing but _unavailable(...) between the rule and its errors guard, and "
          "the guard answers unavailable (graphql_error), keeping only what was learned, so an answer that carries "
          "an error is never ok and never not_found there",
          at is not None and not early and keeps, ast.unparse(parse)[:600])

    end_user = next(n for n in ast.walk(mac_tree) if isinstance(n, ast.FunctionDef) and n.name == "end_user")
    post = next(n for n in ast.walk(mac_tree) if isinstance(n, ast.FunctionDef) and n.name == "_post")
    check("the self-check: CIIClient.end_user hands parse_end_user what _post returned, and _post returns the "
          "JSON of what the transport sent, both untouched, so nothing before its rule rewrites CII's answer",
          only_from(end_user, "doc", "_post") and read_once_by(end_user, "doc", "parse_end_user")
          and only_from(post, "data", "_transport") and read_once_by(post, "data", "loads"),
          ast.unparse(end_user) + " / " + ast.unparse(post)[-300:])
    mparse = mac_fns["parse_end_user"]
    at = errors_guard_at(mparse, "errors not in (None, [])")
    before = docless(mparse)[1:at - (len(mparse.body) - len(docless(mparse)))] if at is not None else []
    raises = at is not None and isinstance(mparse.body[at].body[-1], ast.Raise)
    check("the self-check: parse_end_user returns nothing between its rule and its errors guard, which raises, so "
          "an answer that carries an error is never a user's details and never 'not in CII yet' there",
          at is not None and raises and not any(isinstance(r, ast.Return) for st in before for r in ast.walk(st)),
          ast.unparse(mparse)[:600])
    fake.users["q@pseudocoassistant.com"] = {"trust": "QUESTIONABLE", "failing": ["MFA Flood"]}
    info = client.end_user("q@pseudocoassistant.com")
    check("a persona CII rates QUESTIONABLE and failing MFA Flood reads as such (the nested shape)",
          info == {"trust": "QUESTIONABLE", "failing_checks": ["MFA Flood"], "found": True}, str(info))
    flat = cii.CIIClient(CII["client_id"], CII["client_secret"], CII["token_url"], CII["api_url"], fake,
                         query="query Lab5EndUser($login: String!) { getEndUser(login: $login) "
                               "{ levelOfTrust failingChecks } }")
    try:
        flat.end_user("q@pseudocoassistant.com")
        refused = False
    except Lab5Error:
        refused = True
    check("the old flat query fails against the published schema (a Lab5Error, never a silent Unknown)", refused)
    check("FAVORABLE is a level of trust, and Neutral or better", "FAVORABLE" in cii.TRUST_LEVELS
          and set(cii.GOOD_TRUST) == {"TRUSTED", "FAVORABLE", "NEUTRAL"})
    check("failing() matches check names loosely", cii.failing(["MFA Flood"], "mfa_flood")
          and not cii.failing(["MFA Flood"], "impossible travel"))
    try:
        cii.CIIClient("i", "s", "http://plain/token", CII["api_url"], fake)
        ok = False
    except Lab5Error:
        ok = True
    check("a plain-http CII URL is refused", ok)

    # The gate (backend/services/identity_lookup._cii_parse) runs the same table
    # in tests/test_identity_gate.py: a user the gate reads as "not in CII yet"
    # is one the self-check reads that way too, and an answer the gate counts
    # as an outage is a failed query here, never "not found".
    table = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())
    for case in table["cases"]:
        try:
            got = cii.parse_end_user(case["body"])
        except Lab5Error:
            got = None
        if case["expect"] == "unavailable":
            check(f"{case['name']}: a failed query (Lab5Error)", got is None, str(got))
        elif case["expect"] == "not_found":
            check(f"{case['name']}: not in CII yet", got == {"trust": "UNKNOWN", "failing_checks": [],
                                                              "found": False}, str(got))
        else:
            check(f"{case['name']}: the user's details", got is not None and got["found"] is True
                  and got["trust"] == case["trust"] and got["failing_checks"] == sorted(case["failing"]), str(got))
    # No error is ever "not in CII yet", whatever it says, what code it
    # carries, where the code sits or in which shape it comes (the gate runs
    # the same table and shapes): every code-less message, and every error
    # that carries a code, each code in each place the table covers, on every
    # message the table holds (tests/cii_end_user_answers.py builds them for
    # both suites), so no code and no message it holds go untried together.
    shapes = table["error_shapes"]["shapes"]
    check("the shared table tries each error with data null and the error on getEndUser too (the shape the "
          "published schema gives an error there: GetEndUserOutput! is non-null)",
          any(s["data"] is None and s["path"] == ["getEndUser"] for s in shapes), str(shapes))
    for what, errors in (("code-less error message",
                          [(m, {"message": m}) for m in table["error_messages"]["messages"]]),
                         ("error that carries a code (each code in each place, alone and all at once, on every "
                          "message)", cii_answers.coded_errors(table, cii_answers.all_messages(table)))):
        misread = []
        for name, error in errors:
            for shape in shapes:
                placed = {**copy.deepcopy(error), **({"path": shape["path"]} if shape["path"] else {})}
                try:
                    got = cii.parse_end_user({"data": copy.deepcopy(shape["data"]), "errors": [placed]})
                except Lab5Error as exc:
                    got = None
                    if "never read as" not in str(exc):
                        misread.append(f"{name!r} {shape['where']}: the error does not say why ({exc})")
                if got is not None:
                    misread.append(f"{name!r} {shape['where']}: {got}")
        check(f"every {what} of the shared table ({len(errors)}), in each of its {len(shapes)} shapes (on "
              "getEndUser, on endUserDetails, on getEndUser with data null, with no path): a failed query "
              "(Lab5Error), never 'not in CII yet'", not misread, "; ".join(misread)[:600])


def test_cii_token_cache() -> None:
    print("== the Mac's CII token: one cached token, reused across runs (CII gives an API client 6 an hour) ==")
    login = "a@pseudocoassistant.com"
    fake = FakeCII()
    fake.users[login] = {"trust": "NEUTRAL"}
    kc = FakeKeychain()

    def run_keychain(f: FakeKeychain = kc, stdin_runner: Any = None) -> Keychain:
        """A fresh Keychain object per run: nothing shared in memory between runs."""
        return Keychain(Redactor(), runner=f.runner, stdin_runner=stdin_runner or f.stdin_runner)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
        kept = kc.items.get(cii.TOKEN_ITEM, "")
        check("the first run mints one token and keeps it in the Keychain as <exp>=<token>",
              fake.token_requests == 1 and kept.endswith("=cii-access-token-abcdef123456")
              and kept.split("=")[0].isdigit(), kept)
        cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
        cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
        check("two more runs reuse it: still one token request in all", fake.token_requests == 1)
        check("the token reaches the Keychain only on `security -i`'s stdin, never argv",
              all("cii-access-token-abcdef123456" not in " ".join(a) for a in kc.argv)
              and any("cii-access-token-abcdef123456" in s for s in kc.stdin))
        check("the lock lives in the state directory, owner-only",
              (root / cii.TOKEN_LOCK).exists() and stat.S_IMODE(root.stat().st_mode) == 0o700)

        kc.items[cii.TOKEN_ITEM] = f"{int(time.time()) + 60}=cii-access-token-abcdef123456"
        cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
        check("a cached token with under 10 minutes left is replaced: one new mint, kept",
              fake.token_requests == 2 and int(kc.items[cii.TOKEN_ITEM].split("=")[0]) > time.time() + 3600)

        kc.items[cii.TOKEN_ITEM] = f"{int(time.time()) + 86400}=a-token-cii-refuses"
        info = cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
        check("a cached token CII refuses (401) is dropped: one new token, the query asked once more, the new one kept",
              info["trust"] == "NEUTRAL" and fake.token_requests == 3
              and kc.items[cii.TOKEN_ITEM].endswith("=cii-access-token-abcdef123456"), str(info))

        for bad in ("garbage", "=", "123=", "soon=tok"):
            kc.items[cii.TOKEN_ITEM] = bad
            n = fake.token_requests
            cii.cii_client(run_keychain(), fake, cache_dir=root).end_user(login)
            check(f"an unreadable cached value {bad!r} is never sent: one new mint", fake.token_requests == n + 1)

        # lab5-setup pushes the cached token to the boxes only with 20 h left (TOKEN_KEEP_S).
        long_lived = (200, {"access_token": "cii-access-token-abcdef123456", "expires_in": 86400})
        fake.token_answer = long_lived
        kc.items[cii.TOKEN_ITEM] = f"{int(time.time()) + 10 * 3600}=cii-access-token-abcdef123456"
        n = fake.token_requests
        token, exp = cii.access_token(run_keychain(), fake, root, 20 * 3600)
        check("lab5-setup with a cached token of 10 h: a fresh one for the boxes, kept as the Mac's",
              fake.token_requests == n + 1 and exp > time.time() + 23 * 3600
              and kc.items[cii.TOKEN_ITEM] == f"{int(exp)}={token}")
        token2, exp2 = cii.access_token(run_keychain(), fake, root, 20 * 3600)
        check("...and the next lab5-setup run reuses it", fake.token_requests == n + 1 and (token2, exp2) == (token, exp))
        fake.token_answer = None

    with tempfile.TemporaryDirectory() as tmp:
        refusing = FakeKeychain()
        n = fake.token_requests
        info = cii.cii_client(run_keychain(refusing, lambda argv, stdin: subprocess.CompletedProcess(argv, 1, "", "")),
                              fake, cache_dir=Path(tmp)).end_user(login)
        check("a Keychain that refuses the write: the run still has its token, nothing is kept",
              info["trust"] == "NEUTRAL" and fake.token_requests == n + 1 and cii.TOKEN_ITEM not in refusing.items)

    n = fake.token_requests
    client = cii.CIIClient(CII["client_id"], CII["client_secret"], CII["token_url"], CII["api_url"], fake)
    client.end_user(login)
    client.end_user(login)
    check("without a cache directory (tests, one-off clients) nothing is read or kept: one token per client",
          fake.token_requests == n + 1)


def test_no_cii_failure_is_not_in_cii_yet() -> None:
    print("== no CII failure is ever 'not in CII yet': every error the shared table holds and every failed "
          "request, through the CII client (transport, token, _post, parse_end_user) and the self-check's row ==")
    table = json.loads((ROOT / "tests" / "fixtures" / "cii_end_user_answers.json").read_text())
    shapes = table["error_shapes"]["shapes"]
    login = "grace.lin@pseudocoassistant.com"
    no_record = {"data": {"getEndUser": {"endUserDetails": None, "providerEndUserDetails": []}}}
    record = {"data": {"getEndUser": {"endUserDetails": {"login": login, "failingChecks": [],
                                                         "endUserTrustScore": {"levelOfTrust": "NEUTRAL"}}}}}
    every_message = cii_answers.all_messages(table)
    errors = [(m, {"message": m}) for m in every_message] + cii_answers.coded_errors(table, every_message)

    def answers():
        """(name, answer, token answer): every error in every shape, then every failed request."""
        for name, error in errors:
            for shape in shapes:
                placed = {**copy.deepcopy(error), **({"path": shape["path"]} if shape["path"] else {})}
                yield (f"{name!r} {shape['where']}", (200, {"data": copy.deepcopy(shape["data"]),
                                                             "errors": [placed]}), None)

    bodies = (("no body", b""), ("CII's no-record answer", no_record),
              ("an error answer", {"errors": [{"message": "User not found"}]}), ("the user's record", record))
    failed = []
    for status in (201, 204, 301, 302, 307, 400, 401, 403, 404, 405, 408, 409, 410, 422, 429, 500, 502, 503, 504):
        for label, body in bodies:
            failed.append((f"getEndUser answered HTTP {status} with {label}", (status, body), None))
    for status in (201, 204, 301, 400, 401, 403, 404, 429, 500, 502, 503):
        for label, body in (("no body", b""), ("a token", {"access_token": "tok-x", "expires_in": 36000})):
            failed.append((f"the token endpoint answered HTTP {status} with {label}", None, (status, body)))
    failed += [("getEndUser answered 200 with a body that is not JSON", (200, b"<html>"), None),
               ("getEndUser answered 200 with JSON that is a list", (200, ["no such user"]), None),
               ("getEndUser answered 200 with an empty object", (200, {}), None),
               ("the token endpoint answered 200 with no token", None, (200, {"expires_in": 36000})),
               ("getEndUser could not be reached", Lab5Error("connection refused"), None),
               ("the token endpoint could not be reached", None, Lab5Error("connection refused"))]

    # The client, end to end: whatever the answer, a failed query raises.
    wrong = []
    tried = 0
    for name, answer, token_answer in list(answers()) + failed:
        tried += 1
        fake = FakeCII()
        fake.answer, fake.token_answer = answer, token_answer
        client = cii.CIIClient(CII["client_id"], CII["client_secret"], CII["token_url"], CII["api_url"], fake)
        try:
            got = client.end_user(login)
        except Lab5Error:
            continue
        except Exception as exc:  # noqa: BLE001 - a crash is a wrong answer too
            got = f"{type(exc).__name__}: {exc}"
        wrong.append(f"{name}: {got}")
    check(f"every error the shared table holds ({len(errors)}) in each of its {len(shapes)} shapes, and every "
          f"failed request ({len(failed)}: getEndUser's and the token endpoint's statuses with each body, a 200 it "
          f"cannot read, an unreachable CII), through CIIClient.end_user ({tried} in all): a failed query "
          "(Lab5Error), never 'not in CII yet' and never a user's details", not wrong, "; ".join(wrong)[:1500])

    # The self-check's row: a failed query is a CII problem row, never "not in
    # CII yet", for every code-less message, every coded error on the coded
    # messages, and every failed request.
    coded = cii_answers.coded_errors(table)
    rows = ([(repr(m), (200, {"data": {"getEndUser": None}, "errors": [{"message": m, "path": ["getEndUser"]}]}),
              None) for m in every_message]
            + [(name, (200, {"data": None, "errors": [{**copy.deepcopy(e), "path": ["getEndUser"]}]}), None)
               for name, e in coded] + failed)
    def details(out):
        """The self-check's rows for grace.lin (``  STATUS   persona   detail``)."""
        return [m.group(2) for m in re.finditer(r"(?m)^  (OK|WARN|FAIL)\s+grace\.lin\s+(.*)$", out)]

    with tempfile.TemporaryDirectory() as tmp:
        w = provisioned(Path(tmp))
        cast = lpers.load_cast(w.cast_path)
        for p in cast.personas:
            w.cii.users[cast.email(p)] = {"trust": "NEUTRAL"}
        rc, out = w.pa("baseline", "--jitter-minutes", "0")
        rc, out = w.pa("selfcheck", "--only", "grace.lin", "--no-notify")
        check("the self-check's row reads the persona's details when CII answers", rc == 0
              and any("CII trust NEUTRAL" in d for d in details(out)), out)
        wrong = []
        for name, answer, token_answer in rows:
            w.cii.answer, w.cii.token_answer = answer, token_answer
            # Each case starts with no cached token, as a first run does, so a
            # token endpoint failure is reached (test_cii_token_cache covers reuse).
            w.keychain.items.pop(cii.TOKEN_ITEM, None)
            rc, out = w.pa("selfcheck", "--only", "grace.lin", "--no-notify")
            found = details(out)
            if (not any(d.startswith("CII: ") for d in found)
                    or any(d.startswith("not in CII yet") or "CII trust" in d for d in found)):
                wrong.append(f"{name}: {found}")
        w.cii.answer = w.cii.token_answer = None
        check(f"every code-less message ({len(every_message)}), every coded error on the coded messages "
              f"({len(coded)}) and every failed request ({len(failed)}): the self-check's row names a CII problem, "
              "never 'not in CII yet' and never a trust level", not wrong, "; ".join(wrong)[:1500])


# =========================================================================== launchd
def test_launchd() -> None:
    print("== launchd: the Lab 5 job templates and install-lab5.sh ==")
    script = ROOT / "deploy" / "launchd" / "install-lab5.sh"
    check("install-lab5.sh parses", subprocess.run(["bash", "-n", str(script)]).returncode == 0)
    check("install-lab5.sh is executable", os.access(script, os.X_OK))
    wrapper = ROOT / "deploy" / "launchd" / "run-lab5-job.sh"
    for job, needle in (("expire", ["deploy/launchd/run-lab5-job.sh", "expire"]),
                        ("baseline", ["deploy/launchd/run-lab5-job.sh", "baseline"])):
        label = f"com.yeack.pseudoco-assistant-lab5-{job}"
        proc = subprocess.run(["bash", str(script), "--only", job, "--print"], capture_output=True,
                              env=dict(os.environ, LAB5_PYTHON="/opt/lab5/bin/python"))
        try:
            plist = plistlib.loads(proc.stdout)
        except Exception as exc:  # noqa: BLE001
            check(f"{job}: renders a valid plist", False, f"{exc}: {proc.stderr!r}")
            continue
        args = plist.get("ProgramArguments", [])
        joined = " ".join(args)
        check(f"{job}: label matches its file", plist.get("Label") == label
              and (ROOT / "deploy" / "launchd" / f"{label}.plist").exists())
        check(f"{job}: runs `{' '.join(needle)}` from this checkout",
              str(ROOT / needle[0]) in joined and args[-1] == needle[1] and (ROOT / needle[0]).exists(), joined)
        check(f"{job}: daily at a fixed time, one-shot, not at load",
              set(plist.get("StartCalendarInterval", {})) == {"Hour", "Minute"} and plist.get("KeepAlive") is False
              and plist.get("RunAtLoad") is False)
        check(f"{job}: uses the Lab 5 venv (LAB5_PYTHON for the wrapper), no placeholder left",
              (plist.get("EnvironmentVariables") or {}).get("LAB5_PYTHON") == "/opt/lab5/bin/python"
              and "__" not in proc.stdout.decode())
        check(f"{job}: logs to logs/launchd-lab5-{job}.log (gitignored)",
              plist.get("StandardOutPath", "").endswith(f"/logs/launchd-lab5-{job}.log"))
        check(f"{job}: no workshop file and no secret on its command line",
              not any(a.endswith(".yaml") for a in args) and not any(v in joined for v in KEYCHAIN_SECRETS.values()))
        for doc in ("deploy/lab5/README.md", "deploy/launchd/README.md"):
            text = (ROOT / doc).read_text()
            row = next((line for line in text.splitlines() if line.startswith("|") and f"lab5-{job}" in line), "")
            check(f"{job}: {doc}'s jobs table says it runs `run-lab5-job.sh {job}`, as the plist does",
                  f"run-lab5-job.sh {job}" in row, row)
    install = (ROOT / "deploy" / "launchd" / "install.sh").read_text()
    check("install.sh (the app's agents) does not install the Lab 5 jobs", "lab5" not in install)

    # A job that cannot start (LAB5_PYTHON missing, a broken venv) is the one
    # failure nothing in Python can report: the wrapper notifies for it.
    check("run-lab5-job.sh parses and is executable",
          subprocess.run(["bash", "-n", str(wrapper)]).returncode == 0 and os.access(wrapper, os.X_OK))
    with tempfile.TemporaryDirectory() as tmp:
        stub = Path(tmp) / "osascript"
        said = Path(tmp) / "said.txt"
        stub.write_text(f"#!/bin/bash\nprintf '%s\\n' \"$@\" >> {said}\n")
        stub.chmod(0o755)
        for job in ("expire", "baseline"):
            said.unlink(missing_ok=True)
            run = subprocess.run(["bash", str(wrapper), job], capture_output=True, text=True, timeout=30,
                                 env=dict(os.environ, LAB5_PYTHON=str(Path(tmp) / "no-such-venv" / "python"),
                                          PATH=f"{tmp}:{os.environ.get('PATH', '')}"))
            note = said.read_text() if said.exists() else ""
            check(f"{job}: LAB5_PYTHON missing -> exit 2, the fix in the log, and a macOS notification",
                  run.returncode == 2 and "lacks duo_client/PyYAML" in run.stderr
                  and "display notification" in note and f"Lab 5 {job}" in note and "did not run" in note,
                  f"{run.returncode} {run.stderr!r} {note!r}")
        run = subprocess.run(["bash", str(wrapper), "nonsense"], capture_output=True, text=True, timeout=30)
        check("an unknown job is refused (exit 2) and runs nothing", run.returncode == 2 and "usage" in run.stderr)


def test_daily_job_crash_notifies() -> None:
    print("== a daily job that crashes (not a Lab5Error) still raises its notification ==")
    with tempfile.TemporaryDirectory() as tmp:
        w = World(Path(tmp))
        w.pp("--dry-run")
        w.cii = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bug"))
        try:
            w.pa("selfcheck", "--no-notify")
            raised = None
        except RuntimeError as exc:
            raised = exc
        check("selfcheck: the crash propagates (its traceback reaches the log)", raised is not None)
        check("...after a notification naming it", w.notes and w.notes[-1][0] == "Lab 5 persona selfcheck"
              and "crashed (RuntimeError)" in w.notes[-1][1], str(w.notes))
        # A long checkout path: what is wrong must still reach the notification,
        # which keeps only its first 150 characters.
        bad = Path(tmp) / ("a-checkout-path-" * 10) / "broken.yaml"
        bad.parent.mkdir()
        bad.write_text("personas: [\n")
        out = io.StringIO()
        deps = pa.Deps(keychain_runner=w.keychain.runner, state_root=w.root, out=out,
                       notify=lambda title, msg: w.notes.append((title, msg)))
        rc = pa.main(["baseline", "--cast", str(bad)], deps=deps)
        check("baseline with a personas.yaml it cannot load: exit 2, and a notification (it used to say nothing) "
              "that says why, even under a long path",
              rc == 2 and w.notes[-1][0] == "Lab 5 persona baseline" and "did not run" in w.notes[-1][1]
              and "not valid YAML" in w.notes[-1][1], out.getvalue() + str(w.notes[-1:]))
        rc = pa.main(["baseline", "--cast", str(bad.parent / "missing.yaml")], deps=deps)
        check("baseline with a personas.yaml it cannot read: exit 2, and a notification that says why (the OS's "
              "reason), even under a long path",
              rc == 2 and w.notes[-1][0] == "Lab 5 persona baseline"
              and "cannot read the persona cast (No such file or directory)" in w.notes[-1][1], str(w.notes[-1:]))
        # A lock another run holds: the reason comes before its path too, for
        # the notifications that quote it (a persona's last sign-in error, or
        # "did not run").
        held = bad.parent / "held.lock"
        fd = os.open(str(held), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                with file_lock(held, timeout_s=0.3):
                    said = "the lock was taken"
            except Lab5Error as exc:
                said = str(exc)
        finally:
            os.close(fd)
        check("a lock another run holds: the error says so in its first 120 characters, even under a long path",
              "another run holds the lock" in said[:120], said)
        # Valid YAML with a value of the wrong type: cast_from_dict raised ValueError / AttributeError, outside
        # every handler, so the 09:20 job died with a traceback and no notification.
        good = w.cast_path.read_text()
        for name, typo in (("jitter_minutes: 40m", lambda t: t.replace("jitter_minutes: 40", "jitter_minutes: 40m")),
                           ("spacing_seconds: 10s", lambda t: t.replace("spacing_seconds: 10", "spacing_seconds: 10s")),
                           ("reuse_days: 8d", lambda t: t.replace("reuse_days: 8", "reuse_days: 8d")),
                           ("baseline: true (not baseline.enabled)",
                            lambda t: re.sub(r"(?m)^baseline:\n(?:  .*\n)+", "baseline: true\n", t))):
            text = typo(good)
            bad.write_text(text)
            before = len(w.notes)
            try:
                rc, raised = pa.main(["baseline", "--cast", str(bad)], deps=deps), ""
            except Exception as exc:  # noqa: BLE001
                rc, raised = None, type(exc).__name__
            check(f"baseline with {name}: exit 2 and a notification (a value of the wrong type), never a "
                  "silent traceback",
                  text != good and not raised and rc == 2 and len(w.notes) == before + 1
                  and w.notes[-1][0] == "Lab 5 persona baseline" and "wrong type" in w.notes[-1][1]
                  and "did not run" in w.notes[-1][1], f"{raised} {w.notes[-1:]}")
        real_load = pa.load_cast
        pa.load_cast = lambda path: (_ for _ in ()).throw(RuntimeError("bug"))
        try:
            pa.main(["baseline", "--cast", str(w.cast_path)], deps=deps)
            raised = None
        except RuntimeError as exc:
            raised = exc
        finally:
            pa.load_cast = real_load
        check("a crash while loading the cast (not a Lab5Error) propagates after a notification naming it",
              raised is not None and w.notes[-1][0] == "Lab 5 persona baseline"
              and "crashed loading the persona cast (RuntimeError)" in w.notes[-1][1], str(w.notes[-1:]))


def main() -> int:
    for test in (test_cast_is_disjoint, test_cast_validation, test_keychain_store, test_provision, test_baseline,
                 test_counter_lock, test_takeover, test_replay, test_selfcheck, test_reset_and_teardown,
                 test_cii_client, test_cii_token_cache, test_no_cii_failure_is_not_in_cii_yet, test_launchd,
                 test_daily_job_crash_notifies):
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(f"{test.__name__} raised {type(exc).__name__}", False, str(exc))
    print("== lazy imports ==")
    check("ran without importing duo_client or paramiko (the app venv has neither)",
          "duo_client" not in sys.modules and "paramiko" not in sys.modules)
    print(f"\n{len(_failures)} failure(s)" if _failures else "\nALL PASS")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
