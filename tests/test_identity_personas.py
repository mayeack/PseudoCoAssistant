"""The Lab 5 persona scripts (scripts/identity/) and launchd jobs, against fakes only.

Duo, the Keychain and CII are tests/lab5_fakes; no real Duo, CII or Keychain
item is ever read or written, and no launchd job is loaded.

What it pins (plan 4.3, 4.5, 12.4 and the secrets rule):
  * the cast is disjoint from the app's synthetic end users (ENDUSER_IDS,
    t.nguyen) and from the synthetic-PII name pools and records of all 8 themes;
  * provision_personas creates the group, users and HOTP tokens; each secret
    reaches the Keychain through `security -i` stdin, never argv; it is
    idempotent, and never touches a user without the persona marker;
  * baseline signs every persona in once from home with ipaddr + hostname
    (never client_supports_verified_push), with a locked counter; it does
    nothing while off and refuses documentation addresses;
  * takeover, replay, selfcheck, --reset and --teardown behave as 4.3/4.5 say;
  * the launchd templates render to valid plists that run the right commands.

Run:  .venv/bin/python tests/test_identity_personas.py
"""
from __future__ import annotations

import ast
import io
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
from lab5_common import Keychain, Lab5Error, Redactor  # noqa: E402
from lab5_fakes import API_HOST, CII, KEYCHAIN_SECRETS, Clock, FakeCII, FakeDuo, FakeKeychain  # noqa: E402
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
        squatter = w.duo.add_user("casey.wong", notes="someone else's account")
        rc, out = w.pp()
        check("provision exits 1 because of the foreign casey.wong", rc == 1 and "left alone" in out, out)
        check("... which is untouched", w.duo.users[squatter["user_id"]]["notes"] == "someone else's account"
              and not w.duo.users[squatter["user_id"]]["tokens"] and not w.duo.users[squatter["user_id"]]["groups"])
        cast = lpers.load_cast(w.cast_path)
        check("group PseudoCo Workforce created", any(g["name"] == "PseudoCo Workforce" for g in w.duo.groups.values()))
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
        valid = {duo.hotp(secret, c) for c in range(0, 300)}
        check("the wrong passcodes are never valid codes", all(a["passcode"] not in valid for a in wrong))
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
        check("the group stays (every lab app is limited to it)",
              any(g["name"] == "PseudoCo Workforce" for g in w.duo.groups.values()) and "kept" in out)
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
    check("failing() matches check names loosely", cii.failing(["MFA Flood"], "mfa_flood")
          and not cii.failing(["MFA Flood"], "impossible travel"))
    try:
        cii.CIIClient("i", "s", "http://plain/token", CII["api_url"], fake)
        ok = False
    except Lab5Error:
        ok = True
    check("a plain-http CII URL is refused", ok)


# =========================================================================== launchd
def test_launchd() -> None:
    print("== launchd: the Lab 5 job templates and install-lab5.sh ==")
    script = ROOT / "deploy" / "launchd" / "install-lab5.sh"
    check("install-lab5.sh parses", subprocess.run(["bash", "-n", str(script)]).returncode == 0)
    check("install-lab5.sh is executable", os.access(script, os.X_OK))
    for job, needle in (("expire", ["deploy/lab5/lab5-setup", "expire"]),
                        ("baseline", ["scripts/identity/persona_activity.py", "baseline"])):
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
        check(f"{job}: uses the Lab 5 venv, no placeholder left",
              "/opt/lab5/bin/python" in proc.stdout.decode() and "__" not in proc.stdout.decode())
        check(f"{job}: logs to logs/launchd-lab5-{job}.log (gitignored)",
              plist.get("StandardOutPath", "").endswith(f"/logs/launchd-lab5-{job}.log"))
        check(f"{job}: no workshop file and no secret on its command line",
              not any(a.endswith(".yaml") for a in args) and not any(v in joined for v in KEYCHAIN_SECRETS.values()))
    install = (ROOT / "deploy" / "launchd" / "install.sh").read_text()
    check("install.sh (the app's agents) does not install the Lab 5 jobs", "lab5" not in install)


def main() -> int:
    for test in (test_cast_is_disjoint, test_cast_validation, test_keychain_store, test_provision, test_baseline,
                 test_counter_lock, test_takeover, test_replay, test_selfcheck, test_reset_and_teardown,
                 test_cii_client, test_launchd):
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
