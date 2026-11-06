#!/usr/bin/env python3
"""persona_activity.py: Lab 5 persona sign-ins through the Auth API (plan 4.5).

    persona_activity.py baseline [--only U,..] [--jitter-minutes N] [--no-selfcheck] [--dry-run]
    persona_activity.py takeover --victim U [--force] [--dry-run]
    persona_activity.py replay --victim U [--pushes N] [--dry-run]
    persona_activity.py selfcheck [--gate] [--no-notify]

Runs on the facilitator's Mac with the Auth API app **PseudoCo VPN** (Keychain
items pseudoco-lab5-duo-vpn-ikey/-skey). No broker, SSM or DynamoDB: each
persona's HOTP secret is a Keychain item and its counter a locked file under
~/.pseudoco-lab5/personas/. Every sign-in sends ``ipaddr`` and ``hostname`` and
never ``client_supports_verified_push``.

* ``baseline``: one successful passcode sign-in per persona from its home
  address and device, at random points in the jitter window, then the
  self-check. Off until personas.yaml ``baseline.enabled`` (after spikes S1,
  S2 and S7). launchd runs it daily (deploy/launchd/).
* ``takeover --victim U``: a home sign-in; 5-9 wrong passcodes from the next
  foreign address within MFA Flood's 2 minutes, under the lockout limit of 10;
  then a success from that address with the attacker's device (a previously
  only-failing IP, a new device). Its record under personas/takeovers/ is the
  source of the takeover time. When to run it depends on the S1 decision.
  Afterwards: *Collect Now* on CII's Duo integration (no API).
* ``replay --victim U``: a short push flood to the one victim with Duo Mobile
  on a facilitator phone, who denies each push on stage. Never from the app.
* ``selfcheck``: each persona's last sign-in, Keychain secret and counter, Duo
  preauth, and CII trust and failing checks. Any problem raises a macOS
  notification and exits 1. ``--gate`` is the T-18 gate: Unknown trust fails.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "deploy" / "lab5"))

import lab5_cii as cii  # noqa: E402
import lab5_duo as duo  # noqa: E402
from lab5_cloudflare import urllib_transport  # noqa: E402
from lab5_common import (Keychain, Lab5Error, Redactor, Reporter, StateStore, desktop_notify,  # noqa: E402
                         file_lock, private_dir, utc_now, utc_stamp)
from lab5_personas import DEFAULT_CAST, Cast, Persona, PersonaState, Place, load_cast, require_public  # noqa: E402

ACTIVITY_LOCK = "activity.lock"
STALE_AFTER_H = 26          # a daily sign-in older than this is a warning
FAIL_AFTER_H = 72           # and after three days a failure


@dataclass
class Deps:
    keychain_runner: Optional[Callable[..., Any]] = None
    keychain_stdin_runner: Optional[Callable[..., Any]] = None
    duo_transport: Callable[..., Any] = duo.duo_transport
    https: Callable[..., Tuple[int, bytes]] = urllib_transport
    state_root: Optional[Path] = None
    out: Any = None
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], float] = time.time
    rng: random.Random = field(default_factory=random.SystemRandom)
    notify: Callable[[str, str], None] = desktop_notify
    lock_timeout_s: float = 900.0


class Activity:
    def __init__(self, cast: Cast, keychain: Keychain, state: PersonaState, out: Reporter, deps: Deps) -> None:
        self.cast, self.keychain, self.state, self.out, self.deps = cast, keychain, state, out, deps
        self._auth: Optional[duo.AuthAPI] = None

    @property
    def auth(self) -> duo.AuthAPI:
        if self._auth is None:
            self._auth = duo.auth_api(self.keychain, self.deps.duo_transport)
        return self._auth

    def lock(self):
        return file_lock(self.state.dir / ACTIVITY_LOCK, timeout_s=self.deps.lock_timeout_s)

    def secret(self, p: Persona) -> bytes:
        text = self.keychain.require(self.cast.keychain_item(p), f"HOTP secret of {p.username}")
        return duo.decode_secret(text, self.cast.secret_encoding)

    def sign_in(self, p: Persona, place: Place, step: str) -> Dict[str, Any]:
        """One passcode sign-in with the next counter value (reserved first,
        so a crash never reuses a code)."""
        secret = self.secret(p)
        counter = self.state.reserve(p.username)
        at = utc_now()
        try:
            resp = self.auth.auth_passcode(p.username, duo.hotp(secret, counter), place.ipaddr, place.hostname)
        except Lab5Error as exc:
            resp = {"result": "error", "status": "error", "status_msg": str(exc)[:200]}
        rec = {"step": step, "username": p.username, "at": at, "counter": counter, "ipaddr": place.ipaddr,
               "hostname": place.hostname, "result": resp.get("result"), "status": resp.get("status"),
               "status_msg": resp.get("status_msg")}
        self.out.line(f"  {'OK' if rec['result'] == 'allow' else 'FAIL':<8} {p.username:<14} {step}: "
                      f"{rec['result']} ({rec['status']}) from {place.ipaddr} {place.hostname}")
        return rec

    def wrong(self, p: Persona, place: Place, step: str) -> Dict[str, Any]:
        secret = self.secret(p)
        counter = int((self.state.counter(p.username) or {}).get("next", 0))
        code = duo.wrong_passcode(secret, counter, rng=self.deps.rng.randrange)
        at = utc_now()
        try:
            resp = self.auth.auth_passcode(p.username, code, place.ipaddr, place.hostname)
        except Lab5Error as exc:
            resp = {"result": "error", "status": "error", "status_msg": str(exc)[:200]}
        rec = {"step": step, "username": p.username, "at": at, "ipaddr": place.ipaddr, "hostname": place.hostname,
               "result": resp.get("result"), "status": resp.get("status"), "status_msg": resp.get("status_msg")}
        self.out.line(f"  {'OK' if rec['result'] == 'deny' else 'FAIL':<8} {p.username:<14} {step}: "
                      f"{rec['result']} ({rec['status']}) from {place.ipaddr} {place.hostname}")
        return rec


# =========================================================================== baseline
def baseline(act: Activity, chosen: List[Persona], jitter_min: float, dry: bool) -> int:
    cast, deps = act.cast, act.deps
    for p in chosen:
        require_public(p.home, f"{p.username}.home")
    offsets = sorted((deps.rng.uniform(0, jitter_min * 60.0) if jitter_min else 0.0, p.username) for p in chosen)
    by_name = {p.username: p for p in chosen}
    act.out.line(f"baseline: {len(chosen)} persona(s) over {jitter_min:g} min, from each home address")
    if dry:
        for _, name in offsets:
            p = by_name[name]
            act.out.line(f"  PLAN     {name:<14} passcode sign-in from {p.home.ipaddr} {p.home.hostname}")
        return 0
    results, elapsed = [], 0.0
    for offset, name in offsets:
        if offset > elapsed:
            deps.sleep(offset - elapsed)
            elapsed = offset
        p = by_name[name]
        try:
            with act.lock():
                rec = act.sign_in(p, p.home, "baseline")
        except Lab5Error as exc:
            rec = {"step": "baseline", "username": name, "at": utc_now(), "result": "error",
                   "status": "error", "status_msg": str(exc)[:200]}
            act.out.line(f"  FAIL     {name:<14} baseline: {exc}")
        results.append(rec)
        fields = {"last_attempt": rec["at"], "last_result": rec["result"], "last_status": rec.get("status"),
                  "last_status_msg": rec.get("status_msg")}
        if rec["result"] == "allow":
            fields["last_success"] = rec["at"]
        act.state.update_last(name, **fields)
    act.state.record("runs", f"{utc_stamp()}-baseline", {"kind": "baseline", "at": utc_now(), "results": results})
    bad = [r["username"] for r in results if r["result"] != "allow"]
    act.out.line(f"baseline: {len(results) - len(bad)} signed in, {len(bad)} failed"
                 + (f" ({', '.join(bad)})" if bad else ""))
    return 1 if bad else 0


# =========================================================================== takeover
def _takeovers(state: PersonaState, victim: str) -> List[Dict[str, Any]]:
    return [r for r in state.records("takeovers") if r.get("victim") == victim]


def _parse(text: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(text).timestamp()


def takeover(act: Activity, p: Persona, force: bool, dry: bool) -> int:
    cast, deps = act.cast, act.deps
    if p.role == "trusted":
        raise Lab5Error(f"{p.username} is a trusted persona: a takeover would make the gate refuse it on lab day")
    if not cast.foreign:
        raise Lab5Error("personas.yaml has no takeover.foreign addresses")
    require_public(p.home, f"{p.username}.home")
    for i, place in enumerate(cast.foreign):
        require_public(place, f"takeover.foreign[{i}]")
    previous = _takeovers(act.state, p.username)
    if previous and not force:
        last = max(_parse(r["started_at"]) for r in previous)
        days = (deps.now() - last) / 86400.0
        if days < cast.reuse_days:
            raise Lab5Error(f"{p.username} was taken over {days:.1f} days ago; a victim needs about "
                            f"{cast.reuse_days} days before its next takeover (its failures last 7 days and "
                            "webhooks announce only newly failing users). Use the room's fallback, or --force")
    foreign = cast.foreign[len(previous) % len(cast.foreign)]
    low, high = cast.takeover_attempts
    attempts = deps.rng.randint(low, high)
    act.out.line(f"takeover of {p.username} ({p.role}): home sign-in, {attempts} wrong passcodes from "
                 f"{foreign.ipaddr} {foreign.hostname} {cast.takeover_spacing_s:g} s apart, then a success from there")
    if dry:
        act.out.line("  PLAN     dry run: nothing sent")
        return 0
    with act.lock():
        pre = act.auth.preauth(p.username, p.home.ipaddr, p.home.hostname)
        if pre.get("result") != "auth":
            raise Lab5Error(f"preauth for {p.username} says {pre.get('result')!r} ({pre.get('status_msg')}): it "
                            "must be active, enrolled and not locked out; provision_personas.py --reset")
        record = {"victim": p.username, "started_at": utc_now(), "attempts": attempts,
                  "home": vars(p.home), "foreign": vars(foreign), "steps": []}
        name = f"{utc_stamp()}-{p.username}"
        steps: List[Dict[str, Any]] = record["steps"]
        try:
            steps.append(act.sign_in(p, p.home, "1 home sign-in"))
            if steps[-1]["result"] != "allow":
                raise Lab5Error("the home sign-in failed; nothing else was sent")
            for i in range(attempts):
                if i:
                    deps.sleep(cast.takeover_spacing_s)
                steps.append(act.wrong(p, foreign, f"2 wrong passcode {i + 1}/{attempts}"))
                if steps[-1]["result"] != "deny" or steps[-1].get("status") == "locked_out":
                    raise Lab5Error(f"stopped: wrong passcode {i + 1} came back {steps[-1]['result']} "
                                    f"({steps[-1].get('status')})")
            deps.sleep(cast.takeover_spacing_s)
            steps.append(act.sign_in(p, foreign, "3 success from the failing address, new device"))
            if steps[-1]["result"] != "allow":
                raise Lab5Error("the foreign success was denied")
        except Lab5Error as exc:
            record.update(finished_at=utc_now(), ok=False, error=str(exc)[:300])
            path = act.state.record("takeovers", name, record)
            act.out.line(f"takeover: FAILED: {exc}. Record: {path}")
            return 1
        record.update(finished_at=utc_now(), ok=True)
        path = act.state.record("takeovers", name, record)
    act.out.line(f"takeover: done; record {path} (the takeover time for any labelled backfill, plan 12.4)")
    act.out.line("NEXT: Collect Now on the CII Duo integration (Integrations > Duo; there is no API). Check the "
                 f"victim with `persona_activity.py selfcheck` once CII has analysed it. How its FAILED_CHECK "
                 "reaches the room stacks depends on the S1 decision (plan 12.4)")
    return 0


# =========================================================================== replay
def replay(act: Activity, p: Persona, pushes: int, dry: bool) -> int:
    cast, deps = act.cast, act.deps
    if not p.replay_device:
        raise Lab5Error(f"{p.username} has no replay_device in personas.yaml: only the one victim with Duo Mobile "
                        "on a facilitator phone takes a replay")
    if not 1 <= pushes <= 9:
        raise Lab5Error("--pushes must be 1-9 (under the lockout limit of 10)")
    if not cast.foreign:
        raise Lab5Error("personas.yaml has no takeover.foreign addresses")
    place = cast.foreign[len(_takeovers(act.state, p.username)) % len(cast.foreign)]
    require_public(place, "the replay address")
    act.out.line(f"replay: {pushes} push(es) to {p.username} from {place.ipaddr} {place.hostname}; deny each one")
    if dry:
        act.out.line("  PLAN     dry run: nothing sent")
        return 0
    with act.lock():
        pre = act.auth.preauth(p.username, place.ipaddr, place.hostname)
        devices = [d for d in (pre.get("devices") or []) if "push" in (d.get("capabilities") or [])]
        if pre.get("result") != "auth" or not devices:
            raise Lab5Error(f"preauth for {p.username}: {pre.get('result')!r}, {len(devices)} push device(s); "
                            "the replay needs an active victim with Duo Mobile")
        txids = []
        for i in range(pushes):
            if i:
                deps.sleep(2.0)
            txids.append(act.auth.auth_push_async(p.username, place.ipaddr, place.hostname, text="Lab 5 replay"))
        results = []
        for txid in txids:
            status: Dict[str, Any] = {}
            for _ in range(40):
                status = act.auth.auth_status(txid)
                if status.get("result") != "waiting":
                    break
                deps.sleep(2.0)
            results.append(status.get("result") or "unknown")
    allowed = results.count("allow")
    act.state.record("replays", f"{utc_stamp()}-{p.username}", {"victim": p.username, "at": utc_now(),
                                                                  "place": vars(place), "results": results})
    act.out.line(f"replay: {', '.join(results)}")
    if allowed:
        act.out.line(f"replay: WARNING {allowed} push(es) were APPROVED; the replay expects every one denied")
    return 1 if allowed else 0


# =========================================================================== selfcheck
def _persona_issues(act: Activity, p: Persona, client: Optional[cii.CIIClient], gate: bool,
                    last: Dict[str, Any], now: float) -> Tuple[List[Tuple[str, str]], str]:
    """(problems as (FAIL|WARN, text), the one-line summary when all is well)."""
    cast = act.cast
    issues: List[Tuple[str, str]] = []
    rec = last.get(p.username, {})
    if cast.baseline_enabled:
        success = rec.get("last_success")
        if not success:
            issues.append(("FAIL", "no successful baseline sign-in recorded yet"))
        else:
            hours = (now - _parse(success)) / 3600.0
            if hours > FAIL_AFTER_H:
                issues.append(("FAIL", f"last successful sign-in {hours:.0f} h ago (is the launchd job running?)"))
            elif hours > STALE_AFTER_H:
                issues.append(("WARN", f"last successful sign-in {hours:.0f} h ago"))
        if rec.get("last_result") not in (None, "allow"):
            issues.append(("FAIL", f"last sign-in {rec.get('last_result')} ({rec.get('last_status')}: "
                                   f"{rec.get('last_status_msg')})"))
    counter = act.state.counter(p.username)
    if not counter or not act.keychain.get(cast.keychain_item(p)):
        issues.append(("FAIL", f"HOTP {'counter' if not counter else 'Keychain secret'} missing: "
                               "provision_personas.py"))
    try:
        pre = act.auth.preauth(p.username, p.home.ipaddr, p.home.hostname)
        if pre.get("result") != "auth":
            issues.append(("FAIL", f"Duo preauth {pre.get('result')!r}: {pre.get('status_msg')} (disabled or "
                                   "locked out? provision_personas.py --reset)"))
    except Lab5Error as exc:
        issues.append(("FAIL", f"Duo preauth failed: {exc}"))
    summary = f"{p.role}; signed in {rec.get('last_success') or 'never'}; next counter " \
              f"{counter['next'] if counter else '?'}"
    if client is None:
        return issues, summary
    try:
        info = client.end_user(cast.email(p))
    except Lab5Error as exc:
        issues.append(("FAIL" if gate else "WARN", f"CII: {exc}"))
        return issues, summary
    trust, checks = info["trust"], info["failing_checks"]
    text = f"CII trust {trust}" + (f", failing {', '.join(checks)}" if checks else ", no failing checks")
    if not info["found"]:
        issues.append(("FAIL" if gate else "WARN", f"not in CII yet ({cast.email(p)})"))
    elif p.role == "trusted" and (checks or trust in ("QUESTIONABLE", "UNTRUSTED")):
        issues.append(("FAIL", text + ": a trusted persona must pass (check its CII exclusions)"))
    elif trust == "UNKNOWN":
        issues.append(("FAIL" if gate else "WARN", text + ("; the T-18 gate needs every persona out of Unknown"
                                                           if gate else "")))
    return issues, f"{summary}; {text}"


def selfcheck(act: Activity, chosen: List[Persona], gate: bool, notify: bool) -> int:
    """Each persona's sign-ins, HOTP state, Duo status and CII trust (4.5)."""
    cast, deps = act.cast, act.deps
    act.out.line(f"selfcheck{' --gate (T-18)' if gate else ''}: {len(chosen)} persona(s); baseline "
                 f"{'on' if cast.baseline_enabled else 'off'}")
    rows: List[Dict[str, str]] = []
    try:
        client: Optional[cii.CIIClient] = cii.cii_client(act.keychain, deps.https, cast.cii_query)
    except Lab5Error as exc:
        client = None
        rows.append({"status": "FAIL" if gate else "WARN", "persona": "cii", "detail": f"trust not checked: {exc}"})
    last, now = act.state.last(), deps.now()
    for p in chosen:
        issues, summary = _persona_issues(act, p, client, gate, last, now)
        rows += ([{"status": st, "persona": p.username, "detail": text} for st, text in issues]
                 or [{"status": "OK", "persona": p.username, "detail": summary}])
    for r in rows:
        act.out.line(f"  {r['status']:<8} {r['persona']:<14} {r['detail']}")
    problems = [f"{r['persona']}: {r['detail']}" for r in rows if r["status"] == "FAIL"]
    act.state.record("selfcheck", "latest", {"at": utc_now(), "gate": gate, "rows": rows})
    act.out.line(f"selfcheck: {len(problems)} problem(s), "
                 f"{sum(1 for r in rows if r['status'] == 'WARN')} warning(s)")
    if problems and notify:
        deps.notify("Lab 5 persona self-check", f"{len(problems)} problem(s): {problems[0][:120]}")
    return 1 if problems else 0


# =========================================================================== cli
def main(argv: Optional[Sequence[str]] = None, deps: Optional[Deps] = None) -> int:
    deps = deps or Deps()
    ap = argparse.ArgumentParser(prog="persona_activity.py", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("baseline", help="one successful sign-in per persona, then the self-check")
    b.add_argument("--only", default="")
    b.add_argument("--jitter-minutes", type=float, default=None)
    b.add_argument("--no-selfcheck", action="store_true")
    b.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("takeover", help="the scripted account takeover of one victim")
    t.add_argument("--victim", required=True)
    t.add_argument("--force", action="store_true", help="skip the victim-reuse wait")
    t.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("replay", help="a short push flood the facilitator denies")
    r.add_argument("--victim", required=True)
    r.add_argument("--pushes", type=int, default=None)
    r.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("selfcheck", help="daily self-check; notifies on any problem")
    s.add_argument("--only", default="")
    s.add_argument("--gate", action="store_true", help="T-18 gate: Unknown trust is a failure")
    s.add_argument("--no-notify", action="store_true")
    for p in (b, t, r, s):
        p.add_argument("--cast", type=Path, default=DEFAULT_CAST)
    args = ap.parse_args(argv)
    out = deps.out or sys.stdout
    root = Path(deps.state_root or StateStore.default_root())
    redactor = Redactor()
    try:
        cast = load_cast(args.cast)
    except Lab5Error as exc:
        print(f"persona_activity: {exc}", file=out)
        if args.command in ("baseline", "selfcheck"):        # the daily job: no one reads its output
            deps.notify("Lab 5 persona " + args.command, "did not run: " + str(exc)[:150])
        return 2
    private_dir(root)
    reporter = Reporter(redactor, out=out, log_path=root / "personas" / "runs" / f"{utc_stamp()}-{args.command}.log")
    kwargs: Dict[str, Any] = {}
    if deps.keychain_runner:
        kwargs["runner"] = deps.keychain_runner
    if deps.keychain_stdin_runner:
        kwargs["stdin_runner"] = deps.keychain_stdin_runner
    act = Activity(cast, Keychain(redactor, **kwargs), PersonaState(root), reporter, deps)
    try:
        if args.command == "baseline":
            if not cast.baseline_enabled:
                reporter.line("baseline: off in personas.yaml (baseline.enabled: false). Turn it on once spikes "
                              "S1, S2 and S7 pass, at least 4 weeks before the first delivery (plan 4.5). Nothing sent")
                return 0
            chosen = [cast.get(u.strip()) for u in args.only.split(",") if u.strip()] or cast.personas
            jitter = cast.jitter_minutes if args.jitter_minutes is None else max(0.0, args.jitter_minutes)
            rc = baseline(act, chosen, jitter, args.dry_run)
            if not args.no_selfcheck and not args.dry_run:
                rc = max(rc, selfcheck(act, chosen, gate=False, notify=True))
            elif rc:
                deps.notify("Lab 5 persona baseline", "a persona sign-in failed; see ~/.pseudoco-lab5/personas/runs/")
            return rc
        if args.command == "takeover":
            return takeover(act, cast.get(args.victim), args.force, args.dry_run)
        if args.command == "replay":
            pushes = cast.replay_pushes if args.pushes is None else args.pushes
            return replay(act, cast.get(args.victim), pushes, args.dry_run)
        chosen = [cast.get(u.strip()) for u in args.only.split(",") if u.strip()] or cast.personas
        return selfcheck(act, chosen, gate=args.gate, notify=not args.no_notify)
    except Lab5Error as exc:
        reporter.line(f"persona_activity {args.command}: {exc}")
        if args.command in ("baseline", "selfcheck"):
            deps.notify("Lab 5 persona " + args.command, "did not run: " + redactor.scrub(str(exc))[:150])
        return 2
    except Exception as exc:  # noqa: BLE001 - the daily job's crash must notify too (the traceback follows)
        reporter.line(f"persona_activity {args.command}: crashed ({type(exc).__name__})")
        if args.command in ("baseline", "selfcheck"):
            deps.notify("Lab 5 persona " + args.command, f"crashed ({type(exc).__name__}); see "
                                                          "~/.pseudoco-lab5/personas/runs/")
        raise
    finally:
        reporter.close()


if __name__ == "__main__":
    sys.exit(main())
