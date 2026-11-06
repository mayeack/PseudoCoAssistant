#!/usr/bin/env python3
"""provision_personas.py: the Lab 5 persona cast in Duo (plan 4.3, 12.4).

    provision_personas.py [--dry-run]               create what is missing: the group,
                                                    the users, one HOTP token each
    provision_personas.py --status                  read-only: Duo state, token, counter
    provision_personas.py --reset [--only U,..]     re-enable and unlock, then resync each
                                                    HOTP token to the Mac's counter
    provision_personas.py --teardown [--yes]        delete the cast's users and tokens,
                                                    and their Keychain secrets and counters

Runs on the facilitator's Mac with the Admin API app **PseudoCo Provisioner**
(Keychain items pseudoco-lab5-duo-provisioner-ikey/-skey and the API host).
There is no broker, SSM or DynamoDB: each persona's HOTP secret is a Keychain
item (written through `security -i`, so never in argv), its counter is under
~/.pseudoco-lab5/personas/hotp/ behind a file lock. Nothing else may use these
codes: HOTP only accepts codes ahead of Duo's counter.

Only users listed in scripts/identity/personas.yaml whose notes carry the
persona marker are ever changed or deleted. Users are API-created only (never
directory-synced: the Admin API cannot disable a synced user). The group is
kept on teardown, because every lab app is limited to it.

No API clears a risk-based step-up or CII feedback: after --reset or
--teardown, use Admin Panel > Users > Clear all step-ups, and CII Reset Feedback.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "deploy" / "lab5"))

import lab5_duo as duo  # noqa: E402
from lab5_common import (Keychain, Lab5Error, Redactor, Reporter, StateStore, private_dir,  # noqa: E402
                         utc_now, utc_stamp)
from lab5_personas import (DEFAULT_CAST, Cast, Persona, PersonaState, is_persona_notes,  # noqa: E402
                           load_cast, persona_notes)

STEP_UP_NOTE = ("No API clears a risk-based step-up or CII feedback: Admin Panel > Users > Clear all step-ups, "
                "and CII Reset Feedback on the personas (plan 4.3, 4.6)")


@dataclass
class Deps:
    keychain_runner: Optional[Callable[..., Any]] = None
    keychain_stdin_runner: Optional[Callable[..., Any]] = None
    duo_transport: Callable[..., Any] = duo.duo_transport
    state_root: Optional[Path] = None
    out: Any = None


def make_keychain(redactor: Redactor, deps: Any) -> Keychain:
    kwargs: Dict[str, Any] = {}
    if deps.keychain_runner:
        kwargs["runner"] = deps.keychain_runner
    if getattr(deps, "keychain_stdin_runner", None):
        kwargs["stdin_runner"] = deps.keychain_stdin_runner
    return Keychain(redactor, **kwargs)


class Run:
    def __init__(self, cast: Cast, admin: duo.AdminAPI, keychain: Keychain, state: PersonaState,
                 out: Reporter, dry_run: bool) -> None:
        self.cast, self.admin, self.keychain, self.state, self.out, self.dry = cast, admin, keychain, state, out, dry_run
        self.failed = 0

    def row(self, status: str, name: str, detail: str) -> None:
        if status == "FAIL":
            self.failed += 1
        self.out.line(f"  {status:<8} {name:<14} {detail}")

    def owned(self, p: Persona, user: Dict[str, Any]) -> bool:
        if is_persona_notes(user.get("notes")):
            return True
        self.row("FAIL", p.username, "a Duo user with this name exists without the persona notes marker: "
                                     "not created by this script, left alone")
        return False

    def tokens(self, p: Persona, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        serial = self.cast.token_serial(p)
        found = [t for t in (user.get("tokens") or []) if t.get("serial") == serial]
        if not found:
            orphan = self.admin.token_by_serial(serial)
            found = [orphan] if orphan and not duo.assigned_elsewhere(orphan, str(user.get("user_id") or "")) else []
        return found

    # ------------------------------------------------------------------ create
    def group_id(self) -> str:
        group = self.admin.group_by_name(self.cast.group)
        if group:
            return str(group["group_id"])
        if self.dry:
            self.row("PLAN", "group", f"create {self.cast.group}")
            return ""
        group = self.admin.create_group(self.cast.group, "Lab 5 persona cast (scripts/identity/personas.yaml)")
        self.row("CHANGED", "group", f"created {self.cast.group}; limit every lab app to it (plan 4.2)")
        return str(group["group_id"])

    def ensure(self, p: Persona, group_id: str) -> None:
        user = self.admin.user_by_name(p.username)
        if user and not self.owned(p, user):
            return
        if not user:
            if self.dry:
                self.row("PLAN", p.username, f"create ({p.role}), {self.cast.email(p)}, group {self.cast.group}, "
                                             "HOTP token")
                return
            user = self.admin.create_user(p.username, self.cast.email(p), p.name, persona_notes(p),
                                          firstname=p.first, lastname=p.last)
            self.row("CHANGED", p.username, f"created ({p.role}) {self.cast.email(p)}")
        if self.cast.group not in duo.group_names(user):
            if self.dry:
                self.row("PLAN", p.username, f"add to {self.cast.group}")
            else:
                self.admin.add_user_group(str(user["user_id"]), group_id)
                self.row("CHANGED", p.username, f"added to {self.cast.group}")
        self.ensure_token(p, user)

    def ensure_token(self, p: Persona, user: Dict[str, Any]) -> None:
        item, serial = self.cast.keychain_item(p), self.cast.token_serial(p)
        secret_text = self.keychain.get(item)
        counter = self.state.counter(p.username)
        attached = [t for t in (user.get("tokens") or []) if t.get("serial") == serial]
        if attached and secret_text and counter:
            self.row("OK", p.username, f"{user.get('status')}, HOTP token {serial}, next counter {counter['next']}")
            return
        if attached:
            self.row("FAIL", p.username, f"its HOTP token exists but the Mac lost the "
                                         f"{'Keychain secret' if not secret_text else 'counter'}: run --teardown "
                                         "for this persona (--only) and provision again")
            return
        if self.dry:
            self.row("PLAN", p.username, f"create and attach HOTP token {serial}; secret to Keychain item {item}")
            return
        orphan = self.admin.token_by_serial(serial)
        if orphan and duo.assigned_elsewhere(orphan, str(user["user_id"])):
            self.row("FAIL", p.username, f"HOTP token {serial} belongs to another user; left alone")
            return
        if orphan:                     # from a run that stopped before attaching it
            self.admin.delete_token(str(orphan["token_id"]))
        start = int(counter["next"]) if counter and secret_text else 0
        if not secret_text:
            secret_text = duo.encode_secret(duo.new_hotp_secret(), self.cast.secret_encoding)
            self.keychain.store(item, secret_text)   # first: a token without its secret is useless
        token = self.admin.create_hotp_token(serial, secret_text, start)
        try:
            self.admin.attach_token(str(user["user_id"]), str(token["token_id"]))
        except Lab5Error:
            self.admin.delete_token(str(token["token_id"]))
            raise
        self.state.init_counter(p.username, str(token["token_id"]), start)
        self.row("CHANGED", p.username, f"HOTP token {serial} attached; secret in Keychain item {item}, "
                                        f"counter {start}")

    # ------------------------------------------------------------------ status
    def status(self, p: Persona) -> None:
        user = self.admin.user_by_name(p.username)
        if not user:
            self.row("FAIL", p.username, "missing in Duo: run provision_personas.py")
            return
        if not self.owned(p, user):
            return
        attached = [t for t in (user.get("tokens") or []) if t.get("serial") == self.cast.token_serial(p)]
        counter = self.state.counter(p.username)
        secret = bool(self.keychain.get(self.cast.keychain_item(p)))
        last = self.state.last().get(p.username, {})
        ok = user.get("status") == "active" and attached and counter and secret
        self.row("OK" if ok else "FAIL", p.username,
                 f"{p.role}, {user.get('status')}, token {'attached' if attached else 'MISSING'}, Keychain secret "
                 f"{'present' if secret else 'MISSING'}, next counter {counter['next'] if counter else 'MISSING'}, "
                 f"last baseline success {last.get('last_success') or 'never'}")

    # ------------------------------------------------------------------ reset
    def reset(self, p: Persona) -> None:
        user = self.admin.user_by_name(p.username)
        if not user:
            self.row("FAIL", p.username, "missing in Duo: run provision_personas.py")
            return
        if not self.owned(p, user):
            return
        status = str(user.get("status"))
        if status != "active":
            if self.dry:
                self.row("PLAN", p.username, f"{status} -> active")
            else:
                self.admin.set_status(str(user["user_id"]), "active")
                self.row("CHANGED", p.username, f"{status} -> active (re-enabled / unlocked)")
        tokens = [t for t in (user.get("tokens") or []) if t.get("serial") == self.cast.token_serial(p)]
        secret_text = self.keychain.get(self.cast.keychain_item(p))
        if not tokens or not secret_text or not self.state.counter(p.username):
            self.row("FAIL", p.username, "no HOTP token, Keychain secret or counter to resync: provision it again")
            return
        if self.dry:
            self.row("PLAN", p.username, "resync its HOTP token to the Mac's counter")
            return
        secret = duo.decode_secret(secret_text, self.cast.secret_encoding)
        first = self.state.reserve(p.username, 3)
        self.admin.resync_token(str(tokens[0]["token_id"]), [duo.hotp(secret, first + i) for i in range(3)])
        self.row("CHANGED", p.username, f"HOTP token resynced; next counter {first + 3}")

    # ------------------------------------------------------------------ teardown
    def teardown(self, p: Persona, yes: bool) -> None:
        user = self.admin.user_by_name(p.username)
        if user and not self.owned(p, user):
            return
        tokens = self.tokens(p, user or {})
        item = self.cast.keychain_item(p)
        what = ", ".join(filter(None, ["user" if user else "", f"{len(tokens)} HOTP token(s)" if tokens else "",
                                       f"Keychain item {item}", "counter"]))
        if self.dry or not yes:
            self.row("PLAN", p.username, f"delete {what}")
            return
        for token in tokens:
            self.admin.delete_token(str(token["token_id"]))
        if user:
            self.admin.delete_user(str(user["user_id"]))
        self.keychain.delete(item)
        self.state.forget(p.username)
        self.row("CHANGED", p.username, f"deleted {what}")


def main(argv: Optional[Sequence[str]] = None, deps: Optional[Deps] = None) -> int:
    deps = deps or Deps()
    ap = argparse.ArgumentParser(prog="provision_personas.py", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--status", action="store_true", help="read-only: each persona's state")
    mode.add_argument("--reset", action="store_true", help="re-enable, unlock and resync the HOTP tokens")
    mode.add_argument("--teardown", action="store_true", help="delete the cast (needs --yes)")
    ap.add_argument("--yes", action="store_true", help="--teardown: really delete (permanent, skips Duo's Trash)")
    ap.add_argument("--only", default="", help="comma list of persona usernames")
    ap.add_argument("--dry-run", action="store_true", help="print what would change, change nothing")
    ap.add_argument("--cast", type=Path, default=DEFAULT_CAST, help="the persona cast (personas.yaml)")
    args = ap.parse_args(argv)
    out = deps.out or sys.stdout
    root = Path(deps.state_root or StateStore.default_root())
    redactor = Redactor()
    try:
        cast = load_cast(args.cast)
        chosen = cast.personas
        if args.only:
            chosen = [cast.get(u.strip()) for u in args.only.split(",") if u.strip()]
    except Lab5Error as exc:
        print(f"provision_personas: {exc}", file=out)
        return 2
    private_dir(root)
    mode_name = "status" if args.status else "reset" if args.reset else "teardown" if args.teardown else "provision"
    reporter = Reporter(redactor, out=out, log_path=root / "personas" / "runs" / f"{utc_stamp()}-{mode_name}.log")
    keychain = make_keychain(redactor, deps)
    try:
        admin = duo.admin_api(keychain, deps.duo_transport)
        run = Run(cast, admin, keychain, PersonaState(root), reporter, args.dry_run)
        reporter.line(f"provision_personas {mode_name}{' --dry-run' if args.dry_run else ''}: "
                      f"{len(chosen)} persona(s), group {cast.group!r}, Duo {admin.host}, at {utc_now()}")
        if args.status:
            for p in chosen:
                run.status(p)
        elif args.reset:
            for p in chosen:
                run.reset(p)
            reporter.line(STEP_UP_NOTE)
        elif args.teardown:
            for p in chosen:
                run.teardown(p, args.yes)
            if not args.yes and not args.dry_run:
                reporter.line("Nothing deleted: deleting through the API is immediate and permanent. "
                              "Re-run with --teardown --yes")
                return 1
            reporter.line(f"Group {cast.group!r} kept: every lab app is limited to it. {STEP_UP_NOTE}")
        else:
            group_id = run.group_id()
            for p in chosen:
                run.ensure(p, group_id)
        reporter.line(f"RESULT: {mode_name}: {run.failed} failed")
        return 1 if run.failed else 0
    except Lab5Error as exc:
        reporter.line(f"provision_personas: {exc}")
        return 2
    finally:
        reporter.close()


if __name__ == "__main__":
    sys.exit(main())
