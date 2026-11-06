"""In-memory Duo (Admin API + Auth API), Keychain and CII for the Lab 5 tool tests.

Not a suite (tests/run_all.sh does not run it): tests/test_lab5_participants.py
and tests/test_identity_personas.py import it. Nothing here opens a socket,
runs `security` or reads a real Keychain item.

FakeDuo answers the calls the tools make through duo_client's
``json_api_call`` / ``json_paging_api_call`` signatures, keeps users, groups and
HOTP tokens like Duo does (a token's secret is kept to verify passcodes; HOTP
accepts a code at or ahead of the token's counter within a look-ahead window,
then moves the counter past it; 10 failures in a row lock a user out), and
records every call so the tests can pin what was sent where.
"""
from __future__ import annotations

import itertools
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "lab5"))
import lab5_duo as duo  # noqa: E402

API_HOST = "api-xxxxxxxx.duosecurity.com"
PROVISIONER = {"ikey": "DIPROVISIONERIKEY001", "skey": "prov-skey-6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d"}
VPN = {"ikey": "DIVPNAUTHAPIIKEY0002", "skey": "vpn-skey-0f1e2d3c4b5a69788796a5b4c3d2e1f0"}
CII = {"client_id": "cii-client-id-77aa", "client_secret": "cii-secret-QWERTY-1234567890-zxcvb",
       "token_url": "https://login.oort.example/oauth/token", "api_url": "https://api.oort.example/graphql"}
KEYCHAIN_SECRETS = {
    "pseudoco-lab5-duo-provisioner-ikey": PROVISIONER["ikey"],
    "pseudoco-lab5-duo-provisioner-skey": PROVISIONER["skey"],
    "pseudoco-lab5-duo-vpn-ikey": VPN["ikey"],
    "pseudoco-lab5-duo-vpn-skey": VPN["skey"],
    "pseudoco-lab5-duo-api-host": API_HOST,
    "pseudoco-lab5-cii-client-id": CII["client_id"],
    "pseudoco-lab5-cii-client-secret": CII["client_secret"],
    "pseudoco-lab5-cii-token-url": CII["token_url"],
    "pseudoco-lab5-cii-api-url": CII["api_url"],
}
LOOKAHEAD = 10
LOCKOUT = 10


class DuoFailure(RuntimeError):
    """Shaped like duo_client's RuntimeError: .status and .data."""

    def __init__(self, status: int, code: int, message: str) -> None:
        super().__init__(f"Received {status} {message}")
        self.status = status
        self.data = json.dumps({"stat": "FAIL", "code": code, "message": message}).encode()


class FakeDuo:
    def __init__(self, clock: Callable[[], float]) -> None:
        self.clock = clock
        self.users: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, str, str, Dict[str, str]]] = []   # (kind, method, path, params)
        self.transports: List[Tuple[str, str, str, str]] = []
        self.fail: Dict[Tuple[str, str], DuoFailure] = {}            # (method, path prefix) -> error
        self.pushes: Dict[str, Dict[str, Any]] = {}
        self.push_answer = "deny"
        self._ids = itertools.count(1)
        self.add_group("CII Read-Only", "Identity Intelligence read-only (auto-created)")

    # ------------------------------------------------------------------ setup helpers
    def _id(self, prefix: str) -> str:
        return f"{prefix}{next(self._ids):010d}"

    def add_group(self, name: str, desc: str = "") -> Dict[str, Any]:
        gid = self._id("DG")
        self.groups[gid] = {"group_id": gid, "name": name, "desc": desc, "status": "active"}
        return self.groups[gid]

    def add_user(self, username: str, notes: str = "", groups: Tuple[str, ...] = (), created: Optional[float] = None,
                 status: str = "active", email: str = "") -> Dict[str, Any]:
        uid = self._id("DU")
        self.users[uid] = {"user_id": uid, "username": username, "email": email, "realname": "", "notes": notes,
                           "status": status, "created": int(created if created is not None else self.clock()),
                           "has_password": False, "is_enrolled": False, "groups": [], "tokens": [],
                           "fails": 0, "firstname": "", "lastname": ""}
        for name in groups:
            group = next((g for g in self.groups.values() if g["name"] == name), None) or self.add_group(name)
            self.users[uid]["groups"].append(dict(group))
        return self.users[uid]

    def by_name(self, username: str) -> Optional[Dict[str, Any]]:
        return next((u for u in self.users.values() if u["username"] == username), None)

    def mutations(self) -> List[Tuple[str, str, str]]:
        return [(k, m, p) for k, m, p, _ in self.calls if m != "GET" and not p.startswith("/auth/")]

    # ------------------------------------------------------------------ duo_client surface
    def transport(self, kind: str, ikey: str, skey: str, host: str) -> "FakeClient":
        self.transports.append((kind, ikey, skey, host))
        return FakeClient(self, kind, ikey, skey, host)

    def _view(self, user: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: v for k, v in user.items() if k != "fails"}
        out["groups"] = [dict(g) for g in user["groups"]]
        out["tokens"] = [{"token_id": t, "serial": self.tokens[t]["serial"], "type": "h6"}
                         for t in user["tokens"] if t in self.tokens]
        return out

    def handle(self, kind: str, method: str, path: str, params: Dict[str, str]) -> Any:
        for value in params.values():
            assert isinstance(value, str), f"duo_client sends str params, got {type(value).__name__} for {path}"
        self.calls.append((kind, method, path, dict(params)))
        for (m, prefix), err in list(self.fail.items()):
            if m == method and path.startswith(prefix):
                raise err
        if path.startswith("/auth/"):
            assert kind == "auth", f"{path} called with the {kind} keys"
            return self._auth(method, path, params)
        assert kind == "admin", f"{path} called with the {kind} keys"
        return self._admin(method, path, params)

    def _user(self, uid: str) -> Dict[str, Any]:
        if uid not in self.users:
            raise DuoFailure(404, 40401, "Resource not found")
        return self.users[uid]

    def _admin(self, method: str, path: str, p: Dict[str, str]) -> Any:
        parts = path.strip("/").split("/")[2:]          # after admin/v1
        if parts == ["users"]:
            if method == "GET":
                users = list(self.users.values())
                if "username" in p:
                    users = [u for u in users if u["username"] == p["username"]]
                return [self._view(u) for u in users]
            if self.by_name(p["username"]):
                raise DuoFailure(400, 40003, "Duplicate resource")
            user = self.add_user(p["username"], notes=p.get("notes", ""), email=p.get("email", ""),
                                 status=p.get("status", "active"))
            user.update(realname=p.get("realname", ""), firstname=p.get("firstname", ""),
                        lastname=p.get("lastname", ""))
            return self._view(user)
        if parts[:1] == ["users"] and len(parts) == 2:
            user = self._user(parts[1])
            if method == "DELETE":
                del self.users[parts[1]]                 # tokens stay, unassigned (as in Duo)
                return ""
            if "status" in p:
                user["status"] = p["status"]
                if p["status"] == "active":
                    user["fails"] = 0
            return self._view(user)
        if parts[:1] == ["users"] and parts[2:] == ["groups"]:
            user = self._user(parts[1])
            if method == "GET":
                return [dict(g) for g in user["groups"]]
            group = self.groups[p["group_id"]]
            if all(g["group_id"] != group["group_id"] for g in user["groups"]):
                user["groups"].append(dict(group))
            return ""
        if parts[:1] == ["users"] and parts[2:] == ["tokens"]:
            user = self._user(parts[1])
            if method == "GET":
                return [{"token_id": t, "serial": self.tokens[t]["serial"], "type": "h6"} for t in user["tokens"]]
            tid = p["token_id"]
            if tid not in self.tokens:
                raise DuoFailure(404, 40401, "Resource not found")
            if tid not in user["tokens"]:
                user["tokens"].append(tid)
            self.tokens[tid]["user"] = user["user_id"]
            return ""
        if parts == ["groups"]:
            if method == "GET":
                return [dict(g) for g in self.groups.values()]
            if any(g["name"] == p["name"] for g in self.groups.values()):
                raise DuoFailure(400, 40003, "Duplicate resource")
            return dict(self.add_group(p["name"], p.get("desc", "")))
        if parts == ["tokens"]:
            if method == "GET":
                found = [t for t in self.tokens.values()
                         if t["type"] == p.get("type") and t["serial"] == p.get("serial")]
                return [{"token_id": t["token_id"], "serial": t["serial"], "type": "h6",
                         "users": [{"user_id": u["user_id"], "username": u["username"]}
                                   for u in self.users.values() if t["token_id"] in u["tokens"]]} for t in found]
            assert p["type"] == "h6" and p["secret"] and p["serial"]
            if any(t["serial"] == p["serial"] for t in self.tokens.values()):
                raise DuoFailure(400, 40003, "Duplicate resource")
            tid = self._id("DH")
            self.tokens[tid] = {"token_id": tid, "type": "h6", "serial": p["serial"], "secret_text": p["secret"],
                                "counter": int(p.get("counter", "0")), "user": None}
            return {"token_id": tid, "serial": p["serial"], "type": "h6"}
        if parts[:1] == ["tokens"] and len(parts) == 2 and method == "DELETE":
            self.tokens.pop(parts[1], None)
            for user in self.users.values():
                if parts[1] in user["tokens"]:
                    user["tokens"].remove(parts[1])
            return ""                                   # 200 whether or not it existed
        if parts[:1] == ["tokens"] and parts[2:] == ["resync"]:
            token = self.tokens[parts[1]]
            secret = duo.decode_secret(token["secret_text"], "hex")
            codes = [p["code1"], p["code2"], p["code3"]]
            for c in range(token["counter"], token["counter"] + 1000):
                if [duo.hotp(secret, c + i) for i in range(3)] == codes:
                    token["counter"] = c + 3
                    return ""
            raise DuoFailure(400, 40002, "Invalid request parameters (resync)")
        raise AssertionError(f"unexpected Admin API call {method} {path}")

    # ------------------------------------------------------------------ auth
    def _auth_user(self, p: Dict[str, str]) -> Optional[Dict[str, Any]]:
        return self.by_name(p.get("username", ""))

    def _auth(self, method: str, path: str, p: Dict[str, str]) -> Any:
        assert "client_supports_verified_push" not in p, "client_supports_verified_push must never be sent"
        if path == "/auth/v2/check":
            return {"time": int(self.clock())}
        if path == "/auth/v2/auth_status":
            return self.pushes[p["txid"]]
        assert p.get("ipaddr") and p.get("hostname"), f"{path} without ipaddr/hostname"
        user = self._auth_user(p)
        if path == "/auth/v2/preauth":
            if not user or user["status"] != "active":
                return {"result": "deny", "status_msg": f"user is {user['status'] if user else 'unknown'}"}
            devices = [{"device": "DPHONE01", "capabilities": ["push"]}] if user.get("phone") else []
            devices += [{"device": "token", "capabilities": ["mobile_otp"]}] if user["tokens"] else []
            return {"result": "auth", "status_msg": "Account is active", "devices": devices}
        assert path == "/auth/v2/auth", path
        if not user or user["status"] != "active":
            return {"result": "deny", "status": "locked_out" if user and user["status"] == "locked out" else "deny",
                    "status_msg": "Your account is disabled." if user else "Unknown user"}
        if p["factor"] == "push":
            txid = self._id("TX")
            self.pushes[txid] = {"result": self.push_answer, "status": self.push_answer, "status_msg": "pushed"}
            return {"txid": txid}
        assert p["factor"] == "passcode" and p.get("async") == "0"
        for tid in user["tokens"]:
            token = self.tokens[tid]
            secret = duo.decode_secret(token["secret_text"], "hex")
            for c in range(token["counter"], token["counter"] + LOOKAHEAD):
                if duo.hotp(secret, c) == p["passcode"]:
                    token["counter"] = c + 1
                    user["fails"] = 0
                    return {"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."}
        user["fails"] += 1
        if user["fails"] >= LOCKOUT:
            user["status"] = "locked out"
            return {"result": "deny", "status": "locked_out", "status_msg": "Your account is locked out."}
        return {"result": "deny", "status": "deny", "status_msg": "Incorrect passcode. Please try again."}

    def token_secret(self, serial: str) -> bytes:
        token = next(t for t in self.tokens.values() if t["serial"] == serial)
        return duo.decode_secret(token["secret_text"], "hex")


class FakeClient:
    def __init__(self, duo_: FakeDuo, kind: str, ikey: str, skey: str, host: str) -> None:
        self.duo, self.kind = duo_, kind
        expected = PROVISIONER if kind == "admin" else VPN
        assert (ikey, skey) == (expected["ikey"], expected["skey"]), f"{kind} client built with the wrong keys"
        assert host == API_HOST, host

    def json_api_call(self, method: str, path: str, params: Dict[str, str]) -> Any:
        return self.duo.handle(self.kind, method, path, params)

    def json_paging_api_call(self, method: str, path: str, params: Dict[str, str]):
        result = self.duo.handle(self.kind, method, path, params)
        for item in result:
            yield item


class FakeKeychain:
    """Stands in for /usr/bin/security: find, delete, and `security -i` writes."""

    def __init__(self, items: Optional[Dict[str, str]] = None) -> None:
        self.items = dict(KEYCHAIN_SECRETS if items is None else items)
        self.argv: List[List[str]] = []
        self.stdin: List[str] = []

    def runner(self, argv):
        self.argv.append(list(argv))
        item = argv[argv.index("-s") + 1]
        if argv[1] == "find-generic-password":
            if item in self.items:
                return subprocess.CompletedProcess(argv, 0, self.items[item] + "\n", "")
            return subprocess.CompletedProcess(argv, 44, "", "could not be found\n")
        if argv[1] == "delete-generic-password":
            found = self.items.pop(item, None) is not None
            return subprocess.CompletedProcess(argv, 0 if found else 44, "", "")
        raise AssertionError(f"unexpected security call {argv[:2]}")

    def stdin_runner(self, argv, stdin):
        self.argv.append(list(argv))
        self.stdin.append(stdin)
        assert argv == ["security", "-i"], argv
        words = stdin.strip().split()
        assert words[0] == "add-generic-password" and "-U" in words, words
        self.items[words[words.index("-s") + 1]] = words[words.index("-w") + 1]
        return subprocess.CompletedProcess(argv, 0, "", "")


class FakeCII:
    """The CII token endpoint and getEndUser, behind the (method, url, headers,
    body, timeout) transport the tools use."""

    def __init__(self) -> None:
        self.users: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, str, Dict[str, str], Dict[str, Any]]] = []
        self.token_requests = 0
        self.shape = "strings"        # or "objects"
        self.graphql_error = ""

    def __call__(self, method, url, headers, body, timeout):
        doc = json.loads(body or b"{}")
        self.calls.append((method, url, dict(headers), doc))
        if url == CII["token_url"]:
            self.token_requests += 1
            if doc != {"client_id": CII["client_id"], "client_secret": CII["client_secret"],
                       "grant_type": "client_credentials"}:
                return 401, b'{"error":"invalid_client"}'
            return 200, json.dumps({"access_token": "cii-access-token-abcdef123456", "expires_in": 36000}).encode()
        assert url == CII["api_url"], url
        if headers.get("Authorization") != "Bearer cii-access-token-abcdef123456":
            return 401, b"{}"
        if self.graphql_error:
            return 200, json.dumps({"errors": [{"message": self.graphql_error}]}).encode()
        login = doc["variables"]["login"]
        user = self.users.get(login)
        if user is None:
            return 200, json.dumps({"data": {"getEndUser": None}}).encode()
        checks = user.get("failing", [])
        if self.shape == "objects":
            payload = {"levelOfTrust": {"level": user.get("trust", "UNKNOWN")},
                       "failingChecks": [{"name": c} for c in checks]}
        else:
            payload = {"levelOfTrust": user.get("trust", "UNKNOWN"), "failingChecks": checks}
        return 200, json.dumps({"data": {"getEndUser": payload}}).encode()


class Clock:
    def __init__(self, start: float) -> None:
        self.t = start
        self.slept: List[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds

    def advance_days(self, days: float) -> None:
        self.t += days * 86400.0
