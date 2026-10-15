"""Tiny Agent Observability REST helper for this session's provisioning work.

Token: the Agent Control token saved on the app's Settings page
(medadvice.db app_settings.data -> integration_creds.agent_observability.
splunk_ao_control_token), an O11y API token with the agent_observability_admin
role. Read in-process only; never printed.
"""
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
os.chdir(Path(__file__).resolve().parents[3])
import backend.config  # noqa: E402,F401  (sets the corp CA bundle env)
import httpx  # noqa: E402

REALM = os.getenv("SPLUNK_AO_REALM", "us1")
BASE = f"https://app.{REALM}.observability.splunkcloud.com/ao/api"
AC_BASE = f"https://app.{REALM}.observability.splunkcloud.com/ao/agent-control"


def token() -> str:
    con = sqlite3.connect(Path(__file__).resolve().parents[3] / "medadvice.db")
    try:
        for (raw,) in con.execute("select data from app_settings"):
            data = json.loads(raw) if isinstance(raw, str) else raw
            tok = (((data or {}).get("integration_creds") or {}).get("agent_observability") or {}).get(
                "splunk_ao_control_token")
            if tok:
                return tok
    finally:
        con.close()
    tok = os.getenv("SPLUNK_AO_CONTROL_TOKEN", "")
    if not tok:
        raise SystemExit("no AO control token found")
    return tok


_client = None


def client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(headers={"X-SF-Token": token(), "Content-Type": "application/json"},
                               timeout=60.0)
    return _client


def req(method: str, path: str, body=None, base: str = BASE, params=None):
    r = client().request(method, base + path, json=body, params=params)
    try:
        payload = r.json()
    except ValueError:
        payload = r.text
    return r.status_code, payload


def project_id(name: str = "PseudoCo Assistant") -> str:
    code, data = req("GET", "/projects", params={"project_name": name, "type": "gen_ai"})
    if code != 200:
        raise SystemExit(f"projects -> {code} {str(data)[:200]}")
    items = data if isinstance(data, list) else data.get("projects", data)
    for p in items:
        if p.get("name") == name:
            return p["id"]
    raise SystemExit(f"project {name!r} not found")
