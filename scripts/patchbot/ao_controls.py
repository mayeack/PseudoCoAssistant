"""Create, update and check PatchBot's controls in Splunk Agent Observability.

The control definitions live in ``backend/patchbot/controls.py``
(``CONTROL_DEFINITIONS``), the same ones PatchBot's local mode evaluates, so
what attendees read in the Controls UI is what the offline mode runs.

    venv/bin/python scripts/patchbot/ao_controls.py plan       # print the definitions
    venv/bin/python scripts/patchbot/ao_controls.py validate   # server-side validation, no writes
    venv/bin/python scripts/patchbot/ao_controls.py apply      # create or update, bind to the stream
    venv/bin/python scripts/patchbot/ao_controls.py adopt      # give UI-attached copies the canonical names
    venv/bin/python scripts/patchbot/ao_controls.py status     # what is bound to the PatchBot stream
    venv/bin/python scripts/patchbot/ao_controls.py probe      # one deny and one allow, live

Uses the app's own Agent Control client and credentials (the splunk_ao backend:
``SPLUNK_AO_CONTROL_TOKEN`` with the agent_observability_admin role), so run it
with the box's environment. The PatchBot Agent stream must exist: it is created
by the first PatchBot trace (run the full read once). Idempotent: a control that
already exists by name is updated in place, never duplicated.

Attaching is the one step the API cannot do on us1 (2026-11-18):
``clone-and-bind`` answers 502 AUTH_UPSTREAM_REJECTED for the API token and a
signed-in browser session alike, and ``POST /control-bindings`` answers 405.
So after ``apply``, attach each control from the PatchBot stream's Controls tab
(Add control, Clone and attach), then run ``adopt``. The UI names each copy
``<name>-clone-<hex>``, and control names are unique, so ``adopt`` renames the
unattached library original to ``<name>-template`` and the attached copy to the
canonical name: PatchBot's sentinel, the TA's ES rules and its dashboards
match control names. ``apply`` then updates the attached copies in place.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from backend.config import settings  # noqa: E402
from backend.patchbot import controls  # noqa: E402
from backend.services.agent_control import agent_control_client as client  # noqa: E402

STREAM = settings.patchbot_agent_stream or "PatchBot"

try:  # the Settings page's integration credentials (the Controls token lives there on a box)
    from backend import settings_store  # noqa: E402
    settings_store.apply_integration_creds_from_store()
except Exception as _exc:  # noqa: BLE001
    print(f"note: could not load integration settings from the database ({_exc})")


def _h() -> Dict[str, str]:
    return client._management_headers()


def _url(path: str) -> str:
    return f"{client.control_url}/api/v1{path}"


def _show(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text[:500]


def _all_controls() -> List[Dict[str, Any]]:
    out, cursor = [], None
    for _ in range(50):
        params: Dict[str, Any] = {"limit": 100}
        if cursor is not None:
            params["cursor"] = cursor
        r = httpx.get(_url("/controls"), params=params, headers=_h(), timeout=20)
        r.raise_for_status()
        body = r.json() or {}
        items = body.get("controls") if isinstance(body, dict) else body
        out.extend(i for i in (items or []) if isinstance(i, dict))
        nxt = (body.get("next_cursor") or (body.get("pagination") or {}).get("next_cursor")) if isinstance(body, dict) else None
        if not nxt or nxt == cursor:
            break
        cursor = nxt
    return out


def _target() -> Dict[str, str]:
    return client.target_for_stream(STREAM)


def _bound_ids(target: Dict[str, str]) -> List[int]:
    r = httpx.get(_url("/control-bindings"), params={"target_type": target["target_type"],
                                                    "target_id": target["target_id"]}, headers=_h(), timeout=20)
    r.raise_for_status()
    body = r.json() or {}
    rows = body.get("bindings") if isinstance(body, dict) else body
    ids = []
    for row in rows or []:
        if isinstance(row, dict):
            cid = row.get("control_id") or (row.get("control") or {}).get("id")
            if cid is not None:
                ids.append(int(cid))
    return ids


def cmd_plan() -> int:
    print(json.dumps(controls.CONTROL_DEFINITIONS, indent=1))
    return 0


def cmd_validate() -> int:
    bad = 0
    for c in controls.CONTROL_DEFINITIONS:
        r = httpx.post(_url("/controls/validate"), json={"data": c["data"]}, headers=_h(), timeout=20)
        ok = r.status_code < 300
        bad += 0 if ok else 1
        print(f"{'ok ' if ok else 'BAD'} {c['name']}: HTTP {r.status_code} {json.dumps(_show(r))[:300]}")
    return 1 if bad else 0


def _bind(control_id: int, name: str, target: Dict[str, str]) -> Optional[int]:
    """Bind a library control to the stream; returns the id that ends up bound."""
    body = {"control_id": control_id, "target_type": target["target_type"], "target_id": target["target_id"]}
    r = httpx.post(_url("/control-bindings"), json=body, headers=_h(), timeout=20)
    if r.status_code < 300:
        return control_id
    print(f"   control-bindings POST answered HTTP {r.status_code}; using clone-and-bind (what the UI does)")
    r = httpx.post(_url(f"/controls/{control_id}/clone-and-bind"),
                   json={"target_type": target["target_type"], "target_id": target["target_id"]},
                   headers=_h(), timeout=20)
    if r.status_code >= 300:
        print(f"   clone-and-bind failed: HTTP {r.status_code} {json.dumps(_show(r))[:300]}")
        return None
    data = _show(r) or {}
    clone = data.get("control_id") or data.get("id") or (data.get("control") or {}).get("id")
    if clone:
        _take_name(int(clone), name, _all_controls(), [int(clone)])
    return int(clone) if clone else None


def _take_name(control_id: int, name: str, library: List[Dict[str, Any]], attached: List[int]) -> bool:
    """Give an attached control the canonical name. Names are unique, so an
    unattached library control holding it becomes ``<name>-template`` first."""
    for c in library:
        cid = int(c.get("id") or c.get("control_id") or -1)
        if c.get("name") == name and cid != control_id:
            if cid in attached:
                print(f"   {name} is already attached as #{cid}; leaving #{control_id} as it is")
                return False
            r = httpx.patch(_url(f"/controls/{cid}"), json={"name": f"{name}-template"}, headers=_h(), timeout=20)
            print(f"   library #{cid} {name} -> {name}-template: HTTP {r.status_code}")
    r = httpx.patch(_url(f"/controls/{control_id}"), json={"name": name}, headers=_h(), timeout=20)
    print(f"   attached #{control_id} -> {name}: HTTP {r.status_code}")
    return r.status_code < 300


def cmd_adopt() -> int:
    """After Clone and attach in the UI: canonical names on the attached copies."""
    target = _target()
    attached = _bound_ids(target)
    library = _all_controls()
    names = {int(c.get("id") or c.get("control_id") or -1): c.get("name") or "" for c in library}
    bad = 0
    for c in controls.CONTROL_DEFINITIONS:
        name = c["name"]
        mine = [cid for cid in attached if names.get(cid) == name]
        if mine:
            print(f"ok  {name} is attached as #{mine[0]}")
            continue
        copies = [cid for cid in attached if names.get(cid, "").startswith(f"{name}-clone-")]
        if not copies:
            print(f"MISSING {name}: attach it in the UI (PatchBot stream > Controls > Add control > Clone and attach)")
            bad += 1
            continue
        bad += 0 if _take_name(copies[0], name, library, attached) else 1
    return 1 if bad else 0


def cmd_apply() -> int:
    target = _target()
    print(f"PatchBot Agent stream {STREAM!r} -> {target['target_type']} {target['target_id']}")
    existing = {c.get("name"): c for c in _all_controls()}
    bound = set(_bound_ids(target))
    failures = 0
    for c in controls.CONTROL_DEFINITIONS:
        name = c["name"]
        hit = existing.get(name)
        if hit is not None:
            cid = int(hit.get("id") or hit.get("control_id"))
            r = httpx.put(_url(f"/controls/{cid}/data"), json={"data": c["data"]}, headers=_h(), timeout=20)
            print(f"updated {name} (#{cid}): HTTP {r.status_code}")
        else:
            r = httpx.put(_url("/controls"), json={"name": name, "data": c["data"]}, headers=_h(), timeout=20)
            if r.status_code >= 300:
                failures += 1
                print(f"CREATE FAILED {name}: HTTP {r.status_code} {json.dumps(_show(r))[:300]}")
                continue
            cid = int((_show(r) or {}).get("control_id"))
            print(f"created {name} (#{cid})")
        if cid not in bound:
            got = _bind(cid, name, target)
            print(f"   bound {name} as #{got}" if got else f"   BIND FAILED {name}")
            failures += 0 if got else 1
        else:
            print(f"   already bound to {STREAM}")
    return 1 if failures else 0


def cmd_status() -> int:
    target = _target()
    ids = set(_bound_ids(target))
    names = {int(c.get("id") or c.get("control_id") or -1): c.get("name") for c in _all_controls()}
    print(f"{STREAM}: {len(ids)} bound control(s)")
    for cid in sorted(ids):
        print(f"  #{cid} {names.get(cid, '?')}")
    wanted = {c["name"] for c in controls.CONTROL_DEFINITIONS}
    missing = wanted - {names.get(i) for i in ids}
    if missing:
        print("missing:", ", ".join(sorted(missing)))
    return 1 if missing else 0


def cmd_probe() -> int:
    base = {"app": "pseudoco-assistant", "feature": "patchbot", "estate_owner": "probe", "initiator": "probe"}
    cases = [
        ("apply_patch", {"server": "win-stg-01", "cve": "CVE-2021-34527", "os_family": "windows",
                         "environment": "staging"}, dict(base, initiator_role="linux_patch_operator"), "deny"),
        ("apply_patch", {"server": "web-stg-01", "cve": "CVE-2021-41773", "os_family": "linux",
                         "environment": "staging"}, dict(base, initiator_role="linux_patch_operator"), "observe"),
        ("stop_service", {"server": "web-prod-01", "service": "edr-agent"}, dict(base, initiator_role="estate_owner"),
         "deny"),
    ]
    bad = 0
    for tool, inp, ctx, want in cases:
        settings.patchbot_controls_mode = "agent_observability"
        v = controls.decide(tool, inp, ctx)
        ok = v.decision == want
        bad += 0 if ok else 1
        print(f"{'ok ' if ok else 'BAD'} {tool} {inp.get('os_family', '')} as {ctx['initiator_role']}: "
              f"{v.decision} {v.controls_matched} errored={v.errored} {v.error_message or ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    cmds = {"plan": cmd_plan, "validate": cmd_validate, "apply": cmd_apply, "adopt": cmd_adopt,
            "status": cmd_status, "probe": cmd_probe}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        print(__doc__)
        sys.exit(2)
    sys.exit(cmds[sys.argv[1]]())
