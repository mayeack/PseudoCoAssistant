"""Cisco MCP Scanner for PatchBot's MCP servers (docs/patchbot.md, "MCP Scanner").

Each server's ``tools/list`` catalogue (``mcp_servers.tools_for``) is handed to
Cisco's open-source scanner (PyPI ``cisco-ai-mcp-scanner``) in its offline
``static`` mode, so no access key ever goes on a command line and the scan sees
exactly what the MCP endpoint serves. The yara analyzer runs offline; the llm
analyzer runs on the box's Ollama; the AI Defense ``api`` analyzer joins when
an AI Defense key is configured and ``api`` is in PATCHBOT_MCP_SCANNER_ANALYZERS.

What a scan decides: PatchBot connects the third-party vendor server only
after a clean scan of its current catalogue (a changed description voids the
scan: a rug pull). Findings on PatchBot's own tools are shown with the control
that already denies them at runtime for every role (deny-restricted-tools).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.patchbot import controls, mcp_servers, store, telemetry
from backend.patchbot.run import Run

_SEVERITY = ["SAFE", "INFO", "UNKNOWN", "LOW", "MEDIUM", "HIGH"]
CONNECT_ROLES = frozenset({"linux_patch_operator", "windows_patch_operator", "estate_owner"})


class ScannerUnavailable(RuntimeError):
    pass


def scanner_cmd() -> Optional[str]:
    configured = (settings.patchbot_mcp_scanner_cmd or "").strip()
    if configured:
        return configured if (os.path.exists(configured) or shutil.which(configured)) else None
    found = shutil.which("mcp-scanner")
    if found:
        return found
    beside_venv = Path(sys.prefix).parent / ".venv-mcp-scanner" / "bin" / "mcp-scanner"
    return str(beside_venv) if beside_venv.exists() else None


def analyzers() -> List[str]:
    wanted = [a.strip() for a in (settings.patchbot_mcp_scanner_analyzers or "yara").split(",") if a.strip()]
    if "api" in wanted and not (settings.ai_defense_api_key or "").strip():
        wanted.remove("api")
    return wanted or ["yara"]


def _env(selected: List[str]) -> Dict[str, str]:
    """A minimal environment: the app's own secrets never reach the scanner."""
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR") if k in os.environ}
    if "llm" in selected:
        env.update(MCP_SCANNER_LLM_API_KEY="ollama", MCP_SCANNER_LLM_BASE_URL=settings.ollama_base_url,
                   MCP_SCANNER_LLM_MODEL=f"ollama/{settings.patchbot_ollama_model}", MCP_SCANNER_LLM_TIMEOUT="90")
    if "api" in selected:
        env["MCP_SCANNER_API_KEY"] = settings.ai_defense_api_key
        region = (settings.ai_defense_region or "us").strip().lower()
        env["MCP_SCANNER_ENDPOINT"] = (settings.ai_defense_endpoint or
                                       f"https://{region}.api.inspect.aidefense.security.cisco.com/api/v1")
    return env


def run_scanner(catalogue: Dict[str, Any]) -> Dict[str, Any]:
    """One static scan of a tools/list catalogue; the scanner's raw JSON."""
    cmd = scanner_cmd()
    if not cmd:
        raise ScannerUnavailable("Cisco MCP Scanner is not installed (pip install cisco-ai-mcp-scanner).")
    selected = analyzers()
    with tempfile.TemporaryDirectory(prefix="pb-mcpscan-") as tmp:
        path = Path(tmp) / "tools.json"
        path.write_text(json.dumps(catalogue))
        proc = subprocess.run([cmd, "--analyzers", ",".join(selected), "--format", "raw", "static",
                               "--tools", str(path)], capture_output=True, text=True, cwd=tmp,
                              env=_env(selected), timeout=settings.patchbot_mcp_scanner_timeout_s)
    if proc.returncode != 0:
        raise RuntimeError(f"mcp-scanner exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
    out = proc.stdout
    start = out.find("{")
    return json.loads(out[start:]) if start >= 0 else {}


def _rank(severity: str) -> int:
    s = str(severity or "SAFE").upper()
    return _SEVERITY.index(s) if s in _SEVERITY else 2


def compensating() -> Dict[str, str]:
    """Tools a deny control refuses for every role: the runtime answer to a finding."""
    out: Dict[str, str] = {}
    for c in controls.CONTROL_DEFINITIONS:
        data, cond = c["data"], c["data"]["condition"]
        if (data["action"]["decision"] == "deny" and (cond.get("selector") or {}).get("path") == "context.initiator_role"
                and (cond.get("evaluator") or {}).get("name") == "regex"):
            for step in data["scope"]["step_names"]:
                out[step] = c["name"]
    return out


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    comp = compensating()
    tools: List[Dict[str, Any]] = []
    for item in raw.get("scan_results") or []:
        if item.get("item_type", "tool") != "tool":
            continue
        per, threats, taxonomies, worst = {}, set(), [], "SAFE"
        for key, f in (item.get("findings") or {}).items():
            name, sev = key.replace("_analyzer", ""), str(f.get("severity") or "SAFE").upper()
            per[name] = {"severity": sev, "threats": list(f.get("threat_names") or []),
                         "summary": f.get("threat_summary") or ""}
            threats.update(per[name]["threats"])
            worst = sev if _rank(sev) > _rank(worst) else worst
            taxonomies += [{k: t.get(k) for k in ("scanner_category", "aitech", "aitech_name", "aisubtech",
                                                     "aisubtech_name")} for t in f.get("mcp_taxonomies") or []]
        name = item.get("tool_name") or ""
        safe = bool(item.get("is_safe", True))
        tools.append({"tool": name, "is_safe": safe, "severity": worst, "threats": sorted(threats),
                      "analyzers": per, "taxonomies": taxonomies,
                      "compensated_by": None if safe else comp.get(name)})
    worst_all = max((t["severity"] for t in tools), key=_rank, default="SAFE")
    return {"is_safe": all(t["is_safe"] for t in tools), "severity": worst_all, "tools": tools,
            "analyzers_requested": list(raw.get("requested_analyzers") or []),
            "analyzers_ran": sorted({a for t in tools for a in t["analyzers"]})}


def catalogue_sha(tools: List[Dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- state per estate owner

def vendor_state(state: Dict[str, Any]) -> Dict[str, Any]:
    return state.setdefault("vendor_mcp", {"poisoned": False, "connected": False, "forced": False})


def current_tools(state: Dict[str, Any], server_id: str) -> List[Dict[str, Any]]:
    return mcp_servers.tools_for(server_id, vendor_poisoned=bool(vendor_state(state).get("poisoned")))


def scan_is_current(state: Dict[str, Any], server_id: str) -> bool:
    """A scan holds only for the catalogue it scanned (a changed description voids it)."""
    scan = (state.get("mcp_scans") or {}).get(server_id)
    return bool(scan) and scan.get("catalogue_sha") == catalogue_sha(current_tools(state, server_id))


def vendor_usable(state: Dict[str, Any]) -> bool:
    """Whether PatchBot may offer the vendor's tool to the model right now."""
    v = vendor_state(state)
    if not v.get("connected"):
        return False
    return bool(v.get("forced")) or (scan_is_current(state, mcp_servers.VENDOR)
                                     and state["mcp_scans"][mcp_servers.VENDOR]["is_safe"])


def _event(run: Run, event_type: str, **fields: Any) -> None:
    telemetry.emit("mcp_scan", event_type, {**run.common(), **fields})


def scan(run: Run, server_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Scan servers' catalogues; stores each result on the owner's estate."""
    ids = [s for s in (server_ids or list(mcp_servers.SERVERS)) if s in mcp_servers.SERVERS]
    results: Dict[str, Any] = {}
    for server_id in ids:
        with store.owner_lock(run.owner):
            tools = current_tools(store.load_estate(run.owner), server_id)
        scan_id = f"MCPS-{uuid.uuid4().hex[:10]}"
        try:
            result = normalize(run_scanner({"tools": tools}))
            error = None
        except (ScannerUnavailable, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            result, error = None, str(exc)[:300]
        meta = mcp_servers.SERVERS[server_id]
        if result is None:
            results[server_id] = {"server": server_id, "error": error}
            _event(run, "mcp_server_scan_failed", server=server_id, server_kind=meta["kind"], scan_id=scan_id,
                   error=error)
            continue
        result.update(server=server_id, scan_id=scan_id, scanned_at=datetime.utcnow().isoformat() + "Z",
                      catalogue_sha=catalogue_sha(tools), tools_scanned=len(tools))
        with store.owner_lock(run.owner):
            state = store.load_estate(run.owner)
            state.setdefault("mcp_scans", {})[server_id] = result
            store.save_estate(run.owner, state)
        unsafe = [t for t in result["tools"] if not t["is_safe"]]
        _event(run, "mcp_server_scanned", server=server_id, server_kind=meta["kind"], scan_id=scan_id,
               is_safe=result["is_safe"], severity=result["severity"], tools_scanned=len(tools),
               unsafe_tools=[t["tool"] for t in unsafe], threats=sorted({x for t in unsafe for x in t["threats"]}),
               analyzers_ran=result["analyzers_ran"], analyzers_requested=result["analyzers_requested"],
               catalogue_sha=result["catalogue_sha"])
        for t in unsafe:
            _event(run, "mcp_tool_finding", server=server_id, server_kind=meta["kind"], scan_id=scan_id,
                   tool_name=t["tool"], severity=t["severity"], threats=t["threats"],
                   aitech=sorted({x["aitech"] for x in t["taxonomies"] if x.get("aitech")}),
                   compensated_by=t["compensated_by"] or "")
        verdict = "clean" if result["is_safe"] else f"{len(unsafe)} unsafe tool(s): " + ", ".join(
            f"{t['tool']} ({', '.join(t['threats']) or t['severity']})" for t in unsafe)
        store.add_activity(run.owner, "mcp_scan", f"MCP Scanner rated {meta['title']}: {verdict}",
                           actor="Cisco MCP Scanner", actor_type="scanner")
        results[server_id] = result
    return results


def set_vendor_poisoned(run: Run, poisoned: bool) -> Dict[str, Any]:
    """Demo Control: the vendor ships a poisoned tool description (Lab 4, MCP variant)."""
    with store.owner_lock(run.owner):
        state = store.load_estate(run.owner)
        v = vendor_state(state)
        v["poisoned"] = bool(poisoned)
        store.save_estate(run.owner, state)
    _event(run, "mcp_server_catalogue_changed", server=mcp_servers.VENDOR, server_kind="vendor",
           vendor_poisoned=bool(poisoned))
    return v


def connect_vendor(run: Run, *, force: bool = False) -> Dict[str, Any]:
    """Connect the vendor server: only on a clean scan of its current catalogue,
    unless the instructor's Demo Control forces it."""
    if run.initiator.role not in CONNECT_ROLES:
        return {"ok": False, "message": "Your role cannot connect MCP servers."}
    with store.owner_lock(run.owner):
        state = store.load_estate(run.owner)
        v = vendor_state(state)
        scan_rec = (state.get("mcp_scans") or {}).get(mcp_servers.VENDOR)
        current = scan_is_current(state, mcp_servers.VENDOR)
        clean = current and bool(scan_rec and scan_rec.get("is_safe"))
        if not clean and not force:
            why = ("it has not been scanned" if not scan_rec else
                   "its tool description changed after the last scan" if not current else
                   "MCP Scanner rated it unsafe: " + ", ".join(
                       f"{t['tool']} ({', '.join(t['threats']) or t['severity']})"
                       for t in scan_rec["tools"] if not t["is_safe"]))
            message = f"PatchBot did not connect Vendor Advisories: {why}."
            _event(run, "mcp_server_connect_refused", server=mcp_servers.VENDOR, server_kind="vendor",
                   scan_id=(scan_rec or {}).get("scan_id", ""), scan_is_safe=bool(scan_rec and scan_rec.get("is_safe")),
                   scan_current=current, reason=why)
            store.add_activity(run.owner, "mcp_connect", message, actor="PatchBot", actor_type="agent")
            return {"ok": False, "message": message}
        v.update(connected=True, forced=bool(force and not clean), connected_at=datetime.utcnow().isoformat() + "Z")
        store.save_estate(run.owner, state)
    message = ("Vendor Advisories connected on a clean MCP Scanner verdict." if clean else
               "Vendor Advisories connected WITHOUT a clean scan (Demo Control).")
    _event(run, "mcp_server_connected", server=mcp_servers.VENDOR, server_kind="vendor",
           scan_id=(scan_rec or {}).get("scan_id", ""), scan_is_safe=clean, scan_current=current, forced=not clean)
    store.add_activity(run.owner, "mcp_connect", message, actor=run.initiator.username, actor_type="human")
    return {"ok": True, "message": message, "forced": not clean}


def disconnect_vendor(run: Run) -> Dict[str, Any]:
    with store.owner_lock(run.owner):
        state = store.load_estate(run.owner)
        vendor_state(state).update(connected=False, forced=False)
        store.save_estate(run.owner, state)
    _event(run, "mcp_server_disconnected", server=mcp_servers.VENDOR, server_kind="vendor")
    return {"ok": True}


def overview(owner: str) -> Dict[str, Any]:
    """The Toolchain panel: each server, its latest scan, and the vendor state."""
    state = store.load_estate(owner)
    scans = state.get("mcp_scans") or {}
    servers = []
    for server_id, meta in mcp_servers.SERVERS.items():
        tools = current_tools(state, server_id)
        servers.append({"id": server_id, **meta, "tools": [t["name"] for t in tools],
                        "endpoint": f"/mcp/patchbot/{owner}/{server_id}", "scan": scans.get(server_id),
                        "scan_current": scan_is_current(state, server_id)})
    return {"scanner": {"installed": bool(scanner_cmd()), "analyzers": analyzers()},
            "servers": servers, "vendor": dict(vendor_state(state)), "vendor_usable": vendor_usable(state)}
