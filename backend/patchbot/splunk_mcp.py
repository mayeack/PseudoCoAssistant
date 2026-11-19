"""A minimal MCP client for PatchBot's read path into Splunk (the Splunk MCP Server).

PatchBot reads its ES finding through the Splunk MCP Server's
``splunk_run_query`` tool, so every read is a real MCP call that Splunk audits
(``_audit`` provenance ``MCP:Splunk_MCP_Server:<tool>``). Configured with
``PATCHBOT_SPLUNK_MCP_URL`` (for example ``https://<stack>:8089/services/mcp``)
and ``PATCHBOT_SPLUNK_MCP_TOKEN`` (an MCP token, audience ``mcp``). Unset means
PatchBot reads its own finding record instead and says so.

Streamable HTTP, JSON-RPC 2.0: ``initialize``, ``notifications/initialized``,
then ``tools/call``; a JSON or an SSE reply is accepted. Never raises.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)
_PROTOCOL = "2025-06-18"


def _url() -> str:
    return (os.getenv("PATCHBOT_SPLUNK_MCP_URL") or "").strip()


def _token() -> str:
    return (os.getenv("PATCHBOT_SPLUNK_MCP_TOKEN") or "").strip()


def configured() -> bool:
    return bool(_url() and _token())


def _verify() -> Any:
    flag = (os.getenv("PATCHBOT_SPLUNK_MCP_VERIFY_TLS") or "true").strip().lower()
    if flag in ("0", "false", "no"):
        return False
    return os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or True


def _parse(response: httpx.Response) -> Dict[str, Any]:
    ctype = response.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        last: Dict[str, Any] = {}
        for line in response.text.splitlines():
            if line.startswith("data:"):
                try:
                    last = json.loads(line[5:].strip())
                except ValueError:
                    continue
        return last
    return response.json() if response.content else {}


def call_tool(name: str, arguments: Dict[str, Any], *, timeout: float = 30.0) -> Dict[str, Any]:
    """``{"ok": bool, "text": str, "error": str|None}`` for one MCP tool call."""
    if not configured():
        return {"ok": False, "text": "", "error": "not_configured"}
    headers = {"Authorization": f"Bearer {_token()}", "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    try:
        with httpx.Client(timeout=timeout, verify=_verify()) as client:
            init = client.post(_url(), headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": _PROTOCOL, "capabilities": {},
                           "clientInfo": {"name": "pseudoco-assistant-patchbot", "version": "1"}}})
            init.raise_for_status()
            session = init.headers.get("mcp-session-id")
            if session:
                headers["Mcp-Session-Id"] = session
            client.post(_url(), headers=headers,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            resp = client.post(_url(), headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}})
            resp.raise_for_status()
            body = _parse(resp)
    except Exception as exc:  # noqa: BLE001
        logger.warning("PatchBot Splunk MCP call %s failed: %s", name, exc)
        return {"ok": False, "text": "", "error": type(exc).__name__}
    if body.get("error"):
        return {"ok": False, "text": "", "error": str(body["error"].get("message") or body["error"])[:200]}
    result = body.get("result") or {}
    parts = [c.get("text", "") for c in (result.get("content") or []) if isinstance(c, dict)]
    return {"ok": not result.get("isError"), "text": "\n".join(p for p in parts if p)[:8000],
            "error": None if not result.get("isError") else "tool_error"}


def find_es_finding(owner: str, cve: str) -> Optional[Dict[str, Any]]:
    """The newest ES finding PatchBot's detection raised for this estate and CVE."""
    spl = (f'search index=notable source="PatchBot - Vulnerability Remediation Required - Rule" '
           f'estate_owner="{owner}" cve="{cve}" | head 1 '
           f'| table _time event_id rule_title urgency status estate_owner cve dest_count')
    answer = call_tool("splunk_run_query", {"query": spl, "earliest_time": "-7d", "latest_time": "now",
                                            "row_limit": 1})
    return answer


def _quote(value: Any) -> str:
    """A value safe inside a double-quoted SPL string."""
    return "".join(ch for ch in str(value or "") if ch.isalnum() or ch in "-_.:@ ")[:128]


def _rows(text: str) -> List[Dict[str, Any]]:
    """The result rows in a splunk_run_query answer (its text is JSON with a results list)."""
    try:
        data = json.loads(text or "")
    except ValueError:
        return []
    if isinstance(data, dict):
        for key in ("results", "rows", "data"):
            if isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def read_es_record(*, investigation_id: Optional[str] = None, finding_id: Optional[str] = None,
                   cve: str = "") -> Dict[str, Any]:
    """The ES finding a SOAR action names, read through the Splunk MCP Server: a real MCP call
    that Splunk audits. By finding id when given, else the newest exploitation finding for the CVE."""
    fields = "_time event_id rule_title search_name urgency status_label owner dest cve"
    if finding_id:
        spl = f'search index=notable event_id="{_quote(finding_id)}" | head 1 | table {fields}'
    else:
        spl = (f'search index=notable search_name="PatchBot - Active Exploitation*" cve="{_quote(cve)}" '
               f'| head 1 | table {fields}')
    answer = call_tool("splunk_run_query", {"query": spl, "earliest_time": "-7d", "latest_time": "now",
                                            "row_limit": 1})
    if not answer.get("ok"):
        return {"found": False, "error": answer.get("error") or "read_failed",
                "investigation_id": investigation_id}
    rows = _rows(answer.get("text") or "")
    if not rows:
        return {"found": False, "investigation_id": investigation_id}
    r = rows[0]
    return {"found": True, "investigation_id": investigation_id, "finding_id": r.get("event_id"),
            "title": r.get("rule_title") or r.get("search_name"), "urgency": r.get("urgency"),
            "status": r.get("status_label"), "owner": r.get("owner"), "dest": r.get("dest"),
            "time": r.get("_time")}
