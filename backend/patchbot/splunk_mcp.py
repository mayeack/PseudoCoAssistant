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
from typing import Any, Dict, Optional

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
