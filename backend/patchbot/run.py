"""One PatchBot run: everything PatchBot did for one request, for one person.

A run collects the model calls and tool calls of a request so they can be
emitted as ONE Agent Observability trace on the PatchBot Agent stream, and
carries the identifiers every Splunk event of that request shares.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.patchbot.roles import Initiator


@dataclass
class Run:
    initiator: Initiator
    owner: str
    kind: str                       # chat | patch | full_read | triage | exposure | demo
    session_id: str
    request_text: str = ""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: datetime = field(default_factory=datetime.utcnow)
    started_perf: float = field(default_factory=time.perf_counter)
    model: Optional[str] = None
    llm_calls: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    output_text: str = ""
    finding_id: Optional[str] = None
    investigation_id: Optional[str] = None
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def common(self) -> Dict[str, Any]:
        """Fields every Splunk event of this run carries."""
        return {"estate_owner": self.owner, "patchbot_session_id": self.session_id,
                "initiator": self.initiator.username, "initiator_role": self.initiator.role,
                "auth_method": self.initiator.auth_method, "trace_id": self.trace_id,
                "finding_id": self.finding_id or "", "investigation_id": self.investigation_id or ""}

    def add_llm(self, *, input_text: str, output_text: str, model: str, duration_ms: float,
                input_tokens: Optional[int] = None, output_tokens: Optional[int] = None) -> None:
        self.model = self.model or model
        self.llm_calls.append({"input": input_text[-6000:], "output": output_text[:6000], "model": model,
                               "duration_ms": round(duration_ms, 1), "input_tokens": input_tokens,
                               "output_tokens": output_tokens, "at": time.perf_counter() - self.started_perf})

    def add_tool(self, record: Dict[str, Any]) -> None:
        record = dict(record)
        record["at"] = time.perf_counter() - self.started_perf
        self.tool_calls.append(record)

    def duration_ms(self) -> float:
        return round((time.perf_counter() - self.started_perf) * 1000, 1)

    def ao_record(self) -> Dict[str, Any]:
        """The record the Agent Observability worker turns into a trace."""
        return {
            "_patchbot": True,
            "kind": self.kind, "run_id": self.run_id, "session_id": self.session_id,
            "trace_id": self.trace_id, "timestamp": self.started_at.isoformat(),
            "duration_ms": self.duration_ms(), "input": self.request_text or self.kind,
            "output": self.output_text, "model": self.model or "",
            "initiator": self.initiator.username, "initiator_role": self.initiator.role,
            "auth_method": self.initiator.auth_method, "estate_owner": self.owner,
            "finding_id": self.finding_id or "", "investigation_id": self.investigation_id or "",
            "llm_calls": list(self.llm_calls), "tool_calls": list(self.tool_calls),
        }


def short_json(value: Any, limit: int = 2000) -> str:
    try:
        text = json.dumps(value, default=str, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
