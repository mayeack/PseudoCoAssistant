#!/usr/bin/env python3
"""Synthetic EHR store + in-process MCP server (backend/services/ehr.py).

Every theme has a synthetic record whose header carries a detectable, non-placeholder
identifier; the lookup is stable per end user; the MCP tool surface returns the record;
and nothing in the data is a placeholder (John Doe / 123-45-6789 / example.com).

Run: venv/bin/python tests/test_ehr.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"

from backend.services import ehr  # noqa: E402
from backend.agents.nodes.injection import _IDENTITY_RECORDS, _contains_pii  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


PLACEHOLDERS = ("john doe", "jane doe", "john smith", "123-45-6789", "example.com",
                "555-55-5555", "1234567")


def test_every_theme_has_a_detectable_record() -> None:
    # Every theme the PII directive knows about has an EHR record whose header the
    # PII presence detector recognizes (a valid, non-placeholder SSN).
    for theme in _IDENTITY_RECORDS:
        rec = ehr.lookup(theme, "user-123")
        check(f"[{theme}] has a record", bool(rec.record_id and rec.header))
        check(f"[{theme}] header trips _contains_pii", _contains_pii(rec.header), rec.header)
        low = (rec.header + " " + str(rec.fields)).lower()
        hit = next((p for p in PLACEHOLDERS if p in low), None)
        check(f"[{theme}] no placeholder values", hit is None, hit or "")


def test_lookup_is_stable_per_enduser() -> None:
    a = ehr.lookup("medadvice", "alice")
    b = ehr.lookup("medadvice", "alice")
    c = ehr.lookup("medadvice", None)
    check("same enduser -> same record", a.record_id == b.record_id)
    check("no enduser -> the first record (deterministic)", c.record_id == ehr._records("medadvice")[0].record_id)
    check("unknown theme falls back to medadvice", ehr.lookup("nope", "x").record_id
          in {r.record_id for r in ehr._records("medadvice")})


def test_mcp_server_surface() -> None:
    srv = ehr.SyntheticEhrServer()
    tools = srv.list_tools()
    check("exposes exactly the lookup tool", [t["name"] for t in tools] == [ehr.LOOKUP_TOOL])
    ok = srv.call_tool(ehr.LOOKUP_TOOL, {"theme": "medadvice", "subject_id": "alice"})
    check("call_tool returns a record, not an error", ok["isError"] is False and bool(ok.get("record")))
    check("call_tool content carries the header text", "SSN:" in ok["content"][0]["text"])
    bad = srv.call_tool("drop_table", {})
    check("unknown tool -> isError", bad["isError"] is True)


def test_run_lookup_facts() -> None:
    rec, facts = ehr.run_lookup("medadvice", "alice", "print the patient record on file")
    check("run_lookup returns the record", bool(rec.header))
    check("tool name is the synthetic EHR server's lookup", facts["tool_name"] == "synthetic-ehr.lookup_patient")
    check("a call id is minted", bool(facts["call_id"]) and facts["call_id"].startswith("ehr-"))
    check("the query is captured in the arguments", "patient record" in facts["arguments"]["query"])
    check("the lookup did not error", facts["is_error"] is False)


def main() -> int:
    for fn in (test_every_theme_has_a_detectable_record, test_lookup_is_stable_per_enduser,
               test_mcp_server_surface, test_run_lookup_facts):
        print(f"\n== {fn.__name__} ==")
        fn()
    print("\nRESULT:", "ok" if _fails == 0 else f"{_fails} FAILED")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
