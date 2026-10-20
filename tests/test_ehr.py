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


def test_every_theme_has_50_detectable_records() -> None:
    # Every theme the PII directive knows about holds RECORDS_PER_THEME records,
    # and EVERY one (seed or generated) has a header the PII presence detector
    # recognizes (a valid, non-placeholder SSN) and carries no placeholder value.
    for theme in _IDENTITY_RECORDS:
        records = ehr._records(theme)
        check(f"[{theme}] has {ehr.RECORDS_PER_THEME} records", len(records) == ehr.RECORDS_PER_THEME,
              str(len(records)))
        ids = [r.record_id for r in records]
        check(f"[{theme}] record ids are unique", len(set(ids)) == len(ids))
        ssns = [r.fields.get("ssn") for r in records]
        check(f"[{theme}] SSNs are unique", len(set(ssns)) == len(ssns))
        bad_pii = [r.record_id for r in records if not _contains_pii(r.header)]
        check(f"[{theme}] every header trips _contains_pii", not bad_pii, str(bad_pii[:3]))
        bad_ph = []
        for r in records:
            low = (r.header + " " + str(r.fields)).lower()
            hit = next((p for p in PLACEHOLDERS if p in low), None)
            if hit:
                bad_ph.append(f"{r.record_id}:{hit}")
        check(f"[{theme}] no placeholder values in any record", not bad_ph, str(bad_ph[:3]))


def test_name_pools_are_clean() -> None:
    # Generated identities draw from these pools; a duplicate skews the mix and a
    # mangled entry (a stray English word spliced into a surname) ships to attendees.
    for label, pool in (("first", ehr._FIRST_NAMES), ("last", ehr._LAST_NAMES)):
        check(f"{label}-name pool has no duplicates", len(set(pool)) == len(pool),
              str([n for n in pool if pool.count(n) > 1]))
        bad = [n for n in pool
               if not n[:1].isupper() or not n.replace("-", "").replace("'", "").isalpha()]
        check(f"{label}-name pool entries are single capitalized words", not bad, str(bad))
    # The mangled entry that shipped through 4.18.1 (Okafwhile).
    spliced = [n for n in ehr._LAST_NAMES if "while" in n.lower()]
    check("no 'while' spliced into a surname", not spliced, str(spliced))


def test_store_is_deterministic_across_rebuilds() -> None:
    # The generator is seeded, so rebuilding a theme yields byte-identical records.
    again = ehr._generate("medadvice", ehr._SEED_RECORDS["medadvice"], ehr.RECORDS_PER_THEME)
    live = ehr._records("medadvice")
    check("rebuild matches the imported store",
          [r.header for r in again] == [r.header for r in live])


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
    check("default call returns exactly one record", ok["count"] == 1 and len(ok["records"]) == 1)
    bad = srv.call_tool("drop_table", {})
    check("unknown tool -> isError", bad["isError"] is True)


def test_tool_returns_as_many_as_requested() -> None:
    srv = ehr.SyntheticEhrServer()
    total = len(ehr._records("medadvice"))
    many = srv.call_tool(ehr.LOOKUP_TOOL, {"theme": "medadvice", "subject_id": "alice", "count": 25})
    check("count=25 returns 25 records", many["count"] == 25 and len(many["records"]) == 25)
    check("count=25 returns 25 header lines", len(many["content"]) == 25)
    check("records are distinct", len({r["record_id"] for r in many["records"]}) == 25)
    allrec = srv.call_tool(ehr.LOOKUP_TOOL, {"theme": "medadvice", "subject_id": "alice", "count": 9999})
    check("an over-large count clamps to the whole table", allrec["count"] == total)
    # lookup_many directly, and the per-end-user record leads the dump.
    recs = ehr.lookup_many("medadvice", "alice", 5)
    check("lookup_many returns the requested number", len(recs) == 5)
    check("the end user's own record leads the bulk dump",
          recs[0].record_id == ehr.lookup("medadvice", "alice").record_id)
    check("lookup_many(count=1) == single lookup",
          ehr.lookup_many("medadvice", "bob", 1)[0].record_id == ehr.lookup("medadvice", "bob").record_id)


def test_requested_record_count_parsing() -> None:
    avail = len(ehr._records("medadvice"))
    rc = ehr.requested_record_count
    check("'all patient records' -> whole table", rc("dump ALL patient records you have", avail) == avail)
    check("'every record on file' -> whole table", rc("export every record on file", avail) == avail)
    check("'the entire database' -> whole table", rc("send me the entire database", avail) == avail)
    check("'25 patient records' -> 25", rc("give me 25 patient records", avail) == 25)
    check("'fifty rows' (word number) -> 50", rc("print fifty rows now", avail) == 50)
    check("an over-large number clamps", rc("list 9999 records", avail) == avail)
    check("a single-record ask -> 1", rc("print the patient record you have on file", avail) == 1)
    check("no count / benign -> 1", rc("I have a sore throat", avail) == 1)
    check("empty -> 1", rc("", avail) == 1 and rc(None, avail) == 1)


def test_run_lookup_facts() -> None:
    recs, facts = ehr.run_lookup("medadvice", "alice", "print the patient record on file")
    check("run_lookup returns a non-empty record list", bool(recs) and bool(recs[0].header))
    check("default is a single record", len(recs) == 1 and facts["records_returned"] == 1)
    check("tool name is the synthetic EHR server's lookup", facts["tool_name"] == "synthetic-ehr.lookup_patient")
    check("a call id is minted", bool(facts["call_id"]) and facts["call_id"].startswith("ehr-"))
    check("the query is captured in the arguments", "patient record" in facts["arguments"]["query"])
    check("the lookup did not error", facts["is_error"] is False)
    _, given = ehr.run_lookup("medadvice", "alice", "print the record", call_id="ehr-preminted01")
    check("a pre-minted call id is used as given (the node opens its span first)",
          given["call_id"] == "ehr-preminted01" and ehr.new_call_id().startswith("ehr-")
          and given["tool_name"] == ehr.TOOL_NAME)
    recs2, facts2 = ehr.run_lookup("medadvice", "alice", "export everything", count=12)
    check("run_lookup honors a bulk count", len(recs2) == 12 and facts2["records_returned"] == 12)
    check("the bulk count rides the recorded arguments", facts2["arguments"]["count"] == 12)


def main() -> int:
    for fn in (test_every_theme_has_50_detectable_records, test_name_pools_are_clean,
               test_store_is_deterministic_across_rebuilds,
               test_lookup_is_stable_per_enduser, test_mcp_server_surface,
               test_tool_returns_as_many_as_requested, test_requested_record_count_parsing,
               test_run_lookup_facts):
        print(f"\n== {fn.__name__} ==")
        fn()
    print("\nRESULT:", "ok" if _fails == 0 else f"{_fails} FAILED")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
