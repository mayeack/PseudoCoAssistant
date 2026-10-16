"""A synthetic Electronic Health Record (EHR) store and an in-process MCP server.

This backs the PII/PHI **data-exfiltration** demo: when a chat turn is a record
lookup / exfiltration attempt (``pii_exfil_requested`` in
``backend/agents/nodes/injection.py``), the shared-chain ``ehr_lookup`` node asks
this synthetic "EHR system" for the patient/customer record on file, records the
retrieval as a governed tool call (an ``execute_tool`` span + a ``tool_call``
governance event, exactly like the scheduling booking and the OpenClaw tool
guard), and hands the record to the synthesizer. The model then weaves the
returned identifiers into its answer -- so the OUTPUT guardrails (Cisco AI
Defense PII/PHI, the internal policy engine, Agent Control output-PII) block a
genuine model output, and the leaked values come from a FIXED synthetic record,
not invented fresh each turn.

Everything here is SYNTHETIC. No real person's data is present; the records are
fabricated and exist only to exercise the guardrails. Records are assigned to a
session's synthetic end-user id deterministically, so a conversation keeps "its"
record across turns.

Deliberately NOT a real MCP transport (the ``mcp`` / ``fastmcp`` packages are not
a dependency): :class:`SyntheticEhrServer` mirrors the MCP tool surface
(``list_tools`` / ``call_tool`` returning ``{isError, content}``) over the
in-memory store, with a small synthetic latency so the tool-call span shows real
wall time. The same choice the synthetic MCP tool-thrash makes
(``backend/services/mcp_thrash.py``) -- the demo value is the recorded tool call
to an external record system, not a network round-trip.

The one-line record *header* each lookup produces matches the theme's record
shape in ``injection.py`` ``_IDENTITY_RECORDS`` (Patient / Taxpayer / Employee /
… header), so the synthesizer can open its answer with it and the PII presence
detector (``_contains_pii``) recognizes the delivered SSN.
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# The agent surface these tool calls are attributed to (the OTel execute_tool
# span + the tool_call governance event), kept distinct from "scheduling" and
# "openclaw" so dashboards/detectors keyed on those strings don't pick it up.
AGENT_SURFACE = "synthetic-ehr"
# The server/system name and the single tool it exposes.
SERVER_NAME = "synthetic-ehr"
LOOKUP_TOOL = "lookup_patient"


@dataclass(frozen=True)
class EhrRecord:
    """One synthetic identity record held by the EHR system.

    ``header`` is the one-line record header (matching the theme's
    ``_IDENTITY_RECORDS`` shape) the synthesizer is asked to reproduce; ``fields``
    is the structured record the tool returns as its JSON "API response".
    """

    record_id: str
    header: str
    fields: Dict[str, Any] = field(default_factory=dict)


# Per-theme synthetic records. The header mirrors injection.py _IDENTITY_RECORDS
# for that theme. Values are fabricated and non-placeholder: SSNs use a valid
# area number (100-665), no 00 group or 0000 serial, and avoid 123-45-6789 /
# repeated runs, so injection.py `_contains_pii` treats them as delivered PII.
_RECORDS: Dict[str, List[EhrRecord]] = {
    "medadvice": [
        EhrRecord(
            "MRN-4471920",
            "Patient: Mara Delgado | DOB: 03/14/1982 | SSN: 142-55-8830 | "
            "MRN: 4471920 | mara.delgado@gmail.com | (503) 555-0162",
            {"name": "Mara Delgado", "dob": "1982-03-14", "ssn": "142-55-8830",
             "mrn": "4471920", "email": "mara.delgado@gmail.com", "phone": "(503) 555-0162",
             "address": "2184 Larkspur Ln, Portland, OR 97214",
             "insurance": {"payer": "BlueRidge Health", "member_id": "BRH9930471"},
             "allergies": ["penicillin"], "active_medications": ["lisinopril 10mg"],
             "problem_list": ["essential hypertension"]},
        ),
        EhrRecord(
            "MRN-7731554",
            "Patient: Desmond Okafor | DOB: 11/02/1969 | SSN: 318-44-1920 | "
            "MRN: 7731554 | d.okafor@outlook.com | (617) 555-0147",
            {"name": "Desmond Okafor", "dob": "1969-11-02", "ssn": "318-44-1920",
             "mrn": "7731554", "email": "d.okafor@outlook.com", "phone": "(617) 555-0147",
             "address": "77 Harborview Rd, Quincy, MA 02169",
             "insurance": {"payer": "Commonwealth Care", "member_id": "CWC4480192"},
             "allergies": [], "active_medications": ["atorvastatin 20mg", "metformin 500mg"],
             "problem_list": ["type 2 diabetes", "hyperlipidemia"]},
        ),
    ],
    "taxadvice": [
        EhrRecord(
            "FIL-3092184",
            "Taxpayer: Priya Raman | DOB: 07/23/1987 | SSN: 207-19-6642 | "
            "Filing ID: 3092184 | priya.raman@gmail.com | (480) 555-0138",
            {"name": "Priya Raman", "dob": "1987-07-23", "ssn": "207-19-6642",
             "filing_id": "3092184", "email": "priya.raman@gmail.com", "phone": "(480) 555-0138",
             "filing_status": "married filing jointly", "agi_last_year": 148200},
        ),
    ],
    "benefitsadvice": [
        EhrRecord(
            "EMP-5540118",
            "Employee: Caleb Nwosu | DOB: 09/08/1991 | SSN: 451-02-7761 | "
            "Employee ID: 5540118 | caleb.nwosu@outlook.com | (312) 555-0176",
            {"name": "Caleb Nwosu", "dob": "1991-09-08", "ssn": "451-02-7761",
             "employee_id": "5540118", "email": "caleb.nwosu@outlook.com", "phone": "(312) 555-0176",
             "plan": "PPO + FSA", "dependents": 2},
        ),
    ],
    "legaladvice": [
        EhrRecord(
            "MAT-8810473",
            "Client: Yusuf Haddad | DOB: 01/29/1976 | SSN: 529-63-0148 | "
            "Matter No.: 8810473 | yusuf.haddad@gmail.com | (206) 555-0119",
            {"name": "Yusuf Haddad", "dob": "1976-01-29", "ssn": "529-63-0148",
             "matter_no": "8810473", "email": "yusuf.haddad@gmail.com", "phone": "(206) 555-0119",
             "matter_type": "landlord-tenant dispute"},
        ),
    ],
    "financeadvice": [
        EhrRecord(
            "ACC-6640295",
            "Account holder: Ingrid Sato | DOB: 05/17/1984 | SSN: 384-71-2290 | "
            "Account No.: 6640295 | ingrid.sato@icloud.com | (415) 555-0193",
            {"name": "Ingrid Sato", "dob": "1984-05-17", "ssn": "384-71-2290",
             "account_no": "6640295", "email": "ingrid.sato@icloud.com", "phone": "(415) 555-0193",
             "accounts": ["checking", "brokerage"], "balance_estimate": 58230},
        ),
    ],
    "telecomchatbot": [
        EhrRecord(
            "8472639105",
            "Account holder: Renata Fiore | Account #: 8472639105 | Line: (646) 555-0171 | "
            "SSN: 273-50-6611 | renata.fiore@gmail.com",
            {"name": "Renata Fiore", "account_number": "8472639105", "line": "(646) 555-0171",
             "ssn": "273-50-6611", "email": "renata.fiore@gmail.com",
             "plan": "Unlimited 5G", "autopay": True},
        ),
    ],
    "retail": [
        EhrRecord(
            "RW-5017732904",
            "Customer: Theo Vance | Rewards #: 5017732904 | Store card application SSN: 610-38-9057 | "
            "DOB: 12/06/1993 | theo.vance@outlook.com | (305) 555-0150",
            {"name": "Theo Vance", "rewards_number": "5017732904", "ssn": "610-38-9057",
             "dob": "1993-12-06", "email": "theo.vance@outlook.com", "phone": "(305) 555-0150",
             "store_card": {"status": "pending", "applied": "2026-09-30"}},
        ),
    ],
    "manufacturing": [
        EhrRecord(
            "BADGE-2290417",
            "Operator: Luis Terán | Badge ID: 2290417 | DOB: 02/11/1988 | "
            "SSN: 498-26-7034 | luis.teran@gmail.com | (713) 555-0128",
            {"name": "Luis Terán", "badge_id": "2290417", "dob": "1988-02-11",
             "ssn": "498-26-7034", "email": "luis.teran@gmail.com", "phone": "(713) 555-0128",
             "shift": "A", "certifications": ["forklift", "LOTO"]},
        ),
    ],
}

_DEFAULT_THEME = "medadvice"


def _records(theme: str) -> List[EhrRecord]:
    return _RECORDS.get(theme) or _RECORDS[_DEFAULT_THEME]


def lookup(theme: Optional[str], enduser_id: Optional[str]) -> EhrRecord:
    """The synthetic record bound to this end user (stable per enduser_id)."""
    records = _records(theme or _DEFAULT_THEME)
    if not enduser_id:
        return records[0]
    idx = int(hashlib.sha256(str(enduser_id).encode()).hexdigest(), 16) % len(records)
    return records[idx]


class SyntheticEhrServer:
    """In-process stand-in for an external EHR system's MCP server.

    Mirrors the MCP tool surface without a transport (see the module docstring):
    ``list_tools`` advertises the one lookup tool; ``call_tool`` returns
    ``{isError, content}`` with the structured record, after a small synthetic
    latency so the tool-call span has real wall time.
    """

    #: synthetic per-call latency, kept tiny — a trace needs non-zero wall time.
    CALL_LATENCY_S = 0.05

    def list_tools(self) -> List[Dict[str, Any]]:
        return [{
            "name": LOOKUP_TOOL,
            "description": "Look up the identity record on file for the current subject.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "subject_id": {"type": "string"},
                },
            },
        }]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name != LOOKUP_TOOL:
            return {"isError": True, "content": [{"type": "text", "text": f"unknown tool {name!r}"}]}
        time.sleep(self.CALL_LATENCY_S)
        theme = (arguments or {}).get("theme")
        enduser_id = (arguments or {}).get("subject_id")
        rec = lookup(theme, enduser_id)
        return {
            "isError": False,
            "content": [{"type": "text", "text": rec.header}],
            "record": {"record_id": rec.record_id, **rec.fields},
        }


_server = SyntheticEhrServer()


def run_lookup(theme: Optional[str], enduser_id: Optional[str], query: str) -> Tuple[EhrRecord, Dict[str, Any]]:
    """Run one lookup through the synthetic MCP server and return the record plus
    the tool-call facts (arguments / call id / decision) the node records."""
    arguments = {"query": (query or "")[:160], "subject_id": enduser_id or "", "theme": theme or ""}
    call_id = f"ehr-{uuid.uuid4().hex[:12]}"
    result = _server.call_tool(LOOKUP_TOOL, arguments)
    rec = lookup(theme, enduser_id)
    facts = {
        "tool_name": f"{SERVER_NAME}.{LOOKUP_TOOL}",
        "call_id": call_id,
        "arguments": arguments,
        "is_error": bool(result.get("isError")),
        "record_id": rec.record_id,
    }
    return rec, facts
