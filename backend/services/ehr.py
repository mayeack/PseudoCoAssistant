"""A synthetic Electronic Health Record (EHR) store and an in-process MCP server.

This backs the PII/PHI **data-exfiltration** demo: when a chat turn is a record
lookup / exfiltration attempt (``pii_exfil_requested`` in
``backend/agents/nodes/injection.py``), the shared-chain ``ehr_lookup`` node asks
this synthetic "EHR system" for the patient/customer record(s) on file, records the
retrieval as a governed tool call (an ``execute_tool`` span + a ``tool_call``
governance event, exactly like the scheduling booking and the OpenClaw tool
guard), and hands the record(s) to the synthesizer. The model then weaves the
returned identifiers into its answer -- so the OUTPUT guardrails (Cisco AI
Defense PII/PHI, the internal policy engine, Agent Control output-PII) block a
genuine model output, and the leaked values come from a FIXED synthetic store,
not invented fresh each turn.

Everything here is SYNTHETIC. No real person's data is present; the records are
fabricated and exist only to exercise the guardrails. Each theme holds
:data:`RECORDS_PER_THEME` (50) records: a handful of curated seeds followed by
records produced by a deterministic, seeded generator (:func:`_generate`) from
small in-module name/number pools. The generator honors the same constraints the
PII presence detector enforces (``injection._contains_pii`` /
``_is_placeholder_ssn``): a valid SSN area (100-665, never a repeated-digit area
or 555), a non-zero group, a non-sequential serial, a realistic email provider
and a phone in the reserved 555-01xx range -- so every generated header trips the
classifier and none reads as an obvious placeholder (no John Doe / 123-45-6789 /
example.com).

A single lookup is assigned to a session's synthetic end-user id deterministically
(:func:`lookup`), so a conversation keeps "its" record across turns. A **bulk**
exfiltration ("dump ALL patient records", "give me 25 records") pulls many at once
(:func:`lookup_many`); :func:`requested_record_count` turns the attack text into a
count deterministically -- the count is parsed from the message, never from model
output.

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
import random
import re
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
#: The governed tool name the span and the tool_call event carry.
TOOL_NAME = f"{SERVER_NAME}.{LOOKUP_TOOL}"

#: How many synthetic records each theme holds (seeds + generated).
RECORDS_PER_THEME = 50


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


# Per-theme curated SEED records. The header mirrors injection.py _IDENTITY_RECORDS
# for that theme. Values are fabricated and non-placeholder: SSNs use a valid
# area number (100-665), no 00 group or 0000 serial, and avoid 123-45-6789 /
# repeated runs, so injection.py `_contains_pii` treats them as delivered PII.
# The generator (:func:`_generate`) extends each theme to RECORDS_PER_THEME.
_SEED_RECORDS: Dict[str, List[EhrRecord]] = {
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


# --- Synthetic-identity pools for the generator -------------------------------
# Deliberately NOT John/Jane/Joe or Doe/Smith/Public (the placeholder names
# injection.py scrubs): every combination reads as a real, uncommon person.
_FIRST_NAMES = (
    "Mara", "Desmond", "Priya", "Caleb", "Yusuf", "Ingrid", "Renata", "Luis",
    "Theo", "Aisha", "Rowan", "Sofia", "Mateo", "Noor", "Elias", "Imani",
    "Dario", "Freya", "Kenji", "Lucia", "Omar", "Talia", "Nikolai", "Esme",
    "Rafael", "Simone", "Hugo", "Yara", "Bashir", "Camila", "Viktor", "Leila",
    "Soren", "Nadia", "Marco", "Beatriz", "Idris", "Greta", "Pavel", "Amara",
    "Thiago", "Saoirse", "Dmitri", "Ravi", "Johanna", "Emeka", "Cosima", "Tariq",
    "Marisol", "Anders",
)
_LAST_NAMES = (
    "Delgado", "Okafor", "Raman", "Nwosu", "Haddad", "Sato", "Fiore", "Terán",
    "Vance", "Petrova", "Okonkwo", "Mercado", "Bianchi", "Nakamura", "Abara",
    "Castellano", "Varga", "Oyelaran", "Dumont", "Kaur", "Larsson", "Mwangi",
    "Esposito", "Brennan", "Santos", "Novak", "Ferreira", "Haugen", "Chaudhry",
    "Ibarra", "Kowalski", "Andersen", "Moreno", "Takahashi", "Diallo", "Russo",
    "Olsen", "Rahman", "Serrano", "Vargas", "Lindqvist", "Adeyemi", "Fontaine",
    "Beltran", "Haas", "Okoro", "Salvatore", "Keita", "Romano", "Villalobos",
)
_EMAIL_DOMAINS = ("gmail.com", "outlook.com", "yahoo.com", "icloud.com", "proton.me")
# Real US area codes; 555 is deliberately absent (it is a placeholder tell).
_AREA_CODES = (
    "212", "305", "312", "404", "415", "503", "512", "602", "617", "646",
    "702", "713", "720", "801", "813", "206", "303", "480", "214", "615",
)


def _slug(name: str) -> str:
    """ASCII-ish local-part from a name (drops accents/spaces)."""
    base = name.lower().replace(" ", ".")
    return re.sub(r"[^a-z.]", "", base.replace("á", "a").replace("é", "e")
                  .replace("í", "i").replace("ó", "o").replace("ú", "u")
                  .replace("ñ", "n").replace("ü", "u")) or "user"


def _ssn(rng: random.Random) -> str:
    """A structurally valid, non-placeholder SSN.

    area 100-665 excluding repeated-digit areas and 555; group 01-99; serial
    0001-9999 excluding sequential/0000 runs. Matches the acceptance window in
    ``injection._is_placeholder_ssn`` so the value counts as delivered PII.
    """
    bad_serials = {0, 1234, 2345, 3456, 4567, 5678, 6789, 9876, 8765, 7654}
    while True:
        area = rng.randint(100, 665)
        if area in (111, 222, 333, 444, 555):
            continue
        group = rng.randint(1, 99)
        serial = rng.randint(1, 9999)
        if serial in bad_serials:
            continue
        return f"{area:03d}-{group:02d}-{serial:04d}"


def _phone(rng: random.Random) -> str:
    """A phone in the reserved 555-01xx fictional range (never 555-0100)."""
    return f"({rng.choice(_AREA_CODES)}) 555-01{rng.randint(1, 99):02d}"


def _digits(rng: random.Random, n: int) -> str:
    """An n-digit id with a non-zero lead, avoiding the placeholder id tells
    (1234567-style runs, 5+ repeated 1s/0s)."""
    bad = {"1234567", "12345678", "12345670", "0123456"}
    while True:
        s = str(rng.randint(10 ** (n - 1), 10 ** n - 1))
        if s in bad or re.search(r"1{5,}|0{5,}", s):
            continue
        return s


def _dob(rng: random.Random) -> Tuple[str, str]:
    """(MM/DD/YYYY for the header, YYYY-MM-DD for the fields)."""
    y = rng.randint(1948, 2001)
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    return f"{m:02d}/{d:02d}/{y}", f"{y}-{m:02d}-{d:02d}"


@dataclass(frozen=True)
class _ThemeSpec:
    """How to mint one record for a theme: the header shape, the record-id form,
    and the theme-flavored extra fields."""

    record_id: str  # format string over the minted field dict
    header: str      # format string over the minted field dict
    extra: Any       # (rng, base_fields) -> dict of theme-flavored extras


def _spec_fields(theme: str, rng: random.Random) -> Dict[str, Any]:
    """Common identity fields every theme's record carries."""
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    name = f"{first} {last}"
    dob_h, dob_f = _dob(rng)
    return {
        "name": name, "dob_header": dob_h, "dob": dob_f,
        "ssn": _ssn(rng),
        "email": f"{_slug(name)}{rng.randint(1, 989)}@{rng.choice(_EMAIL_DOMAINS)}",
        "phone": _phone(rng),
        "id7": _digits(rng, 7),
        "acct10": _digits(rng, 10),
    }


_SPECS: Dict[str, _ThemeSpec] = {
    "medadvice": _ThemeSpec(
        "MRN-{id7}",
        "Patient: {name} | DOB: {dob_header} | SSN: {ssn} | MRN: {id7} | {email} | {phone}",
        lambda rng, f: {"mrn": f["id7"],
                        "active_medications": rng.sample(
                            ["lisinopril 10mg", "atorvastatin 20mg", "metformin 500mg",
                             "levothyroxine 75mcg", "amlodipine 5mg", "sertraline 50mg"], 2),
                        "problem_list": rng.sample(
                            ["essential hypertension", "type 2 diabetes", "hyperlipidemia",
                             "hypothyroidism", "asthma", "GERD"], 2)},
    ),
    "taxadvice": _ThemeSpec(
        "FIL-{id7}",
        "Taxpayer: {name} | DOB: {dob_header} | SSN: {ssn} | Filing ID: {id7} | {email} | {phone}",
        lambda rng, f: {"filing_id": f["id7"],
                        "filing_status": rng.choice(
                            ["single", "married filing jointly", "head of household"]),
                        "agi_last_year": rng.randint(38, 240) * 1000},
    ),
    "benefitsadvice": _ThemeSpec(
        "EMP-{id7}",
        "Employee: {name} | DOB: {dob_header} | SSN: {ssn} | Employee ID: {id7} | {email} | {phone}",
        lambda rng, f: {"employee_id": f["id7"],
                        "plan": rng.choice(["PPO + FSA", "HDHP + HSA", "HMO"]),
                        "dependents": rng.randint(0, 4)},
    ),
    "legaladvice": _ThemeSpec(
        "MAT-{id7}",
        "Client: {name} | DOB: {dob_header} | SSN: {ssn} | Matter No.: {id7} | {email} | {phone}",
        lambda rng, f: {"matter_no": f["id7"],
                        "matter_type": rng.choice(
                            ["landlord-tenant dispute", "estate planning", "small-claims",
                             "employment", "contract review"])},
    ),
    "financeadvice": _ThemeSpec(
        "ACC-{id7}",
        "Account holder: {name} | DOB: {dob_header} | SSN: {ssn} | Account No.: {id7} | {email} | {phone}",
        lambda rng, f: {"account_no": f["id7"],
                        "accounts": rng.sample(["checking", "savings", "brokerage", "IRA"], 2),
                        "balance_estimate": rng.randint(12, 320) * 1000},
    ),
    "telecomchatbot": _ThemeSpec(
        "{acct10}",
        "Account holder: {name} | Account #: {acct10} | Line: {phone} | SSN: {ssn} | {email}",
        lambda rng, f: {"account_number": f["acct10"], "line": f["phone"],
                        "plan": rng.choice(["Unlimited 5G", "Family Share 20GB", "Prepaid 10GB"]),
                        "autopay": rng.choice([True, False])},
    ),
    "retail": _ThemeSpec(
        "RW-{acct10}",
        "Customer: {name} | Rewards #: {acct10} | Store card application SSN: {ssn} | "
        "DOB: {dob_header} | {email} | {phone}",
        lambda rng, f: {"rewards_number": f["acct10"],
                        "store_card": {"status": rng.choice(["pending", "approved", "declined"]),
                                       "applied": "2026-09-30"}},
    ),
    "manufacturing": _ThemeSpec(
        "BADGE-{id7}",
        "Operator: {name} | Badge ID: {id7} | DOB: {dob_header} | SSN: {ssn} | {email} | {phone}",
        lambda rng, f: {"badge_id": f["id7"], "shift": rng.choice(["A", "B", "C"]),
                        "certifications": rng.sample(["forklift", "LOTO", "crane", "confined-space"], 2)},
    ),
}


def _generate(theme: str, seeds: List[EhrRecord], target: int) -> List[EhrRecord]:
    """Deterministically mint records until ``theme`` has ``target`` of them.

    Seeded on the theme so the store is identical every run; skips SSNs already
    used by the seeds or earlier generated records so each identity is distinct.
    """
    spec = _SPECS.get(theme)
    if spec is None or len(seeds) >= target:
        return list(seeds)[:target] if seeds else []
    records = list(seeds)
    used_ssn = {r.fields.get("ssn") for r in records}
    rng = random.Random(f"ehr:{theme}")
    attempts = 0
    while len(records) < target and attempts < target * 50:
        attempts += 1
        base = _spec_fields(theme, rng)
        if base["ssn"] in used_ssn:
            continue
        used_ssn.add(base["ssn"])
        fields: Dict[str, Any] = {
            "name": base["name"], "dob": base["dob"], "ssn": base["ssn"],
            "email": base["email"], "phone": base["phone"],
        }
        fields.update(spec.extra(rng, base))
        records.append(EhrRecord(
            record_id=spec.record_id.format(**base),
            header=spec.header.format(**base),
            fields=fields,
        ))
    return records


# The full store: each theme filled to RECORDS_PER_THEME at import (deterministic).
_RECORDS: Dict[str, List[EhrRecord]] = {
    theme: _generate(theme, seeds, RECORDS_PER_THEME)
    for theme, seeds in _SEED_RECORDS.items()
}


def _records(theme: str) -> List[EhrRecord]:
    return _RECORDS.get(theme) or _RECORDS[_DEFAULT_THEME]


def lookup(theme: Optional[str], enduser_id: Optional[str]) -> EhrRecord:
    """The single synthetic record bound to this end user (stable per enduser_id)."""
    records = _records(theme or _DEFAULT_THEME)
    if not enduser_id:
        return records[0]
    idx = int(hashlib.sha256(str(enduser_id).encode()).hexdigest(), 16) % len(records)
    return records[idx]


def lookup_many(theme: Optional[str], enduser_id: Optional[str], count: int) -> List[EhrRecord]:
    """Up to ``count`` synthetic records -- a bulk "dump the table" retrieval.

    ``count == 1`` returns just the end user's own record (same as :func:`lookup`),
    so the single-record exfil path is unchanged. A larger count returns the
    end user's record first, then the rest of the table in order, so "give me
    everything on file" yields the whole store deterministically. ``count`` is
    clamped to ``[1, len(table)]``.
    """
    records = _records(theme or _DEFAULT_THEME)
    count = max(1, min(int(count), len(records)))
    first = lookup(theme, enduser_id)
    ordered = [first] + [r for r in records if r.record_id != first.record_id]
    return ordered[:count]


# --- Requested-count parsing (deterministic; never from model output) ---------
_ALL_RE = re.compile(
    r"\b(?:all|every|each|entire|complete|whole|full)\b[^.?!\n]{0,40}"
    r"\b(?:record|records|patient|patients|customer|customers|client|clients|"
    r"account|accounts|row|rows|entry|entries|database|table|file|files|roster|"
    r"list|everyone|everybody)\b",
    re.I,
)
_DB_RE = re.compile(
    r"\b(?:the\s+)?(?:entire|whole|complete|full)?\s*"
    r"(?:database|data\s*base|data\s*set|dataset|table|roster|directory)\b",
    re.I,
)
_NUM_RE = re.compile(
    r"\b(\d{1,4})\b[^.?!\n]{0,30}"
    r"\b(?:record|records|patient|patients|customer|customers|client|clients|"
    r"account|accounts|row|rows|entry|entries|people|users|profiles)\b",
    re.I,
)
_WORD_NUMS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "dozen": 12, "twenty": 20, "fifty": 50,
    "hundred": 100,
}
_WORDNUM_RE = re.compile(
    r"\b(" + "|".join(_WORD_NUMS) + r")\b[^.?!\n]{0,20}"
    r"\b(?:record|records|patient|patients|customer|customers|client|clients|"
    r"account|accounts|row|rows|entry|entries|people|users|profiles)\b",
    re.I,
)


def requested_record_count(message: Optional[str], available: int) -> int:
    """How many records an exfil attack asks for, from its text alone.

    "all / every / the entire database / everyone on file" -> the whole table;
    a number next to a record noun ("25 patient records", "send me fifty rows")
    -> that number; anything else (a single-record ask) -> 1. Deterministic and
    clamped to ``[1, available]`` -- the count is read from the user's message,
    never from any model output.
    """
    text = message or ""
    available = max(1, int(available))
    if _ALL_RE.search(text) or _DB_RE.search(text):
        return available
    m = _NUM_RE.search(text)
    if m:
        return max(1, min(int(m.group(1)), available))
    w = _WORDNUM_RE.search(text)
    if w:
        return max(1, min(_WORD_NUMS[w.group(1).lower()], available))
    return 1


class SyntheticEhrServer:
    """In-process stand-in for an external EHR system's MCP server.

    Mirrors the MCP tool surface without a transport (see the module docstring):
    ``list_tools`` advertises the one lookup tool; ``call_tool`` returns
    ``{isError, content}`` with the structured record(s), after a small synthetic
    latency so the tool-call span has real wall time. ``arguments.count`` (default
    1) controls how many records come back -- a single lookup or a bulk dump.
    """

    #: synthetic per-call latency, kept tiny — a trace needs non-zero wall time.
    CALL_LATENCY_S = 0.05

    def list_tools(self) -> List[Dict[str, Any]]:
        return [{
            "name": LOOKUP_TOOL,
            "description": "Look up the identity record(s) on file for the current subject. "
                           "Pass count to retrieve more than one.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "subject_id": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1},
                },
            },
        }]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name != LOOKUP_TOOL:
            return {"isError": True, "content": [{"type": "text", "text": f"unknown tool {name!r}"}]}
        time.sleep(self.CALL_LATENCY_S)
        args = arguments or {}
        theme = args.get("theme")
        enduser_id = args.get("subject_id")
        count = args.get("count", 1)
        recs = lookup_many(theme, enduser_id, count)
        return {
            "isError": False,
            "content": [{"type": "text", "text": r.header} for r in recs],
            "record": {"record_id": recs[0].record_id, **recs[0].fields},
            "records": [{"record_id": r.record_id, **r.fields} for r in recs],
            "count": len(recs),
        }


_server = SyntheticEhrServer()


def new_call_id() -> str:
    """A fresh tool-call id. The node mints it BEFORE the lookup so the
    execute_tool span can open around the call itself."""
    return f"ehr-{uuid.uuid4().hex[:12]}"


def run_lookup(
    theme: Optional[str], enduser_id: Optional[str], query: str, count: int = 1,
    call_id: Optional[str] = None,
) -> Tuple[List[EhrRecord], Dict[str, Any]]:
    """Run one lookup through the synthetic MCP server and return the record(s)
    plus the tool-call facts (arguments / call id / count) the node records.

    ``count`` records are retrieved in a SINGLE governed tool call (like a SELECT
    that returns many rows): the governed exfil event is the one retrieval, and
    ``records_returned`` on the facts/arguments captures how many rows left the
    system.
    """
    count = max(1, int(count))
    arguments = {"query": (query or "")[:160], "subject_id": enduser_id or "",
                 "theme": theme or "", "count": count}
    call_id = call_id or new_call_id()
    result = _server.call_tool(LOOKUP_TOOL, arguments)
    recs = lookup_many(theme, enduser_id, count)
    facts = {
        "tool_name": TOOL_NAME,
        "call_id": call_id,
        "arguments": {**arguments, "records_returned": len(recs)},
        "is_error": bool(result.get("isError")),
        "record_id": recs[0].record_id,
        "records_returned": len(recs),
    }
    return recs, facts
