"""PatchBot's CVE catalog and the CISA BOD 26-04 rating (docs/patchbot.md).

The catalog is a snapshot of real public facts (CISA KEV, FIRST EPSS, CISA
Vulnrichment SSVC) for the seven CVEs the synthetic estate carries, plus the
package and fix overlay PatchBot needs. It is data, loaded once; nothing here
calls the network.

The rating is CISA BOD 26-04 Table 1: four inputs (is the asset publicly
exposed, is the CVE in KEV, can an adversary automate the exploit, total or
partial technical impact) pick one of 16 rows and a remediation timeline.
PatchBot's severity is a label on that timeline:

    3 days & forensic triage -> critical
    3 days                   -> high
    14 days                  -> medium
    60 days, fix on upgrade  -> low
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "patchbot" / "cve_catalog.json"

SEVERITY_ORDER = ("critical", "high", "medium", "low")

_TIMELINE_SEVERITY = {
    "3 days & forensic triage": "critical",
    "3 days": "high",
    "14 days": "medium",
    "60 days": "low",
    "Fix on system upgrade": "low",
}
_TIMELINE_DAYS = {
    "3 days & forensic triage": 3,
    "3 days": 3,
    "14 days": 14,
    "60 days": 60,
    "Fix on system upgrade": None,
}


@dataclass(frozen=True)
class Rating:
    row: int
    timeline: str
    due_days: Optional[int]
    forensic_triage: bool
    severity: str
    publicly_exposed: bool
    in_kev: bool
    automatable: bool
    total_impact: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bod_row": self.row,
            "bod_timeline": self.timeline,
            "due_days": self.due_days,
            "forensic_triage": self.forensic_triage,
            "severity": self.severity,
            "publicly_exposed": "yes" if self.publicly_exposed else "no",
            "kev": self.in_kev,
            "automatable": "yes" if self.automatable else "no",
            "technical_impact": "total" if self.total_impact else "partial",
        }


@lru_cache(maxsize=1)
def _load() -> Dict[str, Any]:
    with open(_CATALOG_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def source() -> Dict[str, Any]:
    """Where and when the public facts were read."""
    return dict(_load().get("source") or {})


def cves() -> Dict[str, Dict[str, Any]]:
    return dict(_load()["cves"])


def cve(cve_id: str) -> Optional[Dict[str, Any]]:
    entry = _load()["cves"].get(str(cve_id or "").upper())
    return dict(entry) if entry else None


def cve_ids() -> List[str]:
    return list(_load()["cves"].keys())


def _yes(value: Any) -> bool:
    return str(value).strip().lower() in ("yes", "true", "1", "total")


def rate(cve_id: str, *, publicly_exposed: bool) -> Rating:
    """BOD 26-04 Table 1 for one CVE on one asset."""
    entry = cve(cve_id)
    if entry is None:
        raise KeyError(cve_id)
    in_kev = bool(entry.get("kev"))
    automatable = _yes(entry.get("automatable"))
    total = str(entry.get("technical_impact") or "").lower() == "total"
    for row in _load()["bod_2604"]:
        if (_yes(row["publicly_exposed"]) == bool(publicly_exposed)
                and _yes(row["in_kev"]) == in_kev
                and _yes(row["automatable"]) == automatable
                and (row["technical_impact"] == "total") == total):
            timeline = row["timeline"]
            return Rating(
                row=int(row["row"]), timeline=timeline, due_days=_TIMELINE_DAYS[timeline],
                forensic_triage="forensic triage" in timeline,
                severity=_TIMELINE_SEVERITY[timeline], publicly_exposed=bool(publicly_exposed),
                in_kev=in_kev, automatable=automatable, total_impact=total,
            )
    raise LookupError(f"no BOD 26-04 row for {cve_id}")  # unreachable: the table is complete


def worst(severities: List[str]) -> str:
    present = [s for s in severities if s in SEVERITY_ORDER]
    if not present:
        return "low"
    return min(present, key=SEVERITY_ORDER.index)


def bod_table() -> List[Dict[str, Any]]:
    return [dict(r) for r in _load()["bod_2604"]]
