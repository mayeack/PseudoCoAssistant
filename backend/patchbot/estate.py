"""The synthetic estate: six servers per attendee, their packages, the exposure
model, and the findings the scanner reports on them (docs/patchbot.md).

Pure state logic over one JSON document per estate owner. Nothing here logs,
emits telemetry or calls a model; ``service.py`` wraps these operations with
the activity feed, HEC events and Agent Observability traces.

A host is vulnerable to a CVE when the CVE applies to it (``APPLIES``) and the
installed version of the CVE's package is the catalog's vulnerable version.
Patching sets the fixed version; the "Roll back package" Demo Control sets the
vulnerable version again, so a finding can reopen.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from backend.patchbot import catalog

SCHEMA_VERSION = 1

# host -> (os_family, environment, role, publicly exposed by asset data, label)
HOSTS: Dict[str, Dict[str, Any]] = {
    "web-dev-01": {"os_family": "linux", "environment": "development", "role": "web",
                   "os": "Ubuntu 20.04 LTS", "publicly_exposed": False,
                   "purpose": "Development web tier"},
    "web-stg-01": {"os_family": "linux", "environment": "staging", "role": "web",
                   "os": "Ubuntu 20.04 LTS", "publicly_exposed": False,
                   "purpose": "Staging web tier"},
    "web-prod-01": {"os_family": "linux", "environment": "production", "role": "web",
                    "os": "Ubuntu 20.04 LTS", "publicly_exposed": True,
                    "purpose": "Customer-facing web tier"},
    "web-prod-02": {"os_family": "linux", "environment": "production", "role": "web",
                    "os": "Ubuntu 20.04 LTS", "publicly_exposed": False,
                    "purpose": "Customer-facing web tier, second node"},
    "db-prod-01": {"os_family": "linux", "environment": "production", "role": "database",
                   "os": "RHEL 8.4", "publicly_exposed": False,
                   "purpose": "Orders database"},
    "win-stg-01": {"os_family": "windows", "environment": "staging", "role": "file_print",
                   "os": "Windows Server 2019", "publicly_exposed": False,
                   "purpose": "Staging file and print server"},
    "win-prod-01": {"os_family": "windows", "environment": "production", "role": "file_print",
                    "os": "Windows Server 2019", "publicly_exposed": False,
                    "purpose": "File and print server"},
    "dc-prod-01": {"os_family": "windows", "environment": "production", "role": "domain_controller",
                   "os": "Windows Server 2019", "publicly_exposed": False,
                   "purpose": "Domain controller"},
}

# Which CVE the synthetic estate carries on which hosts.
APPLIES: Dict[str, List[str]] = {
    "CVE-2021-41773": ["web-dev-01", "web-stg-01", "web-prod-01", "web-prod-02"],
    "CVE-2020-1472": ["dc-prod-01"],
    "CVE-2021-3156": ["web-stg-01", "web-prod-01"],
    "CVE-2021-34527": ["win-stg-01", "win-prod-01"],
    "CVE-2021-4034": ["db-prod-01"],
    "CVE-2023-0286": ["db-prod-01"],
    "CVE-2023-48795": ["web-stg-01", "web-prod-01"],
}

# Change models (Splunk-first labs). A server's characteristics decide its model:
# production needs a normal change a Change Approver approves on the Change Board;
# anything else falls under the pre-approved standard change template.
STANDARD_CHANGE_TEMPLATE = {
    "id": "SC-APACHE-SEC",
    "title": "Apache httpd security update on non-production web servers",
    "criteria": "Non-production server, the vendor's fixed version of the same package, the fix already "
                "tested, rollback from the package cache.",
}


def change_model(state: Dict[str, Any], host_name: str) -> str:
    h = (state.get("hosts") or {}).get(host_name) or HOSTS.get(host_name) or {}
    return "normal" if h.get("environment") == "production" else "standard"


DISMISS_REASONS = ("false_positive", "accepted_risk", "duplicate")
_OWNER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def valid_owner(owner: Any) -> bool:
    return bool(owner) and bool(_OWNER_RE.fullmatch(str(owner)))


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def finding_id(owner: str, cve_id: str) -> str:
    return f"PB-{owner}-{cve_id}"


def seed_state() -> Dict[str, Any]:
    """A fresh estate: every applicable package at its vulnerable version."""
    hosts: Dict[str, Any] = {}
    for name, spec in HOSTS.items():
        hosts[name] = {
            "os_family": spec["os_family"], "environment": spec["environment"],
            "role": spec["role"], "os": spec["os"], "purpose": spec["purpose"],
            "publicly_exposed": spec["publicly_exposed"],
            "exposure_source": "asset data",
            "compensating_control": None,
            "packages": {},
        }
    for cve_id, names in APPLIES.items():
        entry = catalog.cve(cve_id) or {}
        for name in names:
            hosts[name]["packages"][entry["package"]] = entry["vulnerable_version"]
    return {
        "schema": SCHEMA_VERSION,
        "hosts": hosts,
        "findings": {},          # cve -> triage meta (dismissal, assignee, change, ES ref)
        "exposure_answered": False,
        "full_read_done": False,
        "scans": 0,
        "advisories": [],
        "created_at": _now(),
    }


def ensure_schema(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(state, dict) or state.get("schema") != SCHEMA_VERSION or "hosts" not in state:
        return seed_state()
    seeded: Optional[Dict[str, Any]] = None
    for name in HOSTS:       # servers added to the estate later join an existing one, unpatched
        if name not in state["hosts"]:
            seeded = seeded or seed_state()
            state["hosts"][name] = seeded["hosts"][name]
    return state


# --------------------------------------------------------------------------- reads

def host(state: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    entry = (state.get("hosts") or {}).get(name)
    return dict(entry, name=name) if entry else None


def hosts(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(v, name=k) for k, v in (state.get("hosts") or {}).items()]


def is_vulnerable(state: Dict[str, Any], host_name: str, cve_id: str) -> bool:
    entry = catalog.cve(cve_id)
    h = (state.get("hosts") or {}).get(host_name)
    if not entry or not h or host_name not in APPLIES.get(cve_id, []):
        return False
    return h["packages"].get(entry["package"]) == entry["vulnerable_version"]


def host_rating(state: Dict[str, Any], host_name: str, cve_id: str) -> catalog.Rating:
    h = state["hosts"][host_name]
    return catalog.rate(cve_id, publicly_exposed=bool(h.get("publicly_exposed")))


def scan_results(state: Dict[str, Any], host_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """What the scanner sees: one row per applicable (host, CVE), open or fixed."""
    wanted = set(host_names or state["hosts"].keys())
    rows = []
    for cve_id, names in APPLIES.items():
        entry = catalog.cve(cve_id) or {}
        for name in names:
            if name not in wanted:
                continue
            h = state["hosts"][name]
            rating = host_rating(state, name, cve_id)
            rows.append({
                "dest": name, "dest_os": h["os_family"], "dest_env": h["environment"],
                "cve": cve_id, "signature": entry.get("short"), "cvss": entry.get("cvss"),
                "package": entry.get("package"),
                "installed_version": h["packages"].get(entry.get("package")),
                "fixed_version": entry.get("fixed_version"),
                "status": "open" if is_vulnerable(state, name, cve_id) else "fixed",
                "epss": entry.get("epss"),
                **rating.as_dict(),
            })
    return rows


def _sentences(text: str, limit: int) -> str:
    """Whole sentences of ``text`` up to about ``limit`` characters (never mid-word)."""
    out = ""
    for part in re.split(r"(?<=[.!?])\s+", " ".join(text.split())):
        if out and len(out) + len(part) + 1 > limit:
            break
        out = f"{out} {part}".strip()
    return out


def _host_phrase(names: List[str]) -> str:
    if not names:
        return "no host"
    if len(names) == 1:
        return names[0]
    return f"{names[0]} and {len(names) - 1} other host" + ("s" if len(names) > 2 else "")


def finding(state: Dict[str, Any], owner: str, cve_id: str) -> Optional[Dict[str, Any]]:
    entry = catalog.cve(cve_id)
    if not entry or cve_id not in APPLIES:
        return None
    names = APPLIES[cve_id]
    meta = (state.get("findings") or {}).get(cve_id) or {}
    open_hosts = [n for n in names if is_vulnerable(state, n, cve_id)]
    ratings = {n: host_rating(state, n, cve_id) for n in names}
    rated_hosts = open_hosts or names
    severity = catalog.worst([ratings[n].severity for n in rated_hosts])
    # The headline names the host that drives the rating (exposed production first).
    lead = sorted(rated_hosts, key=lambda n: (catalog.SEVERITY_ORDER.index(ratings[n].severity),
                                               not state["hosts"][n].get("publicly_exposed"),
                                               state["hosts"][n]["environment"] != "production"))
    lead_host = lead[0]
    exposed = bool(state["hosts"][lead_host].get("publicly_exposed"))
    template = entry.get("headline_public" if exposed else "headline_internal") or entry.get("short")
    headline = template.format(host=lead_host)
    dismissed = meta.get("dismissed")
    if dismissed:
        status, resolution = "resolved", f"dismissed_{dismissed.get('reason')}"
    elif not open_hosts:
        status, resolution = "resolved", meta.get("resolution") or "fixed"
    else:
        status, resolution = "open", None
    lead_rating = ratings[lead_host]
    comp = state["hosts"][lead_host].get("compensating_control")
    checks = [
        {"name": "Exposure", "ok": True,
         "text": ("reachable from the internet" if exposed else "internal network only")
                 + f" ({state['hosts'][lead_host].get('exposure_source', 'asset data')})"},
        {"name": "Exploitability", "ok": bool(entry.get("kev")) or entry.get("automatable") == "yes",
         "text": ", ".join(t for t in (
             "in CISA KEV" if entry.get("kev") else "not in CISA KEV",
             "can be automated" if entry.get("automatable") == "yes" else "not automatable",
             f"EPSS {entry.get('epss'):.2f}" if isinstance(entry.get("epss"), (int, float)) else None) if t)},
        {"name": "Compensating controls", "ok": not comp,
         "text": f"in place: {comp}" if comp else "none in front of the service"},
    ]
    return {
        "id": finding_id(owner, cve_id),
        "cve": cve_id,
        "title": headline,
        "short": entry.get("short"),
        "severity": severity,
        "status": status,
        "resolution": resolution,
        "hosts": names,
        "open_hosts": open_hosts,
        "lead_host": lead_host,
        "os_family": entry.get("os_family"),
        "package": entry.get("package"),
        "installed_version": state["hosts"][lead_host]["packages"].get(entry.get("package")),
        "fixed_version": entry.get("fixed_version"),
        "kev": bool(entry.get("kev")),
        "kev_date_added": entry.get("kev_date_added"),
        "epss": entry.get("epss"),
        "cvss": entry.get("cvss"),
        "automatable": entry.get("automatable"),
        "technical_impact": entry.get("technical_impact"),
        "bod": lead_rating.as_dict(),
        "host_ratings": {n: ratings[n].as_dict() for n in names},
        "checks": checks,
        "checks_passed": sum(1 for c in checks if c["ok"]),
        "attack_path": {
            "actor": "Internet user" if exposed else ("Signed-in account" if entry.get("vector") == "local"
                                                      else "Internal network user"),
            "actor_note": "no sign-in" if entry.get("vector") != "local" else "any local account",
            "service": entry.get("service"), "service_host": lead_host,
            "vulnerable": f"{entry.get('package')} {state['hosts'][lead_host]['packages'].get(entry.get('package'))}",
            "asset": entry.get("asset"),
            "missing_control": None if comp else entry.get("missing_control"),
        },
        "what_we_found": (
            f"{entry.get('short')} ({cve_id}) on {_host_phrase(open_hosts or names)}. "
            f"{_sentences(entry.get('description') or '', 320)}"
        ),
        "how_to_fix": entry.get("fix_text"),
        "why_rating": (
            f"BOD 26-04 row {lead_rating.row}: {lead_rating.timeline}. "
            f"{'Publicly exposed' if exposed else 'Internal only'}, "
            f"{'in KEV' if entry.get('kev') else 'not in KEV'}, "
            f"{'automatable' if entry.get('automatable') == 'yes' else 'not automatable'}, "
            f"{entry.get('technical_impact')} technical impact."
        ),
        "assignee": meta.get("assignee") or owner,
        "change_id": meta.get("change_id"),
        "investigation_id": meta.get("investigation_id"),
        "dismissed": dismissed,
        "found_at": meta.get("found_at"),
        "fixed_at": meta.get("fixed_at"),
        "reopened": int(meta.get("reopened") or 0),
    }


def findings(state: Dict[str, Any], owner: str) -> List[Dict[str, Any]]:
    """Every finding the estate has been scanned for, worst first."""
    out = [finding(state, owner, c) for c in APPLIES if (state.get("findings") or {}).get(c, {}).get("found_at")]
    out = [f for f in out if f]
    # Worst first; within a severity, what an attacker reaches first: publicly
    # exposed, then automatable, then the likeliest to be exploited (EPSS).
    return sorted(out, key=lambda f: (f["status"] != "open", catalog.SEVERITY_ORDER.index(f["severity"]),
                                      f["bod"]["publicly_exposed"] != "yes", f.get("automatable") != "yes",
                                      -(f.get("epss") or 0.0), f["cve"]))


def counts(found: List[Dict[str, Any]]) -> Dict[str, Any]:
    open_ = [f for f in found if f["status"] == "open"]
    by = {s: sum(1 for f in open_ if f["severity"] == s) for s in catalog.SEVERITY_ORDER}
    return {"open": len(open_), "resolved": len(found) - len(open_), "by_severity": by}


# --------------------------------------------------------------------------- writes
# Each returns (new_state, facts) and never mutates its input.

def record_found(state: Dict[str, Any], cve_ids: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Mark CVEs as found by a scan; returns the newly found ones. A fixed
    finding the scan sees again is reopened by ``reopen_if_vulnerable``."""
    s = copy.deepcopy(state)
    newly = []
    for cve_id in cve_ids:
        meta = s["findings"].setdefault(cve_id, {})
        if not meta.get("found_at"):
            meta["found_at"] = _now()
            newly.append(cve_id)
    return s, newly


def mark_fixed_if_clean(state: Dict[str, Any], cve_id: str, *, resolution: str) -> Tuple[Dict[str, Any], bool]:
    s = copy.deepcopy(state)
    meta = s["findings"].setdefault(cve_id, {})
    if any(is_vulnerable(s, n, cve_id) for n in APPLIES.get(cve_id, [])):
        return s, False
    if meta.get("fixed_at"):
        return s, False
    meta["fixed_at"] = _now()
    meta["resolution"] = resolution
    return s, True


def reopen_if_vulnerable(state: Dict[str, Any], cve_id: str) -> Tuple[Dict[str, Any], bool]:
    s = copy.deepcopy(state)
    meta = s["findings"].setdefault(cve_id, {})
    if meta.get("fixed_at") and any(is_vulnerable(s, n, cve_id) for n in APPLIES.get(cve_id, [])):
        meta.pop("fixed_at", None)
        meta.pop("resolution", None)
        meta["reopened"] = int(meta.get("reopened") or 0) + 1
        return s, True
    return s, False


def apply_patch(state: Dict[str, Any], host_name: str, cve_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    entry = catalog.cve(cve_id)
    if not entry or host_name not in APPLIES.get(cve_id, []):
        raise ValueError(f"{cve_id} does not apply to {host_name}")
    s = copy.deepcopy(state)
    pkgs = s["hosts"][host_name]["packages"]
    before = pkgs.get(entry["package"])
    pkgs[entry["package"]] = entry["fixed_version"]
    return s, {"package": entry["package"], "version_before": before, "version_after": entry["fixed_version"]}


def roll_back(state: Dict[str, Any], host_name: str, cve_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    entry = catalog.cve(cve_id)
    if not entry or host_name not in APPLIES.get(cve_id, []):
        raise ValueError(f"{cve_id} does not apply to {host_name}")
    s = copy.deepcopy(state)
    pkgs = s["hosts"][host_name]["packages"]
    before = pkgs.get(entry["package"])
    pkgs[entry["package"]] = entry["vulnerable_version"]
    return s, {"package": entry["package"], "version_before": before, "version_after": entry["vulnerable_version"]}


def set_exposure(state: Dict[str, Any], host_name: str, *, publicly_exposed: bool, source: str,
                 compensating_control: Optional[str] = None) -> Dict[str, Any]:
    if host_name not in state["hosts"]:
        raise ValueError(f"unknown host {host_name}")
    s = copy.deepcopy(state)
    h = s["hosts"][host_name]
    h["publicly_exposed"] = bool(publicly_exposed)
    h["exposure_source"] = source
    if compensating_control is not None:
        h["compensating_control"] = compensating_control.strip()[:120] or None
    return s


def dismiss(state: Dict[str, Any], cve_id: str, *, reason: str, note: str, actor: str) -> Dict[str, Any]:
    if reason not in DISMISS_REASONS:
        raise ValueError(f"reason must be one of {DISMISS_REASONS}")
    s = copy.deepcopy(state)
    s["findings"].setdefault(cve_id, {})["dismissed"] = {
        "reason": reason, "note": (note or "")[:500], "by": actor, "at": _now()}
    return s


def reopen(state: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
    s = copy.deepcopy(state)
    s["findings"].setdefault(cve_id, {}).pop("dismissed", None)
    return s


def set_meta(state: Dict[str, Any], cve_id: str, **values: Any) -> Dict[str, Any]:
    s = copy.deepcopy(state)
    meta = s["findings"].setdefault(cve_id, {})
    for k, v in values.items():
        if v is None:
            meta.pop(k, None)
        else:
            meta[k] = v
    return s
