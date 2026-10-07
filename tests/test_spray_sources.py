"""The Prompt Injection Spray's source addresses are owned, synthetic and documented.

An AI Trust dry run found the spray rotating RFC 5737 documentation addresses
(which the ES Triage agent recognized as test ranges and called benign) plus one
routable address belonging to a real third party. The sources are now PseudoCo's
own internal hosts in RFC 1918 space, each documented as an ES asset in
deploy/splunk/es_assets_pseudoco_spray_sources.csv. This pins:

* every source is private (RFC 1918), never documentation, never routable;
* the turn driver draws from that roster and nothing else;
* the asset CSV documents exactly the roster, in ES Asset & Identity form.

Run:  venv/bin/python tests/test_spray_sources.py
"""
from __future__ import annotations

import csv
import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.spray_campaign import CLIENT_ADDRESSES, SPRAY_SOURCES  # noqa: E402

ASSETS_CSV = ROOT / "deploy" / "splunk" / "es_assets_pseudoco_spray_sources.csv"
# ES Asset & Identity's asset lookup columns, in its documented order.
ES_ASSET_COLUMNS = ["ip", "mac", "nt_host", "dns", "owner", "priority", "lat", "long", "city",
                    "country", "bunit", "category", "pci_domain", "is_expected",
                    "should_timesync", "should_update", "requires_av"]
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
RFC5737 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# The AWS default VPC: a lab box's own address must never be mistaken for the attacker.
AWS_DEFAULT_VPC = ipaddress.ip_network("172.31.0.0/16")

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def test_addresses() -> None:
    print("== spray source addresses ==")
    check("at least three sources, so the campaign shows a source pivot", len(CLIENT_ADDRESSES) >= 3)
    check("no duplicate addresses", len(set(CLIENT_ADDRESSES)) == len(CLIENT_ADDRESSES))
    check("CLIENT_ADDRESSES is exactly the documented roster",
          CLIENT_ADDRESSES == [s["ip"] for s in SPRAY_SOURCES])
    for raw in CLIENT_ADDRESSES:
        ip = ipaddress.ip_address(raw)
        check(f"{raw} is RFC 1918 (owned, unroutable)", any(ip in n for n in RFC1918))
        check(f"{raw} is not an RFC 5737 documentation address", not any(ip in n for n in RFC5737))
        check(f"{raw} is not globally routable", not ip.is_global)
        check(f"{raw} is outside the AWS default VPC (a lab box's own range)", ip not in AWS_DEFAULT_VPC)
    check("the third-party address from the dry run is gone", "76.87.129.168" not in CLIENT_ADDRESSES)


def test_driver_uses_roster() -> None:
    print("== the turn driver draws from the roster ==")
    src = (ROOT / "backend" / "routers" / "spray.py").read_text()
    check("spray.py picks client_address from CLIENT_ADDRESSES",
          "client_address=rng.choice(CLIENT_ADDRESSES)" in src)


def test_assets_csv() -> None:
    print("== ES asset documentation ==")
    check("asset CSV exists", ASSETS_CSV.exists(), str(ASSETS_CSV))
    if not ASSETS_CSV.exists():
        return
    with ASSETS_CSV.open(newline="") as fh:
        reader = csv.DictReader(fh)
        header = reader.fieldnames
        rows = list(reader)
    check("CSV header is the ES asset lookup's column set", header == ES_ASSET_COLUMNS, str(header))
    by_ip = {r["ip"]: r for r in rows}
    check("CSV documents exactly the roster's addresses",
          sorted(by_ip) == sorted(CLIENT_ADDRESSES), str(sorted(by_ip)))
    for s in SPRAY_SOURCES:
        row = by_ip.get(s["ip"], {})
        check(f"{s['ip']}: nt_host + dns match the roster",
              row.get("nt_host") == s["nt_host"] and row.get("dns") == s["dns"], str(row))
        check(f"{s['ip']}: category carries the roster's category",
              s["category"] in (row.get("category") or "").split("|"), str(row.get("category")))
        check(f"{s['ip']}: owned by PseudoCo", "PseudoCo" in (row.get("owner") or ""))


def main() -> int:
    for fn in (test_addresses, test_driver_uses_roster, test_assets_csv):
        fn()
    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
        return 1
    print("All spray-source checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
