"""Splunk HEC destination config (one per integration).

Mirrors the shape of ThreatGenerator's ``HECConfig`` but adapted for PseudoCo Assistant:
the forwarded "event" is a governance/audit log dict keyed by ``log_type``
(governance|escalation|audit|error), and the token is carried in the config
(persisted in the local SQLite DB) rather than the OS keychain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

DEFAULT_INDEX = "main"
DEFAULT_SOURCE = "medadvice"
# Must match the sourcetype whose props.conf sets KV_MODE = json, so the
# governance JSON body is field-extracted at search time. Dashboards and the
# ES correlation rule search `sourcetype="gen_ai:json"`; a destination seeded
# with anything else indexes fine but reads as an empty dashboard.
DEFAULT_SOURCETYPE = "gen_ai:json"
DEFAULT_HOST = "medadvice"


def effective_host(destination_host: str = "") -> str:
    """The ``host`` stamped on an event sent to a destination.

    ``HEC_HOST`` (settings.hec_host) wins when set: each lab instance stamps its
    own name, so ES can tell instances apart even though every destination was
    created with the same default. Empty keeps today's behaviour: the
    destination's own ``host``, else ``DEFAULT_HOST``."""
    from backend.config import settings

    stamp = str(getattr(settings, "hec_host", "") or "").strip()
    return stamp or str(destination_host or "").strip() or DEFAULT_HOST


@dataclass
class HECConfig:
    id: str = ""
    name: str = ""
    enabled: bool = False
    url: str = ""
    token: str = ""
    verify_tls: bool = True
    index: str = DEFAULT_INDEX
    source: str = DEFAULT_SOURCE
    sourcetype: str = DEFAULT_SOURCETYPE
    host: str = DEFAULT_HOST
    # Optional per-log-type sourcetype override, e.g. {"escalation": "medadvice:escalation"}
    sourcetype_map: Dict[str, str] = field(default_factory=dict)
    batch_size: int = 100
    flush_interval_s: float = 2.0
    queue_max: int = 10000
    request_timeout_s: float = 10.0
    max_retries: int = 3

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HECConfig":
        d = dict(d or {})
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})
