"""Cap inbound W3C ``tracestate`` before OpenTelemetry parses it (CVE-2026-114603).

opentelemetry-api < 1.45.1 splits ``tracestate`` with a regular expression whose
cost grows quadratically with a run of spaces or tabs, and applies no length
limit first: one unauthenticated request carrying a ~40 KB header blocks the
event loop for seconds. When the app runs under ``opentelemetry-instrument``
(run.sh, telemetry on), the ASGI middleware parses that header on every request,
before AccessKeyMiddleware, so it is reachable from the public tunnel.

The fix ships in opentelemetry-api 1.45.1, but this app stays on the OTel 1.38
line that splunk-opentelemetry 2.8.0 and splunk-otel-instrumentation-langchain
pin. Until that line moves, a combined ``tracestate`` longer than the W3C
propagation limit (512 characters) is discarded — the spec lets a receiver drop
``tracestate`` — and anything shorter is parsed unchanged. ``traceparent`` is
untouched, so trace correlation still works.

Delete this module (and its ``install()`` call in backend/main.py) once
opentelemetry-api >= 1.45.1.
"""
from __future__ import annotations

import typing

MAX_TRACESTATE_CHARS = 512

_installed = False


def install() -> bool:
    """Patch ``TraceState.from_header`` once. Returns True when the guard is active."""
    global _installed
    if _installed:
        return True
    try:
        from opentelemetry.trace.span import TraceState
    except Exception:  # OpenTelemetry not installed: nothing to guard
        return False

    parse = TraceState.from_header.__func__

    def from_header(cls, header_list: typing.List[str]) -> "TraceState":
        if sum(len(h) for h in header_list) > MAX_TRACESTATE_CHARS:
            return cls()
        return parse(cls, header_list)

    TraceState.from_header = classmethod(from_header)
    _installed = True
    return True
