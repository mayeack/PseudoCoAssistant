"""The tracestate guard (CVE-2026-114603).

opentelemetry-api < 1.45.1 parses W3C ``tracestate`` in quadratic time, so a
single oversized header can stall the event loop. backend/telemetry/
tracestate_guard.py drops any combined tracestate over 512 characters before
OpenTelemetry parses it. These checks pin that behaviour, that normal headers
up to the limit still parse, and that ``traceparent`` still propagates.

No network, no OpenTelemetry exporter:
    venv/bin/python tests/test_tracestate_guard.py
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

logging.disable(logging.CRITICAL)  # OTel logs every malformed member at WARNING

from backend.telemetry import tracestate_guard  # noqa: E402

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def test_guard() -> None:
    from opentelemetry.trace.span import TraceState

    check("install() activates the guard", tracestate_guard.install() is True)
    check("install() is idempotent", tracestate_guard.install() is True)

    ok = TraceState.from_header(["congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"])
    check("a normal tracestate still parses", dict(ok) == {"congo": "t61rcWkgMzE", "rojo": "00f067aa0ba902b7"})

    members = [f"k{i}=" + "v" * 124 for i in range(4)]  # 4 x 127 chars + 3 commas = 511
    at_limit = ",".join(members) + "," * (tracestate_guard.MAX_TRACESTATE_CHARS - 511)
    check("a 512-char tracestate still parses",
          len(at_limit) == tracestate_guard.MAX_TRACESTATE_CHARS and len(TraceState.from_header([at_limit])) == 4,
          f"len={len(at_limit)}")

    hostile = "a=b" + " " * 40_000 + "x"
    t = time.perf_counter()
    dropped = TraceState.from_header([hostile])
    dt = time.perf_counter() - t
    check("an oversized tracestate is dropped", len(dropped) == 0)
    check("an oversized tracestate is dropped fast", dt < 0.05, f"{dt:.3f}s")

    split = ["a=" + "b" * 300, "c=" + "d" * 300]  # each under, combined over
    check("the limit applies to the combined header list", len(TraceState.from_header(split)) == 0)


def test_propagation() -> None:
    from opentelemetry import trace
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    carrier = {
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "tracestate": "a=b" + " " * 40_000 + "x",
    }
    t = time.perf_counter()
    ctx = TraceContextTextMapPropagator().extract(carrier)
    dt = time.perf_counter() - t
    span_ctx = trace.get_current_span(ctx).get_span_context()
    check("traceparent still propagates when tracestate is dropped",
          span_ctx.trace_id == 0x4BF92F3577B34DA6A3CE929D0E0E4736, hex(span_ctx.trace_id))
    check("extract() with a hostile tracestate returns fast", dt < 0.05, f"{dt:.3f}s")


def main() -> int:
    for fn in (test_guard, test_propagation):
        fn()
    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
        return 1
    print("All tracestate-guard checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
