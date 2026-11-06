"""Regression tests for the Auto-Generate Sessions generator (auto_prompter).

In the October 2026 runs on the Mac, every "Auto-prompter error:" line was the
generator's own 30 s httpx timeout firing on a slow Multi-Agent turn. The server
finished every one of those turns with a 200. The blank error text made it read
like a hang. These checks keep the fix from regressing:

  - the self-call timeout leaves room for a slow Multi-Agent turn (72 s was
    observed) and matches the incident load driver's budget;
  - a generated session still sends all its turns, each in Multi-Agent Mode;
  - an exception with an empty message is logged with its type name.

Standalone (no pytest), like the other suites:

    venv/bin/python tests/test_auto_prompter.py

No network, no DB: the HTTP self-calls go to an httpx.MockTransport.
"""
import asyncio
import inspect
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

import backend.config  # noqa: E402,F401  (loads .env)
import backend.services.auto_prompter as ap  # noqa: E402
import backend.routers.incident as incident  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


async def _no_sleep(*_a, **_k):
    return None


# --- 1. A generated session: timeout budget and Multi-Agent turns ------------------
def run_one_session():
    seen_kwargs = {}
    messages = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/session/new":
            return httpx.Response(200, json={"session_id": "s-test"})
        if request.url.path == "/api/chat/message":
            import json
            messages.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        seen_kwargs.update(kwargs)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    svc = ap.AutoPrompterService()
    svc._running = True
    real_sleep = ap.asyncio.sleep
    ap.httpx.AsyncClient = fake_client
    ap.asyncio.sleep = _no_sleep
    try:
        asyncio.run(svc._create_and_run_session())
    finally:
        ap.httpx.AsyncClient = real_client
        ap.asyncio.sleep = real_sleep
    return seen_kwargs, messages


kwargs, msgs = run_one_session()
timeout = kwargs.get("timeout")
read_s = timeout.read if isinstance(timeout, httpx.Timeout) else timeout
check("self-call timeout is set", read_s is not None, repr(timeout))
check("self-call timeout outlasts the slowest observed Multi-Agent turn (72 s)",
      read_s is not None and read_s > 72, f"read timeout {read_s}")
check("self-call timeout is no longer the 30 s that dropped sessions",
      read_s is not None and read_s > 30, f"read timeout {read_s}")
incident_src = inspect.getsource(incident._fire_one)
check("timeout matches the incident load driver's budget",
      f"httpx.Timeout({ap.AutoPrompterService.TURN_TIMEOUT_S})" in incident_src,
      f"TURN_TIMEOUT_S={ap.AutoPrompterService.TURN_TIMEOUT_S}")
check("a session sends its opening turn plus every follow-up (5 turns)",
      len(msgs) == 5, f"sent {len(msgs)}")
check("every generated turn is Multi-Agent",
      bool(msgs) and all(m.get("multi_agent_mode") is True for m in msgs),
      str([m.get("multi_agent_mode") for m in msgs]))


# --- 2. An empty-message timeout is logged by type, not as a blank line ------------
class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def run_failing_loop():
    svc = ap.AutoPrompterService()
    svc._running = True

    async def boom():
        raise httpx.ReadTimeout("")  # str() is "", as in the October logs

    async def stop_after_one(*_a, **_k):
        svc._running = False

    svc._create_and_run_session = boom
    cap = _Capture()
    ap.logger.addHandler(cap)
    real_sleep = ap.asyncio.sleep
    ap.asyncio.sleep = stop_after_one
    try:
        asyncio.run(svc._run_loop())
    finally:
        ap.asyncio.sleep = real_sleep
        ap.logger.removeHandler(cap)
    return svc, cap.lines


svc, lines = run_failing_loop()
err_lines = [l for l in lines if l.startswith("Auto-prompter error:")]
check("a failed session logs one error line", len(err_lines) == 1, str(lines))
check("the error line names the exception type (ReadTimeout)",
      bool(err_lines) and "ReadTimeout" in err_lines[0], str(err_lines))
check("a failed session is not counted as created", svc.stats["sessions_created"] == 0,
      str(svc.stats))
check("_describe_error keeps a non-empty message",
      ap._describe_error(ValueError("bad")) == "ValueError: bad",
      ap._describe_error(ValueError("bad")))


if _failures:
    print(f"\n{len(_failures)} FAILED: {_failures}")
    sys.exit(1)
print("\nAll auto-prompter checks passed.")
