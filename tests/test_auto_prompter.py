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


# --- 3. The 60-minute run timer ------------------------------------------------------
# The generator turns itself off DEFAULT_DURATION_S after it is switched on. The
# session itself is stubbed (no HTTP); a short duration stands in for the hour.
check("default run timer is 60 minutes", ap.AutoPrompterService.DEFAULT_DURATION_S == 3600,
      str(ap.AutoPrompterService.DEFAULT_DURATION_S))


def _stub_sessions(svc):
    async def one_session():
        await asyncio.sleep(0.01)
    svc._create_and_run_session = one_session


async def _timer_scenarios():
    out = {}
    real_sleep = asyncio.sleep

    # A real start() with the default duration reports the hour counting down.
    svc = ap.AutoPrompterService()
    _stub_sessions(svc)
    await svc.start()
    out["default_running"] = dict(svc.stats)
    await svc.stop()
    out["default_stopped"] = dict(svc.stats)

    # A short duration auto-stops on its own, mid-loop (the 60 s gap between
    # sessions is shortened so the loop is busy when the timer fires).
    async def short_sleep(delay, *a, **k):
        return await real_sleep(min(delay, 0.02), *a, **k)

    ap.asyncio.sleep = short_sleep
    try:
        svc2 = ap.AutoPrompterService()
        _stub_sessions(svc2)
        await svc2.start(duration_s=0.2)
        await real_sleep(0.05)
        out["short_running"] = dict(svc2.stats)
        await real_sleep(0.4)
        out["short_expired"] = dict(svc2.stats)
        out["short_task_done"] = svc2._task.done()

        # Switching it back on after an auto-stop starts a fresh run.
        await svc2.start(duration_s=0.2)
        out["restart_running"] = dict(svc2.stats)
        await real_sleep(0.4)
        out["restart_expired"] = dict(svc2.stats)

        # A manual stop is not reported as an auto-stop.
        svc3 = ap.AutoPrompterService()
        _stub_sessions(svc3)
        await svc3.start(duration_s=5)
        await real_sleep(0.05)
        await svc3.stop()
        out["manual_stopped"] = dict(svc3.stats)
    finally:
        ap.asyncio.sleep = real_sleep
    return out


t = asyncio.run(_timer_scenarios())
d = t["default_running"]
check("a running generator reports duration_s 3600", d["duration_s"] == 3600, str(d))
check("a running generator reports remaining_s close to the full hour",
      isinstance(d["remaining_s"], int) and 3590 <= d["remaining_s"] <= 3600, str(d))
check("a running generator reports expires_at", bool(d["expires_at"]), str(d))
check("a fresh run is not marked auto-stopped", d["auto_stopped"] is False, str(d))
ds = t["default_stopped"]
check("a stopped generator reports remaining_s None and no expires_at",
      ds["remaining_s"] is None and ds["expires_at"] is None, str(ds))

check("short run is running before its timer fires",
      t["short_running"]["running"] is True and t["short_running"]["sessions_created"] >= 1,
      str(t["short_running"]))
se = t["short_expired"]
check("the timer turns the generator off on its own", se["running"] is False, str(se))
check("an expired run is reported as auto-stopped", se["auto_stopped"] is True, str(se))
check("an expired run reports remaining_s None", se["remaining_s"] is None, str(se))
check("the loop task has finished after the timer fires", t["short_task_done"] is True)
check("switching it back on after an auto-stop runs again",
      t["restart_running"]["running"] is True and t["restart_running"]["auto_stopped"] is False,
      str(t["restart_running"]))
check("the restarted run also auto-stops",
      t["restart_expired"]["running"] is False and t["restart_expired"]["auto_stopped"] is True,
      str(t["restart_expired"]))
ms = t["manual_stopped"]
check("a manual stop is not reported as auto-stopped",
      ms["running"] is False and ms["auto_stopped"] is False, str(ms))


if _failures:
    print(f"\n{len(_failures)} FAILED: {_failures}")
    sys.exit(1)
print("\nAll auto-prompter checks passed.")
