#!/usr/bin/env python3
"""Regression: host-capability detection + option gating (backend/host_capabilities.py).

Guards the rules that grey out options this box cannot run:
  - provider=nvidia (local NIM inference) needs an NVIDIA GPU on this host;
  - a featured NIM image needs the GPU count / memory it documents;
  - the NemoClaw runtime needs Docker/Colima (Podman is unsupported) and Node >= 22.19;
  - detection never raises when a probe binary is missing, and the cache /
    refresh contract the Settings poll relies on holds.

Offline: every probe is stubbed. Run:
    venv/bin/python tests/test_host_capabilities.py    # exit 0 = pass
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import host_capabilities as hc  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


class _Settings:
    nvidia_base_url = "http://localhost:8000/v1"
    nvidia_api_key = ""
    nvidia_featured_models = (
        "nvidia/nvidia-nemotron-nano-9b-v2|1x A10G / L4 24 GB|22000|1,"
        "nvidia/nemotron-3-super-120b-a12b|8x H100-80GB|76000|8"
    )


def _caps(*, gpu_present, count=1, vram=24000, runtime="docker", available=True,
          node_ok=True, nim_ready=True, url_error=None):
    return {
        "platform": {"os": "linux", "arch": "x86_64"},
        "nvidia_gpu": {"present": gpu_present, "count": count if gpu_present else 0,
                       "name": "NVIDIA A10G" if gpu_present else "", "vram_mb": vram if gpu_present else 0,
                       "total_vram_mb": vram * count if gpu_present else 0, "driver": "550", "source": "nvidia-smi"},
        "container_runtime": {"name": runtime, "available": available, "version": "27", "nvidia_runtime": gpu_present},
        "node": {"version": "22.23.1" if node_ok else "20.1.0", "ok": node_ok},
        "nim": {"base_url": "http://localhost:8000/v1", "ready": nim_ready, "url_error": url_error},
        "checked_at": 0.0,
    }


def test_gpu_less_mac_greys_nvidia_and_nemoclaw_on_podman() -> None:
    g = hc.gated_rules(_caps(gpu_present=False, runtime="podman", nim_ready=False), _Settings())
    check("no GPU -> provider_nvidia gated off", g["provider_nvidia"]["enabled"] is False)
    check("reason says local inference needs a GPU here", "NVIDIA GPU" in g["provider_nvidia"]["reason"])
    check("no GPU -> nim_local gated off", g["nim_local"]["enabled"] is False)
    check("podman -> NemoClaw runtime unsupported with the Colima fix",
          g["nemoclaw_runtime"]["enabled"] is False and "colima" in g["nemoclaw_runtime"]["reason"].lower())
    check("every featured image gated off without a GPU",
          all(v["enabled"] is False for v in g["nvidia_models"].values()))


def test_a10g_box_fits_nano_not_super() -> None:
    # A real A10G reports 23028 MiB for its "24 GB": the per-GPU floor in the
    # featured list is the REPORTED size, so this box must not be greyed out.
    g = hc.gated_rules(_caps(gpu_present=True, count=1, vram=23028), _Settings())
    check("GPU present -> provider_nvidia enabled", g["provider_nvidia"]["enabled"] is True)
    check("NIM ready -> nim_local enabled", g["nim_local"]["enabled"] is True)
    m = g["nvidia_models"]
    check("nano-9b enabled on one A10G reporting 23028 MB",
          m["nvidia/nvidia-nemotron-nano-9b-v2"]["enabled"] is True, str(m))
    check("Nemotron 3 Super gated off on one A10G with its requirement in the reason",
          m["nvidia/nemotron-3-super-120b-a12b"]["enabled"] is False
          and "8x H100-80GB" in m["nvidia/nemotron-3-super-120b-a12b"]["reason"])
    g3 = hc.gated_rules(_caps(gpu_present=True, count=8, vram=81559), _Settings())
    check("Nemotron 3 Super enabled on 8x H100 reporting 81559 MB each",
          g3["nvidia_models"]["nvidia/nemotron-3-super-120b-a12b"]["enabled"] is True)
    g4 = hc.gated_rules(_caps(gpu_present=True, count=2, vram=81559), _Settings())
    check("Nemotron 3 Super gated off on 2x H100 (GPU count)",
          g4["nvidia_models"]["nvidia/nemotron-3-super-120b-a12b"]["enabled"] is False)


def test_gpu_but_nim_down_and_remote_url() -> None:
    g = hc.gated_rules(_caps(gpu_present=True, nim_ready=False), _Settings())
    check("GPU present but NIM down -> nim_local off with the start hint",
          g["nim_local"]["enabled"] is False and "health/ready" in g["nim_local"]["reason"])
    check("provider stays selectable (the model list explains the NIM state)",
          g["provider_nvidia"]["enabled"] is True)
    g2 = hc.gated_rules(_caps(gpu_present=True, url_error="not on this host"), _Settings())
    check("a remote NIM URL is reported as the nim_local reason", g2["nim_local"]["reason"] == "not on this host")


def test_nemoclaw_runtime_rules() -> None:
    check("docker + node ok -> supported",
          hc.gated_rules(_caps(gpu_present=False), _Settings())["nemoclaw_runtime"]["enabled"] is True)
    check("colima counts as docker",
          hc.gated_rules(_caps(gpu_present=False, runtime="colima"), _Settings())["nemoclaw_runtime"]["enabled"] is True)
    g = hc.gated_rules(_caps(gpu_present=False, node_ok=False), _Settings())
    check("old node -> unsupported, names the minimum",
          g["nemoclaw_runtime"]["enabled"] is False and "22.19" in g["nemoclaw_runtime"]["reason"])
    g = hc.gated_rules(_caps(gpu_present=False, runtime="none", available=False), _Settings())
    check("no runtime -> unsupported", g["nemoclaw_runtime"]["enabled"] is False)


def test_probes_never_raise_and_cache_refreshes() -> None:
    # Missing binaries (the common Mac case for nvidia-smi) must read as absent.
    check("_run on a missing binary -> None", hc._run(["definitely-not-a-binary-xyz"]) is None)
    gpu = hc.probe_nvidia_gpu()
    check("probe_nvidia_gpu returns the contract shape",
          set(gpu) >= {"present", "count", "name", "vram_mb", "driver", "source"})
    node = hc.probe_node()
    check("probe_node returns version/ok", set(node) == {"version", "ok"})

    orig_now = hc._detect_now
    calls = {"n": 0}

    def _fake_now(_settings):
        calls["n"] += 1
        return _caps(gpu_present=False, runtime="podman", nim_ready=False)

    try:
        hc._detect_now = _fake_now  # type: ignore[assignment]
        hc._cache.clear(); hc._cached_at = 0.0
        d1 = hc.detect(force=True)
        d2 = hc.detect()
        check("second detect within the TTL is served from cache", calls["n"] == 1)
        check("detect returns capabilities + gated", "capabilities" in d1 and "gated" in d2)
        check("current() mirrors the cache without probing", hc.current().get("gated") == d1["gated"])
        hc.detect(force=True)
        check("force re-probes", calls["n"] == 2)
        check("summary_line is one line of text", "\n" not in hc.summary_line() and "NIM" in hc.summary_line())
    finally:
        hc._detect_now = orig_now
        hc._cache.clear(); hc._cached_at = 0.0


def test_current_revalidates_a_stale_snapshot() -> None:
    """A NIM that comes up AFTER the app (the normal order on a fresh GPU box)
    must flip nim_local within a TTL, not never: current() kicks one
    background re-probe when the snapshot is older than _CACHE_TTL."""
    import threading
    import time

    orig_now = hc._detect_now
    calls = {"n": 0}
    done = threading.Event()

    def _fake_now(_settings):
        calls["n"] += 1
        done.set()
        return _caps(gpu_present=True, runtime="docker", nim_ready=calls["n"] > 1)

    try:
        hc._detect_now = _fake_now  # type: ignore[assignment]
        hc._cache.clear(); hc._cached_at = 0.0; hc._refreshing = False
        hc.detect(force=True)                       # snapshot 1: NIM down
        check("fresh snapshot: current() does not re-probe", hc.current() and calls["n"] == 1)
        hc._cached_at = time.monotonic() - hc._CACHE_TTL - 1   # age it past the TTL
        done.clear()
        stale = hc.current()
        check("stale snapshot is returned immediately (stale-while-revalidate)",
              stale["gated"]["nim_local"]["enabled"] is False)
        done.wait(5)
        for _ in range(50):                          # the thread updates the cache right after
            if hc.current()["gated"]["nim_local"]["enabled"]:
                break
            time.sleep(0.05)
        check("one background re-probe ran and the cache now says NIM ready",
              calls["n"] == 2 and hc.current()["gated"]["nim_local"]["enabled"] is True)
        hc.current(); hc.current()
        check("a fresh snapshot does not re-probe again", calls["n"] == 2 and hc._refreshing is False)
    finally:
        hc._detect_now = orig_now
        hc._cache.clear(); hc._cached_at = 0.0; hc._refreshing = False


def test_pdf_attachments_rule() -> None:
    """Chat attachments (docs/attachments.md): PDF support needs pypdf. The rule
    lives here only; the chat API (503) and the Attach button (greyed out) read it."""
    from backend.services import attachments  # noqa: PLC0415 - imports backend.config

    g = hc.gated_rules(_caps(gpu_present=False), _Settings())
    check("gated_rules carries pdf_attachments, enabled with pypdf installed",
          g.get("pdf_attachments") == {"enabled": True, "reason": ""}, str(g.get("pdf_attachments")))
    check("the rule does not depend on the GPU / runtime probes",
          hc.gated_rules(_caps(gpu_present=True, runtime="none", available=False), _Settings())["pdf_attachments"]
          == g["pdf_attachments"])

    real_find_spec = hc.importlib.util.find_spec

    def _no_pypdf(name, *a, **k):
        return None if name == "pypdf" else real_find_spec(name, *a, **k)

    orig_now = hc._detect_now
    try:
        hc.importlib.util.find_spec = _no_pypdf
        off = hc.gated_rules(_caps(gpu_present=False), _Settings())["pdf_attachments"]
        check("no pypdf -> pdf_attachments gated off with the install hint",
              off == {"enabled": False, "reason": "PDF support is not installed (pip install -r requirements.txt)"},
              str(off))
        hc._cache.clear(); hc._cached_at = 0.0; hc._refreshing = False
        check("pdf_support() evaluates the rule itself before the first detect()",
              attachments.pdf_support() == (False, off["reason"]), str(attachments.pdf_support()))
        hc.importlib.util.find_spec = real_find_spec
        hc._detect_now = lambda _settings: _caps(gpu_present=False)  # type: ignore[assignment]
        hc.detect(force=True)
        check("pdf_support() reads the cached gate once detected", attachments.pdf_support() == (True, ""))
        hc._cache["gated"] = {**hc._cache["gated"], "pdf_attachments": off}
        check("pdf_support() never re-derives a cached gate (one gating channel)",
              attachments.pdf_support() == (False, off["reason"]), str(attachments.pdf_support()))
    finally:
        hc.importlib.util.find_spec = real_find_spec
        hc._detect_now = orig_now
        hc._cache.clear(); hc._cached_at = 0.0; hc._refreshing = False


def main() -> int:
    for fn in (
        test_gpu_less_mac_greys_nvidia_and_nemoclaw_on_podman,
        test_a10g_box_fits_nano_not_super,
        test_gpu_but_nim_down_and_remote_url,
        test_nemoclaw_runtime_rules,
        test_probes_never_raise_and_cache_refreshes,
        test_current_revalidates_a_stale_snapshot,
        test_pdf_attachments_rule,
    ):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            global _fails
            _fails += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
