"""What this host can run — so the UI greys out options that cannot work here.

Gate on the capability an option actually needs, not on a vendor name:

- ``provider=nvidia`` is a NIM container on THIS host, so it needs an NVIDIA
  GPU here (there is no cloud fallback for that provider by design).
- a featured NIM image needs enough GPU memory / GPUs, and only the one the
  running NIM serves can answer a chat turn.
- the NemoClaw runtime needs Docker Engine / Docker Desktop / Colima (Podman is
  explicitly unsupported by NemoClaw) and Node >= 22.19.
- PDF chat attachments need the pypdf package (docs/attachments.md); it is pure
  Python, so "installed" is the whole check.
- Duo sign-in (Lab 5) needs DUO_ENABLED, the Web SDK keys, an https
  PUBLIC_BASE_URL on a DNS name, and a passing Duo health check; once open, it
  closes only after 3 failed checks in a row. The rule reads settings and the
  cached health results (identity_signin re-runs the check every 5 minutes,
  off the event loop); it never calls Duo itself.

Every probe is best-effort, short, cached, and never raises: a missing binary
reads as "absent", not as an error. The Settings poll reads the cache;
``refresh_async`` re-probes at startup and on demand (POST /api/server-info/refresh).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import platform
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 3.0
_CACHE_TTL = 60.0
NEMOCLAW_MIN_NODE = (22, 19)

_lock = threading.Lock()
_cache: Dict[str, Any] = {}
_cached_at = 0.0
_refreshing = False   # one background re-probe in flight at a time


# --------------------------------------------------------------------------- probes
def _run(cmd: List[str], timeout: float = _PROBE_TIMEOUT) -> Optional[str]:
    """Run a probe command; stdout on success, None on any failure/absence."""
    if not cmd or shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def probe_nvidia_gpu() -> Dict[str, Any]:
    """NVIDIA GPU(s) on this host via nvidia-smi, with a sysfs/driver fallback."""
    out = _run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader,nounits"])
    if out:
        gpus = []
        for line in out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                try:
                    vram = int(float(parts[1]))
                except ValueError:
                    vram = 0
                gpus.append({"name": parts[0], "vram_mb": vram,
                             "driver": parts[2] if len(parts) > 2 else ""})
        if gpus:
            return {"present": True, "count": len(gpus), "name": gpus[0]["name"],
                    "vram_mb": min(g["vram_mb"] for g in gpus),
                    "total_vram_mb": sum(g["vram_mb"] for g in gpus),
                    "driver": gpus[0]["driver"], "source": "nvidia-smi"}
    # Driver present but nvidia-smi missing/erroring (or a container without it).
    if os.path.exists("/dev/nvidia0") or os.path.exists("/proc/driver/nvidia/version"):
        return {"present": True, "count": 1, "name": "NVIDIA GPU (driver detected)",
                "vram_mb": 0, "total_vram_mb": 0, "driver": "", "source": "driver"}
    return {"present": False, "count": 0, "name": "", "vram_mb": 0, "total_vram_mb": 0,
            "driver": "", "source": "none"}


def probe_container_runtime() -> Dict[str, Any]:
    """Which container runtime answers here. NemoClaw needs Docker/Colima; Podman
    is reported (Mode C uses it) but does not satisfy NemoClaw."""
    docker = _run(["docker", "info", "--format", "{{.ServerVersion}}|{{.OperatingSystem}}|{{json .Runtimes}}"])
    if docker:
        version, osname, runtimes = (docker.strip().split("|", 2) + ["", ""])[:3]
        name = "colima" if "colima" in osname.lower() or shutil.which("colima") else "docker"
        return {"name": name, "available": True, "version": version,
                "nvidia_runtime": '"nvidia"' in runtimes}
    podman = _run(["podman", "info", "--format", "{{.Version.Version}}"])
    if podman:
        return {"name": "podman", "available": True, "version": podman.strip(), "nvidia_runtime": False}
    if shutil.which("docker") or shutil.which("podman"):
        return {"name": "docker" if shutil.which("docker") else "podman", "available": False,
                "version": "", "nvidia_runtime": False}
    return {"name": "none", "available": False, "version": "", "nvidia_runtime": False}


def probe_node() -> Dict[str, Any]:
    out = _run(["node", "--version"])
    if not out:
        return {"version": "", "ok": False}
    ver = out.strip().lstrip("v")
    try:
        major, minor = (int(p) for p in ver.split(".")[:2])
    except ValueError:
        return {"version": ver, "ok": False}
    return {"version": ver, "ok": (major, minor) >= NEMOCLAW_MIN_NODE}


def probe_nim(settings) -> Dict[str, Any]:
    from backend import nvidia_nim

    base = settings.nvidia_base_url
    try:
        nvidia_nim.validate_nim_base_url(base)
        url_error = None
    except ValueError as exc:
        url_error = str(exc)
    ready = bool(not url_error and nvidia_nim.nim_ready(base, settings.nvidia_api_key or ""))
    return {"base_url": base, "ready": ready, "url_error": url_error}


# --------------------------------------------------------------------------- rules
def _gate(enabled: bool, reason: str = "") -> Dict[str, Any]:
    return {"enabled": bool(enabled), "reason": "" if enabled else reason}


def pdf_attachments_gate() -> Dict[str, Any]:
    """The ``pdf_attachments`` rule. A package lookup, no probe: ``gated_rules``
    carries it, and ``attachments.pdf_support()`` evaluates it directly only
    while there is no cached snapshot yet (before the first ``detect()``)."""
    return _gate(importlib.util.find_spec("pypdf") is not None,
                 "PDF support is not installed (pip install -r requirements.txt)")


# The Duo health check's cached result. The sign-in stage runs the check at
# startup and then on a timer (off the request path) and records each result
# here with record_duo_health(). Until a check has passed, the duo_signin gate
# stays closed ("not checked yet", or the latest failure). A passing check
# opens it, and it closes again only after DUO_HEALTH_FAILURES_TO_CLOSE failed
# checks in a row: one failed check (a blip on the timer) never closes it.
#: Consecutive failed Duo health checks that close an open duo_signin gate.
DUO_HEALTH_FAILURES_TO_CLOSE = 3
_duo_health: Dict[str, Any] = {"checked": False, "open": False, "failures": 0, "detail": ""}
_DUO_HEALTH_DETAIL_MAX = 160
# The Web SDK keys the Universal Prompt needs, by the .env name the reason shows.
_DUO_WEB_SDK_KEYS = (("DUO_CLIENT_ID", "duo_client_id"), ("DUO_CLIENT_SECRET", "duo_client_secret"),
                     ("DUO_API_HOST", "duo_api_host"))


def record_duo_health(ok: bool, detail: str = "") -> int:
    """Record a Duo health check's result for the ``duo_signin`` gate, and
    return how many checks in a row have now failed (0 after a pass).

    A pass opens the gate and clears the count. A failure keeps an open gate
    open until it is the ``DUO_HEALTH_FAILURES_TO_CLOSE``-th in a row; a gate
    that never opened stays closed, with this failure as its reason.

    ``detail`` is a short, already-sanitized failure description (an error
    class or HTTP status, never a URL, key or response body); it is shown as
    the gate's reason once the gate is closed. The cached snapshot is patched
    at once, so the Settings chip and ``GET /api/server-info`` agree without
    waiting for a re-probe."""
    text = " ".join(str(detail or "").split())[:_DUO_HEALTH_DETAIL_MAX]
    with _lock:
        if ok:
            _duo_health.update(checked=True, open=True, failures=0, detail="")
        else:
            failures = int(_duo_health["failures"]) + 1
            _duo_health.update(checked=True, failures=failures, detail=text,
                               open=bool(_duo_health["open"]) and failures < DUO_HEALTH_FAILURES_TO_CLOSE)
        failures = int(_duo_health["failures"])
    gate = duo_signin_gate()
    with _lock:
        if isinstance(_cache.get("gated"), dict):
            _cache["gated"] = {**_cache["gated"], "duo_signin": gate}
    return failures


def reset_duo_health() -> None:
    """Back to "not checked yet" (a settings reload, and tests)."""
    with _lock:
        _duo_health.update(checked=False, open=False, failures=0, detail="")


def duo_signin_gate(settings=None) -> Dict[str, Any]:
    """The ``duo_signin`` rule. Reads settings and the cached health result; no
    network call. Reasons, first match wins:

    1. disabled (``DUO_ENABLED`` off);
    2. Web SDK keys missing (named, never shown);
    3. ``PUBLIC_BASE_URL`` not https on an RFC 1034 host (the redirect URI's only source);
    4. the Duo health check is not passing: not run yet, failing since
       startup, or failed ``DUO_HEALTH_FAILURES_TO_CLOSE`` times in a row
       (fewer leave an open gate open).

    It gates starting a sign-in (``POST /auth/duo/start``, the sign-in page's
    button, the chat page's link), never finishing one: the callback does
    not read it.

    Attribute reads use ``getattr`` defaults, so a settings stub without the
    identity keys (tests/test_host_capabilities.py) reads as disabled."""
    if settings is None:
        from backend.config import settings
    if not getattr(settings, "duo_enabled", False):
        return _gate(False, "Duo sign-in is off (DUO_ENABLED is not true).")
    missing = [env for env, attr in _DUO_WEB_SDK_KEYS if not str(getattr(settings, attr, "") or "").strip()]
    if missing:
        return _gate(False, "Duo Web SDK keys missing: " + ", ".join(missing) + ".")
    if not getattr(settings, "public_base_url_is_https", False):
        return _gate(False, "PUBLIC_BASE_URL must be https:// on a DNS name (not an IP address) with no "
                            "path; the Duo redirect URI is built from it.")
    with _lock:
        health = dict(_duo_health)
    if not health["checked"]:
        return _gate(False, "The Duo health check has not run yet.")
    if not health["open"]:
        return _gate(False, "Duo health check failed" + (f": {health['detail']}" if health["detail"] else "."))
    return _gate(True)


def gated_rules(caps: Dict[str, Any], settings) -> Dict[str, Dict[str, Any]]:
    """The single place the 'can this option work here' rules live. The UI and
    the API validation both read these; neither re-derives them."""
    gpu = caps["nvidia_gpu"]
    runtime = caps["container_runtime"]
    node = caps["node"]
    nim = caps["nim"]

    provider_nvidia = _gate(
        gpu["present"],
        "provider=nvidia is local NIM inference on this host's NVIDIA GPU — none "
        "detected. Run the app on a GPU host (deploy/ec2 --with-nim), or reach a "
        "remote NIM through provider=openai (OPENAI_BASE_URL + OPENAI_REASONING).",
    )
    if nim["url_error"]:
        nim_local = _gate(False, nim["url_error"])
    elif not gpu["present"]:
        nim_local = _gate(False, "no NVIDIA GPU on this host — a NIM cannot run here")
    else:
        nim_local = _gate(
            nim["ready"],
            f"GPU present but no NIM answering {nim['base_url']}/health/ready — "
            "start it (systemctl start pseudoco-assistant-nim, or docker run … nvcr.io/nim/…).",
        )
    if not runtime["available"]:
        nemoclaw = _gate(False, "NemoClaw needs Docker Engine, Docker Desktop or Colima "
                                "— no container runtime is answering on this host.")
    elif runtime["name"] == "podman":
        nemoclaw = _gate(False, "NemoClaw does not support Podman (its onboarding refuses it). "
                                "On macOS: brew install colima docker && colima start.")
    elif not node["ok"]:
        nemoclaw = _gate(False, f"NemoClaw needs Node >= {NEMOCLAW_MIN_NODE[0]}.{NEMOCLAW_MIN_NODE[1]} "
                                f"(found {node['version'] or 'none'}).")
    else:
        nemoclaw = _gate(True)

    # Per featured NIM image: does the detected GPU meet its requirement?
    from backend import nvidia_nim

    models: Dict[str, Dict[str, Any]] = {}
    for f in nvidia_nim.parse_featured_models(getattr(settings, "nvidia_featured_models", "")):
        if not gpu["present"]:
            models[f.id] = _gate(False, "no NVIDIA GPU on this host")
        elif gpu["count"] < f.gpus or (gpu["vram_mb"] and f.min_vram_mb and gpu["vram_mb"] < f.min_vram_mb):
            models[f.id] = _gate(False, f"needs {f.gpu_label}; this host has "
                                        f"{gpu['count']}x {gpu['name']} ({gpu['vram_mb']} MB)")
        else:
            models[f.id] = _gate(True)
    return {"provider_nvidia": provider_nvidia, "nim_local": nim_local,
            "nemoclaw_runtime": nemoclaw, "nvidia_models": models,
            # Chat attachments (docs/attachments.md): the Attach button's gate
            # and the chat API's 503.
            "pdf_attachments": pdf_attachments_gate(),
            # Lab 5 Duo sign-in: the sign-in page's button and its routes.
            "duo_signin": duo_signin_gate(settings)}


# --------------------------------------------------------------------------- api
def _detect_now(settings) -> Dict[str, Any]:
    caps = {
        "platform": {"os": platform.system().lower(), "arch": platform.machine()},
        "nvidia_gpu": probe_nvidia_gpu(),
        "container_runtime": probe_container_runtime(),
        "node": probe_node(),
        "nim": probe_nim(settings),
        "checked_at": time.time(),
    }
    caps["nvidia_container_toolkit"] = bool(caps["container_runtime"].get("nvidia_runtime"))
    return caps


def detect(force: bool = False) -> Dict[str, Any]:
    """Cached capability snapshot + gating rules. Never raises."""
    global _cached_at
    from backend.config import settings

    with _lock:
        fresh = _cache and (time.monotonic() - _cached_at) < _CACHE_TTL
        if fresh and not force:
            return dict(_cache)
    try:
        caps = _detect_now(settings)
        result = {"capabilities": caps, "gated": gated_rules(caps, settings)}
    except Exception as exc:  # noqa: BLE001 - detection must never break a request
        logger.exception("host capability detection failed")
        result = {"capabilities": {"error": str(exc)}, "gated": {}}
    global _refreshing
    with _lock:
        _cache.clear()
        _cache.update(result)
        _cached_at = time.monotonic()
        _refreshing = False
    return dict(result)


def current() -> Dict[str, Any]:
    """The cached snapshot, never probing on the caller's thread.

    Stale-while-revalidate: a snapshot older than ``_CACHE_TTL`` kicks off ONE
    background re-probe and is returned as-is. Without this the cache only ever
    changed at startup or on a manual refresh, so a NIM that came up after the
    app — the normal order on a fresh GPU box, where the image pull takes 20+
    minutes — left ``/api/server-info`` saying "no NIM answering" 45 minutes
    after the same app was serving turns on it (EC2 replica 1, 2026-09-02).
    """
    global _refreshing
    with _lock:
        snap = dict(_cache)
        stale = bool(_cache) and (time.monotonic() - _cached_at) >= _CACHE_TTL
        kick = stale and not _refreshing
        if kick:
            _refreshing = True
    if kick:
        refresh_async()
    return snap


def refresh_async() -> None:
    threading.Thread(target=lambda: detect(force=True), name="host-capabilities", daemon=True).start()


def summary_line() -> str:
    """One line for run.sh / logs: GPU, runtime, NIM, NemoClaw."""
    d = detect()
    caps, gated = d.get("capabilities", {}), d.get("gated", {})
    gpu = caps.get("nvidia_gpu", {})
    rt = caps.get("container_runtime", {})
    gpu_txt = (f"{gpu.get('count')}x {gpu.get('name')} ({gpu.get('vram_mb')} MB)"
               if gpu.get("present") else "no NVIDIA GPU")
    return (f"host capabilities: {gpu_txt}; runtime={rt.get('name')}"
            f"{'' if rt.get('available') else ' (down)'}; "
            f"NIM {'ready' if gated.get('nim_local', {}).get('enabled') else 'unavailable'}; "
            f"NemoClaw {'supported' if gated.get('nemoclaw_runtime', {}).get('enabled') else 'unsupported'}")


if __name__ == "__main__":  # `python -m backend.host_capabilities` (run.sh preflight)
    print(summary_line())
