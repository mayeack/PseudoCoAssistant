"""Run pypdf on an untrusted upload in a one-shot child process that is killed
when its time is up (docs/attachments.md).

This file is imported in two roles, so it stays **stdlib + pypdf only** (no
``backend.*`` import, and pypdf only inside the child):

- by the app (``backend.services.attachments``): :func:`run_parse` and
  :func:`run_extract` start one child per call, hand it the PDF and wait with a
  hard wall-clock timeout. On timeout the child is terminated, then killed,
  and :class:`WorkerTimeout` is raised; a failure inside the child comes back as
  :class:`WorkerError` carrying the child's exception type name (``kind``).
- as the child itself: ``python -I pdf_worker.py`` reads one request on stdin
  (a JSON header line, then the PDF bytes) and writes one JSON reply on stdout.

Why a process and not a thread: pypdf's xref recovery and text extraction are
pure Python and have had denial-of-service bugs (unbounded loops on malformed
streams; the 2026 CVEs fixed up to 6.14.1). A thread cannot be interrupted, so a
hostile PDF would hold a request worker and a CPU core indefinitely. A process
can be killed, and it also gets best-effort CPU (and, on Linux, address-space)
rlimits plus tightened pypdf decompression limits.

Why ``subprocess`` with ``-I`` rather than ``multiprocessing``'s spawn method:
spawn re-runs the parent's ``__main__`` in the child. Under the app that is
``backend.main`` -- the whole application, ~4 s to import -- and under a test
it is the whole test script. The child would also inherit the ``PYTHONPATH``
that ``opentelemetry-instrument`` sets, so its auto-instrumentation
sitecustomize would run first (1-3 s measured). Either one alone eats most of
the 5 s parse budget. Isolated mode ignores every ``PYTHON*`` variable and the
script directory, so the child imports only this file, the stdlib and pypdf
(~0.3 s), whatever launched the app (uvicorn, launchd, systemd, a test).
"""
from __future__ import annotations

import json
import math
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List

#: Seconds a terminated child gets to exit before it is killed (and again to be reaped).
_GRACE_S = 1.0
#: Children allowed at once; a burst of uploads waits (within its own timeout)
#: instead of starting one CPU-bound process per request.
_MAX_CONCURRENT = 4
_SLOTS = threading.BoundedSemaphore(_MAX_CONCURRENT)
#: Linux-only address-space cap for the child (macOS does not enforce RLIMIT_AS).
_AS_LIMIT_BYTES = 1024 * 1024 * 1024
#: The only environment the child inherits: the app's secrets (API keys, tokens)
#: have no business in a process that parses untrusted input.
_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SYSTEMROOT", "LD_LIBRARY_PATH")

#: pypdf Configuration overrides applied in the child. The defaults (75 MB per
#: stream) are sized for trusted files; a 5 MB upload has no business inflating
#: past a few MB, and no external decoder binary may ever run on one.
_PYPDF_LIMITS: Dict[str, Any] = {
    "zlib_maximum_output_length": 8_000_000,
    "lzw_maximum_output_length": 8_000_000,
    "run_length_maximum_output_length": 8_000_000,
    "brotli_maximum_output_length": 8_000_000,
    "jbig2_maximum_output_length": 8_000_000,
    "array_based_stream_maximum_output_length": 8_000_000,
    "image_maximum_buffer_size": 8_000_000,
    "stream_decoding_work_maximum_length": 40_000_000,
    "jbig2dec_binary": None,
}

# Control characters (except \t and \n), C1 controls and lone surrogates: noise
# to a model, and a lone surrogate cannot even be encoded for HEC.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff]")
_TRAILING_SPACE_RE = re.compile(r"[ \t]+\n")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


class WorkerTimeout(Exception):
    """The child did not answer within ``timeout_s`` (it has been killed)."""


class WorkerError(Exception):
    """The child failed. ``kind`` is the exception type name raised in the child
    -- e.g. ``DependencyError`` (AES encryption without the ``cryptography``
    package), ``FileNotDecryptedError``, ``PdfReadError``, ``LimitReachedError``
    -- or ``WorkerCrashed`` / ``WorkerStartError`` / ``WorkerProtocolError``
    when it died, never started, or answered nonsense."""

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind
        self.message = message


# --------------------------------------------------------------------------- parent side
def run_parse(data: bytes, *, timeout_s: float) -> Dict[str, Any]:
    """Open the PDF in a child: ``{"pages": int, "encrypted": bool}``.

    ``pages`` is 0 when ``encrypted`` (the page tree is not read). Raises
    :class:`WorkerTimeout` / :class:`WorkerError`.
    """
    reply = _run("parse", data, timeout_s=timeout_s)
    try:
        return {"pages": int(reply["pages"]), "encrypted": bool(reply["encrypted"])}
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerError("WorkerProtocolError", f"malformed parse reply: {exc}") from None


def run_extract(data: bytes, *, max_chars: int, max_pages: int, timeout_s: float) -> Dict[str, Any]:
    """Extract the text layer in a child, page by page (plain mode), stopping at
    ``max_chars`` (cut exactly there, ``truncated`` True) or ``max_pages``:
    ``{"text": str, "pages_read": int, "chars": int, "truncated": bool}``.

    Raises :class:`WorkerTimeout` / :class:`WorkerError`.
    """
    reply = _run("extract", data, timeout_s=timeout_s, max_chars=int(max_chars), max_pages=int(max_pages))
    try:
        text = str(reply["text"])
        return {"text": text, "pages_read": int(reply["pages_read"]), "chars": len(text),
                "truncated": bool(reply["truncated"])}
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerError("WorkerProtocolError", f"malformed extract reply: {exc}") from None


def _child_argv() -> List[str]:
    """The child's command line. Tests replace this to simulate a hung child."""
    return [sys.executable, "-I", os.path.abspath(__file__)]


def _child_env() -> Dict[str, str]:
    return {key: os.environ[key] for key in _ENV_KEEP if key in os.environ}


def _run(op: str, data: bytes, *, timeout_s: float, **params: Any) -> Dict[str, Any]:
    """Start one child for ``op``, feed it the request, return its result dict."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("PDF data must be bytes")
    timeout_s = float(timeout_s)
    deadline = time.monotonic() + timeout_s
    request = json.dumps({"op": op, "timeout_s": timeout_s, **params}).encode("utf-8") + b"\n" + bytes(data)
    if not _SLOTS.acquire(timeout=timeout_s):
        raise WorkerTimeout(f"no PDF worker free within {timeout_s:g}s")
    try:
        try:
            proc = subprocess.Popen(
                _child_argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=_child_env(), close_fds=True,
            )
        except OSError as exc:
            raise WorkerError("WorkerStartError", str(exc)) from None
        try:
            out, err = proc.communicate(request, timeout=max(0.05, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _stop(proc)
            raise WorkerTimeout(f"PDF {op} did not finish within {timeout_s:g}s") from None
        except BaseException:
            _stop(proc)
            raise
    finally:
        _SLOTS.release()
    return _reply(proc.returncode, out, err)


def _stop(proc: "subprocess.Popen[bytes]") -> None:
    """terminate(), then kill() if it is still there; reaps it and closes its pipes."""
    for send_signal in (proc.terminate, proc.kill):
        try:
            send_signal()
        except OSError:  # already gone
            pass
        try:
            proc.communicate(timeout=_GRACE_S)
            return
        except subprocess.TimeoutExpired:
            continue
        except (OSError, ValueError):
            return


def _reply(returncode: int, out: bytes, err: bytes) -> Dict[str, Any]:
    try:
        reply = json.loads(out.decode("utf-8")) if out else None
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        # A CPU-rlimit kill (SIGXCPU) is the child running out of time.
        xcpu = getattr(signal, "SIGXCPU", None)
        if xcpu is not None and returncode == -xcpu:
            raise WorkerTimeout("PDF worker exceeded its CPU limit")
        tail = (err or b"").decode("utf-8", "replace").strip().splitlines()[-1:]
        detail = f"PDF worker exited with status {returncode}" + (f": {tail[0][:200]}" if tail else "")
        raise WorkerError("WorkerCrashed", detail)
    if not reply.get("ok"):
        raise WorkerError(str(reply.get("kind") or "Error"), str(reply.get("message") or ""))
    result = reply.get("result")
    if not isinstance(result, dict):
        raise WorkerError("WorkerProtocolError", "reply carried no result")
    return result


# --------------------------------------------------------------------------- child side
def normalize_text(text: str) -> str:
    """Model-ready page text: newlines unified, control characters (except \\t,
    \\n) and lone surrogates dropped, trailing spaces trimmed, 3+ newlines
    collapsed to one blank line."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub("", text)
    text = _TRAILING_SPACE_RE.sub("\n", text)
    return _BLANK_LINES_RE.sub("\n\n", text).strip()


def _open(data: bytes):
    from io import BytesIO

    from pypdf import PdfReader

    return PdfReader(BytesIO(data), strict=False)


def _parse(data: bytes) -> Dict[str, Any]:
    reader = _open(data)
    if reader.is_encrypted:
        return {"pages": 0, "encrypted": True}
    return {"pages": len(reader.pages), "encrypted": False}


def _extract(data: bytes, *, max_chars: int, max_pages: int) -> Dict[str, Any]:
    reader = _open(data)
    parts: List[str] = []
    total = 0
    pages_read = 0
    truncated = False
    for index, page in enumerate(reader.pages):
        if index >= max_pages:
            break
        pages_read += 1
        text = normalize_text(page.extract_text(extraction_mode="plain") or "")
        if not text:
            continue
        sep = 2 if parts else 0  # pages are joined with one blank line
        if total + sep + len(text) > max_chars:
            room = max_chars - total - sep
            if room > 0:
                parts.append(text[:room])
            truncated = True
            break
        parts.append(text)
        total += sep + len(text)
    text = "\n\n".join(parts)
    return {"text": text, "pages_read": pages_read, "chars": len(text), "truncated": truncated}


def _set_limit(resource: Any, which: int, soft: int, hard: int) -> None:
    try:
        _cur_soft, cur_hard = resource.getrlimit(which)
        if cur_hard != resource.RLIM_INFINITY:
            hard = min(hard, cur_hard)
            soft = min(soft, hard)
        resource.setrlimit(which, (soft, hard))
    except (ValueError, OSError):  # best effort: never fail the parse over a limit
        pass


def _limit_resources(timeout_s: float) -> None:
    """Best-effort rlimits for this child (POSIX only)."""
    try:
        import resource
    except ImportError:
        return
    cpu = int(math.ceil(timeout_s)) + 1
    _set_limit(resource, resource.RLIMIT_CPU, cpu, cpu + 1)
    _set_limit(resource, resource.RLIMIT_CORE, 0, 0)  # SIGXCPU must not leave a core file
    if sys.platform.startswith("linux"):
        _set_limit(resource, resource.RLIMIT_AS, _AS_LIMIT_BYTES, _AS_LIMIT_BYTES)


def _configure_pypdf() -> None:
    import dataclasses
    import logging

    import pypdf

    logging.getLogger("pypdf").setLevel(logging.ERROR)
    known = {f.name for f in dataclasses.fields(pypdf.Configuration)}
    pypdf.overwrite_configuration(**{k: v for k, v in _PYPDF_LIMITS.items() if k in known})


def _child_main() -> int:
    out = sys.stdout.buffer
    sys.stdout = sys.stderr  # nothing a library prints may corrupt the reply
    try:
        header, _, data = sys.stdin.buffer.read().partition(b"\n")
        request = json.loads(header.decode("utf-8"))
        _limit_resources(float(request.get("timeout_s") or 10.0))
        _configure_pypdf()
        op = request.get("op")
        if op == "parse":
            result = _parse(data)
        elif op == "extract":
            result = _extract(data, max_chars=int(request["max_chars"]), max_pages=int(request["max_pages"]))
        else:
            raise ValueError(f"unknown PDF worker op {op!r}")
        reply: Dict[str, Any] = {"ok": True, "result": result}
    except BaseException as exc:  # noqa: BLE001 - MemoryError/RecursionError too: every failure is a reply
        reply = {"ok": False, "kind": type(exc).__name__, "message": str(exc)[:500]}
    out.write(json.dumps(reply).encode("utf-8"))
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(_child_main())
