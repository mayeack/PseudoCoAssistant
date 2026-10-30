"""Chat attachments: validate an uploaded document, read its text in a killable
worker, and compose the text the prompt guardrails and the model both see
(docs/attachments.md).

PDF only today (``SUPPORTED``); the pipeline is generic over ``kind`` so images
can plug in later through a vision model writing the same extraction record.

The flow, and where each helper sits in it:

1. The chat router calls :func:`validate_upload` before it records anything: a
   rejected file raises :class:`AttachmentRejected` (status + string detail) and
   never becomes a message. The validated dict carries the bytes for THIS turn
   only; :func:`message_metadata` is what gets persisted (never the bytes).
2. The shared-chain ``attachment_intake`` PRE node
   (``backend/agents/nodes/attachment.py``) calls :func:`extract_text` inside an
   ``execute_tool`` span; on failure it records :func:`failed_extraction`.
3. Every prompt screen and the answering agent get :func:`compose_user_turn`:
   the typed message, then the document text in a delimited block. There is
   deliberately NO "untrusted content / ignore its instructions" wrapping: this
   is a prompt-injection demo, and the guardrails -- not the prompt -- are what
   is being shown.
4. Governance events carry :func:`governance_record` (metadata, never the text
   or the bytes); block banners append :func:`block_note`.

pypdf itself only ever runs in the child process (``pdf_worker``), so a hostile
file can cost at most the configured timeouts.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import time
import uuid
from pathlib import PurePosixPath
from typing import Any, Dict, Optional, Tuple

from backend import host_capabilities
from backend.config import settings
from backend.services import pdf_worker

# The agent surface the extraction is attributed to (the OTel execute_tool span
# + the tool_call governance event), distinct from "internal-docs",
# "synthetic-ehr", "scheduling" and "openclaw".
AGENT_SURFACE = "attachment-intake"
SERVER_NAME = "attachment-intake"
EXTRACT_TOOL = "extract_text"
#: The governed tool name the span and the tool_call event carry.
TOOL_NAME = f"{SERVER_NAME}.{EXTRACT_TOOL}"
#: Accepted MIME types -> attachment kind (images go here later).
SUPPORTED: Dict[str, str] = {"application/pdf": "pdf"}
_KIND_LABELS = {"pdf": "PDF"}
#: The file picker's accept attribute.
ACCEPT = "application/pdf,.pdf"
#: The typed message of a turn that only carries an attachment.
ATTACHMENT_ONLY_PROMPT = "Please review the attached document."
#: Shown on the Attach button and under the chip, and repeated in the docs.
UPLOAD_NOTICE = ("Upload synthetic documents only — the extracted text is screened by "
                 "the enabled guardrails and logged to Splunk.")
#: Request-body allowance on top of the base64-encoded file (the JSON envelope,
#: the typed message, the toggles).
BODY_HEADROOM_BYTES = 256 * 1024
ENCRYPTED_DETAIL = "Encrypted or unreadable PDF"
NO_TEXT_NOTE = ("(This document has no extractable text layer — it may be a scanned image, "
                "so its contents could not be read.)")
ERROR_NOTE = "(The text of this document could not be extracted.)"

# Child failures that mean "encrypted": AES without the cryptography package
# raises DependencyError while PdfReader tries the empty password.
_ENCRYPTED_KINDS = frozenset({"DependencyError", "FileNotDecryptedError", "WrongPasswordError"})
# An /Encrypt entry in a trailer (classic) or xref-stream dictionary: an indirect
# reference or an inline dictionary. Checked before the worker starts.
_ENCRYPT_RE = re.compile(rb"/Encrypt\s*(?:\d+\s+\d+\s+R\b|<<)")
_DATA_URL_RE = re.compile(r"^data:[^,]{0,200},", re.IGNORECASE)
# Control and bidi/zero-width characters have no place in a displayed file name.
_NAME_STRIP_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_NAME_MAX = 120
_META_KEYS = ("kind", "name", "mime", "bytes", "sha256", "pages")
# Never on a governance event, a span or a persisted message.
_CONTENT_KEYS = ("text", "data")


class AttachmentRejected(Exception):
    """An upload the chat API refuses. The router turns it into
    ``HTTPException(status_code, detail)``; ``detail`` is always a plain string
    the chat UI shows as is."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = int(status_code)
        self.detail = str(detail)


class AttachmentBytes(bytes):
    """The validated file content, opaque when printed.

    The dict :func:`validate_upload` returns travels into the LangGraph state for
    one turn, and the LangChain/LangGraph OTel instrumentation records a root
    chain's input state with ``json.dumps(..., default=str)``. Plain ``bytes``
    would land in span content as a multi-megabyte repr; this prints as a size.
    It is still ``bytes`` for everything that reads it (hashing, the worker).
    """

    def __repr__(self) -> str:
        return f"<attachment: {len(self)} bytes>"

    __str__ = __repr__


# --------------------------------------------------------------------------- gating / limits
def pdf_support() -> Tuple[bool, str]:
    """``(enabled, reason)`` for PDF attachments, READ from the host-capability
    gate ``pdf_attachments`` -- the one gating channel: the UI greys out the
    Attach button from ``GET /api/server-info`` ``gated`` and the chat API
    answers 503 from here. Never probes on the request path: the cached
    snapshot, or the rule itself before the first ``detect()``."""
    gate = ((host_capabilities.current().get("gated") or {}).get("pdf_attachments")
            or host_capabilities.pdf_attachments_gate())
    return bool(gate.get("enabled")), str(gate.get("reason") or "")


def max_request_body_bytes() -> int:
    """The chat POST body limit: the base64 of the largest allowed file plus
    headroom. Computed per call so a lowered setting (tests) applies at once."""
    return math.ceil(int(settings.attachment_max_bytes) * 4 / 3) + BODY_HEADROOM_BYTES


def client_config() -> Dict[str, Any]:
    """The limits and copy the chat UI needs (``/api/server-info``
    ``attachments``). No ``enabled`` flag: availability is the
    ``pdf_attachments`` gate."""
    return {
        "accept": ACCEPT,
        "kinds": list(dict.fromkeys(SUPPORTED.values())),
        "max_bytes": int(settings.attachment_max_bytes),
        "max_pages": int(settings.attachment_max_pages),
        "max_chars": int(settings.attachment_max_chars),
        "default_prompt": ATTACHMENT_ONLY_PROMPT,
        "upload_notice": UPLOAD_NOTICE,
    }


def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        value, unit = n / (1024 * 1024), "MB"
    elif n >= 1024:
        value, unit = n / 1024, "KB"
    else:
        return f"{n} bytes"
    return f"{value:.0f} {unit}" if value == int(value) else f"{value:.1f} {unit}"


# --------------------------------------------------------------------------- validation
def sanitize_name(name: Optional[str]) -> str:
    """A display-safe base name: no directories, control/bidi characters or
    square brackets (they delimit the document block), whitespace collapsed,
    at most 120 characters with the extension kept; ``document.pdf`` if
    nothing is left."""
    base = PurePosixPath(str(name or "").replace("\\", "/")).name
    base = _NAME_STRIP_RE.sub("", base).replace("[", "(").replace("]", ")")
    base = " ".join(base.split())
    if not base.strip("."):
        return "document.pdf"
    if len(base) > _NAME_MAX:
        stem, dot, ext = base.rpartition(".")
        if dot and stem and len(ext) <= 10:
            base = stem[: _NAME_MAX - len(ext) - 1].rstrip() + "." + ext
        else:
            base = base[:_NAME_MAX].rstrip()
    return base


def validate_upload(name: Optional[str], mime: Optional[str], data_b64: Optional[str]) -> Dict[str, Any]:
    """Validate one upload; return ``{kind, name, mime, bytes, sha256, pages,
    data}`` (``data`` is :class:`AttachmentBytes`) or raise
    :class:`AttachmentRejected`. Checks run cheapest first, in this order:

    1. MIME type not supported                                   -> 415
    2. base64 longer than the size cap allows (before decoding)  -> 413
    3. not strict base64, or empty                               -> 422
    4. decoded size over the cap                                 -> 413
    5. no ``%PDF-`` header within the first 1024 bytes           -> 415
    6. encrypted: an ``/Encrypt`` trailer entry, or the worker says
       so (AES files raise DependencyError without ``cryptography``) -> 422
    7. the worker cannot parse it in time, or it has no pages     -> 422
    8. more pages than the cap                                   -> 413

    PDF support missing on this host answers 503 just before the worker runs.
    """
    mime_key = (mime or "").split(";", 1)[0].strip().lower()[:100]
    kind = SUPPORTED.get(mime_key)
    if kind is None:
        raise AttachmentRejected(415, f"Only PDF attachments are supported (got {mime_key or 'no file type'})")

    max_bytes = int(settings.attachment_max_bytes)
    b64 = _DATA_URL_RE.sub("", (data_b64 or "").strip(), count=1)
    if len(b64) > 4 * math.ceil(max_bytes / 3):
        raise AttachmentRejected(
            413, f"The attachment is about {_fmt_size(len(b64) * 3 // 4)}; the limit is {_fmt_size(max_bytes)}")
    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise AttachmentRejected(422, "The attachment is not valid base64 data") from None
    if not data:
        raise AttachmentRejected(422, "The attachment is empty")
    if len(data) > max_bytes:
        raise AttachmentRejected(413, f"The attachment is {_fmt_size(len(data))}; the limit is {_fmt_size(max_bytes)}")
    if b"%PDF-" not in data[:1024]:
        raise AttachmentRejected(415, "The attachment is not a PDF file")
    if _ENCRYPT_RE.search(data):
        raise AttachmentRejected(422, ENCRYPTED_DETAIL)

    supported, reason = pdf_support()
    if not supported:
        raise AttachmentRejected(503, reason)
    try:
        parsed = pdf_worker.run_parse(data, timeout_s=float(settings.attachment_parse_timeout_s))
    except pdf_worker.WorkerTimeout:
        raise AttachmentRejected(422, "The PDF could not be parsed in time") from None
    except pdf_worker.WorkerError as exc:
        if exc.kind in _ENCRYPTED_KINDS:
            raise AttachmentRejected(422, ENCRYPTED_DETAIL) from None
        if exc.kind in ("ModuleNotFoundError", "ImportError"):
            raise AttachmentRejected(503, f"PDF support is not available on this host ({exc.kind})") from None
        raise AttachmentRejected(422, "The PDF could not be parsed") from None
    if parsed["encrypted"]:
        raise AttachmentRejected(422, ENCRYPTED_DETAIL)
    pages = parsed["pages"]
    if pages < 1:
        raise AttachmentRejected(422, "The PDF has no pages")
    max_pages = int(settings.attachment_max_pages)
    if pages > max_pages:
        raise AttachmentRejected(413, f"The PDF has {pages} pages; the limit is {max_pages}")
    return {
        "kind": kind,
        "name": sanitize_name(name),
        "mime": mime_key,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "pages": pages,
        "data": AttachmentBytes(data),
    }


def message_metadata(att: Dict[str, Any]) -> Dict[str, Any]:
    """What may be persisted or logged about an attachment: a new dict of
    ``kind, name, mime, bytes, sha256, pages`` -- never the bytes."""
    return {key: att[key] for key in _META_KEYS if key in att}


# --------------------------------------------------------------------------- extraction
def new_call_id() -> str:
    """A fresh tool-call id. The node mints it BEFORE the extraction so the
    execute_tool span can open around the call itself."""
    return f"att-{uuid.uuid4().hex[:12]}"


def _record_base(att: Dict[str, Any], call_id: str) -> Dict[str, Any]:
    data = att.get("data")
    size = att.get("bytes")
    if size is None and isinstance(data, (bytes, bytearray)):
        size = len(data)
    sha256 = att.get("sha256")
    if not sha256 and isinstance(data, (bytes, bytearray)):
        sha256 = hashlib.sha256(data).hexdigest()
    return {
        "tool_name": TOOL_NAME,
        "call_id": call_id,
        "kind": att.get("kind") or "pdf",
        "name": att.get("name") or "document.pdf",
        "mime": att.get("mime") or "application/pdf",
        "bytes": size,
        "sha256": sha256,
        "pages": att.get("pages"),
    }


def extract_text(att: Dict[str, Any], *, call_id: str) -> Dict[str, Any]:
    """Read the document's text layer in the worker (capped at
    ``attachment_max_chars``). Returns the extraction record::

        {tool_name, call_id, kind, name, mime, bytes, sha256, pages,
         pages_read, chars, truncated, status: "ok" | "no_text", text, duration_ms}

    RAISES on a worker failure or timeout, so the caller's execute_tool span
    ends with an ERROR status; the caller then records :func:`failed_extraction`.
    """
    started = time.perf_counter()
    out = pdf_worker.run_extract(
        att["data"],
        max_chars=int(settings.attachment_max_chars),
        max_pages=int(settings.attachment_max_pages),
        timeout_s=float(settings.attachment_extract_timeout_s),
    )
    text = out["text"] if out["text"].strip() else ""
    return {
        **_record_base(att, call_id),
        "pages_read": out["pages_read"],
        "chars": len(text),
        "truncated": bool(out["truncated"]) and bool(text),
        "status": "ok" if text else "no_text",
        "text": text,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def failed_extraction(att: Dict[str, Any], call_id: str, error: Any, duration_ms: float) -> Dict[str, Any]:
    """The extraction record of a failed read: same shape, ``status: "error"``,
    no text, plus a short ``error``."""
    if isinstance(error, BaseException):
        error = f"{type(error).__name__}: {error}"
    return {
        **_record_base(att, call_id),
        "pages_read": 0,
        "chars": 0,
        "truncated": False,
        "status": "error",
        "text": "",
        "duration_ms": round(float(duration_ms or 0.0), 1),
        "error": str(error)[:300],
    }


# --------------------------------------------------------------------------- composition
def pages_label(pages: Any) -> str:
    """``"1 page"`` / ``"<n> pages"``."""
    return "1 page" if pages == 1 else f"{pages} pages"


def kind_label(kind: Optional[str]) -> str:
    """The display label of an attachment kind (``"pdf"`` -> ``"PDF"``)."""
    kind = kind or "pdf"
    return _KIND_LABELS.get(kind, kind.upper())


def compose_user_turn(typed: Optional[str], extraction: Optional[Dict[str, Any]]) -> str:
    """The user turn every prompt screen and the answering agent see: the typed
    text first, then the document block (block only when nothing was typed)::

        <typed>

        [Attached document: <name> (<n> page|pages, PDF)]
        <text | no-text note | error note>
        [Document truncated at 12,000 characters]     (only when truncated)
        [End of attached document]

    ``typed`` alone when there is no extraction.
    """
    typed = typed or ""
    if not extraction:
        return typed
    label = kind_label(extraction.get("kind"))
    pages = extraction.get("pages")
    facts = f"{pages_label(pages)}, {label}" if pages is not None else label
    lines = [f"[Attached document: {extraction.get('name') or 'document.pdf'} ({facts})]"]
    status = extraction.get("status")
    if status == "ok":
        lines.append(extraction.get("text") or "")
        if extraction.get("truncated"):
            lines.append(f"[Document truncated at {int(settings.attachment_max_chars):,} characters]")
    elif status == "no_text":
        lines.append(NO_TEXT_NOTE)
    else:
        lines.append(ERROR_NOTE)
    lines.append("[End of attached document]")
    block = "\n".join(lines)
    return f"{typed}\n\n{block}" if typed.strip() else block


def governance_record(extraction: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The extraction minus its text (and any bytes), for governance events and
    Agent Observability; ``None`` without an extraction."""
    if not extraction:
        return None
    return {key: value for key, value in extraction.items() if key not in _CONTENT_KEYS}


def input_modality(record: Optional[Dict[str, Any]]) -> str:
    """``"text"``, or ``"text+<kind>"`` when the turn carried an attachment."""
    if isinstance(record, dict) and record:
        return f"text+{record.get('kind') or 'pdf'}"
    return "text"


def block_note(extraction: Optional[Dict[str, Any]]) -> str:
    """One factual sentence a prompt-stage block banner appends when the turn
    carried a document. It never says which part triggered the block."""
    if not extraction:
        return ""
    return f"Your attached document '{extraction.get('name') or 'document.pdf'}' was screened together with your message."
