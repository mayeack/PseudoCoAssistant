#!/usr/bin/env python3
"""Chat attachments: PDF upload validation, text extraction in the killable
worker, the attachment_intake node and its helpers, and the sample attack
documents (docs/attachments.md).

Covers backend/services/attachments.py, backend/services/pdf_worker.py,
backend/services/attack_documents.py and backend/agents/nodes/attachment.py:

- every validator rejection (status + plain-string detail), including RC4 and
  AES-256 (V5/R6) encryption, a hung worker and a crashed one;
- every theme x sample PDF parses strictly, shows its cover and carries its
  hidden payload exactly where the sample says (white band, 1 pt, off the page);
- the covers trip no deterministic trigger (policy engine, clarifier,
  scheduling, PII exfiltration, internal docs) and carry no label/placeholder;
- the node never raises or terminates, and only the TYPED message drives the
  deterministic logic (a PII-exfil payload inside a document triggers nothing).

Offline: no LLM, no AI Defense; the governance logger is stubbed.

Run: venv/bin/python tests/test_attachments.py
"""
import base64
import inspect
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"
os.environ.setdefault("LOG_TO_FILE", "false")
os.environ.setdefault("LOG_TO_DATABASE", "false")

from backend.agents.blueprints import guardrails  # noqa: E402
from backend.agents.nodes import attachment as node_mod  # noqa: E402
from backend.agents.nodes import injection  # noqa: E402
from backend.agents.nodes.ehr import ehr_lookup_node  # noqa: E402
from backend.agents.nodes.shared import clarifying_service  # noqa: E402
from backend.agents.state import build_initial_state  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402
from backend.config import settings  # noqa: E402
from backend.logging.log_schemas import create_governance_log  # noqa: E402
from backend.models.schemas import ChatAttachment, ChatRequest, GenAILogEntry  # noqa: E402
from backend.services import attachments, internal_docs, pdf_worker, scheduling  # noqa: E402
from backend.services import attack_documents as ad  # noqa: E402
from backend.services.escalation_rules import EscalationRules  # noqa: E402
from backend.services.recommendation_engine import RecommendationEngine  # noqa: E402
from backend.services.spray_corpus import TECHNIQUE_FAMILIES  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


try:
    from pypdf import PdfReader, PdfWriter
except ImportError:  # the whole feature needs it; say so once instead of a traceback
    PdfReader = PdfWriter = None


def norm(text: str) -> str:
    """Whitespace-normalised text (extraction re-flows lines and wraps)."""
    return " ".join((text or "").split())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --------------------------------------------------------------------------- PDF fixtures
def build_pdf(pages, trailer_extra: bytes = b"") -> bytes:
    """A minimal PDF 1.4: one Helvetica font, one content stream per page (an
    empty list is a document with no pages), exact xref offsets. ``trailer_extra``
    is spliced into the trailer dictionary (after the xref, so no offset moves)."""
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>",
               3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"}
    page_ids, next_id = [], 4
    for content in pages:
        pid, cid = next_id, next_id + 1
        next_id += 2
        page_ids.append(pid)
        objects[pid] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                        b"/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % cid)
        objects[cid] = b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"
    objects[2] = (b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % p for p in page_ids)
                  + b"] /Count %d >>" % len(page_ids))
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for oid in sorted(objects):
        offsets[oid] = len(out)
        out += b"%d 0 obj\n" % oid + objects[oid] + b"\nendobj\n"
    xref = len(out)
    size = max(objects) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for oid in range(1, size):
        out += b"%010d 00000 n \n" % offsets[oid]
    out += (b"trailer\n<< /Size %d /Root 1 0 R" % size + trailer_extra
            + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref)
    return bytes(out)


def text_page(*lines: str) -> bytes:
    ops = [b"BT /F1 12 Tf 72 720 Td 14 TL"]
    for line in lines:
        ops.append(b"(" + line.encode("latin-1") + b") Tj T*")
    ops.append(b"ET")
    return b"\n".join(ops)


VISIBLE = "Quarterly Statement"
PDF = build_pdf([text_page(VISIBLE, "Balance carried forward from the last period.")])
# AES-256 (V5/R6) standard security handler: pypdf needs the `cryptography`
# package for it, which the venv deliberately lacks (DependencyError).
AES_TRAILER = (b" /Encrypt << /Filter /Standard /V 5 /R 6 /Length 256 /P -4 /O <" + b"11" * 48
               + b"> /U <" + b"22" * 48 + b"> /OE <" + b"33" * 32 + b"> /UE <" + b"44" * 32
               + b"> /Perms <" + b"55" * 16 + b"> >> /ID [<" + b"66" * 16 + b"> <" + b"66" * 16 + b">]")
HANG_ARGV = [sys.executable, "-I", "-c", "import sys, time; sys.stdin.buffer.read(); time.sleep(60)"]
CRASH_ARGV = [sys.executable, "-I", "-c", "import sys, os; sys.stdin.buffer.read(); os._exit(3)"]
NO_PYPDF_ARGV = [sys.executable, "-I", "-c",
                 "import sys, json; sys.stdin.buffer.read(); sys.stdout.write(json.dumps("
                 "{'ok': False, 'kind': 'ModuleNotFoundError', 'message': \"No module named 'pypdf'\"}))"]


def rc4_pdf() -> bytes:
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(PDF)))
    writer.encrypt(user_password="", owner_password="owner", algorithm="RC4-128")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def rejection(name, mime, data_b64):
    """(status, detail) of a rejected upload, or (None, None) when accepted."""
    try:
        attachments.validate_upload(name, mime, data_b64)
    except attachments.AttachmentRejected as exc:
        return exc.status_code, exc.detail
    return None, None


class _Patched:
    """Set attributes for the duration of a ``with`` block, then restore them."""

    def __init__(self, *triples):
        self.triples = triples
        self.saved = []

    def __enter__(self):
        for obj, attr, value in self.triples:
            self.saved.append((obj, attr, getattr(obj, attr)))
            setattr(obj, attr, value)
        return self

    def __exit__(self, *_exc):
        for obj, attr, value in reversed(self.saved):
            setattr(obj, attr, value)
        return False


# --------------------------------------------------------------------------- contract
def test_contract_and_limits() -> None:
    check("pypdf is importable (requirements.txt pins it)", PdfReader is not None)
    cfg = attachments.client_config()
    check("client_config: limits + copy, no enabled flag (availability is the gate)",
          set(cfg) == {"accept", "kinds", "max_bytes", "max_pages", "max_chars", "default_prompt", "upload_notice"}
          and cfg["accept"] == "application/pdf,.pdf" and cfg["kinds"] == ["pdf"]
          and cfg["default_prompt"] == attachments.ATTACHMENT_ONLY_PROMPT
          and cfg["upload_notice"] == attachments.UPLOAD_NOTICE, str(cfg))
    check("the code defaults: 5 MB, 50 pages, 12,000 characters",
          type(settings).model_fields["attachment_max_bytes"].default == 5 * 1024 * 1024
          and type(settings).model_fields["attachment_max_pages"].default == 50
          and type(settings).model_fields["attachment_max_chars"].default == 12000)
    check("body limit = base64 of the largest file + 256 KiB headroom",
          attachments.max_request_body_bytes()
          == -(-settings.attachment_max_bytes * 4 // 3) + attachments.BODY_HEADROOM_BYTES,
          str(attachments.max_request_body_bytes()))
    with _Patched((settings, "attachment_max_bytes", 3000)):
        check("the body limit follows a lowered setting at once",
              attachments.max_request_body_bytes() == 4000 + attachments.BODY_HEADROOM_BYTES)
    check("pdf_support() reads the host gate (enabled here)", attachments.pdf_support() == (True, ""),
          str(attachments.pdf_support()))
    check("ChatRequest.attachment is a ChatAttachment, not a bool flag",
          ChatRequest(session_id="s", message="m", attachment={"data": "QQ=="}).attachment.name == "document.pdf"
          and ChatRequest(session_id="s", message="m").attachment is None)
    try:
        ChatAttachment(name="x" * 256, data="QQ==")
        too_long = False
    except ValueError:
        too_long = True
    check("ChatAttachment.name is capped at 255 characters", too_long)
    check("GenAILogEntry carries attachment + input_modality",
          {"attachment", "input_modality"} <= set(GenAILogEntry.model_fields))
    check("the legacy engine takes attachment= for kwargs parity",
          "attachment" in inspect.signature(RecommendationEngine.process_message).parameters)
    check("attachment_intake is PRE_NODES[0] and can never terminate the turn",
          guardrails.PRE_NODES[0] == "attachment_intake" and "attachment_intake" not in guardrails._MAY_TERMINATE
          and guardrails._NODE_FNS["attachment_intake"] is node_mod.attachment_intake_node)


# --------------------------------------------------------------------------- validator
def test_validator_accepts() -> None:
    att = attachments.validate_upload("../../reports/Statement [final].pdf", "application/pdf", b64(PDF))
    check("a valid PDF is accepted with its facts",
          att["kind"] == "pdf" and att["mime"] == "application/pdf" and att["pages"] == 1
          and att["bytes"] == len(PDF) and len(att["sha256"]) == 64, str({k: v for k, v in att.items() if k != "data"}))
    check("the bytes ride along for this turn, opaque when printed",
          att["data"] == PDF and isinstance(att["data"], bytes) and repr(att["data"]) == f"<attachment: {len(PDF)} bytes>"
          and "%PDF" not in str(att["data"]))
    check("the name is sanitised", att["name"] == "Statement (final).pdf", att["name"])
    meta = attachments.message_metadata(att)
    check("message_metadata: kind, name, mime, bytes, sha256, pages -- never data",
          set(meta) == {"kind", "name", "mime", "bytes", "sha256", "pages"} and "data" in att)
    check("a data: URL prefix is tolerated",
          attachments.validate_upload("a.pdf", "application/pdf", "data:application/pdf;base64," + b64(PDF))["sha256"]
          == att["sha256"])
    check("a MIME type with parameters and odd case is tolerated",
          attachments.validate_upload("a.pdf", "Application/PDF; charset=binary", b64(PDF))["mime"] == "application/pdf")
    check("%PDF- after a short preamble is accepted",
          attachments.validate_upload("a.pdf", "application/pdf", b64(b"\x00junk\n" + PDF))["pages"] == 1)
    three = build_pdf([text_page("one"), text_page("two"), text_page("three")])
    check("a multi-page PDF reports its page count",
          attachments.validate_upload("a.pdf", "application/pdf", b64(three))["pages"] == 3)


def test_validator_rejections() -> None:
    def expect(name, got, status, detail=None, prefix=None):
        ok = got[0] == status and isinstance(got[1], str) and bool(got[1])
        if detail is not None:
            ok = ok and got[1] == detail
        if prefix is not None:
            ok = ok and got[1].startswith(prefix)
        check(name, ok, str(got))

    expect("wrong MIME type -> 415", rejection("a.png", "image/png", b64(PDF)), 415,
           "Only PDF attachments are supported (got image/png)")
    expect("no MIME type -> 415", rejection("a.pdf", "", b64(PDF)), 415,
           "Only PDF attachments are supported (got no file type)")
    expect("the MIME check runs first (an oversize PNG is still a 415)",
           rejection("a.png", "image/png", "A" * 9_000_000), 415)
    expect("not a PDF (no %PDF- header) -> 415", rejection("a.pdf", "application/pdf", b64(b"hello world")), 415,
           "The attachment is not a PDF file")
    expect("%PDF- beyond the first 1024 bytes -> 415",
           rejection("a.pdf", "application/pdf", b64(b"x" * 1100 + PDF)), 415)
    expect("bad base64 -> 422", rejection("a.pdf", "application/pdf", "not*base64!"), 422,
           "The attachment is not valid base64 data")
    expect("empty -> 422", rejection("a.pdf", "application/pdf", ""), 422)
    expect("corrupt PDF -> 422", rejection("a.pdf", "application/pdf", b64(b"%PDF-1.4\n" + b"garbage " * 256)), 422,
           "The PDF could not be parsed")
    expect("a PDF with no pages -> 422", rejection("a.pdf", "application/pdf", b64(build_pdf([]))), 422,
           "The PDF has no pages")

    # Size: the encoded length is checked BEFORE decoding, the decoded size after.
    with _Patched((settings, "attachment_max_bytes", 600)):
        expect("oversize (encoded length, before decoding) -> 413",
               rejection("a.pdf", "application/pdf", b64(PDF)), 413, prefix="The attachment is about ")
        expect("an oversize body is a 413 even when it is not base64",
               rejection("a.pdf", "application/pdf", "!" * 5000), 413)
    padded = PDF + b"\n" * ((3 - len(PDF) % 3) % 3)   # len % 3 == 0: the encoded check passes at len - 1
    with _Patched((settings, "attachment_max_bytes", len(padded) - 1)):
        got = rejection("a.pdf", "application/pdf", b64(padded))
        expect("oversize (decoded size) -> 413", got, 413, prefix="The attachment is ")
        check("the decoded-size detail names both sizes", "; the limit is " in (got[1] or "")
              and "about" not in (got[1] or ""), str(got))
    with _Patched((settings, "attachment_max_pages", 2)):
        three = build_pdf([text_page("one"), text_page("two"), text_page("three")])
        expect("more pages than the cap -> 413", rejection("a.pdf", "application/pdf", b64(three)), 413,
               "The PDF has 3 pages; the limit is 2")

    # Encryption: the trailer pre-check, and the worker behind it.
    aes = build_pdf([text_page("secret")], trailer_extra=AES_TRAILER)
    rc4 = rc4_pdf()
    expect("AES-256 (V5/R6) -> 422 Encrypted", rejection("a.pdf", "application/pdf", b64(aes)), 422,
           attachments.ENCRYPTED_DETAIL)
    expect("RC4-128 -> 422 Encrypted", rejection("a.pdf", "application/pdf", b64(rc4)), 422,
           attachments.ENCRYPTED_DETAIL)
    try:
        pdf_worker.run_parse(aes, timeout_s=10)
        kind = "no error"
    except pdf_worker.WorkerError as exc:
        kind = exc.kind
    check("the worker reports AES without `cryptography` as DependencyError", kind == "DependencyError", kind)
    check("the worker reports an RC4 file as encrypted with no pages",
          pdf_worker.run_parse(rc4, timeout_s=10) == {"pages": 0, "encrypted": True})
    never = re.compile(rb"(?!)")
    with _Patched((attachments, "_ENCRYPT_RE", never)):
        expect("AES the pre-check misses -> the worker's DependencyError -> 422 Encrypted",
               rejection("a.pdf", "application/pdf", b64(aes)), 422, attachments.ENCRYPTED_DETAIL)
        expect("RC4 the pre-check misses -> the worker's encrypted flag -> 422 Encrypted",
               rejection("a.pdf", "application/pdf", b64(rc4)), 422, attachments.ENCRYPTED_DETAIL)

    # Host support: the gate, and a child that cannot import pypdf.
    reason = "PDF support is not installed (pip install -r requirements.txt)"
    with _Patched((attachments, "pdf_support", lambda: (False, reason))):
        expect("no PDF support on this host -> 503 with the gate's reason",
               rejection("a.pdf", "application/pdf", b64(PDF)), 503, reason)
    with _Patched((pdf_worker, "_child_argv", lambda: list(NO_PYPDF_ARGV))):
        expect("a worker without pypdf -> 503",
               rejection("a.pdf", "application/pdf", b64(PDF)), 503,
               "PDF support is not available on this host (ModuleNotFoundError)")
    with _Patched((pdf_worker, "_child_argv", lambda: list(CRASH_ARGV))):
        expect("a crashed worker -> 422", rejection("a.pdf", "application/pdf", b64(PDF)), 422,
               "The PDF could not be parsed")


def test_worker_hang_is_killed() -> None:
    # A hostile PDF that loops forever must cost at most the timeout: the child is
    # terminated (then killed) and reaped, and the upload answers 422.
    spawned = []
    real_popen = subprocess.Popen

    class RecordingPopen(real_popen):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            spawned.append(self)

    with _Patched((subprocess, "Popen", RecordingPopen), (pdf_worker, "_child_argv", lambda: list(HANG_ARGV)),
                  (settings, "attachment_parse_timeout_s", 1.0)):
        started = time.perf_counter()
        got = rejection("a.pdf", "application/pdf", b64(PDF))
        elapsed = time.perf_counter() - started
        check("a hung worker -> 422 'could not be parsed in time'",
              got == (422, "The PDF could not be parsed in time"), str(got))
        check("... within the timeout plus the kill grace", elapsed < 1.0 + 2 * pdf_worker._GRACE_S + 1.0,
              f"{elapsed:.2f}s")
        alive = True
        if spawned:
            try:
                os.kill(spawned[-1].pid, 0)
            except ProcessLookupError:
                alive = False
        check("the hung child was killed and reaped", bool(spawned) and spawned[-1].returncode is not None
              and not alive, f"rc={spawned[-1].returncode if spawned else None} alive={alive}")

        never_reads = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
        with _Patched((pdf_worker, "_child_argv", lambda: list(never_reads))):
            started = time.perf_counter()
            try:
                pdf_worker.run_parse(PDF * 400, timeout_s=1.0)   # a full pipe must not block the parent
                outcome = "returned"
            except pdf_worker.WorkerTimeout:
                outcome = "timeout"
            check("a child that never reads its stdin still times out",
                  outcome == "timeout" and time.perf_counter() - started < 4.0,
                  f"{outcome} {time.perf_counter() - started:.2f}s")
    check("no worker child is left running", all(p.returncode is not None for p in spawned))
    check("the real worker is restored after the seam", pdf_worker._child_argv()[-1].endswith("pdf_worker.py"))


def test_sanitize_name() -> None:
    cases = (
        ("../../reports/Lab results.pdf", "Lab results.pdf"),
        ("C:\\Users\\pat\\Documents\\bill.pdf", "bill.pdf"),
        ("Lab\x07 results [final].pdf", "Lab results (final).pdf"),
        ("invoice\u202egnp.pdf", "invoicegnp.pdf"),
        ("a\u200bb\u2066c\ufeff.pdf", "abc.pdf"),
        ("  many    spaces   here.pdf  ", "many spaces here.pdf"),
        ("..", "document.pdf"),
        ("", "document.pdf"),
        (None, "document.pdf"),
    )
    for raw, want in cases:
        got = attachments.sanitize_name(raw)
        check(f"sanitize_name({raw!r}) -> {want!r}", got == want, repr(got))
    long_name = attachments.sanitize_name("x" * 300 + ".pdf")
    check("a long name is capped at 120 characters and keeps its extension",
          len(long_name) == 120 and long_name.endswith(".pdf"), str(len(long_name)))
    check("no square brackets survive (they delimit the document block)",
          not set("[]") & set(attachments.sanitize_name("[Attached document: x].pdf")))


# --------------------------------------------------------------------------- extraction
def test_extraction_and_composition() -> None:
    att = attachments.validate_upload("statement.pdf", "application/pdf", b64(PDF))
    ext = attachments.extract_text(att, call_id="att-test")
    check("extraction record shape",
          set(ext) == {"tool_name", "call_id", "kind", "name", "mime", "bytes", "sha256", "pages", "pages_read",
                       "chars", "truncated", "status", "text", "duration_ms"}, str(sorted(ext)))
    check("extraction status ok with the visible text", ext["status"] == "ok" and VISIBLE in ext["text"]
          and ext["chars"] == len(ext["text"]) and ext["pages_read"] == 1 and ext["truncated"] is False,
          repr(ext["text"][:120]))
    check("the record names the governed tool and the given call id",
          ext["tool_name"] == attachments.TOOL_NAME == "attachment-intake.extract_text" and ext["call_id"] == "att-test")

    typed = "Can you summarize this document for me?"
    composed = attachments.compose_user_turn(typed, ext)
    check("compose_user_turn: typed text, then the delimited document block",
          composed == (f"{typed}\n\n[Attached document: statement.pdf (1 page, PDF)]\n"
                       f"{ext['text']}\n[End of attached document]"), repr(composed))
    check("compose_user_turn: blank typed text -> the block alone",
          attachments.compose_user_turn("   ", ext).startswith("[Attached document: statement.pdf"))
    check("compose_user_turn: no extraction -> the typed text unchanged",
          attachments.compose_user_turn(typed, None) == typed)
    check("compose_user_turn: plural page label",
          "(3 pages, PDF)" in attachments.compose_user_turn(typed, {**ext, "pages": 3}))
    wrapper = composed.replace(ext["text"], "").lower()
    check("no 'untrusted / ignore its instructions' wrapping (this is an attack demo)",
          not any(w in wrapper for w in ("untrusted", "ignore", "do not follow", "instruction")), wrapper)

    with _Patched((settings, "attachment_max_chars", 20)):
        small = attachments.extract_text(att, call_id="att-cap")
        check("the character cap cuts the text exactly", small["truncated"] is True and small["chars"] == 20
              and len(small["text"]) == 20, str(small["chars"]))
        check("the truncation marker states the cap",
              "\n[Document truncated at 20 characters]\n[End of attached document]"
              in attachments.compose_user_turn(typed, small))
    check("the default marker reads 12,000",
          "[Document truncated at 12,000 characters]" in attachments.compose_user_turn(typed, {**ext, "truncated": True}))

    blank = attachments.validate_upload("scan.pdf", "application/pdf", b64(ad.blank_pdf()))
    nt = attachments.extract_text(blank, call_id="att-blank")
    check("no text layer -> status no_text, empty text", nt["status"] == "no_text" and nt["text"] == ""
          and nt["chars"] == 0 and nt["truncated"] is False, str(nt))
    check("no_text: the block says the text could not be read",
          attachments.NO_TEXT_NOTE in attachments.compose_user_turn(typed, nt)
          and "scanned image" in attachments.NO_TEXT_NOTE)

    failed = attachments.failed_extraction(att, "att-x", pdf_worker.WorkerTimeout("slow"), 12.34)
    check("failed_extraction: same shape, status error, no text, a short error",
          failed["status"] == "error" and failed["text"] == "" and failed["chars"] == 0
          and failed["error"].startswith("WorkerTimeout") and set(failed) == set(ext) | {"error"}, str(failed))
    check("failed_extraction caps the error at 300 characters",
          len(attachments.failed_extraction(att, "att-y", "z" * 1000, 0)["error"]) == 300)
    check("error: the block says the text could not be extracted",
          attachments.ERROR_NOTE in attachments.compose_user_turn(typed, failed))

    with _Patched((pdf_worker, "_child_argv", lambda: list(CRASH_ARGV))):
        try:
            attachments.extract_text(att, call_id="att-crash")
            raised = "nothing"
        except pdf_worker.WorkerError as exc:
            raised = exc.kind
    check("extract_text raises a worker failure (the node's span records it)", raised == "WorkerCrashed", raised)

    record = attachments.governance_record(ext)
    check("governance_record keeps the facts, never the text or the bytes",
          record and "text" not in record and "data" not in record and record["sha256"] == att["sha256"]
          and record["status"] == "ok" and record["chars"] == ext["chars"])
    check("governance_record of nothing is None",
          attachments.governance_record(None) is None and attachments.governance_record({}) is None)
    check("input_modality: text+pdf with a record, text without",
          attachments.input_modality(record) == "text+pdf" and attachments.input_modality(None) == "text")
    check("block_note: one factual sentence, '' without a document",
          attachments.block_note(ext) == "Your attached document 'statement.pdf' was screened together with your message."
          and attachments.block_note(None) == "")


# --------------------------------------------------------------------------- node
TYPED = "Can you summarize this document for me?"


def _turn_state(att, *, user_message=TYPED, history=None, theme="medadvice"):
    state = build_initial_state(
        session_id="s-att", user_message=user_message, theme=theme, enduser_id="eu-1",
        conversation_history=history if history is not None else [{"role": "user", "content": user_message}],
        force_pii_injection=False, attachment=att)
    state.update(request_id="r-att", trace_id="t" * 32, stage_timings={"policy_ms": 1.5},
                 workflow_name="pseudoco_multi_agent", blueprint="pseudoco_multi_agent")
    return state


def test_attachment_intake_node() -> None:
    calls = []
    att = attachments.validate_upload("statement.pdf", "application/pdf", b64(PDF))
    with _Patched((node_mod.governance_logger, "log_tool_call", lambda **kw: calls.append(kw))):
        check("no attachment -> {} and no tool call",
              node_mod.attachment_intake_node({"user_message": "hi"}) == {} and not calls)
        check("an attachment without bytes -> {}",
              node_mod.attachment_intake_node({"attachment": attachments.message_metadata(att)}) == {})

        state = _turn_state(att)
        before = dict(state)
        dumped = json.dumps(state, default=str)
        check("the initial state prints without the bytes (OTel root-chain input)",
              "%PDF" not in dumped and len(dumped) < 2000, str(len(dumped)))
        out = node_mod.attachment_intake_node(state)
        check("the node returns exactly attachment, attachment_extraction, stage_timings (never a block)",
              set(out) == {"attachment", "attachment_extraction", "stage_timings"}, str(sorted(out)))
        check("state['attachment'] becomes metadata only",
              out["attachment"] == attachments.message_metadata(att) and "data" not in out["attachment"])
        ext = out["attachment_extraction"]
        check("the extraction is in the state", ext["status"] == "ok" and VISIBLE in ext["text"])
        check("stage_timings gains attachment_intake_ms and keeps the rest",
              out["stage_timings"].get("policy_ms") == 1.5 and out["stage_timings"].get("attachment_intake_ms", -1) >= 0)
        check("the input state is not mutated",
              state == before and state["attachment"] is att and "data" in att and "attachment_intake_ms"
              not in state["stage_timings"])
        kw = calls[0] if calls else {}
        check("exactly one governed tool call, all keyword", len(calls) == 1, str(len(calls)))
        check("the tool call names the tool, the surface and the extraction's call id",
              kw.get("tool_name") == attachments.TOOL_NAME and kw.get("agent_surface") == "attachment-intake"
              and kw.get("tool_decision") == "allow" and kw.get("tool_call_id") == ext["call_id"]
              and ext["call_id"].startswith("att-"))
        check("the tool call joins the turn's trace and carries its identity",
              kw.get("session_id") == "s-att" and kw.get("request_id") == "r-att" and kw.get("trace_id") == "t" * 32
              and kw.get("enduser_id") == "eu-1" and kw.get("workflow_name") == "pseudoco_multi_agent"
              and kw.get("blueprint") == "pseudoco_multi_agent")
        check("the tool arguments are metadata, never the bytes or the text",
              att["sha256"] in kw.get("tool_arguments", "") and "%PDF" not in kw.get("tool_arguments", "")
              and VISIBLE not in kw.get("tool_arguments", ""))

        calls.clear()
        # The failures below are deliberate: keep their logger.exception tracebacks
        # out of the suite's output.
        node_mod.logger.disabled = True
        with _Patched((pdf_worker, "_child_argv", lambda: list(CRASH_ARGV))):
            crashed = node_mod.attachment_intake_node(state)
        cext = crashed.get("attachment_extraction") or {}
        check("a crashed worker: the node records status error and does not raise",
              cext.get("status") == "error" and cext.get("text") == "" and "WorkerCrashed" in cext.get("error", ""),
              str(cext))
        check("... still never a block, still one tool call",
              set(crashed) == {"attachment", "attachment_extraction", "stage_timings"} and len(calls) == 1)

        with _Patched((pdf_worker, "_child_argv", lambda: list(HANG_ARGV)),
                      (settings, "attachment_extract_timeout_s", 1.0)):
            started = time.perf_counter()
            hung = node_mod.attachment_intake_node(state)
            elapsed = time.perf_counter() - started
        hext = hung.get("attachment_extraction") or {}
        check("a hung worker: status error (WorkerTimeout) within the timeout",
              hext.get("status") == "error" and "WorkerTimeout" in hext.get("error", "") and elapsed < 4.0,
              f"{hext.get('error')} {elapsed:.2f}s")

        def boom(*_a, **_k):
            raise RuntimeError("unexpected")

        with _Patched((attachments, "extract_text", boom)):
            odd = node_mod.attachment_intake_node(state)
        check("any extraction exception is recorded, never raised",
              (odd.get("attachment_extraction") or {}).get("status") == "error")

    def log_fails(**_kw):
        raise OSError("disk full")

    try:
        with _Patched((node_mod.governance_logger, "log_tool_call", log_fails)):
            survived = node_mod.attachment_intake_node(state)
    finally:
        node_mod.logger.disabled = False
    check("a governance logging fault never breaks the turn",
          (survived.get("attachment_extraction") or {}).get("status") == "ok")


def test_helpers() -> None:
    att = attachments.validate_upload("statement.pdf", "application/pdf", b64(PDF))
    ext = attachments.extract_text(att, call_id="att-h")
    meta = attachments.message_metadata(att)
    plain = {"user_message": TYPED}
    doc = {"user_message": TYPED, "attachment": meta, "attachment_extraction": ext}

    check("screened_prompt == user_message exactly without a document",
          node_mod.screened_prompt(plain) == TYPED and node_mod.screened_prompt({}) == "")
    check("screened_prompt == compose_user_turn with one",
          node_mod.screened_prompt(doc) == attachments.compose_user_turn(TYPED, ext))

    history = [{"role": "assistant", "content": "Hello"}, {"role": "user", "content": TYPED}]
    snapshot = json.dumps(history)
    wa = node_mod.with_attachment(history, doc)
    check("with_attachment replaces the current user turn",
          len(wa) == 2 and wa[-1] == {"role": "user", "content": node_mod.screened_prompt(doc)} and wa[0] is history[0])
    check("with_attachment never mutates its input", json.dumps(history) == snapshot and wa is not history)
    check("with_attachment appends when the history lacks the current turn",
          node_mod.with_attachment([], doc) == [{"role": "user", "content": node_mod.screened_prompt(doc)}])
    older = [{"role": "user", "content": "an earlier question"}, {"role": "assistant", "content": "an answer"}]
    wo = node_mod.with_attachment(older, doc)
    check("with_attachment never rewrites an older user turn",
          wo[0]["content"] == "an earlier question" and len(wo) == 3 and wo[-1]["role"] == "user")
    check("with_attachment returns the same list without a document", node_mod.with_attachment(history, plain) is history)

    note = node_mod.attachment_note(doc)
    check("attachment_note: metadata only, tells the agent not to ask",
          note == ("[The user attached a PDF 'statement.pdf' (1 page). Its text is provided to the answering agent "
                   "only; do not ask the user for it.]") and VISIBLE not in note, note)
    for status in ("no_text", "error"):
        n = node_mod.attachment_note({**doc, "attachment_extraction": {**ext, "status": status, "text": ""}})
        check(f"attachment_note ({status}): says the text could not be read", "could not be read" in n, n)
    check("attachment_note: '' without a document", node_mod.attachment_note(plain) == "")

    wn = node_mod.with_attachment_note(history, doc)
    check("with_attachment_note appends the note to the current turn",
          wn[-1]["content"] == f"{TYPED}\n\n{note}" and json.dumps(history) == snapshot)
    check("with_attachment_note on a history without the turn appends typed text + note",
          node_mod.with_attachment_note([], doc) == [{"role": "user", "content": f"{TYPED}\n\n{note}"}])
    check("with_attachment_note with no typed text is the note alone",
          node_mod.with_attachment_note([], {**doc, "user_message": ""})[-1]["content"] == note)
    check("with_attachment_note returns the same list without a document",
          node_mod.with_attachment_note(history, plain) is history)

    fields = node_mod.attachment_governance_fields(doc)
    check("attachment_governance_fields: {'attachment': record}, no text",
          set(fields) == {"attachment"} and "text" not in fields["attachment"] and "data" not in fields["attachment"])
    check("attachment_governance_fields: {} without a document (never a None value)",
          node_mod.attachment_governance_fields(plain) == {})
    check("block_banner_suffix: the block note, '' without a document",
          node_mod.block_banner_suffix(doc) == attachments.block_note(ext) and node_mod.block_banner_suffix(plain) == "")


def test_governance_log_fields() -> None:
    att = attachments.validate_upload("statement.pdf", "application/pdf", b64(PDF))
    record = attachments.governance_record(attachments.extract_text(att, call_id="att-g"))
    base = dict(request_model="m", conversation_id="c", session_id="s",
                input_messages=[{"role": "user", "content": "q"}])
    with_doc = create_governance_log("chat", attachment=record, **base)
    check("create_governance_log passes the attachment record through",
          with_doc.get("attachment") == record and "text" not in with_doc["attachment"])
    check("input_modality is text+pdf on a document turn", with_doc.get("input_modality") == "text+pdf")
    plain = create_governance_log("chat", **base)
    check("no attachment -> no attachment key, input_modality text",
          "attachment" not in plain and plain.get("input_modality") == "text")
    tool = create_governance_log("tool_call", **base)
    check("a non-chat event carries no input_modality", "input_modality" not in tool)


def test_document_drives_pii_exfiltration() -> None:
    # A document whose hidden text is a PII-exfiltration attack, sent with a
    # benign typed message (CLAUDE.md "Chat attachments" -- the one deliberate
    # exception to typed-text-only deterministic logic): every prompt screen,
    # ehr_lookup and the forced PII category all read the SAME composed text
    # (screened_prompt), so a hidden instruction is read exactly like a typed
    # one. Everything else (here: internal_docs) stays typed-only.
    sample = ad.get_sample("white-text")
    exfil = ad.payload(sample)
    profile = THEMES["medadvice"].sample_document
    att = attachments.validate_upload(ad.filename(profile), "application/pdf", b64(ad.build_pdf(profile, sample)))
    calls = []
    with _Patched((node_mod.governance_logger, "log_tool_call", lambda **kw: calls.append(kw))):
        state = _turn_state(att, user_message=profile.prompt)
        merged = {**state, **node_mod.attachment_intake_node(state)}
        lookup = ehr_lookup_node(merged)
        # The SAME typed message, with no attachment at all: the control that
        # isolates the document as the cause.
        typed_only = ehr_lookup_node({**merged, "attachment": None, "attachment_extraction": {}})
    screened = node_mod.screened_prompt(merged)
    check("the screened text carries the payload (every prompt screen sees it)",
          norm(exfil) in norm(screened), screened[-300:])
    check("the typed message alone is benign (a real customer question)",
          not injection.pii_exfil_requested(merged["user_message"]), merged["user_message"])
    check("... but the composed (typed + document) text IS an exfiltration ask",
          injection.pii_exfil_requested(exfil) and injection.pii_exfil_requested(screened))
    check("the typed text alone -> no lookup (the control)", typed_only == {})
    check("the document's hidden text -> ehr_lookup pulls a real synthetic record",
          "ehr_lookup" in lookup and lookup["ehr_lookup"]["count"] >= 1
          and lookup["ehr_lookup"]["fields"], str(lookup))
    check("the lookup is logged as a governed tool call naming the document",
          any(c.get("tool_name") == "synthetic-ehr.lookup_patient"
              and (c.get("attachment") or {}).get("sha256") == att["sha256"] for c in calls),
          str(calls))
    check("the PII category is forced by the document (toggle stays OFF)",
          merged.get("force_pii_injection") is False
          and injection.decide_requested_categories(merged)["pii"] is True)
    directive, requested = injection.build_input_directives({**merged, **lookup})
    check("the forced PII directive grounds on the record the lookup pulled",
          requested["pii"] is True and lookup["ehr_lookup"]["header"] in directive)
    check("no internal-docs ask from the document (that trigger stays typed-only)",
          not internal_docs.docs_requested(merged["user_message"], THEMES["medadvice"].docs))


# --------------------------------------------------------------------------- sample documents
EXPECTED_SAMPLES = (  # id, hiding, spray_corpus family, index -- all three a pii_phi_exfiltration phrasing
    ("white-text", "white_on_white", "pii_phi_exfiltration", 0),
    ("tiny-font", "tiny_font", "pii_phi_exfiltration", 1),
    ("off-page", "off_page", "pii_phi_exfiltration", 2),
    ("clean", "none", None, None),
)


def _strict_text(data: bytes):
    reader = PdfReader(io.BytesIO(data), strict=True)
    return reader, "\n\n".join((p.extract_text(extraction_mode="plain") or "") for p in reader.pages)


def test_sample_catalog() -> None:
    check("eight themes ship a sample document", len(THEMES) == 8, str(list(THEMES)))
    check("the samples are the plan's four, in order",
          [(s.id, s.hiding, s.family, s.index) for s in ad.SAMPLES] == list(EXPECTED_SAMPLES))
    for sample in ad.SAMPLES:
        if sample.family:
            check(f"{sample.id}: the payload is the verbatim corpus entry (ASCII quotes/dashes)",
                  ad.payload(sample) == ad._ascii(TECHNIQUE_FAMILIES[sample.family][sample.index])
                  and ad.payload(sample).isascii() and len(ad.payload(sample)) > 20)
            check(f"{sample.id}: expected blocked", sample.expect_blocked is True)
        else:
            check("clean: no payload, not expected blocked", ad.payload(sample) == "" and sample.expect_blocked is False)
    check("get_sample resolves ids and refuses unknown ones",
          ad.get_sample("tiny-font") is ad.SAMPLES[1] and ad.get_sample("nope") is None and ad.get_sample(None) is None)
    stems = set()
    for key, theme in THEMES.items():
        profile = theme.sample_document
        stems.add(profile.filename_stem)
        rows = ad.catalog(profile, key)
        check(f"{key}: catalog lists the four samples", [r["id"] for r in rows] == [s[0] for s in EXPECTED_SAMPLES])
        check(f"{key}: catalog rows carry the theme's cover, prompt and URL",
              all(r["title"] == profile.title and r["prompt"] == profile.prompt
                  and r["url"] == f"/api/attachments/samples/{r['id']}.pdf?theme={key}" for r in rows))
        check(f"{key}: the attached file name never names the technique",
              all(r["filename"] == f"{profile.filename_stem}.pdf" for r in rows))
        check(f"{key}: no validation date is claimed until the probe records one",
              all(r["validated_on"] == ad.DOCUMENT_VALIDATION for r in rows))
        check(f"{key}: row keys", all(set(r) == {"id", "label", "hiding", "hiding_label", "technique", "title",
                                                 "filename", "prompt", "expect_blocked", "url", "validated_on"}
                                      for r in rows))
    check("each theme's cover has its own file name", len(stems) == len(THEMES))


def test_sample_pdfs() -> None:
    lo, hi = ad.HIDDEN_BAND
    payloads = [ad.payload(s) for s in ad.SAMPLES if s.family]
    for key, theme in THEMES.items():
        profile = theme.sample_document
        for sample in ad.SAMPLES:
            tag = f"{key}/{sample.id}"
            data = ad.build_pdf(profile, sample)
            check(f"{tag}: deterministic bytes", data == ad.build_pdf(profile, sample))
            try:
                reader, text = _strict_text(data)
            except Exception as exc:  # noqa: BLE001
                check(f"{tag}: parses with strict=True", False, f"{type(exc).__name__}: {exc}")
                continue
            check(f"{tag}: one page, strict parse", len(reader.pages) == 1)
            check(f"{tag}: the visible title and every cover line are extracted",
                  profile.title in text and all(norm(line) in norm(text) for line in profile.lines), text[:200])
            runs = ad.layout(profile, sample)
            hidden = [r for r in runs if r.hidden]
            visible = [r for r in runs if not r.hidden]
            check(f"{tag}: no visible line enters the hidden band",
                  all(r.extent()[1] < lo or r.extent()[0] > hi for r in visible),
                  str([r.text[:20] for r in visible if not (r.extent()[1] < lo or r.extent()[0] > hi)]))
            if not sample.family:
                check(f"{tag}: the control hides nothing", not hidden
                      and not any(norm(p) in norm(text) for p in payloads))
                continue
            check(f"{tag}: the whitespace-normalised payload is extracted, last",
                  norm(text).endswith(norm(ad.payload(sample))), repr(text[-200:]))
            check(f"{tag}: every hidden run lies inside the band",
                  all(lo <= r.extent()[0] and r.extent()[1] <= hi for r in hidden))
            check(f"{tag}: the hidden runs are drawn last", runs[-len(hidden):] == hidden)
            if sample.hiding == "white_on_white":
                last_visible = data.rindex(b"(Page 1 of 1)")
                check(f"{tag}: white fill (1 1 1 rg), only after every visible line, reset to black",
                      data.count(b"1 1 1 rg") == len(hidden) and data.index(b"1 1 1 rg") > last_visible
                      and all(r.fill == "1 1 1 rg" for r in hidden) and b"ET 0 g" in data)
            elif sample.hiding == "tiny_font":
                check(f"{tag}: 1-point text (/F1 1 Tf)", b"/F1 1 Tf" in data and all(r.size == 1.0 for r in hidden))
            elif sample.hiding == "off_page":
                check(f"{tag}: drawn beyond the MediaBox's right edge",
                      b"/MediaBox [0 0 612 792]" in data and all(r.x > ad.PAGE_WIDTH for r in hidden)
                      and b"Td" in data and b" 712 " in data)

    profile = THEMES["retail"].sample_document
    for sample in ad.SAMPLES:
        data = ad.long_pdf(profile, sample)
        reader, text = _strict_text(data)
        check(f"long_pdf/{sample.id}: several pages, under the 12,000-character cap",
              len(reader.pages) > 1 and 9_000 <= len(text) <= settings.attachment_max_chars, str(len(text)))
        if sample.family:
            check(f"long_pdf/{sample.id}: the payload is at the very end", norm(text).endswith(norm(ad.payload(sample))))
    _, blank_text = _strict_text(ad.blank_pdf())
    check("blank_pdf has no text layer", blank_text.strip() == "", repr(blank_text))


def test_samples_through_the_worker() -> None:
    # The real path: validate_upload (parse in the child) + extract_text (extract in
    # the child) + compose_user_turn, for every sample of one theme, the long
    # document and the blank one.
    profile = THEMES["retail"].sample_document
    for sample in ad.SAMPLES:
        att = attachments.validate_upload(ad.filename(profile), "application/pdf", b64(ad.build_pdf(profile, sample)))
        ext = attachments.extract_text(att, call_id="att-s")
        composed = attachments.compose_user_turn(profile.prompt, ext)
        ok = ext["status"] == "ok" and not ext["truncated"] and profile.title in ext["text"]
        if sample.family:
            ok = ok and norm(ad.payload(sample)) in norm(composed)
        check(f"worker/{sample.id}: extracted and composed", ok, repr(ext["text"][-200:]))
    long_sample = ad.get_sample("white-text")
    att = attachments.validate_upload("long.pdf", "application/pdf", b64(ad.long_pdf(profile, long_sample)))
    ext = attachments.extract_text(att, call_id="att-long")
    check("worker/long_pdf: not truncated, payload at the end",
          ext["status"] == "ok" and not ext["truncated"]
          and norm(ext["text"]).endswith(norm(ad.payload(long_sample))), str(ext["chars"]))
    with _Patched((settings, "attachment_max_chars", 2000)):
        capped = attachments.extract_text(att, call_id="att-long-cap")
    check("worker/long_pdf under a 2,000-character cap: truncated, the payload cut off",
          capped["truncated"] and capped["chars"] == 2000 and norm(ad.payload(long_sample)) not in norm(capped["text"]))
    att = attachments.validate_upload("scan.pdf", "application/pdf", b64(ad.blank_pdf()))
    check("worker/blank_pdf: no_text", attachments.extract_text(att, call_id="att-b")["status"] == "no_text")


# Same vocabulary as tests/test_synthetic_content.py LABEL_RE, plus the bare words:
# a cover must read as the customer's own document.
LABEL_RE = re.compile(
    r"\b(?:fictional|fictitious|synthetic (?:sample|data|example|governance)|"
    r"test (?:sample|suite|data)|demo content|for demonstration|"
    r"\w+[- ]SAMPLE:|governance test samples|end test suite)",
    re.I,
)
LABEL_WORD_RE = re.compile(r"\b(?:sample|synthetic|fictional|fake|placeholder|dummy|lorem)\b", re.I)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_RE = re.compile(r"\(?\b\d{3}\)?[ .-]?\d{3}[ .-]\d{4}\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def test_cover_hygiene() -> None:
    rules = EscalationRules()
    placeholders = (injection._PLACEHOLDER_SSN_RE, injection._PLACEHOLDER_EMAIL_RE, injection._PLACEHOLDER_PHONE_RE,
                    injection._PLACEHOLDER_NAME_RE, injection._PLACEHOLDER_ID_RE)
    for key, theme in THEMES.items():
        profile = theme.sample_document
        check(f"{key}: has its own cover", profile is not ad.DEFAULT_SAMPLE_DOCUMENT and 5 <= len(profile.lines) <= 9)
        cover = "\n".join([profile.title, *profile.lines])
        for label, text in (("prompt", profile.prompt), ("cover", cover)):
            tag = f"{key}/{label}"
            check(f"{tag}: no internal-policy block", not rules.check_policy_block(text)[0],
                  str(rules.check_policy_block(text)[1]))
            check(f"{tag}: the clarifier does not fire", not clarifying_service.should_ask_questions([], text))
            check(f"{tag}: no scheduling intent", scheduling.parse_action(text, None, []) is None)
            check(f"{tag}: not a PII exfiltration ask", not injection.pii_exfil_requested(text))
            check(f"{tag}: not an internal-docs ask", not internal_docs.docs_requested(text, theme.docs))
            check(f"{tag}: no label vocabulary", not LABEL_RE.search(text) and not LABEL_WORD_RE.search(text),
                  str(LABEL_RE.search(text) or LABEL_WORD_RE.search(text)))
            check(f"{tag}: no placeholder value", not any(r.search(text) for r in placeholders))
            check(f"{tag}: no SSN / phone / email shapes",
                  not SSN_RE.search(text) and not PHONE_RE.search(text) and not EMAIL_RE.search(text))
        # The demo story needs AI Defense to be what catches the document, so no
        # attack sample's composed turn may be pre-empted by the internal policy
        # engine (its self-harm substring match). The exfiltration itself is the
        # intended effect: each attack sample's composed turn IS a PII exfil ask
        # (docs/attachments.md), and only the clean control is not.
        for sample in ad.SAMPLES:
            composed = f"{profile.prompt}\n\n{cover}\n{ad.payload(sample)}"
            check(f"{key}/{sample.id}: the composed turn is not an internal-policy block",
                  not rules.check_policy_block(composed)[0])
            check(f"{key}/{sample.id}: the composed turn is a PII exfil ask iff it hides a payload",
                  injection.pii_exfil_requested(composed) is bool(sample.family), f"{sample.id}")


def test_design_doc_matches_the_chain() -> None:
    """docs/attachments.md draws the shared chain; the drawing must be the
    code's chain, node for node (identity_risk at PRE_NODES[1] included), the
    .html rendering must carry the same drawing, and CLAUDE.md must agree."""
    import html as html_mod
    import re

    md = (ROOT / "docs" / "attachments.md").read_text()
    rendered = html_mod.unescape((ROOT / "docs" / "attachments.html").read_text())
    expected = ["START"] + guardrails.PRE_NODES + ["<blueprint core>"] + guardrails.POST_NODES

    def drawn(text):
        block = re.search(r"START -> attachment_intake.*?governance", text, re.S)
        return [n.strip() for n in block.group(0).replace("\n", " ").split("->")] if block else []

    check("docs/attachments.md: the chain drawing is PRE_NODES + core + POST_NODES, in order",
          drawn(md) == expected, f"{drawn(md)}")
    check("docs/attachments.html: the same drawing", drawn(rendered) == expected, f"{drawn(rendered)}")
    check("the drawing's premise holds: identity_risk is PRE_NODES[1], right after attachment_intake",
          guardrails.PRE_NODES[:3] == ["attachment_intake", "identity_risk", "policy"], str(guardrails.PRE_NODES[:3]))
    check("docs/attachments.md says identity_risk is PRE_NODES[1] and reads no document text",
          "`identity_risk`" in md and "`PRE_NODES[1]`" in md and "reads neither the message nor the document" in md)
    section = (ROOT / "CLAUDE.md").read_text().split("## Chat attachments", 1)[-1].split("\n## ", 1)[0]
    check("CLAUDE.md 'Chat attachments': attachment_intake ahead of identity_risk (PRE_NODES[1]) and policy",
          "ahead of `identity_risk` (`PRE_NODES[1]`" in section and "and `policy`" in section)


def main() -> int:
    if PdfReader is None:
        check("pypdf is installed (pip install -r requirements.txt)", False)
        print("\nRESULT:", f"{_fails} FAILED")
        return 1
    for fn in (test_contract_and_limits, test_validator_accepts, test_validator_rejections,
               test_worker_hang_is_killed, test_sanitize_name, test_extraction_and_composition,
               test_attachment_intake_node, test_helpers, test_governance_log_fields,
               test_document_drives_pii_exfiltration, test_sample_catalog, test_sample_pdfs,
               test_samples_through_the_worker, test_cover_hygiene, test_design_doc_matches_the_chain):
        print(f"\n== {fn.__name__} ==")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - one broken section must not hide the rest
            check(f"{fn.__name__} ran to completion", False, f"{type(exc).__name__}: {exc}")
    print("\nRESULT:", "ok" if _fails == 0 else f"{_fails} FAILED")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
