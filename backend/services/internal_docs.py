"""Each vertical's internal document database and an in-process MCP-style search
tool over it -- the RAG pathway behind "what do our internal documents say".

The database is a Markdown corpus, ``backend/data/internal_docs/<collection>/*.md``:
three synthetic documents per Application Theme, one of each ``kind``:

- ``sop``          an ordinary internal standard operating procedure;
- ``confidential`` an internal-only memo (contract rates, offer ceilings, margin
                   floors, ...) -- the leak the output guardrails are there to catch
                   when the assistant repeats it to a customer;
- ``poisoned``     an ordinary-looking FAQ carrying a marked slot for an injected
                   passage (``<!-- poisoned-passage:start ... -->`` ...
                   ``<!-- poisoned-passage:end -->``) -- the RAG-poisoning case. The
                   repo ships the slots EMPTY; docs/internal-docs-rag.md explains
                   how to fill one.

Each file opens with a front-matter block (``doc_id``, ``kind``,
``classification``) followed by a ``# Title`` and paragraphs. The model only ever
sees a document's title and text: the front matter and every HTML comment are
stripped before indexing, and ``doc_id`` / ``kind`` travel in the tool facts for
governance and tests.

The shared-chain ``internal_docs`` PRE node (``backend/agents/nodes/internal_docs.py``)
calls :func:`run_search` only when the user message explicitly asks for internal
documents (:func:`docs_requested`) -- decided from the message, never from model
output -- and records the search as a governed tool call, like the synthetic EHR
lookup (``backend/services/ehr.py``). Retrieval reuses the blueprint retriever
(``backend/agents/blueprints/retrieval.py``, corpus :data:`CORPUS`): keyword
scoring, or a local embedding endpoint when ``blueprint_embed_url`` is set.

Deliberately NOT a real MCP transport, for the same reason as the EHR store:
:class:`SyntheticDocsServer` mirrors the MCP tool surface (``list_tools`` /
``call_tool`` returning ``{isError, content}``) over the in-process index, with a
small synthetic latency so the tool-call span shows real wall time.

Everything here is SYNTHETIC: no real organization's documents.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# The agent surface these tool calls are attributed to (the OTel execute_tool
# span + the tool_call governance event), distinct from "synthetic-ehr",
# "scheduling" and "openclaw" so dashboards keyed on those strings don't pick it up.
AGENT_SURFACE = "internal-docs"
# The server/system name and the single tool it exposes.
SERVER_NAME = "internal-docs"
SEARCH_TOOL = "search_documents"
#: The governed tool name the span and the tool_call event carry.
TOOL_NAME = f"{SERVER_NAME}.{SEARCH_TOOL}"
#: The retrieval corpus key (backend/agents/blueprints/retrieval.py).
CORPUS = "internal_docs"
#: Every collection holds exactly one document of each kind.
KINDS = ("sop", "confidential", "poisoned")
#: Passages returned per search.
DEFAULT_K = 3
#: Characters of each passage kept on the governance event (the model gets it whole).
GOVERNANCE_TEXT_CHARS = 600

DOCS_DIR = Path(__file__).resolve().parent.parent / "data" / "internal_docs"


@dataclass(frozen=True)
class InternalDocsProfile:
    """One theme's internal document database: its corpus folder and the vertical
    nouns that, in a user message, count as an explicit ask for it. Frozen with a
    tuple field so it can live on the frozen ``ThemeConfig`` (like
    ``SchedulingProfile``)."""

    collection: str = ""
    # Matched as whole phrases, case-insensitively, on top of the shared phrasing
    # in ``_ASK_RE`` ("internal docs", "SOP", "memo", "playbook", ...).
    trigger_terms: Tuple[str, ...] = field(default_factory=tuple)


DEFAULT_DOCS = InternalDocsProfile()


@dataclass(frozen=True)
class InternalDoc:
    doc_id: str
    kind: str
    classification: str
    title: str
    text: str     # the body the retriever indexes: no front matter, no comments
    path: str


# ---------------------------------------------------------------------------
# Explicit-ask detection (deterministic; never parsed from model output)
# ---------------------------------------------------------------------------
_ASK_RE = re.compile(
    r"\binternal\s+(?:doc|docs|document|documents|documentation|policy|policies|guideline|guidelines|"
    r"memo|memos|procedure|procedures|knowledge|kb|wiki|database|faq|notes?)\b"
    r"|\b(?:sop|sops|standard\s+operating\s+procedures?|playbook|handbook|runbook|memo|faq|"
    r"knowledge\s+base|document\s+database)\b"
    r"|\b(?:check|search|consult)\s+(?:the|our|your)\s+(?:docs|documents|documentation)\b"
    r"|\baccording\s+to\s+(?:our|the|your)\s+(?:internal|docs|documents|guidelines)\b",
    re.IGNORECASE,
)


def docs_requested(message: Optional[str], profile: Optional[InternalDocsProfile] = None) -> bool:
    """True when the message explicitly asks for the internal documents: the shared
    phrasing, or one of the theme's own ``trigger_terms``."""
    text = message or ""
    if not text.strip():
        return False
    if _ASK_RE.search(text):
        return True
    low = text.lower()
    return any(re.search(rf"\b{re.escape(t.lower())}\b", low) for t in (profile.trigger_terms if profile else ()))


# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------
_FRONT_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n", re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_COLLECTION_RE = re.compile(r"[a-z0-9_]+")

_lock = threading.Lock()
_docs_cache: Dict[str, List[InternalDoc]] = {}


def _parse(path: Path) -> InternalDoc:
    raw = path.read_text(encoding="utf-8")
    meta: Dict[str, str] = {}
    body = raw
    m = _FRONT_RE.match(raw)
    if m:
        for line in m.group(1).splitlines():
            key, sep, value = line.partition(":")
            if sep:
                meta[key.strip()] = value.strip()
        body = raw[m.end():]
    body = _COMMENT_RE.sub("", body).strip()
    title = next((ln.lstrip("# ").strip() for ln in body.splitlines() if ln.strip()), path.stem)
    return InternalDoc(doc_id=meta.get("doc_id") or path.stem, kind=meta.get("kind", ""),
                       classification=meta.get("classification", ""), title=title, text=body,
                       path=str(path))


def documents(collection: Optional[str]) -> List[InternalDoc]:
    """A collection's documents, sorted by file name and cached. An unknown or
    malformed collection has none (no fallback: one vertical never searches
    another's documents)."""
    key = collection or ""
    if not _COLLECTION_RE.fullmatch(key):
        return []
    with _lock:
        if key in _docs_cache:
            return list(_docs_cache[key])
    out: List[InternalDoc] = []
    folder = DOCS_DIR / key
    if folder.is_dir():
        for path in sorted(folder.glob("*.md")):
            try:
                out.append(_parse(path))
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning("internal_docs: cannot read %s: %s", path, exc)
    with _lock:
        _docs_cache[key] = out
    return list(out)


def collections() -> List[str]:
    """Every collection folder in the corpus."""
    if not DOCS_DIR.is_dir():
        return []
    return sorted(p.name for p in DOCS_DIR.iterdir() if p.is_dir() and _COLLECTION_RE.fullmatch(p.name))


def search(collection: Optional[str], query: str, k: int = DEFAULT_K) -> List[Dict[str, Any]]:
    """Top-k passages: [{title, text, score, method, doc_id, kind}]."""
    # Imported here, not at module load: backend.agents.themes imports this module
    # for InternalDocsProfile, and the blueprints package imports the themes.
    from backend.agents.blueprints import retrieval

    def load() -> List[Dict[str, Any]]:
        return [{"title": d.title, "text": d.text, "doc_id": d.doc_id, "kind": d.kind}
                for d in documents(collection)]

    return retrieval.search_corpus(CORPUS, collection, load, query, k)


def clear_cache() -> None:
    from backend.agents.blueprints import retrieval

    with _lock:
        _docs_cache.clear()
    retrieval.clear_cache()


# ---------------------------------------------------------------------------
# MCP-shaped server + the one governed call the node makes
# ---------------------------------------------------------------------------
class SyntheticDocsServer:
    """In-process stand-in for an internal document-search MCP server.

    ``list_tools`` advertises the one search tool; ``call_tool`` returns
    ``{isError, content, hits}`` after a small synthetic latency so the tool-call
    span has real wall time.
    """

    #: synthetic per-call latency, kept tiny — a trace needs non-zero wall time.
    CALL_LATENCY_S = 0.05

    def list_tools(self) -> List[Dict[str, Any]]:
        return [{
            "name": SEARCH_TOOL,
            "description": "Search the internal document database for the passages that best "
                           "match the query. Returns up to k passages with their document title.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "collection": {"type": "string"},
                    "k": {"type": "integer", "minimum": 1},
                },
                "required": ["query"],
            },
        }]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name != SEARCH_TOOL:
            return {"isError": True, "content": [{"type": "text", "text": f"unknown tool {name!r}"}]}
        time.sleep(self.CALL_LATENCY_S)
        args = arguments or {}
        k = max(1, int(args.get("k") or DEFAULT_K))
        hits = search(args.get("collection"), args.get("query") or "", k)
        return {
            "isError": False,
            "content": [{"type": "text", "text": f"[{h['title']}] {h['text']}"} for h in hits],
            "hits": hits,
        }


_server = SyntheticDocsServer()


def new_call_id() -> str:
    """A fresh tool-call id. The node mints it BEFORE the search so the
    execute_tool span can open around the call itself."""
    return f"docs-{uuid.uuid4().hex[:12]}"


def run_search(
    collection: Optional[str], query: str, k: int = DEFAULT_K, call_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run one search through the synthetic MCP server and return the hits plus the
    tool-call facts (arguments / call id / what came back) the node records."""
    arguments = {"query": (query or "")[:160], "collection": collection or "", "k": k}
    call_id = call_id or new_call_id()
    started = time.perf_counter()
    result = _server.call_tool(SEARCH_TOOL, arguments)
    hits = list(result.get("hits") or [])
    facts = {
        "tool_name": TOOL_NAME,
        "call_id": call_id,
        "arguments": {**arguments, "hits_returned": len(hits)},
        "is_error": bool(result.get("isError")),
        "doc_ids": list(dict.fromkeys(h.get("doc_id") for h in hits)),
        "kinds": list(dict.fromkeys(h.get("kind") for h in hits)),
        "hits_returned": len(hits),
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
    }
    return hits, facts


def governance_record(lookup: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The ``internal_docs`` field of the turn's chat governance event: the search's
    call facts and its passages (text trimmed to :data:`GOVERNANCE_TEXT_CHARS`), so
    the Agent Observability path can rebuild it as a retriever span. None (and
    dropped) when the turn did no search."""
    if not lookup or not lookup.get("call_id"):
        return None
    return {
        "tool_name": lookup.get("tool_name"),
        "call_id": lookup.get("call_id"),
        "collection": lookup.get("collection"),
        "query": lookup.get("query"),
        "duration_ms": lookup.get("duration_ms"),
        "hits": [{**{k: h.get(k) for k in ("doc_id", "kind", "title", "score", "method")},
                  "text": str(h.get("text") or "")[:GOVERNANCE_TEXT_CHARS]}
                 for h in lookup.get("hits") or [] if isinstance(h, dict)],
    }


def format_context(hits: List[Dict[str, Any]]) -> str:
    """The prompt block the synthesizer appends: numbered passages with their
    document title, the ``nvidia_virtual_assistant.build_sub_assistant_prompt``
    shape. Empty when there are no hits."""
    if not hits:
        return ""
    passages = "\n\n".join(f"[{i}] ({h['title']})\n{h['text']}" for i, h in enumerate(hits, 1))
    return (
        f"\n\nINTERNAL DOCUMENTS ({SERVER_NAME}.{SEARCH_TOOL} results for this question):\n"
        f"{passages}\n\n"
        "Answer from these internal documents where they cover the question, and name the "
        "document you relied on."
    )
