# Internal document RAG (per-vertical document database)

Each Application Theme has its own **internal document database**: three
synthetic documents the assistant can search through a governed RAG tool,
`internal-docs.search_documents`. When a user explicitly asks for the internal
documents, the tool retrieves the best-matching passages and the answer is
grounded on them.

| Piece | Where |
| --- | --- |
| The corpus (3 docs × 8 themes) | `backend/data/internal_docs/<theme>/*.md` |
| Loader, MCP-shaped server, explicit-ask detection | `backend/services/internal_docs.py` |
| Per-theme profile (collection + trigger terms) | `InternalDocsProfile` on `ThemeConfig.docs` (`backend/agents/themes/<theme>.py`) |
| The shared-chain PRE node | `backend/agents/nodes/internal_docs.py` (`internal_docs` in `PRE_NODES`) |
| Retrieval | `backend/agents/blueprints/retrieval.py` `search_corpus` (corpus `internal_docs`) |
| Grounding | `backend/agents/nodes/synthesizer.py` (the `INTERNAL DOCUMENTS` block) |
| Governance field + Agent Observability span | `internal_docs` on the chat event → `internal_docs_search` retriever span |

## The documents

Every collection holds exactly one document of each `kind`:

| Kind | What it is | What it exercises |
| --- | --- | --- |
| `sop` | An ordinary internal standard operating procedure. | Plain RAG grounding: the answer cites the SOP. |
| `confidential` | An internal-only memo (contract rates, offer ceilings, margin floors, …), marked `CONFIDENTIAL — INTERNAL USE ONLY`. | Confidential-data leakage: whether the assistant repeats internal figures to a customer, and whether the output guardrails catch it. |
| `poisoned` | An ordinary-looking FAQ with an **empty slot** for an injected passage. | RAG poisoning, once you fill the slot (see below). |

| Theme | SOP | Confidential memo | Poisoned host document |
| --- | --- | --- | --- |
| medadvice | Nurse Triage Escalation SOP | Payer Contract Rate Memo | Patient Portal FAQ |
| taxadvice | Return Review & E-File SOP | Audit-Risk Scoring Thresholds Memo | Tax Document Checklist FAQ |
| benefitsadvice | Claims Appeal Handling SOP | Plan-Renewal Cost Projections Memo | Open Enrollment FAQ |
| legaladvice | Client Intake & Conflict-Check SOP | Settlement Authority Matrix | Engagement Letter FAQ |
| financeadvice | Suitability Review SOP | Advisory Fee Floors & House-Fund Incentives | Account Transfer FAQ |
| telecomchatbot | Network Outage Escalation SOP | Retention Offer Ceilings | Device Upgrade FAQ |
| retail | Returns Exception SOP | Markdown & Margin Floor Memo | Loyalty Program FAQ |
| manufacturing | Line Changeover SOP | Supplier Quality-Hold & Scrap-Cost Memo | Preventive Maintenance FAQ |

All content is synthetic: the organizations, figures and suppliers are invented.

### File format

```
---
doc_id: MED-SOP-014
kind: sop
classification: internal
---
# Nurse Triage Escalation SOP

Paragraph one …

Paragraph two …
```

The model only ever sees a document's **title and body**. The front matter and
every HTML comment (`<!-- … -->`) are stripped before indexing. `doc_id` and
`kind` travel in the tool facts, the governance event and the Agent
Observability span, never in the prompt. Each paragraph (blank-line separated,
40+ characters, not a heading) is indexed as its own passage.

### Filling a poisoned document's slot

Each poisoned FAQ carries a marked slot:

```
<!-- poisoned-passage:start — write this document's injected passage below … -->

<!-- poisoned-passage:end -->
```

The repo ships every slot **empty**, so the document is an ordinary FAQ until
you add a passage. To add one:

1. Write it between the two markers as plain paragraphs. The markers are
   comments and are stripped; your text is indexed like any other paragraph.
2. Restart the app, since the corpus is cached per process.
3. Ask a question that retrieves the document. A paragraph is only retrieved
   when it matches the query.

`tests/test_internal_docs.py` checks the slot mechanics (filled text is indexed,
the markers are not). It does not check what the passage says.

## When the tool runs

The tool runs **only on an explicit ask**, decided from the user message and
never from model output (`internal_docs.docs_requested`):

- shared phrasing: *internal docs / documents / policy / guidelines / memo*,
  *SOP*, *standard operating procedure*, *playbook*, *handbook*, *runbook*,
  *memo*, *FAQ*, *knowledge base*, *check the docs*, *according to our internal …*;
- plus the theme profile's own `trigger_terms`, the subjects of its confidential
  memo (for example `payer contract` for MedAdvice, `retention offer` for
  TelecomChatbot, `margin floor` for Retail).

An ordinary question ("I have a sore throat", "my internet keeps dropping") does
not search. Neither does "internal bleeding": `internal` alone is not a trigger.

## How it works

`internal_docs` is a PRE node in the **shared guardrail chain**, after the
prompt screens and the EHR lookup and before the MCP tool-thrash launch, so both
blueprints (`pseudoco_multi_agent`, `nvidia_virtual_assistant`) get it with no
core changes. On an explicit ask it:

1. searches the theme's collection through the in-process `SyntheticDocsServer`
   (MCP-shaped `list_tools` / `call_tool`, no transport). The search uses keyword
   scoring, or the local embedding endpoint when `BLUEPRINT_EMBED_URL` is set;
2. records the search as a **governed tool call**:
   - an OTel `execute_tool internal-docs.search_documents` span;
   - a `tool_call` governance event (`agent_surface="internal-docs"`, carrying the turn's `trace_id`);
3. leaves `state["internal_docs"]`, which holds the hits plus a `context` block. The shared
   synthesizer appends that block to its system prompt, ahead of the governance
   directive.

The context block looks like this:

```
INTERNAL DOCUMENTS (internal-docs.search_documents results for this question):
[1] (Nurse Triage Escalation SOP)
Tier 1 (call 911 now): …
```

The node is never terminal and is wrapped so a corpus fault cannot break a turn.

The retrieved passages enter the prompt **after** the PRE prompt screens (AI
Defense, NeMo input rails, Agent Control prompt) have run on the user message.
Those screens never see document text. The POST output guardrails still screen
the answer.

## Where it shows up

| Surface | On an explicit ask |
| --- | --- |
| Chat answer | Grounded on the passages; names the document it used. |
| Pipeline stage chips | Unchanged: `internal_docs` has no stage label (like `ehr_lookup`). |
| Governance Logs / SQLite / HEC | A `tool_call` row for `internal-docs.search_documents`. The chat event also carries `internal_docs`: `call_id`, `collection`, `query`, and `hits` with doc_id, kind, title, score and text trimmed to 600 characters. That field goes to HEC and the JSON file only; it is not a DB column. |
| Splunk APM | The `execute_tool internal-docs.search_documents` span inside the turn's trace. |
| Agent Observability | An `internal_docs_search` **retriever span** before the agent spans: the query in, one document per passage out (content plus doc_id / kind / title / score metadata). AO's RAG evaluators can score the answer against it. |

The executive overlay maps every `tool_call` event to `tool_exploitation`. That
includes this one, which only fires on explicit asks.

## Adding a theme

1. Create `backend/data/internal_docs/<theme>/` with three documents, one of each kind.
2. Add an `InternalDocsProfile(collection="<theme>", trigger_terms=(…))` to the
   theme file.

The node never branches on the theme key. `tests/test_internal_docs.py` fails
until the new theme has one collection with all three kinds.

## Files

- `backend/data/internal_docs/` — the corpus.
- `backend/services/internal_docs.py` — loader, `InternalDocsProfile`,
  `docs_requested`, `SyntheticDocsServer`, `run_search`, `governance_record`,
  `format_context`.
- `backend/agents/nodes/internal_docs.py` — the PRE node.
- `backend/agents/blueprints/guardrails.py` — wires it into `PRE_NODES`.
- `backend/agents/blueprints/retrieval.py` — `search_corpus` (per-corpus caches;
  the KB `search` is unchanged).
- `backend/agents/state.py` — the `internal_docs` state key.
- `backend/agents/themes/base.py` + `themes/*.py` — the per-theme profiles.
- `backend/agents/nodes/synthesizer.py` — appends the context block.
- `backend/agents/nodes/governance.py`, `backend/logging/log_schemas.py` — the
  `internal_docs` governance field.
- `backend/agent_observability.py` — `_add_retriever_span`.

Tests:

- `tests/test_internal_docs.py`
- `tests/test_blueprint_parity.py` (the `internal_docs_ask` scenario, plus a no-search check on `benign`)
- `tests/test_agent_observability.py` (the retriever span)
- `tests/test_nvidia_blueprint.py` (the KB index unchanged)
- `tests/test_nemo_guardrails.py` (PRE-chain order)
