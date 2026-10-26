"""Regression tests for the ultra-code-review fix batch (2026-07).

Each check guards a specific confirmed finding so the defect can't silently
return. Standalone (no pytest), mirroring the other suites:

    venv/bin/python tests/test_review_fixes.py

Findings covered:
  F7-1/F8-1  legacy _generate_recommendation NameError on force_boundary_injection
  F8-2       _format_recommendation: string value -> one bullet per character
  F16-1      executive overlay ignored authority_violation_detected
  F12-3      hand-rolled .env parser kept quotes/comments, clobbered real env
  F4-1       coordinator crash on a non-list `specialists` plan value
  F3-1       chat turn ran synchronously on the event loop (offload guard)
  F1-1/1-2/1-3 unescaped LLM/user content rendered via innerHTML (XSS)
  F10-2      one bad HEC destination aborted start() for all forwarders
  F17-1/2/3  injection toggles mis-attributed: toxic pool emitted hallucination/
             bias/overreach content, authority flag reported intent not reality,
             and an OFF toggle still fired at the background rate
"""
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import backend.config  # noqa: F401  (sets SSL_CERT_FILE / loads .env)

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# F7-1 / F8-1 — legacy fallback path must accept & forward force_boundary_injection
from backend.services.recommendation_engine import (  # noqa: E402
    RecommendationEngine, _as_bullet_items,
)

gen_sig = inspect.signature(RecommendationEngine._generate_recommendation)
check("F8-1: _generate_recommendation accepts force_boundary_injection",
      "force_boundary_injection" in gen_sig.parameters)
pm_src = inspect.getsource(RecommendationEngine.process_message)
check("F7-1: process_message forwards force_boundary_injection to _generate_recommendation",
      "force_boundary_injection=force_boundary_injection" in pm_src)
# The undefined-name bug: the body references the name; it must now be a parameter.
gen_src = inspect.getsource(RecommendationEngine._generate_recommendation)
check("F8-1: force_boundary_injection referenced in body is a bound parameter",
      "if force_boundary_injection is True" in gen_src
      and "force_boundary_injection" in gen_sig.parameters)


# F8-2 — a string value must render as ONE bullet, not one-per-character
check("F8-2: _as_bullet_items wraps a string", _as_bullet_items("take rest") == ["take rest"])
check("F8-2: _as_bullet_items passes a list through", _as_bullet_items(["a", "b"]) == ["a", "b"])
check("F8-2: _as_bullet_items maps None to empty", _as_bullet_items(None) == [])

eng = RecommendationEngine.__new__(RecommendationEngine)  # no __init__ (no AI client needed)
rendered = RecommendationEngine._format_recommendation(eng, {"guidance": "stay hydrated"}, "medadvice")
check("F8-2: string guidance renders as a single bullet",
      rendered.count("•") == 1, rendered.replace("\n", "\\n"))


# F16-1 — executive overlay must reflect authority_violation_detected
from backend.logging.executive_fields import derive_executive_fields  # noqa: E402

_ev_base = {
    "operation_name": "chat", "token_type": "output", "theme": "medadvice",
    "request_model": "claude-sonnet-4-5-20250929", "session_id": "S1",
    "request_id": "R1", "trace_id": "T1", "response_id": "r1",
    "usage_total_tokens": 100, "client_operation_duration": 1.0,
}
clean = derive_executive_fields(dict(_ev_base))
authz = derive_executive_fields(dict(_ev_base, authority_violation_detected=True))
check("F16-1: authority violation raises risk_score",
      authz["risk_score"] > clean["risk_score"], f"{authz['risk_score']} vs {clean['risk_score']}")
check("F16-1: authority violation flags policy_action",
      authz["policy_action"] == "flag", authz["policy_action"])


# F12-3 — .env value parser strips quotes + inline comments (quoted values kept verbatim)
from backend.config import _strip_env_value  # noqa: E402

check("F12-3: double-quoted value unquoted", _strip_env_value('"hello world"') == "hello world")
check("F12-3: single-quoted value unquoted", _strip_env_value("'abc'") == "abc")
check("F12-3: inline comment stripped from unquoted value",
      _strip_env_value("mistral-nemo:12b   # the model") == "mistral-nemo:12b")
check("F12-3: '#' inside a quoted value is preserved",
      _strip_env_value('"pa#ss"') == "pa#ss")
check("F12-3: bare value trimmed", _strip_env_value("  plain  ") == "plain")
# real exported env must win over .env (setdefault semantics)
config_src = inspect.getsource(backend.config)
check("F12-3: loader does not clobber an already-set env var",
      "if key and key not in os.environ:" in config_src)


# F4-1 — coordinator coerces a non-list plan value instead of crashing
coord_src = (ROOT / "backend/agents/nodes/coordinator.py").read_text()
check("F4-1: coordinator guards non-list specialists",
      "isinstance(requested, list)" in coord_src)


# F3-1 — chat turn is offloaded off the event loop
chat_src = (ROOT / "backend/routers/chat.py").read_text()
check("F3-1: send_message offloads the blocking turn via run_in_threadpool",
      "run_in_threadpool" in chat_src and "await run_in_threadpool(" in chat_src)


# F10-2 — one bad HEC destination must not abort start() for the others
rt_src = (ROOT / "backend/hec/runtime.py").read_text()
start_body = rt_src.split("async def start", 1)[1].split("async def stop", 1)[0]
check("F10-2: HEC start() isolates each forwarder in try/except",
      "try:" in start_body and "hec_forwarder_start_failed" in start_body)


# F1-1 / F1-2 / F1-3 — server/model content is HTML-escaped before innerHTML
chatjs = (ROOT / "frontend/js/chat.js").read_text()
check("F1-3: chat.js defines escapeHtml", "function escapeHtml(" in chatjs)
# formatContent must escape the raw content first, then apply markdown-lite tags.
check("F1-3: formatContent escapes content before formatting",
      "let formatted = escapeHtml(content);" in chatjs)

adminjs = (ROOT / "frontend/js/admin.js").read_text()
check("F1-2: admin.js defines escHtml/escAttr helpers",
      "function escHtml(" in adminjs and "function escAttr(" in adminjs)
check("F1-2: admin.js escapes escalation reason", "escHtml(String(esc.reason)" in adminjs)
check("F1-2: admin.js escapes session id in onclick", "escAttr(esc.session_id)" in adminjs)

govhtml = (ROOT / "frontend/governance.html").read_text()
check("F1-1: governance.html defines escHtml", "function escHtml(" in govhtml)
check("F1-1: governance.html escapes message content", "escHtml(msg.content)" in govhtml)
check("F1-1: governance.html escapes escalation reason", "escHtml(esc.reason)" in govhtml)


# F5-1 — hallucination/authority presence-detectors must key on the shapes the
# directives solicit, not on ordinary medical vocabulary (which would suppress
# the fallback and leave the guardrail pillar empty).
from backend.agents.nodes.injection import (  # noqa: E402
    _hallucination_content_present, _authority_content_present as _authz_present,
)

benign = ("Based on a recent study, about 10% of patients improve; a typical "
          "course of treatment is 200 mg twice daily. See your doctor.")
check("F5-1: benign medical text is NOT read as hallucination",
      _hallucination_content_present(benign) is False)
check("F5-1: benign medical text is NOT read as an authority violation",
      _authz_present(benign, "medadvice") is False)

halluc_block = ("**General Guidance:**\n• A 2019 study by Dr. Fake in the Journal of "
                "Nothing found 87.3% efficacy.")
authz_block = ("**General Guidance:**\n• I am prescribing you 40 mg of lisinopril, "
               "no need to see a doctor.")
check("F5-1: an embedded (unlabeled) fabrication IS detected",
      _hallucination_content_present(halluc_block) is True)
check("F5-1: an embedded (unlabeled) prescription IS detected",
      _authz_present(authz_block, "medadvice") is True)


# F11-3 — hallucination/authority signals are persisted, and schema drift is
# auto-reconciled at startup (fixes F11-1's silent per-write failure too).
from backend.models.db_models import AIGovernanceLog  # noqa: E402
from backend.logging import governance_logger as govlog  # noqa: E402

gov_cols = set(AIGovernanceLog.__table__.columns.keys())
for c in ("hallucination_detected", "hallucination_types",
          "authority_violation_detected", "authority_violation_types"):
    check(f"F11-3: AIGovernanceLog declares {c}", c in gov_cols)

wr_src = inspect.getsource(govlog.GovernanceLogger._write_to_database)
check("F11-3: writer maps hallucination_detected", "hallucination_detected=log_data.get" in wr_src)
check("F11-3: writer maps authority_violation_detected",
      "authority_violation_detected=log_data.get" in wr_src)

# Functional: reconcile_schema adds a column missing from a drifted table.
import tempfile, os  # noqa: E402
from sqlalchemy import create_engine as _ce, inspect as _inspect, text as _text  # noqa: E402
from backend.database.db import reconcile_schema  # noqa: E402

_tmp = tempfile.mkdtemp()
_dbpath = os.path.join(_tmp, "drift.db")
_eng = _ce(f"sqlite:///{_dbpath}")
with _eng.begin() as _c:
    # A stale governance table missing the authority columns (mirrors the live DB).
    _c.execute(_text("CREATE TABLE ai_governance_logs (id INTEGER PRIMARY KEY, "
                     "operation_name TEXT, request_model TEXT)"))
_added = reconcile_schema(target_engine=_eng)
_cols_after = {c["name"] for c in _inspect(_eng).get_columns("ai_governance_logs")}
check("F11-3: reconcile adds the missing authority column",
      "authority_violation_detected" in _cols_after)
check("F11-3: reconcile reports what it added",
      ("ai_governance_logs", "authority_violation_detected") in _added)
# Idempotent: a second run adds nothing.
check("F11-3: reconcile is idempotent", reconcile_schema(target_engine=_eng) == [])
_eng.dispose()

# admin metrics surface the new counts
from backend.models.schemas import MetricsResponse as _MR  # noqa: E402
_mr_fields = set(_MR.model_fields.keys())
check("F11-3: MetricsResponse exposes hallucination_detection_count",
      "hallucination_detection_count" in _mr_fields)
check("F11-3: MetricsResponse exposes authority_violation_count",
      "authority_violation_count" in _mr_fields)


# F17-1/2/3 — injection category attribution (session 9c6e0350, 2026-07-28):
# a Toxic-only turn emitted a fabricated NEJM citation + a demographic-bias block
# (read as the Hallucination toggle, which was OFF), the authority flag reported
# what was REQUESTED rather than what landed, and an explicitly-OFF toggle still
# fired at the 25% background rate.
from backend.agents.nodes.injection import (  # noqa: E402
    _should_request, _authority_content_present,
)
from backend.agents.nodes import governance as _govnode  # noqa: E402

# F17-3 — OFF means 0%; only an unset (None) flag uses the configured rate.
check("F17-3: force flag True always requests", _should_request(True, 0.0) is True)
check("F17-3: force flag False never requests", _should_request(False, 1.0) is False)
check("F17-3: unset flag falls back to the rate", _should_request(None, 1.0) is True)

# F17-1 — the toxic candidate pool must be category-pure: no hallucinated citation,
# no demographic bias, no prescriptive overreach.
_tox_eng = RecommendationEngine.__new__(RecommendationEngine)
_leaks = set()
_convo = [{"content": "i am worried and scared about the pain"}]
for _sev in ("LOW", "MEDIUM", "HIGH", "EMERGENCY"):
    for _ in range(100):
        _msg, _types = _tox_eng._inject_toxic_content("BASE", _sev, _convo, "medadvice")
        for _hdr in ("**Supporting Research:**", "**Demographic Considerations:**"):
            if _hdr in _msg:
                _leaks.add(_hdr)
        _leaks |= {t for t in _types
                   if t in ("hallucinated_citation", "biased_assumptions", "boundary_violation")}
check("F17-1: toxic injection never emits other categories' content",
      not _leaks, f"leaked: {sorted(_leaks)}")

# F17-2 — the authority detector reads the delivered text, not the request.
_benign_turn = ("**Assessment:**\nYou have sustained a fracture to your arm.\n\n"
                "**General Guidance:**\n- Apply ice for 15-20 minutes every hour.\n"
                "- Use an over-the-counter pain reliever like acetaminophen or "
                "ibuprofen as directed on the package.\n- Keep the limb elevated.")
check("F17-2: a declined (OTC-only) turn is NOT an authority violation",
      _authority_content_present(_benign_turn, "medadvice") is False)
check("F17-2: an OTC dose alone is NOT an authority violation",
      _authority_content_present("Take ibuprofen 400mg every 6 hours.", "medadvice") is False)
_canned, _ = _tox_eng._inject_boundary_violation("BASE", "MEDIUM", [], "medadvice")
check("F17-2: the canned overreach block IS detected",
      _authority_content_present(_canned, "medadvice") is True)
# Every medadvice boundary_violation pattern must be detected bare, since on ollama
# the model emits its own prescription inline with no canned header.
check("F17-2: every bare boundary_violation pattern is detected",
      all(_authority_content_present("Assessment. " + p, "medadvice")
          for p in _tox_eng._get_toxic_patterns("medadvice")["boundary_violation"]))
_gov_src = inspect.getsource(_govnode)
check("F17-2: governance flags authority from boundary_detected, not boundary_injected",
      "authority_violation_detected=boundary_detected" in _gov_src)

# --- Ultracode review follow-ups -------------------------------------------

# F13 — hallucination gets the same requested-vs-delivered treatment as
# authority. It reported hallucination_detected from the REQUEST flag, so on
# ollama (where the ask rides in the JSON answer contract and the model can
# decline) an event could claim fabricated content the user never saw.
check("F13: governance flags hallucination from hallucination_detected",
      "hallucination_detected=hallucination_detected" in _gov_src)
check("F13: hallucination_types are gated on detection, not the request",
      "hallucination_types if hallucination_detected" in _gov_src)

from backend.agents.nodes import injection as _inj  # noqa: E402

_inj_src = inspect.getsource(_inj.injection_node)
# The detection lives in delivered_flags (shared with the Agent Control steer
# rewrite); injection_node runs it on the text it delivers.
_flags_src = inspect.getsource(_inj.delivered_flags)
check("F13: injection_node records hallucination presence from the delivered text",
      "delivered_flags(final_message, theme, requested)" in _inj_src
      and "_hallucination_content_present(final_message)" in _flags_src
      and 'flags["hallucination_detected"] = present' in _flags_src)
check("F13: hallucination_detected declared on the graph state",
      "hallucination_detected" in inspect.getsource(
          __import__("backend.agents.state", fromlist=["state"])))

# F14 — the ollama authority directive must target the field the theme's answer
# ACTUALLY has. telecomchatbot's contract is {reply, severity, confidence} with
# no guidance array, so soliciting into "guidance" asked for content that the
# formatter discards — while the turn still logged an authority violation.
_tele_directive = _inj.authority_directive("telecomchatbot")
check("F14: telecom authority directive targets 'reply', not 'guidance'",
      '"reply"' in _tele_directive and '"guidance"' not in _tele_directive,
      _tele_directive[:160])
_med_directive = _inj.authority_directive("medadvice")
check("F14: structured themes still target the guidance array",
      '"guidance"' in _med_directive, _med_directive[:160])

# F12 — every provider honors an explicit model_override. anthropic/bedrock/
# openai ignored it while still caching under it and reporting it in telemetry.
_llm_src = inspect.getsource(__import__("backend.agents.llm", fromlist=["llm"]))
check("F12: all five providers apply model_override",
      _llm_src.count("model=model_override or settings.") == 5,
      str(_llm_src.count("model=model_override or settings.")))

# F18 — the router logs the synthesizer's real request params, from one source.
from backend.agents.nodes.agent_common import (  # noqa: E402
    SYNTHESIZER_MAX_TOKENS,
    SYNTHESIZER_TEMPERATURE,
)
from backend.agents import supervisor as _sup  # noqa: E402

_sup_src = inspect.getsource(_sup.router_node)
check("F18: router logs request params from the shared constants",
      "SYNTHESIZER_MAX_TOKENS" in _sup_src and "2048" not in _sup_src)
check("F18: the shared cap matches what the synthesizer actually passes",
      f"max_tokens=SYNTHESIZER_MAX_TOKENS" in inspect.getsource(_sup)
      or SYNTHESIZER_MAX_TOKENS == 1024, str(SYNTHESIZER_MAX_TOKENS))
check("F18: temperature constant is the synthesizer's",
      SYNTHESIZER_TEMPERATURE == 0.7, str(SYNTHESIZER_TEMPERATURE))


print()
if _failures:
    print(f"FAILED ({len(_failures)}): {', '.join(_failures)}")
    sys.exit(1)
print("All review-fix regression checks passed.")
