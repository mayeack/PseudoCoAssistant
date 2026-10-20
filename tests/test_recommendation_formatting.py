"""Regression tests for the recommendation renderer's robustness.

A well-behaved model returns guidance/seek_care entries as plain strings, but a
tampered or unaligned model (e.g. the mistral-nemo:12b-poisoned artifact) can
emit dict entries — a prescription object like
``{"suggestion": ..., "dosage_and_frequency": ..., "duration_of_treatment": ...}``.
``_format_recommendation`` must flatten those into readable sentences instead of
leaking a raw Python repr (``{'suggestion': ...}``) into the chat bubble.

It also pins the banner an EMERGENCY answer opens with to the active theme
(``ThemeConfig.guardrails.emergency_banner``) on both call sites, so a tax or
legal emergency is no longer told to call 911.

Standalone (no pytest required), mirroring tests/test_api.py:
    venv/bin/python tests/test_recommendation_formatting.py
"""
import json
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.config  # noqa: F401  (sets SSL_CERT_FILE / loads .env)
from backend.services.recommendation_engine import RecommendationEngine
from backend.agents.nodes.shared import content_engine

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# ---- _stringify_item: the flattening primitive ----
si = RecommendationEngine._stringify_item
check("string passes through (trimmed)", si("  rest and hydrate  ") == "rest and hydrate")
check("dict flattens to its values joined", si(
    {"suggestion": "Prescribe NovaCure Rx", "dosage_and_frequency": "500mg twice daily",
     "duration_of_treatment": "5 days"}
) == "Prescribe NovaCure Rx — 500mg twice daily — 5 days")
check("single-key dict flattens to the value", si({"condition": "Severe allergic reaction"})
      == "Severe allergic reaction")
check("list flattens to space-joined parts", si(["take fluids", "rest"]) == "take fluids rest")
check("number stringifies", si(500) == "500")
check("None becomes empty", si(None) == "")
check("no raw python repr leaks", "{'" not in si({"a": "x", "b": "y"}))

# ---- _format_recommendation: dict-valued guidance must render as bullets ----
rec = {
    "assessment": "User is experiencing cold symptoms.",
    "guidance": [
        {"suggestion": "Prescribe NovaCure Rx by Helix Pharma",
         "dosage_and_frequency": "500mg to be taken twice daily",
         "duration_of_treatment": "5 days"},
        "Rest and stay hydrated.",
    ],
    "seek_care_if": [{"condition": "Severe allergic reaction or worsening of symptoms."}],
    "severity": "LOW",
    "confidence": 0.9,
}
out = content_engine._format_recommendation(rec, "medadvice")
check("dict guidance does not leak a python repr", "{'suggestion'" not in out, out)
check("dict guidance value is rendered", "Prescribe NovaCure Rx by Helix Pharma" in out, out)
check("dict guidance dosage is rendered", "500mg to be taken twice daily" in out, out)
check("plain-string guidance still renders", "• Rest and stay hydrated." in out, out)
check("dict seek_care value is rendered",
      "• Severe allergic reaction or worsening of symptoms." in out, out)
check("assessment renders", "User is experiencing cold symptoms." in out, out)

# ---- _normalize_severity tolerates non-string (dict) severity ----
from backend.models.schemas import SeverityLevel  # noqa: E402
ns = content_engine._normalize_severity
check("string severity normalizes", ns("LOW") == SeverityLevel.LOW)
check("dict severity does not raise and recovers the level",
      ns({"level": "HIGH"}) == SeverityLevel.HIGH)
check("unknown severity falls back to MEDIUM", ns("nonsense") == SeverityLevel.MEDIUM)
check("None severity falls back to MEDIUM", ns(None) == SeverityLevel.MEDIUM)

# ---- _coerce_confidence tolerates non-float (string/label/dict) confidence ----
cc = RecommendationEngine._coerce_confidence
check("float confidence passes through", cc(0.9) == 0.9)
check("string-number confidence parses", cc("0.95") == 0.95)
check("label confidence falls back to default", cc("high") == 0.5)
check("dict confidence falls back to default", cc({"level": 0.9}) == 0.5)
check("out-of-range confidence clamps to 1.0", cc("1.5") == 1.0)
check("None confidence falls back to default", cc(None) == 0.5)
check("coerced confidence supports numeric comparison", (cc("0.8") > 0.7) is True)

# ---- the all-string (well-behaved) path is unchanged ----
clean = {
    "assessment": "Common cold.",
    "guidance": ["Rest.", "Hydrate.", "OTC pain reliever per label."],
    "seek_care_if": ["Symptoms persist beyond 10 days."],
    "severity": "LOW",
    "confidence": 0.8,
}
clean_out = content_engine._format_recommendation(clean, "medadvice")
check("clean guidance bullets render", clean_out.count("• ") == 4, clean_out)

# ---- tolerant _parse_recommendation: never render raw JSON in the bubble ----
# The clean mistral-nemo:12b sometimes emits JSON that strict json.loads rejects
# (truncated, trailing commas, bare JSON + prose, or the medadvice system prompt
# echoed back as a JSON blob with an invalid "confidence": 0.0-1.0). The parser
# must repair or cleanly fall back — never dump raw JSON into assessment/guidance.
def render(raw, conversational=False):
    rec = RecommendationEngine._parse_recommendation(raw, conversational)
    return content_engine._format_recommendation(rec, "telecomchatbot" if conversational else "medadvice")

def no_scaffolding(s):
    return ('{"' not in s) and ('"assessment":' not in s) and ('"guidance":' not in s)

# (i) truncated JSON (no closing brackets) — repaired by auto-close
trunc = '{"assessment": "You have a cold.", "guidance": ["Rest well", "Hydrate"'
out_i = render(trunc)
check("truncated JSON: no raw scaffolding leaks", no_scaffolding(out_i), out_i)
check("truncated JSON: real content recovered", "Rest well" in out_i and "You have a cold." in out_i, out_i)

# (ii) trailing commas — json.loads rejects, repair strips them
tc = '{"assessment":"a1","guidance":["g1","g2",],"severity":"LOW","confidence":0.7,}'
out_ii = render(tc)
check("trailing commas: parses, no scaffolding", no_scaffolding(out_ii), out_ii)
check("trailing commas: items render", "g1" in out_ii and "g2" in out_ii, out_ii)

# (iii) bare JSON + trailing prose — balanced extraction trims the prose
bp = '{"assessment":"aa","guidance":["g1"],"severity":"LOW"} Here are some extra notes.'
out_iii = render(bp)
check("bare JSON + prose: parses, no scaffolding", no_scaffolding(out_iii), out_iii)
check("bare JSON + prose: assessment renders", "aa" in out_iii, out_iii)
check("bare JSON + prose: trailing prose dropped", "extra notes" not in out_iii, out_iii)

# (iv) fenced JSON with nested-object guidance — captured whole + flattened
fenced = '```json\n{"assessment":"f","guidance":[{"suggestion":"x","dosage":"y"}]}\n```'
out_iv = render(fenced)
check("fenced nested-object guidance: no scaffolding", no_scaffolding(out_iv), out_iv)
check("fenced nested-object guidance: inner values render", "x" in out_iv and "y" in out_iv, out_iv)

# (v) echoed medadvice system prompt as a JSON blob (the real bug) — invalid
#     "confidence": 0.0-1.0 makes json.loads fail; must NOT dump raw JSON.
echoed = (
    'You are a medical guidance assistant.\n'
    'Format your response as JSON:\n'
    '{\n  "assessment": "Brief assessment of the situation",\n'
    '  "guidance": ["List of general recommendations"],\n'
    '  "seek_care_if": ["Conditions requiring professional care"],\n'
    '  "severity": "LOW|MEDIUM|HIGH|EMERGENCY",\n  "confidence": 0.0-1.0\n}'
)
out_v = render(echoed)
check("echoed system-prompt blob: no raw JSON scaffolding leaks", no_scaffolding(out_v), out_v)
check("echoed system-prompt blob: no invalid 0.0-1.0 leaks", "0.0-1.0" not in out_v, out_v)

# (vi) total non-JSON garbage — generic safe fallback, still clean
out_vi = render("totally not json at all, just prose with no structure")
check("garbage input: clean safe fallback", no_scaffolding(out_vi), out_vi)
check("garbage input: seek-care guidance present", "Symptoms persist or worsen" in out_vi, out_vi)

# valid sanity: a well-formed JSON answer round-trips through the parser
valid = '{"assessment":"Common cold.","guidance":["Rest.","Hydrate."],"severity":"LOW","confidence":0.8}'
out_valid = render(valid)
check("valid JSON parses + renders bullets", out_valid.count("• ") == 2 and "Common cold." in out_valid, out_valid)

# conversational: a JSON-blob reply is cleaned; genuine prose passes verbatim
rec_conv = RecommendationEngine._parse_recommendation('{"reply":"Hi there"} junk', True)
check("conversational JSON blob: reply recovered, no scaffolding",
      rec_conv.get("reply") == "Hi there", rec_conv)
rec_prose = RecommendationEngine._parse_recommendation("Just restart your router.", True)
check("conversational prose passes through verbatim", rec_prose.get("reply") == "Just restart your router.")

# ---- the EMERGENCY banner speaks the active theme, not medicine ----
# An answer the model rates EMERGENCY opens with its theme's banner
# (ThemeConfig.guardrails.emergency_banner). It used to be hardcoded, so an IRS
# lien, a COBRA deadline, a court date or a foreclosure was answered with "Call
# 911 or go to the nearest emergency room".
from backend.agents.nodes import injection  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402
from backend.agents.themes.base import DEFAULT_GUARDRAIL_COPY  # noqa: E402
from backend.logging.governance_logger import governance_logger  # noqa: E402
from backend.services.clarifying_questions import ClarifyingQuestionsService  # noqa: E402
from backend.services.escalation_rules import EscalationRules  # noqa: E402

MEDICAL_TELLS = ("911", "emergency room")


def medical_tells(text):
    low = (text or "").lower()
    return [t for t in MEDICAL_TELLS if t in low]


def banner_line(banner):
    return f"⚠️ **{banner}** ⚠️\n"


emergency = {
    "assessment": "This needs action today.",
    "guidance": ["Gather the notice you received."],
    "seek_care_if": ["The deadline is within 48 hours."],
    "severity": "EMERGENCY",
    "confidence": 0.9,
}

med_out = content_engine._format_recommendation(emergency, "medadvice")
check("medadvice: EMERGENCY answer keeps its 911 banner verbatim",
      med_out.startswith("⚠️ **EMERGENCY: Call 911 or go to the nearest emergency room immediately.** ⚠️\n"),
      med_out)

for key, cfg in THEMES.items():
    banner = cfg.guardrails.emergency_banner
    check(f"{key}: defines its own emergency banner",
          bool(banner) and banner != DEFAULT_GUARDRAIL_COPY.emergency_banner, repr(banner))
    if cfg.conversational:
        # The reply is the whole answer; nothing is stitched onto it.
        reply = {"reply": "Please hang up and call 911 from any phone.", "severity": "EMERGENCY"}
        out = content_engine._format_recommendation(reply, key)
        check(f"{key}: conversational EMERGENCY reply renders verbatim, no banner",
              out == reply["reply"], out)
        continue
    out = content_engine._format_recommendation(emergency, key)
    check(f"{key}: EMERGENCY answer opens with its own banner", out.startswith(banner_line(banner)), out)
    if key != "medadvice":
        check(f"{key}: EMERGENCY answer carries no 911 / emergency-room copy",
              not medical_tells(out), f"{medical_tells(out)} in {out!r}")

check("a HIGH answer gets no banner (EMERGENCY only)",
      "⚠️" not in content_engine._format_recommendation(dict(emergency, severity="HIGH"), "taxadvice"))
check("an unknown or absent theme falls back to the default theme's banner",
      content_engine._format_recommendation(emergency, "not-a-theme")
      == content_engine._format_recommendation(emergency, None) == med_out)


# The banner is part of the answer the POST chain inspects, so the app's own copy
# must never read as the model's: nothing the label scrubber or placeholder
# realizer rewrites, nothing a presence detector counts (a citation word would
# pair with any year the model wrote and flag a hallucination), and no phone
# number for AI Defense's PII rule to score.
def detector_hits(banner, key):
    hits = []
    if injection.strip_sample_labels(banner) != banner:
        hits.append("label scrubber")
    if injection.realize_pii_placeholders(banner) != banner:
        hits.append("placeholder realizer")
    if injection._contains_pii(banner):
        hits.append("pii")
    if injection._toxic_content_present(banner):
        hits.append("toxic")
    if (injection._PCT_DECIMAL_RE.search(banner) or injection._YEAR_RE.search(banner)
            or injection._CITATION_RE.search(banner)):
        hits.append("hallucination")
    if injection._authority_content_present(banner, key):
        hits.append("authority")
    if re.search(r"\d{3}\D?\d{4}", banner):
        hits.append("phone number")
    return hits


for key, cfg in THEMES.items():
    hits = detector_hits(cfg.guardrails.emergency_banner, key)
    check(f"{key}: emergency banner is inert to the POST-chain detectors", not hits, str(hits))


# ---- the seek_care_if heading speaks the active theme, not medicine ----
# It was hardcoded "Seek Professional Care If", so a budgeting or conveyor-jam
# answer told the user when to seek care. medadvice keeps those exact words (the
# workshop's Healthcare screenshots show them); every other structured theme
# names its own escalation.
med_heading = "**Seek Professional Care If:**"
check("medadvice: the escalation heading is unchanged",
      med_heading in content_engine._format_recommendation(emergency, "medadvice"))
for key, cfg in THEMES.items():
    if cfg.conversational:
        continue
    heading = cfg.guardrails.escalation_heading
    out = content_engine._format_recommendation(dict(emergency, severity="MEDIUM"), key)
    check(f"{key}: the seek_care_if list sits under the theme's own heading",
          f"**{heading}:**\n• The deadline is within 48 hours." in out, out)
    if key != "medadvice":
        check(f"{key}: defines its own escalation heading, with no medical wording",
              heading != DEFAULT_GUARDRAIL_COPY.escalation_heading
              and "care" not in heading.lower() and med_heading not in out, repr(heading))
    hits = detector_hits(heading, key)
    check(f"{key}: escalation heading is inert to the POST-chain detectors", not hits, str(hits))


# Both call sites pass the turn's theme. The legacy fallback engine is driven
# here with a fake AI client and the governance log stubbed, so nothing is
# written; the agentic synthesizer (both blueprint cores) is covered in
# tests/test_multi_agent.py.
class _FakeAIClient:
    def create_message(self, **_kw):
        return SimpleNamespace(content=json.dumps(emergency), id="r", model="fake-model",
                               input_tokens=1, output_tokens=1, stop_reason="end_turn")


legacy = RecommendationEngine.__new__(RecommendationEngine)  # no __init__: no real AI client
legacy._ai_client = _FakeAIClient()
legacy.escalation_rules = EscalationRules()
legacy.clarifying_service = ClarifyingQuestionsService()
_saved_log = {n: getattr(governance_logger, n) for n in ("log_response", "log_escalation")}
try:
    for _n in _saved_log:
        setattr(governance_logger, _n, lambda **_kw: None)
    _lien = "The IRS filed a lien on my house."
    legacy_msg = legacy._generate_recommendation(
        "S-emergency", "R-emergency", "T-emergency", _lien, [{"role": "user", "content": _lien}],
        time.time(), None, theme="taxadvice", force_pii_injection=False,
        force_toxic_injection=False, force_hallucination_injection=False,
        force_boundary_injection=False,
    )["message"]
finally:
    for _n, _fn in _saved_log.items():
        setattr(governance_logger, _n, _fn)
check("legacy engine: a tax EMERGENCY answer opens with the tax banner",
      legacy_msg.startswith(banner_line(THEMES["taxadvice"].guardrails.emergency_banner)), legacy_msg)
check("legacy engine: a tax EMERGENCY answer carries no 911 / emergency-room copy",
      not medical_tells(legacy_msg), legacy_msg)

print(f"RESULT: {'ok' if not _failures else str(len(_failures)) + ' failed'}")
sys.exit(1 if _failures else 0)
