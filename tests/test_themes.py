#!/usr/bin/env python3
"""Every Application Theme is wired end to end.

A theme is a module in backend/agents/themes plus a row in a dozen tables
across the backend and the UI (prompt, Synthetic Content directives, NVIDIA
blueprint data, the header picker, the login brand, ...). A table that misses
a theme does not fail loudly: the turn silently falls back to MedAdvice's copy
or the toggle reports nothing delivered. This suite walks the registry and
checks each table has its row, so adding a theme cannot half-land.

Also pins the chat header: the app title IS the theme picker (no separate
"Application Theme" box), labelled "Application Theme" beside it, with the
Session ID on the subtitle's line under New Session.

Run: venv/bin/python tests/test_themes.py
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["OTEL_ENABLED"] = "false"

from backend.agents.blueprints import data as bp_data  # noqa: E402
from backend.agents.nodes import injection as inj  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402
from backend.agents.themes.base import DEFAULT_GUARDRAIL_COPY  # noqa: E402
from backend.services.recommendation_engine import RecommendationEngine as RE  # noqa: E402
from backend.services.scheduling import DEFAULT_PROFILE  # noqa: E402

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


KEYS = list(THEMES)
FRONTEND = ROOT / "frontend"
INDEX = (FRONTEND / "index.html").read_text()
CHAT_JS = (FRONTEND / "js" / "chat.js").read_text()


def _block(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


def _keys(block: str, pattern: str) -> list:
    return re.findall(pattern, block, re.M)


# ------------------------------------------------------------------- backend
check("the two newest themes are registered", {"retail", "manufacturing"} <= set(KEYS), str(KEYS))
for key, cfg in THEMES.items():
    check(f"{key}: has its own system prompt", key in RE.THEME_PROMPTS
          and cfg.system_prompt == RE.THEME_PROMPTS[key])
    check(f"{key}: has at least three specialists", len(cfg.specialists) >= 3)
    check(f"{key}: has its own scheduling vertical", cfg.scheduling is not DEFAULT_PROFILE)
    check(f"{key}: has its own guardrail copy", cfg.guardrails is not DEFAULT_GUARDRAIL_COPY)
    check(f"{key}: legacy context keywords", key in RE.THEME_CONTEXT_KEYWORDS)
    # Conversational <=> renders "reply" <=> every directive targets "reply".
    reply = inj._ANSWER_FIELD.get(key) == "reply"
    check(f"{key}: conversational flag matches its answer field", cfg.conversational is reply)
    check(f"{key}: prompt contract matches its answer field",
          ('"reply":' in cfg.system_prompt) is reply and ('"guidance":' in cfg.system_prompt) is not reply)

    # Synthetic Content: every category has this theme's own wording.
    check(f"{key}: own PII record line", key in inj._IDENTITY_RECORDS)
    check(f"{key}: own hallucination kinds", key in inj._HALLUCINATION_DIRECTIVES)
    authority = key == "medadvice" or key in inj._COMMITMENTS or key in inj._AUTHORITY_DIRECTIVES
    check(f"{key}: own outside-of-authority directive", authority)
    detected = key == "medadvice" or key in inj._COMMITMENTS or key in inj._ILLICIT_RES
    check(f"{key}: own outside-of-authority detector", detected)
    # The relaxations are string replacements: a drifted prompt line is a silent no-op.
    for old, _new in inj._SCOPE_RULE_RELAXATIONS.get(key, ()):
        check(f"{key}: scope relaxation hits the live prompt ({old[:28]}…)", old in cfg.system_prompt)
    if reply:
        rule = inj._NO_FABRICATION_RELAXATIONS.get(key, ("",))[0]
        check(f"{key}: no-fabrication rule is relaxed for the hallucination toggle",
              bool(rule) and rule in cfg.system_prompt)
    check(f"{key}: hallucination requirement lands in the contract",
          inj.embed_hallucination_contract(cfg.system_prompt, key) != cfg.system_prompt)

    # NVIDIA AI Virtual Assistant blueprint: its tools read per-theme synthetic data.
    check(f"{key}: blueprint records", bool(bp_data.records_for(key)))
    check(f"{key}: blueprint knowledge docs", bool(bp_data.docs_for(key)))

# The labels the drawer shows for the fourth Synthetic Content toggle are what the
# directives solicit.
check("retail: Unauthorized Refund solicits a refund, a discount and a warranty",
      all(k in inj.authority_directive("retail") for k in ("$189.99 refund", "30% discount", "warranty")))
check("manufacturing: Safety Override solicits the clearance, not repair steps",
      all(k in inj.authority_directive("manufacturing")
          for k in ("interlock bypassed", "lockout/tagout", "failed final inspection", "sign-off authority")))
for key in ("retail", "manufacturing"):
    check(f"{key}: the rules that forbid its overreach are lifted when it is requested",
          len(inj._SCOPE_RULE_RELAXATIONS.get(key, ())) == 3)

# ------------------------------------------------------------------- frontend
js_themes = _block(CHAT_JS, "const THEMES = {", "\n};")
js_keys = _keys(js_themes, r"^    (\w+): \{")
check("chat.js THEMES lists every registered theme, in order", js_keys == KEYS, str(js_keys))
for key, cfg in THEMES.items():
    entry = js_themes[js_themes.index(f"    {key}: {{"):]
    entry = entry[:entry.index("\n    }")]
    check(f"chat.js {key}: label matches the backend", f"label: '{cfg.label}'," in entry)
    check(f"chat.js {key}: names its outside-of-authority toggle", "boundaryLabel:" in entry)

safe = _block(CHAT_JS, "const SAFE_PROMPTS = {", "\n};")
check("Prompt Library has safe prompts for every theme", _keys(safe, r"^    (\w+): \[") == KEYS)

picker = _block(INDEX, '<select id="themeSelect"', "</select>")
options = re.findall(r'<option value="(\w+)">([^<]+)</option>', picker)
check("header picker offers every registered theme, in order", [k for k, _ in options] == KEYS,
      str(options))
for key, text in options:
    app_title = re.search(r"appTitle: '([^']+)'", js_themes[js_themes.index(f"    {key}: {{"):]).group(1)
    check(f"header picker: {key} reads as its app title", text == app_title, f"{text!r} vs {app_title!r}")

for page, pattern in (("login.html", r"^      (\w+):\s+\["), ("settings-login.html", r"^      (\w+):\s+'")):
    brand = _block((FRONTEND / page).read_text(), "const BRAND = {", "};")
    check(f"{page} brands every theme", _keys(brand, pattern) == KEYS, str(_keys(brand, pattern)))
labels = _block((FRONTEND / "js" / "appointments.js").read_text(), "const THEME_LABELS = {", "};")
check("My Appointments labels every theme", sorted(re.findall(r"(\w+): '", labels)) == sorted(KEYS))

# ------------------------------------------------------------------- header layout
header = _block(INDEX, '<div class="container mx-auto p-4">', 'id="emergencyBanner"')
check("no separate Application Theme box above the header", header.count('id="themeSelect"') == 1
      and "Application Theme:</label>" not in INDEX)
check("the app title is the theme picker", re.search(r"<h1[^>]*>\s*<select id=\"themeSelect\"", header) is not None)
check("no static title left for applyTheme to overwrite",
      'id="appTitle"' not in INDEX and "getElementById('appTitle')" not in CHAT_JS)
label_at = header.find('>Application Theme</label>')
check("'Application Theme' labels the picker, right after it",
      label_at > header.index("</h1>") and 'for="themeSelect"' in header[header.index("</h1>"):label_at]
      and "text-xs" in header[header.index("</h1>"):label_at])
row1 = header[:header.index('id="appSubtitle"')]
check("New Session sits on the title row", 'id="newSessionBtn"' in row1)
sub_row = header[header.index('id="appSubtitle"') - 200:header.index('id="sessionId"')]
check("Session ID shares the subtitle's row, under New Session",
      'id="sessionId"' not in row1 and "justify-between" in sub_row and sub_row.count("<div") == 1)
check("chat.js sizes the picker to the chosen name", "function sizeThemeSelect()" in CHAT_JS)

print()
if _fails:
    print(f"FAILED: {_fails} check(s)")
    sys.exit(1)
print("ALL THEME CHECKS PASSED")
