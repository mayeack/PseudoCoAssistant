#!/usr/bin/env python3
"""Regression: the Demo Controls visibility panel and its keep-in-sync rule.

Guards CLAUDE.md "Demo Controls drawer formatting": every card in the chat page's
Demo Controls drawer (frontend/index.html #settingsDrawer) carries
data-control="<key>", the key is registered in backend/settings_store.py
DEMO_CONTROLS with its group, and the Settings page's Demo Controls panel plus
the chat page's per-card visibility (GET/PUT /api/settings/demo-controls,
chat.js applyDemoControlVisibility) are generated from that registry. The suite
fails on any divergence between the markup and the registry, and pins:

  (a) registry <-> markup: same keys, same order, same group, same title, same
      group headers; no duplicates; no card hard-coded hidden;
  (b) the Settings page has the panel and settings.js drives the endpoint;
  (c) the API round-trip (401 without the key; overrides merge; unknown key and
      non-bool are 422; {} is a no-op) against an in-memory store, so a run never
      touches this box's real app_settings row;
  (d) chat.js applies visibility before the disclaimer branch and on the poll,
      leaves NemoClaw polling live and keeps no visibility in localStorage;
  (e) CONTROL_FLAGS maps exactly the request-kind controls onto ChatRequest
      fields, so a hidden card can send null (= server default) for its flag.

Run:  venv/bin/python tests/test_demo_controls.py    # exit 0 = pass
"""
import base64
import html
import re
import sys
from typing import Optional
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from backend import settings_store  # noqa: E402
from backend.config import settings  # noqa: E402
from backend.models.schemas import ChatRequest  # noqa: E402
from test_integration_settings import _TempStore  # noqa: E402  (in-memory store, never the real row)

# Exercise the access gate even if this box has no ACCESS_KEY; no startup pre-warm.
KEY = settings.access_key or "test-access-key"
settings.access_key = KEY
settings.prewarm_llm = False

AUTH = {"Authorization": "Basic " + base64.b64encode(f"x:{KEY}".encode()).decode()}
INDEX = (ROOT / "frontend" / "index.html").read_text()
CHAT_JS = (ROOT / "frontend" / "js" / "chat.js").read_text()
SETTINGS_HTML = (ROOT / "frontend" / "settings.html").read_text()
SETTINGS_JS = (ROOT / "frontend" / "js" / "settings.js").read_text()
DRAWER = INDEX[INDEX.index('id="settingsDrawer"'):INDEX.index('id="drawerToggle"')]
# The card container (CLAUDE.md): the class string is the identity of a card.
CARD = '<div class="bg-gray-50 border border-gray-200 rounded-lg p-3"'
ENDPOINT = "/api/settings/demo-controls"

_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        _fails += 1


def _cards():
    """One record per drawer card, in markup order:
    (group key, group header text, data-control key or None, title, opening-tag attrs)."""
    out = []
    for m in re.finditer(r'<section [^>]*data-group="([^"]+)"[^>]*>(.*?)</section>', DRAWER, re.S):
        group, body = m.group(1), m.group(2)
        header = re.search(r"<h3[^>]*>(.*?)</h3>", body, re.S)
        label = html.unescape(header.group(1).strip()) if header else ""
        for chunk in body.split(CARD)[1:]:
            attrs = chunk[:chunk.index(">")]
            key = re.search(r'data-control="([^"]*)"', attrs)
            title = re.search(r'<span[^>]*class="text-sm font-semibold text-gray-700"[^>]*>(.*?)</span>',
                              chunk, re.S)
            out.append((group, label, key.group(1) if key else None,
                        html.unescape(title.group(1).strip()) if title else "", attrs))
    return out


# ---------------------------------------------------------------------------
def test_registry_matches_markup() -> None:
    reg = settings_store.DEMO_CONTROLS
    cards = _cards()
    keys = [c[2] for c in cards]
    check(f"drawer has one card per registry entry ({len(reg)})", len(cards) == len(reg),
          f"{len(cards)} cards vs {len(reg)} registered")
    check("every drawer card carries data-control", all(keys), str([c[3] for c in cards if not c[2]]))
    check("data-control keys == DEMO_CONTROL_KEYS, in drawer order",
          tuple(keys) == settings_store.DEMO_CONTROL_KEYS,
          f"{keys} vs {list(settings_store.DEMO_CONTROL_KEYS)}")
    check("no duplicate data-control", len(set(keys)) == len(keys))
    check("data-control count == card count (no hook outside a card, none loose)",
          DRAWER.count('data-control="') == DRAWER.count(CARD),
          f"{DRAWER.count('data-control=')} hooks vs {DRAWER.count(CARD)} cards")
    by_key = {c["key"]: c for c in reg}
    bad_group = [(k, g) for g, _, k, _, _ in cards if k in by_key and by_key[k]["group"] != g]
    check("each card sits in the <section data-group> its registry entry names", not bad_group, str(bad_group))
    bad_title = [(k, t) for _, _, k, t, _ in cards if k in by_key and by_key[k]["label"] != t]
    check("each card's title is its registry label", not bad_title, str(bad_title))
    groups = {g["key"]: g["label"] for g in settings_store.DEMO_CONTROL_GROUPS}
    seen = {g: lbl for g, lbl, _, _, _ in cards}
    check("drawer groups == DEMO_CONTROL_GROUPS (keys and header text)", seen == groups, f"{seen} vs {groups}")
    check("registry group order == drawer section order",
          [g["key"] for g in settings_store.DEMO_CONTROL_GROUPS] == list(dict.fromkeys(c[0] for c in cards)))
    hidden = [k for _, _, k, _, attrs in cards if re.search(r"\bhidden\b", attrs)]
    check("no card is hard-coded hidden (hide it from the Settings panel instead)", not hidden, str(hidden))
    kinds = {k: sum(1 for c in reg if c["kind"] == k) for k in settings_store.DEMO_CONTROL_KINDS}
    check("kinds: 9 request / 5 server / 1 display",
          kinds == {"request": 9, "server": 5, "display": 1}, str(kinds))
    check("every registry record has key/label/group/kind",
          all(set(c) == {"key", "label", "group", "kind"} for c in reg))


def test_settings_page_panel() -> None:
    check('settings.html: Demo Controls card toggle (data-toggle="controls")', 'data-toggle="controls"' in SETTINGS_HTML)
    check('settings.html: collapsible body id="section-controls"', 'id="section-controls"' in SETTINGS_HTML)
    check("settings.html: list mount + status line + Save button",
          all(s in SETTINGS_HTML for s in ('id="demoControlsList"', 'id="controlsStatus"',
                                           'onclick="saveDemoControls()"')))
    check("settings.html: the Demo Controls card is the first card after the header",
          SETTINGS_HTML.index('data-toggle="controls"') < SETTINGS_HTML.index('data-toggle="creds"'))
    check("settings.html: the card follows the neutral card format (no accent palette)",
          re.search(r'id="section-controls".*?</div>\s*</div>', SETTINGS_HTML, re.S) is not None
          and not re.search(r'id="section-controls".*?(bg-indigo-50|bg-sky-50|bg-red-50|bg-fuchsia-50)',
                            SETTINGS_HTML[:SETTINGS_HTML.index('data-toggle="creds"')], re.S))
    sections = re.search(r"const SECTIONS = \[(.*?)\]", SETTINGS_JS).group(1)
    check("settings.js: 'controls' registered in SECTIONS (collapse persistence)", "'controls'" in sections)
    check(f"settings.js: GET + PUT {ENDPOINT}", SETTINGS_JS.count(f"'{ENDPOINT}'") >= 2)
    for fn in ("loadDemoControls", "renderDemoControls", "saveDemoControls", "setControlsStatus"):
        check(f"settings.js: {fn}() defined", f"function {fn}(" in SETTINGS_JS)
    boot = SETTINGS_JS[SETTINGS_JS.index("document.addEventListener('DOMContentLoaded'"):]
    check("settings.js: the bootstrap loads the panel", "loadDemoControls()" in boot)
    check("settings.js: an API failure is reported as 'Error: …' in #controlsStatus",
          "setControlsStatus('Error: ' + e.message, false)" in SETTINGS_JS
          and "getElementById('controlsStatus')" in SETTINGS_JS)
    check("settings.js: renders one sub-block per group with the group's label, one checkbox per control",
          "c.group === g.key" in SETTINGS_JS and "${esc(g.label)}" in SETTINGS_JS
          and 'type="checkbox" data-control-key=' in SETTINGS_JS)


def test_chat_js_visibility() -> None:
    check("chat.js: applyDemoControlVisibility() defined", "async function applyDemoControlVisibility()" in CHAT_JS)
    boot = CHAT_JS[CHAT_JS.index("document.addEventListener('DOMContentLoaded'"):]
    boot = boot[:boot.index("\n});")]
    call, branch = boot.find("applyDemoControlVisibility();"), boot.find("if (savedDisclaimerAccepted === 'true')")
    check("chat.js: visibility applied at load, BEFORE the disclaimer branch",
          0 <= call < branch, f"call at {call}, branch at {branch}")
    ri = re.search(r"function refreshIndicators\(\) \{(.*?)\n\}", CHAT_JS, re.S).group(1)
    check("chat.js: refreshIndicators() re-applies visibility (the 10 s poll)", "applyDemoControlVisibility();" in ri)
    check(f"chat.js: reads GET {ENDPOINT}", f"fetch('{ENDPOINT}')" in CHAT_JS)
    body = re.search(r"async function applyDemoControlVisibility\(\) \{(.*?)\n\}", CHAT_JS, re.S).group(1)
    check("chat.js: toggles the hidden attribute on [data-control] cards",
          "querySelectorAll('[data-control]')" in body and ".hidden =" in body)
    check("chat.js: hides a section[data-group] with no visible card",
          "querySelectorAll('section[data-group]')" in body and ":not([hidden])" in body)
    check("chat.js: a fetch failure is swallowed (the drawer keeps its state)", "catch (e)" in body)
    live = [ln for ln in CHAT_JS.splitlines()
            if "startNemoClawPolling();" in ln and not ln.strip().startswith("//")]
    check("chat.js: startNemoClawPolling(); is live (not commented out)", len(live) >= 1)
    check("chat.js: visibility is never kept in localStorage",
          re.search(r"localStorage\.[gs]etItem\([^)]*(visib|hidden|demo_control)", CHAT_JS, re.I) is None)
    check("chat.js: buildChatPayload sends null for the flag of a hidden card",
          "_hiddenControls.has(key)) payload[flag] = null" in CHAT_JS)


def test_control_flags_match_registry() -> None:
    m = re.search(r"const CONTROL_FLAGS = \{(.*?)\};", CHAT_JS, re.S)
    check("chat.js: CONTROL_FLAGS defined", m is not None)
    flags = dict(re.findall(r"(\w+):\s*'(\w+)'", m.group(1))) if m else {}
    request_keys = {c["key"] for c in settings_store.DEMO_CONTROLS if c["kind"] == "request"}
    check("CONTROL_FLAGS keys == request-kind registry keys",
          set(flags) == request_keys, f"{sorted(flags)} vs {sorted(request_keys)}")
    fields = ChatRequest.model_fields
    check("every CONTROL_FLAGS value is a ChatRequest field",
          set(flags.values()) <= set(fields), str(set(flags.values()) - set(fields)))
    check("no two controls share a flag", len(set(flags.values())) == len(flags))
    optional_bools = {f for f, fi in fields.items() if fi.annotation == Optional[bool]}
    check("every Optional[bool] ChatRequest flag is a drawer control (and vice versa)",
          set(flags.values()) == optional_bools, f"{sorted(flags.values())} vs {sorted(optional_bools)}")
    check("the flags default to None — the server default a hidden card falls back to",
          all(fields[f].default is None for f in flags.values()))


def test_api_round_trip() -> None:
    from fastapi.testclient import TestClient
    from backend.main import app

    def vis(resp):
        return {c["key"]: c["visible"] for c in resp.json()["controls"]}

    with _TempStore() as store, TestClient(app) as c:
        check(f"GET {ENDPOINT} -> 401 without the key", c.get(ENDPOINT).status_code == 401)
        check(f"PUT {ENDPOINT} -> 401 without the key", c.put(ENDPOINT, json={"visible": {}}).status_code == 401)
        r = c.get(ENDPOINT, headers=AUTH)
        d = r.json()
        check("GET -> 200 with controls + groups", r.status_code == 200 and set(d) == {"controls", "groups"})
        check("GET: keys in registry order", [x["key"] for x in d["controls"]] == list(settings_store.DEMO_CONTROL_KEYS))
        check("GET: every control carries key/label/group/kind/visible",
              all(set(x) == {"key", "label", "group", "kind", "visible"} for x in d["controls"]))
        check("GET: default = every card visible", all(x["visible"] is True for x in d["controls"]))
        check("GET: groups == DEMO_CONTROL_GROUPS", d["groups"] == settings_store.DEMO_CONTROL_GROUPS)

        r = c.put(ENDPOINT, headers=AUTH, json={"visible": {"nemo_guardrails": False}})
        check("PUT one false -> 200, that card hidden, the others untouched",
              r.status_code == 200 and vis(r)["nemo_guardrails"] is False
              and all(v for k, v in vis(r).items() if k != "nemo_guardrails"), r.text[:160])
        check("GET agrees after the PUT", vis(c.get(ENDPOINT, headers=AUTH))["nemo_guardrails"] is False)
        r = c.put(ENDPOINT, headers=AUTH, json={"visible": {"nemoclaw_guardrails": False}})
        check("a second PUT merges (both hidden)",
              vis(r)["nemo_guardrails"] is False and vis(r)["nemoclaw_guardrails"] is False)
        check("the store holds overrides only",
              store["demo_controls"] == {"nemo_guardrails": False, "nemoclaw_guardrails": False},
              str(store.get("demo_controls")))
        check("the shared default dict is never mutated", settings_store._DEFAULTS["demo_controls"] == {})

        r = c.put(ENDPOINT, headers=AUTH, json={"visible": {"blueprint_picker": False}})
        check("unknown key -> 422 naming it", r.status_code == 422 and "blueprint_picker" in r.text, r.text[:160])
        check("non-bool -> 422", c.put(ENDPOINT, headers=AUTH, json={"visible": {"appearance": "no"}}).status_code == 422)
        check("1/0 are not a visibility -> 422 (StrictBool)",
              c.put(ENDPOINT, headers=AUTH, json={"visible": {"appearance": 1}}).status_code == 422)
        check("a rejected PUT wrote nothing",
              store["demo_controls"] == {"nemo_guardrails": False, "nemoclaw_guardrails": False})
        r = c.put(ENDPOINT, headers=AUTH, json={"visible": {}})
        check("{} is a no-op", r.status_code == 200 and vis(r)["nemo_guardrails"] is False
              and vis(r)["nemoclaw_guardrails"] is False)
        r = c.put(ENDPOINT, headers=AUTH, json={"visible": {"nemo_guardrails": True, "nemoclaw_guardrails": True}})
        check("PUT true restores", r.status_code == 200 and all(vis(r).values()))


def main() -> int:
    global _fails
    for fn in (test_registry_matches_markup, test_settings_page_panel, test_chat_js_visibility,
               test_control_flags_match_registry, test_api_round_trip):
        print(f"[{fn.__name__}]")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            _fails += 1
            print(f"  ERROR {fn.__name__}: {e!r}")
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
