#!/usr/bin/env python3
"""Regression: Agent Control enforcement ("Agent Observability Controls").

Guards the contract of the toggle end to end without touching the network:

  1. no-op safety — no AGENT_CONTROL_API_KEY (or master switch off) means the client is
     unconfigured and the graph node never calls out;
  2. verdict semantics — deny blocks, steer/observe do not, and an errored
     evaluation honors ``galileo_agent_control_fail_open``;
  3. the request payload actually submitted (post stage, llm step, input AND
     output) — a control that scores correctness cannot work without both sides;
  4. the node short-circuits the turn on deny with a governance-logged block, and
     stays transparent otherwise;
  5. the wiring: the flag reaches the graph, the node sits between compliance and
     response_defense, and the frontend toggle is present.

    venv/bin/python tests/test_agent_control.py    # exit 0 = pass
"""
import json
import os
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_fails = 0


def check(name: str, cond: bool) -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        _fails += 1


class _FakeResponse:
    """Minimal httpx.Response stand-in.

    ``raise_for_status`` raises like the real thing for 4xx/5xx, so a test can
    reproduce the actual failure this deployment sees (``/evaluation`` answering
    401 when no runtime token could be minted) instead of a lenient 200.
    """

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=None, response=self
            )
        return None

    def json(self):
        return self._payload


os.environ.pop("GALILEO_API_KEY", None)
os.environ.pop("AGENT_CONTROL_API_KEY", None)

from backend.config import settings  # noqa: E402
from backend.services import agent_control as ac  # noqa: E402

# backend.config loads .env at import, which may repopulate AGENT_CONTROL_API_KEY —
# drop it again so the no-op guarantee is tested against a truly absent key.
os.environ.pop("GALILEO_API_KEY", None)
os.environ.pop("AGENT_CONTROL_API_KEY", None)

# ---- 1. no-op safety guarantee -------------------------------------------
print("\n[1] no-op safety")
client = ac.AgentControlClient()
check("unconfigured when AGENT_CONTROL_API_KEY unset", client.is_configured is False)

os.environ["AGENT_CONTROL_API_KEY"] = "test-key-unused"
check("configured when AGENT_CONTROL_API_KEY set", client.is_configured is True)

# The former GALILEO_API_KEY still configures the client (deprecated fallback,
# one warning per process) — trace logging moved to SPLUNK_AO_* and no longer
# shares this credential.
with mock.patch.dict(os.environ, {"GALILEO_API_KEY": "legacy-key"}):
    os.environ.pop("AGENT_CONTROL_API_KEY", None)
    ac._legacy_env_warned = False
    check("legacy GALILEO_API_KEY still configures the client (deprecated fallback)",
          ac.AgentControlClient().is_configured is True)
    check("deprecated-name warning fires on the fallback", ac._legacy_env_warned is True)

with mock.patch.object(settings, "galileo_agent_control_enabled", False):
    check(
        "master switch off wins over a present API key",
        ac.AgentControlClient().is_configured is False,
    )

try:
    with mock.patch.object(settings, "galileo_agent_control_enabled", False):
        ac.AgentControlClient().evaluate_response("q", "a")
    check("evaluate_response raises when unconfigured", False)
except ac.AgentControlError:
    check("evaluate_response raises when unconfigured", True)

# console API base is derived from the console URL, not hardcoded
with mock.patch.dict(
    os.environ, {"AGENT_CONTROL_CONSOLE_URL": "https://console.multitenant.galileocloud.io"}
):
    check(
        "console API url derived from AGENT_CONTROL_CONSOLE_URL",
        ac.AgentControlClient().console_api_url
        == "https://api.multitenant.galileocloud.io",
    )
with mock.patch.dict(os.environ, {"AGENT_CONTROL_CONSOLE_URL": "", "GALILEO_CONSOLE_URL": ""}):
    check(
        "console API url defaults to the hosted API",
        ac.AgentControlClient().console_api_url == "https://api.galileo.ai",
    )
# The splunk-ao SDK injects GALILEO_CONSOLE_URL=<O11y app host> into the process
# env on its first session call; with AGENT_CONTROL_API_KEY set that must be
# ignored, while the legacy pair (GALILEO_API_KEY + GALILEO_CONSOLE_URL) is honored.
with mock.patch.dict(os.environ, {
    "AGENT_CONTROL_CONSOLE_URL": "", "AGENT_CONTROL_API_KEY": "k",
    "GALILEO_CONSOLE_URL": "https://app.us1.observability.splunkcloud.com/",
}):
    check(
        "a bridged GALILEO_CONSOLE_URL is ignored when AGENT_CONTROL_API_KEY is set",
        ac.AgentControlClient().console_api_url == "https://api.galileo.ai",
    )
with mock.patch.dict(os.environ, {
    "AGENT_CONTROL_CONSOLE_URL": "", "GALILEO_API_KEY": "legacy",
    "GALILEO_CONSOLE_URL": "https://console.multitenant.galileocloud.io",
}):
    os.environ.pop("AGENT_CONTROL_API_KEY", None)
    check(
        "the legacy pair honors GALILEO_CONSOLE_URL",
        ac.AgentControlClient().console_api_url == "https://api.multitenant.galileocloud.io",
    )

# ---- 2. verdict semantics ------------------------------------------------
print("\n[2] verdict semantics")
check(
    "deny blocks",
    ac.ControlVerdict(is_safe=False, decisions=["deny"]).should_block is True,
)
check(
    "steer does not block (the response node rewrites instead, see [10])",
    ac.ControlVerdict(is_safe=False, decisions=["steer"]).should_block is False,
)
check(
    "observe does not block",
    ac.ControlVerdict(is_safe=False, decisions=["observe"]).should_block is False,
)
check("clean verdict does not block", ac.ControlVerdict().should_block is False)
check(
    "deny alongside observe still blocks",
    ac.ControlVerdict(decisions=["observe", "deny"]).should_block is True,
)

errored = ac.ControlVerdict(errored=True, error_message="boom")
with mock.patch.object(settings, "galileo_agent_control_fail_open", True):
    check("errored + fail-open releases the response", errored.should_block is False)
with mock.patch.object(settings, "galileo_agent_control_fail_open", False):
    check("errored + fail-closed withholds the response", errored.should_block is True)

parsed = ac.AgentControlClient._parse_response(
    {
        "is_safe": False,
        "confidence": 0.91,
        "reason": "control matched",
        "matches": [
            {
                "control_name": "PseudoCoAssistant-block-hallucinated-output",
                "action": "deny",
                "result": {"matched": True, "confidence": 0.91, "message": "score 0.2 < 0.5"},
            }
        ],
        "errors": [{"control_name": "some-broken-control"}],
    }
)
check("parses matched control name", parsed.matched_controls == ["PseudoCoAssistant-block-hallucinated-output"])
check("parses decision", parsed.decisions == ["deny"])
check("parses evaluator message", parsed.messages == ["score 0.2 < 0.5"])
check("parses evaluator errors", parsed.evaluator_errors == ["some-broken-control"])
check("parsed deny blocks", parsed.should_block is True)
check("a deny carries no steering", parsed.steering == [])
steer_parsed = ac.AgentControlClient._parse_response(
    {
        "is_safe": False,
        "confidence": 1.0,
        "matches": [
            {"control_name": "steer-remove-output-pii-regex", "action": "steer",
             "result": {"matched": True, "message": "Condition tree matched"},
             "steering_context": {"message": "Remove all personal data from the output."}},
            # Guidance on a non-steer match is not steering.
            {"control_name": "watch-it", "action": "observe",
             "steering_context": {"message": "ignored"}},
        ],
    }
)
check("parses a steer match's steering_context message",
      steer_parsed.steering == ["Remove all personal data from the output."]
      and steer_parsed.steered and steer_parsed.should_block is False)
check("the verdict record carries the steering guidance (and no outcome yet)",
      steer_parsed.record()["steering"] == ["Remove all personal data from the output."]
      and steer_parsed.record()["steer"] is None)
check(
    "a body without is_safe is treated as an error, not as safe",
    ac.AgentControlClient._parse_response({"confidence": 1.0}).errored is True,
)

# ---- 3. submitted payload ------------------------------------------------
print("\n[3] submitted evaluation payload")
posted = {}


def _fake_post(url, **kwargs):
    posted[url] = kwargs
    if url.endswith("/v2/login/api_key"):
        return _FakeResponse({"access_token": "header.eyJleHAiOjk5OTk5OTk5OTl9.sig"})
    if url.endswith("/runtime-token-exchange"):
        return _FakeResponse(
            {"token": "rt.eyJleHAiOjk5OTk5OTk5OTl9.sig", "expires_at": "2099-01-01T00:00:00Z"}
        )
    return _FakeResponse({"is_safe": True, "confidence": 0.0, "matches": []})


with mock.patch.object(ac.httpx, "post", side_effect=_fake_post):
    verdict = ac.AgentControlClient().evaluate_response(
        "How much Tylenol is safe?",
        "Up to 12,000 mg per day.",
        session_id="s-1",
        theme="medadvice",
        model="mistral-nemo:12b",
        enduser_id="user-7",
    )

eval_url = next((u for u in posted if u.endswith("/api/v1/evaluation")), None)
check("evaluation endpoint called", eval_url is not None)
body = posted.get(eval_url, {}).get("json", {}) if eval_url else {}
step = body.get("step", {})
check("agent_name is the configured agent", body.get("agent_name") == settings.galileo_agent_control_agent_name)
check("stage is post (the response is what gets judged)", body.get("stage") == "post")
check("step type is llm", step.get("type") == "llm")
check("step carries the user prompt as input", step.get("input") == "How much Tylenol is safe?")
check("step carries the generated answer as output", step.get("output") == "Up to 12,000 mg per day.")
check("context carries session/theme/model for triage",
      (step.get("context") or {}).get("session_id") == "s-1"
      and (step.get("context") or {}).get("theme") == "medadvice"
      and (step.get("context") or {}).get("model") == "mistral-nemo:12b")
check("clean verdict released", verdict.should_block is False)

auth = posted.get(eval_url, {}).get("headers", {}).get("Authorization", "")
check("evaluation presents the minted runtime token as Bearer", auth == "Bearer rt.eyJleHAiOjk5OTk5OTk5OTl9.sig")


# An unavailable runtime-token exchange must fall back to console-token auth
# (the SDK's "auto" mode) instead of failing the turn.
def _fake_post_no_runtime(url, **kwargs):
    if url.endswith("/v2/login/api_key"):
        return _FakeResponse({"access_token": "at.eyJleHAiOjk5OTk5OTk5OTl9.sig"})
    if url.endswith("/runtime-token-exchange"):
        raise ac.httpx.ConnectError("no runtime grant")
    posted["fallback"] = kwargs
    return _FakeResponse({"is_safe": True, "confidence": 0.0})


with mock.patch.object(ac.httpx, "post", side_effect=_fake_post_no_runtime):
    fallback_verdict = ac.AgentControlClient().evaluate_response("q", "a")
check("runtime-token exchange failure does not raise", fallback_verdict.errored is False)
check(
    "falls back to console-token auth when no runtime token can be minted",
    posted.get("fallback", {}).get("headers", {}).get("Authorization")
    == "Bearer at.eyJleHAiOjk5OTk5OTk5OTl9.sig",
)

# A dead server must not raise into the turn — it must produce an errored verdict.
with mock.patch.object(ac.httpx, "post", side_effect=ac.httpx.ConnectError("down")):
    dead = ac.AgentControlClient().evaluate_response("q", "a")
check("unreachable server yields an errored verdict, never an exception", dead.errored is True)

# ---- 4. graph node behavior ---------------------------------------------
print("\n[4] graph node")
from backend.agents.nodes import agent_control as node_mod  # noqa: E402

base_state = {
    "session_id": "s-1",
    "request_id": "r-1",
    "trace_id": "t-1",
    "start_time": 0.0,
    "user_message": "q",
    "final_message": "a",
    "messages": [{"role": "user", "content": "q"}],
    "llm_model": "mistral-nemo:12b",
    "llm_input_tokens": 11,
    "llm_output_tokens": 22,
}

check(
    "node is a no-op when the request did not opt in",
    node_mod.agent_control_node(dict(base_state)) == {},
)

with mock.patch.object(
    ac.AgentControlClient, "is_configured", new_callable=mock.PropertyMock
) as configured:
    configured.return_value = False
    check(
        "node is a no-op when the client is unconfigured, even if opted in",
        node_mod.agent_control_node(dict(base_state, agent_control_review=True)) == {},
    )

deny_verdict = ac.ControlVerdict(
    is_safe=False,
    confidence=0.9,
    decisions=["deny"],
    matched_controls=["PseudoCoAssistant-block-hallucinated-output"],
    messages=["correctness 0.2 < 0.5"],
)
with mock.patch.object(
    ac.AgentControlClient, "is_configured", new_callable=mock.PropertyMock
) as configured, mock.patch.object(
    node_mod.agent_control_client, "evaluate_response", return_value=deny_verdict
), mock.patch.object(
    node_mod.content_engine, "_handle_agent_control_block"
) as handler:
    configured.return_value = True
    handler.return_value = {"message": "withheld", "policy_blocked": True}
    out = node_mod.agent_control_node(dict(base_state, agent_control_review=True))

check("deny short-circuits the turn", out.get("terminal") is True)
check("deny returns the block result", out.get("result", {}).get("policy_blocked") is True)
check("deny records the verdict on state", out.get("agent_control") is deny_verdict)
check("deny records stage timing", "agent_control_ms" in (out.get("stage_timings") or {}))
handler_kwargs = handler.call_args.kwargs
check(
    "block handler gets the real model + token spend (not zeros)",
    handler_kwargs.get("llm_model") == "mistral-nemo:12b"
    and handler_kwargs["usage_data"]["usage_total_tokens"] == 33,
)

allow_verdict = ac.ControlVerdict(is_safe=True, decisions=["observe"], matched_controls=["watch-me"])
with mock.patch.object(
    ac.AgentControlClient, "is_configured", new_callable=mock.PropertyMock
) as configured, mock.patch.object(
    node_mod.agent_control_client, "evaluate_response", return_value=allow_verdict
):
    configured.return_value = True
    allowed = node_mod.agent_control_node(dict(base_state, agent_control_review=True))
check("non-blocking verdict does not terminate the turn", allowed.get("terminal") is None)
check("non-blocking verdict still reaches governance via state", allowed.get("agent_control") is allow_verdict)

# ---- 5. ported Luna comparison semantics --------------------------------
# These pin the bug that made control 259 unable to ever fire: the `correctness`
# scorer emits a BOOLEAN, and a numeric operator over a bool raises inside the
# evaluator (reported as an evaluator error -> fail open). Do not "simplify"
# coerce_number to treat bools as 0/1 — that silently changes every control's
# verdict and diverges from what the server would decide.
print("\n[5] Luna comparison semantics (ported verbatim)")
check("eq/false matches a false score (control 259 as repaired)",
      ac.score_matches(False, "eq", False) is True)
check("eq/false does not match a true score", ac.score_matches(True, "eq", False) is False)
try:
    ac.score_matches(False, "lt", 0.5)
    check("lt over a boolean score raises (the original 259 defect)", False)
except ValueError:
    check("lt over a boolean score raises (the original 259 defect)", True)
check("any is INVERTED for correctness (fires on a correct answer)",
      ac.score_matches(True, "any", None) is True
      and ac.score_matches(False, "any", None) is False)
check("numeric lt still works for float scorers",
      ac.score_matches(0.2, "lt", 0.5) is True and ac.score_matches(0.8, "lt", 0.5) is False)
check("string scores coerce numerically", ac.score_matches("0.2", "lt", 0.5) is True)
check("ne compares directly", ac.score_matches(True, "ne", False) is True)
check("contains over a list score (the PII SLM shape)",
      ac.score_matches(["ssn", "phone_number"], "contains", "ssn") is True
      and ac.score_matches([], "contains", "ssn") is False)
check("coerce_number returns None for bool/None",
      ac.coerce_number(True) is None and ac.coerce_number(None) is None)
try:
    ac.score_matches(0.2, "wat", 0.5)
    check("an unsupported operator raises", False)
except ValueError:
    check("an unsupported operator raises", True)

# A deny control whose evaluator errored comes back under `errors`, not
# `matches`, while the engine still flips is_safe to False. Reading only
# `matches` took that as a clean pass — neither blocking nor honoring fail-open.
errored_deny = ac.AgentControlClient._parse_response(
    {
        "is_safe": False,
        "confidence": 0.0,
        "matches": [],
        "errors": [
            {
                "control_name": "PseudoCoAssistant-block-hallucinated-output",
                "action": "deny",
                "result": {"matched": False, "confidence": 0.0, "error": "not numeric"},
            }
        ],
    }
)
check("is_safe=false with only errors is an ERROR, not a clean pass",
      errored_deny.errored is True)
check("the errored deny control is named in the message",
      "PseudoCoAssistant-block-hallucinated-output" in (errored_deny.error_message or ""))
with mock.patch.object(settings, "galileo_agent_control_fail_open", False):
    check("errored deny withholds under fail-closed", errored_deny.should_block is True)
with mock.patch.object(settings, "galileo_agent_control_fail_open", True):
    check("errored deny releases under fail-open", errored_deny.should_block is False)

# ---- 6. client-side execution -------------------------------------------
print("\n[6] client-side execution")

# The live shape of GET /agents/{name}/controls: definition under "control".
CONTROLS_BODY = {
    "controls": [
        {
            "id": 259,
            "name": "PseudoCoAssistant-block-hallucinated-output",
            "control": {
                "enabled": True,
                "execution": "server",
                "scope": {"step_types": ["llm"], "stages": ["post"]},
                "action": {"decision": "deny"},
                "condition": {
                    "selector": {"path": "*"},
                    "evaluator": {
                        "name": "galileo.luna",
                        "config": {
                            "scorer_label": "correctness",
                            "scorer_id": "89d579ce",
                            "operator": "eq",
                            "threshold": False,
                            "timeout_ms": 15000,
                        },
                    },
                },
            },
        }
    ]
}


def _client_transport(score_body, *, controls=None, runtime=False, calls=None):
    """Build (post, get) fakes for a client-side evaluation.

    runtime=False reproduces today's deployment: the exchange 502s, so the
    server path cannot produce a verdict and the client path takes over.
    """
    calls = calls if calls is not None else []

    def _post(url, **kwargs):
        calls.append(url)
        if url.endswith("/v2/login/api_key"):
            return _FakeResponse({"access_token": "at.eyJleHAiOjk5OTk5OTk5OTl9.sig"})
        if url.endswith("/runtime-token-exchange"):
            if runtime:
                return _FakeResponse({"token": "rt.eyJleHAiOjk5OTk5OTk5OTl9.sig"})
            raise ac.httpx.ConnectError("no runtime grant")
        if url.endswith("/api/v1/evaluation"):
            if not runtime:
                # What the live deployment actually answers when the console
                # token is presented in place of a runtime token.
                return _FakeResponse(
                    {"detail": 'Runtime token is invalid: Token is missing the "iat" claim'},
                    status_code=401,
                )
            return _FakeResponse({"is_safe": True, "confidence": 0.0, "matches": []})
        if url.endswith("/scorers/invoke"):
            _post.invoke_body = kwargs.get("json")
            return _FakeResponse(score_body)
        raise AssertionError(f"unexpected POST {url}")

    def _get(url, **kwargs):
        calls.append(url)
        return _FakeResponse(CONTROLS_BODY if controls is None else controls)

    _post.invoke_body = None
    return _post, _get, calls


def _evaluate(score_body, *, controls=None, runtime=False, execution="auto"):
    post, get, calls = _client_transport(score_body, controls=controls, runtime=runtime)
    client = ac.AgentControlClient()
    with mock.patch.object(ac.httpx, "post", side_effect=post), mock.patch.object(
        ac.httpx, "get", side_effect=get
    ), mock.patch.object(settings, "galileo_agent_control_execution", execution):
        verdict = client.evaluate_response("How much Tylenol is safe?", "12,000 mg a day.")
    return verdict, post, calls, client


# correctness=false -> incorrect -> the deny control matches
deny, post, calls, _ = _evaluate({"score": False, "status": "success"})
check("falls back to client-side when no runtime token can be minted",
      deny.transport == "client")
check("a false correctness score denies", deny.should_block is True)
check("the matched control is named", deny.matched_controls == ["PseudoCoAssistant-block-hallucinated-output"])
check("decision is deny", deny.decisions == ["deny"])
check("scorer invoked with query + response as plain strings",
      (post.invoke_body or {}).get("inputs")
      == {"query": "How much Tylenol is safe?", "response": "12,000 mg a day."})
check("scorer id/label forwarded from the control definition",
      (post.invoke_body or {}).get("scorer_id") == "89d579ce"
      and (post.invoke_body or {}).get("scorer_label") == "correctness")

allow, _, _, _ = _evaluate({"score": True, "status": "success"})
check("a true correctness score releases", allow.should_block is False)
check("released client verdict is not errored", allow.errored is False)

# Today's real behavior: the LLM-judge scorers fail server-side.
broken, _, _, _ = _evaluate(
    {
        "score": None,
        "status": "failed",
        "error_message": "'str' object has no attribute 'format_content_for_message'",
    }
)
check("a failed scorer invoke is an evaluator error, never a match",
      broken.errored is True and broken.matched_controls == [])
check("the scorer's own error text is preserved",
      "format_content_for_message" in (broken.error_message or ""))
with mock.patch.object(settings, "galileo_agent_control_fail_open", True):
    check("failed scorer releases under fail-open (today's path)", broken.should_block is False)
with mock.patch.object(settings, "galileo_agent_control_fail_open", False):
    check("failed scorer withholds under fail-closed", broken.should_block is True)

# The server path stays preferred when a runtime token IS mintable.
server_verdict, post_srv, calls_srv, _ = _evaluate(
    {"score": False, "status": "success"}, runtime=True
)
check("runtime token available -> server transport", server_verdict.transport == "server")
check("server path does not invoke scorers locally",
      not any(u.endswith("/scorers/invoke") for u in calls_srv))
check("execution=server never falls back",
      _evaluate({"score": False, "status": "success"}, execution="server")[0].transport
      == "server")
check("execution=client skips the server entirely",
      not any(
          u.endswith("/api/v1/evaluation")
          for u in _evaluate({"score": True, "status": "success"}, execution="client")[2]
      ))

# Scope / enabled / evaluator filtering — none of these may invoke a scorer.
def _only(definition_overrides):
    body = json.loads(json.dumps(CONTROLS_BODY))
    body["controls"][0]["control"].update(definition_overrides)
    return body


for label, override in [
    ("stage pre is skipped", {"scope": {"stages": ["pre"], "step_types": ["llm"]}}),
    ("step_type tool is skipped", {"scope": {"stages": ["post"], "step_types": ["tool"]}}),
    ("disabled control is skipped", {"enabled": False}),
]:
    verdict, post_f, calls_f, _ = _evaluate(
        {"score": False, "status": "success"}, controls=_only(override)
    )
    check(f"{label} (no scorer call, no block)",
          not any(u.endswith("/scorers/invoke") for u in calls_f)
          and verdict.should_block is False)

steer_c, _, _, _ = _evaluate(
    {"score": False, "status": "success"},
    controls=_only({"action": {"decision": "steer",
                               "steering_context": {"message": "Correct the dose."}}}),
)
check("client-side: a matched steer control carries its steering_context message",
      steer_c.decisions == ["steer"] and steer_c.steering == ["Correct the dose."])

unsupported = _only(
    {"condition": {"selector": {"path": "*"}, "evaluator": {"name": "regex", "config": {}}}}
)
verdict_u, _, calls_u, _ = _evaluate({"score": False, "status": "success"}, controls=unsupported)
check("a non-Luna evaluator is reported unevaluated, not guessed at",
      not any(u.endswith("/scorers/invoke") for u in calls_u)
      and verdict_u.errored is True
      and any("regex" in e for e in verdict_u.evaluator_errors))

# Definition caching: one fetch serves many turns.
post_c, get_c, calls_c = _client_transport({"score": True, "status": "success"})
client_c = ac.AgentControlClient()
with mock.patch.object(ac.httpx, "post", side_effect=post_c), mock.patch.object(
    ac.httpx, "get", side_effect=get_c
), mock.patch.object(settings, "galileo_agent_control_execution", "client"):
    for _ in range(3):
        client_c.evaluate_response("q", "a")
fetches = [u for u in calls_c if u.endswith("/controls")]
check("control definitions are fetched once across turns (TTL cache)", len(fetches) == 1)
check("invoke still runs per turn",
      len([u for u in calls_c if u.endswith("/scorers/invoke")]) == 3)

# A refresh failure serves the stale set rather than failing the turn.
fail_get = mock.Mock(side_effect=ac.httpx.ConnectError("management api down"))
with mock.patch.object(ac.httpx, "post", side_effect=post_c), mock.patch.object(
    ac.httpx, "get", fail_get
), mock.patch.object(settings, "galileo_agent_control_execution", "client"), mock.patch.object(
    settings, "galileo_agent_control_refresh_seconds", 0.0
):
    stale = client_c.evaluate_response("q", "a")
check("a definition-refresh failure reuses the cached set", stale.errored is False)

# Cold cache + fetch failure = errored verdict (fail-open decides).
post_e, _, _ = _client_transport({"score": True, "status": "success"})
client_e = ac.AgentControlClient()
with mock.patch.object(ac.httpx, "post", side_effect=post_e), mock.patch.object(
    ac.httpx, "get", mock.Mock(side_effect=ac.httpx.ConnectError("down"))
), mock.patch.object(settings, "galileo_agent_control_execution", "client"):
    cold = client_e.evaluate_response("q", "a")
check("cold cache + unreachable management API -> errored verdict", cold.errored is True)
with mock.patch.object(settings, "galileo_agent_control_fail_open", True):
    check("...which fail-open releases", cold.should_block is False)

# ---- 6b. composite conditions + the per-evaluation scorer memo ----------
# The output-PII control ORs one `contains` leaf per category, because the
# Output PII (SLM) scorer returns a LIST (["ssn","name",…]) and `contains` takes a
# single category. Without a memo that shape costs one judge call per leaf.
print("\n[6b] composite conditions + scorer memo")

PII_CATS = ["ssn", "date_of_birth", "email", "phone_number"]
PII_CONTROLS = {
    "controls": [
        {
            "id": 263,
            "name": "PseudoCoAssistant-block-output-pii",
            "control": {
                "enabled": True,
                "execution": "server",
                "scope": {"step_types": ["llm"], "stages": ["post"]},
                "action": {"decision": "deny"},
                "condition": {
                    "or": [
                        {
                            "selector": {"path": "*"},
                            "evaluator": {
                                "name": "galileo.luna",
                                "config": {
                                    "scorer_label": "Output PII (SLM)",
                                    "scorer_id": "88eada48",
                                    "operator": "contains",
                                    "threshold": cat,
                                },
                            },
                        }
                        for cat in PII_CATS
                    ]
                },
            },
        }
    ]
}

# A response the scorer flags with a category NOT in the first leaf, to prove the
# OR keeps walking rather than stopping at the first non-match.
pii_hit, post_pii, calls_pii, _ = _evaluate(
    {"score": ["name", "phone_number"], "status": "success"}, controls=PII_CONTROLS
)
check("an OR of contains leaves denies on a later category",
      pii_hit.should_block is True and pii_hit.matched_controls == ["PseudoCoAssistant-block-output-pii"])
check("the deciding category is reported in the message",
      "phone_number" in " ".join(pii_hit.messages))
check("OR over one scorer costs ONE invoke, not one per leaf (memo)",
      len([u for u in calls_pii if u.endswith("/scorers/invoke")]) == 1)

# `name` alone must not trigger: a normal PseudoCo Assistant answer naming a care provider
# scores ["name"], so including that category would withhold good responses.
pii_name_only, _, calls_name, _ = _evaluate(
    {"score": ["name"], "status": "success"}, controls=PII_CONTROLS
)
check("a bare name does not trigger the PII control (no over-blocking)",
      pii_name_only.should_block is False)
check("a clean scorer result releases",
      _evaluate({"score": [], "status": "success"}, controls=PII_CONTROLS)[0].should_block
      is False)

# AND short-circuits, NOT inverts.
def _tree(node):
    body = json.loads(json.dumps(PII_CONTROLS))
    body["controls"][0]["control"]["condition"] = node
    return body


LEAF_HIT = {
    "selector": {"path": "*"},
    "evaluator": {
        "name": "galileo.luna",
        "config": {"scorer_id": "88eada48", "operator": "contains", "threshold": "ssn"},
    },
}
LEAF_MISS = {
    "selector": {"path": "*"},
    "evaluator": {
        "name": "galileo.luna",
        "config": {"scorer_id": "88eada48", "operator": "contains", "threshold": "password"},
    },
}
check("AND of hit+miss does not match",
      _evaluate({"score": ["ssn"], "status": "success"},
                controls=_tree({"and": [LEAF_HIT, LEAF_MISS]}))[0].should_block is False)
check("AND of hit+hit matches",
      _evaluate({"score": ["ssn"], "status": "success"},
                controls=_tree({"and": [LEAF_HIT, LEAF_HIT]}))[0].should_block is True)
check("NOT inverts a leaf",
      _evaluate({"score": ["ssn"], "status": "success"},
                controls=_tree({"not": LEAF_HIT}))[0].should_block is False)

# A failing scorer inside a tree is memoized too: still one call, still an error.
tree_err, _, calls_err, _ = _evaluate(
    {"status": "failed", "error_message": "boom"}, controls=PII_CONTROLS
)
check("a failing scorer in a tree errors once, not per leaf",
      tree_err.errored is True
      and len([u for u in calls_err if u.endswith("/scorers/invoke")]) == 1)

# ---- 7. wiring ----------------------------------------------------------
print("\n[7] wiring")
from backend.agents.state import build_initial_state  # noqa: E402
from backend.models.schemas import ChatRequest  # noqa: E402

check(
    "ChatRequest accepts agent_control_review",
    ChatRequest(session_id="s", message="m", agent_control_review=True).agent_control_review
    is True,
)
check(
    "flag defaults to None (off) on the request",
    ChatRequest(session_id="s", message="m").agent_control_review is None,
)
check(
    "flag reaches the graph state",
    build_initial_state(
        session_id="s", user_message="m", conversation_history=[], agent_control_review=True
    )["agent_control_review"]
    is True,
)

# The guardrail chain is wired once for every blueprint (backend/agents/blueprints/
# guardrails.py), so assert the COMPILED graph rather than source strings.
from backend.agents.blueprints import list_blueprints  # noqa: E402
from backend.agents.graph import build_theme_subgraph  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

for _bp in list_blueprints():
    _edges = {(e.source, e.target) for e in build_theme_subgraph(THEMES["medadvice"], _bp).get_graph().edges}
    _nodes = set(build_theme_subgraph(THEMES["medadvice"], _bp).get_graph().nodes)
    check(f"[{_bp.key}] node registered on the theme subgraph", "agent_control" in _nodes)
    check(f"[{_bp.key}] compliance routes into agent_control", ("compliance", "agent_control") in _edges)
    # NeMo Guardrails' output rails sit between Agent Control and AI Defense, so
    # the chain is agent_control -> nemo_output_rails -> response_defense: Cisco
    # is still the last word on output.
    check(
        f"[{_bp.key}] agent_control -> nemo_output_rails -> response_defense (AI Defense stays the last word)",
        ("agent_control", "nemo_output_rails") in _edges and ("nemo_output_rails", "response_defense") in _edges,
    )

chat_src = (ROOT / "backend/routers/chat.py").read_text()
check("router forwards the flag", "agent_control_review=chat_request.agent_control_review" in chat_src)

engine_src = (ROOT / "backend/services/recommendation_engine.py").read_text()
check(
    "legacy engine path enforces it too (graph-unavailable fallback)",
    "if agent_control_review and agent_control_client.is_configured:" in engine_src,
)
check("legacy engine has the block handler", "def _handle_agent_control_block(" in engine_src)
check(
    "block handler attributes the guardrail to Agent Control",
    'guardrail_ids=["galileo_agent_control"]' in engine_src,
)
check(
    "block metadata records which transport decided",
    '"transport": verdict.transport' in engine_src,
)

check(
    "new settings exposed with documented defaults",
    settings.galileo_agent_control_execution == "auto"
    and settings.galileo_agent_control_refresh_seconds == 300.0,
)

script_src = (ROOT / "scripts/demo/register_agent_control.py").read_text()
check(
    "setup script reads the 'control' key this endpoint actually returns",
    'control.get("control")' in script_src,
)
check("setup script can replace a control definition", "--set-data" in script_src)
control_json = json.loads(
    (ROOT / "scripts/demo/controls/259-block-hallucinated-output.json").read_text()
)
cfg_259 = control_json["condition"]["evaluator"]["config"]
check(
    "checked-in control 259 uses eq/false, not a numeric operator",
    cfg_259["operator"] == "eq" and cfg_259["threshold"] is False,
)
check(
    "checked-in control 259 stays execution=server (inherits the server path later)",
    control_json["execution"] == "server",
)

pii_json = json.loads(
    (ROOT / "scripts/demo/controls/block-output-pii.json").read_text()
)
pii_leaves = pii_json["condition"]["or"]
pii_thresholds = {
    leaf["evaluator"]["config"]["threshold"] for leaf in pii_leaves
}
check(
    "checked-in output-PII control ORs contains leaves over the PII SLM scorer",
    all(
        leaf["evaluator"]["config"]["operator"] == "contains"
        and leaf["evaluator"]["config"]["scorer_id"] == "88eada48-109f-4f4e-8dc6-bf65799a331e"
        for leaf in pii_leaves
    ),
)
check(
    "output-PII control covers the sensitive identifiers",
    {"ssn", "date_of_birth", "email", "phone_number"} <= pii_thresholds,
)
check(
    "output-PII control excludes the bare 'name' category (would over-block "
    "answers naming a care provider)",
    "name" not in pii_thresholds,
)
check("output-PII control denies", pii_json["action"]["decision"] == "deny")

check(
    "the block message does not claim a specific cause (any deny control lands there)",
    "factually reliable" not in engine_src
    and "withheld by our agent control" in engine_src,
)

gov_src = (ROOT / "backend/agents/nodes/governance.py").read_text()
check(
    "non-blocking matches are attributed on the allowed-turn event",
    'guardrail_ids.append("galileo_agent_control")' in gov_src,
)

html = (ROOT / "frontend/index.html").read_text()
check("drawer has the Agent Observability Controls toggle", 'id="agentControlToggle"' in html)
check("toggle is labelled as asked", "Agent Observability Controls" in html)
check(
    "toggle sits directly beneath Cisco AI Defense Policy Review",
    html.index("Cisco AI Defense Policy Review")
    < html.index("Agent Observability Controls")
    < html.index("Internal Policy Engine"),
)

js = (ROOT / "frontend/js/chat.js").read_text()
check("toggle handler exists", "function toggleAgentControl()" in js)
check("toggle state is persisted", "medadvice_agent_control_enabled" in js)
check("flag is sent on every chat turn", "agent_control_review: agentControlEnabled" in js)

# ---- 8. splunk_ao backend: Agent Control hosted inside Agent Observability ---
# Kumar's intent (kumar-aamit/DemoBot, 2026-09-23): controls authored in the AO
# Controls UI and attached to the Agent stream, PRE + POST around the LLM step,
# X-SF-Token auth with an O11y API token, no Galileo console. Pinned here
# against the wire contract (no network): the same client, a second backend.
print("\n[8] splunk_ao backend")
posts = []
gets = []


def _fake_get(url, **kwargs):
    gets.append((url, kwargs))
    if url.endswith("/ao/api/projects"):
        return _FakeResponse([{"id": "proj-uuid", "name": "PseudoCo Assistant"}])
    if url.endswith("/log_streams/paginated"):
        token = (kwargs.get("params") or {}).get("starting_token", 0)
        if token == 0:
            return _FakeResponse({"log_streams": [{"id": "stream-med", "name": "MedAdvice"}],
                                  "paginated": True, "next_starting_token": 1})
        return _FakeResponse({"log_streams": [{"id": "stream-tele", "name": "TelecomChatbot"}],
                              "paginated": False, "next_starting_token": None})
    return _FakeResponse({"controls": []})


def _fake_post_ao(url, **kwargs):
    posts.append((url, kwargs))
    if url.endswith("/runtime-token-exchange"):
        return _FakeResponse({"detail": "not found"}, status_code=404)
    if url.endswith("/initAgent"):
        return _FakeResponse({"created": True, "controls": []})
    return _FakeResponse({
        "is_safe": False, "confidence": 0.8,
        "matches": [{"control_name": "tele-block", "action": "deny",
                     "result": {"matched": True, "confidence": 0.8, "message": "nope"}}],
    })


_ao_env = {"SPLUNK_AO_REALM": "us1", "SPLUNK_AO_PROJECT": "PseudoCo Assistant",
           "SPLUNK_AO_AGENT_STREAM_PER_THEME": "true",
           "SPLUNK_AO_CONTROL_TOKEN": "o11y-api-token", "AGENT_CONTROL_API_KEY": "galileo-console-key"}
with mock.patch.dict(os.environ, _ao_env), \
     mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
     mock.patch.object(settings, "galileo_agent_control_stages", ""), \
     mock.patch.object(ac.httpx, "get", side_effect=_fake_get), \
     mock.patch.object(ac.httpx, "post", side_effect=_fake_post_ao):
    ao_client = ac.AgentControlClient()
    check("backend reads as splunk_ao", ao_client.backend == "splunk_ao" and ao_client.is_splunk_ao)
    check("configured by the AO token alone (no console key involved)", ao_client.is_configured is True)
    check("never presents the Galileo console key on this backend", ao_client.api_key == "o11y-api-token")
    check("control URL derives from SPLUNK_AO_REALM",
          ao_client.control_url == "https://app.us1.observability.splunkcloud.com/ao/agent-control")
    check("AO CRUD API sits beside it", ao_client.ao_api_url == "https://app.us1.observability.splunkcloud.com/ao/api")
    check("both stages run by default on splunk_ao", ao_client.stages == ["pre", "post"])
    check("the step name is the UI's complete_chat", ao_client.step_name == "complete_chat")
    check("the target is the theme's Agent stream (the same resolver the AO worker uses)",
          ao_client.stream_for_theme("telecomchatbot") == "TelecomChatbot")

    pre = ao_client.evaluate_prompt("How do I get a refund?", session_id="s-2", theme="telecomchatbot")
    post = ao_client.evaluate_response("q", "a", session_id="s-2", theme="telecomchatbot", model="gpt-4o")
    with mock.patch.object(settings, "galileo_agent_control_execution", "client"):
        forced = ao_client.evaluate_response("q", "a", theme="telecomchatbot")
    missing = ao_client.evaluate_prompt("q", theme="no-such-theme")

evals = [(u, k) for u, k in posts if u.endswith("/api/v1/evaluation")]
inits = [(u, k) for u, k in posts if u.endswith("/api/v1/agents/initAgent")]
exchanges = [(u, k) for u, k in posts if u.endswith("/runtime-token-exchange")]
check("evaluations went to the AO-hosted server",
      evals and all(u.startswith("https://app.us1.observability.splunkcloud.com/ao/agent-control/") for u, _ in evals))
check("three evaluations were posted (pre, post, and the client-mode one forced to server)", len(evals) == 3)
_h = evals[0][1].get("headers", {})
check("auth is X-SF-Token with the AO token, no Authorization header",
      _h.get("X-SF-Token") == "o11y-api-token" and "Authorization" not in _h)
_pre_body, _post_body = evals[0][1]["json"], evals[1][1]["json"]
check("pre stage: stage=pre, the prompt as input, no output key",
      _pre_body.get("stage") == "pre" and _pre_body["step"].get("input") == "How do I get a refund?"
      and "output" not in _pre_body["step"])
check("post stage: stage=post with the answer as output",
      _post_body.get("stage") == "post" and _post_body["step"].get("output") == "a")
check("the step is llm / complete_chat",
      _pre_body["step"].get("type") == "llm" and _pre_body["step"].get("name") == "complete_chat")
check("every evaluation is bound to the theme's stream as a log_stream target (found on page 2)",
      all(k["json"].get("target_type") == "log_stream" and k["json"].get("target_id") == "stream-tele"
          for _, k in evals))
check("the context names the Agent stream for triage",
      (_post_body["step"].get("context") or {}).get("agent_stream") == "TelecomChatbot")
check("the agent is registered once per target with the target in the body (like the SDK's init)",
      len(inits) == 1 and inits[0][1]["json"].get("target_id") == "stream-tele"
      and inits[0][1]["json"]["steps"][0]["name"] == "complete_chat"
      and inits[0][1]["headers"].get("X-SF-Token") == "o11y-api-token")
check("a 404 runtime-token exchange falls back to the API token alone (SDK auto mode)",
      len(exchanges) == 1 and pre.errored is False and "X-Agent-Control-Runtime-Token" not in _h)
_pages = [k for u, k in gets if u.endswith("/log_streams/paginated")]
# 2 pages to find TelecomChatbot (cached across the pre / post / forced calls),
# then 2 more for the stream that does not exist (a miss is rescanned, never
# negatively cached: the stream appears on the theme's first logged turn).
check("the stream id is resolved through /ao/api with X-SF-Token, following pagination, then cached",
      len(_pages) == 4 and all(k["headers"].get("X-SF-Token") == "o11y-api-token" for _, k in gets)
      and any(u.endswith("/ao/api/projects") and (k.get("params") or {}).get("project_name") == "PseudoCo Assistant"
              for u, k in gets))
check("a deny at the prompt stage blocks, and the verdict knows its stage / backend / target",
      pre.should_block is True and pre.stage == "pre" and pre.backend == "splunk_ao"
      and pre.target == "TelecomChatbot" and pre.duration_ms is not None)
check("verdict records carry what the governance event and the control span need",
      set(pre.record()) >= {"stage", "backend", "target", "controls", "decisions", "errored", "duration_ms", "agent_name"}
      and pre.record()["controls"] == ["tele-block"] and pre.record()["decisions"] == ["deny"])
check("execution=client is forced to server on splunk_ao (its scorers live in the AO org)",
      forced.transport == "server" and forced.errored is False)
check("a stream that does not exist yet is an errored verdict (fail-open policy decides), never an exception",
      missing.errored is True and "target:" in (missing.error_message or ""))

# ---- 8b. 4.12.1: the target type the us1 gateway actually accepts ------------
# Live probe 2026-09-23 with a token carrying agent_observability_admin: every
# call bound to target_type=agent_stream (Splunk's how-to value, the 4.12.0
# default) answered 502 AUTH_UPSTREAM_REJECTED — controls GET, attachment
# filter, runtime-token exchange — while log_stream minted a runtime token and
# resolved the stream's bindings. Pin the default and the operator hint.
print("\n[8b] splunk_ao target type (4.12.1)")
check("the default target type is log_stream", settings.splunk_ao_control_target_type == "log_stream")
_body_502 = {"type": "https://agentcontrol.dev/errors/auth-upstream-rejected", "status": 502,
             "title": "Authorization Upstream Rejected Request",
             "detail": "An unexpected error occurred. Please try again or contact support.",
             "error_code": "AUTH_UPSTREAM_REJECTED"}
_r502 = _FakeResponse(_body_502, status_code=502)
check("gateway errors lead with the problem document's error_code",
      ac.AgentControlClient._safe_error_detail(_r502).startswith("AUTH_UPSTREAM_REJECTED: "))
check("an agent_stream target that draws AUTH_UPSTREAM_REJECTED gets the log_stream hint",
      "SPLUNK_AO_CONTROL_TARGET_TYPE=log_stream" in ac.AgentControlClient._target_type_hint(
          _r502, {"target_type": "agent_stream", "target_id": "x"}))
check("no hint when the target is already log_stream, or on another error",
      ac.AgentControlClient._target_type_hint(_r502, {"target_type": "log_stream", "target_id": "x"}) == ""
      and ac.AgentControlClient._target_type_hint(
          _FakeResponse({"detail": "down"}, status_code=502), {"target_type": "agent_stream", "target_id": "x"}) == ""
      and ac.AgentControlClient._target_type_hint(_r502, None) == "")


def _fake_post_502(url, **kwargs):
    posts.append((url, kwargs))
    if url.endswith("/initAgent"):
        return _FakeResponse({"created": True, "controls": []})
    return _FakeResponse(_body_502, status_code=502)


posts.clear()
gets.clear()
with mock.patch.dict(os.environ, _ao_env), \
     mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
     mock.patch.object(settings, "splunk_ao_control_target_type", "agent_stream"), \
     mock.patch.object(ac.httpx, "get", side_effect=_fake_get), \
     mock.patch.object(ac.httpx, "post", side_effect=_fake_post_502):
    bad = ac.AgentControlClient().evaluate_prompt("hi", theme="telecomchatbot")
check("an agent_stream evaluation that 502s is an errored verdict naming the fix",
      bad.errored is True and "AUTH_UPSTREAM_REJECTED" in (bad.error_message or "")
      and "SPLUNK_AO_CONTROL_TARGET_TYPE=log_stream" in (bad.error_message or ""))

# The acceptance probe registers the agent for the stream before listing: an
# agent the server has never seen answers 404 AGENT_NOT_FOUND on the controls GET.
posts.clear()
gets.clear()
with mock.patch.dict(os.environ, _ao_env), \
     mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
     mock.patch.object(ac.httpx, "get", side_effect=_fake_get), \
     mock.patch.object(ac.httpx, "post", side_effect=_fake_post_ao):
    listed = ac.AgentControlClient().list_controls(theme="telecomchatbot")
_init_calls = [k for u, k in posts if u.endswith("/api/v1/agents/initAgent")]
_ctl_gets = [k for u, k in gets if u.endswith("/agents/pseudoco-assistant-agent/controls")]
check("list_controls registers the agent for the stream first (log_stream target in the body)",
      len(_init_calls) == 1 and _init_calls[0]["json"].get("target_type") == "log_stream"
      and _init_calls[0]["json"].get("target_id") == "stream-tele")
check("list_controls then asks for the stream-bound effective set",
      len(_ctl_gets) == 1 and (_ctl_gets[0].get("params") or {}) == {"target_type": "log_stream", "target_id": "stream-tele"}
      and listed == [])


def _fake_get_502(url, **kwargs):
    if url.endswith("/controls") and "/agents/" in url:
        return _FakeResponse(_body_502, status_code=502)
    return _fake_get(url, **kwargs)


with mock.patch.dict(os.environ, _ao_env), \
     mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
     mock.patch.object(settings, "splunk_ao_control_target_type", "agent_stream"), \
     mock.patch.object(ac.httpx, "get", side_effect=_fake_get_502), \
     mock.patch.object(ac.httpx, "post", side_effect=_fake_post_ao):
    try:
        ac.AgentControlClient().list_controls(theme="telecomchatbot")
        check("the probe turns a 502 into an AgentControlError with the fix", False)
    except ac.AgentControlError as exc:
        check("the probe turns a 502 into an AgentControlError with the fix",
              "SPLUNK_AO_CONTROL_TARGET_TYPE=log_stream" in str(exc))

# Backend isolation: the galileo path is untouched, and each backend has its
# own credential — a box with both keys never sends one vendor the other's.
with mock.patch.dict(os.environ, {"AGENT_CONTROL_API_KEY": "galileo-console-key",
                                  "SPLUNK_AO_CONTROL_TOKEN": "", "SPLUNK_AO_O11Y_API_TOKEN": "",
                                  "SPLUNK_AO_REALM": "us1"}):
    with mock.patch.object(settings, "galileo_agent_control_backend", "galileo"), \
         mock.patch.object(settings, "galileo_agent_control_stages", ""):
        g = ac.AgentControlClient()
        check("galileo backend still reads AGENT_CONTROL_API_KEY and runs post only",
              g.backend == "galileo" and g.api_key == "galileo-console-key" and g.stages == ["post"]
              and g.control_url == settings.galileo_agent_control_url.rstrip("/"))
    with mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"):
        check("splunk_ao with only the Galileo key set is NOT configured (no credential sharing)",
              ac.AgentControlClient().is_configured is False)
    with mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
         mock.patch.dict(os.environ, {"SPLUNK_AO_O11Y_API_TOKEN": "sessions-token"}):
        check("splunk_ao falls back to the AO worker's SPLUNK_AO_O11Y_API_TOKEN",
              ac.AgentControlClient().api_key == "sessions-token")
    with mock.patch.object(settings, "galileo_agent_control_backend", "galileo"), \
         mock.patch.object(settings, "galileo_agent_control_stages", "pre,post"):
        check("GALILEO_AGENT_CONTROL_STAGES overrides the backend default", ac.AgentControlClient().stages == ["pre", "post"])
    with mock.patch.object(settings, "galileo_agent_control_backend", "splunk_ao"), \
         mock.patch.object(settings, "galileo_agent_control_stages", "post"):
        check("stages can be narrowed to post on splunk_ao too", ac.AgentControlClient().stages == ["post"])

# ---- 9. prompt-stage node ---------------------------------------------------
print("\n[9] prompt-stage node")


class _AOStub:
    is_configured = True
    stages = ["pre", "post"]

    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []

    def evaluate_prompt(self, msg, **k):
        self.calls.append(("pre", msg, k))
        return self.verdict

    def evaluate_response(self, **k):
        self.calls.append(("post", k))
        return ac.ControlVerdict()


pre_deny = ac.ControlVerdict(is_safe=False, decisions=["deny"], matched_controls=["tele-prompt-block"], stage="pre")
_saved_node_client = node_mod.agent_control_client
try:
    node_mod.agent_control_client = _AOStub(pre_deny)
    with mock.patch.object(node_mod.content_engine, "_handle_agent_control_prompt_block") as ph:
        ph.return_value = {"message": "withheld", "policy_blocked": True}
        out = node_mod.agent_control_prompt_node(dict(base_state, agent_control_review=True))
    check("a prompt deny short-circuits before any model call",
          out.get("terminal") is True and out.get("result", {}).get("policy_blocked") is True)
    check("the prompt verdict is recorded on its own state key", out.get("agent_control_prompt") is pre_deny)
    check("prompt stage timing recorded", "agent_control_prompt_ms" in (out.get("stage_timings") or {}))
    check("the prompt block handler gets the user message and the theme",
          ph.call_args.kwargs.get("user_message") == "q" and "theme" in ph.call_args.kwargs)

    node_mod.agent_control_client = _AOStub(
        ac.ControlVerdict(decisions=["observe"], matched_controls=["watch"], stage="pre"))
    allowed = node_mod.agent_control_prompt_node(dict(base_state, agent_control_review=True))
    check("a non-blocking prompt verdict continues the turn and still reaches governance",
          allowed.get("terminal") is None and allowed.get("agent_control_prompt") is not None)
    check("the prompt node is a no-op without opt-in", node_mod.agent_control_prompt_node(dict(base_state)) == {})

    post_only = _AOStub(pre_deny)
    post_only.stages = ["post"]
    node_mod.agent_control_client = post_only
    check("the prompt node is a no-op when the backend runs the response stage only",
          node_mod.agent_control_prompt_node(dict(base_state, agent_control_review=True)) == {}
          and not post_only.calls)

    class _Legacy:                      # a stub without ``stages``: response stage only
        is_configured = True

        def evaluate_response(self, **k):
            return ac.ControlVerdict()

    node_mod.agent_control_client = _Legacy()
    check("a client without `stages` runs the response stage only",
          node_mod.agent_control_prompt_node(dict(base_state, agent_control_review=True)) == {})
finally:
    node_mod.agent_control_client = _saved_node_client

from backend.agents.blueprints.guardrails import PRE_NODES, _MAY_TERMINATE  # noqa: E402

check("the prompt node sits right after Cisco AI Defense in the PRE chain",
      PRE_NODES.index("agent_control_prompt") == PRE_NODES.index("prompt_defense") + 1)
check("the prompt node may terminate the turn", "agent_control_prompt" in _MAY_TERMINATE)
check("governance reads the prompt-stage verdict too", "agent_control_prompt" in gov_src)
check("governance carries both verdicts to Agent Observability", "agent_control_verdicts" in gov_src)
check("chat.js labels the prompt stage", "agent_control_prompt:" in js)

# ---- 10. response-stage steer -------------------------------------------
# A steer control's guidance (steering_context.message) is applied: a steer agent
# rewrites the answer, the rewrite is evaluated again, and the rewrite ships.
print("\n[10] response-stage steer")
from backend.agents.llm import ChatModelError, NormalizedLLMResponse  # noqa: E402
from backend.models.schemas import SeverityLevel  # noqa: E402

_PII_ANSWER = ("Customer: Alexandra Martinez | Rewards #: (305) 392-8471 | Store card application SSN: "
               "234-56-7890 | DOB: 06/15/1985 | amartinez@gmail.com | (305) 392-8471\n\n"
               "I recommend trying size 9. Would you like me to start the exchange?")
_CLEAN_ANSWER = "I recommend trying size 9. Would you like me to start the exchange?"
_GUIDANCE = "Remove all personal data from the output."

steer_state = dict(
    base_state, agent_control_review=True, theme="retail", final_message=_PII_ANSWER,
    complete_display_text="MEDIUM\n" + _PII_ANSWER, severity=SeverityLevel.MEDIUM,
    requested_categories={"pii": True}, pii_detected=True, pii_types=["synthetic_pii"],
    agent_trace=[{"name": "retail_synthesizer", "role": "synthesizer"}],
    llm_output_tokens_cached=0, llm_output_tokens_uncached=22,
)


def _steer_verdict(guidance=_GUIDANCE):
    return ac.ControlVerdict(is_safe=False, confidence=1.0, decisions=["steer"],
                             matched_controls=["steer-remove-output-pii-regex"],
                             steering=[guidance] if guidance else [])


def _rewrite(text, out=7):
    return NormalizedLLMResponse(id="rw", content=text, model="mistral-nemo:12b", input_tokens=40,
                                 output_tokens=out, output_tokens_cached=0, output_tokens_uncached=out,
                                 stop_reason="end_turn")


def _run_steer(verdicts, rewrites, *, attempts=1, fail_open=True):
    """The response node with evaluate_response answering ``verdicts`` in order and
    the steer agent answering ``rewrites`` in order (an exception instance raises)."""
    llm = mock.Mock(side_effect=rewrites)
    with mock.patch.object(
        ac.AgentControlClient, "is_configured", new_callable=mock.PropertyMock
    ) as configured, mock.patch.object(
        node_mod.agent_control_client, "evaluate_response", side_effect=verdicts
    ) as ev, mock.patch.object(node_mod, "invoke_agent", llm), mock.patch.object(
        node_mod.content_engine, "_handle_agent_control_block"
    ) as handler, mock.patch.object(
        settings, "galileo_agent_control_steer_attempts", attempts
    ), mock.patch.object(settings, "galileo_agent_control_fail_open", fail_open):
        configured.return_value = True
        handler.return_value = {"message": "withheld", "policy_blocked": True}
        out = node_mod.agent_control_node(dict(steer_state))
    return out, llm, ev, handler


out, llm, ev, handler = _run_steer([_steer_verdict(), ac.ControlVerdict()], [_rewrite(_CLEAN_ANSWER)])
v = out.get("agent_control")
check("steer: the answer is rewritten, not withheld",
      out.get("terminal") is None and out.get("final_message") == _CLEAN_ANSWER and not handler.called)
check("steer: the display text is rebuilt around the rewrite (severity badge kept)",
      out.get("complete_display_text") == "MEDIUM\n" + _CLEAN_ANSWER)
check("steer: the rewrite is re-evaluated before it ships",
      ev.call_count == 2 and ev.call_args_list[1].kwargs["assistant_message"] == _CLEAN_ANSWER)
sent = llm.call_args.kwargs
check("steer: the steer agent gets the control's guidance and the original answer",
      sent["agent_name"] == "retail_agent_control_steer_agent"
      and _GUIDANCE in sent["messages"][0]["content"] and _PII_ANSWER in sent["messages"][0]["content"])
check("steer: the outcome rides on the verdict record",
      v.record()["steer"] == {"attempts": 1, "outcome": "applied", "recheck_controls": [],
                              "recheck_decisions": []}
      and v.record()["decisions"] == ["steer"] and v.record()["steering"] == [_GUIDANCE])
check("steer: Synthetic Content flags are re-read from the delivered rewrite",
      out.get("pii_detected") is False and out.get("pii_types") == [])
check("steer: the steer agent joins agent_trace and its tokens the turn's sums",
      [t["name"] for t in out["agent_trace"]] == ["retail_synthesizer", "retail_agent_control_steer_agent"]
      and out["llm_input_tokens"] == 51 and out["llm_output_tokens"] == 29
      and out["llm_output_tokens_cached"] + out["llm_output_tokens_uncached"] == 29)

out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()], [_rewrite(f"<reply>\n{_CLEAN_ANSWER}\n</reply>")])
check("steer: echoed <reply> tags are stripped", out.get("final_message") == _CLEAN_ANSWER)

# Seen live on llama3.2:3b (v4.19.0): a heading line, and the record line's labels
# kept with every value blanked. Both go before the re-check and the user see them.
_SKELETON = "Customer:  | Rewards #:  | Store card application SSN:  | DOB:  |  | "
out, llm, ev, _ = _run_steer([_steer_verdict(), ac.ControlVerdict()],
                             [_rewrite(f"Rewritten reply:\n\n{_SKELETON}\n{_CLEAN_ANSWER}")])
check("steer: a 'Rewritten reply:' heading and an emptied record line are removed",
      out.get("final_message") == _CLEAN_ANSWER
      and ev.call_args_list[1].kwargs["assistant_message"] == _CLEAN_ANSWER)
out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()],
                     [_rewrite(f"Customer: | Rewards #: | Store card application SSN: | DOB: | | \n\n{_CLEAN_ANSWER}")])
check("steer: an emptied record line at the top is removed with its blank line",
      out.get("final_message") == _CLEAN_ANSWER)
for husk in ("Customer: |  |  | ", "Customer:  | Rewards #:  | Store card application  |  |  |  | ",
             "Customer:"):
    out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()], [_rewrite(f"{husk}\n\n{_CLEAN_ANSWER}")])
    check(f"steer: the emptied record line {husk!r} is removed", out.get("final_message") == _CLEAN_ANSWER)
out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()],
                     [_rewrite("**Here is the revised response:**\n"
                               "Customer: [REDACTED] | Rewards #: [removed] | Store card application SSN: N/A "
                               f"| DOB: — |  | \n{_CLEAN_ANSWER}")])
check("steer: redaction markers count as emptied values; a bold heading is removed",
      out.get("final_message") == _CLEAN_ANSWER)
out, *_ = _run_steer([_steer_verdict()], [_rewrite(f"Rewritten reply:\n{_SKELETON}")])
check("steer: a rewrite that is only a heading and a skeleton is an empty rewrite (error)",
      "final_message" not in out and out["agent_control"].steer["outcome"] == "error")
_KEEP = ("Here's how:\n| Size | Fit |\n|---|---|\n| 9 | true |\nCustomer: Alexandra | Rewards #: |\n"
         "Price: $20 | Tax: $1.60\nRevised pricing applies from Monday:\n- Shoes $20")
out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()], [_rewrite(_KEEP)])
check("steer: tables, partly filled record lines and ordinary colon lines are kept",
      out.get("final_message") == _KEEP)
out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict()],
                     [_rewrite("Order: | Status: | \nNotes:\nI recommend trying size 9.")])
check("steer: a label-only line whose labels are not from the original record line is kept",
      out.get("final_message") == "Order: | Status: | \nNotes:\nI recommend trying size 9.")

deny_after = ac.ControlVerdict(is_safe=False, confidence=1.0, decisions=["deny"], matched_controls=["block-x"])
out, llm, ev, handler = _run_steer([_steer_verdict(), deny_after], [_rewrite(_CLEAN_ANSWER)])
blocked_with = handler.call_args.kwargs if handler.called else {}
check("steer: a rewrite the re-check denies is withheld", out.get("terminal") is True and handler.called)
check("steer: the block records the denying verdict, marked as a denied steer",
      blocked_with.get("verdict") is deny_after and (deny_after.steer or {}).get("outcome") == "denied"
      and out.get("agent_control") is deny_after)
check("steer: the block reports the rewrite's tokens too",
      blocked_with.get("usage_data", {}).get("usage_total_tokens") == 33 + 47)

out, llm, ev, _ = _run_steer(
    [_steer_verdict(), _steer_verdict("Also drop the email address."), _steer_verdict()],
    [_rewrite("first pass"), _rewrite("second pass")], attempts=2,
)
check("steer: attempts are bounded; the last rewrite ships, recorded unresolved",
      llm.call_count == 2 and out.get("final_message") == "second pass" and out.get("terminal") is None
      and out["agent_control"].steer["outcome"] == "unresolved" and out["agent_control"].steer["attempts"] == 2)
check("steer: a further attempt applies the re-check's guidance to the previous rewrite",
      "Also drop the email address." in llm.call_args.kwargs["messages"][0]["content"]
      and "first pass" in llm.call_args.kwargs["messages"][0]["content"])

out, *_ = _run_steer([_steer_verdict(), ac.ControlVerdict(errored=True, error_message="timeout")],
                     [_rewrite(_CLEAN_ANSWER)])
check("steer: a re-check that errors (fail-open) ships the rewrite as unverified",
      out.get("final_message") == _CLEAN_ANSWER and out["agent_control"].steer["outcome"] == "unverified")

out, llm, ev, handler = _run_steer([_steer_verdict()], [ChatModelError("boom")])
v = out["agent_control"]
check("steer: a failed rewrite under fail-open releases the original answer, flagged",
      out.get("terminal") is None and "final_message" not in out and v.errored
      and v.steer["outcome"] == "error" and "steer rewrite failed" in (v.error_message or "")
      and ev.call_count == 1 and not handler.called)
out, _, _, handler = _run_steer([_steer_verdict()], [ChatModelError("boom")], fail_open=False)
check("steer: a failed rewrite under fail-closed withholds the answer",
      out.get("terminal") is True and handler.called)
out, *_ = _run_steer([_steer_verdict()], [_rewrite("   ")])
check("steer: an empty rewrite is an error, never an empty answer",
      "final_message" not in out and out["agent_control"].steer["outcome"] == "error")

out, llm, _, _ = _run_steer([_steer_verdict()], [], attempts=0)
check("steer: steer_attempts=0 records the steer without rewriting",
      not llm.called and "final_message" not in out and out["agent_control"].steer is None
      and out["agent_control"].decisions == ["steer"])
out, llm, _, _ = _run_steer([_steer_verdict(guidance=None)], [])
check("steer: a steer control without steering context has nothing to apply",
      not llm.called and out["agent_control"].steer["outcome"] == "no_guidance")
both = ac.ControlVerdict(is_safe=False, decisions=["steer", "deny"], matched_controls=["s", "d"],
                         steering=[_GUIDANCE])
out, llm, _, handler = _run_steer([both], [])
check("steer: a deny in the same verdict wins (withheld, no rewrite)",
      out.get("terminal") is True and handler.called and not llm.called)

with mock.patch.object(
    ac.AgentControlClient, "is_configured", new_callable=mock.PropertyMock
) as configured, mock.patch.object(
    ac.AgentControlClient, "stages", new_callable=mock.PropertyMock
) as stages, mock.patch.object(
    node_mod.agent_control_client, "evaluate_prompt", return_value=_steer_verdict()
), mock.patch.object(node_mod, "invoke_agent") as llm:
    configured.return_value = True
    stages.return_value = ["pre", "post"]
    out = node_mod.agent_control_prompt_node(dict(steer_state))
check("a prompt-stage steer is recorded, never rewritten",
      not llm.called and "final_message" not in out and out["agent_control_prompt"].steered)

os.environ.pop("GALILEO_API_KEY", None)
os.environ.pop("AGENT_CONTROL_API_KEY", None)

print(f"\n{'FAILED' if _fails else 'OK'}: {_fails} failure(s)")
raise SystemExit(1 if _fails else 0)
