#!/bin/bash
# Run every standalone regression suite (no pytest here — each is a script that
# exits non-zero on failure). Exit 0 only if ALL pass.
#
#   ./tests/run_all.sh            # all suites
#   ./tests/run_all.sh --quick    # skip the slow TestClient suite (test_api.py)
#
# Add a suite here when you add one; CLAUDE.md "Blueprint feature parity"
# requires tests/test_blueprint_parity.py to stay in this list.
set -u
cd "$(dirname "$0")/.." || exit 2
# PY=... overrides the interpreter (e.g. a worktree without its own venv).
PY=${PY:-./venv/bin/python}
if ! "$PY" -c "import fastapi" >/dev/null 2>&1; then
  echo "ERROR: $PY is not a PseudoCo Assistant venv interpreter (set PY=/path/to/venv/bin/python)" >&2
  exit 2
fi

SUITES=(
  tests/test_nvidia_provider.py
  tests/test_host_capabilities.py
  tests/test_ec2_scripts.py
  tests/test_box_identity.py
  tests/test_lab5_setup.py
  tests/test_lab5_participants.py
  tests/test_identity_personas.py
  tests/test_tracestate_guard.py
  tests/test_spray_sources.py
  tests/test_spray_driver.py
  tests/test_set_ao_api_token.py
  tests/test_provider_setting.py
  tests/test_model_catalog.py
  tests/test_model_emitter.py
  tests/test_ollama_provider.py
  tests/test_integration_settings.py
  tests/test_demo_controls.py
  tests/test_nemo_guardrails.py
  tests/test_nemoclaw_guard.py
  tests/test_tool_guard.py
  tests/test_guardrail_nodes.py
  tests/test_agent_control.py
  tests/test_multi_agent.py
  tests/test_blueprint_parity.py
  tests/test_nvidia_blueprint.py
  tests/test_executive_fields.py
  tests/test_db_integrity.py
  tests/test_scheduling.py
  tests/test_review_fixes.py
  tests/test_auto_prompter.py
  tests/test_synthetic_content.py
  tests/test_ehr.py
  tests/test_internal_docs.py
  tests/test_attachments.py
  tests/test_chat_completions.py
  tests/test_identity_sessions.py
  tests/test_duo_signin.py
  tests/test_identity_gate.py
  tests/test_themes.py
  tests/test_token_cache_split.py
  tests/test_recommendation_formatting.py
  tests/test_agent_observability.py
  tests/observability/test_genai_span_content.py
  tests/observability/test_tool_span_content.py
)
[ "${1:-}" = "--quick" ] || SUITES+=(tests/test_api.py)

# No suite may reach a real Duo tenant or Identity Intelligence: a checkout's
# .env can hold the Lab 5 keys (the dev copy's does, plan 12.5). An exported
# variable beats .env in both loaders (backend/config.py, pydantic-settings),
# so these blank them; each identity suite sets what it needs, with fakes
# (tests/identity_isolation.py also refuses any lookup a suite forgets to fake).
export DUO_ENABLED=false PUBLIC_BASE_URL= IDENTITY_ALLOWED_USERS= \
       DUO_CLIENT_ID= DUO_CLIENT_SECRET= DUO_API_HOST= DUO_ADMIN_IKEY= DUO_ADMIN_SKEY= \
       CII_CLIENT_ID= CII_CLIENT_SECRET= CII_TOKEN_URL= CII_API_URL= CII_ACCESS_TOKEN=

pass=0; fail=0; failed=()
for s in "${SUITES[@]}"; do
  [ -f "$s" ] || { echo "SKIP  $s (missing)"; continue; }
  if OTEL_ENABLED=false PREWARM_LLM=false SPLUNK_AO_LOGGING_DISABLED=1 "$PY" "$s" >/tmp/run_all.$$.log 2>&1; then
    echo "PASS  $s"; pass=$((pass+1))
  else
    echo "FAIL  $s"; fail=$((fail+1)); failed+=("$s")
    grep -E "FAIL|ERROR" /tmp/run_all.$$.log | head -8 | sed 's/^/      /'
  fi
done
rm -f /tmp/run_all.$$.log
echo
echo "RESULT: $pass passed, $fail failed${failed:+ — ${failed[*]}}"
[ "$fail" -eq 0 ]
