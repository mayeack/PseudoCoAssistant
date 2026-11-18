"""PatchBot regression suite (docs/patchbot.md).

Covers the BOD 26-04 rating, the estate model, the control rules (local
mode), the Change Board's separation of duties, the TA-patchbot data contract
for every sourcetype, and the whole Lab 1 to 5 path through the API with a
TestClient: full read, exposure answer, staging patch, the production deny,
approval, production patch, the role-boundary deny, a Viewer's denied
dismissal, the restricted-tool deny and the rollback reopen.

Standalone (no pytest required):
    venv/bin/python tests/test_patchbot.py

Side-effect-safe: temp SQLite file, local controls mode, no HEC, no Agent
Observability, and the model is never called (the chat and advisory paths are
covered by tests/manual/probe_patchbot.py against a live Ollama).
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OTEL_ENABLED"] = "false"
os.environ.pop("SPLUNK_AO_O11Y_TOKEN", None)
os.environ["SPLUNK_AO_LOGGING_DISABLED"] = "1"

import backend.config  # noqa: F401,E402
from backend.config import settings  # noqa: E402


_tmpdir = tempfile.mkdtemp(prefix="pseudoco-assistant-patchbottest-")
settings.database_url = f"sqlite:///{os.path.join(_tmpdir, 'patchbot.db')}"
settings.prewarm_llm = False
settings.patchbot_controls_mode = "local"
settings.patchbot_hec_url = ""
settings.patchbot_hec_token = ""
settings.duo_enabled = False
os.chdir(_tmpdir)   # logs/patchbot.jsonl lands in the temp dir

sys.path.insert(0, str(Path(__file__).resolve().parent))
import identity_isolation  # noqa: E402  (no real Duo / CII, whatever .env holds)

identity_isolation.isolate(settings)

from backend.database import db as dbmod  # noqa: E402
from backend.models.db_models import Base  # noqa: E402

Base.metadata.create_all(bind=dbmod.engine)

from backend.patchbot import catalog, controls, telemetry  # noqa: E402
from backend.logging.governance_logger import governance_logger  # noqa: E402

governance_logger.set_logs_directory(os.path.join(_tmpdir, "logs"))   # never the repo's logs/
from backend.patchbot import estate as est  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok  {name}")
    else:
        print(f"  FAIL {name} {detail}")
        _failures.append(name)


def events(kind=None, event_type=None):
    path = telemetry._log_path()
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [r for r in rows if (kind is None or r["sourcetype"] == f"pseudoco:patchbot:{kind}")
            and (event_type is None or r["event_type"] == event_type)]


print("BOD 26-04 rating")
check("Apache public = row 1, critical", catalog.rate("CVE-2021-41773", publicly_exposed=True).row == 1)
check("sudo internal = 14 days", catalog.rate("CVE-2021-3156", publicly_exposed=False).timeline == "14 days")
check("OpenSSL internal = fix on upgrade",
      catalog.rate("CVE-2023-0286", publicly_exposed=False).timeline == "Fix on system upgrade")
check("table has 16 rows", len(catalog.bod_table()) == 16)

print("Estate model")
s = est.seed_state()
check("six hosts", len(s["hosts"]) == 6)
check("web-prod-01 vulnerable to Apache", est.is_vulnerable(s, "web-prod-01", "CVE-2021-41773"))
s2, facts = est.apply_patch(s, "web-stg-01", "CVE-2021-41773")
check("patch sets fixed version", facts["version_after"] == "2.4.51" and not est.is_vulnerable(s2, "web-stg-01", "CVE-2021-41773"))
check("patch does not mutate input", est.is_vulnerable(s, "web-stg-01", "CVE-2021-41773"))

print("Control rules (local mode)")
ctx = lambda role, **k: dict({"initiator": "u", "initiator_role": role}, **k)  # noqa: E731
check("Linux operator, Windows host: deny",
      controls.evaluate_local("apply_patch", {"os_family": "windows", "environment": "staging"},
                              ctx("linux_patch_operator")).decision == "deny")
check("prod without approval: deny",
      "deny-prod-without-approved-change" in controls.evaluate_local(
          "apply_patch", {"os_family": "linux", "environment": "production"},
          ctx("linux_patch_operator", change_status="awaiting_approval")).controls_matched)
check("restricted tool: deny for owner",
      controls.evaluate_local("stop_service", {}, ctx("estate_owner")).decision == "deny")
check("read tool: allow", controls.evaluate_local("list_servers", {}, ctx("patch_viewer")).decision == "allow")

print("Agent Observability mode: fail closed")
from backend.services import agent_control as _ac  # noqa: E402

_real_eval = _ac.agent_control_client.evaluate_tool_call
settings.patchbot_controls_mode = "agent_observability"
_ac.agent_control_client.evaluate_tool_call = lambda *a, **k: _ac.ControlVerdict(errored=True, error_message="down")
v = controls.decide("apply_patch", {"os_family": "linux", "environment": "staging"}, ctx("linux_patch_operator"))
check("Controls down: patch refused", v.decision == "deny" and v.fail_closed, v)
check("Controls down: read runs", controls.decide("list_servers", {}, ctx("patch_viewer")).runs)
_ac.agent_control_client.evaluate_tool_call = lambda *a, **k: _ac.ControlVerdict()
v = controls.decide("apply_patch", {"os_family": "linux", "environment": "staging"}, ctx("linux_patch_operator"))
check("no controls attached: patch refused", v.decision == "deny" and v.fail_closed, v)
_ac.agent_control_client.evaluate_tool_call = lambda *a, **k: _ac.ControlVerdict(
    matched_controls=["observe-all-patches"], decisions=["observe"])
check("attached and clean: patch runs",
      controls.decide("apply_patch", {"os_family": "linux", "environment": "staging"}, ctx("linux_patch_operator")).runs)
# A live AO deny (response shape of 2026-11-18): the evaluator says "Condition
# tree matched"; the person sees the message the control's author wrote.
_raw = {"is_safe": False, "confidence": 1.0, "reason": "Condition tree matched", "errors": None, "matches": [
    {"control_name": "deny-prod-without-approved-change", "action": "deny",
     "result": {"matched": True, "message": "Condition tree matched"},
     "steering_context": {"message": "Production needs an approved change. Request approval on the Change Board first."}},
    {"control_name": "observe-all-patches", "action": "observe",
     "result": {"matched": True, "message": "Pattern '.+' found"}, "steering_context": {"message": "Recorded."}}]}
_parsed = _ac.agent_control_client._parse_response(_raw)
check("parser keeps each control's authored message",
      _parsed.guidance_by_control.get("observe-all-patches") == "Recorded." and _parsed.steering == [], _parsed)
_ac.agent_control_client.evaluate_tool_call = lambda *a, **k: _parsed
v = controls.decide("apply_patch", {"os_family": "linux", "environment": "production"}, ctx("linux_patch_operator"))
check("AO deny shows the control's message, not the evaluator's",
      v.decision == "deny" and v.deny_reason.startswith("Production needs an approved change") and not v.fail_closed, v)
_ac.agent_control_client.evaluate_tool_call = _real_eval
settings.patchbot_controls_mode = "local"

print("API path (Labs 1 to 5)")
from fastapi.testclient import TestClient  # noqa: E402
import backend.main as main  # noqa: E402
from backend.patchbot import agent as pb_agent  # noqa: E402

print("Patch summary never contradicts the facts")
from backend.patchbot import roles as _roles  # noqa: E402
from backend.patchbot.run import Run as _Run  # noqa: E402


class _Says:
    def __init__(self, text):
        self.text = text

    def invoke(self, messages):
        from langchain_core.messages import AIMessage
        return AIMessage(content=self.text)


_real_model = pb_agent._model
_ok = ["Patched web-stg-01: httpd 2.4.49 → 2.4.51.", "Checked web-stg-01: CVE gone confident, service healthy confident."]
_no = ["win-stg-01 not patched: This patch is outside your role."]


def _summary(model_text, facts, refused, hosts):
    pb_agent._model = lambda max_tokens=700: _Says(model_text)
    r = _Run(initiator=_roles.Initiator("dana.lee", "linux_patch_operator", ["linux_patch_operator"]),
             owner="dana.lee", kind="patch", session_id="testsession01")
    return pb_agent._summarize(r, facts, " ".join(facts), refused=refused, hosts=hosts), r


out, r = _summary("Policy refused patching web-stg-01 due to version mismatch.", _ok, [], ["web-stg-01"])
check("invented refusal falls back to the facts", out == " ".join(_ok), out)
check("LLM span keeps what the model wrote", "version mismatch" in r.llm_calls[-1]["output"])
out, _ = _summary("Patched web-stg-01 to httpd 2.4.51; the CVE is gone and the service is healthy.", _ok, [], ["web-stg-01"])
check("faithful summary is used", out.startswith("Patched web-stg-01"), out)
out, _ = _summary("All done.", _ok, [], ["web-stg-01"])
check("summary must name every host", out == " ".join(_ok), out)
out, _ = _summary('"Policy refused win-stg-01: it is outside your role."', _no, ["win-stg-01"], ["win-stg-01"])
check("refusal summary is used, quotes stripped", out == "Policy refused win-stg-01: it is outside your role.", out)
out, _ = _summary("Patched win-stg-01.", _no, ["win-stg-01"], ["win-stg-01"])
check("summary that hides a refusal falls back", out == " ".join(_no), out)
pb_agent._model = _real_model

pb_agent._summarize = lambda run, facts, fallback, **kw: fallback   # the model is never called here

dana = TestClient(main.app)
sam = TestClient(main.app)
jo = TestClient(main.app)
ravi = TestClient(main.app)
H = {"x-patchbot-session": "testsession01"}
check("no persona: 401", dana.get("/api/patchbot/workspace", headers=H).status_code == 401)
for client, name in ((dana, "dana.lee"), (sam, "sam.ortiz"), (jo, "jo.kim"), (ravi, "ravi.patel")):
    client.post("/api/patchbot/persona", json={"username": name})
ws = dana.get("/api/patchbot/workspace", headers=H).json()
check("persona role", ws["initiator"]["role"] == "linux_patch_operator")
check("no findings before the full read", ws["counts"]["open"] == 0)
r = dana.post("/api/patchbot/full-read", headers=H).json()
check("full read reports 11 open host-CVE pairs", len(r["result"]["open"]) == 11, r["result"]["open"])
ws = dana.get("/api/patchbot/workspace", headers=H).json()
check("7 findings after the full read", ws["counts"]["open"] == 7, ws["counts"])
check("Apache is critical and first", ws["findings"][0]["severity"] == "critical")
check("vuln events carry CIM fields", all(e.get("dest") and e.get("cve") and e.get("severity")
                                          for e in events("vuln")))
check("finding_opened x7", len(events("finding", "finding_opened")) == 7)

r = dana.post("/api/patchbot/exposure", headers=H,
              json={"server": "web-prod-01", "publicly_exposed": False}).json()
check("exposure answer re-rates sudo", any(x["cve"] == "CVE-2021-3156" for x in r["output"]["rerated"]), r)
dana.post("/api/patchbot/exposure", headers=H, json={"server": "web-prod-01", "publicly_exposed": True})

r = dana.post("/api/patchbot/findings/CVE-2021-41773/patch", headers=H, json={"environment": "staging"}).json()
check("staging patched", any("Patched web-stg-01" in f for f in r["facts"]), r)
r = dana.post("/api/patchbot/findings/CVE-2021-41773/patch", headers=H, json={"environment": "production"}).json()
denies = [t for t in events("tool") if t["tool_name"] == "apply_patch" and t["decision"] == "deny"]
check("production patch denied before approval",
      any("deny-prod-without-approved-change" in d["controls_matched"] for d in denies), r)
change_id = r.get("change_id")
check("a change was opened", bool(change_id))
check("requester cannot approve", dana.post(f"/api/patchbot/changes/{change_id}/decision", headers=H,
                                            json={"decision": "approve"}).status_code == 403)
check("approver approves", sam.post(f"/api/patchbot/changes/{change_id}/decision", headers=H,
                                    json={"decision": "approve"}).status_code == 200)
r = dana.post("/api/patchbot/findings/CVE-2021-41773/patch", headers=H, json={"environment": "production"}).json()
check("production patched after approval", any("Patched web-prod-01" in f for f in r["facts"]), r)
d = dana.get("/api/patchbot/findings/CVE-2021-41773", headers=H).json()
check("finding resolved, fixed by change", d["status"] == "resolved" and d["resolution"] == "fixed_by_change", d)
check("change closed", d["change"]["status"] == "closed")
check("patch events map to CIM Updates", all(e["status"] == "installed" and e["signature"] for e in events("patch")))

r = dana.post("/api/patchbot/findings/CVE-2021-34527/patch", headers=H, json={"environment": "staging"}).json()
check("Linux operator cannot patch Windows",
      any(t["tool_name"] == "apply_patch" and "deny-patch-outside-role-os" in t["controls_matched"]
          for t in events("tool")), r)
r = ravi.post("/api/patchbot/full-read", headers=H)
r = ravi.post("/api/patchbot/findings/CVE-2021-34527/patch", headers=H, json={"environment": "staging"}).json()
check("Windows operator can patch Windows staging", any("Patched win-stg-01" in f for f in r["facts"]), r)

jo.post("/api/patchbot/full-read", headers=H)
r = jo.post("/api/patchbot/findings/CVE-2023-0286/triage", headers=H,
            json={"action": "dismiss", "reason": "accepted_risk", "note": "lab"}).json()
check("Viewer's dismissal denied", r["denied"] and "deny-viewer-actions" in r["verdict"]["controls"], r)
r = dana.post("/api/patchbot/findings/CVE-2023-0286/triage", headers=H,
              json={"action": "dismiss", "reason": "accepted_risk", "note": "internal only"}).json()
check("operator's dismissal runs", r["ok"], r)

from backend.patchbot import roles, tools  # noqa: E402
from backend.patchbot.run import Run  # noqa: E402

run = Run(initiator=roles.Initiator("dana.lee", "linux_patch_operator", ["linux_patch_operator"]),
          owner="dana.lee", kind="chat", session_id="testsession01")
res = tools.call(run, "stop_service", {"server": "web-prod-01", "service": "edr-agent"})
check("restricted tool denied", res["denied"] and "deny-restricted-tools" in res["verdict"]["controls"], res)
check("AO record has tool + control", run.ao_record()["tool_calls"][-1]["control"]["controls"] == ["deny-restricted-tools"])

r = dana.post("/api/patchbot/demo/rollback", headers=H, json={"cve": "CVE-2021-41773"}).json()
check("rollback reopens the finding", len(events("finding", "finding_reopened")) >= 1, r)

print("Data contract")
common = ("event_type", "app", "feature", "estate_owner", "patchbot_session_id", "investigation_id", "finding_id")
for kind in telemetry.KINDS:
    rows = events(kind)
    if kind == "session":
        check("session_started written", any(x["event_type"] == "session_started" for x in rows))
    if rows:
        check(f"{kind}: common fields", all(all(k in x for k in common) for x in rows))
check("tool events carry a decision", all(e.get("decision") for e in events("tool")))
check("no event goes to gen_ai_log", settings.patchbot_hec_index == "patchbot")

if _failures:
    print(f"\n{len(_failures)} FAILED: {_failures}")
    sys.exit(1)
print("\nAll PatchBot checks passed.")
