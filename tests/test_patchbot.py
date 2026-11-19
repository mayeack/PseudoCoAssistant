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
check("eight hosts", len(s["hosts"]) == 8)
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
out, _ = _summary('"Policy refused win-stg-01. This patch is outside your role."', _no, ["win-stg-01"], ["win-stg-01"])
check("refusal summary is used, quotes stripped", out == "Policy refused win-stg-01. This patch is outside your role.", out)
out, _ = _summary("Policy refused win-stg-01 due to a role mismatch.", _no, ["win-stg-01"], ["win-stg-01"])
check("summary that paraphrases the refusal reason falls back", out == " ".join(_no), out)
out, _ = _summary("Patched win-stg-01.", _no, ["win-stg-01"], ["win-stg-01"])
check("summary that hides a refusal falls back", out == " ".join(_no), out)
pb_agent._model = _real_model

print("Advisory reply never relays refused steps")
import json as _json  # noqa: E402
_deny = _json.dumps({"message": "PatchBot does not run commands or stop services."})


def _adv_run():
    return _Run(initiator=_roles.Initiator("dana.lee", "linux_patch_operator", ["linux_patch_operator"]),
                owner="dana.lee", kind="advisory", session_id="testsession02")


r = _adv_run()
r.add_tool({"name": "stop_service", "arguments": _json.dumps({"server": "web-prod-01", "service": "edr-agent"}),
            "output": _deny, "ok": False, "decision": "deny", "origin": "model"})
r.add_tool({"name": "run_command", "arguments": _json.dumps({"server": "dc-prod-01", "command": "curl | sh"}),
            "output": _deny, "ok": False, "decision": "deny", "origin": "model"})
out = pb_agent._refusal_report(r, {"reply": "Please perform these steps manually: stop the EDR service.", "tool_calls": []})
check("refused advisory: the model's do-it-by-hand reply is replaced",
      "manually" not in out["reply"] and "stop_service on web-prod-01 and run_command on dc-prod-01" in out["reply"]
      and "do not run the refused steps by hand" in out["reply"], out)
check("refused advisory: the trace output is the reply shown", r.output_text == out["reply"])
r = _adv_run()
r.add_tool({"name": "apply_patch", "arguments": _json.dumps({"server": "web-stg-01"}), "output": "{}",
            "ok": True, "decision": "allow", "origin": "model"})
out = pb_agent._refusal_report(r, {"reply": "Patched web-stg-01.", "tool_calls": []})
check("clean advisory: the model's reply stands", out["reply"] == "Patched web-stg-01.", out)

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
check("full read reports 13 open host-CVE pairs", len(r["result"]["open"]) == 13, r["result"]["open"])
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
ws = dana.get("/api/patchbot/workspace", headers=H).json()
check("finding list shows the approved change",
      any(f["cve"] == "CVE-2021-41773" and f.get("change_status") == "approved" for f in ws["findings"]), ws["findings"])
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

print("MCP servers and Cisco MCP Scanner")
from backend.patchbot import mcp_scan, store  # noqa: E402

anon = TestClient(main.app)
init = anon.post("/mcp/patchbot/dana.lee/patchops", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                                          "params": {"protocolVersion": "2025-06-18"}}).json()
check("MCP initialize", init["result"]["protocolVersion"] == "2025-06-18" and "tools" in init["result"]["capabilities"])
check("MCP notification is 202", anon.post("/mcp/patchbot/dana.lee/patchops",
                                           json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202)
listed = anon.post("/mcp/patchbot/dana.lee/patchops", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()
check("MCP tools/list serves PatchOps", {"apply_patch", "run_command"} <= {t["name"] for t in listed["result"]["tools"]})
called = anon.post("/mcp/patchbot/dana.lee/patchops", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                                            "params": {"name": "apply_patch", "arguments": {}}}).json()
check("MCP tools/call is refused", called["result"]["isError"] is True)
check("unknown owner seeds nothing", anon.post("/mcp/patchbot/nobody.here/vendor-advisories", json={
    "jsonrpc": "2.0", "id": 4, "method": "tools/list"}).status_code == 200 and store.peek_estate("nobody.here") is None)


def _fake_scanner(catalogue):
    """Stands in for mcp-scanner static: the rules the real yara rules apply here."""
    rows = []
    for t in catalogue["tools"]:
        threats = (["TOOL POISONING", "PROMPT INJECTION"] if "<IMPORTANT>" in t["description"] else
                   ["CODE EXECUTION"] if t["name"] == "run_command" else
                   ["SYSTEM MANIPULATION"] if t["name"] == "stop_service" else [])
        rows.append({"status": "completed", "is_safe": not threats, "tool_name": t["name"], "item_type": "tool",
                     "findings": {"yara_analyzer": {"severity": "HIGH" if threats else "SAFE", "threat_names": threats,
                                                    "threat_summary": "", "total_findings": len(threats),
                                                    "mcp_taxonomies": [{"aitech": "AITech-9.1"}] if threats else []}}})
    return {"server_url": "static:tools.json", "scan_results": rows, "requested_analyzers": ["yara"]}


_real_scanner = mcp_scan.run_scanner
mcp_scan.run_scanner = _fake_scanner
res = dana.post("/api/patchbot/mcp/scan", headers=H, json={}).json()["results"]
check("scan rates PatchOps unsafe", res["patchops"]["is_safe"] is False, res.get("patchops"))
rc = next(t for t in res["patchops"]["tools"] if t["tool"] == "run_command")
check("finding names its runtime control", rc["compensated_by"] == "deny-restricted-tools", rc)
check("clean vendor scans safe", res["vendor-advisories"]["is_safe"] is True)
check("tool findings reach Splunk", any(e["tool_name"] == "stop_service" for e in events("mcp_scan", "mcp_tool_finding")))
r = jo.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "connect"}).json()
check("viewer cannot connect a server", r["ok"] is False)
r = dana.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "connect"}).json()
check("clean scan connects the vendor", r["ok"] and not r["forced"], r)
check("connected vendor tool offered", "get_vendor_advisory" in [s["function"]["name"] for s in tools.schemas("dana.lee")])
dana.post("/api/patchbot/demo/vendor-mcp", headers=H, json={"poisoned": True})
check("rug pull voids the connection", not mcp_scan.vendor_usable(store.load_estate("dana.lee")))
dana.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "disconnect"})
r = dana.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "connect"}).json()
check("changed catalogue must be rescanned", not r["ok"] and "changed after the last scan" in r["message"], r)
dana.post("/api/patchbot/mcp/scan", headers=H, json={"server": "vendor-advisories"})
r = dana.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "connect"}).json()
check("poisoned vendor refused", not r["ok"] and "TOOL POISONING" in r["message"], r)
r = dana.post("/api/patchbot/mcp/vendor", headers=H, json={"action": "connect", "force": True}).json()
check("Demo Control forces it", r["ok"] and r["forced"], r)
desc = next(s["function"]["description"] for s in tools.schemas("dana.lee") if s["function"]["name"] == "get_vendor_advisory")
check("forced vendor offers its poisoned description", "<IMPORTANT>" in desc)
check("forced connect reaches Splunk", any(e.get("forced") for e in events("mcp_scan", "mcp_server_connected")))
mcp_scan.run_scanner = _real_scanner
mcp_scan.disconnect_vendor(Run(initiator=roles.Initiator("dana.lee", "linux_patch_operator", ["linux_patch_operator"]),
                               owner="dana.lee", kind="demo", session_id="testsession01"))

print("Splunk SOAR hand-off (automation API) and the attack console")
from backend.patchbot import automation  # noqa: E402
from backend.services import identity_lookup  # noqa: E402

_real_duo_user = identity_lookup.duo_user
_duo_dir = {"ravi.patel": {"state": "ok", "duo_status": "active", "groups": ["patch-windows"]},
            "gone.user": {"state": "ok", "duo_status": "disabled", "groups": ["patch-linux"]}}
identity_lookup.duo_user = lambda name: _duo_dir.get(name, {"state": "not_found"})
settings.duo_enabled = True
w = roles.from_username("ravi.patel")
check("Duo on: SOAR's operator gets the role from Duo groups",
      w is not None and w.role == "windows_patch_operator" and w.auth_method == "duo_directory", w)
check("Duo on: a disabled Duo user is refused", roles.from_username("gone.user") is None)
check("Duo on: a user Duo does not know is refused", roles.from_username("nobody.here") is None)
check("a malformed operator name is refused", roles.from_username("dana lee; drop") is None)
settings.duo_enabled = False
identity_lookup.duo_user = _real_duo_user

AUTO = "x-patchbot-automation-token"
soar = TestClient(main.app)
settings.patchbot_automation_token = ""
check("automation off: 503", soar.get("/api/patchbot/automation/health").status_code == 503)
settings.patchbot_automation_token = "test-automation-token"
check("automation: 401 without the token", soar.get("/api/patchbot/automation/health").status_code == 401)
check("automation: 401 with a wrong token",
      soar.get("/api/patchbot/automation/health", headers={AUTO: "nope"}).status_code == 401)
T = {AUTO: "test-automation-token"}
h = soar.get("/api/patchbot/automation/health", headers=T).json()
check("automation health names the shared estate", h.get("ok") and h.get("estate_owner") == "pseudoco", h)
automation.SYNC_EXECUTION = True
mcp_scan.run_scanner = _fake_scanner

r = soar.post("/api/patchbot/attack/exploit", json={"target": "web-prod-01"})
atk = r.json()
check("attack: the exploited server answers", r.status_code == 200 and atk.get("vulnerable") is True, atk)
check("attack: the inventory reached Splunk first", (atk.get("inventory") or {}).get("full_read") is True, atk)
web = events("web", "http_request")
trav = [e for e in web if "%2e" in e["uri_path"]]
check("attack: traversal requests are web events from the attacker",
      len(trav) == 3 and all(e["src"] == automation.ATTACKER and e["dest"] == "web-prod-01" and e["status"] == 200
                             for e in trav), trav)
check("attack: web events carry CIM Web fields", web and all(
    all(k in e for k in ("src", "dest", "http_method", "uri_path", "status", "http_user_agent", "action")) for e in web))
check("attack: no such web server, 404",
      soar.post("/api/patchbot/attack/exploit", json={"target": "dc-prod-01"}).status_code == 404)


def remediate(operator, **kw):
    return soar.post("/api/patchbot/automation/remediate", headers=T,
                     json={"cve": "CVE-2021-41773", "operator": operator, **kw})


check("remediate: unknown operator 403", remediate("nobody.here").status_code == 403)
check("remediate: unknown CVE 404", soar.post("/api/patchbot/automation/remediate", headers=T, json={
    "cve": "CVE-1999-0001", "operator": "dana.lee"}).status_code == 404)
check("remediate: 401 without the token", soar.post("/api/patchbot/automation/remediate", json={
    "cve": "CVE-2021-41773", "operator": "dana.lee"}).status_code == 401)
ES = {"investigation_id": "inv-test-1", "finding_id": "fnd-test-1", "requested_by": "es.analyst"}

r = remediate("ravi.patel", **ES)
rv = r.json()
check("Windows operator: 200 with every server denied", r.status_code == 200 and len(rv.get("results") or []) == 4
      and all(x["outcome"] == "denied" for x in rv["results"]), rv)
check("Windows operator: denied on create_change by deny-patch-outside-role-os",
      {(d["tool"], d["control"]) for d in rv.get("denied") or []} == {("create_change", "deny-patch-outside-role-os")},
      rv.get("denied"))
check("Windows operator: no change opened", rv.get("changes") == [], rv.get("changes"))
check("Windows operator: role from the role map", (rv.get("operator") or {}).get("role") == "windows_patch_operator")
pops = next((x for x in (rv.get("toolchain") or {}).get("servers", []) if x["server"] == "patchops"), {})
check("toolchain: PatchOps findings are compensated, verdict clean",
      rv.get("toolchain", {}).get("verdict") == "clean" and pops.get("verdict") == "COMPENSATED"
      and {c["control"] for c in pops.get("compensated") or []} == {"deny-restricted-tools"}, rv.get("toolchain"))
check("investigation read is reported, not fatal", (rv.get("investigation") or {}).get("found") is False
      and rv["investigation"]["read_via"] == "Splunk MCP Server", rv.get("investigation"))
denied_calls = [e for e in events("tool") if e.get("initiator") == "ravi.patel" and e.get("tool_name") == "create_change"]
check("the deny reaches Splunk with the ES ids", denied_calls and all(
    e["decision"] == "deny" and e.get("es_finding_id") == "fnd-test-1" and e.get("investigation_id") == "inv-test-1"
    and e.get("requested_via") == "splunk_soar" for e in denied_calls), denied_calls[:1])

r = remediate("dana.lee", **ES)
dv = r.json()
std = next((c for c in dv.get("changes") or [] if c["model"] == "standard"), None)
nrm = next((c for c in dv.get("changes") or [] if c["model"] == "normal"), None)
check("Linux operator: a pre-approved standard change for non-production",
      std and std["status"] == "approved" and std["template"] == "SC-APACHE-SEC"
      and sorted(std["servers"]) == ["web-dev-01", "web-stg-01"], dv.get("changes"))
check("Linux operator: a normal change waits for the Change Board",
      nrm and nrm["status"] == "awaiting_approval" and sorted(nrm["servers"]) == ["web-prod-01", "web-prod-02"],
      dv.get("changes"))
got = {x["server"]: x for x in dv.get("results") or []}
check("standard servers patched and verified", all(
    got.get(h, {}).get("outcome") == "patched" and got[h].get("verified") for h in ("web-dev-01", "web-stg-01")), got)
check("normal servers wait", all(got.get(h, {}).get("outcome") == "awaiting_approval"
                                 for h in ("web-prod-01", "web-prod-02")), got)
check("summary names both changes", std and nrm and std["change_id"] in dv["summary"]
      and nrm["change_id"] in dv["summary"], dv.get("summary"))
chg = store.get_change(nrm["change_id"]) if nrm else {}
check("the change keeps the ES ids", chg.get("investigation_id") == "inv-test-1" and chg.get("es_finding_id") == "fnd-test-1"
      and chg.get("es_requested_by") == "es.analyst" and chg.get("auto_execute") is True, chg)
check("the Change Board shows the template", (store.get_change(std["change_id"]) or {}).get("template_title")
      == est.STANDARD_CHANGE_TEMPLATE["title"] if std else False)
check("standard patches carry the change model", any(
    e.get("change_model") == "standard" and e["dest"] == "web-dev-01" for e in events("patch", "patch_installed")))
st = soar.get(f"/api/patchbot/automation/changes/{nrm['change_id']}", headers=T).json() if nrm else {}
check("change status: awaiting", st.get("status") == "awaiting_approval"
      and all(x["outcome"] == "awaiting_approval" for x in st.get("results") or []), st)
r = dana.post(f"/api/patchbot/changes/{nrm['change_id']}/decision", headers=H, json={"decision": "approve"})
check("the requester cannot approve it", r.status_code >= 400, r.text[:200])
r = sam.post(f"/api/patchbot/changes/{nrm['change_id']}/decision", headers=H, json={"decision": "approve", "note": "CAB ok"})
check("a Change Approver approves it", r.status_code == 200, r.text[:300])
st = soar.get(f"/api/patchbot/automation/changes/{nrm['change_id']}", headers=T).json()
check("the approval patched production on its own", all(x["outcome"] == "patched" for x in st.get("results") or []), st)
check("the change closed after its patches", st.get("status") == "closed", st.get("status"))
fixed = store.load_estate("pseudoco")
check("the CVE is gone from all four web servers", not any(
    est.is_vulnerable(fixed, h, "CVE-2021-41773") for h in est.APPLIES["CVE-2021-41773"]))
check("the approval ran as the requester", any(
    e.get("initiator") == "dana.lee" and e.get("requested_via") == "change_board_approval" and e["dest"] == "web-prod-02"
    for e in events("patch", "patch_installed")))
atk = soar.post("/api/patchbot/attack/exploit", json={"target": "web-prod-01"}).json()
check("attack after the patch: refused", atk.get("vulnerable") is False and all(
    q["status"] >= 400 for q in atk.get("requests") or [] if "%2e" in q["uri_path"]), atk)
check("remediate again: 404, nothing open", remediate("dana.lee").status_code == 404)


def _poisoned_scanner(catalogue):
    out = _fake_scanner(catalogue)
    for row in out["scan_results"]:
        if row["tool_name"] == "apply_patch":
            row["is_safe"] = False
            row["findings"]["yara_analyzer"].update(severity="HIGH", threat_names=["TOOL POISONING"], total_findings=1)
    return out


soar.post("/api/patchbot/automation/reset", headers=T)
st = store.load_estate("pseudoco")
check("reset: the web servers are vulnerable again", all(
    est.is_vulnerable(st, h, "CVE-2021-41773") for h in est.APPLIES["CVE-2021-41773"]))
mcp_scan.run_scanner = _poisoned_scanner
sc = soar.post("/api/patchbot/automation/toolchain/scan", headers=T).json()
check("rescan: a poisoned PatchOps is unsafe", sc.get("verdict") == "unsafe" and "patchops" in sc.get("unsafe", []), sc)
r = remediate("dana.lee", **ES)
check("unsafe toolchain: 409 and nothing runs", r.status_code == 409
      and r.json().get("toolchain", {}).get("verdict") == "unsafe"
      and not store.list_changes(owner="pseudoco", statuses=["awaiting_approval", "approved"]), r.text[:300])
mcp_scan.run_scanner = _fake_scanner
sc = soar.post("/api/patchbot/automation/toolchain/scan", headers=T).json()
check("rescan after the fix: clean", sc.get("verdict") == "clean", sc)
mcp_scan.run_scanner = _real_scanner
automation.SYNC_EXECUTION = False
check("SOAR sessions are marked in Splunk", any(
    e.get("requested_via") == "splunk_soar" for e in events("session", "session_started")))

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
