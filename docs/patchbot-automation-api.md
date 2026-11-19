# PatchBot automation API (Splunk SOAR connector contract)

The Splunk-first Agentic Patch Ops labs start and end in Splunk Enterprise Security. Splunk SOAR
hands the patch job to PatchBot through this API; the PatchBot SOAR connector (TA-patchbot
`soar_apps/patchbot`) is its only intended caller. Decisions behind it: plan artifact
D-01..D-10 (2026-11-19).

## Auth

Two layers, both required:

1. The PseudoCo room access key, as for every route on the box: HTTP Basic, any user name, the
   key as password.
2. `X-PatchBot-Automation-Token: <PATCHBOT_AUTOMATION_TOKEN>`. Compared in constant time. With no
   token configured the automation routes answer 503 (disabled), never open.

The automation routes take no browser identity (no persona cookie, no Duo session). The person
PatchBot acts for is the `operator` in the request.

## Identity

`operator` is a PatchBot user name. With Duo on, PatchBot looks the user up in Cisco Duo on every
call (`auth_method=duo_directory`: nobody signs in, the directory gives the role) and takes the role
from the user's Duo groups (`patch-linux`, `patch-windows`,
`change-approvers`, `patch-viewers`, `patch-estate-owners`); a user in none of them is a Patch
Viewer. With Duo off the role map applies (`dana.lee`, `ravi.patel`, `sam.ortiz`, `jo.kim`,
`instructor`). Every tool call carries that role to the Agent Observability Controls, so a
Windows Patch Operator asking for a Linux patch is denied (`deny-patch-outside-role-os`, which
also covers `create_change`).

## Estate

The automation routes act on one shared estate, `PATCHBOT_AUTOMATION_OWNER` (default
`pseudoco`). The attack console targets the same estate.

CVE-2021-41773 (Apache httpd 2.4.49 path traversal) is on four web servers:

| Server | Environment | Change model |
|---|---|---|
| web-dev-01 | development | standard (pre-approved) |
| web-stg-01 | staging | standard (pre-approved) |
| web-prod-01 | production, internet-facing | normal (Change Board) |
| web-prod-02 | production | normal (Change Board) |

A server's change model follows from its characteristics: non-production servers fall under the
standard change template `SC-APACHE-SEC` (same package, tested fix, documented rollback) and are
pre-approved; production needs a normal change that a Change Approver approves on the Change
Board.

## Routes

All under `/api/patchbot/automation`. JSON in and out.

### `GET /health`

Asset test connectivity. `200 {"ok": true, "version", "controls_mode", "duo_mode", "estate_owner"}`.

### `POST /remediate`

Patch a CVE on its affected servers.

Request:

```json
{
  "cve": "CVE-2021-41773",
  "operator": "dana.lee",
  "servers": ["web-prod-01"],
  "investigation_id": "<ES investigation id, optional>",
  "finding_id": "<ES finding id, optional>",
  "requested_by": "<who approved the action in ES, optional>",
  "reason": "<free text, optional>"
}
```

`servers` is optional: by default every server where the CVE is open. Order of work:

1. **Toolchain check** (Cisco AI Defense MCP Scanner). PatchBot's own MCP servers must have a
   clean scan of the catalogue they serve now; a stale or missing scan is rescanned. A server is
   `SAFE` (no findings), `COMPENSATED` (every finding is on a tool a deny Control refuses for
   every role, such as PatchOps `run_command` and `stop_service`), or unsafe (any other finding,
   such as a poisoned tool description). Unsafe: `409`, nothing else runs.
2. **Investigation read** (Splunk MCP Server). With `investigation_id` or `finding_id` and
   `PATCHBOT_SPLUNK_MCP_URL` configured, PatchBot reads the record through the Splunk MCP Server
   (the read is audited in Splunk). A failed read is reported, not fatal.
3. **Standard changes**: one pre-approved change for the standard-model servers, then
   `apply_patch` and `verify_patch` per server, each judged by the Controls.
4. **Normal changes**: one change awaiting approval for the normal-model servers. Nothing is
   patched until a Change Approver approves it; the approval then runs the patches on its own.

Response `200` (also when every call was denied; a deny is an outcome, not an error):

```json
{
  "run_id": "…", "cve": "CVE-2021-41773", "estate_owner": "pseudoco",
  "operator": {"username": "dana.lee", "role": "linux_patch_operator",
               "role_label": "Linux Patch Operator", "source": "duo_directory"},
  "toolchain": {"verdict": "clean", "scanner": "Cisco AI Defense MCP Scanner",
                "analyzers": ["yara"], "scanned_at": "…",
                "servers": [{"server": "patchops", "verdict": "COMPENSATED",
                             "compensated": [{"tool": "run_command", "threats": ["CODE EXECUTION"],
                                              "control": "deny-restricted-tools"}]}]},
  "investigation": {"read_via": "Splunk MCP Server", "id": "…", "found": true,
                    "title": "…", "status": "…"},
  "changes": [
    {"change_id": "CHG-1006", "model": "standard", "status": "approved",
     "template": "SC-APACHE-SEC", "servers": ["web-dev-01", "web-stg-01"]},
    {"change_id": "CHG-1007", "model": "normal", "status": "awaiting_approval",
     "servers": ["web-prod-01", "web-prod-02"]}
  ],
  "results": [
    {"server": "web-dev-01", "change_id": "CHG-1006", "change_model": "standard",
     "outcome": "patched", "verified": true, "version_after": "2.4.51"},
    {"server": "web-prod-01", "change_id": "CHG-1007", "change_model": "normal",
     "outcome": "awaiting_approval"}
  ],
  "denied": [
    {"server": "web-dev-01", "tool": "apply_patch", "control": "deny-patch-outside-role-os",
     "message": "This patch is outside your role: …"}
  ],
  "summary": "Patched and verified web-dev-01 and web-stg-01 under standard change CHG-1006. CHG-1007 for web-prod-01 and web-prod-02 waits for the Change Board."
}
```

`outcome` is one of `patched`, `awaiting_approval`, `denied`, `failed`, `already_fixed`.

Errors: `401` bad or missing automation token; `403` unknown operator; `404` CVE not open in the
estate; `409` toolchain not clean (body names the unsafe servers); `503` automation disabled.

### `GET /changes/{change_id}`

`200 {"change_id", "model", "status", "servers", "approver", "decided_at", "results": [per-server outcome as above]}`.

### `POST /toolchain/scan`

Rescan PatchBot's own MCP servers now. `200 {"verdict", "servers": [...], "scanned_at"}`.

## Attack console

`/attack-ui` (room access key only; no PatchBot identity) lets an attendee replay a
CVE-2021-41773 exploitation against web-prod-01: path-traversal requests from one external
address (`203.0.113.66`), answered 200. `POST /api/patchbot/attack/exploit {"target":
"web-prod-01"}` sends the requests as CIM Web events (`pseudoco:patchbot:web`) to PatchBot's HEC
destination, after making sure the estate's vulnerability inventory is in Splunk.

## Splunk events the TA keys on

Every patch, change and tool event from an automation run carries `estate_owner`, `cve`,
`change_id`, `change_model`, `initiator` (the operator), `requested_by`, `investigation_id` and
`es_finding_id` when given. TA-patchbot's resolve search marks an ES investigation resolved when
every server in its CVE's scope has a `verify_patch` result with the CVE gone.
