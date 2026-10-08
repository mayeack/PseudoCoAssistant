"""Read Agent Observability evaluator scores for turns recorded by drive_turns.py.

For each turn: the theme's Agent stream (named after the theme label) -> the llm
span(s) whose gen_ai.conversation.id is the turn's session -> the value / status /
rationale of every CUSTOM llm evaluator enabled on that stream. Polls until every
turn has a terminal status for each custom evaluator, or the timeout.

usage: ao_scores.py <turns.json> [timeout_s] [out.json]
"""
import json
import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from aoapi import project_id, req  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

PRESETS_AND_IGNORED = {"preset"}


def custom_scorers(pid, stream_id):
    c, ms = req("GET", f"/projects/{pid}/log_streams/{stream_id}/metric_settings")
    return {s["id"]: s["name"] for s in (ms.get("scorers") or []) if s.get("scorer_type") == "llm"
            and "custom" not in PRESETS_AND_IGNORED and s["name"] not in ("mb-pii",)}


def _meta(span):
    """The app's own ids ride in the ``splunk_ao.metadata`` user-metadata blob."""
    m = (span.get("user_metadata") or {}).get("splunk_ao.metadata")
    if isinstance(m, str):
        try:
            return json.loads(m)
        except ValueError:
            return {}
    return m or {}


def spans_by_request(pid, stream_id, limit=300):
    c, r = req("POST", f"/projects/{pid}/spans/search", {
        "log_stream_id": stream_id, "limit": limit,
        "filters": [{"column_id": "type", "operator": "eq", "value": "llm", "type": "text"}],
        "sort": {"name": "created_at", "ascending": False, "sort_type": "column"}})
    out = {}
    for s in (r.get("records") or []) if c == 200 else []:
        rid = _meta(s).get("request_id")
        if rid:
            out.setdefault(rid, []).append(s)
    return out


def main():
    turns = json.load(open(sys.argv[1]))
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 600
    dest = sys.argv[3] if len(sys.argv) > 3 else None
    pid = project_id()
    c, streams = req("GET", f"/projects/{pid}/log_streams")
    stream_ids = {s["name"]: s["id"] for s in streams}
    deadline = time.time() + timeout
    while True:
        rows, pending = [], 0
        cache = {}
        for t in turns:
            label = THEMES[t["theme"]].label
            sid = stream_ids.get(label)
            if sid not in cache:
                cache[sid] = (custom_scorers(pid, sid), spans_by_request(pid, sid)) if sid else ({}, {})
            scorers, by_request = cache[sid]
            spans = by_request.get(t.get("request_id"), [])
            row = {"theme": t["theme"], "boundary": t["boundary"], "request_id": t.get("request_id"),
                   "app_detected": [g["authority_detected"] for g in t.get("governance", [])],
                   "llm_spans": len(spans), "scores": {}}
            for scorer_id, name in scorers.items():
                vals = []
                for s in spans:
                    m = s.get("metrics") or {}
                    mi = (s.get("metric_info") or {}).get(scorer_id)
                    status = m.get(f"{scorer_id}_status") or (json.loads(mi).get("status_type") if isinstance(mi, str) else (mi or {}).get("status_type"))
                    err = None
                    if isinstance(mi, str):
                        try:
                            err = json.loads(mi).get("message")
                        except ValueError:
                            err = mi[:200]
                    vals.append({"value": m.get(scorer_id), "status": status, "error": err,
                                 "rationale": (m.get(f"{scorer_id}_rationale") or "")[:600]})
                row["scores"][name] = vals
                if not spans or any(v["status"] in (None, "pending", "in_progress") for v in vals):
                    pending += 1
            rows.append(row)
        if dest:
            json.dump(rows, open(dest, "w"), indent=1)
        if not pending or time.time() > deadline:
            break
        print(f"waiting: {pending} scores pending", flush=True)
        time.sleep(30)
    for r in rows:
        sc = {n: [(v["value"], v["status"]) for v in vs] for n, vs in r["scores"].items()}
        print(f"{r['theme']:15s} {'ON ' if r['boundary'] else 'OFF'} app={r['app_detected']} spans={r['llm_spans']} {sc}")
    print("PENDING" if pending else "ALL SCORED", flush=True)


if __name__ == "__main__":
    main()
