"""Create the per-theme outside-of-authority custom LLM evaluators in Splunk Agent
Observability and enable each on its theme's Agent stream.

Shape is copied from the two already deployed in this org (prescriptive_overreach,
unauthorized_commitment): scorer_type llm, output percentage, 1 judge, CoT on,
scoreable_node_types ["llm"], model "Claude Haiku 4.5" (verified scoring today).

Idempotent: an evaluator that already exists by name is reused (a new version is
added only with --new-version); a stream that already has it enabled is left alone.

usage: provision_evaluators.py <drafts.json> [--apply] [--themes a,b] [--new-version]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from aoapi import project_id, req  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

MODEL = "Claude Haiku 4.5"
NUM_JUDGES = 1
APPLY = "--apply" in sys.argv
NEW_VERSION = "--new-version" in sys.argv
ONLY = next((a.split("=", 1)[1].split(",") for a in sys.argv if a.startswith("--themes=")), None)


def existing_scorers():
    c, r = req("POST", "/scorers/list", {"filters": [{"name": "scorer_type", "value": "llm", "operator": "eq"}]})
    items = r.get("scorers", r) if isinstance(r, dict) else r
    return {s["name"]: s for s in items}


def create_scorer(name, rubric, description):
    body = {
        "name": name, "scorer_type": "llm", "description": description, "tags": ["custom"],
        "defaults": {"model_name": MODEL, "num_judges": NUM_JUDGES, "cot_enabled": True},
        "scoreable_node_types": ["llm"], "output_type": "percentage", "ground_truth": False,
    }
    c, r = req("POST", "/scorers", body)
    if c not in (200, 201):
        raise SystemExit(f"create scorer {name} -> {c} {str(r)[:400]}")
    sid = r["id"]
    c, v = req("POST", f"/scorers/{sid}/version/llm", {
        "user_prompt": rubric, "model_name": MODEL, "num_judges": NUM_JUDGES,
        "cot_enabled": True, "output_type": "percentage", "scoreable_node_types": ["llm"]})
    if c not in (200, 201):
        raise SystemExit(f"create version {name} -> {c} {str(v)[:400]}")
    return sid, v


def enable_on_stream(pid, stream_id, stream_name, scorer_id, scorer_version_id, name):
    c, ms = req("GET", f"/projects/{pid}/log_streams/{stream_id}/metric_settings")
    current = ms.get("scorers") or []
    if any(s["id"] == scorer_id for s in current):
        print(f"    already enabled on {stream_name}")
        return current
    keep = [{k: s[k] for k in ("id", "scorer_type", "name", "model_name", "num_judges",
                               "scoreable_node_types", "cot_enabled", "output_type", "input_type",
                               "scorer_version_id", "roll_up_method", "filters") if s.get(k) is not None}
            for s in current]
    keep.append({"id": scorer_id, "scorer_type": "llm", "name": name, "model_name": MODEL,
                 "num_judges": NUM_JUDGES, "scoreable_node_types": ["llm"], "cot_enabled": True,
                 "output_type": "percentage", "input_type": "llm_spans",
                 "scorer_version_id": scorer_version_id, "roll_up_method": "average"})
    c, r = req("PATCH", f"/projects/{pid}/log_streams/{stream_id}/metric_settings",
               {"scorers": keep, "segment_filters": ms.get("segment_filters") or []})
    if c not in (200, 201):
        raise SystemExit(f"enable {name} on {stream_name} -> {c} {str(r)[:400]}")
    return keep


def main():
    drafts = {d["theme"]: d for d in json.load(open(sys.argv[1]))}
    pid = project_id()
    c, streams = req("GET", f"/projects/{pid}/log_streams")
    stream_ids = {s["name"]: s["id"] for s in streams}
    have = existing_scorers()
    themes = ONLY or list(THEMES)
    for key in themes:
        d = drafts.get(key)
        if not d:
            print(f"{key}: no draft, skipped")
            continue
        label = THEMES[key].label
        name = d["evaluator_name"]
        sid = stream_ids.get(label)
        print(f"\n== {key} -> evaluator '{name}' on stream '{label}' ({sid})")
        if not sid:
            print("    NO STREAM — skipped")
            continue
        scorer = have.get(name)
        if scorer and not NEW_VERSION:
            print(f"    evaluator exists ({scorer['id']}) — reusing, not re-versioning")
            scorer_id = scorer["id"]
            version_id = (scorer.get("latest_version") or {}).get("id")
            if not version_id:
                c, full = req("GET", f"/scorers/{scorer_id}")
                version_id = (full.get("latest_version") or {}).get("id")
        elif not APPLY:
            print(f"    WOULD CREATE evaluator ({len(d['evaluator_rubric'])} chars) + enable on stream")
            continue
        else:
            scorer_id, version = create_scorer(name, d["evaluator_rubric"],
                                               f"Outside-of-authority control for the {label} theme "
                                               f"({d['policy_studio_profile_name']}).")
            version_id = version["id"]
            print(f"    created scorer {scorer_id} version {version_id}")
        if not APPLY:
            print("    (dry run: not enabling)")
            continue
        enable_on_stream(pid, sid, label, scorer_id, version_id, name)
        c, ms = req("GET", f"/projects/{pid}/log_streams/{sid}/metric_settings")
        print("    stream now scores:", [s["name"] for s in (ms.get("scorers") or [])])


if __name__ == "__main__":
    main()
