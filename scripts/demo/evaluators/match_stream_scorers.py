"""Make every theme's Agent stream score with the same evaluators as a template stream.

The template (default MedAdvice) defines the column set. Its own outside-of-authority
evaluator (from authority_evaluators.json) is swapped, in place, for each target theme's
evaluator, so every stream gets the shared evaluators plus exactly its own
outside-of-authority one. Evaluators the template does not have are removed from the
target. The theme evaluator keeps the version currently enabled on the target stream
(or its latest version if it is not enabled there yet).

Dry run by default; --apply PATCHes metric_settings and reads it back.

usage: match_stream_scorers.py [--apply] [--template=MedAdvice] [--themes=a,b]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from aoapi import project_id, req  # noqa: E402
from backend.agents.themes import THEMES  # noqa: E402

APPLY = "--apply" in sys.argv
TEMPLATE = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--template=")), "MedAdvice")
ONLY = next((a.split("=", 1)[1].split(",") for a in sys.argv if a.startswith("--themes=")), None)
KEYS = ("id", "scorer_type", "name", "model_name", "num_judges", "scoreable_node_types", "cot_enabled",
        "output_type", "input_type", "scorer_version_id", "roll_up_method", "filters")


def entry(s):
    return {k: s[k] for k in KEYS if s.get(k) is not None}


def metric_settings(pid, stream_id):
    c, ms = req("GET", f"/projects/{pid}/log_streams/{stream_id}/metric_settings")
    if c != 200:
        raise SystemExit(f"metric_settings {stream_id} -> {c} {str(ms)[:300]}")
    return ms


def latest_version_id(scorer_id):
    c, full = req("GET", f"/scorers/{scorer_id}")
    return (full.get("latest_version") or {}).get("id")


def main():
    drafts = json.load(open(Path(__file__).resolve().parent / "authority_evaluators.json"))
    authority = {d["theme"]: d["evaluator_name"] for d in drafts}
    by_label = {t.label: key for key, t in THEMES.items()}
    pid = project_id()
    c, streams = req("GET", f"/projects/{pid}/log_streams")
    stream_ids = {s["name"]: s["id"] for s in streams}

    template = metric_settings(pid, stream_ids[TEMPLATE])
    template_own = authority[by_label[TEMPLATE]]
    names = [s["name"] for s in template["scorers"]]
    if template_own not in names:
        raise SystemExit(f"template {TEMPLATE} does not score with its own evaluator {template_own}")
    print(f"template {TEMPLATE}: {names}")

    c, r = req("POST", "/scorers/list", {"filters": [{"name": "scorer_type", "value": "llm", "operator": "eq"}]})
    llm_scorers = {s["name"]: s for s in (r.get("scorers", r) if isinstance(r, dict) else r)}

    for key in ONLY or list(THEMES):
        label = THEMES[key].label
        if label == TEMPLATE:
            continue
        sid = stream_ids.get(label)
        if not sid:
            print(f"\n{label}: no Agent stream yet (send one chat turn on the theme first) — skipped")
            continue
        own = authority[key]
        current = metric_settings(pid, sid)
        on_stream = {s["name"]: s for s in current["scorers"]}
        if own in on_stream:
            own_entry = entry(on_stream[own])
        else:
            s = llm_scorers[own]
            own_entry = {"id": s["id"], "scorer_type": "llm", "name": own,
                         "scorer_version_id": latest_version_id(s["id"])}
            own_entry.update({k: v for k, v in entry(next(x for x in template["scorers"]
                                                          if x["name"] == template_own)).items()
                              if k in ("model_name", "num_judges", "scoreable_node_types", "cot_enabled",
                                       "output_type", "input_type", "roll_up_method")})
        wanted = [own_entry if s["name"] == template_own else entry(s) for s in template["scorers"]]
        before = list(on_stream)
        after = [s["name"] for s in wanted]
        print(f"\n== {label} ({sid})")
        print(f"   now:    {before}")
        print(f"   target: {after}")
        print(f"   adds {sorted(set(after) - set(before))}, removes {sorted(set(before) - set(after))}")
        if before == after:
            print("   already matches")
            continue
        if not APPLY:
            continue
        c, r = req("PATCH", f"/projects/{pid}/log_streams/{sid}/metric_settings",
                   {"scorers": wanted, "segment_filters": current.get("segment_filters") or []})
        if c not in (200, 201):
            raise SystemExit(f"PATCH {label} -> {c} {str(r)[:400]}")
        got = [s["name"] for s in metric_settings(pid, sid)["scorers"]]
        print(f"   applied: {got}", "OK" if got == after else "MISMATCH")


if __name__ == "__main__":
    main()
