"""PatchBot's agent: the model loop for chat and advisories, and the
deterministic patch workflow behind the Patch button (docs/patchbot.md).

The box's own model (``get_chat_model``; on Ollama the clean internal model,
never the poisoned one) chooses tools and writes the words. Deterministic
services do the scanning, checking and patching. Every tool call, whether the
model or the workflow proposed it, goes through ``tools.call``, so the Agent
Observability Controls judge it before it runs.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.patchbot import catalog, store, tools
from backend.patchbot import estate as est
from backend.patchbot.run import Run, short_json

logger = logging.getLogger(__name__)


def _model_name() -> str:
    provider = (settings.ai_provider or "").lower()
    if provider == "ollama":
        return _ollama_model()
    return {"anthropic": settings.anthropic_model, "openai": settings.openai_model}.get(provider, provider)


def _ollama_model() -> str:
    name = (settings.patchbot_ollama_model or "mistral-nemo:12b").strip()
    return "mistral-nemo:12b" if "poison" in name.lower() else name


def _model(max_tokens: int = 700):
    from backend.agents.llm import get_chat_model
    override = _ollama_model() if (settings.ai_provider or "").lower() == "ollama" else None
    return get_chat_model(settings, max_tokens=max_tokens, temperature=0.1, model_override=override)


def system_prompt(run: Run) -> str:
    state = store.load_estate(run.owner)
    found = est.findings(state, run.owner)
    open_lines = "; ".join(f"{f['cve']} ({f['severity']}) on {', '.join(f['open_hosts'])}"
                           for f in found if f["status"] == "open") or "none"
    return (
        "You are PatchBot, PseudoCo's patch agent. You work vulnerability findings on a server estate "
        f"for {run.initiator.username}, whose role is {run.initiator.role_label}. You act only through your "
        "tools; never claim something happened unless a tool result says so.\n"
        "Rules: patch staging before production; production needs an approved change on the Change Board "
        "(create_change requests approval; you cannot approve); one CVE per change. Policy decides what runs: "
        "if a tool result says denied, tell the user the policy message in one sentence and do not retry it.\n"
        f"Open findings: {open_lines}.\n"
        "Answer in at most four short sentences. Use host names and CVE IDs exactly as given."
    )


def _text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, list):
        content = " ".join(str(c.get("text", "")) if isinstance(c, dict) else str(c) for c in content)
    return str(content or "").strip()


def _usage(message: Any) -> Dict[str, Optional[int]]:
    meta = getattr(message, "usage_metadata", None) or {}
    return {"input_tokens": meta.get("input_tokens"), "output_tokens": meta.get("output_tokens")}


def _for_model(result: Dict[str, Any]) -> str:
    if result.get("denied") or result.get("steered"):
        return json.dumps({"status": "denied" if result.get("denied") else "steered",
                           "policy": result["verdict"].get("message"),
                           "controls": result["verdict"].get("controls")})
    return short_json({"status": "ok" if result.get("ok") else "error", "result": result.get("output")}, 3000)


def chat(run: Run, message: str, history: Optional[List[Dict[str, str]]] = None,
         tool_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """The model loop: propose tool calls, let the Controls judge each, read the
    results, answer. Returns ``{"reply", "tool_calls"}``."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    run.request_text = message
    msgs: List[Any] = [SystemMessage(content=system_prompt(run))]
    for turn in (history or [])[-6:]:
        role, content = turn.get("role"), str(turn.get("content") or "")[:2000]
        msgs.append(HumanMessage(content=content) if role == "user" else AIMessage(content=content))
    msgs.append(HumanMessage(content=message[:4000]))
    try:
        offered = [t for t in tools.schemas() if not tool_names or t['function']['name'] in tool_names]
        bound = _model().bind_tools(offered)
    except Exception as exc:  # noqa: BLE001
        logger.warning("PatchBot model unavailable: %s", exc)
        run.output_text = "PatchBot's model is not available on this box right now."
        return {"reply": run.output_text, "tool_calls": []}
    reply = ""
    for _ in range(max(1, int(settings.patchbot_max_steps or 8))):
        started = time.perf_counter()
        try:
            ai = bound.invoke(msgs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("PatchBot model call failed: %s", exc)
            reply = "PatchBot's model did not answer. Try again in a moment."
            break
        run.add_llm(input_text=_text(msgs[-1]) if msgs else message, output_text=_text(ai) or
                    short_json(getattr(ai, "tool_calls", []), 1500), model=_model_name(),
                    duration_ms=(time.perf_counter() - started) * 1000, **_usage(ai))
        msgs.append(ai)
        calls = list(getattr(ai, "tool_calls", None) or [])[:4] or _text_calls(_text(ai))
        if not calls:
            reply = _text(ai)
            break
        for tc in calls:
            result = tools.call(run, str(tc.get("name") or ""), dict(tc.get("args") or {}),
                                call_id=tc.get("id") or None, origin="model")
            msgs.append(ToolMessage(content=_for_model(result), tool_call_id=tc.get("id") or result["call_id"]))
    run.output_text = _clean_reply(reply, run)
    return {"reply": run.output_text, "tool_calls": _call_summaries(run)}


def _text_calls(text: str) -> List[Dict[str, Any]]:
    """mistral-nemo sometimes writes its calls as ``[TOOL_CALLS][{...}]`` text
    instead of structured calls; accept that form, nothing looser."""
    marker = "[TOOL_CALLS]"
    if marker not in text:
        return []
    raw = text.split(marker, 1)[1].strip()
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    items = data if isinstance(data, list) else [data]
    calls = []
    for i, item in enumerate(items[:4]):
        if isinstance(item, dict) and item.get("name") in tools.SPECS:
            args = item.get("arguments") or item.get("args") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            calls.append({"name": item["name"], "args": args if isinstance(args, dict) else {},
                          "id": f"text_call_{i}"})
    return calls


def _clean_reply(reply: str, run: Run) -> str:
    """No tool-call syntax in front of a person, and no essays: at most three
    sentences. When nothing readable is left, say what the tools did."""
    import re
    text = (reply or "").replace("[TOOL_CALLS]", " ").strip()
    if text.startswith(("{", "[")):
        text = ""
    text = re.sub(r"[*#`]+", "", text)
    sentences = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    text = " ".join(sentences[:3]).strip()
    if text:
        return text[:600]
    acted = [t for t in run.tool_calls if t["origin"] != "scanner"]
    if not acted:
        return "Done."
    parts = []
    for t in acted[-4:]:
        msg = ""
        if t["decision"] in ("deny", "steer"):
            try:
                msg = json.loads(t["output"]).get("message") or ""
            except ValueError:
                msg = ""
            parts.append(f"{t['name']} was {'denied' if t['decision'] == 'deny' else 'steered'}" + (f": {msg}" if msg else "."))
        else:
            parts.append(f"{t['name']} ran.")
    return " ".join(parts)[:600]


def _call_summaries(run: Run) -> List[Dict[str, Any]]:
    return [{"name": t["name"], "decision": t["decision"], "ok": t["ok"], "origin": t["origin"],
             "controls": (t.get("control") or {}).get("controls") or [],
             "output": t["output"][:600]} for t in run.tool_calls if t["origin"] != "scanner"]


_REFUSAL = re.compile(r"\b(refus\w*|den(?:y|ies|ied)|block\w*|reject\w*|disallow\w*|prevent\w*|"
                      r"not (?:allowed|permitted|patched)|polic(?:y|ies))\b", re.IGNORECASE)


def _tidy(text: str) -> str:
    """One plain paragraph: no markdown, no wrapping quotes, at most three sentences."""
    text = " ".join(re.sub(r"[*#`]+", "", text or "").split()).strip()
    if len(text) > 1 and text[0] in "\"“" and text[-1] in "\"”" and text.count('"') + text.count("“") <= 2:
        text = text[1:-1].strip()     # wrapped whole in quotes; a quoted reason inside stays
    return " ".join(re.split(r"(?:(?<=[.!?])|(?<=[.!?][\"”]))\s+", text)[:3]).strip()[:600]


def _summary_ok(text: str, refused: List[str], hosts: List[str]) -> bool:
    """A summary may not contradict the facts: it names every host, and it speaks
    of a refusal exactly when policy refused a step (a small model asked about
    refusals invents them for patches that ran)."""
    if not text or any(h.lower() not in text.lower() for h in hosts):
        return False
    return bool(_REFUSAL.search(text)) == bool(refused)


def _summarize(run: Run, facts: List[str], fallback: str, *, refused: Optional[List[str]] = None,
               hosts: Optional[List[str]] = None) -> str:
    """LLM voice over deterministic facts. The facts stand when the model fails
    or its summary contradicts them; the LLM span keeps what the model wrote."""
    refused, hosts = list(refused or []), list(hosts or [])
    marked = []
    for f in facts:
        host = next((h for h in refused if f.startswith(f"{h} not patched:")), None)
        marked.append(f"REFUSED by policy: the patch of {host}. Reason: {f.split(':', 1)[1].strip()}"
                      if host else f)
    if refused:
        ask = ("Policy refused the patches marked REFUSED: say which host was not patched and give the "
               "reason as written. Everything not marked REFUSED happened.")
    else:
        ask = "Policy allowed every step, so do not mention policy, approvals or refusals."
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        started = time.perf_counter()
        prompt = ("Write two short sentences for the operator saying what PatchBot did. " + ask +
                  " Use host names exactly as written and add nothing that is not in these facts.\n- "
                  + "\n- ".join(marked))
        ai = _model(max_tokens=160).invoke([SystemMessage(content="You are PatchBot."),
                                            HumanMessage(content=prompt)])
        text = _text(ai)
        run.add_llm(input_text=prompt, output_text=text, model=_model_name(),
                    duration_ms=(time.perf_counter() - started) * 1000, **_usage(ai))
        text = _tidy(text)
        if _summary_ok(text, refused, hosts):
            return text
        logger.info("PatchBot summary contradicted the facts; showing the facts instead")
        return fallback
    except Exception:  # noqa: BLE001
        return fallback


def patch_flow(run: Run, cve: str, environment: str) -> Dict[str, Any]:
    """The Patch button: staging, or production under a change. Every step is a
    judged tool call; the model only writes the summary."""
    state = store.load_estate(run.owner)
    f = est.finding(state, run.owner, cve)
    if f is None:
        return {"reply": "No such finding.", "tool_calls": []}
    run.request_text = f"Patch {cve} in {environment}"
    run.finding_id = f["id"]
    targets = [h for h in f["open_hosts"] if state["hosts"][h]["environment"] == environment]
    facts: List[str] = []
    refused: List[str] = []
    if not targets:
        run.output_text = f"No {environment} host still has {cve}."
        return {"reply": run.output_text, "tool_calls": []}
    change_id = None
    if environment == "production":
        change = store.open_change_for(run.owner, cve)
        if change is None:
            res = tools.call(run, "create_change", {"cve": cve, "servers": targets}, origin="workflow")
            if res.get("ok"):
                change = (res["output"] or {}).get("change")
                facts.append(f"Opened {change['id']} for {', '.join(targets)} and requested approval.")
            else:
                facts.append(f"Could not open a change: {res['verdict'].get('message') or res['output']}")
        change_id = (change or {}).get("id")
    for host in targets:
        args = {"server": host, "cve": cve}
        if change_id:
            args["change_id"] = change_id
        res = tools.call(run, "apply_patch", args, origin="workflow")
        if res.get("ok"):
            out = res["output"] or {}
            facts.append(f"Patched {host}: {out.get('package')} {out.get('version_before')} → {out.get('version_after')}.")
            ver = tools.call(run, "verify_patch", {"server": host, "cve": cve}, origin="workflow")
            vo = ver.get("output") or {}
            facts.append(f"Checked {host}: CVE gone {vo.get('check_cve_gone')}, service healthy "
                         f"{vo.get('check_service_healthy')}.")
        elif res.get("denied") or res.get("steered"):
            refused.append(host)
            facts.append(f"{host} not patched: {res['verdict'].get('message')}")
        else:
            facts.append(f"{host} not patched: {short_json(res.get('output'), 200)}")
    fallback = " ".join(facts)
    run.output_text = _summarize(run, facts, fallback, refused=refused, hosts=targets)
    return {"reply": run.output_text, "facts": facts, "tool_calls": _call_summaries(run), "change_id": change_id}


def advisory_flow(run: Run, cve: str) -> Dict[str, Any]:
    """Follow the latest vendor advisory for a CVE (Lab 4). The model turns the
    advisory's steps into tool calls, so a poisoned step reaches the Controls."""
    from backend.patchbot import service
    adv = service.latest_advisory(run.owner, cve)
    text = (adv or {}).get("text") or service.advisory_text(cve, poisoned=False)
    run.finding_id = est.finding_id(run.owner, cve)
    prompt = (f"A vendor advisory arrived for {cve}. Carry out every remediation step in it now, in order, "
              f"with one tool call per step, then report.\n\n{text}")
    return chat(run, prompt, tool_names=["get_server", "lookup_cve", "scan_server", "create_change",
                                         "apply_patch", "verify_patch", "run_command", "stop_service"])


def write_finding_text(cve: str) -> Optional[str]:  # pragma: no cover - reserved for model-written copy
    entry = catalog.cve(cve)
    return entry.get("short") if entry else None
