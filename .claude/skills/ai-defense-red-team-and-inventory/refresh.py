#!/usr/bin/env python3
"""Keep PseudoCo Assistant's Cisco AI Defense data fresh.

Two jobs, both against the PseudoCo SCC org:

* AI Inventory: scan PseudoCo Assistant's ``main`` with Cisco's ``cisco-aibom``
  and upload the report (AI Defense -> AI Inventory).
* AI Red Teaming: start a run of the "AI Defense Quick Start" profile against
  the PseudoCo Assistant targets, wait for it, and summarize the results
  against the previous run of the same target.

Read SKILL.md next to this file before running it. Usage:

    python3 refresh.py setup            # venv + catalog in ~/.ai-defense-refresh
    python3 refresh.py preflight        # every check, changes nothing
    python3 refresh.py inventory        # scan (or re-upload) + upload
    python3 refresh.py redteam-start    # start a run, print its task_id
    python3 refresh.py redteam-wait  TASK_ID
    python3 refresh.py redteam-report TASK_ID
    python3 refresh.py status
    python3 refresh.py refresh          # the monthly job: all of the above

Stdlib only, so the system python3 can run it. Secrets are read from files and
handed to child processes through the environment; nothing here prints them.
"""

import argparse
import datetime as dt
import gzip
import hashlib
import html
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

# --- configuration ---------------------------------------------------------

REPO = Path(__file__).resolve().parents[3]          # the PseudoCo Assistant checkout
ENV_FILE = REPO / ".env"
HOME = Path(os.environ.get("AI_DEFENSE_REFRESH_HOME", "~/.ai-defense-refresh")).expanduser()
KEY_FILE = Path(os.environ.get("AI_DEFENSE_MANAGEMENT_KEY_FILE", "~/.aibom-ai-defense-key")).expanduser()
# The scan's Anthropic key: this file if it exists (mode 600), else .env ANTHROPIC_API_KEY.
LLM_KEY_FILE = Path(os.environ.get("AIBOM_ANTHROPIC_KEY_FILE", "~/.aibom-anthropic-key")).expanduser()

API = "https://api.security.cisco.com/api/ai-defense/v1"
AIBOM_POST_URL = API + "/aibom/analysis"

GITHUB_URL = "https://github.com/mayeack/PseudoCoAssistant.git"
SCAN_BRANCH = "main"
PUBLIC_URL = "https://pseudocoassistant.com"
LOCAL_URL = "http://localhost:8001"
USER_AGENT = "ai-defense-refresh/1.0"

# Pinned on purpose: 1.10.0 is the version the AI Inventory was built with and
# whose gotchas SKILL.md records. Bump deliberately, with one attended run.
AIBOM_VERSION = "1.10.0"
AIBOM_PYTHONS = ("/opt/homebrew/bin/python3.11", "python3.11", "python3.12", "python3.13")
LLM_MODEL = "claude-sonnet-5-5"    # no --agentic-fast-model: claude-haiku-5-5 rejects temperature

# Red-team targets in the PseudoCo SCC org. The order is the run order.
# "theme" is the app's theme label (ThemeConfig.label) the target's template
# pins; "needs_ai_defense" is its ai_defense_review. Together they name the run
# (run_name).
TARGETS = {
    "protected": {
        "id": "465aecb9-2367-4f70-95fb-7b110dd3234a",
        "theme": "MedAdvice",
        "needs_ai_defense": True,
    },
    "baseline": {
        "id": "536c17ae-23b3-4ffb-b05c-c4d01ead7878",
        "theme": "MedAdvice",
        "needs_ai_defense": False,
    },
}
# Both run every month, one after the other: they share the one local model.
# Protected first (~2 h, AI Defense stops most prompts before the model), then the
# baseline, where every prompt reaches the model (many hours; may end JOB_STOPPED).
DEFAULT_TARGETS = ("protected", "baseline")
PROFILE_ID = "95751205-3d1e-434f-b619-7a951e76965a"   # "AI Defense Quick Start" (1,998 prompts via API)

TERMINAL_JOB_STATES = {"JOB_COMPLETED", "JOB_STOPPED", "JOB_FAILED", "JOB_CANCELLED", "JOB_CANCELED", "JOB_ERROR"}

STATE_FILE = HOME / "state.json"
HISTORY_FILE = HOME / "history.jsonl"
VENV = HOME / "venv"
CATALOG_DIR = HOME / "catalog"
CACHE_DIR = HOME / "aibom-cache"
SCAN_DIR = HOME / "scan" / "PseudoCoAssistant"     # stable path: the agentic cache keys on it
REPORTS = HOME / "reports"


class Fail(Exception):
    """A check or step failed; the message says what to do."""


# --- small helpers ---------------------------------------------------------

def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def today():
    return dt.date.today().isoformat()


def log(msg):
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def read_env(path=ENV_FILE):
    vals = {}
    if not path.exists():
        return vals
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip("'\"")
    return vals


def management_key():
    if not KEY_FILE.exists():
        raise Fail(f"{KEY_FILE} is missing. It holds the AI Defense Management API key "
                   "(SCC -> AI Defense -> Administration -> API keys). Create it with mode 600.")
    mode = stat.S_IMODE(KEY_FILE.stat().st_mode)
    if mode & 0o077:
        raise Fail(f"{KEY_FILE} is readable by others (mode {oct(mode)}); chmod 600 it.")
    key = KEY_FILE.read_text().strip()
    if not key:
        raise Fail(f"{KEY_FILE} is empty.")
    return key


def anthropic_key():
    if LLM_KEY_FILE.exists():
        if stat.S_IMODE(LLM_KEY_FILE.stat().st_mode) & 0o077:
            raise Fail(f"{LLM_KEY_FILE} is readable by others; chmod 600 it.")
        key, source = LLM_KEY_FILE.read_text().strip(), str(LLM_KEY_FILE)
    else:
        key, source = read_env().get("ANTHROPIC_API_KEY", ""), ".env ANTHROPIC_API_KEY"
    if not key:
        raise Fail(f"no Anthropic key for the scan: create {LLM_KEY_FILE} (mode 600) "
                   "or set ANTHROPIC_API_KEY in .env")
    return key, source


def check_anthropic_key():
    """Validate the scan's key with a zero-token GET /v1/models. Returns its source."""
    key, source = anthropic_key()
    req = urllib.request.Request("https://api.anthropic.com/v1/models?limit=1", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20):
            return source
    except urllib.error.HTTPError as e:
        raise Fail(f"Anthropic rejects the key from {source} (HTTP {e.code}); put a working key "
                   f"in {LLM_KEY_FILE} (mode 600) or .env")
    except urllib.error.URLError as e:
        raise Fail(f"api.anthropic.com unreachable: {e.reason}")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state):
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    tmp.replace(STATE_FILE)


def append_history(entry):
    HOME.mkdir(parents=True, exist_ok=True)
    entry = {"at": now_utc().isoformat(timespec="seconds"), **entry}
    with HISTORY_FILE.open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def report_dir():
    d = REPORTS / today()
    d.mkdir(parents=True, exist_ok=True)
    return d


def api(method, path, body=None, timeout=120):
    """Call the AI Defense management API. Returns the parsed JSON body."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("X-Cisco-AI-Defense-Tenant-API-Key", management_key())
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = e.read()[:400].decode(errors="replace")
        raise Fail(f"AI Defense API {method} {path} -> HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise Fail(f"AI Defense API {method} {path} unreachable: {e.reason}")


def http_status(url, headers=None, timeout=15):
    # Cloudflare in front of the tunnel 403s urllib's default "Python-urllib" agent.
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, OSError) as e:
        return None, str(e).encode()


def run(cmd, env=None, log_file=None, cwd=None, check=True):
    """Run a command; stream its output to log_file (or capture it)."""
    if log_file:
        with open(log_file, "a") as fh:
            fh.write(f"\n$ {' '.join(str(c) for c in cmd)}\n")
            fh.flush()
            proc = subprocess.run(cmd, env=env, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT)
        out = ""
    else:
        proc = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True)
        out = (proc.stdout or "") + (proc.stderr or "")
    if check and proc.returncode != 0:
        where = f" (log: {log_file})" if log_file else f":\n{out[-2000:]}"
        raise Fail(f"{cmd[0]} exited {proc.returncode}{where}")
    return out


def child_env(**extra):
    """Environment for child processes, with no stray AI Defense / AIBOM settings."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AIBOM_", "AI_DEFENSE_"))}
    env["COLUMNS"] = "160"
    env.update({k: v for k, v in extra.items() if v is not None})
    return env


def parse_targets(spec):
    names = [t.strip() for t in spec.split(",") if t.strip()] if spec else list(DEFAULT_TARGETS)
    bad = [n for n in names if n not in TARGETS]
    if bad:
        raise Fail(f"unknown target(s) {bad}; known: {sorted(TARGETS)}")
    return names


# --- setup -----------------------------------------------------------------

def find_python():
    for cand in AIBOM_PYTHONS:
        path = cand if os.path.isabs(cand) else shutil.which(cand)
        if path and os.path.exists(path):
            return path
    raise Fail("cisco-aibom needs Python >=3.11.4,<3.14; install one (brew install python@3.11).")


def aibom_bin():
    return VENV / "bin" / "cisco-aibom"


def catalog_path():
    return CATALOG_DIR / f"aibom_catalog-{AIBOM_VERSION}.duckdb"


def installed_aibom_version():
    if not aibom_bin().exists():
        return None
    out = run([str(VENV / "bin" / "python"), "-I", "-c",
               "import importlib.metadata as m; print(m.version('cisco-aibom'))"], check=False)
    return out.strip() or None


def cmd_setup(args):
    HOME.mkdir(parents=True, exist_ok=True)
    os.chmod(HOME, 0o700)
    if installed_aibom_version() != AIBOM_VERSION:
        log(f"installing cisco-aibom[agentic,llm-anthropic]=={AIBOM_VERSION} into {VENV}")
        if VENV.exists():
            shutil.rmtree(VENV)
        run([find_python(), "-m", "venv", str(VENV)])
        pip = [str(VENV / "bin" / "pip"), "install", "-q", "--index-url", "https://pypi.org/simple"]
        run(pip + ["--upgrade", "pip"])
        run(pip + [f"cisco-aibom[agentic,llm-anthropic]=={AIBOM_VERSION}"])
    log(f"cisco-aibom {installed_aibom_version()} ready")
    if not catalog_path().exists():
        CATALOG_DIR.mkdir(parents=True, exist_ok=True)
        log(f"downloading catalog {catalog_path().name}")
        run(["gh", "release", "download", AIBOM_VERSION, "--repo", "cisco-ai-defense/aibom",
             "--pattern", catalog_path().name, "--dir", str(CATALOG_DIR), "--clobber"])
    log(f"catalog ready: {catalog_path()}")
    for d in (CACHE_DIR, REPORTS):
        d.mkdir(parents=True, exist_ok=True)
    return 0


# --- preflight -------------------------------------------------------------

def access_key_fingerprint(env):
    key = env.get("ACCESS_KEY", "")
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else None


def checks_for(targets, inventory=True, redteam=True, accept_access_key=False):
    """Yield (name, ok, detail). Never raises for a failed check."""
    env = read_env()

    try:
        api("GET", "/ai-validation/profiles")
        yield "Management API key", True, f"{KEY_FILE} works"
    except Fail as e:
        yield "Management API key", False, str(e)
        return

    if inventory:
        ver = installed_aibom_version()
        ok = ver == AIBOM_VERSION and catalog_path().exists()
        yield "cisco-aibom install", ok, (f"{ver} + catalog in {HOME}" if ok
                                          else "run `refresh.py setup` first")
        # cisco-aibom 1.10.0 has no static mode: the LLM pass is mandatory. A
        # re-upload of an unchanged main does not need the key.
        try:
            yield "Anthropic key for the scan", True, check_anthropic_key() + " works"
        except Fail as e:
            yield "Anthropic key for the scan", False, str(e)
        code, _ = http_status("https://github.com/mayeack/PseudoCoAssistant")
        yield "GitHub repo reachable", code == 200, f"HTTP {code}"

    if not redteam:
        return

    jobs = api("GET", "/ai-validation/jobs").get("jobs", [])
    known = {t["target_id"]: t for t in api("GET", "/ai-validation/targets").get("targets", [])}
    for name in targets:
        t = TARGETS[name]
        found = known.get(t["id"])
        ok = bool(found) and found.get("status") == "OBJECT_STATUS_ACTIVE"
        yield (f"target '{name}'", ok,
               (found or {}).get("name", "") + ("" if ok else f" (id {t['id']} missing or not active)"))
        busy = [j["job"]["task_id"] for j in jobs
                if j["job"].get("target_id") == t["id"]
                and j["job"].get("status") not in TERMINAL_JOB_STATES]
        yield (f"no run in flight on '{name}'", not busy,
               "none" if not busy else f"already running: {busy} (wait for it or use redteam-wait)")
    profiles = {p["profile"]["profile_id"] for p in api("GET", "/ai-validation/profiles").get("profiles", [])}
    yield "profile AI Defense Quick Start", PROFILE_ID in profiles, PROFILE_ID

    code, body = http_status(LOCAL_URL + "/health", timeout=5)
    version = ""
    if code == 200:
        try:
            version = json.loads(body).get("version", "")
        except ValueError:
            pass
    yield "app on this Mac", code == 200, (f"{LOCAL_URL} v{version}" if code == 200
                                           else f"{LOCAL_URL}/health -> {code}; start it (launch-medadvice skill)")
    code, _ = http_status(PUBLIC_URL + "/health")
    yield "public tunnel", code == 200, f"{PUBLIC_URL}/health -> {code}"

    key = env.get("ACCESS_KEY")
    if key:
        code, _ = http_status(PUBLIC_URL + "/api/server-info", headers={"X-Access-Key": key})
        yield "X-Access-Key accepted", code == 200, f"/api/server-info -> {code}"
    else:
        yield "X-Access-Key accepted", False, "ACCESS_KEY missing from .env"

    # The targets store the ACCESS_KEY that was current when they were made, and
    # the API never returns it. If .env's key changed since, every attack would
    # 401 and the run would score garbage, so stop and have the targets updated.
    state = load_state()
    fp = access_key_fingerprint(env)
    seen = state.get("access_key_fingerprint")
    if fp and (seen is None or accept_access_key):
        state["access_key_fingerprint"] = fp
        state["access_key_fingerprint_at"] = now_utc().isoformat(timespec="seconds")
        save_state(state)
        yield "ACCESS_KEY unchanged", True, "fingerprint recorded"
    else:
        same = fp == seen
        yield ("ACCESS_KEY unchanged", same,
               "matches the key the targets were last confirmed with" if same else
               "ACCESS_KEY changed since " + state.get("access_key_fingerprint_at", "?") +
               ": update each target's X-Access-Key (SKILL.md, 'ACCESS_KEY rotated'), "
               "then rerun preflight with --accept-access-key")

    if any(TARGETS[n]["needs_ai_defense"] for n in targets):
        on = env.get("AI_DEFENSE_ENABLED", "").lower() in ("true", "1", "yes")
        yield ("AI_DEFENSE_ENABLED in .env", on,
               "True" if on else "the protected target's ai_defense_review:true is ignored while this is off")


def preflight(targets, inventory=True, redteam=True, accept_access_key=False):
    failed = []
    for name, ok, detail in checks_for(targets, inventory, redteam, accept_access_key):
        print(f"  {'OK  ' if ok else 'FAIL'} {name}: {detail}", flush=True)
        if not ok:
            failed.append(name)
    if failed:
        raise Fail(f"preflight failed: {', '.join(failed)}")
    log("preflight passed")


def cmd_preflight(args):
    preflight(parse_targets(args.targets), inventory=not args.redteam_only,
              redteam=not args.inventory_only, accept_access_key=args.accept_access_key)
    return 0


# --- AI Inventory ----------------------------------------------------------

def remote_head():
    out = run(["git", "ls-remote", GITHUB_URL, f"refs/heads/{SCAN_BRANCH}"])
    sha = out.split()[0] if out.strip() else ""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Fail(f"could not resolve {SCAN_BRANCH} on {GITHUB_URL}")
    return sha


def fresh_clone(sha, log_file):
    """A clean clone of GitHub main with openclaw/ never written to disk.

    EDR on this Mac quarantines OpenClaw artifacts, so the clone is blobless and
    the sparse pattern excludes openclaw/ before anything is checked out.
    """
    if SCAN_DIR.exists():
        shutil.rmtree(SCAN_DIR)
    SCAN_DIR.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "--branch", SCAN_BRANCH,
         GITHUB_URL, str(SCAN_DIR)], log_file=log_file)
    git = ["git", "-C", str(SCAN_DIR)]
    run(git + ["sparse-checkout", "set", "--no-cone", "/*", "!/openclaw/"], log_file=log_file)
    run(git + ["checkout", "-q", SCAN_BRANCH], log_file=log_file)
    head = run(git + ["rev-parse", "HEAD"]).strip()
    if head != sha:
        raise Fail(f"clone is at {head[:12]}, expected {sha[:12]} (main moved mid-run? rerun)")
    if (SCAN_DIR / "openclaw").exists():
        shutil.rmtree(SCAN_DIR)
        raise Fail("openclaw/ landed on disk despite the sparse pattern; clone removed")


def summarize_aibom(report_path):
    a = json.loads(Path(report_path).read_text())["aibom_analysis"]
    m, s = a["metadata"], a["summary"]
    return {
        "status": m.get("status"),
        "agentic_status": m.get("agentic_status"),
        "analyzer_version": m.get("analyzer_version"),
        "llm_model": m.get("llm_model"),
        "total_tokens": m.get("total_tokens"),
        "cached_tokens": m.get("cached_tokens"),
        "total_components": s.get("total_components"),
        "component_types": s.get("component_types"),
        "pending_agent_review": s.get("pending_agent_review"),
        "risk_score": s.get("risk_score"),
        "risk_severity": s.get("risk_severity"),
    }


def upload_report(report_path, log_file):
    env = child_env(AIBOM_POST_URL=AIBOM_POST_URL, AI_DEFENSE_API_KEY=management_key())
    run([str(aibom_bin()), "report", "upload", str(report_path), "--format", "json",
         "--post-timeout", "120"], env=env, log_file=log_file)
    text = Path(log_file).read_text()
    if "Uploaded 1 report(s)" not in text.split("$ ")[-1]:
        raise Fail(f"upload did not confirm (log: {log_file})")


def cmd_inventory(args):
    if installed_aibom_version() != AIBOM_VERSION or not catalog_path().exists():
        cmd_setup(args)
    state = load_state()
    inv = state.get("inventory", {})
    sha = remote_head()
    out_dir = report_dir()
    log_file = out_dir / "aibom.log"
    reuse = (not args.force_scan and inv.get("commit") == sha
             and inv.get("report") and Path(inv["report"]).exists())

    if reuse:
        report = Path(inv["report"])
        log(f"main is still {sha[:12]}, scanned {inv.get('scanned_at', '?')}: re-uploading that report")
        mode = "reupload"
    else:
        log(f"scanning {GITHUB_URL} {SCAN_BRANCH} @ {sha[:12]} ({LLM_MODEL})")
        check_anthropic_key()
        llm_key, _ = anthropic_key()
        fresh_clone(sha, log_file)
        report = out_dir / f"aibom-{sha[:12]}.json"
        cmd = [str(aibom_bin()), "analyze", str(SCAN_DIR), "-o", "json", "-O", str(report),
               "--component-summary", "--cache-dir", str(CACHE_DIR), "--no-progress", "--timing"]
        cmd += ["--llm-provider", "anthropic", "--llm-model", LLM_MODEL,
                "--agentic-batch-size", "2", "--agentic-concurrency", "3",
                "--agentic-rate-limit", "2"]
        env = child_env(AIBOM_DB_PATH=str(catalog_path()), AIBOM_LLM_API_KEY=llm_key)
        t0 = time.time()
        offset = log_file.stat().st_size if log_file.exists() else 0
        run(cmd, env=env, log_file=log_file, cwd=str(HOME))
        log(f"scan finished in {int(time.time() - t0)} s")
        with open(log_file) as fh:
            fh.seek(offset)
            scan_log = fh.read()
        # cisco-aibom still reports status "completed" when every LLM batch
        # failed; that BOM is deterministic-only and must not replace a real one.
        if "the LLM added nothing" in scan_log or "authentication_error" in scan_log:
            raise Fail(f"the LLM classification pass failed, not uploading (log: {log_file})")
        mode = "scan"

    summary = summarize_aibom(report)
    if summary["status"] != "completed":
        raise Fail(f"scan status is {summary['status']!r}, not uploading (log: {log_file})")
    if args.no_upload:
        log("--no-upload: report left at " + str(report))
    else:
        upload_report(report, log_file)
        log(f"uploaded to AI Inventory ({AIBOM_POST_URL})")
    entry = {"kind": "inventory", "mode": mode, "commit": sha, "report": str(report),
             "uploaded": not args.no_upload, **summary}
    if not args.no_upload:
        state["inventory"] = {"commit": sha, "report": str(report),
                              "scanned_at": inv.get("scanned_at") if reuse else today(),
                              "uploaded_at": now_utc().isoformat(timespec="seconds"),
                              "mode": inv.get("mode", mode) if reuse else mode}
        save_state(state)
        append_history(entry)
    (out_dir / "inventory.json").write_text(json.dumps(entry, indent=2) + "\n")
    print(json.dumps(entry, indent=2))
    return 0


# --- AI Red Teaming --------------------------------------------------------

def get_job(task_id):
    return api("GET", f"/ai-validation/job/{task_id}")


def run_name(name):
    """The run's name in SCC: "PseudoCo <theme> <Protected|Unprotected>".

    The same every time, so a target's runs line up in the AI Red Teaming list;
    the start time tells them apart. Names reject "+", and no theme label has one.
    """
    t = TARGETS[name]
    return f"PseudoCo {t['theme']} {'Protected' if t['needs_ai_defense'] else 'Unprotected'}"


def start_run(name):
    t = TARGETS[name]
    scan_name = run_name(name)
    body = {"validation_scan_name": scan_name, "target_id": t["id"], "profile_id": PROFILE_ID}
    task_id = api("POST", "/ai-validation/start", body).get("task_id")
    if not task_id:
        raise Fail(f"start returned no task_id for '{name}'")
    state = load_state()
    state.setdefault("redteam", {})[name] = {"task_id": task_id, "started_at": now_utc().isoformat(timespec="seconds"),
                                             "scan_name": scan_name}
    save_state(state)
    append_history({"kind": "redteam-start", "target": name, "task_id": task_id, "scan_name": scan_name})
    log(f"started '{scan_name}' -> task {task_id}")
    return task_id


def cmd_redteam_start(args):
    names = parse_targets(args.targets)
    if not args.skip_preflight:
        preflight(names, inventory=False)
    if len(names) > 1:
        log("starting only the first target; the others would queue on the one local model. "
            "Use `refresh` to run several in sequence.")
    print(start_run(names[0]))
    return 0


def wait_job(task_id, interval, max_hours):
    deadline = time.time() + max_hours * 3600
    last = None
    while True:
        job = get_job(task_id)
        status, progress = job.get("status"), job.get("progress")
        if (status, progress) != last:
            log(f"{task_id[:8]} {status} {progress}% of {job.get('total_num_prompts')} prompts")
            last = (status, progress)
        if status in TERMINAL_JOB_STATES:
            if job.get("error_message"):
                log("error_message: " + job["error_message"][:500])
            return job
        if time.time() > deadline:
            raise Fail(f"{task_id} still {status} after {max_hours} h; check it later with redteam-wait/redteam-report")
        time.sleep(interval)


def cmd_redteam_wait(args):
    job = wait_job(args.task_id, args.interval, args.max_hours)
    return 0 if job.get("status") == "JOB_COMPLETED" else 1


def target_name_for(target_id):
    return next((n for n, t in TARGETS.items() if t["id"] == target_id), target_id)


def previous_job(job):
    """The newest earlier run on the same target that reached a terminal state."""
    jobs = [j["job"] for j in api("GET", "/ai-validation/jobs").get("jobs", [])]
    earlier = [j for j in jobs if j.get("target_id") == job.get("target_id")
               and j["task_id"] != job["task_id"]
               and j.get("created_at", "") < job.get("created_at", "")
               and j.get("status") in TERMINAL_JOB_STATES]
    earlier.sort(key=lambda j: j.get("created_at", ""))
    done = [j for j in earlier if j.get("status") == "JOB_COMPLETED"]
    return (done or earlier or [None])[-1]


def short(enum_value, prefix):
    return (enum_value or "").replace(prefix, "").replace("_", " ").lower() or "unspecified"


SUCCEEDED, FAILED = "ATTACK_RESULT_SUCCEEDED", "ATTACK_RESULT_FAILED"   # FAILED = the attack was blocked


def summarize_results(job, rows):
    # Only SUCCEEDED/FAILED rows are scored. ATTACK_RESULT_ERROR rows are attacks
    # Cisco could not finish (e.g. DeadlineExceeded while the local model queued);
    # counting them as blocked would flatter the result.
    scored = [r for r in rows if r.get("attack_result") in (SUCCEEDED, FAILED)]
    through = [r for r in scored if r.get("attack_result") == SUCCEEDED]
    layers = Counter((r.get("blocking_attribution") or {}).get("layer_name") or "not blocked" for r in scored)
    cats = defaultdict(lambda: [0, 0])
    for r in scored:
        c = short(r.get("attack_content_category"), "CONTENT_CATEGORY_")
        cats[c][0] += 1
        cats[c][1] += r.get("attack_result") == SUCCEEDED
    n = len(scored)
    return {
        "task_id": job["task_id"],
        "target": target_name_for(job.get("target_id")),
        "status": job.get("status"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "prompts": job.get("total_num_prompts"),
        "attacks_scored": n,
        "through": len(through),
        "blocked": n - len(through),
        "blocked_pct": round(100.0 * (n - len(through)) / n, 1) if n else None,
        "skipped": len(rows) - n,
        "blocked_by_layer": dict(layers.most_common()),
        "by_category": {c: {"attacks": t, "through": s, "blocked_pct": round(100.0 * (t - s) / t, 1)}
                        for c, (t, s) in sorted(cats.items(), key=lambda kv: -kv[1][1])},
        "through_by_severity": dict(Counter(short(r.get("severity"), "SEVERITY_") for r in through)),
        "through_by_technique": dict(Counter(r.get("attack_procedure") or "?" for r in through).most_common(10)),
    }


def pair_key(r):
    return (r.get("attack_intent", ""), r.get("attack_procedure", ""))


def compare(prev_rows, rows):
    """Pair the same attack across two runs by (intent, procedure), scored rows only."""
    scored = (SUCCEEDED, FAILED)
    prev = {pair_key(r): r.get("attack_result") for r in prev_rows if r.get("attack_result") in scored}
    pairs = [(prev[pair_key(r)], r.get("attack_result")) for r in rows
             if r.get("attack_result") in scored and pair_key(r) in prev]
    ok = SUCCEEDED
    return {
        "paired_attacks": len(pairs),
        "through_before": sum(a == ok for a, _ in pairs),
        "through_now": sum(b == ok for _, b in pairs),
        "newly_through": sum(a != ok and b == ok for a, b in pairs),
        "newly_blocked": sum(a == ok and b != ok for a, b in pairs),
    }


def fetch_results(task_id, out_dir):
    rows = api("GET", f"/ai-validation/results/{task_id}", timeout=300).get("results", [])
    with gzip.open(out_dir / f"redteam-{task_id[:8]}-results.json.gz", "wt") as fh:
        json.dump(rows, fh)
    return rows


def redteam_report(task_id):
    out_dir = report_dir()
    job = get_job(task_id)
    if job.get("status") not in TERMINAL_JOB_STATES:
        raise Fail(f"{task_id} is {job.get('status')} ({job.get('progress')}%); report after it finishes")
    rows = fetch_results(task_id, out_dir)
    summary = summarize_results(job, rows)
    prev = previous_job(job)
    if prev:
        prev_rows = api("GET", f"/ai-validation/results/{prev['task_id']}", timeout=300).get("results", [])
        prev_sum = summarize_results(prev, prev_rows)
        summary["previous"] = {k: prev_sum[k] for k in
                               ("task_id", "status", "created_at", "attacks_scored", "through", "blocked_pct")}
        summary["vs_previous"] = compare(prev_rows, rows)
    (out_dir / f"redteam-{summary['target']}-{task_id[:8]}.json").write_text(json.dumps(summary, indent=2) + "\n")
    append_history({"kind": "redteam-result", **{k: summary[k] for k in
                    ("task_id", "target", "status", "attacks_scored", "through", "blocked_pct")}})
    return summary


def redteam_markdown(s):
    lines = [f"### Red team: {run_name(s['target']) if s['target'] in TARGETS else s['target']}", "",
             f"Task `{s['task_id']}`, {s['status']}, {s['created_at'][:16].replace('T', ' ')} UTC"
             f" to {(s.get('completed_at') or '?')[:16].replace('T', ' ')} UTC.", ""]
    if not s["attacks_scored"]:
        return lines + ["No attacks were scored.", ""]
    lines += [f"**{s['blocked']}/{s['attacks_scored']} blocked ({s['blocked_pct']}%)**, "
              f"{s['through']} got through, {s['skipped'] or 0} skipped.", ""]
    if s.get("previous"):
        p, v = s["previous"], s["vs_previous"]
        lines += [f"Previous run `{p['task_id'][:8]}` ({p['created_at'][:10]}): "
                  f"{p['blocked_pct']}% blocked, {p['through']} through. "
                  f"Across {v['paired_attacks']} attacks run both times: {v['through_before']} -> "
                  f"{v['through_now']} through ({v['newly_through']} newly through, "
                  f"{v['newly_blocked']} newly blocked).", ""]
    lines += ["| Blocked by | Attacks |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in s["blocked_by_layer"].items()]
    lines += ["", "| Content category | Attacks | Through | Blocked |", "|---|---|---|---|"]
    lines += [f"| {c} | {v['attacks']} | {v['through']} | {v['blocked_pct']}% |" for c, v in s["by_category"].items()]
    lines.append("")
    return lines


def cmd_redteam_report(args):
    s = redteam_report(args.task_id)
    print("\n".join(redteam_markdown(s)))
    return 0


# --- status ----------------------------------------------------------------

def cmd_status(args):
    state = load_state()
    inv = state.get("inventory")
    print("AI Inventory:", (f"commit {inv['commit'][:12]} ({inv.get('mode')}), scanned {inv.get('scanned_at')}, "
                            f"last uploaded {inv.get('uploaded_at')}") if inv else "never uploaded by this script")
    jobs = [j["job"] for j in api("GET", "/ai-validation/jobs").get("jobs", [])]
    print("Red-team runs (newest first):")
    for j in sorted(jobs, key=lambda j: j.get("created_at", ""), reverse=True)[:10]:
        print(f"  {j['task_id']}  {target_name_for(j.get('target_id')):9}  {j.get('status'):14} "
              f"{j.get('progress')}%  {j.get('total_num_prompts')} prompts  {j.get('created_at', '')[:16]}")
    return 0


# --- the monthly job -------------------------------------------------------

def md_to_html(md, title):
    """Render the small Markdown subset write_summary() emits."""
    out, in_table, in_list = [], False, False

    def inline(t):
        t = html.escape(t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        return re.sub(r"`(.+?)`", r"<code>\1</code>", t)

    for line in md.splitlines():
        if in_table and not line.startswith("|"):
            out.append("</table>")
            in_table = False
        if in_list and not line.startswith("- "):
            out.append("</ul>")
            in_list = False
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            out.append(f"<h{level}>{inline(line[level:].strip())}</h{level}>")
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                out.append("<table>")
                in_table = True
            out.append("<tr>" + "".join(f"<{tag}>{inline(c)}</{tag}>" for c in cells) + "</tr>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    if in_table:
        out.append("</table>")
    if in_list:
        out.append("</ul>")
    style = ("body{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:880px;"
             "margin:2rem auto;padding:0 1rem;color:#1f2937;line-height:1.55}"
             "code{background:#f3f4f6;padding:.1rem .3rem;border-radius:3px}"
             "table{border-collapse:collapse;width:100%;margin:.8rem 0;font-size:.93em}"
             "th,td{border:1px solid #e5e7eb;padding:.4rem .6rem;text-align:left}th{background:#f9fafb}")
    return (f"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{html.escape(title)}</title>\n<style>{style}</style>\n</head>\n<body>\n"
            + "\n".join(out) + "\n</body>\n</html>\n")


def write_summary(inventory_entry, redteam_summaries, problems):
    title = f"AI Defense refresh {today()}"
    lines = [f"# {title}", ""]
    if inventory_entry:
        e = inventory_entry
        types = ", ".join(f"{v} {k}" for k, v in sorted((e.get("component_types") or {}).items()))
        lines += ["### AI Inventory", "",
                  f"Commit `{e['commit'][:12]}`, {e['mode']}, uploaded: {e['uploaded']}. "
                  f"{e.get('total_components')} components ({types}); risk {e.get('risk_score')} "
                  f"({e.get('risk_severity')}); agentic status {e.get('agentic_status')}; "
                  f"{e.get('total_tokens') or 0} LLM tokens.", ""]
    for s in redteam_summaries:
        lines += redteam_markdown(s)
    if problems:
        lines += ["### Problems", ""] + [f"- {p}" for p in problems] + [""]
    md = "\n".join(lines)
    out_dir = report_dir()
    (out_dir / "SUMMARY.md").write_text(md)
    (out_dir / "SUMMARY.html").write_text(md_to_html(md, title))
    return out_dir / "SUMMARY.md", md


def cmd_refresh(args):
    names = parse_targets(args.targets)
    if installed_aibom_version() != AIBOM_VERSION or not catalog_path().exists():
        cmd_setup(args)
    # Only the red-team checks are fatal here; an inventory problem (say, a dead
    # Anthropic key) is reported in the summary and the red team still runs.
    preflight(names, inventory=False, redteam=not args.skip_redteam)
    problems, inventory_entry, summaries = [], None, []

    if not args.skip_inventory:
        try:
            cmd_inventory(args)
            inventory_entry = json.loads((report_dir() / "inventory.json").read_text())
        except Fail as e:
            problems.append(f"AI Inventory: {e}")
            log(f"AI Inventory step failed (reported in the summary): {e}")

    if not args.skip_redteam:
        for name in names:
            try:
                task_id = start_run(name)
                job = wait_job(task_id, args.interval, args.max_hours)
                if job.get("status") != "JOB_COMPLETED":
                    problems.append(f"red team '{name}' ended {job.get('status')}: "
                                    f"{(job.get('error_message') or '')[:300]}")
                summaries.append(redteam_report(task_id))
            except Fail as e:
                problems.append(f"red team '{name}': {e}")
                log(f"red team '{name}' failed: {e}")

    path, md = write_summary(inventory_entry, summaries, problems)
    print("\n" + md)
    log(f"summary written to {path} (+ .html)")
    return 1 if problems else 0


# --- CLI -------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_targets(sp):
        sp.add_argument("--targets", default=",".join(DEFAULT_TARGETS),
                        help=f"comma list of {sorted(TARGETS)} (default: {','.join(DEFAULT_TARGETS)})")

    def add_inventory_opts(sp):
        sp.add_argument("--force-scan", action="store_true", help="scan even if main has not moved")
        sp.add_argument("--no-upload", action="store_true", help="scan only; leave AI Inventory alone")

    def add_wait_opts(sp):
        sp.add_argument("--interval", type=int, default=300, help="poll seconds (default 300)")
        sp.add_argument("--max-hours", type=float, default=30, help="give up waiting on one run after this long")

    sub.add_parser("setup", help="install cisco-aibom + catalog under ~/.ai-defense-refresh")

    sp = sub.add_parser("preflight", help="run every check; changes nothing in AI Defense")
    add_targets(sp)
    sp.add_argument("--inventory-only", action="store_true")
    sp.add_argument("--redteam-only", action="store_true")
    sp.add_argument("--accept-access-key", action="store_true",
                    help="record the current ACCESS_KEY as the one the targets hold")

    sp = sub.add_parser("inventory", help="scan main (or re-upload) and upload to AI Inventory")
    add_inventory_opts(sp)

    sp = sub.add_parser("redteam-start", help="start one red-team run")
    add_targets(sp)
    sp.add_argument("--skip-preflight", action="store_true")

    sp = sub.add_parser("redteam-wait", help="poll a run until it ends")
    sp.add_argument("task_id")
    add_wait_opts(sp)

    sp = sub.add_parser("redteam-report", help="summarize a finished run vs the previous one")
    sp.add_argument("task_id")

    sub.add_parser("status", help="last upload + recent red-team runs")

    sp = sub.add_parser("refresh", help="the monthly job: preflight, inventory, red team, summary")
    add_targets(sp)
    add_inventory_opts(sp)
    add_wait_opts(sp)
    sp.add_argument("--skip-inventory", action="store_true")
    sp.add_argument("--skip-redteam", action="store_true")

    args = p.parse_args(argv)
    handler = {"setup": cmd_setup, "preflight": cmd_preflight, "inventory": cmd_inventory,
               "redteam-start": cmd_redteam_start, "redteam-wait": cmd_redteam_wait,
               "redteam-report": cmd_redteam_report, "status": cmd_status, "refresh": cmd_refresh}[args.cmd]
    try:
        return handler(args)
    except Fail as e:
        log(f"FAILED: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
