#!/usr/bin/env python3
"""Regression: the Cisco AI Defense / Splunk Observability Settings cards.

Guards the Settings-page controls that repoint this box at a different AI Defense
connection, O11y org, or Splunk Agent Observability project at runtime
(GET /api/settings/integrations, PUT /api/settings/integration-creds). The risky
parts are:

  1. A secret VALUE must never reach the browser — presence only.
  2. Blank secret = keep existing. A save must never silently wipe a key.
  3. Fields whose consumer is a separate process go to .env, and the .env writer
     must replace in place: a duplicate line makes backend/config.py take the
     first value while the shell readers in run.sh / run-collector.sh return BOTH.
  4. Saving must reach the live consumer, whose singleton snapshots config in
     __init__ — otherwise a new key silently does nothing.

Fully isolated: both the .env writer and the settings store are monkeypatched to
throwaway state, so a run never mutates this box's real .env or app_settings row.

Run:  venv/bin/python tests/test_integration_settings.py    # exit 0 = pass
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import settings_store  # noqa: E402
from backend.config import settings  # noqa: E402

_fails = 0


def check(name: str, cond: bool) -> None:
    global _fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        _fails += 1


class _TempEnv:
    """Point settings_store's .env writer at a throwaway file."""

    def __init__(self, initial: str = ""):
        self.initial = initial

    def __enter__(self) -> Path:
        fd, name = tempfile.mkstemp(prefix="env-test-")
        os.close(fd)
        self.path = Path(name)
        self.path.write_text(self.initial)
        self.path.chmod(0o600)
        self._orig = settings_store._env_path
        settings_store._env_path = lambda: self.path
        return self.path

    def __exit__(self, *exc) -> None:
        settings_store._env_path = self._orig
        self.path.unlink(missing_ok=True)


class _TempStore:
    """Swap the settings store for an in-memory dict.

    set_integration_creds persists non-.env fields, so without this a test run
    would leave sentinel credentials in this box's real app_settings row — and
    they would be re-applied at the next startup."""

    def __enter__(self) -> dict:
        self.data = dict(settings_store._DEFAULTS)
        self.data["integration_creds"] = {}
        self._load, self._persist = settings_store.load, settings_store._persist
        settings_store.load = lambda: dict(self.data)
        settings_store._persist = lambda d: self.data.update(d)
        return self.data

    def __exit__(self, *exc) -> None:
        settings_store.load = self._load
        settings_store._persist = self._persist


def _count(path: Path, key: str) -> int:
    return sum(1 for ln in path.read_text().splitlines() if ln.startswith(key + "="))


def _value(path: Path, key: str) -> str:
    for ln in path.read_text().splitlines():
        if ln.startswith(key + "="):
            return ln.split("=", 1)[1]
    return ""


# ---------------------------------------------------------------------------
def test_choices_and_field_shape() -> None:
    check("INTEGRATION_CHOICES == the 4 Settings groups",
          settings_store.INTEGRATION_CHOICES
          == ["ai_defense", "splunk_o11y", "agent_observability", "nemo_guardrails"])
    fields = settings_store.get_integration_fields()
    check("get_integration_fields covers every choice",
          set(fields) == set(settings_store.INTEGRATION_CHOICES))
    every = [f for items in fields.values() for f in items]
    check("every field declares key/label/secret/boolean/present",
          all(all(k in f for k in ("key", "label", "secret", "boolean", "present"))
              for f in every))


def test_no_secret_value_ever_leaves_the_box() -> None:
    fields = settings_store.get_integration_fields()
    leaked = [f"{i}.{f['key']}" for i, items in fields.items()
              for f in items if f["secret"] and "value" in f]
    check("no secret field carries a value (presence only)", not leaked)
    if leaked:
        print(f"    leaked: {leaked}")
    secrets = [f for items in fields.values() for f in items if f["secret"]]
    # 6 + the splunk_ao Agent Control token (SPLUNK_AO_CONTROL_TOKEN).
    check("the expected 7 secrets are declared secret", len(secrets) == 7)
    check("the AO control token is one of them",
          any(f["key"] == "splunk_ao_control_token" for f in secrets))


def test_blank_secret_keeps_existing() -> None:
    orig = settings.ai_defense_api_key
    try:
        settings_store.set_integration_creds("ai_defense", {"api_key": "sentinel-key-1"})
        check("a non-blank secret is applied", settings.ai_defense_api_key == "sentinel-key-1")
        settings_store.set_integration_creds("ai_defense", {"api_key": "   "})
        check("a blank secret keeps the existing value",
              settings.ai_defense_api_key == "sentinel-key-1")
    finally:
        settings.ai_defense_api_key = orig


def test_boolean_false_is_a_real_value() -> None:
    orig = settings.ai_defense_enabled
    try:
        settings_store.set_integration_creds("ai_defense", {"enabled": "false"})
        check("unchecking a boolean turns it off (not 'leave alone')",
              settings.ai_defense_enabled is False)
        settings_store.set_integration_creds("ai_defense", {"enabled": "true"})
        check("checking a boolean turns it on", settings.ai_defense_enabled is True)
    finally:
        settings.ai_defense_enabled = orig


def test_ai_defense_save_reaches_the_live_client() -> None:
    from backend.services.ai_defense import ai_defense_client

    orig = settings.ai_defense_api_key
    try:
        settings_store.set_integration_creds("ai_defense", {"api_key": "sentinel-key-2"})
        check("the client singleton picked up the new key (reconfigure ran)",
              ai_defense_client._api_key == "sentinel-key-2")
    finally:
        settings.ai_defense_api_key = orig
        ai_defense_client.reconfigure()


def test_startup_applies_saved_ai_defense_key_to_the_live_client() -> None:
    """A box whose AI Defense key lives ONLY in the Settings page (app_settings
    row, nothing in .env) must come up configured after a restart.

    ai_defense_client is built at import time (backend.main -> routers.chat ->
    recommendation_engine), BEFORE the startup hook overlays the saved creds onto
    ``settings`` — so the hook itself has to push them into the singleton, the way
    a Settings save does. Before the fix the client kept its import-time snapshot
    and the per-chat AI Defense toggle silently did nothing."""
    from backend.services.ai_defense import ai_defense_client

    attrs = ("ai_defense_enabled", "ai_defense_api_key", "ai_defense_region",
             "ai_defense_endpoint")
    orig = {a: getattr(settings, a) for a in attrs}
    try:
        with _TempStore() as data:
            # .env without an AI Defense key: the import-time snapshot is empty.
            settings.ai_defense_enabled = False
            settings.ai_defense_api_key = ""
            settings.ai_defense_region = "us"
            settings.ai_defense_endpoint = ""
            ai_defense_client.reconfigure()
            check("precondition: client imported unconfigured",
                  not ai_defense_client.is_configured)

            # The app_settings row a Settings-page save leaves behind.
            data["integration_creds"] = {"ai_defense": {
                "enabled": "true",
                "api_key": "sentinel-startup-key",
                "endpoint": "https://sentinel.example.invalid",
            }}
            settings_store.apply_integration_creds_from_store()  # main.py startup hook

            check("startup: settings carry the saved key",
                  settings.ai_defense_api_key == "sentinel-startup-key")
            check("startup: the live client is configured from the saved row",
                  ai_defense_client.is_configured)
            check("startup: the live client holds the saved key",
                  ai_defense_client._api_key == "sentinel-startup-key")
            check("startup: the live client targets the saved endpoint",
                  ai_defense_client._url
                  == "https://sentinel.example.invalid/api/v1/inspect/chat")
    finally:
        for a, v in orig.items():
            setattr(settings, a, v)
        ai_defense_client.reconfigure()


def test_startup_reconfigures_only_integrations_it_applied() -> None:
    """The startup hook runs the same _reconfigure_integration path as a save, for
    every integration whose saved values it applied — and only those: an empty
    blob must not touch a consumer, and a .env-owned key (splunk_o11y, SPLUNK_AO_*)
    in the blob is skipped, so it is not "applied"."""
    calls = []
    orig_reconf = settings_store._reconfigure_integration
    settings_store._reconfigure_integration = calls.append
    attrs = ("ai_defense_api_key", "nemo_guardrails_rails")
    orig = {a: getattr(settings, a) for a in attrs}
    orig_ac = os.environ.get("AGENT_CONTROL_API_KEY")
    try:
        with _TempStore() as data:
            settings_store.apply_integration_creds_from_store()
            check("startup: an empty blob reconfigures nothing", calls == [])

            data["integration_creds"] = {
                "ai_defense": {"api_key": "k-ai"},
                "agent_observability": {"agent_control_api_key": "k-ac"},
                "nemo_guardrails": {"rails": "overreach"},
                "splunk_o11y": {"realm": "ignored"},  # env_file: not applied here
            }
            settings_store.apply_integration_creds_from_store()
            check("startup: every applied integration is reconfigured once",
                  sorted(calls) == ["agent_observability", "ai_defense", "nemo_guardrails"])

            calls.clear()
            data["integration_creds"] = {"agent_observability": {"project": "env-owned"}}
            settings_store.apply_integration_creds_from_store()
            check("startup: a blob holding only .env-owned keys reconfigures nothing",
                  calls == [])

            def _boom(integration):
                calls.append(integration)
                raise RuntimeError("consumer down")

            calls.clear()
            settings_store._reconfigure_integration = _boom
            data["integration_creds"] = {"ai_defense": {"api_key": "k-ai"},
                                         "nemo_guardrails": {"rails": "overreach"}}
            settings_store.apply_integration_creds_from_store()  # must not raise
            check("startup: one failing consumer does not stop the others",
                  sorted(calls) == ["ai_defense", "nemo_guardrails"])
    finally:
        settings_store._reconfigure_integration = orig_reconf
        for a, v in orig.items():
            setattr(settings, a, v)
        if orig_ac is None:
            os.environ.pop("AGENT_CONTROL_API_KEY", None)
        else:
            os.environ["AGENT_CONTROL_API_KEY"] = orig_ac
        from backend.services.ai_defense import ai_defense_client
        ai_defense_client.reconfigure()


def test_agent_observability_save_sets_env() -> None:
    """The four SPLUNK_AO_* keys have two consumers: the SDK path (os.environ, live)
    and the collector overlay (.env at start). A save must feed both, retire the
    live logger, and ask for a collector restart."""
    import backend.agent_observability as ao

    orig = os.environ.get("SPLUNK_AO_PROJECT")
    reconfigured = []
    orig_reconf = ao.reconfigure
    ao.reconfigure = lambda: reconfigured.append(1)
    try:
        with _TempStore() as data, _TempEnv("SPLUNK_AO_PROJECT=old\n") as p:
            restart = settings_store.set_integration_creds(
                "agent_observability", {"project": "SentinelProj"})
            check("SPLUNK_AO_PROJECT is set in os.environ (SDK path rebuilds from it)",
                  os.environ.get("SPLUNK_AO_PROJECT") == "SentinelProj")
            check("SPLUNK_AO_PROJECT is written to .env in place (collector overlay reads it)",
                  _value(p, "SPLUNK_AO_PROJECT") == "SentinelProj" and _count(p, "SPLUNK_AO_PROJECT") == 1)
            check("a SPLUNK_AO_* save asks for a collector restart", restart == ["collector"])
            check("SPLUNK_AO_* keys are .env-owned, not blob-persisted",
                  "project" not in (data.get("integration_creds") or {}).get("agent_observability", {}))
            check("agent_observability.reconfigure() ran after the save", len(reconfigured) == 1)
    finally:
        ao.reconfigure = orig_reconf
        if orig is None:
            os.environ.pop("SPLUNK_AO_PROJECT", None)
        else:
            os.environ["SPLUNK_AO_PROJECT"] = orig


def test_agent_control_creds_are_blob_persisted() -> None:
    """Agent Control's credentials are app-only: applied live, persisted in the
    settings blob, no restart."""
    orig = os.environ.get("AGENT_CONTROL_API_KEY")
    try:
        with _TempStore() as data:
            restart = settings_store.set_integration_creds(
                "agent_observability", {"agent_control_api_key": "k1"})
            check("AGENT_CONTROL_API_KEY applied to os.environ", os.environ.get("AGENT_CONTROL_API_KEY") == "k1")
            check("Agent Control creds apply live (no restart)", restart == [])
            check("Agent Control creds persist in the blob",
                  (data.get("integration_creds") or {}).get("agent_observability", {}).get("agent_control_api_key") == "k1")
    finally:
        if orig is None:
            os.environ.pop("AGENT_CONTROL_API_KEY", None)
        else:
            os.environ["AGENT_CONTROL_API_KEY"] = orig


def test_env_writer_replaces_in_place() -> None:
    with _TempEnv("A=1\nSPLUNK_REALM=old\nB=2\n") as p:
        settings_store._write_env_key("SPLUNK_REALM", "us1")
        check("existing key replaced in place", _value(p, "SPLUNK_REALM") == "us1")
        check("exactly one line after replace", _count(p, "SPLUNK_REALM") == 1)
        settings_store._write_env_key("SPLUNK_REALM", "eu0")
        check("still exactly one line after a second write", _count(p, "SPLUNK_REALM") == 1)
        check("neighbouring keys untouched",
              _value(p, "A") == "1" and _value(p, "B") == "2")


def test_env_writer_collapses_pre_existing_duplicates() -> None:
    with _TempEnv("SPLUNK_REALM=one\nX=9\nSPLUNK_REALM=two\n") as p:
        settings_store._write_env_key("SPLUNK_REALM", "us1")
        check("a pre-existing duplicate is collapsed to one line",
              _count(p, "SPLUNK_REALM") == 1)
        check("the surviving line has the new value", _value(p, "SPLUNK_REALM") == "us1")
        check("unrelated key survives the collapse", _value(p, "X") == "9")


def test_env_writer_appends_when_absent_and_preserves_mode() -> None:
    with _TempEnv("A=1\n") as p:
        settings_store._write_env_key("O11Y_API", "tok")
        check("absent key is appended", _value(p, "O11Y_API") == "tok")
        check("file mode stays 0600", stat.S_IMODE(p.stat().st_mode) == 0o600)

    # A file with no trailing newline must not get its last line glued to the new one.
    with _TempEnv("A=1") as p:
        settings_store._write_env_key("SPLUNK_REALM", "us1")
        check("missing trailing newline handled", _value(p, "A") == "1"
              and _value(p, "SPLUNK_REALM") == "us1")


def test_env_writer_survives_awkward_values() -> None:
    with _TempEnv("O11Y_INGEST=old\n") as p:
        awkward = "a=b&c/d|e+f=="
        settings_store._write_env_key("O11Y_INGEST", awkward)
        check("a value containing = & / | round-trips verbatim",
              _value(p, "O11Y_INGEST") == awkward)
        rejected = False
        try:
            settings_store._write_env_key("SPLUNK_REALM", "us1\nEVIL=1")
        except ValueError:
            rejected = True
        check("a newline in a value is rejected (would forge a second key)", rejected)
        check("the injected key was not written", _count(p, "EVIL") == 0)


def test_collector_keys_go_to_env_not_the_blob() -> None:
    with _TempEnv("SPLUNK_REALM=old\n") as p:
        restart = settings_store.set_integration_creds("splunk_o11y", {"realm": "us1"})
        check("realm written to .env", _value(p, "SPLUNK_REALM") == "us1")
        check("save reports the collector needs a restart", restart == ["collector"])
        blob = settings_store.load().get("integration_creds") or {}
        check("collector key is NOT mirrored into the settings blob "
              "(.env stays its single source of truth)",
              "realm" not in (blob.get("splunk_o11y") or {}))


def test_live_fields_report_no_restart() -> None:
    orig = settings.ai_defense_region
    try:
        restart = settings_store.set_integration_creds("ai_defense", {"region": "us"})
        check("an applies-live save reports no restart needed", restart == [])
    finally:
        settings.ai_defense_region = orig


def test_resource_attributes_round_trip() -> None:
    """The per-instance identity field: what a multi-instance workshop edits."""
    with _TempEnv("SPLUNK_REALM=us1\n"
                  "OTEL_RESOURCE_ATTRIBUTES=deployment.environment=pseudoco-assistant-local\n"
                  "OTEL_ENABLED=True\n") as env:
        restart = settings_store.set_integration_creds(
            "splunk_o11y",
            {"resource_attributes": "deployment.environment=medadvice2,host.name=box2"})
        check("resource attributes rewritten in place",
              _value(env, "OTEL_RESOURCE_ATTRIBUTES")
              == "deployment.environment=medadvice2,host.name=box2")
        check("exactly one OTEL_RESOURCE_ATTRIBUTES line",
              _count(env, "OTEL_RESOURCE_ATTRIBUTES") == 1)
        check("the comma-separated value survives the .env round-trip",
              "," in _value(env, "OTEL_RESOURCE_ATTRIBUTES"))
        check("save reports the app needs a restart", restart == ["app"])
        check("neighbouring keys untouched",
              _value(env, "SPLUNK_REALM") == "us1" and _value(env, "OTEL_ENABLED") == "True")
        check("it is a .env field, not mirrored into the blob",
              "resource_attributes" not in (
                  settings_store.load().get("integration_creds", {}).get("splunk_o11y") or {}))


def test_resource_attributes_rejects_malformed_values() -> None:
    """A malformed list fails SILENTLY in the OTel SDK — the box would just never
    get its identity. Reject it at save time instead."""
    bad = {
        "no key=value pair": "pseudoco-assistant-local",
        "a stray comma": "deployment.environment=a,,host.name=b",
        "an empty key": "=pseudoco-assistant-local",
        # backend/config.py::_strip_env_value would truncate this on the next reload.
        "an unquoted ' #' comment": "deployment.environment=a # box 2",
    }
    for name, value in bad.items():
        with _TempEnv("OTEL_RESOURCE_ATTRIBUTES=deployment.environment=keep-me\n") as env:
            try:
                settings_store.set_integration_creds(
                    "splunk_o11y", {"resource_attributes": value})
                check(f"rejects {name}", False)
            except ValueError:
                check(f"rejects {name}", True)
            check(f"...and leaves the existing value alone ({name})",
                  _value(env, "OTEL_RESOURCE_ATTRIBUTES") == "deployment.environment=keep-me")

    with _TempEnv() as env:
        for value in ("deployment.environment=pseudoco-assistant-local",
                      "deployment.environment=a, host.name=b , service.version=4.1.0"):
            settings_store.set_integration_creds(
                "splunk_o11y", {"resource_attributes": value})
        check("a well-formed list is accepted",
              _value(env, "OTEL_RESOURCE_ATTRIBUTES").startswith("deployment.environment=a,"))


def test_env_file_fields_prefill_from_env_not_the_process() -> None:
    """An env_file field is owned by .env, and a library may rewrite the process
    copy. The Splunk OTel distro appends its own telemetry.distro.* attributes to
    OTEL_RESOURCE_ATTRIBUTES at bootstrap, so prefilling from os.environ would show
    a value .env does not have — and a save the operator never edited would write
    the distro's internals into .env."""
    key = "OTEL_RESOURCE_ATTRIBUTES"
    orig = os.environ.get(key)
    os.environ[key] = ("deployment.environment=pseudoco-assistant-local,"
                       "telemetry.distro.name=splunk-opentelemetry,"
                       "telemetry.distro.version=2.8.0")
    try:
        with _TempEnv(f"{key}=deployment.environment=pseudoco-assistant-local\n"):
            f = [x for x in settings_store.get_integration_fields()["splunk_o11y"]
                 if x["key"] == "resource_attributes"][0]
            check("prefills from .env, not the mutated process environment",
                  f["value"] == "deployment.environment=pseudoco-assistant-local")
            check("the distro's own attributes are not offered back for saving",
                  "telemetry.distro" not in f["value"])
    finally:
        if orig is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = orig

    with _TempEnv('SPLUNK_REALM="eu0"  \nO11Y_API=tok # the read-only one\n'):
        vals = {x["key"]: x.get("value") for x
                in settings_store.get_integration_fields()["splunk_o11y"]}
        check("a quoted .env value is unquoted for display", vals["realm"] == "eu0")
        check("a secret still reports presence only, never its value",
              "api_token" in vals and vals["api_token"] is None)

    with _TempEnv(""):
        vals = {x["key"]: x.get("value") for x
                in settings_store.get_integration_fields()["splunk_o11y"]}
        check("a key absent from .env prefills blank", vals["resource_attributes"] == "")


def test_a_rejected_field_does_not_half_write_the_card() -> None:
    """One card saves every field in one PUT and .env is written key by key, so
    validation has to run over the whole payload BEFORE anything is applied."""
    with _TempEnv("SPLUNK_REALM=us1\n") as env:
        try:
            settings_store.set_integration_creds(
                "splunk_o11y", {"realm": "eu0", "resource_attributes": "malformed"})
            check("a malformed field rejects the whole save", False)
        except ValueError:
            check("a malformed field rejects the whole save", True)
        check("the valid sibling field was NOT written (no partial save)",
              _value(env, "SPLUNK_REALM") == "us1")


def test_unknown_integration_and_empty_payload() -> None:
    check("unknown integration id is a no-op at the store layer",
          settings_store.set_integration_creds("nope", {"api_key": "x"}) == [])
    check("empty payload is a no-op",
          settings_store.set_integration_creds("ai_defense", {}) == [])


def main() -> int:
    for fn in (
        test_choices_and_field_shape,
        test_no_secret_value_ever_leaves_the_box,
        test_blank_secret_keeps_existing,
        test_boolean_false_is_a_real_value,
        test_ai_defense_save_reaches_the_live_client,
        test_startup_applies_saved_ai_defense_key_to_the_live_client,
        test_startup_reconfigures_only_integrations_it_applied,
        test_agent_observability_save_sets_env,
        test_agent_control_creds_are_blob_persisted,
        test_env_writer_replaces_in_place,
        test_env_writer_collapses_pre_existing_duplicates,
        test_env_writer_appends_when_absent_and_preserves_mode,
        test_env_writer_survives_awkward_values,
        test_collector_keys_go_to_env_not_the_blob,
        test_resource_attributes_round_trip,
        test_resource_attributes_rejects_malformed_values,
        test_env_file_fields_prefill_from_env_not_the_process,
        test_a_rejected_field_does_not_half_write_the_card,
        test_live_fields_report_no_restart,
        test_unknown_integration_and_empty_payload,
    ):
        try:
            with _TempStore():
                fn()
        except Exception as e:  # noqa: BLE001
            global _fails
            _fails += 1
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"RESULT: {'ok' if not _fails else str(_fails) + ' failed'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
