"""Keep a test suite off every real Duo tenant and CII, and off the Lab 5 settings of the checkout's .env.

``backend.config`` loads the checkout's ``.env``, and the dev copy's ``.env``
holds the Lab 5 keys (plan 12.5: the release is tested on the dev copy). A
suite that turns ``DUO_ENABLED`` on would then send signed Duo Admin
API status requests for real personas, and CII token and GraphQL calls after
them, with results that depend on the live tenant; and a suite would read
lab5-setup's behaviour settings (``IDENTITY_FAIL_OPEN``, the TTLs,
``HEC_HOST``) instead of the app's defaults it was written against.

``isolate(settings)`` blanks every Duo / CII setting (a suite sets the ones it
needs itself, with fakes), puts the other Lab 5 keys lab5-setup writes back to
the app's defaults, routes ``identity_lookup`` through a transport that
answers nothing, and installs a Duo Web SDK client factory that builds
nothing: each request either one gets is recorded and refused, and
``requests_refused()`` lists them, so a suite can fail on any. ``restore()``
puts the lookup transport back after a test installed its own fake, and
``refuse_websdk()`` the client factory. ``tests/run_all.sh`` also exports the
credentials empty, which beats ``.env`` in both loaders.

A suite that starts the app in a child process gets none of this from its own
process: the child loads ``.env`` again. Run it with ``env=child_env()``.

Import it after ``backend.config`` and call ``isolate`` before the app is
imported (tests/test_duo_signin.py fails on a suite that starts the app
without that call).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional

import httpx

#: Every Duo / CII setting (and what points a sign-in at an instance). Empty:
#: identity_lookup and identity_signin are not configured, so they send nothing.
IDENTITY_SETTINGS = ("public_base_url", "duo_client_id", "duo_client_secret", "duo_api_host", "duo_admin_ikey",
                     "duo_admin_skey", "cii_client_id", "cii_client_secret", "cii_token_url", "cii_api_url",
                     "identity_allowed_users")
#: The other Lab 5 keys lab5-setup writes (deploy/lab5/lab5_envfile.LAB5_KEYS):
#: put back to the app's defaults (``Settings`` field defaults).
LAB5_DEFAULT_SETTINGS = ("identity_session_ttl_minutes", "identity_status_ttl_seconds", "identity_fail_open",
                         "hec_host")

_refused: List[str] = []


def _refuse(request: httpx.Request) -> httpx.Response:
    _refused.append(f"{request.method} {request.url.host}{request.url.path}")
    return httpx.Response(503, json={"error": "the test suites never reach Duo or Identity Intelligence"})


REFUSING_TRANSPORT = httpx.MockTransport(_refuse)


def _refuse_websdk(*, client_id: str = "", client_secret: str = "", host: str = "", redirect_uri: str = "",
                   duo_certs: Optional[str] = None) -> Any:
    """identity_signin's client factory while a suite is isolated: no
    duo_universal client is built, so no Web SDK call (health check, sign-in
    start, code exchange) can reach Duo; the attempt is recorded."""
    _refused.append(f"Web SDK client for {host or '(no host)'}")
    raise ConnectionError("the test suites never reach Duo (Web SDK)")


def restore() -> None:
    """Route identity_lookup through the refusing transport again."""
    from backend.services import identity_lookup

    identity_lookup.set_transport(REFUSING_TRANSPORT)


def refuse_websdk() -> None:
    """Build no Duo Web SDK client again (after a test installed its own fake)."""
    from backend.services import identity_signin

    identity_signin.set_client_factory(_refuse_websdk)


def isolate(settings: Any) -> None:
    """Duo sign-in off, every Duo / CII setting blank, the other Lab 5
    settings at their defaults, lookups and Web SDK clients refused."""
    settings.duo_enabled = False
    for name in IDENTITY_SETTINGS:
        setattr(settings, name, "")
    fields = type(settings).model_fields
    for name in LAB5_DEFAULT_SETTINGS:
        setattr(settings, name, fields[name].default)
    restore()
    refuse_websdk()


def child_env(base: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """The environment for a child process that starts the app: ``base``
    (default: this process's) with every Lab 5 key overridden, the credentials
    empty and the rest at the app's defaults. An exported variable beats
    ``.env`` in both loaders, so the child never reads the checkout's."""
    from backend.config import Settings

    env = dict(os.environ if base is None else base)
    env["DUO_ENABLED"] = "false"
    env.update({name.upper(): "" for name in IDENTITY_SETTINGS})
    for name in LAB5_DEFAULT_SETTINGS:
        value = Settings.model_fields[name].default
        env[name.upper()] = str(value).lower() if isinstance(value, bool) else str(value)
    return env


def requests_refused() -> List[str]:
    """Every identity request a suite made while isolated (it should make none)."""
    return list(_refused)
