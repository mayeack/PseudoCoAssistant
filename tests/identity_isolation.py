"""Keep a test suite's identity code off every real Duo tenant and CII (Lab 5).

``backend.config`` loads the checkout's ``.env``, and the dev copy's ``.env``
holds the Lab 5 keys (plan 12.5). A suite that turns ``DUO_ENABLED`` on would
then send signed Duo Admin API status requests for real personas, and CII
token and GraphQL calls after them, with results that depend on the live
tenant. ``isolate(settings)`` blanks every Duo / CII setting (a suite sets the
ones it needs itself, with fakes) and routes ``identity_lookup`` through a
transport that answers nothing: each request it gets is recorded and refused
with a 503, and ``requests_refused()`` lists them, so a suite can fail on any.
``restore()`` puts that transport back after a test installed its own fake.
``tests/run_all.sh`` also exports the keys empty, which beats ``.env`` in both
loaders.

Import it after ``backend.config`` and call ``isolate`` before the app is
imported.
"""
from __future__ import annotations

from typing import Any, List

import httpx

#: Every Duo / CII setting (and what points a sign-in at an instance). Empty:
#: identity_lookup and identity_signin are not configured, so they send nothing.
IDENTITY_SETTINGS = ("public_base_url", "duo_client_id", "duo_client_secret", "duo_api_host", "duo_admin_ikey",
                     "duo_admin_skey", "cii_client_id", "cii_client_secret", "cii_token_url", "cii_api_url",
                     "identity_allowed_users")

_refused: List[str] = []


def _refuse(request: httpx.Request) -> httpx.Response:
    _refused.append(f"{request.method} {request.url.host}{request.url.path}")
    return httpx.Response(503, json={"error": "the test suites never reach Duo or Identity Intelligence"})


REFUSING_TRANSPORT = httpx.MockTransport(_refuse)


def restore() -> None:
    """Route identity_lookup through the refusing transport again."""
    from backend.services import identity_lookup

    identity_lookup.set_transport(REFUSING_TRANSPORT)


def isolate(settings: Any) -> None:
    """Duo sign-in off, every Duo / CII setting blank, lookups refused."""
    settings.duo_enabled = False
    for name in IDENTITY_SETTINGS:
        setattr(settings, name, "")
    restore()


def requests_refused() -> List[str]:
    """Every identity request a suite made while isolated (it should make none)."""
    return list(_refused)
