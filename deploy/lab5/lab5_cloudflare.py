"""The Cloudflare calls lab5-setup makes, with the scoped API token from the
Keychain item ``pseudoco-lab5-cloudflare`` (Tunnel edit + pseudocoassistant.com
DNS edit). Stdlib only.

The token travels in the Authorization header and nowhere else: not in a URL,
an error message or the run log. Tunnel-create and token responses carry the
tunnel secret; they are read for the id and token and never printed.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from lab5_common import Lab5Error

API = "https://api.cloudflare.com/client/v4"
Transport = Callable[[str, str, Dict[str, str], Optional[bytes], float], Tuple[int, bytes]]


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # optional: python.org builds on macOS ship no CA bundle
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes],
                     timeout: float) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise Lab5Error(f"{urllib.parse.urlsplit(url).netloc} unreachable ({type(reason).__name__})")


class CloudflareAPI:
    def __init__(self, token: str, transport: Transport = urllib_transport, timeout: float = 30.0) -> None:
        self._token = token
        self._transport = transport
        self._timeout = timeout

    # ---------------------------------------------------------------- plumbing
    def _call(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
              body: Optional[Dict[str, Any]] = None, missing_ok: bool = False) -> Any:
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status, raw = self._transport(method, url, headers, data, self._timeout)
        try:
            doc = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            doc = {}
        if status == 404 and missing_ok:
            return None
        if status >= 300 or not doc.get("success", False):
            errors = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in (doc.get("errors") or [])[:3])
            raise Lab5Error(f"Cloudflare {method} {path.split('?')[0]}: HTTP {status} {errors}".rstrip())
        return doc.get("result")

    # ---------------------------------------------------------------- zone
    def zone(self, name: str) -> Tuple[str, str]:
        """(zone id, account id) for the zone the token can edit."""
        result = self._call("GET", "/zones", {"name": name}) or []
        if not result:
            raise Lab5Error(f"the Cloudflare token cannot see zone {name} (needs DNS edit on it)")
        zone = result[0]
        return zone["id"], (zone.get("account") or {}).get("id", "")

    # ---------------------------------------------------------------- tunnels
    def find_tunnels(self, account: str, name: str) -> List[Dict[str, Any]]:
        return list(self._call("GET", f"/accounts/{account}/cfd_tunnel",
                               {"name": name, "is_deleted": "false"}) or [])

    def tunnels_with_prefix(self, account: str, prefix: str) -> List[Dict[str, Any]]:
        return list(self._call("GET", f"/accounts/{account}/cfd_tunnel",
                               {"include_prefix": prefix, "is_deleted": "false", "per_page": 1000}) or [])

    def get_tunnel(self, account: str, tunnel_id: str) -> Optional[Dict[str, Any]]:
        tunnel = self._call("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}", missing_ok=True)
        if not tunnel or tunnel.get("deleted_at"):
            return None
        return tunnel

    def create_tunnel(self, account: str, name: str) -> str:
        """A remotely managed tunnel (its ingress lives in Cloudflare). Returns
        the id; the secret in the response is dropped here."""
        result = self._call("POST", f"/accounts/{account}/cfd_tunnel",
                            body={"name": name, "config_src": "cloudflare"})
        return result["id"]

    def tunnel_token(self, account: str, tunnel_id: str) -> str:
        token = self._call("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/token")
        if not isinstance(token, str) or not token:
            raise Lab5Error("Cloudflare returned no tunnel token")
        return token

    def tunnel_ingress(self, account: str, tunnel_id: str) -> List[Dict[str, Any]]:
        result = self._call("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations",
                            missing_ok=True) or {}
        return list(((result.get("config") or {}).get("ingress")) or [])

    def set_tunnel_ingress(self, account: str, tunnel_id: str, hostname: str, service: str) -> None:
        self._call("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations",
                   body={"config": {"ingress": [
                       {"hostname": hostname, "service": service, "originRequest": {}},
                       {"service": "http_status:404"},
                   ]}})

    def delete_tunnel(self, account: str, tunnel_id: str) -> bool:
        """Drop its connections (a connector that never stopped, or a box Show
        already destroyed), then the tunnel. False if it was already gone."""
        if self.get_tunnel(account, tunnel_id) is None:
            return False
        self._call("DELETE", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/connections", missing_ok=True)
        return self._call("DELETE", f"/accounts/{account}/cfd_tunnel/{tunnel_id}", missing_ok=True) is not None

    # ---------------------------------------------------------------- dns
    def find_records(self, zone: str, fqdn: str) -> List[Dict[str, Any]]:
        return list(self._call("GET", f"/zones/{zone}/dns_records", {"name.exact": fqdn}) or [])

    def records_with_prefix(self, zone: str, prefix: str) -> List[Dict[str, Any]]:
        return list(self._call("GET", f"/zones/{zone}/dns_records",
                               {"name.startswith": prefix, "per_page": 5000}) or [])

    def get_record(self, zone: str, record_id: str) -> Optional[Dict[str, Any]]:
        return self._call("GET", f"/zones/{zone}/dns_records/{record_id}", missing_ok=True)

    def create_cname(self, zone: str, fqdn: str, target: str, comment: str) -> str:
        result = self._call("POST", f"/zones/{zone}/dns_records",
                            body={"type": "CNAME", "name": fqdn, "content": target,
                                  "proxied": True, "ttl": 1, "comment": comment[:100]})
        return result["id"]

    def update_cname(self, zone: str, record_id: str, target: str) -> None:
        self._call("PATCH", f"/zones/{zone}/dns_records/{record_id}",
                   body={"content": target, "proxied": True})

    def delete_record(self, zone: str, record_id: str) -> bool:
        return self._call("DELETE", f"/zones/{zone}/dns_records/{record_id}", missing_ok=True) is not None
