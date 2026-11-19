"""Who is asking PatchBot to act, and with which role (docs/patchbot.md).

The role always comes from the person, never from the request body:

- **Duo** (``DUO_ENABLED``): the verified identity session
  (``request.state.identity``) gives the username; the user's Duo groups give
  the role (``DUO_GROUP_ROLES``). A signed-in user in none of those groups is a
  Patch Viewer. ``auth_method="duo"``.
- **Role map** (Duo off, offline dev and boxes without Duo): the attendee picks
  one of the fixed ``PERSONAS`` on the PatchBot page. ``auth_method="role_map"``
  is recorded on every event, so nobody mistakes it for a verified identity.

Each role is what PatchBot's tool calls carry to the Agent Observability
Controls as ``context.initiator_role``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.config import settings

PATCH_VIEWER = "patch_viewer"
LINUX_OPERATOR = "linux_patch_operator"
WINDOWS_OPERATOR = "windows_patch_operator"
CHANGE_APPROVER = "change_approver"
ESTATE_OWNER = "estate_owner"

ROLE_LABELS = {
    PATCH_VIEWER: "Patch Viewer",
    LINUX_OPERATOR: "Linux Patch Operator",
    WINDOWS_OPERATOR: "Windows Patch Operator",
    CHANGE_APPROVER: "Change Approver",
    ESTATE_OWNER: "Estate owner",
}

# Highest first: a user in several groups acts with the first one listed here.
_PRECEDENCE = (ESTATE_OWNER, LINUX_OPERATOR, WINDOWS_OPERATOR, CHANGE_APPROVER, PATCH_VIEWER)

DUO_GROUP_ROLES = {
    "patch-estate-owners": ESTATE_OWNER,
    "patch-linux": LINUX_OPERATOR,
    "patch-windows": WINDOWS_OPERATOR,
    "change-approvers": CHANGE_APPROVER,
    "patch-viewers": PATCH_VIEWER,
}

# Role-map personas (Duo off). Fictional people; no identifiers.
PERSONAS: Dict[str, str] = {
    "dana.lee": LINUX_OPERATOR,
    "ravi.patel": WINDOWS_OPERATOR,
    "sam.ortiz": CHANGE_APPROVER,
    "jo.kim": PATCH_VIEWER,
    "instructor": ESTATE_OWNER,
}

PERSONA_COOKIE = "patchbot_persona"


@dataclass(frozen=True)
class Initiator:
    username: str
    role: str
    roles: List[str] = field(default_factory=list)
    auth_method: str = "role_map"
    duo_groups: List[str] = field(default_factory=list)
    identity_session_ref: Optional[str] = None

    @property
    def role_label(self) -> str:
        return ROLE_LABELS.get(self.role, self.role)

    def as_dict(self) -> Dict[str, Any]:
        return {"username": self.username, "role": self.role, "role_label": self.role_label,
                "roles": list(self.roles), "auth_method": self.auth_method,
                "duo_groups": list(self.duo_groups), "identity_session_ref": self.identity_session_ref}

    def context(self) -> Dict[str, Any]:
        """What every tool call tells the Controls about who it acts for."""
        return {"initiator": self.username, "initiator_role": self.role,
                "initiator_roles": list(self.roles), "auth_method": self.auth_method}


def roles_from_groups(groups: List[str]) -> List[str]:
    found = {DUO_GROUP_ROLES[g] for g in groups if g in DUO_GROUP_ROLES}
    return [r for r in _PRECEDENCE if r in found] or [PATCH_VIEWER]


def duo_mode() -> bool:
    return bool(getattr(settings, "duo_enabled", False))


def from_request(request: Any) -> Optional[Initiator]:
    """The initiator for this request, or None when nobody can be named
    (Duo on and not signed in, or Duo off and no persona picked)."""
    identity = getattr(getattr(request, "state", None), "identity", None)
    if identity is not None and getattr(identity, "username", None):
        groups: List[str] = []
        try:
            from backend.services import identity_lookup
            answer = identity_lookup.duo_user(identity.username) or {}
            groups = [str(g) for g in (answer.get("groups") or [])]
        except Exception:  # noqa: BLE001 - an unreachable Duo leaves the least role
            groups = []
        roles = roles_from_groups(groups)
        return Initiator(username=str(identity.username), role=roles[0], roles=roles,
                         auth_method="duo", duo_groups=groups,
                         identity_session_ref=getattr(identity, "session_ref", None))
    if duo_mode():
        return None
    persona = ""
    try:
        persona = str(request.cookies.get(PERSONA_COOKIE) or "").strip().lower()
    except Exception:  # noqa: BLE001
        persona = ""
    if persona in PERSONAS:
        role = PERSONAS[persona]
        return Initiator(username=persona, role=role, roles=[role], auth_method="role_map")
    return None


def personas() -> List[Dict[str, str]]:
    return [{"username": u, "role": r, "role_label": ROLE_LABELS[r]} for u, r in PERSONAS.items()]
