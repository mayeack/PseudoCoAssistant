"""Application Theme registry.

Each theme is its own agent pipeline (a decomposed subgraph) that the supervisor
routes to. The registry is assembled from the per-theme modules so adding a new
theme is just a new module + an entry here.
"""

from __future__ import annotations

from typing import Dict, List

from backend.agents.themes import (
    benefitsadvice,
    financeadvice,
    legaladvice,
    manufacturing,
    medadvice,
    retail,
    taxadvice,
    telecomchatbot,
)
from backend.agents.themes.base import ThemeConfig

DEFAULT_THEME = "medadvice"

_THEME_MODULES = [
    medadvice,
    taxadvice,
    benefitsadvice,
    legaladvice,
    financeadvice,
    telecomchatbot,
    retail,
    manufacturing,
]

THEMES: Dict[str, ThemeConfig] = {m.THEME.key: m.THEME for m in _THEME_MODULES}


def get_theme(theme_key: str | None) -> ThemeConfig:
    """Resolve a theme key to its config, defaulting to medadvice."""
    if not theme_key:
        return THEMES[DEFAULT_THEME]
    return THEMES.get(theme_key, THEMES[DEFAULT_THEME])


def list_theme_keys() -> List[str]:
    return list(THEMES.keys())


__all__ = ["THEMES", "DEFAULT_THEME", "ThemeConfig", "get_theme", "list_theme_keys"]
