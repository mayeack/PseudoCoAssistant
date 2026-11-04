"""Sample attack documents for the Prompt Library's "Document injection" section
(docs/attachments.md, backend/services/attack_documents.py).

Behind the access key like every /api route (not in ``PUBLIC_PATHS``). The PDFs
are rendered on demand from the theme's cover profile; the theme is resolved
here and passed in, because attack_documents may not import the theme registry.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.agents.themes import DEFAULT_THEME, THEMES, ThemeConfig
from backend.services import attack_documents

router = APIRouter(prefix="/api/attachments", tags=["attachments"])


def _theme(theme: Optional[str]) -> ThemeConfig:
    # Strict, unlike get_theme(): an unknown key is a 404, not medadvice's PDF
    # under another theme's name.
    key = theme or DEFAULT_THEME
    config = THEMES.get(key)
    if config is None:
        raise HTTPException(status_code=404, detail=f"Unknown theme '{key}'")
    return config


@router.get("/samples")
async def list_samples(theme: Optional[str] = None):
    """The theme's sample documents: one per hiding technique plus the clean
    control, each with the prompt to send it with and its PDF URL."""
    config = _theme(theme)
    return {
        "theme": config.key,
        "samples": attack_documents.catalog(config.sample_document, config.key),
    }


@router.get("/samples/{sample_id}.pdf")
async def get_sample_pdf(sample_id: str, theme: Optional[str] = None):
    """One sample PDF, inline: a viewer shows only the cover, never the hidden
    text. ``no-store`` so a preview is never served from a stale cache after
    the cover or payload changes."""
    config = _theme(theme)
    sample = attack_documents.get_sample(sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample '{sample_id}'")
    profile = config.sample_document
    return Response(
        content=attack_documents.build_pdf(profile, sample),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{attack_documents.download_filename(profile, sample)}"',
            "Cache-Control": "no-store",
        },
    )
