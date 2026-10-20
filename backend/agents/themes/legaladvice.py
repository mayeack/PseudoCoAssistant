"""LegalAdvice theme - general legal information (not attorney counsel)."""

from backend.agents.themes.base import (
    GuardrailCopy,
    SpecialistSpec,
    ThemeConfig,
    is_conversational,
    prompt_for,
)
from backend.services.scheduling import SchedulingProfile
from backend.services.internal_docs import InternalDocsProfile
from backend.services.mcp_thrash import build_profile

SPECIALISTS = (
    SpecialistSpec(
        key="issue_spotting",
        label="Issue Spotting",
        role="identifying the legal issues and area of law in play",
        focus=(
            "identifying the underlying legal issues and the area(s) of law involved, "
            "framing what is actually at stake (general information only)"
        ),
    ),
    SpecialistSpec(
        key="rights_obligations",
        label="Rights & Obligations",
        role="general rights, obligations, and common options",
        focus=(
            "the user's general rights and obligations and the common options people "
            "have in this kind of situation, without giving tailored legal advice"
        ),
    ),
    SpecialistSpec(
        key="procedure_deadlines",
        label="Procedure & Deadlines",
        role="processes, filings, and time-sensitive deadlines",
        focus=(
            "relevant processes/filings and any time-sensitive deadlines or statutes "
            "of limitations the user should be aware of"
        ),
    ),
    SpecialistSpec(
        key="referral_scope",
        label="Referral & Scope",
        role="when a licensed attorney is needed and red-line topics",
        focus=(
            "clear indicators the user needs a licensed attorney, and red-line topics "
            "(criminal exposure, court deadlines) that must not be self-handled"
        ),
    ),
)

# Scheduling vertical: a consultation with an attorney.
SCHEDULING = SchedulingProfile(
    appointment_noun="consultation",
    provider_noun="an attorney",
    provider_label="Attorney consultation",
    slot_minutes=30,
    business_days=(0, 1, 2, 3, 4),
    open_hour=9,
    close_hour=17,
    lead_minutes=180,
    offer=(
        "Would you like to schedule a consultation with an attorney about this? "
        "Here are the next available times:"
    ),
    confirmed=(
        "You're booked: {label} — consultation with an attorney, under {name}. "
        "Bring any documents, notices or deadlines you have."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If you need urgent legal help, contact a licensed attorney or your "
        "local legal aid service."
    ),
    advice_noun="legal advice",
    emergency_banner=(
        "LEGAL EMERGENCY: Contact a licensed attorney or your local legal aid "
        "service immediately."
    ),
)

THRASH = build_profile("case-law-mcp", "case_file")

DOCS = InternalDocsProfile(
    collection="legaladvice",
    trigger_terms=(
        "settlement authority",
        "authority matrix",
    ),
)

THEME = ThemeConfig(
    key="legaladvice",
    label="LegalAdvice",
    conversational=is_conversational("legaladvice"),
    system_prompt=prompt_for("legaladvice"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
