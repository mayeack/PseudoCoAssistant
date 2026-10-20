"""TaxAdvice theme - general tax information (not CPA advice)."""

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
        key="deductions",
        label="Deductions & Credits",
        role="common deductions, credits, and recordkeeping awareness",
        focus=(
            "commonly available deductions and credits, eligibility basics, and the "
            "records a taxpayer should keep (general awareness, not filing instructions)"
        ),
    ),
    SpecialistSpec(
        key="filing_status",
        label="Filing Status & Deadlines",
        role="filing status, forms, and key deadlines",
        focus=(
            "filing status options, the common forms involved, and the key deadlines "
            "or extension considerations relevant to the question"
        ),
    ),
    SpecialistSpec(
        key="compliance_risk",
        label="Compliance Risk",
        role="audit-risk, penalties, liens, and when to see a professional",
        focus=(
            "audit/penalty exposure, liens or garnishments, and clear indicators that "
            "the user needs a CPA, enrolled agent, or tax attorney"
        ),
    ),
    SpecialistSpec(
        key="entity_structuring",
        label="Entity & Situation Complexity",
        role="business/multi-state/estate complexity that exceeds general guidance",
        focus=(
            "business, multi-state, international, or estate/gift complexity that "
            "exceeds general guidance and should be flagged for professional help"
        ),
    ),
)

# Scheduling vertical: a meeting with a tax preparer (Saturdays included).
SCHEDULING = SchedulingProfile(
    appointment_noun="meeting",
    provider_noun="a tax preparer",
    provider_label="Tax preparer meeting",
    slot_minutes=30,
    business_days=(0, 1, 2, 3, 4, 5),
    open_hour=9,
    close_hour=18,
    lead_minutes=180,
    offer=(
        "Would you like to schedule a meeting with a tax preparer to review your "
        "situation? Here are the next available times (Saturdays included):"
    ),
    confirmed=(
        "You're booked: {label} — meeting with a tax preparer, under {name}. "
        "Have last year's return and any notices handy."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If you are facing an imminent IRS deadline, lien, or levy, contact a "
        "licensed tax professional or the IRS at 1-800-829-1040."
    ),
    advice_noun="tax advice",
    emergency_banner=(
        "URGENT TAX MATTER: Contact a licensed tax professional or the IRS "
        "immediately."
    ),
    escalation_heading="Talk to a Tax Professional If",
)

THRASH = build_profile("tax-filing-mcp", "tax_return")

DOCS = InternalDocsProfile(
    collection="taxadvice",
    trigger_terms=(
        "audit-risk score",
        "audit risk score",
        "risk scoring",
        "audit-defense plan",
    ),
)

THEME = ThemeConfig(
    key="taxadvice",
    label="TaxAdvice",
    conversational=is_conversational("taxadvice"),
    system_prompt=prompt_for("taxadvice"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
