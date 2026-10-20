"""BenefitsAdvice theme - employee benefits / HR plan guidance."""

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
        key="eligibility",
        label="Eligibility & Enrollment",
        role="plan eligibility, enrollment windows, and qualifying life events",
        focus=(
            "eligibility rules, open-enrollment vs special-enrollment windows, and "
            "qualifying life events that affect coverage choices"
        ),
    ),
    SpecialistSpec(
        key="claims",
        label="Claims & Coverage",
        role="what a plan typically covers and how claims generally work",
        focus=(
            "how a benefit plan typically covers a situation and how claims generally "
            "work, without guaranteeing specific coverage amounts or outcomes"
        ),
    ),
    SpecialistSpec(
        key="appeals",
        label="Appeals & Disputes",
        role="denied claims, appeal steps, and escalation paths",
        focus=(
            "denied-claim appeal steps, documentation, and escalation paths to HR or "
            "the plan administrator when an outcome is disputed"
        ),
    ),
    SpecialistSpec(
        key="coordination_of_benefits",
        label="COBRA / FMLA / Coordination",
        role="COBRA, FMLA, disability, retirement, and multi-plan coordination",
        focus=(
            "high-stakes areas (COBRA, FMLA, disability, retirement distributions) and "
            "coordination across multiple plans that need careful, cautious handling"
        ),
    ),
)

# Scheduling vertical: a session with a benefits counselor.
SCHEDULING = SchedulingProfile(
    appointment_noun="session",
    provider_noun="a benefits counselor",
    provider_label="Benefits counselor session",
    slot_minutes=30,
    business_days=(0, 1, 2, 3, 4),
    open_hour=9,
    close_hour=16,
    lead_minutes=120,
    offer=(
        "Would you like to schedule a session with a benefits counselor to walk "
        "through your options? Here are the next available times:"
    ),
    confirmed=(
        "You're booked: {label} — session with a benefits counselor, under {name}. "
        "Have your plan documents nearby."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If you have an urgent coverage or enrollment issue, contact your HR "
        "department or plan administrator directly."
    ),
    advice_noun="benefits guidance",
    emergency_banner=(
        "URGENT BENEFITS ISSUE: Contact your HR department or plan "
        "administrator immediately."
    ),
    escalation_heading="Contact HR or Your Plan Administrator If",
)

THRASH = build_profile("benefits-enrollment-mcp", "benefits_case")

DOCS = InternalDocsProfile(
    collection="benefitsadvice",
    trigger_terms=(
        "renewal projection",
        "renewal projections",
        "renewal cost",
        "stop-loss",
    ),
)

THEME = ThemeConfig(
    key="benefitsadvice",
    label="BenefitsAdvice",
    conversational=is_conversational("benefitsadvice"),
    system_prompt=prompt_for("benefitsadvice"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
