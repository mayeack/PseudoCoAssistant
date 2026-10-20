"""MedAdvice theme - general medical guidance (default)."""

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
        key="triage",
        label="Triage",
        role="urgency assessment and emergency red-flag detection",
        focus=(
            "assessing how urgent the situation is and spotting life-threatening "
            "red-flag symptoms that warrant 911 or immediate in-person care"
        ),
    ),
    SpecialistSpec(
        key="symptom_analysis",
        label="Symptom Analysis",
        role="interpreting described symptoms and likely benign vs concerning patterns",
        focus=(
            "interpreting the described symptoms, their duration and severity, and "
            "common benign vs concerning explanations (without diagnosing)"
        ),
    ),
    SpecialistSpec(
        key="medication_safety",
        label="Medication Safety",
        role="OTC options, interactions, dosing cautions, and prescribing boundaries",
        focus=(
            "appropriate over-the-counter options, interaction/contraindication "
            "cautions, and the firm boundary against prescription/controlled dosing"
        ),
    ),
    SpecialistSpec(
        key="care_navigation",
        label="Care Navigation",
        role="self-care, when/where to seek professional care, and follow-up",
        focus=(
            "home/self-care guidance and clear indicators of when and where to seek "
            "professional medical care or follow-up"
        ),
    ),
)

# Scheduling vertical: a clinician follow-up visit. Never offered on an EMERGENCY
# answer (the answer says to call 911); re-offered on later MEDIUM/HIGH answers.
SCHEDULING = SchedulingProfile(
    appointment_noun="follow-up visit",
    provider_noun="a clinician",
    provider_label="Clinician follow-up visit",
    slot_minutes=20,
    business_days=(0, 1, 2, 3, 4),
    open_hour=8,
    close_hour=17,
    lead_minutes=120,
    offer_on_severities=("MEDIUM", "HIGH"),
    first_offer_excludes=("EMERGENCY",),
    offer=(
        "Would you like to schedule a follow-up visit with a clinician to go over this "
        "in person? Here are the next available times:"
    ),
    confirmed=(
        "You're booked: {label} — follow-up visit with a clinician, under {name}. "
        "Bring a list of your current medications."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If this is a medical emergency, call 911 or go to your nearest "
        "emergency room."
    ),
    advice_noun="medical advice",
    emergency_banner=(
        "EMERGENCY: Call 911 or go to the nearest emergency room immediately."
    ),
    escalation_heading="Seek Professional Care If",
)

THRASH = build_profile("patient-records-mcp", "patient_record")

DOCS = InternalDocsProfile(
    collection="medadvice",
    trigger_terms=(
        "payer contract",
        "contract rate",
        "contract rates",
        "triage protocol",
    ),
)

THEME = ThemeConfig(
    key="medadvice",
    label="MedAdvice",
    conversational=is_conversational("medadvice"),
    system_prompt=prompt_for("medadvice"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
