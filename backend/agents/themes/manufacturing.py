"""Manufacturing theme - plant-floor operations, maintenance and quality guidance.

Structured like the advice themes (assessment / guidance / seek_care_if). Its
outside-of-authority category is a Safety Override: the assistant clearing an
operator to run with an interlock bypassed, skip lockout/tagout, or ship a lot
that failed inspection -- authority that belongs to supervision, EHS and quality.
"""

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
        key="equipment_troubleshooting",
        label="Equipment Troubleshooting",
        role="faults, alarms, jams, and abnormal machine behavior",
        focus=(
            "diagnosing machine faults, alarm codes, jams, vibration, overheating, and "
            "other abnormal behavior, and the safe first checks an operator can make"
        ),
    ),
    SpecialistSpec(
        key="maintenance",
        label="Preventive Maintenance",
        role="PM schedules, lubrication, wear parts, and work orders",
        focus=(
            "preventive-maintenance practices — inspection intervals, lubrication, "
            "wear-part replacement, and when a maintenance work order is warranted"
        ),
    ),
    SpecialistSpec(
        key="quality_control",
        label="Quality Control",
        role="defects, inspections, nonconforming product, and holds",
        focus=(
            "defect patterns, inspection and measurement basics, and handling "
            "nonconforming product, while making clear that releasing held product "
            "or approving a deviation belongs to quality, not the assistant"
        ),
    ),
    SpecialistSpec(
        key="workplace_safety",
        label="Workplace Safety",
        role="lockout/tagout, machine guarding, PPE, and when to stop the line",
        focus=(
            "lockout/tagout, machine guarding and interlocks, PPE, and the clear "
            "signs that the line must stop and a supervisor or EHS be called"
        ),
    ),
)

# Scheduling vertical: a maintenance technician inspecting the equipment, booked
# across the production week (Mon-Sat) and early shifts. Never offered on an
# EMERGENCY answer (the answer says to stop and clear the area).
SCHEDULING = SchedulingProfile(
    appointment_noun="maintenance visit",
    provider_noun="a maintenance technician",
    provider_label="Maintenance technician visit",
    slot_minutes=60,
    business_days=(0, 1, 2, 3, 4, 5),
    open_hour=6,
    close_hour=18,
    lead_minutes=120,
    offer_on_severities=("MEDIUM", "HIGH"),
    first_offer_excludes=("EMERGENCY",),
    check="Did that get the equipment running again?",
    check_yes="Yes, it's running",
    check_no="No, it's still down",
    resolved=("Good to hear it's running. If it acts up again, I can book a maintenance "
              "technician to take a look."),
    offer=("Want me to book a maintenance technician to inspect the equipment? "
           "Here are the next available slots:"),
    choose="Here are the next maintenance technician slots:",
    ask_name="Got it — whose name should the maintenance visit be under?",
    confirmed=(
        "You're booked: {label} — maintenance technician visit, under {name}. "
        "Keep the equipment locked out and tagged until they arrive."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If this is urgent, stop the line and contact your supervisor or your "
        "site's EHS team right away."
    ),
    advice_noun="operational guidance",
    # Opens an EMERGENCY answer (an injury, fire, chemical release, or someone
    # trapped -- see the theme prompt). Plant procedure, not a phone number: the
    # site's emergency response team makes the outside call.
    emergency_banner=(
        "PLANT EMERGENCY: Hit the E-stop, clear the area, and alert your supervisor "
        "and the plant emergency response team immediately."
    ),
    escalation_heading="Escalate to a Supervisor or EHS If",
    fallback_guidance=(
        "Stop and make the equipment safe before you investigate.",
        "Follow your site's lockout/tagout and jam-clearing procedures.",
        "Escalate to your supervisor or maintenance lead if you're unsure.",
    ),
    fallback_escalation="A safety device is damaged or the fault keeps coming back",
)

THRASH = build_profile("mes-mcp", "work_order")

DOCS = InternalDocsProfile(
    collection="manufacturing",
    trigger_terms=(
        "quality hold",
        "quality-hold",
        "scrap cost",
        "second source",
    ),
)

THEME = ThemeConfig(
    key="manufacturing",
    label="Manufacturing",
    conversational=is_conversational("manufacturing"),
    system_prompt=prompt_for("manufacturing"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
