"""TelecomChatbot theme - synthetic wireless/internet support (conversational).

This theme is conversational: it skips the medical clarifier and renders the
model's free-text ``reply`` verbatim. The specialists still produce internal
findings; only the synthesizer's ``reply`` is shown to the customer.
"""

from backend.agents.themes.base import (
    GuardrailCopy,
    SpecialistSpec,
    ThemeConfig,
    is_conversational,
    prompt_for,
)
from backend.services.scheduling import SchedulingProfile
from backend.services.mcp_thrash import build_profile

SPECIALISTS = (
    SpecialistSpec(
        key="network_diagnostics",
        label="Network Diagnostics",
        role="cell/data/Wi-Fi signal and connectivity troubleshooting",
        focus=(
            "diagnosing cell service, mobile data, and home Wi-Fi/router connectivity "
            "problems and the basic troubleshooting steps that usually help"
        ),
    ),
    SpecialistSpec(
        key="billing",
        label="Billing & Plans",
        role="general billing and plan questions (no real account access)",
        focus=(
            "general billing and plan questions, while making clear the assistant "
            "cannot view or change any real account and must defer such changes"
        ),
    ),
    SpecialistSpec(
        key="device_setup",
        label="Device Setup",
        role="restarts, updates, SIM/eSIM, and network-reset steps",
        focus=(
            "device basics — restarts, software updates, SIM/eSIM reseating, and "
            "network-reset steps the customer can safely perform themselves"
        ),
    ),
    SpecialistSpec(
        key="account_security",
        label="Account Security",
        role="lost/stolen device, fraud, SIM-swap, and escalation",
        focus=(
            "account-security concerns (lost/stolen device, suspected fraud or "
            "SIM-swap) and when to escalate to a human agent or store visit, never "
            "accepting real passwords, PINs, or one-time codes"
        ),
    ),
)

# Scheduling vertical: a technician visit booked as a 2-hour ARRIVAL WINDOW
# (Mon-Sat), the way a truck roll is actually scheduled.
SCHEDULING = SchedulingProfile(
    appointment_noun="technician visit",
    provider_noun="a field technician",
    provider_label="Technician visit",
    slot_minutes=120,
    window_minutes=120,
    business_days=(0, 1, 2, 3, 4, 5),
    open_hour=8,
    close_hour=18,
    lead_minutes=240,
    offer_on_severities=("HIGH", "EMERGENCY"),
    check="Did that fix the problem?",
    check_yes="Yes, it's working now",
    check_no="No, still having trouble",
    resolved="Great — glad it's sorted. If it acts up again, I can get a technician out to you.",
    offer="Want me to schedule a technician visit? Pick an arrival window:",
    choose="Here are the next technician arrival windows:",
    clarify_slot="Just so I send the technician at the right time — did you mean one of these?",
    day_unavailable=("I don't have {day} arrival windows — technician visits run {days}. "
                     "Here are the closest:"),
    ask_name="Got it — whose name should the visit be under?",
    confirmed=(
        "You're all set: a technician will arrive {label}, booked under {name}. "
        "Please make sure someone 18+ is home."
    ),
    already_booked=(
        "You already have a technician visit scheduled for {label}. Ask me about "
        "your schedule if you'd like to change it."
    ),
    cancelled="Done — the technician visit for {label} has been cancelled.",
    rescheduled="Done — the technician will now arrive {label}.",
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If you need help right away, call our support line or visit a retail "
        "store to speak with an agent."
    ),
    advice_noun="assistance",
    # This theme's EMERGENCY is a life-threatening one (see its prompt), so 911
    # is right here. Its reply is shown verbatim, so the banner never renders
    # today -- it is defined so the copy is correct if that changes.
    emergency_banner=(
        "EMERGENCY: Call 911 from any available phone or landline immediately."
    ),
)

THRASH = build_profile("subscriber-crm-mcp", "subscriber_account")

THEME = ThemeConfig(
    key="telecomchatbot",
    label="TelecomChatbot",
    conversational=is_conversational("telecomchatbot"),
    system_prompt=prompt_for("telecomchatbot"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
)
