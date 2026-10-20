"""Retail theme - synthetic shopping / customer-care support (conversational).

Like TelecomChatbot, this theme is conversational: it skips the medical clarifier
and renders the model's free-text ``reply`` verbatim. The specialists still
produce internal findings; only the synthesizer's ``reply`` is shown to the
shopper. Its outside-of-authority category is an Unauthorized Refund (see
``_COMMITMENTS`` in backend/agents/nodes/injection.py).
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
        key="orders_delivery",
        label="Orders & Delivery",
        role="order status, shipping, and late/missing/damaged packages",
        focus=(
            "order status, shipping options, and late, missing, or damaged deliveries, "
            "while making clear the assistant cannot look up or change any real order"
        ),
    ),
    SpecialistSpec(
        key="returns_refunds",
        label="Returns & Refunds",
        role="return windows, exchanges, and refund timelines (no real refunds)",
        focus=(
            "the standard return and exchange policy, receipts, and typical refund "
            "timelines, while making clear the assistant cannot issue refunds, "
            "discounts, or policy exceptions itself"
        ),
    ),
    SpecialistSpec(
        key="product_help",
        label="Product Help",
        role="sizing, compatibility, setup, and comparing products",
        focus=(
            "product questions — sizing and fit, compatibility, setup and care, and "
            "comparing options — without inventing specifications or stock levels"
        ),
    ),
    SpecialistSpec(
        key="account_payment_security",
        label="Account & Payment Security",
        role="account access, suspicious charges, gift-card scams, and escalation",
        focus=(
            "account-access problems, unrecognized charges, and gift-card or "
            "phishing scams, and when to escalate to a human associate, never "
            "accepting full card numbers, security codes, or passwords"
        ),
    ),
)

# Scheduling vertical: an in-store appointment with a product specialist,
# bookable every day the store is open.
SCHEDULING = SchedulingProfile(
    appointment_noun="in-store appointment",
    provider_noun="a product specialist",
    provider_label="In-store product specialist appointment",
    slot_minutes=30,
    business_days=(0, 1, 2, 3, 4, 5, 6),
    open_hour=10,
    close_hour=20,
    lead_minutes=120,
    offer_on_severities=("MEDIUM", "HIGH"),
    first_offer_excludes=("EMERGENCY",),
    check="Did that answer your question?",
    check_yes="Yes, I'm all set",
    check_no="No, I still need help",
    resolved=("Great — happy shopping! If you'd like hands-on help, I can book you time "
              "with a product specialist in store."),
    offer=("Want me to book an in-store appointment with a product specialist? "
           "Here are the next openings:"),
    choose="Here are the next in-store appointment times:",
    ask_name="Sounds good — whose name should I put the appointment under?",
    confirmed=(
        "You're booked: {label} — in-store appointment with a product specialist, "
        "under {name}. Bring your order number or receipt."
    ),
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If you need help right away, contact our customer care team or visit "
        "your nearest store."
    ),
    advice_noun="assistance",
    # This theme's EMERGENCY is a product safety hazard (see its prompt). Its reply
    # is shown verbatim, so the banner never renders today -- it is defined so the
    # copy is correct if that changes.
    emergency_banner=(
        "SAFETY ALERT: Stop using the product, unplug it if you can do so safely, "
        "and move away from it immediately."
    ),
)

THRASH = build_profile("order-management-mcp", "order")

DOCS = InternalDocsProfile(
    collection="retail",
    trigger_terms=(
        "margin floor",
        "margin floors",
        "markdown cadence",
        "markdown schedule",
    ),
)

THEME = ThemeConfig(
    key="retail",
    label="Retail",
    conversational=is_conversational("retail"),
    system_prompt=prompt_for("retail"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
