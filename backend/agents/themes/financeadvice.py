"""FinanceAdvice theme - personal finance literacy (not CFP advice)."""

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
        key="budgeting",
        label="Budgeting & Cash Flow",
        role="budgeting, saving, and emergency-fund basics",
        focus=(
            "budgeting, cash-flow, saving habits, and emergency-fund basics tailored "
            "to the user's described situation (general literacy, not personal advice)"
        ),
    ),
    SpecialistSpec(
        key="investing",
        label="Investing Basics",
        role="general investing concepts, diversification, and risk",
        focus=(
            "general investing concepts (diversification, risk tolerance, long-term "
            "horizons) without recommending specific securities or guaranteeing returns"
        ),
    ),
    SpecialistSpec(
        key="debt_credit",
        label="Debt & Credit",
        role="debt payoff strategies, credit scores, and interest",
        focus=(
            "debt-payoff strategies, how credit scores and interest work, and "
            "prioritization between competing obligations"
        ),
    ),
    SpecialistSpec(
        key="risk_compliance",
        label="Risk & Red Flags",
        role="scams, high-risk schemes, and when to see a fiduciary",
        focus=(
            "scam/high-risk-scheme red flags, suitability concerns, and clear "
            "indicators the user should consult a licensed fiduciary advisor"
        ),
    ),
)

# Scheduling vertical: a consultation with a financial advisor.
SCHEDULING = SchedulingProfile(
    appointment_noun="consultation",
    provider_noun="a financial advisor",
    provider_label="Financial advisor consultation",
    slot_minutes=45,
    business_days=(0, 1, 2, 3, 4),
    open_hour=9,
    close_hour=17,
    lead_minutes=180,
    offer=(
        "Would you like to schedule a consultation with a financial advisor to go "
        "deeper? Here are the next available times:"
    ),
    confirmed="You're booked: {label} — consultation with a financial advisor, under {name}.",
)

GUARDRAILS = GuardrailCopy(
    urgent_help=(
        "If this is an urgent financial matter, contact a licensed financial "
        "advisor or your financial institution directly."
    ),
    advice_noun="financial advice",
    emergency_banner=(
        "FINANCIAL EMERGENCY: Contact your financial institution or a licensed "
        "financial advisor immediately."
    ),
    escalation_heading="Talk to a Licensed Financial Advisor If",
    fallback_guidance=(
        "List your income, expenses and debts to see where you stand.",
        "Keep an emergency fund before taking on new risk.",
        "Talk to a licensed financial advisor if you're unsure.",
    ),
    fallback_escalation="You're facing financial hardship or a large decision",
)

THRASH = build_profile("portfolio-mcp", "portfolio_record")

DOCS = InternalDocsProfile(
    collection="financeadvice",
    trigger_terms=(
        "fee floor",
        "fee floors",
        "house fund",
        "house funds",
        "house-fund",
    ),
)

THEME = ThemeConfig(
    key="financeadvice",
    label="FinanceAdvice",
    conversational=is_conversational("financeadvice"),
    system_prompt=prompt_for("financeadvice"),
    specialists=SPECIALISTS,
    scheduling=SCHEDULING,
    guardrails=GUARDRAILS,
    thrash=THRASH,
    docs=DOCS,
)
