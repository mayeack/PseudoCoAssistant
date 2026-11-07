# System Policies

This document describes the situations under which the medical advice agent will provide a generic response indicating that a policy has been violated. When a policy is triggered, the `policy_blocked` field is set to `true` in the governance logs.

---

## 1. Disclaimer & Access Policy

**Policy ID:** `POLICY-ACCESS-001`

**Description:** Users must accept the medical disclaimer before starting any consultation.

**Trigger Conditions:**
- New session initiated without `disclaimer_accepted=True`

**Response Behavior:**
- HTTP 400 error returned
- Message: "Medical disclaimer must be accepted before starting consultation"

**Policy Summary:**
> This service requires acknowledgment that it is not a substitute for professional medical care before any consultation can begin.

---

## 2. Emergency Medical Situations

**Policy ID:** `POLICY-EMERGENCY-001`

**Description:** Life-threatening symptoms require immediate emergency services, not AI guidance.

**Trigger Conditions:**
Any mention of the following symptoms:
- Chest pain, difficulty breathing, severe shortness of breath
- Stroke, paralysis, loss of consciousness, unconscious
- Severe bleeding, severe head injury, seizure
- Severe allergic reaction, anaphylaxis
- Severe abdominal pain, coughing up blood, vomiting blood
- Sudden vision loss, sudden weakness, slurred speech
- Severe burns, poisoning, overdose

**Response Behavior:**
- Response prepended with emergency warning
- Message includes: "⚠️ **EMERGENCY: Call 911 or go to the nearest emergency room immediately.** ⚠️"
- Consultation is escalated for human review

**Policy Summary:**
> For life-threatening symptoms, the system will always recommend calling 911 or visiting the nearest emergency room. The AI cannot provide emergency medical care.

---

## 3. Mental Health Crisis & Self-Harm

**Policy ID:** `POLICY-MENTAL-HEALTH-001`

**Description:** Expressions of suicidal ideation or self-harm require immediate crisis intervention resources.

**Trigger Conditions:**
Any mention of:
- "kill myself", "end my life"
- "suicide", "suicidal"
- "self-harm", "hurt myself"
- "don't want to live"

**Response Behavior:**
- Immediate escalation triggered
- Crisis resources provided
- Escalation reason: "Self-harm ideation expressed"

The hard block (the crisis response in place of an answer) is the **Internal
Policy Engine** (Demo Controls → Guardrails, `internal_policy_review`), which
is **off by default**. With it off, the turn is still escalated for review but
the model answers.

**Policy Summary:**
> If you are experiencing thoughts of self-harm or suicide, please contact emergency services (911) or a crisis helpline immediately. The National Suicide Prevention Lifeline is available at 988.

---

## 4. Prescription & Medication Policy

**Policy ID:** `POLICY-PRESCRIPTION-001`

**Description:** The system does not provide prescription drug dosages or specific medication recommendations.

**Trigger Conditions:**
- Requests for prescription drug dosages
- Multiple medications mentioned (potential interaction risk)
- Pattern detection: "taking [medication]", "on [drug/medicine]", "prescription"

**Response Behavior:**
- Declines to provide specific dosages
- Recommends consulting pharmacist or physician
- Escalates when multiple medications detected (2+ mentions)
- Escalation reason: "Potential medication interactions"

**Policy Summary:**
> This service does NOT provide prescription medication advice. For dosing information or medication interactions, please consult your pharmacist or prescribing physician.

---

## 5. Pediatric Care Restrictions

**Policy ID:** `POLICY-PEDIATRIC-001`

**Description:** Special restrictions apply for children, particularly infants and toddlers.

**Trigger Conditions:**
- Mentions of: infant, baby, newborn, toddler
- Age references: "under 2 years", "less than 2 months"
- Requests for pediatric dosing

**Response Behavior:**
- Automatic escalation triggered
- Escalation reason: "Vulnerable age group identified"
- Recommends consultation with pediatrician

**Policy Summary:**
> This service does NOT provide pediatric dosing information. Children, especially infants and toddlers, require specialized medical guidance. Please consult a pediatrician for any concerns about your child's health.

---

## 6. Vulnerable Population Policy

**Policy ID:** `POLICY-VULNERABLE-001`

**Description:** Extra caution and escalation for vulnerable populations including elderly and pregnant individuals.

**Trigger Conditions:**

*Elderly:*
- Mentions of: elderly, senior
- Age references: "over 65", "older than 70/80/90"

*Pregnancy:*
- Mentions of: pregnant, pregnancy, expecting
- References to: trimester, due date

**Response Behavior:**
- Escalation triggered for professional review
- Escalation reasons: "Vulnerable age group identified" or "Pregnancy detected"
- Recommends professional medical evaluation

**Policy Summary:**
> If you are pregnant, elderly (65+), or have chronic health conditions, please consult with a healthcare provider before following any recommendations. These populations require specialized medical attention.

---

## 7. High-Risk Symptom Handling

**Policy ID:** `POLICY-HIGH-RISK-001`

**Description:** Certain symptoms indicate conditions that require professional medical evaluation.

**Trigger Conditions:**
Any mention of:
- Persistent fever, high fever, fever over 103°F
- Severe pain, chronic pain, worsening pain
- Infection, infected wound
- Difficulty swallowing, persistent vomiting, severe diarrhea
- Blood in stool, blood in urine
- Rapid heartbeat, irregular heartbeat, palpitations
- Confusion, disorientation, memory loss
- Severe headache, migraine, "worst headache"

**Response Behavior:**
- Severity level set to HIGH
- Escalation may be triggered
- Strong recommendation to seek professional care

**Policy Summary:**
> These symptoms may indicate serious conditions that require professional medical evaluation. Please consult a healthcare provider promptly.

---

## 8. Persistent or Worsening Symptoms

**Policy ID:** `POLICY-PERSISTENT-001`

**Description:** Symptoms that persist over time or are getting worse require professional evaluation.

**Trigger Conditions:**
- "getting worse", "worsening", "not getting better"
- "still have", "persistent"
- "for weeks", "for months"
- "keeps happening", "recurring", "chronic"

**Response Behavior:**
- Escalation triggered
- Escalation reason: "Persistent or worsening symptoms"
- Recommends professional medical evaluation

**Policy Summary:**
> Symptoms that persist or worsen over time should be evaluated by a healthcare professional. This service is not appropriate for managing chronic or worsening conditions.

---

## 9. Human Review Request

**Policy ID:** `POLICY-HUMAN-REVIEW-001`

**Description:** Users can explicitly request to speak with a medical professional.

**Trigger Conditions:**
- "talk to a doctor", "see a doctor", "speak to a professional"
- "human review", "real doctor", "medical professional"
- "need a doctor", "want to see a doctor"

**Response Behavior:**
- Escalation triggered
- Escalation reason: "User requested professional review"
- Consultation flagged for human review

**Policy Summary:**
> You have requested to speak with a medical professional. Your consultation has been escalated for human review.

---

## Policy Enforcement Summary

| Policy Category | Policy ID | Escalation | Blocked |
|-----------------|-----------|------------|---------|
| Disclaimer Required | POLICY-ACCESS-001 | No | Yes (HTTP 400) |
| Emergency Symptoms | POLICY-EMERGENCY-001 | Yes | Yes |
| Self-Harm/Suicide | POLICY-MENTAL-HEALTH-001 | Yes | Yes |
| Prescription Requests | POLICY-PRESCRIPTION-001 | Conditional | Yes |
| Pediatric Care | POLICY-PEDIATRIC-001 | Yes | Yes |
| Vulnerable Populations | POLICY-VULNERABLE-001 | Yes | Yes |
| High-Risk Symptoms | POLICY-HIGH-RISK-001 | Conditional | Conditional |
| Persistent Symptoms | POLICY-PERSISTENT-001 | Yes | Yes |
| Human Review Request | POLICY-HUMAN-REVIEW-001 | Yes | No |

---

## Technical Implementation

When any policy is triggered that results in escalation, the following fields are set in the governance logs:

- `policy_blocked: true` - Indicates a policy was triggered
- `guardrail_triggered: true` - Indicates guardrails were activated
- `guardrail_ids: ["escalation_rules"]` - Identifies which guardrail system was triggered
- `safety_violated: true` - Indicates safety concerns were detected
- `safety_categories: [...]` - Lists the specific escalation reasons

## Related Files

- `backend/services/escalation_rules.py` - Escalation pattern definitions
- `backend/services/recommendation_engine.py` - System prompt and response handling
- `backend/routers/chat.py` - Disclaimer enforcement
- `backend/models/db_models.py` - Database schema including `policy_blocked` field
