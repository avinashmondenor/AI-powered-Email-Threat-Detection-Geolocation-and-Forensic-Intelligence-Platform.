import re
from typing import Dict, Any, List

URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediate", "immediately", "action required", "account suspended",
    "temporarily suspended", "24 hours", "48 hours", "expiration notice", "lock-out", "locked",
    "confirm within", "terminate", "final warning"
]

CREDENTIAL_KEYWORDS = [
    "password", "passcode", "login", "credentials", "verify account", "reset password",
    "confirm identity", "update billing", "sign-in", "verification", "auth", "security details"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "payment", "invoice", "overdue", "remittance", "acquisition",
    "gift card", "bank details", "routing number", "legal retainer", "funds", "$48,500"
]

IMPERSONATION_KEYWORDS = [
    "chief executive officer", "ceo", "helpdesk", "it support", "paypal security",
    "valued customer", "security operations team", "hr department", "accounts payable"
]

def analyze_content(subject: str, body_text: str, body_html: str) -> Dict[str, Any]:
    full_text = f"{subject} {body_text} {body_html}".lower()

    detected_urgency = []
    for kw in URGENCY_KEYWORDS:
        if kw in full_text:
            detected_urgency.append(kw)

    detected_creds = []
    for kw in CREDENTIAL_KEYWORDS:
        if kw in full_text:
            detected_creds.append(kw)

    detected_financial = []
    for kw in FINANCIAL_KEYWORDS:
        if kw in full_text:
            detected_financial.append(kw)

    detected_impersonation = []
    for kw in IMPERSONATION_KEYWORDS:
        if kw in full_text:
            detected_impersonation.append(kw)

    urgency_signal = len(detected_urgency) > 0
    cred_signal = len(detected_creds) > 0
    financial_signal = len(detected_financial) > 0
    impersonation_signal = len(detected_impersonation) > 0

    all_keywords = list(set(detected_urgency + detected_creds + detected_financial + detected_impersonation))

    return {
        "urgency": urgency_signal,
        "credential_request": cred_signal,
        "financial_request": financial_signal,
        "impersonation_language": impersonation_signal,
        "detected_keywords": all_keywords,
        "summary": {
            "urgency_count": len(detected_urgency),
            "credential_count": len(detected_creds),
            "financial_count": len(detected_financial),
            "impersonation_count": len(detected_impersonation)
        }
    }
