"""Constants for data sensitivity classification of skill integrations."""

from __future__ import annotations

DATA_SENSITIVITY_SCORE: int = 55

HIGH_SENSITIVITY_SERVICES: tuple[str, ...] = (
    "gmail",
    "outlook",
    "stripe",
    "paypal",
    "braintree",
    "square",
    "salesforce",
    "hubspot",
    "bamboohr",
    "workday",
    "gusto",
    "rippling",
    "adp",
    "zenefits",
    "namely",
)

MEDIUM_SENSITIVITY_SERVICES: tuple[str, ...] = (
    "github",
    "gitlab",
    "bitbucket",
    "slack",
    "discord",
    "teams",
    "jira",
    "linear",
    "asana",
    "notion",
    "confluence",
    "trello",
    "monday",
    "clickup",
    "airtable",
)

LOW_SENSITIVITY_SERVICES: tuple[str, ...] = (
    "weather",
    "giphy",
    "nasa",
    "unsplash",
    "wikipedia",
    "wolfram",
    "openweather",
)

HIGH_SENSITIVITY_CATEGORY: str = "financial/PII"
MEDIUM_SENSITIVITY_CATEGORY: str = "source-code/collaboration"
LOW_SENSITIVITY_CATEGORY: str = "public-data"

SERVICE_CATEGORY_MAP: dict[str, str] = {
    "gmail": "communication/PII",
    "outlook": "communication/PII",
    "stripe": "financial",
    "paypal": "financial",
    "braintree": "financial",
    "square": "financial",
    "salesforce": "CRM/PII",
    "hubspot": "CRM/PII",
    "bamboohr": "HR/PII",
    "workday": "HR/PII",
    "gusto": "HR/PII",
    "rippling": "HR/PII",
    "adp": "HR/PII",
    "zenefits": "HR/PII",
    "namely": "HR/PII",
    "github": "source-code",
    "gitlab": "source-code",
    "bitbucket": "source-code",
    "slack": "messaging",
    "discord": "messaging",
    "teams": "messaging",
    "jira": "project-management",
    "linear": "project-management",
    "asana": "project-management",
    "notion": "knowledge-base",
    "confluence": "knowledge-base",
    "trello": "project-management",
    "monday": "project-management",
    "clickup": "project-management",
    "airtable": "database",
    "weather": "public-data",
    "giphy": "public-data",
    "nasa": "public-data",
    "unsplash": "public-data",
    "wikipedia": "public-data",
    "wolfram": "public-data",
    "openweather": "public-data",
}

HIGH_SENSITIVITY_KEYWORDS: tuple[str, ...] = (
    "payment",
    "credit card",
    "social security",
    "bank account",
    "salary",
    "medical",
    "password",
    "credential",
    "billing",
    "invoice",
    "ssn",
    "tax",
    "payroll",
    "health record",
    "patient",
    "diagnosis",
)

MEDIUM_SENSITIVITY_KEYWORDS: tuple[str, ...] = (
    "private repository",
    "private repo",
    "direct message",
    "private message",
    "confidential",
    "proprietary",
)

WEAK_MEDIUM_SENSITIVITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "internal",
        "employee",
        "personnel",
    }
)

SENSITIVITY_TIER_SCORES: dict[str, int] = {
    "high": 65,
    "medium": 40,
    "low": 15,
}

KEYWORD_BONUS: int = 10

FINANCIAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "payment",
        "credit card",
        "bank account",
        "billing",
        "invoice",
        "tax",
        "payroll",
    }
)

MEDICAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "medical",
        "health record",
        "patient",
        "diagnosis",
    }
)

PII_KEYWORDS: frozenset[str] = frozenset(
    {
        "social security",
        "ssn",
        "salary",
        "password",
        "credential",
    }
)
