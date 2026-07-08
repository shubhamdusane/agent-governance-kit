"""PII detection — regex-based for speed, covers common EU/US/India PII shapes."""

from __future__ import annotations

import re

# Patterns ordered by specificity — more specific wins when overlapping.
PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "us_credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "india_pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "india_aadhaar": re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
    "india_phone": re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?[6-9]\d{9}(?!\d)"),
    "intl_phone": re.compile(r"\+(?:[0-9][\s-]?){7,14}[0-9]"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "uk_nino": re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]?\b"),
}


def detect_pii(text: str) -> list[tuple[str, str, int, int]]:
    """Return list of (pii_type, match_text, start, end) tuples."""
    hits: list[tuple[str, str, int, int]] = []
    for pii_type, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            hits.append((pii_type, m.group(0), m.start(), m.end()))
    return hits


def redact_pii(text: str, placeholder: str = "[REDACTED]") -> tuple[str, list[str]]:
    """Return (redacted_text, list_of_redacted_types)."""
    redacted_types: list[str] = []
    output = text
    # Apply longer patterns first to avoid partial overlap with shorter ones.
    hits = sorted(detect_pii(text), key=lambda h: (h[2], -(h[3] - h[2])))
    # Deduplicate overlapping — prefer earliest start + widest span.
    filtered: list[tuple[str, str, int, int]] = []
    for h in hits:
        if filtered and h[2] < filtered[-1][3]:
            continue
        filtered.append(h)
    # Walk from end so indices stay valid.
    for pii_type, _, start, end in reversed(filtered):
        output = output[:start] + placeholder + output[end:]
        redacted_types.append(pii_type)
    return output, redacted_types
