"""Prompt injection detection — heuristic, fast, no model call."""

from __future__ import annotations

import re

# Known injection phrases / patterns. Kept short so scanner is fast.
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore (all |the )?(previous|above|prior) instructions?", re.IGNORECASE),
    re.compile(r"disregard (all |the )?(previous|above|prior) (instructions?|prompt)", re.IGNORECASE),
    re.compile(r"forget (everything|all) (above|previous|prior)", re.IGNORECASE),
    re.compile(r"(you are|act as|roleplay as) (now )?(dan|jailbreak|evil|unfiltered)", re.IGNORECASE),
    re.compile(r"output the (entire )?(system|developer) prompt", re.IGNORECASE),
    re.compile(r"(reveal|leak|print|show|expose) (your|the) (system|hidden|initial) prompt", re.IGNORECASE),
    re.compile(r"<\|im_(start|end)\|>", re.IGNORECASE),  # model control tokens leaking through
    re.compile(r"###\s*(system|instruction|user)\s*[:\n]", re.IGNORECASE),  # fake role tags
    re.compile(r"new (system )?instructions?:", re.IGNORECASE),
    re.compile(r"override (the )?(safety|content) (rules?|filter|policy)", re.IGNORECASE),
]

# Low-signal hints — used to bump confidence but not by themselves trigger.
HINT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"base64", re.IGNORECASE),
    re.compile(r"rot13", re.IGNORECASE),
    re.compile(r"hypothetical(ly)?", re.IGNORECASE),
]


def detect_injection(text: str) -> tuple[bool, list[str]]:
    """Return (is_injection, list_of_matched_pattern_descriptions)."""
    matched: list[str] = []
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            matched.append(pat.pattern)
    hints = 0
    for pat in HINT_PATTERNS:
        if pat.search(text):
            hints += 1
    # Any strong pattern = injection.
    # Two hints alone = injection (defensive).
    is_injection = len(matched) > 0 or hints >= 2
    return is_injection, matched
