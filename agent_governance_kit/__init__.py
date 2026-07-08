"""agent-governance-kit — OWASP Top 10 Agentic AI + EU AI Act compliance middleware."""

from .middleware import GovernanceLayer
from .types import (
    PolicyViolation,
    ViolationSeverity,
    ViolationRecord,
    PolicyDecision,
)
from .policies import ALL_POLICIES, PolicyRegistry

__version__ = "0.1.0"
__all__ = [
    "GovernanceLayer",
    "PolicyViolation",
    "ViolationSeverity",
    "ViolationRecord",
    "PolicyDecision",
    "ALL_POLICIES",
    "PolicyRegistry",
]
