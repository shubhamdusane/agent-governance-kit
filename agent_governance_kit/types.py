"""Core types for agent-governance-kit."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ViolationSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ESCALATE = "escalate"


@dataclass
class ViolationRecord:
    """Structured record of a policy violation. Written to log / webhook."""

    policy: str
    severity: ViolationSeverity
    decision: PolicyDecision
    summary: str
    timestamp: float = field(default_factory=time.time)
    redacted_sample: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "policy": self.policy,
            "severity": self.severity.value,
            "decision": self.decision.value,
            "summary": self.summary,
            "redacted_sample": self.redacted_sample,
            "metadata": self.metadata,
        }


class PolicyViolation(Exception):
    """Raised when a blocking policy fires."""

    def __init__(self, record: ViolationRecord):
        self.record = record
        super().__init__(f"{record.policy}: {record.summary}")
