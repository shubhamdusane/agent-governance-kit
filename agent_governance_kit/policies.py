"""Built-in policies mapped 1:1 to OWASP Top 10 for Agentic AI.

Each policy is a callable: check(stage, payload) -> (PolicyDecision, ViolationRecord | None).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

from .detector.pii import detect_pii, redact_pii
from .detector.prompt_injection import detect_injection
from .rate_limiter import RateLimiter
from .types import PolicyDecision, ViolationRecord, ViolationSeverity


class Policy(Protocol):
    name: str
    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]: ...


@dataclass
class PolicyContext:
    """Context passed to every policy check."""
    stage: str          # "input" | "output" | "tool_call" | "memory_write"
    tool_name: str | None = None
    metadata: dict[str, Any] | None = None


# ─── Policy 1: Prompt injection (OWASP LLM01) ─────────────────────────────────

class PromptInjectionPolicy:
    name = "prompt_injection_detection"

    def __init__(self, decision: PolicyDecision = PolicyDecision.BLOCK):
        self.decision = decision

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage not in ("input", "tool_output"):
            return PolicyDecision.ALLOW, None
        text = payload if isinstance(payload, str) else str(payload)
        is_inj, matches = detect_injection(text)
        if is_inj:
            return self.decision, ViolationRecord(
                policy=self.name,
                severity=ViolationSeverity.HIGH,
                decision=self.decision,
                summary=f"Prompt injection detected (matched {len(matches)} patterns)",
                redacted_sample=text[:200],
                metadata={"patterns": matches},
            )
        return PolicyDecision.ALLOW, None


# ─── Policy 2: PII detection (OWASP LLM06) ────────────────────────────────────

class PiiDetectionPolicy:
    name = "pii_detection"

    def __init__(self, decision: PolicyDecision = PolicyDecision.REDACT):
        self.decision = decision

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage not in ("input", "output", "tool_output", "memory_write"):
            return PolicyDecision.ALLOW, None
        text = payload if isinstance(payload, str) else str(payload)
        hits = detect_pii(text)
        if hits:
            redacted, types = redact_pii(text)
            return self.decision, ViolationRecord(
                policy=self.name,
                severity=ViolationSeverity.HIGH,
                decision=self.decision,
                summary=f"PII detected: {', '.join(sorted(set(types)))}",
                redacted_sample=redacted[:200],
                metadata={"pii_types": list(sorted(set(types))), "count": len(hits)},
            )
        return PolicyDecision.ALLOW, None


# ─── Policy 3: Tool call rate limit (OWASP LLM04 — model DoS) ─────────────────

class ToolCallRateLimitPolicy:
    name = "tool_call_rate_limit"

    def __init__(self, spec: str = "50/min"):
        self.limiter = RateLimiter.parse_spec(spec)
        self.spec = spec

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage != "tool_call":
            return PolicyDecision.ALLOW, None
        if self.limiter.allow():
            return PolicyDecision.ALLOW, None
        return PolicyDecision.BLOCK, ViolationRecord(
            policy=self.name,
            severity=ViolationSeverity.MEDIUM,
            decision=PolicyDecision.BLOCK,
            summary=f"Tool call rate limit exceeded ({self.spec})",
            metadata={"spec": self.spec},
        )


# ─── Policy 4: No external URLs (OWASP LLM05 — supply chain) ──────────────────

class NoExternalUrlsPolicy:
    name = "no_external_urls"

    def __init__(self, allowlist: list[str] | None = None):
        self.allowlist = set((allowlist or []))

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage != "tool_call":
            return PolicyDecision.ALLOW, None
        args = payload if isinstance(payload, dict) else {}
        for v in args.values():
            if not isinstance(v, str):
                continue
            if "://" in v:
                parsed = urlparse(v)
                if parsed.hostname and parsed.hostname not in self.allowlist:
                    return PolicyDecision.BLOCK, ViolationRecord(
                        policy=self.name,
                        severity=ViolationSeverity.HIGH,
                        decision=PolicyDecision.BLOCK,
                        summary=f"Tool attempted to access external URL: {parsed.hostname}",
                        metadata={"url": v},
                    )
        return PolicyDecision.ALLOW, None


# ─── Policy 5: Tool allowlist (OWASP LLM07 — plugin design) ───────────────────

class ToolAllowlistPolicy:
    name = "tool_allowlist"

    def __init__(self, allowed_tools: list[str]):
        self.allowed = set(allowed_tools)

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage != "tool_call":
            return PolicyDecision.ALLOW, None
        tool_name = payload.get("tool_name") if isinstance(payload, dict) else None
        if tool_name and tool_name not in self.allowed:
            return PolicyDecision.BLOCK, ViolationRecord(
                policy=self.name,
                severity=ViolationSeverity.HIGH,
                decision=PolicyDecision.BLOCK,
                summary=f"Tool '{tool_name}' not in allowlist",
                metadata={"tool": tool_name, "allowlist": sorted(self.allowed)},
            )
        return PolicyDecision.ALLOW, None


# ─── Policy 6: Human escalation threshold (OWASP LLM09 — overreliance) ────────

class HumanEscalationPolicy:
    name = "human_escalation_threshold"

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage != "output":
            return PolicyDecision.ALLOW, None
        confidence = None
        if isinstance(payload, dict):
            confidence = payload.get("confidence")
        if confidence is None:
            return PolicyDecision.ALLOW, None
        if confidence < self.threshold:
            return PolicyDecision.ESCALATE, ViolationRecord(
                policy=self.name,
                severity=ViolationSeverity.MEDIUM,
                decision=PolicyDecision.ESCALATE,
                summary=f"Confidence {confidence:.2f} below threshold {self.threshold}",
                metadata={"confidence": confidence, "threshold": self.threshold},
            )
        return PolicyDecision.ALLOW, None


# ─── Policy 7: Loop detection (OWASP LLM04 — model DoS) ───────────────────────

class LoopDetectionPolicy:
    name = "loop_detection"

    def __init__(self, window: int = 10, max_same_call: int = 3):
        self.window = window
        self.max_same_call = max_same_call
        self._history: list[str] = []

    def check(self, stage: str, payload: Any) -> tuple[PolicyDecision, ViolationRecord | None]:
        if stage != "tool_call":
            return PolicyDecision.ALLOW, None
        call_sig = repr(payload)
        self._history.append(call_sig)
        if len(self._history) > self.window:
            self._history.pop(0)
        count = self._history.count(call_sig)
        if count >= self.max_same_call:
            return PolicyDecision.BLOCK, ViolationRecord(
                policy=self.name,
                severity=ViolationSeverity.HIGH,
                decision=PolicyDecision.BLOCK,
                summary=f"Same tool call repeated {count} times in last {self.window} calls",
                metadata={"signature": call_sig[:200]},
            )
        return PolicyDecision.ALLOW, None


# ─── Policy registry ──────────────────────────────────────────────────────────

ALL_POLICIES: dict[str, Callable[..., Policy]] = {
    "prompt_injection_detection": PromptInjectionPolicy,
    "pii_detection": PiiDetectionPolicy,
    "tool_call_rate_limit": ToolCallRateLimitPolicy,
    "no_external_urls": NoExternalUrlsPolicy,
    "tool_allowlist": ToolAllowlistPolicy,
    "human_escalation_threshold": HumanEscalationPolicy,
    "loop_detection": LoopDetectionPolicy,
}


class PolicyRegistry:
    """Parses policy spec strings and constructs policy instances."""

    @staticmethod
    def build(spec: str) -> Policy:
        """Parse 'name:arg1:arg2' or 'name' and construct the policy."""
        parts = spec.split(":", 1)
        name = parts[0]
        arg = parts[1] if len(parts) > 1 else None

        if name not in ALL_POLICIES:
            raise ValueError(f"Unknown policy: {name}. Available: {sorted(ALL_POLICIES)}")

        cls = ALL_POLICIES[name]

        if name == "pii_detection":
            decision = PolicyDecision(arg) if arg else PolicyDecision.REDACT
            return cls(decision=decision)  # type: ignore[call-arg]
        if name == "prompt_injection_detection":
            decision = PolicyDecision(arg) if arg else PolicyDecision.BLOCK
            return cls(decision=decision)  # type: ignore[call-arg]
        if name == "tool_call_rate_limit":
            return cls(spec=arg or "50/min")  # type: ignore[call-arg]
        if name == "no_external_urls":
            allow = arg.split(",") if arg else []
            return cls(allowlist=allow)  # type: ignore[call-arg]
        if name == "tool_allowlist":
            if not arg:
                raise ValueError("tool_allowlist requires list: tool_allowlist:[search,compute]")
            tools = arg.strip("[]").split(",")
            return cls(allowed_tools=[t.strip() for t in tools])  # type: ignore[call-arg]
        if name == "human_escalation_threshold":
            threshold = float(arg) if arg else 0.7
            return cls(threshold=threshold)  # type: ignore[call-arg]
        if name == "loop_detection":
            parts = (arg or "10:3").split(":")
            window = int(parts[0]) if len(parts) > 0 else 10
            max_same = int(parts[1]) if len(parts) > 1 else 3
            return cls(window=window, max_same_call=max_same)  # type: ignore[call-arg]

        return cls()  # type: ignore[call-arg]
