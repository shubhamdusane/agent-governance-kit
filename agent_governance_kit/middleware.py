"""GovernanceLayer — wraps any agent, enforces policies, logs violations."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .policies import PolicyRegistry, Policy
from .types import PolicyDecision, PolicyViolation, ViolationRecord


class GovernanceLayer:
    """Wrap any agent with policy checks.

    Args:
        agent: Any object with a `.run(input) -> Any` method, or a callable.
        policies: List of policy spec strings ("pii_detection", "tool_call_rate_limit:50/min", ...).
        violation_webhook: Optional URL to POST violations to (e.g. Slack incoming webhook).
            Only policy name + severity + summary are sent. No PII, no user input.
        violation_log_path: Optional JSONL file path to append violations to.
            Records contain only pre-redacted samples.
        block_on_violation: If True, raise PolicyViolation on any BLOCK decision.
        on_violation: Optional callback fn(record) -> None for custom handling.
    """

    def __init__(
        self,
        agent: Any,
        policies: list[str],
        violation_webhook: str | None = None,
        violation_log_path: str | None = None,
        block_on_violation: bool = True,
        on_violation: Callable[[ViolationRecord], None] | None = None,
    ):
        self.agent = agent
        self.policies: list[Policy] = [PolicyRegistry.build(p) for p in policies]
        self.violation_webhook = violation_webhook
        self.violation_log_path = violation_log_path
        self.block_on_violation = block_on_violation
        self.on_violation = on_violation
        self._violations: list[ViolationRecord] = []

    @property
    def violations(self) -> list[ViolationRecord]:
        """Return a copy of all violations recorded during this layer's lifetime."""
        return list(self._violations)

    # ─── Public API ──────────────────────────────────────────────────────────

    def run(self, user_input: Any) -> Any:
        """Run agent with input + output policies applied."""
        self._check_stage("input", user_input)
        if hasattr(self.agent, "run"):
            output = self.agent.run(user_input)
        else:
            output = self.agent(user_input)
        self._check_stage("output", output)
        return output

    def check_tool_call(self, tool_name: str, args: dict[str, Any]) -> None:
        """Call before executing a tool. Raises PolicyViolation if blocked."""
        payload = {"tool_name": tool_name, **args}
        self._check_stage("tool_call", payload)

    def check_tool_output(self, tool_name: str, output: Any) -> None:
        """Call after a tool returns. Checks for injection in returned content."""
        self._check_stage("tool_output", output)

    def check_memory_write(self, memory_content: str) -> None:
        """Call before committing a memory to storage."""
        self._check_stage("memory_write", memory_content)

    # ─── Internal ────────────────────────────────────────────────────────────

    def _check_stage(self, stage: str, payload: Any) -> None:
        for policy in self.policies:
            decision, record = policy.check(stage, payload)
            if record is None:
                continue
            self._handle_violation(decision, record)

    def _handle_violation(self, decision: PolicyDecision, record: ViolationRecord) -> None:
        self._violations.append(record)

        if self.violation_log_path:
            self._append_to_log(record)
        if self.violation_webhook:
            self._send_webhook(record)
        if self.on_violation:
            try:
                self.on_violation(record)
            except Exception:
                pass  # never let user callback crash the governed agent

        if decision == PolicyDecision.BLOCK and self.block_on_violation:
            raise PolicyViolation(record)

    def _append_to_log(self, record: ViolationRecord) -> None:
        assert self.violation_log_path is not None
        path = Path(self.violation_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def _send_webhook(self, record: ViolationRecord) -> None:
        assert self.violation_webhook is not None
        try:
            body = json.dumps(
                {"text": f"[{record.severity.value}] {record.policy}: {record.summary}"}
            ).encode()
            req = urllib.request.Request(
                self.violation_webhook,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # never let logging failures propagate
