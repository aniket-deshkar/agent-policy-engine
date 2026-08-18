from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .engine import PolicyEngine
from .model import Decision, PolicyDecision, ReasonCode, ToolCall


class ToolAdapter(Protocol):
    def invoke(self, tool: str, arguments: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class AuditRecord:
    occurred_at: datetime
    subject: str
    tool: str
    decision: Decision
    reason: ReasonCode
    policy_id: str | None


class PolicyDeniedError(PermissionError):
    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason.value)
        self.decision = decision


class PolicyEnforcer:
    def __init__(
        self,
        engine: PolicyEngine,
        adapter: ToolAdapter,
        approval: Callable[[ToolCall, PolicyDecision], bool] | None = None,
        audit: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        self._engine, self._adapter, self._approval = engine, adapter, approval
        self._audit = audit or (lambda record: None)

    def execute(self, call: ToolCall) -> Any:
        decision = self._engine.evaluate(call)
        allowed = decision.decision == Decision.ALLOW
        if decision.decision == Decision.REQUIRE_APPROVAL:
            allowed = self._approval is not None and self._approval(call, decision)
            if not allowed:
                decision = PolicyDecision(
                    Decision.DENY, ReasonCode.APPROVAL_REJECTED, decision.policy_id
                )
        self._audit(
            AuditRecord(
                datetime.now(UTC),
                call.identity.subject,
                call.tool,
                decision.decision,
                decision.reason,
                decision.policy_id,
            )
        )
        if not allowed:
            raise PolicyDeniedError(decision)
        return self._adapter.invoke(call.tool, call.arguments)
