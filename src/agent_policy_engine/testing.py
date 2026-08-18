from __future__ import annotations

from dataclasses import dataclass

from .engine import PolicyEngine
from .model import Decision, ToolCall


@dataclass(frozen=True)
class PolicyExpectation:
    engine: PolicyEngine
    call: ToolCall

    def is_allowed(self) -> None:
        actual = self.engine.evaluate(self.call)
        assert actual.decision == Decision.ALLOW, actual

    def is_denied(self) -> None:
        actual = self.engine.evaluate(self.call)
        assert actual.decision == Decision.DENY, actual

    def requires_approval(self) -> None:
        actual = self.engine.evaluate(self.call)
        assert actual.decision == Decision.REQUIRE_APPROVAL, actual


def expect(engine: PolicyEngine, call: ToolCall) -> PolicyExpectation:
    return PolicyExpectation(engine, call)
