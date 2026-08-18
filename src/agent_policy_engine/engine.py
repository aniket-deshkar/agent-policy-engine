from __future__ import annotations

import re
from collections import Counter
from threading import Lock
from typing import Any

from .model import Decision, PolicyDecision, ReasonCode, Rule, ToolCall


class PolicyEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = tuple(rules)
        self._usage: Counter[tuple[str, str]] = Counter()
        self._lock = Lock()

    def evaluate(self, call: ToolCall) -> PolicyDecision:
        candidates = [rule for rule in self._rules if rule.tool == call.tool]
        if not candidates:
            return PolicyDecision(Decision.DENY, ReasonCode.NO_MATCHING_POLICY)
        failures: list[ReasonCode] = []
        for rule in candidates:
            reason = self._mismatch(rule, call)
            if reason:
                failures.append(reason)
                continue
            if rule.quota is not None:
                key = (rule.id, call.identity.subject)
                with self._lock:
                    if self._usage[key] >= rule.quota:
                        return PolicyDecision(Decision.DENY, ReasonCode.QUOTA_EXCEEDED, rule.id)
                    if rule.decision == Decision.ALLOW:
                        self._usage[key] += 1
            reason = (
                ReasonCode.RISK_REQUIRES_APPROVAL
                if rule.decision == Decision.REQUIRE_APPROVAL
                else ReasonCode.ALLOWED
            )
            return PolicyDecision(rule.decision, reason, rule.id)
        return PolicyDecision(Decision.DENY, failures[0], candidates[0].id)

    @staticmethod
    def _mismatch(rule: Rule, call: ToolCall) -> ReasonCode | None:
        if rule.roles and not (rule.roles & call.identity.roles):
            return ReasonCode.ROLE_MISMATCH
        if any(
            call.identity.attributes.get(key) != value for key, value in rule.attributes.items()
        ):
            return ReasonCode.ATTRIBUTE_MISMATCH
        if rule.environments and call.environment not in rule.environments:
            return ReasonCode.ENVIRONMENT_MISMATCH
        if any(
            not _matches(call.arguments.get(name), constraint)
            for name, constraint in rule.arguments.items()
        ):
            return ReasonCode.ARGUMENT_CONSTRAINT
        return None


def _matches(value: Any, constraint: dict[str, Any]) -> bool:
    if "required" in constraint and constraint["required"] and value is None:
        return False
    if value is None:
        return True
    if "equals" in constraint and value != constraint["equals"]:
        return False
    if "in" in constraint and value not in constraint["in"]:
        return False
    if "min" in constraint and (not isinstance(value, int | float) or value < constraint["min"]):
        return False
    if "max" in constraint and (not isinstance(value, int | float) or value > constraint["max"]):
        return False
    return not (
        "pattern" in constraint
        and (not isinstance(value, str) or re.fullmatch(constraint["pattern"], value) is None)
    )
