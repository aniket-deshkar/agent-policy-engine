import pytest

from agent_policy_engine import Decision, Identity, PolicyEngine, ReasonCode, Rule, ToolCall


def call(**overrides):
    values = {
        "tool": "payments.refund",
        "arguments": {"amount": 20, "currency": "USD"},
        "identity": Identity("alice", frozenset({"operator"}), {"tenant": "a"}),
        "environment": "production",
    }
    values.update(overrides)
    return ToolCall(**values)


def rule(**overrides):
    values = {
        "id": "refund",
        "tool": "payments.refund",
        "decision": Decision.ALLOW,
        "roles": frozenset({"operator"}),
        "attributes": {"tenant": "a"},
        "environments": frozenset({"production"}),
        "arguments": {"amount": {"min": 1, "max": 100}, "currency": {"in": ["USD"]}},
    }
    values.update(overrides)
    return Rule(**values)


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        ({"tool": "unknown"}, ReasonCode.NO_MATCHING_POLICY),
        (
            {"identity": Identity("alice", frozenset({"viewer"}), {"tenant": "a"})},
            ReasonCode.ROLE_MISMATCH,
        ),
        (
            {"identity": Identity("alice", frozenset({"operator"}), {"tenant": "b"})},
            ReasonCode.ATTRIBUTE_MISMATCH,
        ),
        ({"environment": "development"}, ReasonCode.ENVIRONMENT_MISMATCH),
        ({"arguments": {"amount": 101, "currency": "USD"}}, ReasonCode.ARGUMENT_CONSTRAINT),
    ],
)
def test_denies_mismatch_with_reason(changed, reason):
    decision = PolicyEngine([rule()]).evaluate(call(**changed))
    assert decision.decision == Decision.DENY
    assert decision.reason == reason


def test_allows_matching_rbac_abac_environment_and_arguments():
    assert PolicyEngine([rule()]).evaluate(call()).decision == Decision.ALLOW


def test_require_approval_is_explicit():
    decision = PolicyEngine([rule(decision=Decision.REQUIRE_APPROVAL)]).evaluate(call())
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.reason == ReasonCode.RISK_REQUIRES_APPROVAL


def test_quota_is_per_policy_and_subject():
    engine = PolicyEngine([rule(quota=1)])
    assert engine.evaluate(call()).decision == Decision.ALLOW
    assert engine.evaluate(call()).reason == ReasonCode.QUOTA_EXCEEDED
    assert (
        engine.evaluate(
            call(identity=Identity("bob", frozenset({"operator"}), {"tenant": "a"}))
        ).decision
        == Decision.ALLOW
    )


def test_deny_rule_is_returned_without_incrementing_quota():
    engine = PolicyEngine([rule(decision=Decision.DENY, quota=1)])
    assert engine.evaluate(call()).decision == Decision.DENY
    assert engine.evaluate(call()).decision == Decision.DENY


def test_required_and_pattern_constraints():
    constrained = rule(arguments={"reference": {"required": True, "pattern": "ORD-[0-9]+"}})
    engine = PolicyEngine([constrained])
    assert engine.evaluate(call(arguments={})).decision == Decision.DENY
    assert engine.evaluate(call(arguments={"reference": "ORD-42"})).decision == Decision.ALLOW
