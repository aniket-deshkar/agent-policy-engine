import json

import pytest

from agent_policy_engine import (
    Decision,
    Identity,
    PolicyDeniedError,
    PolicyEnforcer,
    PolicyEngine,
    PolicyValidationError,
    ToolCall,
    expect,
    load_policy,
    parse_policy,
)

POLICY = {
    "rules": [
        {"id": "read", "tool": "docs.read", "decision": "ALLOW", "roles": ["reader"]},
        {"id": "delete", "tool": "docs.delete", "decision": "REQUIRE_APPROVAL", "roles": ["admin"]},
    ]
}


class FakeTool:
    def __init__(self):
        self.calls = []

    def invoke(self, tool, arguments):
        self.calls.append((tool, arguments))
        return "ok"


def make_call(tool="docs.read", roles=frozenset({"reader"})):
    return ToolCall(tool, {"id": 1}, Identity("alice", roles), "test")


def test_loads_json_and_yaml(tmp_path):
    json_path = tmp_path / "policy.json"
    json_path.write_text(json.dumps(POLICY))
    yaml_path = tmp_path / "policy.yaml"
    yaml_path.write_text("rules:\n  - id: read\n    tool: docs.read\n    decision: ALLOW\n")
    assert len(load_policy(json_path)) == 2
    assert load_policy(yaml_path)[0].tool == "docs.read"


@pytest.mark.parametrize(
    "invalid",
    [
        {},
        {"rules": [{"id": "x", "tool": "t", "decision": "MAYBE"}]},
        {"rules": [{"id": "x", "tool": "t", "decision": "ALLOW", "quota": 0}]},
        {"rules": [{"id": "x", "tool": "t", "decision": "ALLOW", "extra": True}]},
        {
            "rules": [
                {"id": "x", "tool": "a", "decision": "ALLOW"},
                {"id": "x", "tool": "b", "decision": "DENY"},
            ]
        },
    ],
)
def test_validates_policy_files(invalid):
    with pytest.raises(PolicyValidationError):
        parse_policy(invalid)


def test_denied_call_never_invokes_tool_and_is_audited():
    adapter, audits = FakeTool(), []
    enforcer = PolicyEnforcer(PolicyEngine(parse_policy(POLICY)), adapter, audit=audits.append)
    with pytest.raises(PolicyDeniedError):
        enforcer.execute(make_call(roles=frozenset({"guest"})))
    assert adapter.calls == []
    assert audits[0].decision == Decision.DENY


def test_approved_call_invokes_tool_only_after_hook():
    adapter, order = FakeTool(), []

    def approve(call, decision):
        order.append("approval")
        return True

    original = adapter.invoke

    def invoke(tool, args):
        order.append("invoke")
        return original(tool, args)

    adapter.invoke = invoke
    enforcer = PolicyEnforcer(PolicyEngine(parse_policy(POLICY)), adapter, approval=approve)
    assert enforcer.execute(make_call("docs.delete", frozenset({"admin"}))) == "ok"
    assert order == ["approval", "invoke"]


def test_rejected_approval_does_not_invoke():
    adapter = FakeTool()
    enforcer = PolicyEnforcer(
        PolicyEngine(parse_policy(POLICY)), adapter, approval=lambda call, decision: False
    )
    with pytest.raises(PolicyDeniedError):
        enforcer.execute(make_call("docs.delete", frozenset({"admin"})))
    assert not adapter.calls


def test_unit_test_dsl():
    engine = PolicyEngine(parse_policy(POLICY))
    expect(engine, make_call()).is_allowed()
    expect(engine, make_call(roles=frozenset())).is_denied()
    expect(engine, make_call("docs.delete", frozenset({"admin"}))).requires_approval()
