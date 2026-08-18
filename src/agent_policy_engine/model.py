from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ReasonCode(StrEnum):
    ALLOWED = "ALLOWED"
    NO_MATCHING_POLICY = "NO_MATCHING_POLICY"
    ROLE_MISMATCH = "ROLE_MISMATCH"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    ARGUMENT_CONSTRAINT = "ARGUMENT_CONSTRAINT"
    RISK_REQUIRES_APPROVAL = "RISK_REQUIRES_APPROVAL"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str] = frozenset()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: dict[str, Any]
    identity: Identity
    environment: str


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: ReasonCode
    policy_id: str | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str
    decision: Decision
    roles: frozenset[str] = frozenset()
    attributes: dict[str, Any] = field(default_factory=dict)
    environments: frozenset[str] = frozenset()
    arguments: dict[str, dict[str, Any]] = field(default_factory=dict)
    quota: int | None = None
