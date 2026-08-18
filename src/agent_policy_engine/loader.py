from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .model import Decision, Rule


class PolicyValidationError(ValueError):
    pass


def load_policy(path: str | Path) -> list[Rule]:
    source = Path(path)
    data = (
        json.loads(source.read_text())
        if source.suffix.lower() == ".json"
        else yaml.safe_load(source.read_text())
    )
    return parse_policy(data)


def parse_policy(data: Any) -> list[Rule]:
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise PolicyValidationError("policy must contain a rules list")
    rules: list[Rule] = []
    ids: set[str] = set()
    allowed = {
        "id",
        "tool",
        "decision",
        "roles",
        "attributes",
        "environments",
        "arguments",
        "quota",
    }
    for raw in data["rules"]:
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise PolicyValidationError("rule contains invalid fields")
        if not isinstance(raw.get("id"), str) or not isinstance(raw.get("tool"), str):
            raise PolicyValidationError("rule id and tool are required")
        if raw["id"] in ids:
            raise PolicyValidationError("rule ids must be unique")
        ids.add(raw["id"])
        try:
            decision = Decision(raw.get("decision"))
        except ValueError as error:
            raise PolicyValidationError("invalid decision") from error
        quota = raw.get("quota")
        if quota is not None and (not isinstance(quota, int) or quota <= 0):
            raise PolicyValidationError("quota must be a positive integer")
        rules.append(
            Rule(
                raw["id"],
                raw["tool"],
                decision,
                frozenset(raw.get("roles", [])),
                dict(raw.get("attributes", {})),
                frozenset(raw.get("environments", [])),
                dict(raw.get("arguments", {})),
                quota,
            )
        )
    return rules
