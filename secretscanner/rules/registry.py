"""Extensible, precompiled detection-rule registry."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from secretscanner.exceptions import ConfigurationError
from secretscanner.models import Confidence, Severity

Validator = Callable[[str, str], bool]


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    description: str
    regex: str
    category: str
    severity: Severity
    confidence: Confidence
    remediation: str
    tags: frozenset[str] = field(default_factory=frozenset)
    keywords: frozenset[str] = field(default_factory=frozenset)
    file_extensions: frozenset[str] = field(default_factory=frozenset)
    exclude_patterns: tuple[str, ...] = ()
    match_group: int = 0
    validator: Validator | None = None
    enabled: bool = True
    compiled: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "compiled", re.compile(self.regex))
        except re.error as exc:
            raise ConfigurationError(f"Invalid regex for rule '{self.rule_id}': {exc}") from exc


class RuleRegistry:
    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: Rule) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", rule.rule_id):
            raise ConfigurationError(f"Invalid rule id: {rule.rule_id}")
        if rule.rule_id in self._rules:
            raise ConfigurationError(f"Duplicate rule id: {rule.rule_id}")
        self._rules[rule.rule_id] = rule

    def configure(
        self, rule_id: str, *, enabled: bool | None = None, severity: Severity | None = None
    ) -> None:
        if rule_id not in self._rules:
            raise ConfigurationError(f"Unknown configured rule: {rule_id}")
        current = self._rules[rule_id]
        self._rules[rule_id] = replace(
            current,
            enabled=current.enabled if enabled is None else enabled,
            severity=severity or current.severity,
        )

    def rules(self) -> tuple[Rule, ...]:
        return tuple(rule for rule in self._rules.values() if rule.enabled)

    def all_rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules.values())
