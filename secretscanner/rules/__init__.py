"""Rule definitions and registry."""

from secretscanner.rules.builtin import builtin_rules
from secretscanner.rules.registry import Rule, RuleRegistry

__all__ = ["Rule", "RuleRegistry", "builtin_rules"]
