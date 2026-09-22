"""Project configuration loading with CLI-over-project-over-default precedence."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secretscanner.exceptions import ConfigurationError
from secretscanner.models import Confidence, Severity
from secretscanner.rules import Rule, RuleRegistry, builtin_rules

CONFIG_NAMES = (".secretscanner.yml", ".secretscanner.yaml", ".secretscanner.toml")


@dataclass(slots=True)
class AllowlistConfig:
    paths: list[str] = field(default_factory=list)
    rules: set[str] = field(default_factory=set)
    fingerprints: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ScannerConfig:
    max_file_size_mb: int = 5
    entropy: bool = True
    exclude: list[str] = field(default_factory=list)
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    follow_symlinks: bool = False


def find_config(start: Path) -> Path | None:
    directory = start.resolve() if start.is_dir() else start.resolve().parent
    for candidate_dir in (directory, *directory.parents):
        for name in CONFIG_NAMES:
            candidate = candidate_dir / name
            if candidate.is_file():
                return candidate
    return None


def _read_config(path: Path) -> dict[str, Any]:
    try:
        if path.suffix == ".toml":
            with path.open("rb") as handle:
                result = tomllib.load(handle)
        else:
            result = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not load {path.name}: {exc}") from exc
    if not isinstance(result, dict):
        raise ConfigurationError(f"{path.name} must contain a mapping at its root.")
    return result


def load_config(
    start: Path, explicit: Path | None = None
) -> tuple[ScannerConfig, RuleRegistry, Path | None]:
    config_path = explicit or find_config(start)
    data = _read_config(config_path) if config_path else {}
    scan = data.get("scan", {}) or {}
    allow = data.get("allowlist", {}) or {}
    exclude = data.get("exclude", scan.get("exclude", [])) or []
    config = ScannerConfig(
        max_file_size_mb=_positive_int(scan.get("max_file_size_mb", 5), "scan.max_file_size_mb"),
        entropy=bool(scan.get("entropy", True)),
        exclude=_string_list(exclude, "exclude"),
        follow_symlinks=bool(scan.get("follow_symlinks", False)),
        allowlist=AllowlistConfig(
            paths=_string_list(allow.get("paths", []), "allowlist.paths"),
            rules=set(_string_list(allow.get("rules", []), "allowlist.rules")),
            fingerprints=set(_string_list(allow.get("fingerprints", []), "allowlist.fingerprints")),
        ),
    )
    registry = RuleRegistry(builtin_rules())
    _apply_rule_config(registry, data.get("rules", {}) or {})
    _add_custom_rules(registry, data.get("custom_rules", []) or [])
    return config, registry, config_path


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer.")
    return value


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigurationError(f"{name} must be a list of strings.")
    return value


def _apply_rule_config(registry: RuleRegistry, settings: Any) -> None:
    if not isinstance(settings, dict):
        raise ConfigurationError("rules must be a mapping.")
    for rule_id, raw in settings.items():
        if not isinstance(raw, dict):
            raise ConfigurationError(f"rules.{rule_id} must be a mapping.")
        severity = None
        if "severity" in raw:
            try:
                severity = Severity(str(raw["severity"]))
            except ValueError as exc:
                raise ConfigurationError(f"Invalid severity for rule {rule_id}.") from exc
        if "enabled" in raw and not isinstance(raw["enabled"], bool):
            raise ConfigurationError(f"rules.{rule_id}.enabled must be a boolean.")
        registry.configure(rule_id, enabled=raw.get("enabled"), severity=severity)


def _add_custom_rules(registry: RuleRegistry, rules: Any) -> None:
    if not isinstance(rules, list):
        raise ConfigurationError("custom_rules must be a list.")
    for index, raw in enumerate(rules, start=1):
        if not isinstance(raw, dict):
            raise ConfigurationError(f"custom_rules item {index} must be a mapping.")
        for field_name in ("tags", "keywords"):
            if field_name in raw:
                _string_list(raw[field_name], f"custom_rules[{index}].{field_name}")
        try:
            rule = Rule(
                rule_id=str(raw["id"]),
                name=str(raw["name"]),
                description=str(raw.get("description", raw["name"])),
                regex=str(raw["regex"]),
                category=str(raw.get("category", "custom")),
                severity=Severity(str(raw.get("severity", "high"))),
                confidence=Confidence(str(raw.get("confidence", "high"))),
                remediation=str(
                    raw.get(
                        "remediation", "Rotate the credential and remove it from source control."
                    )
                ),
                tags=frozenset(str(item) for item in raw.get("tags", [])),
                keywords=frozenset(str(item).lower() for item in raw.get("keywords", [])),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid custom rule at item {index}: {exc}") from exc
        registry.register(rule)
