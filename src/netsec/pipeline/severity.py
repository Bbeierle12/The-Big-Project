"""Severity classification and escalation rules."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from netsec.pipeline.normalization import NormalizedAlert

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class SeverityRule:
    """A rule that can escalate or override severity."""
    name: str
    condition: str  # category, source_tool, keyword match
    value: str
    target_severity: str
    escalate_only: bool = True  # Only escalate, never downgrade


DEFAULT_RULES: list[SeverityRule] = [
    SeverityRule("critical_intrusion", "category", "intrusion", "high", escalate_only=True),
    SeverityRule("malware_escalate", "category", "malware", "high", escalate_only=True),
    SeverityRule("repeated_high", "count_above", "10", "critical", escalate_only=True),
]


class SeverityClassifier:
    """Applies severity rules to alerts."""

    def __init__(self, rules: list[SeverityRule] | None = None) -> None:
        self._rules = rules or DEFAULT_RULES

    def classify(self, alert: NormalizedAlert, occurrence_count: int = 1) -> str:
        """Apply rules and return final severity."""
        current = alert.severity
        current_level = SEVERITY_LEVELS.get(current, 0)

        for rule in self._rules:
            match rule.condition:
                case "category":
                    if alert.category != rule.value:
                        continue
                case "source_tool":
                    if alert.source_tool != rule.value:
                        continue
                case "keyword":
                    if rule.value.lower() not in alert.title.lower():
                        continue
                case "count_above":
                    if occurrence_count <= int(rule.value):
                        continue
                case _:
                    continue

            target_level = SEVERITY_LEVELS.get(rule.target_severity, 0)
            if rule.escalate_only and target_level <= current_level:
                continue

            logger.debug("Rule '%s' escalating %s -> %s", rule.name, current, rule.target_severity)
            current = rule.target_severity
            current_level = target_level

        return current
