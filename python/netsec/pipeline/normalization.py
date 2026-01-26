"""Alert normalization — convert tool-specific alerts to common format."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class NormalizedAlert:
    """Tool-agnostic alert representation."""
    title: str
    description: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    source_tool: str = ""
    source_event_id: str = ""
    category: str = ""  # intrusion, malware, vulnerability, policy, anomaly
    device_ip: str = ""
    fingerprint: str = ""  # dedup key
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = field(default_factory=dict)


class AlertNormalizer:
    """Normalizes alerts from various security tools into a common format."""

    def __init__(self) -> None:
        self._normalizers: dict[str, Any] = {
            "nmap": self._normalize_nmap,
            "suricata": self._normalize_suricata,
            "zeek": self._normalize_zeek,
            "openvas": self._normalize_openvas,
            "clamav": self._normalize_clamav,
            "ossec": self._normalize_ossec,
            "fail2ban": self._normalize_fail2ban,
        }

    def normalize(self, source_tool: str, raw_data: dict[str, Any]) -> NormalizedAlert:
        """Normalize a raw alert from any tool."""
        normalizer = self._normalizers.get(source_tool)
        if normalizer:
            alert = normalizer(raw_data)
        else:
            alert = self._normalize_generic(source_tool, raw_data)

        # Generate fingerprint if not set
        if not alert.fingerprint:
            alert.fingerprint = self._generate_fingerprint(alert)

        alert.source_tool = source_tool
        return alert

    def _generate_fingerprint(self, alert: NormalizedAlert) -> str:
        """Generate a dedup fingerprint from alert content."""
        key = f"{alert.source_tool}:{alert.category}:{alert.title}:{alert.device_ip}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _normalize_nmap(self, data: dict[str, Any]) -> NormalizedAlert:
        # Nmap alerts typically come from vuln script output
        return NormalizedAlert(
            title=data.get("title", "Nmap finding"),
            description=data.get("output", ""),
            severity=data.get("severity", "info"),
            category="vulnerability",
            device_ip=data.get("host", ""),
            raw_data=data,
        )

    def _normalize_suricata(self, data: dict[str, Any]) -> NormalizedAlert:
        alert_data = data.get("alert", {})
        return NormalizedAlert(
            title=alert_data.get("signature", "Suricata alert"),
            description=f"Category: {alert_data.get('category', 'unknown')}",
            severity=self._suricata_severity(alert_data.get("severity", 3)),
            source_event_id=str(alert_data.get("signature_id", "")),
            category="intrusion",
            device_ip=data.get("src_ip", ""),
            raw_data=data,
        )

    def _normalize_zeek(self, data: dict[str, Any]) -> NormalizedAlert:
        return NormalizedAlert(
            title=data.get("note", "Zeek notice"),
            description=data.get("msg", ""),
            severity=self._zeek_severity(data.get("note", "")),
            category="anomaly",
            device_ip=data.get("src", ""),
            raw_data=data,
        )

    def _normalize_openvas(self, data: dict[str, Any]) -> NormalizedAlert:
        cvss = data.get("cvss_score", 0)
        return NormalizedAlert(
            title=data.get("name", "OpenVAS finding"),
            description=data.get("description", ""),
            severity=self._cvss_to_severity(cvss),
            category="vulnerability",
            device_ip=data.get("host", ""),
            source_event_id=data.get("oid", ""),
            raw_data=data,
        )

    def _normalize_clamav(self, data: dict[str, Any]) -> NormalizedAlert:
        return NormalizedAlert(
            title=f"Malware detected: {data.get('signature', 'unknown')}",
            description=f"File: {data.get('file', 'unknown')}",
            severity="high",
            category="malware",
            device_ip=data.get("host", ""),
            raw_data=data,
        )

    def _normalize_ossec(self, data: dict[str, Any]) -> NormalizedAlert:
        level = data.get("level", 0)
        return NormalizedAlert(
            title=data.get("description", "OSSEC alert"),
            description=data.get("full_log", ""),
            severity=self._ossec_severity(level),
            source_event_id=str(data.get("rule_id", "")),
            category="intrusion",
            device_ip=data.get("srcip", ""),
            raw_data=data,
        )

    def _normalize_fail2ban(self, data: dict[str, Any]) -> NormalizedAlert:
        return NormalizedAlert(
            title=f"IP banned: {data.get('ip', 'unknown')} in jail {data.get('jail', 'unknown')}",
            description=f"Failures: {data.get('failures', 0)}",
            severity="medium",
            category="policy",
            device_ip=data.get("ip", ""),
            raw_data=data,
        )

    def _normalize_generic(self, source: str, data: dict[str, Any]) -> NormalizedAlert:
        return NormalizedAlert(
            title=data.get("title", data.get("message", f"Alert from {source}")),
            description=str(data.get("description", "")),
            severity=data.get("severity", "info"),
            category=data.get("category", "unknown"),
            device_ip=data.get("ip", data.get("host", "")),
            raw_data=data,
        )

    @staticmethod
    def _suricata_severity(level: int) -> str:
        return {1: "critical", 2: "high", 3: "medium"}.get(level, "low")

    @staticmethod
    def _zeek_severity(note: str) -> str:
        note_lower = note.lower()
        if "attack" in note_lower or "exploit" in note_lower:
            return "critical"
        if "scan" in note_lower:
            return "medium"
        return "info"

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @staticmethod
    def _ossec_severity(level: int) -> str:
        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 4:
            return "medium"
        if level >= 2:
            return "low"
        return "info"
