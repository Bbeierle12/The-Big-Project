"""Test alert pipeline stages."""
import pytest
from netsec.pipeline.normalization import AlertNormalizer
from netsec.pipeline.deduplication import AlertDeduplicator
from netsec.pipeline.severity import SeverityClassifier


def test_normalize_suricata():
    normalizer = AlertNormalizer()
    raw = {
        "alert": {
            "signature": "ET SCAN Nmap",
            "signature_id": 2001,
            "severity": 2,
            "category": "Attempted Recon",
        },
        "src_ip": "192.168.1.100",
    }
    alert = normalizer.normalize("suricata", raw)
    assert alert.title == "ET SCAN Nmap"
    assert alert.severity == "high"
    assert alert.category == "intrusion"
    assert alert.device_ip == "192.168.1.100"


def test_dedup_within_window():
    dedup = AlertDeduplicator(window_seconds=60)
    normalizer = AlertNormalizer()

    raw = {"title": "Test Alert", "host": "10.0.0.1"}
    alert = normalizer.normalize("generic", raw)

    is_new1, count1 = dedup.check(alert)
    assert is_new1 is True
    assert count1 == 1

    is_new2, count2 = dedup.check(alert)
    assert is_new2 is False
    assert count2 == 2


def test_severity_escalation():
    classifier = SeverityClassifier()
    normalizer = AlertNormalizer()

    raw = {"title": "Malware detected", "host": "10.0.0.1"}
    alert = normalizer.normalize("clamav", raw)
    alert.category = "malware"
    alert.severity = "medium"

    result = classifier.classify(alert)
    assert result == "high"  # Escalated by malware rule
