"""Cross-tool alert correlation."""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from netsec.pipeline.normalization import NormalizedAlert

logger = logging.getLogger(__name__)


class AlertCorrelator:
    """Correlates alerts from different tools targeting the same device/event."""

    def __init__(self, correlation_window: int = 600) -> None:
        self._window = timedelta(seconds=correlation_window)
        # device_ip -> list of (alert, correlation_id, timestamp)
        self._recent: dict[str, list[tuple[NormalizedAlert, str, datetime]]] = defaultdict(list)

    def correlate(self, alert: NormalizedAlert) -> str | None:
        """Try to correlate this alert with recent alerts for the same device.

        Returns a correlation_id if correlated, None otherwise.
        """
        if not alert.device_ip:
            return None

        now = datetime.now(timezone.utc)
        device_alerts = self._recent[alert.device_ip]

        # Clean expired
        device_alerts[:] = [
            (a, cid, ts) for a, cid, ts in device_alerts
            if now - ts <= self._window
        ]

        # Check for correlation — same device, different tool, within window
        for existing_alert, correlation_id, _ in device_alerts:
            if existing_alert.source_tool != alert.source_tool:
                # Different tool saw something on the same device
                logger.info(
                    "Correlated alerts: %s (%s) <-> %s (%s) for device %s",
                    alert.title, alert.source_tool,
                    existing_alert.title, existing_alert.source_tool,
                    alert.device_ip,
                )
                device_alerts.append((alert, correlation_id, now))
                return correlation_id

        # No correlation found — create new group
        new_correlation_id = uuid4().hex[:12]
        device_alerts.append((alert, new_correlation_id, now))
        return new_correlation_id

    def cleanup(self) -> None:
        """Remove expired correlation data."""
        now = datetime.now(timezone.utc)
        for ip in list(self._recent.keys()):
            self._recent[ip] = [
                (a, cid, ts) for a, cid, ts in self._recent[ip]
                if now - ts <= self._window * 2
            ]
            if not self._recent[ip]:
                del self._recent[ip]
