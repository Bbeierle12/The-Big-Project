"""Alert service — orchestrates the alert pipeline."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.core.config import get_settings
from netsec.core.events import Event, EventBus, EventType
from netsec.models.alert import Alert
from netsec.pipeline.normalization import AlertNormalizer, NormalizedAlert
from netsec.pipeline.deduplication import AlertDeduplicator
from netsec.pipeline.correlation import AlertCorrelator
from netsec.pipeline.severity import SeverityClassifier
from netsec.pipeline.dispatch import AlertDispatcher

logger = logging.getLogger(__name__)


class AlertService:
    """Full alert pipeline: normalize -> dedup -> correlate -> classify -> dispatch."""

    def __init__(self, session: AsyncSession, event_bus: EventBus) -> None:
        self.session = session
        self.event_bus = event_bus
        settings = get_settings()

        self._normalizer = AlertNormalizer()
        self._deduplicator = AlertDeduplicator(window_seconds=settings.alerts.dedup_window_seconds)
        self._correlator = AlertCorrelator()
        self._classifier = SeverityClassifier()
        self._dispatcher = AlertDispatcher()

    async def process_raw_alert(self, source_tool: str, raw_data: dict[str, Any]) -> Alert | None:
        """Process a raw alert through the full pipeline.

        Returns the Alert model if it's new, None if deduplicated.
        """
        # 1. Normalize
        normalized = self._normalizer.normalize(source_tool, raw_data)

        # 2. Deduplicate
        is_new, count = self._deduplicator.check(normalized)

        if not is_new:
            # Update existing alert count
            await self._update_existing_alert(normalized.fingerprint, count)
            return None

        # 3. Correlate
        correlation_id = self._correlator.correlate(normalized)

        # 4. Classify severity
        final_severity = self._classifier.classify(normalized, count)
        normalized.severity = final_severity

        # 5. Persist
        alert = await self._create_alert(normalized, correlation_id, count)

        # 6. Dispatch
        await self._dispatcher.dispatch(normalized, correlation_id)

        # 7. Emit event
        await self.event_bus.publish(Event(
            type=EventType.ALERT_CREATED,
            source="alert_service",
            data={
                "alert_id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "source_tool": source_tool,
                "device_ip": normalized.device_ip,
                "correlation_id": correlation_id,
            },
        ))

        return alert

    async def get_alert(self, alert_id: str) -> Alert | None:
        return await self.session.get(Alert, alert_id)

    async def list_alerts(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        severity: str | None = None,
        status: str | None = None,
        source_tool: str | None = None,
    ) -> list[Alert]:
        stmt = select(Alert).order_by(Alert.last_seen.desc()).offset(offset).limit(limit)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if status:
            stmt = stmt.where(Alert.status == status)
        if source_tool:
            stmt = stmt.where(Alert.source_tool == source_tool)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_alert_status(self, alert_id: str, status: str) -> Alert | None:
        """Update alert status only (legacy method)."""
        return await self.update_alert(alert_id, status=status)

    async def update_alert(
        self,
        alert_id: str,
        status: str | None = None,
        severity: str | None = None,
        notes: str | None = None,
    ) -> Alert | None:
        """Update alert fields (status, severity, and/or notes)."""
        alert = await self.get_alert(alert_id)
        if alert is None:
            return None

        changed = False
        if status is not None and alert.status != status:
            alert.status = status
            changed = True
        if severity is not None and alert.severity != severity:
            alert.severity = severity
            changed = True
        if notes is not None and alert.notes != notes:
            alert.notes = notes
            changed = True

        if changed:
            await self.session.flush()

            # Determine event type based on new status
            if status == "resolved":
                event_type = EventType.ALERT_RESOLVED
            else:
                event_type = EventType.ALERT_UPDATED

            await self.event_bus.publish(Event(
                type=event_type,
                source="alert_service",
                data={
                    "alert_id": alert.id,
                    "status": alert.status,
                    "severity": alert.severity,
                },
            ))
        return alert

    async def get_alert_stats(self) -> dict[str, Any]:
        """Get alert statistics."""
        total = await self.session.execute(select(func.count(Alert.id)))
        by_severity = await self.session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status == "open")
            .group_by(Alert.severity)
        )
        by_tool = await self.session.execute(
            select(Alert.source_tool, func.count(Alert.id))
            .where(Alert.status == "open")
            .group_by(Alert.source_tool)
        )
        return {
            "total": total.scalar_one(),
            "open_by_severity": dict(by_severity.all()),
            "open_by_tool": dict(by_tool.all()),
        }

    async def _create_alert(
        self, normalized: NormalizedAlert, correlation_id: str | None, count: int
    ) -> Alert:
        now = datetime.now(timezone.utc)
        alert = Alert(
            id=uuid4().hex,
            title=normalized.title,
            description=normalized.description,
            severity=normalized.severity,
            status="open",
            source_tool=normalized.source_tool,
            source_event_id=normalized.source_event_id,
            category=normalized.category,
            device_ip=normalized.device_ip,
            fingerprint=normalized.fingerprint,
            count=count,
            first_seen=normalized.timestamp,
            last_seen=now,
            raw_data=normalized.raw_data,
            correlation_id=correlation_id,
        )
        self.session.add(alert)
        await self.session.flush()
        return alert

    async def _update_existing_alert(self, fingerprint: str, count: int) -> None:
        stmt = select(Alert).where(Alert.fingerprint == fingerprint).order_by(Alert.last_seen.desc())
        result = await self.session.execute(stmt)
        alert = result.scalar_one_or_none()
        if alert:
            alert.count = count
            alert.last_seen = datetime.now(timezone.utc)
            await self.session.flush()
