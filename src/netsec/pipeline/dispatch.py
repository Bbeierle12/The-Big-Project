"""Alert dispatch — send alerts to configured channels."""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from netsec.core.config import get_settings
from netsec.pipeline.normalization import NormalizedAlert

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Dispatches alerts to configured notification channels."""

    def __init__(self) -> None:
        settings = get_settings()
        self._dispatch_config = settings.alerts.dispatch
        self._http_client: httpx.AsyncClient | None = None

    async def dispatch(self, alert: NormalizedAlert, correlation_id: str | None = None) -> dict[str, bool]:
        """Send alert to all configured channels.

        Returns dict of {channel: success}.
        """
        results: dict[str, bool] = {}

        if self._dispatch_config.webhook_url:
            results["webhook"] = await self._send_webhook(alert, correlation_id)

        if self._dispatch_config.email_enabled:
            results["email"] = await self._send_email(alert, correlation_id)

        return results

    async def _send_webhook(self, alert: NormalizedAlert, correlation_id: str | None) -> bool:
        """Send alert via webhook."""
        try:
            if self._http_client is None:
                self._http_client = httpx.AsyncClient(timeout=30.0)

            payload = {
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "source_tool": alert.source_tool,
                "category": alert.category,
                "device_ip": alert.device_ip,
                "timestamp": alert.timestamp.isoformat(),
                "correlation_id": correlation_id,
            }

            response = await self._http_client.post(
                self._dispatch_config.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            logger.info("Webhook dispatched: %s", alert.title)
            return True

        except Exception:
            logger.exception("Webhook dispatch failed")
            return False

    async def _send_email(self, alert: NormalizedAlert, correlation_id: str | None) -> bool:
        """Send alert via email (SMTP)."""
        try:
            import smtplib
            from email.mime.text import MIMEText

            cfg = self._dispatch_config
            body = (
                f"Alert: {alert.title}\n"
                f"Severity: {alert.severity}\n"
                f"Source: {alert.source_tool}\n"
                f"Category: {alert.category}\n"
                f"Device: {alert.device_ip}\n"
                f"Time: {alert.timestamp.isoformat()}\n"
                f"Correlation: {correlation_id or 'N/A'}\n\n"
                f"Description:\n{alert.description}"
            )

            msg = MIMEText(body)
            msg["Subject"] = f"[NetSec {alert.severity.upper()}] {alert.title}"
            msg["From"] = cfg.email_from
            msg["To"] = cfg.email_to

            with smtplib.SMTP(cfg.email_smtp_host, cfg.email_smtp_port) as server:
                server.starttls()
                server.send_message(msg)

            logger.info("Email dispatched: %s", alert.title)
            return True

        except Exception:
            logger.exception("Email dispatch failed")
            return False

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
