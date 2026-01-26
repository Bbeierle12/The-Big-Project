"""Alert deduplication using fingerprint-based matching."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from netsec.pipeline.normalization import NormalizedAlert

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """Deduplicates alerts within a configurable time window."""

    def __init__(self, window_seconds: int = 300, max_size: int = 10_000) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._max_size = max_size
        # fingerprint -> (first_seen, last_seen, count)
        self._seen: dict[str, tuple[datetime, datetime, int]] = {}

    def check(self, alert: NormalizedAlert) -> tuple[bool, int]:
        """Check if an alert is a duplicate.

        Returns:
            (is_new, count) — is_new=False means it's a duplicate within the window.
            count is the total occurrences including this one.
        """
        fp = alert.fingerprint
        now = datetime.now(timezone.utc)

        if fp in self._seen:
            first_seen, last_seen, count = self._seen[fp]
            if now - last_seen <= self._window:
                # Within window — duplicate
                self._seen[fp] = (first_seen, now, count + 1)
                logger.debug("Duplicate alert (count=%d): %s", count + 1, alert.title)
                return False, count + 1
            else:
                # Window expired — treat as new
                self._seen[fp] = (now, now, 1)
                return True, 1

        if len(self._seen) >= self._max_size:
            self._evict_oldest()
        self._seen[fp] = (now, now, 1)
        return True, 1

    def _evict_oldest(self) -> None:
        """Evict the oldest 25% of entries by last_seen timestamp."""
        count_to_remove = len(self._seen) // 4 or 1
        sorted_fps = sorted(self._seen, key=lambda fp: self._seen[fp][1])
        for fp in sorted_fps[:count_to_remove]:
            del self._seen[fp]

    def cleanup(self) -> int:
        """Remove expired entries. Returns number removed."""
        now = datetime.now(timezone.utc)
        expired = [
            fp for fp, (_, last_seen, _) in self._seen.items()
            if now - last_seen > self._window * 2
        ]
        for fp in expired:
            del self._seen[fp]
        return len(expired)
