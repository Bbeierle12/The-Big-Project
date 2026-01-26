"""APScheduler integration for scheduled tasks."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Coroutine
from uuid import uuid4

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from netsec.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class JobInfo:
    id: str
    name: str
    trigger_type: str  # cron, interval
    trigger_args: dict[str, Any]
    task_type: str
    task_params: dict[str, Any]
    enabled: bool = True
    next_run: str | None = None


class Scheduler:
    """Manages scheduled security tasks."""

    def __init__(self) -> None:
        settings = get_settings()
        self._scheduler = AsyncIOScheduler(timezone=settings.scheduler.timezone)
        self._jobs: dict[str, JobInfo] = {}
        self._task_handler: Callable[..., Coroutine[Any, Any, Any]] | None = None

    def set_task_handler(self, handler: Callable[..., Coroutine[Any, Any, Any]]) -> None:
        """Set the async function that executes scheduled tasks."""
        self._task_handler = handler

    async def start(self) -> None:
        settings = get_settings()
        if not settings.scheduler.enabled:
            logger.info("Scheduler disabled by config")
            return
        self._scheduler.start()
        logger.info("Scheduler started")

    async def stop(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

    def add_job(
        self,
        name: str,
        trigger_type: str,
        trigger_args: dict[str, Any],
        task_type: str,
        task_params: dict[str, Any],
    ) -> JobInfo:
        """Add a scheduled job."""
        job_id = uuid4().hex[:12]

        if trigger_type == "cron":
            trigger = CronTrigger(**trigger_args)
        elif trigger_type == "interval":
            trigger = IntervalTrigger(**trigger_args)
        else:
            raise ValueError(f"Unsupported trigger type: {trigger_type}")

        async def _run_job():
            if self._task_handler:
                try:
                    await self._task_handler(task_type, task_params)
                except Exception:
                    logger.exception("Scheduled job failed: %s", name)

        self._scheduler.add_job(
            _run_job,
            trigger=trigger,
            id=job_id,
            name=name,
        )

        info = JobInfo(
            id=job_id,
            name=name,
            trigger_type=trigger_type,
            trigger_args=trigger_args,
            task_type=task_type,
            task_params=task_params,
        )
        self._jobs[job_id] = info
        logger.info("Added scheduled job: %s (%s)", name, trigger_type)
        return info

    def remove_job(self, job_id: str) -> bool:
        if job_id in self._jobs:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
            del self._jobs[job_id]
            return True
        return False

    def list_jobs(self) -> list[JobInfo]:
        result = []
        for info in self._jobs.values():
            # Try to get next run time
            ap_job = self._scheduler.get_job(info.id)
            if ap_job and ap_job.next_run_time:
                info.next_run = ap_job.next_run_time.isoformat()
            result.append(info)
        return result

    def get_job(self, job_id: str) -> JobInfo | None:
        return self._jobs.get(job_id)

    def pause_job(self, job_id: str) -> bool:
        if job_id in self._jobs:
            self._scheduler.pause_job(job_id)
            self._jobs[job_id].enabled = False
            return True
        return False

    def resume_job(self, job_id: str) -> bool:
        if job_id in self._jobs:
            self._scheduler.resume_job(job_id)
            self._jobs[job_id].enabled = True
            return True
        return False
