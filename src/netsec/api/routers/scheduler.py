"""Scheduler router — manage scheduled jobs."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()


class JobCreate(BaseModel):
    name: str
    trigger_type: str  # cron, interval
    trigger_args: dict[str, Any]
    task_type: str
    task_params: dict[str, Any] = {}


class JobOut(BaseModel):
    id: str
    name: str
    trigger_type: str
    trigger_args: dict[str, Any]
    task_type: str
    task_params: dict[str, Any]
    enabled: bool
    next_run: str | None = None


def _get_scheduler(request: Request):
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    return scheduler


@router.get("/jobs", response_model=list[JobOut])
async def list_jobs(request: Request) -> list[JobOut]:
    """List all scheduled jobs."""
    scheduler = _get_scheduler(request)
    jobs = scheduler.list_jobs()
    return [
        JobOut(
            id=j.id,
            name=j.name,
            trigger_type=j.trigger_type,
            trigger_args=j.trigger_args,
            task_type=j.task_type,
            task_params=j.task_params,
            enabled=j.enabled,
            next_run=j.next_run,
        )
        for j in jobs
    ]


@router.post("/jobs", response_model=JobOut, status_code=201)
async def create_job(body: JobCreate, request: Request) -> JobOut:
    """Create a scheduled job."""
    scheduler = _get_scheduler(request)
    try:
        job = scheduler.add_job(
            name=body.name,
            trigger_type=body.trigger_type,
            trigger_args=body.trigger_args,
            task_type=body.task_type,
            task_params=body.task_params,
        )
        return JobOut(
            id=job.id,
            name=job.name,
            trigger_type=job.trigger_type,
            trigger_args=job.trigger_args,
            task_type=job.task_type,
            task_params=job.task_params,
            enabled=job.enabled,
            next_run=job.next_run,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/jobs/{job_id}", status_code=204)
async def delete_job(job_id: str, request: Request) -> None:
    """Delete a scheduled job."""
    scheduler = _get_scheduler(request)
    if not scheduler.remove_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")


@router.post("/jobs/{job_id}/pause", response_model=JobOut)
async def pause_job(job_id: str, request: Request) -> JobOut:
    """Pause a scheduled job."""
    scheduler = _get_scheduler(request)
    if not scheduler.pause_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    job = scheduler.get_job(job_id)
    return JobOut(
        id=job.id, name=job.name, trigger_type=job.trigger_type,
        trigger_args=job.trigger_args, task_type=job.task_type,
        task_params=job.task_params, enabled=job.enabled, next_run=job.next_run,
    )


@router.post("/jobs/{job_id}/resume", response_model=JobOut)
async def resume_job(job_id: str, request: Request) -> JobOut:
    """Resume a paused job."""
    scheduler = _get_scheduler(request)
    if not scheduler.resume_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    job = scheduler.get_job(job_id)
    return JobOut(
        id=job.id, name=job.name, trigger_type=job.trigger_type,
        trigger_args=job.trigger_args, task_type=job.task_type,
        task_params=job.task_params, enabled=job.enabled, next_run=job.next_run,
    )
