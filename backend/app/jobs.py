"""Persistent database-backed scan job queue."""

import asyncio
import json
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import ScanJob
from app.scan_service import execute_scan_request
from app.schemas import ScanJobOut, ScanRequest


def job_to_out(job: ScanJob) -> ScanJobOut:
    return ScanJobOut(
        id=job.id,
        status=job.status,
        progress=job.progress,
        phase=job.phase,
        owner=job.owner,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        cancel_requested=job.cancel_requested,
        error=job.error,
        scan_ids=job.get_scan_ids(),
        request=job.get_request(),
        requires_authorized_worker=bool(job.requires_authorized_worker),
    )


async def enqueue_job(db: AsyncSession, request: ScanRequest, owner: str) -> ScanJob:
    job = ScanJob(
        id=str(uuid.uuid4()),
        owner=owner,
        request_json="{}",
        requires_authorized_worker=request.execution_mode == "authorized",
    )
    job.set_request(request.model_dump(mode="json"))
    db.add(job)
    await db.flush()
    return job


async def _load_job(session: AsyncSession, job_id: str) -> ScanJob | None:
    result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
    return result.scalar_one_or_none()


async def process_job(job_id: str, worker_id: str | None = None) -> None:
    worker_id = worker_id or settings.worker_id
    async with async_session() as session:
        job = await _load_job(session, job_id)
        if not job or job.status not in ("queued", "claimed"):
            return
        if bool(job.requires_authorized_worker) != bool(settings.authorized_worker):
            return
        job.status = "running"
        job.worker_id = worker_id
        job.started_at = datetime.now(timezone.utc)
        job.phase = "Validando alcance"
        await session.commit()

    async def progress(value: float, phase: str) -> None:
        async with async_session() as progress_session:
            current = await _load_job(progress_session, job_id)
            if current:
                current.progress = round(value, 2)
                current.phase = phase
                await progress_session.commit()

    async def cancelled() -> bool:
        async with async_session() as cancel_session:
            current = await _load_job(cancel_session, job_id)
            return bool(current and current.cancel_requested)

    try:
        async with async_session() as session:
            job = await _load_job(session, job_id)
            if not job:
                return
            request = ScanRequest.model_validate(job.get_request())
            scans = await execute_scan_request(
                request,
                session,
                owner=job.owner,
                job_id=job.id,
                progress_callback=progress,
                cancel_callback=cancelled,
            )
            await session.commit()
            scan_ids = [scan.id for scan in scans]

        async with async_session() as session:
            job = await _load_job(session, job_id)
            if job:
                job.status = "completed"
                job.progress = 100.0
                job.phase = "Completado"
                job.finished_at = datetime.now(timezone.utc)
                job.set_scan_ids(scan_ids)
                await session.commit()
                await _send_webhook(job)
    except asyncio.CancelledError:
        async with async_session() as session:
            job = await _load_job(session, job_id)
            if job:
                job.status = "cancelled"
                job.phase = "Cancelado"
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
    except Exception as exc:
        async with async_session() as session:
            job = await _load_job(session, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)[:4000]
                job.phase = "Error"
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()


async def claim_next_job(worker_id: str | None = None) -> str | None:
    """Claim one queued job. FOR UPDATE works on PostgreSQL; SQLite serializes writes."""
    async with async_session() as session:
        statement = (
            select(ScanJob)
            .where(
                ScanJob.status == "queued",
                ScanJob.requires_authorized_worker == settings.authorized_worker,
            )
            .order_by(ScanJob.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        result = await session.execute(statement)
        job = result.scalar_one_or_none()
        if not job:
            return None
        job.status = "claimed"
        job.worker_id = worker_id or settings.worker_id
        await session.commit()
        return job.id


async def _send_webhook(job: ScanJob) -> None:
    if not settings.webhook_url:
        return
    payload = json.dumps(job_to_out(job).model_dump(mode="json")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if settings.webhook_secret:
        import hashlib
        import hmac

        headers["X-GeekNosy-Signature"] = hmac.new(
            settings.webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(settings.webhook_url, content=payload, headers=headers)
