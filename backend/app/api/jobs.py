"""Asynchronous job API."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.jobs import enqueue_job, job_to_out, process_job
from app.models import ScanJob
from app.schemas import ScanJobCreate, ScanJobOut
from app.security import require_api_key

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


async def _owned_job(db: AsyncSession, job_id: str, identity: str) -> ScanJob:
    result = await db.execute(
        select(ScanJob).where(ScanJob.id == job_id, ScanJob.owner == identity)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Trabajo no encontrado")
    return job


@router.post("", response_model=ScanJobOut, status_code=202)
async def create_job(
    body: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    if not body.request.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Debe confirmar que cuenta con autorización para evaluar los objetivos",
        )
    job = await enqueue_job(db, body.request, identity)
    await db.commit()
    if settings.inline_worker:
        # Development fallback. Production uses the standalone persistent worker.
        asyncio.create_task(process_job(job.id, "api-background"))
    return job_to_out(job)


@router.get("", response_model=list[ScanJobOut])
async def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.owner == identity)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
    )
    return [job_to_out(job) for job in result.scalars().all()]


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    return job_to_out(await _owned_job(db, job_id, identity))


@router.post("/{job_id}/cancel", response_model=ScanJobOut)
async def cancel_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    job = await _owned_job(db, job_id, identity)
    if job.status in ("completed", "failed", "cancelled"):
        return job_to_out(job)
    job.cancel_requested = True
    job.phase = "Cancelación solicitada"
    await db.flush()
    return job_to_out(job)


@router.post("/{job_id}/retry", response_model=ScanJobOut)
async def retry_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    job = await _owned_job(db, job_id, identity)
    if job.status not in ("failed", "cancelled"):
        raise HTTPException(
            status_code=409,
            detail="Solo se pueden reintentar trabajos fallidos o cancelados",
        )
    job.status = "queued"
    job.progress = 0
    job.phase = "En cola para reintento"
    job.error = None
    job.cancel_requested = False
    job.started_at = None
    job.finished_at = None
    job.set_scan_ids([])
    await db.commit()
    if settings.inline_worker:
        asyncio.create_task(process_job(job.id, "api-background"))
    return job_to_out(job)


@router.delete("/{job_id}")
async def delete_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    job = await _owned_job(db, job_id, identity)
    if job.status not in ("completed", "failed", "cancelled"):
        raise HTTPException(
            status_code=409,
            detail="Solo se pueden eliminar trabajos terminados",
        )
    await db.delete(job)
    return {"ok": True}
