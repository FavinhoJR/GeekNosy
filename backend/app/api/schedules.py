"""Recurring scan schedule API."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ScanSchedule
from app.schedules import new_schedule_id
from app.schemas import ScheduleCreate, ScheduleOut, ScheduleUpdate
from app.security import require_api_key

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _out(schedule: ScanSchedule) -> ScheduleOut:
    return ScheduleOut(
        id=schedule.id,
        name=schedule.name,
        interval_minutes=schedule.interval_minutes,
        enabled=schedule.enabled,
        next_run_at=schedule.next_run_at,
        last_run_at=schedule.last_run_at,
        created_at=schedule.created_at,
        request=schedule.get_request(),
    )


async def _owned(db: AsyncSession, schedule_id: str, identity: str) -> ScanSchedule:
    result = await db.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.owner == identity
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Programación no encontrada")
    return schedule


@router.post("", response_model=ScheduleOut, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    if not body.request.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Debe confirmar autorización")
    schedule = ScanSchedule(
        id=new_schedule_id(),
        owner=identity,
        name=body.name,
        interval_minutes=body.interval_minutes,
        next_run_at=datetime.now(timezone.utc) + timedelta(minutes=body.interval_minutes),
        request_json="{}",
    )
    schedule.set_request(body.request.model_dump(mode="json"))
    db.add(schedule)
    await db.flush()
    return _out(schedule)


@router.get("", response_model=list[ScheduleOut])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.owner == identity)
        .order_by(ScanSchedule.created_at.desc())
    )
    return [_out(schedule) for schedule in result.scalars().all()]


@router.patch("/{schedule_id}", response_model=ScheduleOut)
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    schedule = await _owned(db, schedule_id, identity)
    schedule.enabled = body.enabled
    await db.flush()
    return _out(schedule)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    schedule = await _owned(db, schedule_id, identity)
    await db.delete(schedule)
    return {"ok": True}
