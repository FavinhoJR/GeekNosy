"""Interval-based scheduling for authorized recurring scans."""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import async_session
from app.jobs import enqueue_job
from app.models import ScanSchedule
from app.schemas import ScanRequest


async def enqueue_due_schedules() -> int:
    now = datetime.now(timezone.utc)
    created = 0
    async with async_session() as session:
        result = await session.execute(
            select(ScanSchedule)
            .where(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= now,
            )
            .with_for_update(skip_locked=True)
        )
        schedules = result.scalars().all()
        for schedule in schedules:
            request = ScanRequest.model_validate(schedule.get_request())
            await enqueue_job(session, request, schedule.owner)
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            created += 1
        await session.commit()
    return created


def new_schedule_id() -> str:
    return str(uuid.uuid4())
