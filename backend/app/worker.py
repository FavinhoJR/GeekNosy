"""Standalone persistent worker: python -m app.worker."""

import asyncio
import logging

from app.config import settings
from app.database import init_db
from app.jobs import claim_next_job, process_job
from app.schedules import enqueue_due_schedules

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("datagobs.worker")


async def run_worker() -> None:
    await init_db()
    logger.info("Worker %s iniciado", settings.worker_id)
    while True:
        await enqueue_due_schedules()
        job_id = await claim_next_job(settings.worker_id)
        if job_id:
            logger.info("Procesando trabajo %s", job_id)
            await process_job(job_id, settings.worker_id)
        else:
            await asyncio.sleep(settings.worker_poll_seconds)


if __name__ == "__main__":
    asyncio.run(run_worker())
