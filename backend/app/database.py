from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(settings.database_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def migrate_legacy_data():
    """Actualiza registros antiguos (notas A-F, estados legacy) a formato actual."""
    from sqlalchemy import select

    from app.compat import normalize_comparison_status, normalize_grade, normalize_mode
    from app.models import Scan

    from sqlalchemy.orm import selectinload

    async with async_session() as session:
        result = await session.execute(select(Scan).options(selectinload(Scan.results)))
        scans = result.scalars().all()
        for scan in scans:
            scan.overall_grade = normalize_grade(scan.overall_grade, scan.overall_score)
            scan.comparison_status = normalize_comparison_status(scan.comparison_status)
            scan.mode = normalize_mode(scan.mode)
            for result in scan.results:
                result.grade = normalize_grade(result.grade, result.score)
        await session.commit()


async def _ensure_columns():
    """Small compatibility migration until Alembic is introduced."""
    columns = [
        ("route_profile", "VARCHAR(32)"),
        ("include_exposure_checks", "BOOLEAN DEFAULT 0"),
        ("max_paths_per_domain", "INTEGER"),
        ("route_meta_json", "TEXT"),
        ("intensity", "VARCHAR(32) DEFAULT 'standard'"),
        ("owner", "VARCHAR(128)"),
        ("job_id", "VARCHAR(36)"),
        ("finding_details_json", "TEXT"),
    ]
    if engine.url.get_backend_name() == "sqlite":
        for name, sql_type in columns:
            async with engine.begin() as conn:
                try:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE scans ADD COLUMN {name} {sql_type}"
                    )
                except Exception:
                    pass
    else:
        async with engine.begin() as conn:
            for name, sql_type in columns:
                await conn.exec_driver_sql(
                    f"ALTER TABLE scans ADD COLUMN IF NOT EXISTS {name} {sql_type}"
                )

    job_columns = [("requires_authorized_worker", "BOOLEAN DEFAULT FALSE")]
    async with engine.begin() as conn:
        for name, sql_type in job_columns:
            try:
                suffix = "" if engine.url.get_backend_name() == "sqlite" else " IF NOT EXISTS"
                await conn.exec_driver_sql(
                    f"ALTER TABLE scan_jobs ADD COLUMN{suffix} {name} {sql_type}"
                )
            except Exception:
                pass


async def init_db():
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _ensure_columns()
    try:
        await migrate_legacy_data()
    except Exception:
        pass


async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
