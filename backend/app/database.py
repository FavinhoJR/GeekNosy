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
    from app.models import Scan, ScanResult

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
    """Añade columnas nuevas en SQLite si la BD ya existía."""
    migrations = [
        "ALTER TABLE scans ADD COLUMN route_profile VARCHAR(32)",
        "ALTER TABLE scans ADD COLUMN include_exposure_checks BOOLEAN DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN max_paths_per_domain INTEGER",
        "ALTER TABLE scans ADD COLUMN route_meta_json TEXT",
    ]
    async with engine.begin() as conn:
        for sql in migrations:
            try:
                await conn.exec_driver_sql(sql)
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
