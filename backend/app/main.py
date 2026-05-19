from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import __author__, __version__
from app.api.reports import router as reports_router
from app.api.routes import router as scans_router
from app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="DataGobs",
    description="Herramienta defensiva de evaluación de seguridad web pública",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)
app.include_router(reports_router)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "tool": "DataGobs",
        "version": __version__,
        "author": __author__,
    }


@app.get("/api/info")
async def info():
    from app.config import DEFAULT_PATHS

    return {
        "name": "DataGobs",
        "version": __version__,
        "author": __author__,
        "license": "Uso abierto",
        "description": "Evaluación no intrusiva de configuración pública de seguridad web",
        "default_paths": DEFAULT_PATHS,
        "modes": ["standard", "advanced"],
        "restrictions": [
            "Sin explotación ni fuzzing agresivo",
            "Sin fuerza bruta ni bypass",
            "Solo configuración HTTP/HTTPS/DNS pública visible",
        ],
    }


# Servir frontend estático en producción
frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
