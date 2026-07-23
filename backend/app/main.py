from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import __author__, __version__
from app.api.reports import router as reports_router
from app.api.routes import router as scans_router
from app.api.jobs import router as jobs_router
from app.api.findings import router as findings_router
from app.api.schedules import router as schedules_router
from app.api.imports import router as imports_router
from app.config import settings
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
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(jobs_router)
app.include_router(findings_router)
app.include_router(schedules_router)
app.include_router(imports_router)


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
    from app.config import settings
    from app.route_profiles import PROFILE_DESCRIPTIONS, ROUTE_PROFILES, ROUTE_PROFILE_MODES

    return {
        "name": "DataGobs",
        "version": __version__,
        "author": __author__,
        "license": "Uso abierto",
        "description": "Evaluación no intrusiva de configuración pública de seguridad web",
        "route_profiles": {
            "available": ROUTE_PROFILE_MODES,
            "descriptions": PROFILE_DESCRIPTIONS,
            "paths_by_profile": ROUTE_PROFILES,
            "auto_mode": (
                "Evalúa rutas core, detecta tecnología (WordPress, Joomla, Drupal, Laravel, "
                "Django, Node, IIS, APIs) y agrega rutas del perfil correspondiente. "
                "Equivalente a standard con detección dinámica."
            ),
            "profile_behavior": {
                "minimal": "Solo core",
                "standard": "Core + tecnología detectada",
                "advanced": "Core + common + tecnología detectada + api_docs si aplica",
                "all": "Todos los perfiles (respetando max_paths_per_domain)",
                "auto": "Igual que standard según detección",
            },
        },
        "scan_options": {
            "route_profile": ROUTE_PROFILE_MODES,
            "include_exposure_checks": "Solo metadatos HEAD; nunca descarga contenido sensible",
            "max_paths_per_domain_default": settings.max_paths_per_domain_default,
            "intensity": ["passive", "fast", "standard", "bug_bounty", "deep", "custom"],
            "authorization_confirmation_required": settings.require_authorization_confirmation,
            "api_key_required": bool(settings.api_keys),
        },
        "modes": ["standard", "advanced"],
        "restrictions": [
            "Sin explotación ni fuzzing agresivo",
            "Sin fuerza bruta ni bypass",
            "Solo GET/HEAD públicos",
            "Sin autenticación ni payloads",
            "Rutas sensibles: solo status, headers y content-type/length",
            "Bloqueo SSRF de loopback, redes privadas, link-local y metadata cloud",
            "Redirecciones limitadas al host autorizado",
        ],
        "automation": {
            "persistent_jobs": True,
            "progress_and_cancellation": True,
            "schedules": True,
            "webhooks": bool(settings.webhook_url),
            "exports": ["json", "jsonl", "csv", "pdf", "sarif", "markdown", "html"],
            "external_imports": ["nuclei-jsonl"],
        },
    }


# Servir frontend estático en producción
frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
