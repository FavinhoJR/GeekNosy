# DataGobs

**DataGobs** es una herramienta defensiva y no intrusiva para evaluar la configuración pública de seguridad web de dominios autorizados.

**Autor:** Favio Urrea  
**Licencia:** MIT (uso abierto)

## Qué evalúa

- Certificado SSL/TLS, expiración, emisor, TLS 1.2/1.3
- Redirección HTTP → HTTPS
- Cabeceras de seguridad (HSTS, CSP, X-Frame-Options, etc.)
- Cookies (Secure, HttpOnly, SameSite)
- DNS básico y CAA
- Consistencia de headers en respuestas 200, 301/302, 403 y 404
- Archivos públicos: `security.txt`, `robots.txt`, `sitemap.xml`

## Qué NO hace

- Explotación de vulnerabilidades
- Fuerza bruta, fuzzing agresivo o bypass de WAF
- Autenticación ni scraping masivo
- Pruebas intrusivas de ningún tipo

## Rutas evaluadas por defecto

```
/
/web/
/administrator/
/web/administrator/
/component/users
/web/component/users
/web/index.php/component/users
```

Puede agregar rutas personalizadas desde la interfaz.

## Modos de puntuación

| Modo | Composición |
|------|-------------|
| **Estándar** | SSL/TLS 45% + Headers 55% |
| **Avanzado** | SSL 30% + Headers 40% + Cookies 10% + DNS 10% + Consistencia 10% |

Nota del 1 al 10 (10 = más alta, 1 = más baja), derivada del puntaje 0-100

La nota global se calcula **solo** con la URL del sitio principal (respuesta 200 en `/`). Las rutas 403/404 se reportan por separado; si una 403 no tiene headers, se marca como *inconsistencia en página bloqueada*, no como fallo del sitio principal.

## Inicio rápido con Docker

```bash
cd DataGobs
docker compose up --build -d
```

Abra **http://localhost:3000**

### Ejemplo de escaneo por API

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com"],
    "institution": "Mi Institución",
    "mode": "standard",
    "custom_paths": ["/portal/"],
    "include_default_paths": true
  }'
```

### Exportar reportes

```bash
# JSON
curl -O http://localhost:3000/api/reports/1/json

# CSV
curl -O http://localhost:3000/api/reports/1/csv

# PDF
curl -O http://localhost:3000/api/reports/1/pdf
```

## Desarrollo local

### Backend (Python 3.11+)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
mkdir -p data
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend en http://localhost:5173 (proxy API → :8000)

## Estructura del proyecto

```
DataGobs/
├── backend/          # FastAPI + scanner + SQLite
├── frontend/         # React + Tailwind
├── examples/         # Reporte JSON de ejemplo
├── docker-compose.yml
└── README.md
```

## API principal

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/health` | Estado del servicio |
| GET | `/api/info` | Información y rutas por defecto |
| POST | `/api/scan` | Ejecutar escaneo |
| GET | `/api/scans` | Listar escaneos (filtros: search, grade, comparison_status) |
| GET | `/api/scans/{id}` | Detalle de escaneo |
| GET | `/api/scans/{id}/history` | Historial del dominio |
| GET | `/api/reports/{id}/json` | Exportar JSON |
| GET | `/api/reports/{id}/csv` | Exportar CSV |
| GET | `/api/reports/{id}/pdf` | Exportar PDF |

## Ejemplo de reporte

Ver [`examples/sample-report.json`](examples/sample-report.json).

## Recomendaciones por hallazgo

Cada hallazgo incluye título, recomendación técnica y severidad. Ejemplos:

- **missing_csp** → Definir Content-Security-Policy restrictiva
- **blocked_page_inconsistency** → Las páginas 403 deben incluir las mismas cabeceras que el sitio principal
- **cookie_no_secure** → Activar flag Secure en cookies HTTPS

Lista completa en `backend/app/recommendations.py`.

## Advertencia legal

Use DataGobs **únicamente** sobre dominios y sistemas para los que tenga autorización explícita. El desarrollador no se hace responsable del uso indebido de esta herramienta.
