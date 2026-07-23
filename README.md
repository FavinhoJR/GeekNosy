# DataGobs 2.0

DataGobs es una plataforma defensiva para auditorías web autorizadas, bug bounty y
automatización de postura de seguridad. Combina análisis HTTP, TLS y DNS, rutas
inteligentes, crawling limitado al mismo origen, checks versionados, trabajos
persistentes, triage y reportes reproducibles.

Autor: Favio Urrea
Licencia: MIT

## Seguridad operativa

- Confirmación explícita de autorización en cada trabajo.
- API keys opcionales mediante `DATAGOBS_API_KEYS`.
- Bloqueo SSRF de loopback, redes privadas, link-local, multicast y direcciones reservadas.
- Validación DNS y de scope en cada redirección.
- Solo HTTP/HTTPS y puertos permitidos.
- Redirecciones limitadas al host autorizado.
- Límite de respuesta, timeouts, concurrencia y solicitudes por segundo.
- Cookies y evidencia sensible redactadas.
- Checks de exposición mediante `HEAD`.
- Aislamiento de trabajos, escaneos, reportes y triage por propietario/API key.

Las redes privadas están bloqueadas por defecto. Habilítelas únicamente en un
worker aislado y autorizado con `DATAGOBS_ALLOW_PRIVATE_TARGETS=true`.

## Capacidades

- Certificado, protocolo, cipher, ALPN, SAN y TLS 1.0-1.3.
- Redirección HTTP a HTTPS.
- Cabeceras, CSP semántica, CORS, cache y exposición de versiones.
- Cookies Secure, HttpOnly y SameSite.
- DNS A, AAAA, MX, NS, CAA, SPF, DMARC y DNSSEC.
- Detección de WordPress, Joomla, Drupal, Laravel, Django, Node, IIS y APIs.
- Crawling acotado al mismo origen en perfiles bug bounty/deep.
- Rutas públicas, tecnológicas, personalizadas y checks de exposición.
- Plantillas YAML versionadas con firma HMAC opcional.
- Cola persistente, progreso, cancelación y reintentos operativos.
- Programación recurrente por intervalos.
- Triage: nuevo, confirmado, falso positivo, aceptado y resuelto.
- Historial y comparación por dominio.
- JSON, JSONL, CSV, PDF, SARIF, Markdown y HTML.
- Webhook de finalización firmado.
- Importación de resultados JSONL de Nuclei.
- CLI y API OpenAPI.

## Perfiles de intensidad

| Perfil | Límite de rutas | Uso |
|---|---:|---|
| `passive` | 8 | Evidencia pública mínima |
| `fast` | 15 | Auditoría rápida |
| `standard` | 40 | Evaluación general |
| `bug_bounty` | 80 | Crawling y cobertura ampliada |
| `deep` | 120 | Auditoría autorizada exhaustiva |
| `custom` | 120 | Política definida por el operador |

Los perfiles no habilitan explotación, fuerza bruta ni payloads destructivos.

## Inicio con Docker

```bash
copy .env.example .env
# Edite .env y cambie las credenciales.
docker compose up --build -d
```

Abra `http://localhost:3000`.

La arquitectura de producción incluye:

- Nginx + React
- FastAPI
- Worker persistente
- PostgreSQL

## Desarrollo

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm run dev
```

## API de trabajos

Crear un trabajo:

```bash
curl -X POST http://localhost:3000/api/jobs ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: YOUR_KEY" ^
  -d "{\"request\":{\"domains\":[\"example.com\"],\"authorization_confirmed\":true,\"mode\":\"advanced\",\"intensity\":\"bug_bounty\",\"route_profile\":\"auto\",\"max_paths_per_domain\":80}}"
```

Consultar y cancelar:

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:3000/api/jobs/JOB_ID
curl -X POST -H "X-API-Key: YOUR_KEY" http://localhost:3000/api/jobs/JOB_ID/cancel
```

El endpoint histórico `POST /api/scan` continúa disponible para compatibilidad,
pero las automatizaciones deben usar `/api/jobs`.

## CLI

Desde `backend`:

```bash
python -m app.cli --api-key YOUR_KEY scan example.com --authorized --intensity bug_bounty --wait
python -m app.cli --api-key YOUR_KEY jobs
python -m app.cli --api-key YOUR_KEY report 1 sarif --output result.sarif
```

También puede definir `DATAGOBS_API_KEY`.

## Programación y webhooks

`POST /api/schedules` recibe:

```json
{
  "name": "Auditoría diaria",
  "interval_minutes": 1440,
  "request": {
    "domains": ["example.com"],
    "authorization_confirmed": true,
    "intensity": "standard"
  }
}
```

Configure `DATAGOBS_WEBHOOK_URL` y `DATAGOBS_WEBHOOK_SECRET` para recibir el
resultado del trabajo. La firma SHA-256 se envía en `X-DataGobs-Signature`.

## Plantillas

Las plantillas viven en `backend/app/checks/templates/`:

```yaml
id: example-check
name: Ejemplo
version: 1.0.0
severity: low
confidence: high
intrusiveness: passive
minimum_intensity: passive
recommendation: Descripción de remediación.
references:
  - CWE-200
match:
  path_regex: ^/example$
  status: 200
```

Si configura `DATAGOBS_TEMPLATE_SIGNING_SECRET`, solo se cargarán plantillas con
firma HMAC válida.

## Nuclei

DataGobs no ejecuta automáticamente plantillas comunitarias. Puede ejecutar
Nuclei con su propia política de scope/rate limit y después importar JSONL:

```bash
curl -X POST http://localhost:3000/api/imports/nuclei/SCAN_ID ^
  -H "X-API-Key: YOUR_KEY" ^
  -F "file=@nuclei.jsonl"
```

Los hallazgos quedan normalizados, deduplicados y disponibles para triage y SARIF.

## Endpoints principales

| Método | Ruta |
|---|---|
| GET | `/api/health` |
| GET | `/api/info` |
| POST/GET | `/api/jobs` |
| GET | `/api/jobs/{id}` |
| POST | `/api/jobs/{id}/cancel` |
| GET/POST/PATCH/DELETE | `/api/schedules` |
| GET | `/api/scans` |
| GET/DELETE | `/api/scans/{id}` |
| GET/PATCH | `/api/scans/{id}/findings` |
| GET | `/api/reports/{id}/{format}` |
| POST | `/api/imports/nuclei/{scan_id}` |

## Calidad

- Suite pytest para scope/SSRF, plugins, crawling, scoring y API.
- Build reproducible del frontend con lockfile.
- CI para backend, frontend y contenedores.
- Contenedor backend sin privilegios root.

DataGobs debe utilizarse exclusivamente sobre activos propios o con autorización
expresa del propietario.
