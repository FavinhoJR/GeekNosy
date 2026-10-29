# GeekNosy: guía técnica

## 1. Arquitectura

GeekNosy separa la interfaz, la API, la persistencia y la ejecución de trabajos:

```text
Navegador :3000 -> Nginx :8080 -> FastAPI :8000 -> PostgreSQL
                                      |
                            worker pasivo / worker autorizado
```

El stack base incluye:

- `frontend`: React compilado y servido por Nginx sin privilegios;
- `backend`: API FastAPI y creación de trabajos;
- `worker`: procesa exclusivamente trabajos pasivos;
- `postgres`: conserva trabajos, escaneos, hallazgos, triage y agendas.

Las acciones activas o autenticadas no se ejecutan en el worker base. Requieren el perfil Docker `authorized`, una referencia de alcance y una segunda confirmación.

## 2. Inicio con Docker

Requisitos: Docker Engine 24+ o Docker Desktop actual, Docker Compose v2 y al menos 2 GB de RAM disponibles.

```powershell
git clone https://github.com/FavinhoJR/GeekNosy.git
Set-Location GeekNosy
Copy-Item .env.example .env
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Abre `http://localhost:3000`. No es necesario instalar Python, Node, pnpm ni PostgreSQL en el host.

Antes de desplegar fuera de un equipo local, cambia `GEEKNOSY_POSTGRES_PASSWORD`, configura `GEEKNOSY_API_KEYS` y limita `GEEKNOSY_ALLOWED_DOMAINS` o `GEEKNOSY_ALLOWED_CIDRS`.

## 3. Verificación

```powershell
(Invoke-WebRequest 'http://localhost:3000').StatusCode
Invoke-RestMethod 'http://localhost:3000/api/health'
Invoke-RestMethod 'http://localhost:3000/api/info'
Invoke-RestMethod 'http://localhost:3000/api/jobs'
```

El resultado esperado es HTTP 200, `status: ok`, capacidades públicas y una lista de trabajos posiblemente vacía. Si configuraste una clave, agrega `-Headers @{ 'X-API-Key' = 'TU_CLAVE' }` a las solicitudes protegidas.

Para probar el motor usa únicamente un dominio propio o expresamente autorizado. Por política, los destinos privados, loopback, link-local, multicast y reservados permanecen bloqueados salvo configuración explícita.

## 4. Operación

```powershell
# Estado y logs
docker compose ps
docker compose logs --tail 100 backend worker frontend postgres

# Reconstruir después de actualizar
git pull --ff-only
docker compose build --pull
docker compose up -d

# Apagar conservando datos
docker compose down
```

No uses `docker compose down -v` si necesitas conservar el historial: elimina los volúmenes `geeknosy-postgres` y `geeknosy-data`.

Respaldo de PostgreSQL:

```powershell
docker compose exec postgres pg_dump -U geeknosy geeknosy > geeknosy-backup.sql
```

## 5. Configuración

Las variables se definen en `.env` y usan el prefijo `GEEKNOSY_`.

| Variable | Uso |
| --- | --- |
| `GEEKNOSY_POSTGRES_PASSWORD` | Contraseña usada por PostgreSQL en Compose |
| `GEEKNOSY_API_KEYS` | Claves separadas por comas; vacía en desarrollo local |
| `GEEKNOSY_CORS_ORIGINS` | Orígenes permitidos separados por comas |
| `GEEKNOSY_ALLOWED_DOMAINS` | Allowlist de dominios |
| `GEEKNOSY_ALLOWED_CIDRS` | Allowlist de redes |
| `GEEKNOSY_ALLOW_PRIVATE_TARGETS` | Permite destinos privados en el stack base; `false` por defecto |
| `GEEKNOSY_AUTHORIZED_ALLOW_PRIVATE_TARGETS` | Equivalente exclusivo del worker autorizado |
| `GEEKNOSY_ALLOW_ACTIVE_CHECKS` | Habilita comprobaciones activas en el worker autorizado |
| `GEEKNOSY_AUTH_PROFILES_JSON` | Perfiles de credenciales nombrados, sin enviar secretos desde el navegador |
| `GEEKNOSY_WEBHOOK_URL` | Destino opcional de notificaciones |
| `GEEKNOSY_WEBHOOK_SECRET` | Firma HMAC de webhooks |
| `GEEKNOSY_OSV_ENABLED` | Consulta opcional de vulnerabilidades de dependencias |

El código también admite límites mediante `GEEKNOSY_ALLOWED_PORTS`, `GEEKNOSY_GLOBAL_REQUESTS_PER_SECOND`, `GEEKNOSY_PER_HOST_REQUESTS_PER_SECOND`, `GEEKNOSY_MAX_CONCURRENT_REQUESTS`, `GEEKNOSY_MAX_DOMAINS_PER_JOB` y `GEEKNOSY_MAX_RESPONSE_BYTES`.

No publiques `.env`, claves API, secretos de webhook ni perfiles de credenciales.

## 6. Modos de evaluación

### Pasivo

Disponible en el stack base. Recolecta evidencia pública HTTP, TLS y DNS, revisa cabeceras, cookies, CORS, CSP, exposición de configuración, tecnología observable y dependencias JavaScript. No intenta explotar vulnerabilidades.

### Autorizado

Configura primero `.env` y levanta el worker separado:

```powershell
docker compose --profile authorized up --build -d authorized-worker
```

Requiere `GEEKNOSY_ALLOW_ACTIVE_CHECKS=true`, confirmación reforzada y `authorization_reference`. Las comprobaciones disponibles son reflexión controlada, redirección abierta, errores SQL, métodos HTTP peligrosos, CORS reflejado y CRLF. GeekNosy no ordena al objetivo contactar metadatos de nube, loopback o terceros para probar SSRF.

### Herramientas externas opcionales

```powershell
docker compose --profile authorized-tools run --rm zap -t https://tu-dominio.example
docker compose --profile authorized-tools run --rm nuclei -u https://tu-dominio.example
docker compose --profile authorized-tools run --rm testssl https://tu-dominio.example
```

Estas herramientas mantienen su propia política y nivel de intrusión. Revisa el alcance y sus argumentos antes de ejecutarlas.

## 7. API

Base: `http://localhost:3000/api`. En desarrollo, OpenAPI está disponible en `http://localhost:8000/docs`.

| Método | Ruta | Uso |
| --- | --- | --- |
| `GET` | `/api/health` | Salud del servicio |
| `GET` | `/api/info` | Capacidades y límites públicos |
| `POST/GET` | `/api/jobs` | Crear o listar trabajos |
| `GET` | `/api/jobs/{id}` | Progreso y resultado |
| `POST` | `/api/jobs/{id}/cancel` | Cancelación cooperativa |
| `POST` | `/api/jobs/{id}/retry` | Reintentar un trabajo |
| `GET/POST/PATCH/DELETE` | `/api/schedules` | Agenda recurrente |
| `GET` | `/api/scans` | Historial filtrable |
| `GET` | `/api/scans/{id}` | Evidencia del análisis |
| `GET/PATCH` | `/api/scans/{id}/findings` | Triage |
| `GET` | `/api/reports/{id}/{format}` | Exportación |
| `POST` | `/api/imports/nuclei/{scan_id}` | Importar Nuclei JSONL |

Formatos de reporte: `json`, `jsonl`, `csv`, `pdf`, `sarif`, `sbom`, `markdown` y `html`.

Ejemplo de trabajo pasivo:

```powershell
$headers = @{ 'Content-Type' = 'application/json'; 'X-API-Key' = 'TU_CLAVE' }
$body = @{
  request = @{
    domains = @('tu-dominio.example')
    authorization_confirmed = $true
    execution_mode = 'passive'
    mode = 'advanced'
    intensity = 'standard'
  }
} | ConvertTo-Json -Depth 5

$job = Invoke-RestMethod -Method Post -Uri 'http://localhost:3000/api/jobs' -Headers $headers -Body $body
Invoke-RestMethod "http://localhost:3000/api/jobs/$($job.id)" -Headers $headers
```

## 8. Desarrollo local

Backend, desde la raíz:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

El backend usa SQLite localmente si no se define `GEEKNOSY_DATABASE_URL`; el worker inline está activo por defecto para simplificar el desarrollo.

Frontend, en otra terminal:

```powershell
Set-Location frontend
corepack enable
pnpm install --frozen-lockfile
pnpm run dev
```

Interfaz: `http://localhost:5173`. Vite redirige `/api` a `http://localhost:8000`.

## 9. Pruebas y build

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m pytest -q

Set-Location ..\frontend
pnpm run build

Set-Location ..
docker compose config --quiet
docker compose build
```

## 10. Documentación complementaria

- [Capacidades y límites](docs/FEATURES.md)
- [Modelo de seguridad](docs/SECURITY.md)
- [Despliegue](docs/DEPLOYMENT.md)
- [API y automatización](docs/API.md)
- [Sistema visual](DESIGN.md)

## 11. Diagnóstico

| Problema | Qué revisar |
| --- | --- |
| Docker no responde | Abre Docker Desktop y espera a que `docker info` muestre el servidor |
| Puerto 3000 ocupado | Detén el servicio reconocido o cambia el puerto publicado |
| HTTP 502 | Salud y logs de `backend`; espera a PostgreSQL y al healthcheck |
| Trabajo sin avanzar | Logs de `worker` o `authorized-worker` según el modo |
| Objetivo bloqueado | Allowlist, puertos y política de destinos privados/reservados |
| Sin TLS o DNS | Resolución DNS, salida del contenedor y disponibilidad del objetivo |
| API 401 | `GEEKNOSY_API_KEYS` y cabecera `X-API-Key` |
