# GeekNosy: guía técnica

## 1. Requisitos y arquitectura

- Git y Docker Desktop con el motor Linux iniciado (en Windows, WSL 2).
- Puerto 3000 disponible y conexión a Internet para descargar imágenes y dependencias.
- Para evaluar dominios externos, el backend necesita salida HTTP/HTTPS y DNS.

Flujo: navegador → puerto 3000 → Nginx/React → `/api/` → FastAPI → SQLite.
El backend escucha en el puerto 8000 dentro de la red de Compose; no se publica directamente en Windows.

El nombre del proyecto es **GeekNosy**. Esta versión conserva identificadores heredados de DataGobs en la interfaz, metadatos de API y reportes, nombres de contenedores, base de datos y variables `DATAGOBS_`. No cambies estos últimos sin planificar la compatibilidad y la conservación de datos.

## 2. Descargar e iniciar con Docker

Si todavía no tienes el repositorio, ejecuta desde la carpeta donde quieras guardarlo:

```powershell
git clone https://github.com/FavinhoJR/GeekNosy.git
cd GeekNosy
```

En esta PC ya está descargado. Para iniciarlo desde PowerShell:

```powershell
Set-Location 'C:\Users\favio\OneDrive\Documentos\ChatGPT\GeekNosy'
docker info
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Abre **http://localhost:3000**. No hay inicio de sesión implementado.
El primer arranque puede tardar mientras se construyen las imágenes. El backend tiene un healthcheck periódico.

El Compose actual publica `3000:80` en todas las interfaces del equipo. Para uso exclusivamente local, cambia esa entrada a `127.0.0.1:3000:80` antes del arranque. No expongas esta instancia sin controles de acceso: la API permite iniciar evaluaciones, leer reportes y borrar registros sin autenticación.

## 3. Verificar y usar

Comprueba la web, la API y la comunicación a través de Nginx:

```powershell
(Invoke-WebRequest 'http://localhost:3000').StatusCode
Invoke-RestMethod 'http://localhost:3000/api/health'
Invoke-RestMethod 'http://localhost:3000/api/info'
Invoke-RestMethod 'http://localhost:3000/api/scans'
```

Resultado esperado: web HTTP 200, salud con `status: ok`, información de perfiles y listado de escaneos (vacío si aún no hay datos). El campo `tool` de salud conserva el nombre heredado DataGobs.

En el navegador:

1. Introduce un dominio propio o expresamente autorizado.
2. Empieza con modo Estándar, perfil Minimal y checks de exposición desactivados.
3. Pulsa **Iniciar escaneo** y espera la respuesta.
4. Busca el registro en **Escaneos Realizados** y abre **Detalle**.
5. Revisa la URL puntuada, hallazgos y evidencias; descarga JSON, CSV o PDF.
6. Repite con el mismo dominio para comprobar la comparación histórica.

No necesitas escanear un objetivo externo para verificar que la aplicación arranca. Para probar el motor usa un objetivo bajo tu control; `localhost` dentro del backend corresponde al contenedor, no al host Windows.

## 4. Apagar, consultar logs y actualizar

Ejecuta estos comandos desde la raíz del repositorio:

```powershell
# Estado y logs
docker compose ps
docker compose logs --tail 100 backend frontend

# Apagar conservando el historial
docker compose down

# Volver a encender
docker compose up -d

# Reconstruir después de cambios
docker compose up --build -d
```

Para actualizar el código, primero revisa `git status`, guarda o confirma tus cambios y luego ejecuta `git pull --ff-only` y reconstruye.

SQLite se guarda en `/app/data/datagobs.db`, dentro del volumen lógico `datagobs-data` (Compose normalmente lo crea como `geeknosy_datagobs-data`). `docker compose down` conserva ese volumen. **No uses `docker compose down -v` si necesitas conservar los escaneos: elimina el volumen y su historial.**

## 5. Configuración

No se necesita un archivo `.env` para el arranque Docker actual. Compose define `DATAGOBS_DATABASE_URL=sqlite+aiosqlite:////app/data/datagobs.db`.

`backend/app/config.py` admite estas variables de entorno, con prefijo `DATAGOBS_`:

| Variable | Valor predeterminado del código |
| --- | --- |
| `DATAGOBS_DATABASE_URL` | `sqlite+aiosqlite:///./data/datagobs.db` |
| `DATAGOBS_SCAN_TIMEOUT` | `15.0` segundos |
| `DATAGOBS_PATH_TIMEOUT` | `8.0` segundos |
| `DATAGOBS_PATH_RATE_LIMIT_MS` | `250` milisegundos |
| `DATAGOBS_MAX_REDIRECTS` | `5` |
| `DATAGOBS_MAX_PATHS_PER_DOMAIN_DEFAULT` | `40` |
| `DATAGOBS_MAX_BODY_PREVIEW` | `8192` |
| `DATAGOBS_DATA_DIR` | `./data` |
| `DATAGOBS_USER_AGENT` | Identificador heredado definido en `config.py` |

En Docker agrega los ajustes al bloque `environment` del servicio backend y recrea con `docker compose up -d`. Un `.env` de Compose no pasa automáticamente todas sus variables al contenedor: debes referenciarlas en `environment` o usar `env_file`. No publiques secretos.

El esquema de la petición define su propio valor predeterminado de 40 rutas; para variar una evaluación usa `max_paths_per_domain`.

## 6. Perfiles y puntuación

Los perfiles combinan rutas base, tecnología detectada y rutas personalizadas. La lista declarada se consulta en `GET /api/info` y en `backend/app/route_profiles.py`.

| `route_profile` | Selección |
| --- | --- |
| `minimal` | Rutas core |
| `auto` / `standard` | Core y perfiles según tecnología detectada |
| `advanced` | Core, common, tecnología y rutas API cuando aplica |
| `all` | Todos los perfiles generales, con el límite configurado |

Perfiles internos: `core`, `common`, `wordpress`, `joomla`, `drupal`, `laravel_php`, `django_python`, `node_frontend`, `aspnet_iis`, `api_docs` y `exposure_checks`.

- `custom_paths`: rutas adicionales, normalizadas y sin duplicados.
- `include_default_paths`: activa las rutas predeterminadas.
- `include_exposure_checks`: agrega checks sensibles cuando las rutas predeterminadas están activas. Estas rutas usan HEAD para inspeccionar metadatos, sin descargar su contenido.
- `max_paths_per_domain`: de 1 a 120, predeterminado 40. La fase inicial core y comprobaciones complementarias pueden producir solicitudes adicionales; no es un límite global de peticiones de red.

| Modo | Ponderación |
| --- | --- |
| `standard` | TLS 45 %, cabeceras 55 % |
| `advanced` | TLS 30 %, cabeceras 40 %, cookies 10 %, DNS 10 %, consistencia 10 % |

El componente TLS se ajusta según la redirección HTTP → HTTPS. La nota va de 1 a 10 a partir del puntaje 0–100. El motor prioriza la raíz con respuesta 200; si no la obtiene, aplica alternativas de selección. Revisa `scoring_url`, `scoring_http_code` y las evidencias antes de interpretar el resultado. Las respuestas 403/404 también se reportan individualmente.

## 7. API

Base local a través de Nginx: `http://localhost:3000/api`.

| Método | Ruta | Función |
| --- | --- | --- |
| GET | `/api/health` | Estado del servicio |
| GET | `/api/info` | Opciones, perfiles y metadatos |
| POST | `/api/scan` | Evaluar uno o varios dominios |
| GET | `/api/scans` | Listar; filtros `search`, `grade`, `comparison_status` |
| GET | `/api/scans/{id}` | Detalle |
| GET | `/api/scans/{id}/history` | Historial del dominio |
| DELETE | `/api/scans/{id}` | Eliminar un registro |
| GET | `/api/reports/{id}/json` | Reporte JSON |
| GET | `/api/reports/{id}/csv` | Reporte CSV |
| GET | `/api/reports/{id}/pdf` | Reporte PDF |

Ejemplo PowerShell: reemplaza el dominio reservado por uno que tengas autorización para evaluar.

```powershell
$body = @{
    domains = @('tu-dominio.example')
    institution = 'Validación local'
    mode = 'standard'
    route_profile = 'minimal'
    include_default_paths = $true
    include_exposure_checks = $false
    max_paths_per_domain = 10
    custom_paths = @()
} | ConvertTo-Json

$resultado = Invoke-RestMethod -Method Post `
    -Uri 'http://localhost:3000/api/scan' `
    -ContentType 'application/json' -Body $body -TimeoutSec 180

$id = $resultado[0].id
Invoke-RestMethod "http://localhost:3000/api/scans/$id"
Invoke-WebRequest "http://localhost:3000/api/reports/$id/json" -OutFile "reporte-$id.json"
Invoke-WebRequest "http://localhost:3000/api/reports/$id/csv" -OutFile "reporte-$id.csv"
Invoke-WebRequest "http://localhost:3000/api/reports/$id/pdf" -OutFile "reporte-$id.pdf"
```

Las evaluaciones se procesan dentro de la petición HTTP. Nginx tiene `proxy_read_timeout 120s`; si aparece un 504, revisa los logs y el historial antes de repetir el escaneo. Ampliar el timeout del cliente no modifica el timeout del proxy.

Reporte ilustrativo: [examples/sample-report.json](examples/sample-report.json). No es evidencia de una evaluación ejecutada en esta PC.

## 8. Desarrollo sin Docker (PowerShell)

Requiere Python 3.11 o superior y Node.js con npm; el Dockerfile del frontend usa Node 22.

Terminal 1, desde la raíz:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Terminal 2, desde la raíz:

```powershell
cd frontend
npm install
npm run dev
```

Interfaz: http://localhost:5173. Vite redirige `/api` a `localhost:8000`. Documentación interactiva del backend: http://localhost:8000/docs. La carpeta de datos se crea al cargar la configuración.

## 9. Estructura y diagnóstico

```text
GeekNosy/
├── backend/          # FastAPI, scanner, modelos y SQLite
├── frontend/         # React, Vite, Tailwind y Nginx
├── examples/         # Reporte ilustrativo
├── scripts/          # Script heredado de publicación inicial
├── docker-compose.yml
├── AGENTS.md
├── README.md
└── GUIA_TECNICA.md
```

No uses `scripts/publicar-github.ps1` para actualizar este clon: es un script heredado para crear un repositorio DataGobs. Aquí ya existe `origin` apuntando a GeekNosy.

| Problema | Qué revisar |
| --- | --- |
| Error `dockerDesktopLinuxEngine` | Abre Docker Desktop y espera a que `docker info` responda |
| Puerto 3000 ocupado | `Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue`; detén el servicio que reconozcas o cambia el puerto publicado |
| HTTP 502 | Estado y logs del backend; espera a que termine el arranque |
| HTTP 504 | Tiempo de evaluación, rutas, conectividad y logs; consulta el historial |
| Sin resultados de TLS/DNS | Acceso del contenedor al objetivo, DNS y disponibilidad del sitio |
| Historial vacío tras cambiar de carpeta/proyecto Compose | Verifica qué volumen está montado con `docker inspect datagobs-backend --format '{{json .Mounts}}'` |
