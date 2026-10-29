# Despliegue con Docker

## Requisitos

- Docker Engine 24+ o Docker Desktop actual.
- Docker Compose v2.
- 2 GB de RAM disponibles para el stack base.

No es necesario instalar Python, Node, pnpm ni PostgreSQL en el host. Las imágenes instalan y fijan las dependencias requeridas durante el build.

## Stack base

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Servicios:

- `frontend`: Nginx y aplicación React en el puerto 3000;
- `backend`: FastAPI, accesible solo desde la red de Compose;
- `worker`: procesa exclusivamente trabajos pasivos;
- `postgres`: persistencia de trabajos, hallazgos y agenda.

## Configuración mínima recomendada

Cambie `GEEKNOSY_POSTGRES_PASSWORD` y `GEEKNOSY_API_KEYS`. Limite `GEEKNOSY_ALLOWED_DOMAINS` cuando el despliegue pertenezca a un programa o cliente específico. Mantenga `GEEKNOSY_ALLOW_PRIVATE_TARGETS=false` salvo en un entorno de laboratorio aislado.

## Perfil autorizado

```bash
docker compose --profile authorized up --build -d authorized-worker
```

El worker base nunca reclama trabajos autorizados; el worker autorizado nunca reclama trabajos pasivos. Esta separación evita que un cambio en la interfaz amplíe silenciosamente la capacidad del servicio base.

## Herramientas externas opcionales

Las imágenes se descargan solo al invocarlas:

```bash
docker compose --profile authorized-tools run --rm zap -t https://example.com
docker compose --profile authorized-tools run --rm nuclei -u https://example.com
docker compose --profile authorized-tools run --rm testssl https://example.com
```

Revise siempre el scope y los argumentos propios de cada herramienta. GeekNosy no hereda ni controla automáticamente su nivel de intrusión.

## Actualización y respaldo

```bash
docker compose pull
docker compose build --pull
docker compose up -d
docker compose exec postgres pg_dump -U geeknosy geeknosy > geeknosy-backup.sql
```

Los volúmenes `geeknosy-postgres` y `geeknosy-data` conservan estado entre reinicios.
