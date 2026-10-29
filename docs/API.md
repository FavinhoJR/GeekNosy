# API y automatización

La especificación OpenAPI está disponible en `/docs` del backend durante desarrollo. Si `GEEKNOSY_API_KEYS` contiene valores, envíe `X-API-Key` en cada solicitud.

## Crear un trabajo pasivo

```bash
curl -X POST http://localhost:3000/api/jobs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"request":{"domains":["example.com"],"authorization_confirmed":true,"execution_mode":"passive","mode":"advanced","intensity":"standard"}}'
```

## Crear un trabajo autorizado

El perfil Docker `authorized` debe estar activo.

```json
{
  "request": {
    "domains": ["staging.example.com"],
    "authorization_confirmed": true,
    "execution_mode": "authorized",
    "active_authorization_confirmed": true,
    "authorization_reference": "BBP-2026-104",
    "credential_profile": "staging-readonly",
    "active_checks": ["reflection", "open_redirect"],
    "requests_per_second": 1
  }
}
```

## Endpoints principales

| Método | Ruta | Uso |
|---|---|---|
| `GET` | `/api/health` | Estado del servicio |
| `GET` | `/api/info` | Capacidades y límites públicos |
| `POST/GET` | `/api/jobs` | Crear o listar trabajos |
| `GET` | `/api/jobs/{id}` | Progreso y resultado |
| `POST` | `/api/jobs/{id}/cancel` | Cancelación cooperativa |
| `GET/POST/PATCH/DELETE` | `/api/schedules` | Agenda recurrente |
| `GET` | `/api/scans` | Historial filtrable |
| `GET` | `/api/scans/{id}` | Evidencia del análisis |
| `GET/PATCH` | `/api/scans/{id}/findings` | Triage |
| `GET` | `/api/reports/{id}/{format}` | Exportación |
| `POST` | `/api/imports/nuclei/{scan_id}` | Importar Nuclei JSONL |

Formatos: `json`, `jsonl`, `csv`, `pdf`, `sarif`, `sbom`, `markdown` y `html`.
