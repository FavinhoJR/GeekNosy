# Instrucciones de desarrollo

Proyecto: GeekNosy (antes DataGobs).

- Responder en español, de forma clara, breve y práctica.
- Revisar la estructura y el flujo actual antes de modificar código.
- Mantener la arquitectura y el estilo existentes; aplicar cambios mínimos y seguros.
- No eliminar funcionalidades ni inventar dependencias, rutas o variables.
- Cuidar validaciones, errores, logs y seguridad. Usar variables de entorno para secretos.
- Avisar antes de operaciones riesgosas y preguntar solo por información crítica.
- Verificar los cambios con las comprobaciones apropiadas y resumir qué cambió, por qué, cómo probarlo y qué revisar si falla.

## Estructura e inicio local

- `backend/`: FastAPI y SQLite. Dependencias en `requirements.txt`.
- `frontend/`: React, Vite y Tailwind CSS 4 mediante `@tailwindcss/vite`. Tema en `src/index.css`; no restaurar la configuración PostCSS de Tailwind 3.
- Backend: desde `backend/`, ejecutar `.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000` después de preparar el entorno virtual e instalar dependencias.
- Frontend: desde `frontend/`, ejecutar `npm ci` y `npm run dev -- --host 127.0.0.1 --port 5173 --strictPort`.
- Vite redirige `/api` al backend en el puerto 8000. Salud: `/api/health`.
- Mantener los datos locales, entornos virtuales y secretos fuera de Git.
- Configuración: preferir `GEEKNOSY_`; conservar compatibilidad con `DATAGOBS_` y la base de datos anterior.
