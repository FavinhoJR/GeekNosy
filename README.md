# GeekNosy

**GeekNosy** es una herramienta de evaluación defensiva de la configuración pública de seguridad web. Ayuda a identificar oportunidades de mejora, consultar evidencias y dar seguimiento a los resultados de sitios propios o autorizados.

## Qué permite hacer

- Revisar aspectos de HTTPS/TLS, cabeceras de seguridad, cookies y DNS.
- Evaluar rutas públicas y observar diferencias entre sus respuestas.
- Consultar hallazgos, recomendaciones y una calificación orientativa.
- Mantener un historial y comparar evaluaciones de un mismo dominio.
- Exportar resultados para su revisión y documentación.

## Uso general

1. Accede a la interfaz web de GeekNosy.
2. Introduce uno o varios dominios que tengas autorización para evaluar.
3. Selecciona las opciones de evaluación e inicia el escaneo.
4. Revisa los resultados, las evidencias y las recomendaciones.
5. Consulta el historial o exporta un reporte para dar seguimiento a las mejoras.

La herramienta realiza solicitudes de red a los objetivos. Su alcance es la configuración pública observable; los resultados no equivalen a una auditoría completa ni garantizan la ausencia de vulnerabilidades. No incluye explotación, fuerza bruta ni bypass de controles.

## Instalación y documentación

Consulta la [guía técnica](GUIA_TECNICA.md) para los requisitos, el arranque con Docker, la validación local, la configuración, los perfiles de evaluación y la referencia de API.

## Autor y licencia

**Autor:** [Favio Urrea (@FavinhoJR)](https://github.com/FavinhoJR).

**Licencia:** [MIT](LICENSE).
