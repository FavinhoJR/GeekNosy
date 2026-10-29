# Capacidades de GeekNosy

GeekNosy reúne evidencia pública, normaliza hallazgos y conserva suficiente contexto para que una persona pueda validar y priorizar. No afirma explotabilidad automáticamente.

## Núcleo pasivo

- TLS: certificado, SAN, emisor, vigencia, cipher, ALPN y soporte TLS 1.0–1.3.
- HTTP: redirección a HTTPS, estado, cadena de redirección, límites de respuesta y consistencia entre rutas.
- Cabeceras: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP y CORP.
- CSP semántica: `unsafe-inline`, `unsafe-eval`, comodines y ausencia de `default-src`.
- CORS: combinaciones inseguras de comodín/credenciales y origen `null` cuando aparecen en la respuesta.
- HSTS: evaluación de directivas necesarias para preload. Esto no sustituye consultar la lista oficial de preload.
- Recursos externos: detección de scripts y hojas de estilo sin SRI.
- Cookies: Secure, HttpOnly, SameSite, prefijos `__Host-`/`__Secure-`, Path, Domain y duración excesiva.
- Caché: respuestas sensibles sin `no-store` o `private`.
- Contenido público: source maps, listados de directorio, versiones de servidor, patrones de secretos redactados y configuraciones expuestas.
- JavaScript del mismo origen: hasta seis bundles públicos por objetivo en perfiles estándar o superiores; el contenido no se conserva.
- Inventario de librerías por nombre de archivo y enriquecimiento opcional con OSV. Al habilitarlo, solo se envían nombre y versión públicos a `api.osv.dev`.
- DNS y correo: A/AAAA, CNAME, MX, NS, CAA, SPF, DMARC, DNSKEY y búsqueda informativa de selectores DKIM comunes.
- CNAME de terceros: señal informativa para revisión de propiedad; nunca se reporta como takeover confirmado solo por existir.
- Rutas inteligentes: perfiles por tecnología, rutas personalizadas, crawling limitado al mismo origen y consultas HEAD para recursos sensibles.

## Modo autorizado de bajo impacto

Solo el worker del perfil Docker `authorized` puede ejecutarlo. Requiere:

1. confirmación general de autorización;
2. referencia de ticket, contrato o scope;
3. segunda confirmación del modo reforzado;
4. `GEEKNOSY_ALLOW_ACTIVE_CHECKS=true` en el worker aislado.

Checks disponibles:

- reflexión de marcador único, sin payload ejecutable;
- redirección externa hacia `example.invalid`;
- divulgación de errores SQL mediante una comilla aislada;
- consulta OPTIONS para métodos anunciados, sin ejecutar PUT/DELETE.
- reflexión CORS con un origen reservado `example.invalid`;
- inyección CRLF con un marcador propio en una cabecera de respuesta.

Las credenciales no se pegan en la web. El operador solicita un nombre de perfil y el worker resuelve el header desde `GEEKNOSY_AUTH_PROFILES_JSON` en memoria.

## Operación y automatización

- Cola PostgreSQL con progreso, cancelación, reintentos y separación por propietario/API key.
- Trabajos multi-dominio con límites por política.
- Programación recurrente por intervalo.
- Webhooks firmados al finalizar.
- Triage: nuevo, confirmado, falso positivo, aceptado o resuelto.
- Historial y diferencias de puntuación por dominio.
- CLI y API OpenAPI.
- Plantillas YAML versionadas y opcionalmente firmadas.
- Política YAML para límites, modos y checks autorizados.

## Reportes

JSON, JSONL, CSV, PDF, SARIF 2.1, Markdown, HTML y SBOM CycloneDX parcial de componentes JavaScript observados. Los hallazgos detallados incluyen severidad, confianza, evidencia mínima, recomendación y referencias. Los mapeos cubren OWASP Top 10, OWASP ASVS, PCI DSS, SOC 2 y NIST CSF cuando aplican; son ayudas de clasificación, no certificaciones de cumplimiento.

## Integraciones opcionales

GeekNosy no ejecuta plantillas comunitarias automáticamente. El perfil `authorized-tools` expone imágenes de ZAP Baseline, Nuclei y testssl.sh para que el operador las invoque con su propia política. Los resultados JSONL de Nuclei pueden importarse para normalización, deduplicación, triage y SARIF.
