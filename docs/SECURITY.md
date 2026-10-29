# Seguridad, alcance y autorización

## Modelo seguro por defecto

El stack base solo procesa trabajos pasivos. Bloquea loopback, redes privadas, link-local, multicast, direcciones reservadas, esquemas distintos de HTTP(S), credenciales embebidas en URLs y puertos no permitidos. Cada salto de redirección se vuelve a resolver y debe permanecer en el host autorizado.

Los límites de concurrencia, velocidad, tiempo, redirecciones y bytes de respuesta se aplican en el cliente de red. Las rutas de exposición usan HEAD y nunca descargan el cuerpo. Cookies, headers de autorización y coincidencias de secretos no se almacenan con su valor.

## Perfil autorizado

Inicie el worker únicamente durante una ventana aprobada:

```bash
docker compose --profile authorized up -d authorized-worker
```

Antes debe configurar en `.env`:

```dotenv
GEEKNOSY_ALLOW_ACTIVE_CHECKS=true
GEEKNOSY_ALLOWED_DOMAINS=staging.example.com
GEEKNOSY_AUTHORIZED_ALLOW_PRIVATE_TARGETS=false
GEEKNOSY_AUTH_PROFILES_JSON={"staging":{"header":"Authorization","value":"Bearer replace-me"}}
```

Deténgalo al finalizar:

```bash
docker compose --profile authorized stop authorized-worker
```

No incluya secretos reales en archivos versionados. En producción, inyecte `GEEKNOSY_AUTH_PROFILES_JSON` desde el gestor de secretos de la plataforma.

## Lo que GeekNosy no hace

- fuerza bruta, password spraying o credential stuffing;
- explotación destructiva, persistencia, evasión o bypass de WAF;
- SQL injection de extracción, XSS ejecutable o escritura de archivos;
- pruebas SSRF que ordenen al objetivo contactar loopback, metadata cloud o terceros;
- confirmación automática de takeover;
- escaneo de puertos general.

## Reporte responsable

Para vulnerabilidades en GeekNosy, abra un aviso privado de seguridad en GitHub si está disponible. No adjunte credenciales, datos personales ni evidencia de terceros sin autorización.
