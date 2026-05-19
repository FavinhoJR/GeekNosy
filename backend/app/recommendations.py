"""Recomendaciones técnicas por hallazgo."""

RECOMMENDATIONS: dict[str, dict] = {
    "ssl_invalid": {
        "title": "Certificado SSL inválido o no confiable",
        "recommendation": "Instale un certificado válido emitido por una CA reconocida. Verifique la cadena completa y que el dominio coincida con el CN/SAN.",
        "severity": "critical",
    },
    "ssl_expiring_soon": {
        "title": "Certificado próximo a expirar",
        "recommendation": "Renueve el certificado antes de la fecha de expiración. Configure alertas automáticas a 30 días.",
        "severity": "high",
    },
    "no_https_redirect": {
        "title": "Sin redirección HTTP a HTTPS",
        "recommendation": "Configure redirección 301 permanente de http:// a https:// en el servidor web o balanceador.",
        "severity": "high",
    },
    "missing_hsts": {
        "title": "Falta Strict-Transport-Security (HSTS)",
        "recommendation": 'Agregue: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        "severity": "high",
    },
    "missing_csp": {
        "title": "Falta Content-Security-Policy",
        "recommendation": "Defina una política CSP restrictiva. Comience con default-src 'self' y refine según recursos necesarios.",
        "severity": "high",
    },
    "missing_x_frame_options": {
        "title": "Falta X-Frame-Options",
        "recommendation": "Agregue X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking.",
        "severity": "medium",
    },
    "missing_x_content_type_options": {
        "title": "Falta X-Content-Type-Options",
        "recommendation": "Agregue X-Content-Type-Options: nosniff para evitar MIME sniffing.",
        "severity": "medium",
    },
    "missing_referrer_policy": {
        "title": "Falta Referrer-Policy",
        "recommendation": "Agregue Referrer-Policy: strict-origin-when-cross-origin o no-referrer según necesidad.",
        "severity": "low",
    },
    "missing_permissions_policy": {
        "title": "Falta Permissions-Policy",
        "recommendation": "Restrinja APIs del navegador: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "severity": "low",
    },
    "missing_x_xss_protection": {
        "title": "Falta X-XSS-Protection",
        "recommendation": "Agregue X-XSS-Protection: 0 (recomendado en navegadores modernos con CSP) o 1; mode=block.",
        "severity": "low",
    },
    "missing_coop": {
        "title": "Falta Cross-Origin-Opener-Policy",
        "recommendation": "Agregue Cross-Origin-Opener-Policy: same-origin para aislar el contexto de navegación.",
        "severity": "medium",
    },
    "missing_coep": {
        "title": "Falta Cross-Origin-Embedder-Policy",
        "recommendation": "Agregue Cross-Origin-Embedder-Policy: require-corp si requiere aislamiento cross-origin.",
        "severity": "medium",
    },
    "missing_corp": {
        "title": "Falta Cross-Origin-Resource-Policy",
        "recommendation": "Agregue Cross-Origin-Resource-Policy: same-origin para controlar carga cross-origin.",
        "severity": "medium",
    },
    "server_header_exposed": {
        "title": "Cabecera Server expuesta",
        "recommendation": "Oculte o genere la cabecera Server para no revelar versión del software.",
        "severity": "low",
    },
    "x_powered_by_exposed": {
        "title": "Cabecera X-Powered-By expuesta",
        "recommendation": "Elimine X-Powered-By en la configuración del framework (PHP, ASP.NET, etc.).",
        "severity": "low",
    },
    "cookie_no_secure": {
        "title": "Cookie sin flag Secure",
        "recommendation": "Establezca el flag Secure en todas las cookies transmitidas por HTTPS.",
        "severity": "high",
    },
    "cookie_no_httponly": {
        "title": "Cookie sin flag HttpOnly",
        "recommendation": "Establezca HttpOnly en cookies de sesión para prevenir acceso desde JavaScript.",
        "severity": "high",
    },
    "cookie_no_samesite": {
        "title": "Cookie sin SameSite",
        "recommendation": "Use SameSite=Lax o Strict según el caso de uso CSRF.",
        "severity": "medium",
    },
    "no_dns_caa": {
        "title": "Sin registro DNS CAA",
        "recommendation": "Publique registros CAA para restringir qué CAs pueden emitir certificados para su dominio.",
        "severity": "medium",
    },
    "no_security_txt": {
        "title": "No se encontró security.txt",
        "recommendation": "Publique /.well-known/security.txt según RFC 9116 con contacto de seguridad.",
        "severity": "low",
    },
    "tls12_unsupported": {
        "title": "TLS 1.2 no soportado",
        "recommendation": "Habilite TLS 1.2 como mínimo en la configuración del servidor.",
        "severity": "high",
    },
    "tls13_unsupported": {
        "title": "TLS 1.3 no soportado",
        "recommendation": "Habilite TLS 1.3 para mejor rendimiento y seguridad.",
        "severity": "medium",
    },
    "blocked_page_inconsistency": {
        "title": "Inconsistencia en página bloqueada (403)",
        "recommendation": "Las respuestas 403 deben incluir las mismas cabeceras de seguridad que el sitio principal.",
        "severity": "medium",
    },
    "error_page_inconsistency": {
        "title": "Inconsistencia en página de error (404)",
        "recommendation": "Las páginas 404 deben mantener cabeceras de seguridad consistentes con respuestas 200.",
        "severity": "medium",
    },
    "weak_hsts_max_age": {
        "title": "HSTS con max-age bajo",
        "recommendation": "Use max-age de al menos 31536000 (1 año) en Strict-Transport-Security.",
        "severity": "medium",
    },
}


def get_recommendations(finding_ids: list[str]) -> list[dict]:
    result = []
    for fid in finding_ids:
        if fid in RECOMMENDATIONS:
            result.append({"id": fid, **RECOMMENDATIONS[fid]})
    return result
