"""Low-impact checks restricted to the isolated authorized worker.

These probes use unique markers, one request per check and no destructive payloads.
They report observable behavior, never exploitability.
"""

import hashlib
import json
import re
import secrets
from urllib.parse import urlencode

from app.scanner.http_scanner import build_base_url, fetch_path, normalize_domain


def _finding(
    check_id: str,
    title: str,
    severity: str,
    confidence: str,
    evidence: dict,
    recommendation: str,
    references: list[str],
) -> dict:
    fingerprint = hashlib.sha256(
        json.dumps([check_id, evidence.get("url"), evidence.get("matcher")], sort_keys=True).encode()
    ).hexdigest()
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "intrusiveness": "authorized-low-impact",
        "version": "1.0.0",
        "recommendation": recommendation,
        "references": references,
        "evidence": evidence,
        "fingerprint": fingerprint,
        "template_hash": "builtin-authorized",
    }


async def run_authorized_checks(
    domain: str,
    checks: list[str],
    *,
    request_headers: dict[str, str] | None = None,
    requests_per_second: float | None = None,
) -> list[dict]:
    if not checks:
        return []
    host = normalize_domain(domain)
    base = build_base_url(domain).rstrip("/") + "/"
    marker = f"geeknosy-{secrets.token_hex(6)}"
    findings: list[dict] = []

    if "cors" in checks:
        probe_origin = f"https://{marker}.example.invalid"
        result = await fetch_path(
            base,
            path="/ [Origin probe]",
            profile="authorized",
            capture_body_preview=False,
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers={**(request_headers or {}), "Origin": probe_origin},
        )
        headers = result.get("headers") or {}
        if headers.get("access-control-allow-origin") == probe_origin:
            findings.append(
                _finding(
                    "cors_origin_reflection",
                    "CORS refleja un origen no confiable",
                    "high" if headers.get("access-control-allow-credentials", "").lower() == "true" else "medium",
                    "high",
                    {"url": base, "matcher": "origin-reflection", "credentials": headers.get("access-control-allow-credentials")},
                    "Valide una allowlist exacta y envíe Vary: Origin cuando la respuesta dependa del origen.",
                    ["CWE-942", "OWASP-A05:2021", "OWASP-ASVS-4.2"],
                )
            )

    if "reflection" in checks:
        url = f"{base}?{urlencode({'geeknosy_probe': marker})}"
        result = await fetch_path(
            url,
            path="/?geeknosy_probe=[marker]",
            profile="authorized",
            capture_body_preview=True,
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers=request_headers,
        )
        if marker in (result.get("body_preview") or ""):
            findings.append(
                _finding(
                    "input_reflected_unencoded",
                    "Entrada de prueba reflejada en la respuesta",
                    "medium",
                    "medium",
                    {"url": base, "matcher": "unique-marker-reflection"},
                    "Aplique codificación contextual de salida y valide el contexto DOM antes de clasificarlo como XSS.",
                    ["CWE-79", "OWASP-A03:2021", "OWASP-ASVS-5.3"],
                )
            )

    if "open_redirect" in checks:
        destination = f"https://example.invalid/{marker}"
        url = f"{base}?{urlencode({'next': destination, 'redirect': destination, 'url': destination})}"
        result = await fetch_path(
            url,
            path="/?next=[external-marker]",
            profile="authorized",
            follow_redirects=False,
            capture_body_preview=False,
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers=request_headers,
        )
        location = (result.get("headers") or {}).get("location", "")
        if destination in location:
            findings.append(
                _finding(
                    "open_redirect_observed",
                    "Redirección externa controlable observada",
                    "medium",
                    "high",
                    {"url": base, "matcher": "location-external-marker"},
                    "Valide destinos contra una allowlist y utilice identificadores internos en vez de URLs aportadas por el usuario.",
                    ["CWE-601", "OWASP-A01:2021", "OWASP-ASVS-5.5"],
                )
            )

    if "sql_error" in checks:
        query = urlencode({"id": "1'"})
        url = f"{base}?{query}"
        result = await fetch_path(
            url,
            path="/?id=[quote-marker]",
            profile="authorized",
            capture_body_preview=True,
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers=request_headers,
        )
        body = result.get("body_preview") or ""
        if re.search(r"sql syntax|postgresql.*error|sqlite.*error|ora-\d{4,5}|odbc sql", body, re.I):
            findings.append(
                _finding(
                    "database_error_disclosure",
                    "Mensaje de error de base de datos expuesto",
                    "high",
                    "medium",
                    {"url": base, "matcher": "database-error-signature"},
                    "Use consultas parametrizadas y respuestas de error genéricas; confirme manualmente sin ampliar el payload.",
                    ["CWE-89", "CWE-209", "OWASP-A03:2021", "OWASP-ASVS-5.3"],
                )
            )

    if "dangerous_methods" in checks:
        result = await fetch_path(
            base,
            path="/ [OPTIONS]",
            profile="authorized",
            follow_redirects=False,
            method="OPTIONS",
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers=request_headers,
        )
        allow = (result.get("headers") or {}).get("allow", "")
        risky = sorted({m for m in re.split(r"\s*,\s*", allow.upper()) if m in {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}})
        if risky:
            findings.append(
                _finding(
                    "dangerous_http_methods_advertised",
                    "Métodos HTTP de riesgo anunciados",
                    "medium",
                    "medium",
                    {"url": base, "matcher": "options-allow", "methods": risky},
                    "Deshabilite métodos no utilizados y aplique autorización por recurso; valide manualmente antes de probarlos.",
                    ["CWE-749", "OWASP-ASVS-4.1"],
                )
            )

    if "crlf" in checks:
        url = f"{base}?geeknosy_probe={marker}%0D%0AX-GeekNosy-Probe:%20{marker}"
        result = await fetch_path(
            url,
            path="/?geeknosy_probe=[crlf-marker]",
            profile="authorized",
            follow_redirects=False,
            authorized_host=host,
            requests_per_second=requests_per_second,
            request_headers=request_headers,
        )
        if (result.get("headers") or {}).get("x-geeknosy-probe") == marker:
            findings.append(
                _finding(
                    "crlf_response_splitting_observed",
                    "Inyección CRLF observada en cabeceras",
                    "high",
                    "high",
                    {"url": base, "matcher": "response-header-marker"},
                    "Rechace CR/LF antes de construir cabeceras y use APIs de framework que validen sus valores.",
                    ["CWE-113", "OWASP-A03:2021", "OWASP-ASVS-5.5"],
                )
            )

    return findings
