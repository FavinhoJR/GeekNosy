"""Análisis de hallazgos por ruta (complementario, no afecta nota global principal)."""

from app.config import ADVANCED_SECURITY_HEADERS, SECURITY_HEADERS
from app.route_profiles import CRITICAL_EXPOSURE_PATHS, EXPOSURE_PATHS
from app.scanner.route_selector import is_exposure_path, normalize_path


def _cookies_safe(cookies: list[dict]) -> list[dict]:
    """Cookies sin valores sensibles."""
    return [
        {
            "name": c.get("name", ""),
            "secure": c.get("secure", False),
            "httponly": c.get("httponly", False),
            "samesite": c.get("samesite"),
        }
        for c in cookies
    ]


def analyze_path_result(
    result: dict,
    mode: str = "standard",
    is_scoring_source: bool = False,
) -> dict:
    """
    Enriquece resultado de ruta con severity, finding_key y notas.
    No altera score global principal salvo is_scoring_source.
    """
    path = result.get("path", "/")
    http_code = result.get("http_code", 0)
    headers = result.get("headers", {})
    response_type = result.get("response_type", "unknown")
    profile = result.get("profile", "unknown")

    check_list = ADVANCED_SECURITY_HEADERS if mode == "advanced" else SECURITY_HEADERS
    missing = [h for h in check_list if h not in headers]
    present = [h for h in check_list if h in headers]

    severity = "info"
    finding_key = None
    notes = result.get("notes")

    if is_exposure_path(path):
        finding_key, severity = _analyze_exposure(path, http_code, result)
    elif response_type == "blocked" and not headers:
        severity = "medium"
        finding_key = "blocked_page_inconsistency"
        notes = notes or "Inconsistencia en página bloqueada: sin cabeceras de seguridad"
    elif response_type == "not_found" and not headers and http_code == 404:
        severity = "low"
        finding_key = "error_page_inconsistency"
        notes = notes or "Inconsistencia en página de error: sin cabeceras de seguridad"
    elif profile == "api_docs" and http_code == 200:
        severity = "low"
        finding_key = "api_docs_exposed"
    elif not is_scoring_source and http_code == 200 and len(missing) > 3:
        severity = "low"
        finding_key = "route_missing_security_headers"

    result["severity"] = severity
    result["finding_key"] = finding_key
    result["notes"] = notes
    result["missing_headers"] = missing
    result["present_headers"] = present
    result["cookies"] = _cookies_safe(result.get("cookies", []))
    result["is_scoring_source"] = is_scoring_source
    # No incluir cuerpo ni secretos en evidencia
    result["evidence"] = {
        "path": path,
        "profile": profile,
        "content_type": result.get("content_type"),
        "content_length": result.get("content_length"),
        "method": result.get("method", "GET"),
        "exposure_check": is_exposure_path(path),
        "severity": severity,
        "finding_key": finding_key,
    }
    return result


def _analyze_exposure(path: str, http_code: int, result: dict) -> tuple[str | None, str]:
    norm = normalize_path(path)
    if http_code == 200:
        if norm in CRITICAL_EXPOSURE_PATHS or norm.endswith(".env"):
            return "critical_exposure_public", "critical"
        return "sensitive_path_accessible", "high"
    if http_code in (401, 403):
        return "sensitive_path_protected", "info"
    if http_code == 404:
        return None, "info"
    if http_code in (301, 302, 303, 307, 308):
        return "sensitive_path_redirect", "medium"
    return None, "info"


def collect_supplementary_findings(results: list[dict]) -> list[str]:
    """Hallazgos de rutas complementarias (no scoring source)."""
    findings: list[str] = []
    for r in results:
        if r.get("is_scoring_source"):
            continue
        fk = r.get("finding_key")
        if fk and fk not in findings:
            findings.append(fk)
    return findings
