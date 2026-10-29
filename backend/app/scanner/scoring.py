"""Sistema de ponderación estándar y avanzado."""

import math

from app.config import (
    ADVANCED_HEADER_POINTS,
    HEADER_POINTS,
    SECURITY_HEADERS,
)


def score_to_grade(score: float) -> int:
    """Convierte puntaje 0-100 a nota 1-10 (10 = más alta, 1 = más baja)."""
    if score <= 0:
        return 1
    return max(1, min(10, math.ceil(score / 10)))


def check_header_present(headers: dict, header_name: str) -> bool:
    return header_name.lower() in headers


def score_headers(headers: dict, mode: str = "standard") -> tuple[float, list[str], dict]:
    """Puntaje de headers 0-100 basado en puntos ponderados."""
    points_map = ADVANCED_HEADER_POINTS if mode == "advanced" else HEADER_POINTS
    max_points = sum(points_map.values())
    earned = 0.0
    findings: list[str] = []
    checks: dict[str, bool] = {}

    header_finding_map = {
        "strict-transport-security": "missing_hsts",
        "content-security-policy": "missing_csp",
        "x-frame-options": "missing_x_frame_options",
        "x-content-type-options": "missing_x_content_type_options",
        "referrer-policy": "missing_referrer_policy",
        "permissions-policy": "missing_permissions_policy",
        "x-xss-protection": "missing_x_xss_protection",
        "cross-origin-opener-policy": "missing_coop",
        "cross-origin-embedder-policy": "missing_coep",
        "cross-origin-resource-policy": "missing_corp",
    }

    for header, points in points_map.items():
        present = check_header_present(headers, header)
        checks[header] = present
        if present:
            earned += points
            if header == "strict-transport-security":
                hsts = headers.get("strict-transport-security", "")
                if "max-age=" in hsts.lower():
                    try:
                        max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
                        if max_age < 31536000:
                            findings.append("weak_hsts_max_age")
                    except ValueError:
                        pass
        else:
            fid = header_finding_map.get(header)
            if fid:
                findings.append(fid)

    if "server" in headers:
        findings.append("server_header_exposed")
    if "x-powered-by" in headers:
        findings.append("x_powered_by_exposed")

    score = (earned / max_points * 100) if max_points > 0 else 0
    return score, findings, checks


def score_cookies(cookies: list[dict]) -> tuple[float, list[str]]:
    if not cookies:
        return 100.0, []

    findings: list[str] = []
    total_checks = len(cookies) * 3
    passed = 0

    for cookie in cookies:
        if cookie.get("secure"):
            passed += 1
        else:
            findings.append("cookie_no_secure")
        if cookie.get("httponly"):
            passed += 1
        else:
            findings.append("cookie_no_httponly")
        if cookie.get("samesite"):
            passed += 1
        else:
            findings.append("cookie_no_samesite")

    score = (passed / total_checks * 100) if total_checks > 0 else 100
    return score, list(set(findings))


def score_consistency(results: list[dict], main_headers: dict) -> tuple[float, list[str]]:
    """Evalúa consistencia de headers en 403/404 vs sitio principal."""
    findings: list[str] = []
    if not main_headers:
        return 50.0, findings

    main_security = {h for h in SECURITY_HEADERS if h in main_headers}
    if not main_security:
        return 50.0, findings

    blocked = [r for r in results if r.get("response_type") == "blocked"]
    not_found = [r for r in results if r.get("response_type") == "not_found"]

    consistency_scores = []

    for r in blocked + not_found:
        rh = r.get("headers", {})
        if r.get("http_code") in (403, 404) and not rh:
            if r.get("response_type") == "blocked":
                findings.append("blocked_page_inconsistency")
                r["notes"] = "Inconsistencia en página bloqueada: sin cabeceras de seguridad"
            else:
                findings.append("error_page_inconsistency")
                r["notes"] = "Inconsistencia en página de error: sin cabeceras de seguridad"
            consistency_scores.append(0)
            continue

        present = {h for h in SECURITY_HEADERS if h in rh}
        if main_security:
            ratio = len(present & main_security) / len(main_security)
            consistency_scores.append(ratio * 100)
            if ratio < 0.5:
                if r.get("response_type") == "blocked":
                    findings.append("blocked_page_inconsistency")
                else:
                    findings.append("error_page_inconsistency")

    if not consistency_scores:
        return 100.0, findings

    return sum(consistency_scores) / len(consistency_scores), list(set(findings))


def compute_overall_score(
    mode: str,
    tls_score: float,
    headers_score: float,
    cookies_score: float = 0,
    dns_score: float = 0,
    consistency_score: float = 0,
    https_redirect: bool = False,
) -> float:
    """Calcula puntaje global según modo."""
    tls_adjusted = tls_score
    if https_redirect:
        tls_adjusted = min(100, tls_score + 10)
    else:
        tls_adjusted = max(0, tls_score - 15)

    if mode == "standard":
        return round(tls_adjusted * 0.45 + headers_score * 0.55, 2)
    return round(
        tls_adjusted * 0.30
        + headers_score * 0.40
        + cookies_score * 0.10
        + dns_score * 0.10
        + consistency_score * 0.10,
        2,
    )


def build_score_explanation(
    current: float,
    previous: float | None,
    status: str,
    findings: list[str],
) -> str:
    parts = []
    if previous is not None:
        delta = round(current - previous, 2)
        if status == "greater":
            parts.append(f"Nota mayor: +{delta} puntos respecto al escaneo anterior ({previous}).")
        elif status == "less":
            parts.append(f"Nota menor: {delta} puntos respecto al escaneo anterior ({previous}).")
        else:
            parts.append(f"Nota igual al escaneo anterior ({previous}).")

    if findings:
        key_findings = findings[:5]
        parts.append(f"Hallazgos principales: {', '.join(key_findings)}.")
    return " ".join(parts) if parts else "Primer escaneo registrado para este dominio."
