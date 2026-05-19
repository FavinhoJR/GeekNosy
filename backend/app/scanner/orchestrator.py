"""Orquestador de escaneo completo."""

import json
from datetime import datetime, timezone

from app.config import DEFAULT_PATHS
from app.recommendations import get_recommendations
from app.scanner.dns_scanner import scan_dns, score_dns
from app.scanner.http_scanner import (
    build_base_url,
    check_http_to_https_redirect,
    fetch_url,
    fetch_well_known,
)
from app.scanner.scoring import (
    build_score_explanation,
    compute_overall_score,
    score_consistency,
    score_cookies,
    score_headers,
    score_to_grade,
)
from app.scanner.tls_scanner import scan_tls, score_tls


def _select_scoring_source(results: list[dict]) -> dict | None:
    """Selecciona la URL que define la nota del sitio principal (prioriza / con 200)."""
    if not results:
        return None

    domain = results[0].get("_domain", "")
    root_url = build_base_url(domain).rstrip("/") + "/"

    for r in results:
        if r["http_code"] == 200 and r.get("path") in ("/", ""):
            return r

    for r in results:
        if r["http_code"] == 200 and r["response_type"] == "main":
            return r

    for r in results:
        if r["response_type"] == "redirect" and r["url_evaluated"].rstrip("/") in (
            root_url.rstrip("/"),
            build_base_url(domain).rstrip("/"),
        ):
            return r

    for r in results:
        if r["http_code"] == 200:
            return r

    return results[0]


async def run_full_scan(
    domain: str,
    mode: str = "standard",
    custom_paths: list[str] | None = None,
    include_default_paths: bool = True,
) -> dict:
    paths = []
    if include_default_paths:
        paths.extend(DEFAULT_PATHS)
    if custom_paths:
        paths.extend(custom_paths)
    # deduplicate preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    base = build_base_url(domain)
    http_results: list[dict] = []

    for path in unique_paths:
        url = base.rstrip("/") + (path if path.startswith("/") else f"/{path}")
        result = await fetch_url(url)
        result["_domain"] = domain
        result["path"] = path
        http_results.append(result)

    # TLS
    tls_evidence = await scan_tls(domain)
    tls_score, tls_findings = score_tls(tls_evidence)

    # HTTP redirect
    redirect_check = await check_http_to_https_redirect(domain)
    https_redirect = redirect_check.get("redirects_to_https", False)
    if not https_redirect:
        tls_findings.append("no_https_redirect")

    # DNS (solo advanced o siempre para evidencia)
    dns_evidence = await scan_dns(domain)
    dns_score, dns_findings = score_dns(dns_evidence)

    # Well-known files
    security_txt = await fetch_well_known(domain, "/.well-known/security.txt")
    robots_txt = await fetch_well_known(domain, "/robots.txt")
    sitemap = await fetch_well_known(domain, "/sitemap.xml")
    if not security_txt.get("found"):
        tls_findings.append("no_security_txt")

    # Seleccionar fuente de puntuación
    scoring_source = _select_scoring_source(http_results)
    all_findings: list[str] = list(tls_findings)

    headers_score = 0.0
    cookies_score = 100.0
    header_checks: dict = {}
    scoring_headers: dict = {}

    if scoring_source:
        scoring_headers = scoring_source.get("headers", {})
        headers_score, header_findings, header_checks = score_headers(scoring_headers, mode)
        all_findings.extend(header_findings)

        cookies = scoring_source.get("cookies", [])
        cookies_score, cookie_findings = score_cookies(cookies)
        all_findings.extend(cookie_findings)
        scoring_source["is_scoring_source"] = True

        # Score per-path (informativo, no define nota global excepto scoring source)
        for r in http_results:
            if r is scoring_source:
                r["score"] = 0  # se calcula después
                r["is_scoring_source"] = True
            else:
                hs, _, _ = score_headers(r.get("headers", {}), mode)
                r["score"] = round(hs, 2)
                r["grade"] = score_to_grade(hs)
                r["is_scoring_source"] = False
                if r["response_type"] == "blocked" and not r.get("headers"):
                    r["notes"] = "Inconsistencia en página bloqueada: sin cabeceras de seguridad"
                elif r["response_type"] == "not_found" and not r.get("headers"):
                    r["notes"] = "Inconsistencia en página de error: sin cabeceras de seguridad"
    else:
        for r in http_results:
            r["is_scoring_source"] = False

    consistency_score, consistency_findings = score_consistency(
        http_results, scoring_headers
    )
    all_findings.extend(consistency_findings)

    overall = compute_overall_score(
        mode=mode,
        tls_score=tls_score,
        headers_score=headers_score,
        cookies_score=cookies_score,
        dns_score=dns_score,
        consistency_score=consistency_score,
        https_redirect=https_redirect,
    )

    if scoring_source:
        scoring_source["score"] = overall
        scoring_source["grade"] = score_to_grade(overall)

    # Missing headers on scoring source
    from app.config import ADVANCED_SECURITY_HEADERS, SECURITY_HEADERS

    check_list = ADVANCED_SECURITY_HEADERS if mode == "advanced" else SECURITY_HEADERS
    missing = [h for h in check_list if h not in scoring_headers] if scoring_source else []

    grade = score_to_grade(overall)
    all_findings = list(dict.fromkeys(all_findings))  # unique preserve order

    return {
        "domain": domain,
        "mode": mode,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "overall_grade": grade,
        "scoring_url": scoring_source["url_evaluated"] if scoring_source else None,
        "scoring_http_code": scoring_source["http_code"] if scoring_source else None,
        "scoring_response_type": scoring_source["response_type"] if scoring_source else None,
        "tls_score": round(tls_score, 2),
        "headers_score": round(headers_score, 2),
        "cookies_score": round(cookies_score, 2),
        "dns_score": round(dns_score, 2),
        "consistency_score": round(consistency_score, 2),
        "findings": all_findings,
        "recommendations": get_recommendations(all_findings),
        "tls_evidence": tls_evidence,
        "dns_evidence": dns_evidence,
        "redirect_check": redirect_check,
        "well_known": {
            "security_txt": security_txt,
            "robots_txt": robots_txt,
            "sitemap": sitemap,
        },
        "header_checks": header_checks,
        "missing_headers": missing,
        "results": http_results,
    }
