"""Orquestador de escaneo completo con perfiles de rutas inteligentes."""

import asyncio
from datetime import datetime, timezone

from app.checks import check_engine
from app.recommendations import get_recommendations
from app.scanner.dns_scanner import scan_dns, score_dns
from app.scanner.http_scanner import (
    build_base_url,
    check_http_to_https_redirect,
    fetch_paths_batch,
)
from app.scanner.path_analyzer import analyze_path_result, collect_supplementary_findings
from app.scanner.route_selector import get_core_paths, select_paths_after_detection
from app.scanner.crawler import discover_same_origin_paths
from app.scanner.scoring import (
    compute_overall_score,
    score_consistency,
    score_cookies,
    score_headers,
    score_to_grade,
)
from app.scanner.tech_detection import detect_technologies
from app.scanner.tls_scanner import scan_tls, score_tls


def _select_scoring_source(results: list[dict]) -> dict | None:
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
    route_profile: str = "auto",
    include_exposure_checks: bool = False,
    max_paths_per_domain: int = 40,
    intensity: str = "standard",
    requests_per_second: float | None = None,
    cancel_callback=None,
) -> dict:
    intensity_caps = {
        "passive": 8,
        "fast": 15,
        "standard": 40,
        "bug_bounty": 80,
        "deep": 120,
        "custom": 120,
    }
    max_paths_per_domain = min(
        max_paths_per_domain, intensity_caps.get(intensity, max_paths_per_domain)
    )
    if intensity == "passive":
        route_profile = "minimal"

    # Fase 1: rutas core para detección
    core_items = get_core_paths() if include_default_paths else []
    scanned_paths: set[str] = set()
    http_results: list[dict] = []

    if core_items:
        core_results = await fetch_paths_batch(
            domain,
            core_items[:max_paths_per_domain],
            requests_per_second=requests_per_second,
            cancel_callback=cancel_callback,
        )
        for r in core_results:
            scanned_paths.add(r.get("path", "/"))
        http_results.extend(core_results)

    root_result = next((r for r in http_results if r.get("path") in ("/", "")), None)
    body_preview = (root_result or {}).get("body_preview") or ""

    tech_info = detect_technologies(root_result, http_results, body_preview)
    detected = tech_info.get("technologies", [])
    discovered_paths = []
    if intensity in ("bug_bounty", "deep", "custom") and root_result:
        discovered_paths = discover_same_origin_paths(
            root_result.get("final_url") or root_result.get("url_evaluated"),
            body_preview,
            max_paths=max(0, max_paths_per_domain - len(scanned_paths)),
        )
    combined_custom_paths = list(custom_paths or []) + discovered_paths

    # Fase 2: selección completa de rutas
    selection = select_paths_after_detection(
        route_profile=route_profile,
        mode=mode,
        detected_technologies=detected,
        include_exposure_checks=include_exposure_checks,
        include_default_paths=include_default_paths,
        custom_paths=combined_custom_paths,
        max_paths=max_paths_per_domain,
    )

    remaining_items = [
        (p["path"], p["profile"])
        for p in selection["paths"]
        if p["path"] not in scanned_paths
    ]

    if remaining_items:
        more_results = await fetch_paths_batch(
            domain,
            remaining_items,
            skip_paths=scanned_paths,
            requests_per_second=requests_per_second,
            cancel_callback=cancel_callback,
        )
        http_results.extend(more_results)

    # TLS, DNS, redirect
    tls_evidence, redirect_check, dns_evidence = await asyncio.gather(
        scan_tls(domain),
        check_http_to_https_redirect(domain),
        scan_dns(domain),
    )
    tls_score, tls_findings = score_tls(tls_evidence)

    https_redirect = redirect_check.get("redirects_to_https", False)
    if not https_redirect:
        tls_findings.append("no_https_redirect")

    dns_score, dns_findings = score_dns(dns_evidence)

    security_txt = next(
        (item for item in http_results if item.get("path") == "/.well-known/security.txt"),
        None,
    )
    if not security_txt or security_txt.get("http_code") != 200:
        tls_findings.append("no_security_txt")

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
        cookies_score, cookie_findings = score_cookies(scoring_source.get("cookies", []))
        all_findings.extend(cookie_findings)

    # Analizar cada ruta (complementaria vs principal)
    analyzed_results: list[dict] = []
    finding_details: list[dict] = []
    for r in http_results:
        is_main = scoring_source is not None and r is scoring_source
        analyzed = analyze_path_result(r, mode=mode, is_scoring_source=is_main)
        if is_main:
            analyzed["is_scoring_source"] = True
            analyzed["score"] = 0
        else:
            analyzed["is_scoring_source"] = False
            hs, _, _ = score_headers(analyzed.get("headers", {}), mode)
            analyzed["score"] = round(hs, 2)
            analyzed["grade"] = score_to_grade(hs)
        plugin_findings = check_engine.run(analyzed, intensity=intensity)
        analyzed["plugin_findings"] = plugin_findings
        analyzed.setdefault("evidence", {})["plugin_findings"] = plugin_findings
        for finding in plugin_findings:
            all_findings.append(finding["id"])
            finding_details.append(finding)
        analyzed.pop("body_preview", None)
        analyzed_results.append(analyzed)

    all_findings.extend(collect_supplementary_findings(analyzed_results))

    consistency_score, consistency_findings = score_consistency(analyzed_results, scoring_headers)
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
        for r in analyzed_results:
            if r.get("is_scoring_source"):
                r["score"] = overall
                r["grade"] = score_to_grade(overall)
                break

    from app.config import ADVANCED_SECURITY_HEADERS, SECURITY_HEADERS

    check_list = ADVANCED_SECURITY_HEADERS if mode == "advanced" else SECURITY_HEADERS
    missing = [h for h in check_list if h not in scoring_headers] if scoring_source else []
    all_findings = list(dict.fromkeys(all_findings))

    return {
        "domain": domain,
        "mode": mode,
        "intensity": intensity,
        "route_profile": route_profile,
        "include_exposure_checks": include_exposure_checks,
        "max_paths_per_domain": max_paths_per_domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "overall_grade": score_to_grade(overall),
        "scoring_url": scoring_source["url_evaluated"] if scoring_source else None,
        "scoring_http_code": scoring_source["http_code"] if scoring_source else None,
        "scoring_response_type": scoring_source["response_type"] if scoring_source else None,
        "tls_score": round(tls_score, 2),
        "headers_score": round(headers_score, 2),
        "cookies_score": round(cookies_score, 2),
        "dns_score": round(dns_score, 2),
        "consistency_score": round(consistency_score, 2),
        "findings": all_findings,
        "finding_details": finding_details,
        "recommendations": get_recommendations(all_findings),
        "tls_evidence": tls_evidence,
        "dns_evidence": dns_evidence,
        "redirect_check": redirect_check,
        "tech_detection": tech_info,
        "route_selection": selection,
        "header_checks": header_checks,
        "missing_headers": missing,
        "results": analyzed_results,
    }
