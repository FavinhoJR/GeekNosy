"""Reusable scan execution and persistence service."""

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compat import normalize_grade
from app.config import ADVANCED_SECURITY_HEADERS, SECURITY_HEADERS, settings
from app.models import Scan, ScanResult
from app.schemas import ScanRequest
from app.scanner import run_full_scan
from app.scanner.scoring import build_score_explanation, score_to_grade
from app.target_policy import normalize_and_validate_domain

ProgressCallback = Callable[[float, str], Awaitable[None] | None]
CancelCallback = Callable[[], Awaitable[bool] | bool]


async def _notify(callback: ProgressCallback | None, progress: float, phase: str) -> None:
    if not callback:
        return
    result = callback(progress, phase)
    if inspect.isawaitable(result):
        await result


async def _is_cancelled(callback: CancelCallback | None) -> bool:
    if not callback:
        return False
    result = callback()
    return await result if inspect.isawaitable(result) else bool(result)


async def _previous_scan(db: AsyncSession, domain: str, owner: str | None) -> Scan | None:
    statement = select(Scan).where(Scan.domain == domain)
    if owner is not None:
        statement = statement.where(Scan.owner == owner)
    result = await db.execute(statement.order_by(Scan.created_at.desc()).limit(1))
    return result.scalar_one_or_none()


async def execute_scan_request(
    request: ScanRequest,
    db: AsyncSession,
    *,
    owner: str | None = None,
    job_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
    cancel_callback: CancelCallback | None = None,
) -> list[Scan]:
    if settings.require_authorization_confirmation and not request.authorization_confirmed:
        raise ValueError("Debe confirmar que cuenta con autorización para evaluar los objetivos")
    if len(request.domains) > settings.max_domains_per_job:
        raise ValueError(
            f"El trabajo excede el máximo de {settings.max_domains_per_job} dominios"
        )

    outputs: list[Scan] = []
    total = len(request.domains)
    for index, raw_domain in enumerate(request.domains):
        if await _is_cancelled(cancel_callback):
            raise asyncio.CancelledError("Cancelación solicitada")

        target = await normalize_and_validate_domain(raw_domain)
        domain = target.hostname if target.port in (80, 443) else f"{target.hostname}:{target.port}"
        base_progress = index / total * 100
        await _notify(
            progress_callback,
            base_progress,
            f"Evaluando {domain} ({index + 1}/{total})",
        )

        scan_data = await run_full_scan(
            domain=domain,
            mode=request.mode,
            custom_paths=request.custom_paths,
            include_default_paths=request.include_default_paths,
            route_profile=request.route_profile,
            include_exposure_checks=request.include_exposure_checks,
            max_paths_per_domain=request.max_paths_per_domain,
            intensity=request.intensity,
            requests_per_second=request.requests_per_second,
            cancel_callback=cancel_callback,
        )

        previous = await _previous_scan(db, domain, owner)
        previous_score = previous.overall_score if previous else None
        score_delta = (
            round(scan_data["overall_score"] - previous_score, 2)
            if previous_score is not None
            else None
        )
        comparison_status = None
        if score_delta is not None:
            comparison_status = (
                "greater" if score_delta > 0 else "less" if score_delta < 0 else "equal"
            )

        explanation = build_score_explanation(
            scan_data["overall_score"],
            previous_score,
            comparison_status or "equal",
            scan_data["findings"],
        )
        scan = Scan(
            results=[],
            institution=request.institution,
            domain=domain,
            mode=request.mode,
            intensity=request.intensity,
            owner=owner,
            job_id=job_id,
            route_profile=scan_data.get("route_profile"),
            include_exposure_checks=scan_data.get("include_exposure_checks", False),
            max_paths_per_domain=scan_data.get("max_paths_per_domain"),
            overall_score=scan_data["overall_score"],
            overall_grade=scan_data["overall_grade"],
            scoring_url=scan_data["scoring_url"],
            scoring_http_code=scan_data["scoring_http_code"],
            comparison_status=comparison_status,
            score_delta=score_delta,
            previous_score=previous_score,
            score_explanation=explanation,
            tls_score=scan_data["tls_score"],
            headers_score=scan_data["headers_score"],
            cookies_score=scan_data["cookies_score"],
            dns_score=scan_data["dns_score"],
            consistency_score=scan_data["consistency_score"],
            tls_evidence_json=json.dumps(scan_data["tls_evidence"], default=str),
            dns_evidence_json=json.dumps(scan_data["dns_evidence"], default=str),
        )
        scan.set_findings(scan_data["findings"])
        scan.set_finding_details(scan_data.get("finding_details", []))
        scan.set_route_meta(
            scan_data.get("tech_detection", {}),
            scan_data.get("route_selection", {}),
        )
        db.add(scan)
        await db.flush()

        check_list = (
            ADVANCED_SECURITY_HEADERS if request.mode == "advanced" else SECURITY_HEADERS
        )
        for item in scan_data["results"]:
            missing = item.get("missing_headers") or [
                header for header in check_list if header not in item.get("headers", {})
            ]
            result = ScanResult(
                scan_id=scan.id,
                domain=domain,
                url_evaluated=item["url_evaluated"],
                final_url=item.get("final_url"),
                http_code=item.get("http_code", 0),
                response_type=item.get("response_type", "unknown"),
                score=item.get("score", 0),
                grade=normalize_grade(
                    item.get("grade"), item.get("score", 0)
                )
                if item.get("grade") is not None
                else score_to_grade(item.get("score", 0)),
                is_scoring_source=item.get("is_scoring_source", False),
                notes=item.get("notes"),
            )
            result.set_headers(item.get("headers", {}))
            result.set_missing_headers(missing)
            result.set_redirect_chain(item.get("redirect_chain", []))
            result.set_cookies(item.get("cookies", []))
            evidence = dict(item.get("evidence", {}))
            evidence.update(
                {
                    "path": item.get("path"),
                    "profile": item.get("profile"),
                    "response_type": item.get("response_type"),
                    "error": item.get("error"),
                    "content_type": item.get("content_type"),
                    "content_length": item.get("content_length"),
                    "severity": item.get("severity"),
                    "finding_key": item.get("finding_key"),
                    "method": item.get("method"),
                }
            )
            result.set_evidence(evidence)
            scan.results.append(result)
            db.add(result)

        await db.flush()
        outputs.append(scan)
        await _notify(
            progress_callback,
            (index + 1) / total * 100,
            f"Finalizado {domain}",
        )

    return outputs
