import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.compat import normalize_comparison_status, normalize_grade, normalize_mode
from app.database import get_db
from app.models import Scan, ScanResult
from app.recommendations import get_recommendations
from app.schemas import ScanOut, ScanRequest, ScanResultOut, ScanSummary
from app.scan_service import execute_scan_request
from app.security import require_api_key

router = APIRouter(
    prefix="/api",
    tags=["scans"],
    dependencies=[Depends(require_api_key)],
)


def _result_to_out(r: ScanResult) -> ScanResultOut:
    ev = r.get_evidence()
    finding_key = ev.get("finding_key")
    recs = get_recommendations([finding_key]) if finding_key else []
    headers = r.get_headers()
    missing = r.get_missing_headers()
    present = [h for h in headers if h not in missing]

    return ScanResultOut(
        id=r.id,
        domain=r.domain,
        path=ev.get("path", "/"),
        profile=ev.get("profile", "unknown"),
        url_evaluated=r.url_evaluated,
        final_url=r.final_url,
        http_code=r.http_code,
        response_type=r.response_type,
        redirect_chain=r.get_redirect_chain(),
        scanned_at=r.scanned_at,
        headers=headers,
        missing_headers=missing,
        present_headers=present,
        cookies=r.get_cookies(),
        content_type=ev.get("content_type"),
        content_length=ev.get("content_length"),
        severity=ev.get("severity"),
        finding_key=finding_key,
        score=r.score,
        grade=normalize_grade(r.grade, r.score),
        is_scoring_source=r.is_scoring_source,
        evidence=ev,
        notes=r.notes,
        recommendation=recs[0] if recs else None,
    )


def _scan_to_out(scan: Scan) -> ScanOut:
    findings = scan.get_findings()
    meta = scan.get_route_meta()
    results_out = [_result_to_out(r) for r in scan.results]

    return ScanOut(
        id=scan.id,
        institution=scan.institution,
        domain=scan.domain,
        mode=normalize_mode(scan.mode),
        intensity=scan.intensity or "standard",
        job_id=scan.job_id,
        route_profile=scan.route_profile,
        include_exposure_checks=scan.include_exposure_checks or False,
        max_paths_per_domain=scan.max_paths_per_domain,
        created_at=scan.created_at,
        overall_score=scan.overall_score,
        overall_grade=normalize_grade(scan.overall_grade, scan.overall_score),
        scoring_url=scan.scoring_url,
        scoring_http_code=scan.scoring_http_code,
        comparison_status=normalize_comparison_status(scan.comparison_status),
        score_delta=scan.score_delta,
        previous_score=scan.previous_score,
        score_explanation=scan.score_explanation,
        tls_score=scan.tls_score,
        headers_score=scan.headers_score,
        cookies_score=scan.cookies_score,
        dns_score=scan.dns_score,
        consistency_score=scan.consistency_score,
        findings=findings,
        finding_details=scan.get_finding_details(),
        recommendations=get_recommendations(findings),
        tech_detection=meta.get("tech_detection"),
        route_selection=meta.get("route_selection"),
        tls_evidence=json.loads(scan.tls_evidence_json) if scan.tls_evidence_json else None,
        dns_evidence=json.loads(scan.dns_evidence_json) if scan.dns_evidence_json else None,
        results=results_out,
    )


def _extract_header_checks(scan: Scan) -> dict[str, bool]:
    scoring = next((r for r in scan.results if r.is_scoring_source), None)
    if not scoring:
        return {}
    headers = scoring.get_headers()
    keys = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    return {k: k in headers for k in keys}


async def _get_previous_scan(db: AsyncSession, domain: str, current_id: int | None = None) -> Scan | None:
    q = (
        select(Scan)
        .where(Scan.domain == domain)
        .order_by(Scan.created_at.desc())
        .limit(2)
    )
    result = await db.execute(q)
    scans = result.scalars().all()
    for s in scans:
        if current_id is None or s.id != current_id:
            return s
    return None


@router.post("/scan", response_model=list[ScanOut])
async def create_scan(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    try:
        scans = await execute_scan_request(request, db, owner=identity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [_scan_to_out(scan) for scan in scans]


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    search: str | None = Query(None),
    grade: str | None = Query(None),
    comparison_status: str | None = Query(None),
    mode: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    q = (
        select(Scan)
        .options(selectinload(Scan.results))
        .where(Scan.owner == identity)
        .order_by(Scan.created_at.desc())
    )
    result = await db.execute(q)
    scans = result.scalars().all()

    summaries = []
    for scan in scans:
        if search:
            s = search.lower()
            if s not in (scan.domain or "").lower() and s not in (scan.institution or "").lower():
                continue
        normalized_grade = normalize_grade(scan.overall_grade, scan.overall_score)
        normalized_status = normalize_comparison_status(scan.comparison_status)
        normalized_mode = normalize_mode(scan.mode)
        if grade is not None and str(normalized_grade) != str(grade):
            continue
        if comparison_status and normalized_status != comparison_status:
            continue
        if mode and normalized_mode != mode:
            continue

        scoring = next((r for r in scan.results if r.is_scoring_source), None)
        header_checks = _extract_header_checks(scan)
        cookies = scoring.get_cookies() if scoring else []
        cookies_ok = (
            all(c.get("secure") and c.get("httponly") for c in cookies) if cookies else None
        )

        summaries.append(
            ScanSummary(
                id=scan.id,
                institution=scan.institution,
                domain=scan.domain,
                mode=normalized_mode,
                intensity=scan.intensity or "standard",
                job_id=scan.job_id,
                created_at=scan.created_at,
                overall_score=scan.overall_score,
                overall_grade=normalized_grade,
                scoring_url=scan.scoring_url,
                scoring_http_code=scan.scoring_http_code,
                comparison_status=normalized_status,
                score_delta=scan.score_delta,
                previous_score=scan.previous_score,
                route_profile=scan.route_profile,
                scoring_source_type=scoring.response_type if scoring else None,
                header_checks=header_checks,
                cookies_ok=cookies_ok,
                tls_ok=scan.tls_score >= 70,
                paths_evaluated_count=len(scan.results),
            )
        )
    return summaries


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    q = (
        select(Scan)
        .options(selectinload(Scan.results))
        .where(Scan.id == scan_id, Scan.owner == identity)
    )
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return _scan_to_out(scan)


@router.get("/scans/{scan_id}/history", response_model=list[ScanSummary])
async def get_scan_history(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    q = select(Scan).where(Scan.id == scan_id, Scan.owner == identity)
    result = await db.execute(q)
    current = result.scalar_one_or_none()
    if not current:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    q2 = (
        select(Scan)
        .options(selectinload(Scan.results))
        .where(Scan.domain == current.domain)
        .where(Scan.owner == identity)
        .order_by(Scan.created_at.desc())
    )
    result2 = await db.execute(q2)
    scans = result2.scalars().all()

    return [
        ScanSummary(
            id=s.id,
            institution=s.institution,
            domain=s.domain,
            mode=normalize_mode(s.mode),
            intensity=s.intensity or "standard",
            job_id=s.job_id,
            created_at=s.created_at,
            overall_score=s.overall_score,
            overall_grade=normalize_grade(s.overall_grade, s.overall_score),
            scoring_url=s.scoring_url,
            scoring_http_code=s.scoring_http_code,
            comparison_status=normalize_comparison_status(s.comparison_status),
            score_delta=s.score_delta,
            previous_score=s.previous_score,
        )
        for s in scans
    ]


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    q = select(Scan).where(Scan.id == scan_id, Scan.owner == identity)
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    await db.delete(scan)
    return {"ok": True}
