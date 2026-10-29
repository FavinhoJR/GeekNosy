"""Finding triage API with stable fingerprints."""

import hashlib

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import FindingTriage, Scan
from app.recommendations import get_recommendations
from app.schemas import FindingOut, FindingTriageUpdate
from app.security import require_api_key

router = APIRouter(prefix="/api/scans", tags=["findings"])


async def _owned_scan(db: AsyncSession, scan_id: int, owner: str) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner == owner)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan


def _finding_rows(scan: Scan) -> list[dict]:
    details = scan.get_finding_details()
    detailed_ids = {item["id"] for item in details}
    for finding_id in scan.get_findings():
        if finding_id in detailed_ids:
            continue
        recommendation = get_recommendations([finding_id])
        rec = recommendation[0] if recommendation else {}
        details.append(
            {
                "id": finding_id,
                "fingerprint": hashlib.sha256(
                    f"{scan.domain}:{finding_id}".encode()
                ).hexdigest(),
                "title": rec.get("title", finding_id),
                "severity": rec.get("severity", "info"),
                "confidence": "medium",
                "recommendation": rec.get("recommendation", ""),
                "references": [],
                "evidence": {"url": scan.scoring_url},
            }
        )
    return details


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _owned_scan(db, scan_id, identity)
    result = await db.execute(
        select(FindingTriage).where(
            FindingTriage.scan_id == scan_id, FindingTriage.owner == identity
        )
    )
    states = {item.fingerprint: item for item in result.scalars().all()}
    output = []
    for detail in _finding_rows(scan):
        state = states.get(detail["fingerprint"])
        output.append(
            FindingOut(
                id=detail["id"],
                fingerprint=detail["fingerprint"],
                title=detail.get("title", detail["id"]),
                severity=detail.get("severity", "info"),
                confidence=detail.get("confidence", "medium"),
                status=state.status if state else "new",
                notes=state.notes if state else None,
                recommendation=detail.get("recommendation", ""),
                references=detail.get("references", []),
                evidence=detail.get("evidence", {}),
            )
        )
    return output


@router.patch("/{scan_id}/findings/{fingerprint}", response_model=FindingOut)
async def update_finding(
    scan_id: int,
    fingerprint: str,
    update: FindingTriageUpdate,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _owned_scan(db, scan_id, identity)
    detail = next(
        (item for item in _finding_rows(scan) if item["fingerprint"] == fingerprint),
        None,
    )
    if not detail:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    result = await db.execute(
        select(FindingTriage).where(
            FindingTriage.scan_id == scan_id,
            FindingTriage.owner == identity,
            FindingTriage.fingerprint == fingerprint,
        )
    )
    state = result.scalar_one_or_none()
    if not state:
        state = FindingTriage(
            scan_id=scan_id,
            owner=identity,
            fingerprint=fingerprint,
        )
        db.add(state)
    state.status = update.status
    state.notes = update.notes
    await db.flush()
    return FindingOut(
        id=detail["id"],
        fingerprint=fingerprint,
        title=detail.get("title", detail["id"]),
        severity=detail.get("severity", "info"),
        confidence=detail.get("confidence", "medium"),
        status=state.status,
        notes=state.notes,
        recommendation=detail.get("recommendation", ""),
        references=detail.get("references", []),
        evidence=detail.get("evidence", {}),
    )
