"""Safe import adapters for external scanner results."""

import hashlib
import json

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan
from app.security import require_api_key

router = APIRouter(prefix="/api/imports", tags=["integrations"])
MAX_IMPORT_BYTES = 5_000_000


async def _scan(db: AsyncSession, scan_id: int, identity: str) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner == identity)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan


@router.post("/nuclei/{scan_id}")
async def import_nuclei_jsonl(
    scan_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _scan(db, scan_id, identity)
    content = await file.read(MAX_IMPORT_BYTES + 1)
    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="Archivo demasiado grande")

    details = scan.get_finding_details()
    imported = 0
    for line_number, raw_line in enumerate(content.decode("utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400, detail=f"JSONL inválido en línea {line_number}"
            ) from exc
        template_id = str(item.get("template-id") or item.get("templateID") or "unknown")
        info = item.get("info") or {}
        matched_at = item.get("matched-at") or item.get("host") or scan.scoring_url
        fingerprint = hashlib.sha256(
            f"nuclei:{template_id}:{matched_at}".encode()
        ).hexdigest()
        details.append(
            {
                "id": f"nuclei:{template_id}",
                "title": info.get("name") or template_id,
                "severity": info.get("severity") or "info",
                "confidence": "medium",
                "intrusiveness": "external",
                "version": "nuclei-import-v1",
                "recommendation": info.get("description") or "",
                "references": info.get("reference") or [],
                "template_hash": item.get("template-url") or "external",
                "fingerprint": fingerprint,
                "evidence": {
                    "url": matched_at,
                    "matcher": item.get("matcher-name"),
                    "source": "nuclei",
                    "timestamp": item.get("timestamp"),
                },
            }
        )
        imported += 1

    deduped = {detail["fingerprint"]: detail for detail in details}
    scan.set_finding_details(list(deduped.values()))
    findings = scan.get_findings()
    findings.extend(
        detail["id"] for detail in details if detail["id"] not in findings
    )
    scan.set_findings(list(dict.fromkeys(findings)))
    await db.flush()
    return {"ok": True, "imported": imported, "total": len(deduped)}
