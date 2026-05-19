"""Exportación de reportes JSON, CSV y PDF."""

import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Scan
from app.recommendations import get_recommendations

router = APIRouter(prefix="/api/reports", tags=["reports"])


async def _load_scan(scan_id: int, db: AsyncSession) -> Scan:
    q = select(Scan).options(selectinload(Scan.results)).where(Scan.id == scan_id)
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan


def _scan_to_dict(scan: Scan) -> dict:
    findings = scan.get_findings()
    return {
        "tool": "DataGobs",
        "version": "1.0.0",
        "author": "Favio Urrea",
        "license": "Uso abierto",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scan": {
            "id": scan.id,
            "institution": scan.institution,
            "domain": scan.domain,
            "mode": scan.mode,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "overall_score": scan.overall_score,
            "overall_grade": scan.overall_grade,
            "scoring_url": scan.scoring_url,
            "scoring_http_code": scan.scoring_http_code,
            "comparison_status": scan.comparison_status,
            "score_delta": scan.score_delta,
            "previous_score": scan.previous_score,
            "score_explanation": scan.score_explanation,
            "component_scores": {
                "tls": scan.tls_score,
                "headers": scan.headers_score,
                "cookies": scan.cookies_score,
                "dns": scan.dns_score,
                "consistency": scan.consistency_score,
            },
            "findings": findings,
            "recommendations": get_recommendations(findings),
            "tls_evidence": json.loads(scan.tls_evidence_json) if scan.tls_evidence_json else {},
            "dns_evidence": json.loads(scan.dns_evidence_json) if scan.dns_evidence_json else {},
        },
        "results": [
            {
                "url_evaluated": r.url_evaluated,
                "final_url": r.final_url,
                "http_code": r.http_code,
                "response_type": r.response_type,
                "is_scoring_source": r.is_scoring_source,
                "score": r.score,
                "grade": r.grade,
                "headers": r.get_headers(),
                "missing_headers": r.get_missing_headers(),
                "cookies": r.get_cookies(),
                "redirect_chain": r.get_redirect_chain(),
                "notes": r.notes,
            }
            for r in scan.results
        ],
    }


@router.get("/{scan_id}/json")
async def export_json(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    data = _scan_to_dict(scan)
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="datagobs-{scan.domain}-{scan_id}.json"'},
    )


@router.get("/{scan_id}/csv")
async def export_csv(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Institución", "Dominio", "URL evaluada", "URL final", "Código HTTP",
        "Tipo respuesta", "Fuente nota", "Puntaje", "Nota", "HSTS", "CSP",
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Permissions-Policy", "Notas",
    ])
    for r in scan.results:
        h = r.get_headers()
        writer.writerow([
            scan.institution or "",
            scan.domain,
            r.url_evaluated,
            r.final_url or "",
            r.http_code,
            r.response_type,
            "Sí" if r.is_scoring_source else "No",
            r.score,
            r.grade,
            "Sí" if "strict-transport-security" in h else "No",
            "Sí" if "content-security-policy" in h else "No",
            "Sí" if "x-frame-options" in h else "No",
            "Sí" if "x-content-type-options" in h else "No",
            "Sí" if "referrer-policy" in h else "No",
            "Sí" if "permissions-policy" in h else "No",
            r.notes or "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="datagobs-{scan.domain}-{scan_id}.csv"'},
    )


@router.get("/{scan_id}/pdf")
async def export_pdf(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _load_scan(scan_id, db)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=18, spaceAfter=12)
    elements = []

    elements.append(Paragraph("DataGobs - Reporte de Seguridad Web", title_style))
    elements.append(Paragraph(f"Dominio: <b>{scan.domain}</b>", styles["Normal"]))
    if scan.institution:
        elements.append(Paragraph(f"Institución: {scan.institution}", styles["Normal"]))
    elements.append(Paragraph(
        f"Puntaje: <b>{scan.overall_score}</b> | Nota: <b>{scan.overall_grade}</b> | Modo: {scan.mode}",
        styles["Normal"],
    ))
    elements.append(Paragraph(
        f"URL usada para nota: {scan.scoring_url} (HTTP {scan.scoring_http_code})",
        styles["Normal"],
    ))
    if scan.score_explanation:
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph(f"<i>{scan.score_explanation}</i>", styles["Normal"]))

    elements.append(Spacer(1, 0.5 * cm))
    table_data = [["URL", "HTTP", "Tipo", "Nota", "Puntaje"]]
    for r in scan.results:
        marker = " *" if r.is_scoring_source else ""
        table_data.append([
            r.url_evaluated[:60] + marker,
            str(r.http_code),
            r.response_type,
            r.grade,
            f"{r.score:.1f}",
        ])

    t = Table(table_data, colWidths=[8 * cm, 1.5 * cm, 2.5 * cm, 1.5 * cm, 2 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
    ]))
    elements.append(t)

    findings = scan.get_findings()
    if findings:
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph("Recomendaciones", styles["Heading2"]))
        for rec in get_recommendations(findings)[:10]:
            elements.append(Paragraph(
                f"• <b>{rec['title']}</b>: {rec['recommendation']}",
                styles["Normal"],
            ))

    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph(
        "DataGobs v1.0 — Herramienta defensiva. Autor: Favio Urrea. Uso abierto.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey),
    ))

    doc.build(elements)
    buffer.seek(0)
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="datagobs-{scan.domain}-{scan_id}.pdf"'},
    )
