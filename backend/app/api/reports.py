"""Exportación de reportes JSON, CSV y PDF."""

import csv
import html
import io
import json
import uuid
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
from app.security import require_api_key
from app import __version__

router = APIRouter(
    prefix="/api/reports",
    tags=["reports"],
    dependencies=[Depends(require_api_key)],
)


async def _load_scan(scan_id: int, db: AsyncSession, identity: str) -> Scan:
    q = (
        select(Scan)
        .options(selectinload(Scan.results))
        .where(Scan.id == scan_id, Scan.owner == identity)
    )
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan


def _scan_to_dict(scan: Scan) -> dict:
    findings = scan.get_findings()
    return {
        "tool": "GeekNosy",
        "version": __version__,
        "author": "Favio Urrea",
        "license": "Uso abierto",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scan": {
            "id": scan.id,
            "institution": scan.institution,
            "domain": scan.domain,
            "mode": scan.mode,
            "intensity": scan.intensity,
            "job_id": scan.job_id,
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
            "finding_details": scan.get_finding_details(),
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
                "evidence": r.get_evidence(),
            }
            for r in scan.results
        ],
    }


@router.get("/{scan_id}/json")
async def export_json(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    data = _scan_to_dict(scan)
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.json"'},
    )


@router.get("/{scan_id}/csv")
async def export_csv(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
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
        headers={"Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.csv"'},
    )


@router.get("/{scan_id}/pdf")
async def export_pdf(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=18, spaceAfter=12)
    elements = []

    elements.append(Paragraph("GeekNosy - Reporte de Seguridad Web", title_style))
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
        "GeekNosy v2.0 — Herramienta defensiva. Autor: Favio Urrea. Uso abierto.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey),
    ))

    doc.build(elements)
    buffer.seek(0)
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.pdf"'},
    )


@router.get("/{scan_id}/jsonl")
async def export_jsonl(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    data = _scan_to_dict(scan)
    lines = [
        json.dumps(
            {"type": "scan", **data["scan"]},
            ensure_ascii=False,
            default=str,
        )
    ]
    lines.extend(
        json.dumps({"type": "result", **item}, ensure_ascii=False, default=str)
        for item in data["results"]
    )
    return Response(
        content="\n".join(lines) + "\n",
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.jsonl"'
        },
    )


@router.get("/{scan_id}/sarif")
async def export_sarif(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    details = scan.get_finding_details()
    if not details:
        details = [
            {
                "id": finding,
                "title": finding,
                "severity": get_recommendations([finding])[0]["severity"]
                if get_recommendations([finding])
                else "warning",
                "recommendation": get_recommendations([finding])[0]["recommendation"]
                if get_recommendations([finding])
                else "",
                "evidence": {"url": scan.scoring_url},
            }
            for finding in scan.get_findings()
        ]
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    rules = {}
    results = []
    for finding in details:
        rule_id = finding["id"]
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.get("title", rule_id),
            "shortDescription": {"text": finding.get("title", rule_id)},
            "help": {"text": finding.get("recommendation", "")},
            "properties": {
                "security-severity": finding.get("severity", "info"),
                "confidence": finding.get("confidence", "medium"),
                "references": finding.get("references", []),
            },
        }
        url = finding.get("evidence", {}).get("url") or scan.scoring_url or ""
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(finding.get("severity", "info"), "note"),
                "message": {"text": finding.get("title", rule_id)},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": url}}}
                ],
                "fingerprints": {
                    "geeknosy": finding.get("fingerprint", f"{scan.id}:{rule_id}")
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GeekNosy",
                        "version": "2.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return Response(
        content=json.dumps(sarif, ensure_ascii=False, indent=2),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.sarif"'
        },
    )


@router.get("/{scan_id}/sbom")
async def export_sbom(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    inventory = scan.get_route_meta().get("tech_detection", {}).get("software_inventory", [])
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg:npm/{item['package']}@{item['version']}",
            "name": item["package"],
            "version": item["version"],
            "purl": f"pkg:npm/{item['package']}@{item['version']}",
            "properties": [{"name": "geeknosy:observed-source", "value": item.get("source", "")}],
        }
        for item in inventory
    ]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'geeknosy:{scan.id}:{scan.domain}')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"vendor": "Favio Urrea", "name": "GeekNosy", "version": __version__}],
            "component": {"type": "application", "name": scan.domain},
            "properties": [
                {"name": "geeknosy:inventory-method", "value": "passive-public-script-filename"},
                {"name": "geeknosy:completeness", "value": "partial-observed-only"},
            ],
        },
        "components": components,
    }
    return Response(
        content=json.dumps(bom, ensure_ascii=False, indent=2),
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.cdx.json"'},
    )


def _markdown_report(scan: Scan) -> str:
    lines = [
        "# GeekNosy - Reporte de Seguridad",
        "",
        f"- Dominio: `{scan.domain}`",
        f"- Puntaje: **{scan.overall_score}/100**",
        f"- Nota: **{scan.overall_grade}/10**",
        f"- Intensidad: `{scan.intensity}`",
        f"- Fecha: `{scan.created_at.isoformat()}`",
        "",
        "## Hallazgos",
        "",
    ]
    recommendations = get_recommendations(scan.get_findings())
    if not recommendations:
        lines.append("No se registraron hallazgos.")
    for rec in recommendations:
        lines.extend(
            [
                f"### {rec['title']}",
                "",
                f"- Severidad: **{rec['severity']}**",
                f"- Recomendación: {rec['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines)


@router.get("/{scan_id}/markdown")
async def export_markdown(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    return Response(
        content=_markdown_report(scan),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.md"'
        },
    )


@router.get("/{scan_id}/html")
async def export_html(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    identity: str = Depends(require_api_key),
):
    scan = await _load_scan(scan_id, db, identity)
    cards = "".join(
        f"<article><h2>{html.escape(rec['title'])}</h2>"
        f"<p><strong>{html.escape(rec['severity'])}</strong></p>"
        f"<p>{html.escape(rec['recommendation'])}</p></article>"
        for rec in get_recommendations(scan.get_findings())
    )
    document = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>GeekNosy - {html.escape(scan.domain)}</title>
<style>body{{font:16px system-ui;background:#020617;color:#cbd5e1;max-width:960px;margin:auto;padding:32px}}
article{{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:16px;margin:12px 0}}
h1,h2{{color:#fff}}strong{{color:#f59e0b}}</style></head>
<body><h1>GeekNosy - {html.escape(scan.domain)}</h1>
<p>Puntaje <strong>{scan.overall_score}/100</strong> · Nota <strong>{scan.overall_grade}/10</strong></p>
{cards or "<p>No se registraron hallazgos.</p>"}</body></html>"""
    return Response(
        content=document,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="geeknosy-{scan.domain}-{scan_id}.html"'
        },
    )
