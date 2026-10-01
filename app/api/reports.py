from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from datetime import datetime
import io
import pandas as pd

from app.core.database import get_db
from app.models.models import Asset, AssetVulnerability, CVE, IOCEntry, CVESeverity, UserRole
from app.api.deps import require_role

router = APIRouter()


@router.get("/perimeter/csv")
async def export_perimeter_csv(db: Session = Depends(get_db)):
    """Exports full perimeter assets report as CSV."""
    assets = db.query(Asset).all()
    records = []
    for a in assets:
        vuln_count = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == a.id).count()
        records.append({
            "ID": a.id,
            "Tipo": a.tipo.value if a.tipo else "",
            "Vendor": a.vendor,
            "Nome": a.nome,
            "Versione": a.versione or "",
            "CPE": a.cpe or "",
            "Criticita": a.criticita.value if a.criticita else "",
            "Vulnerabilita_Associate": vuln_count,
            "Note": a.note or "",
            "Creato_il": a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else ""
        })
    df = pd.DataFrame(records)
    csv_data = df.to_csv(index=False)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_perimetro_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@router.get("/misp-ioc/csv")
async def export_misp_ioc_csv(db: Session = Depends(get_db)):
    """Exports deduplicated Threat Intelligence IoC report as CSV."""
    iocs = db.query(IOCEntry).order_by(IOCEntry.relevance_score.desc()).all()
    records = []
    for i in iocs:
        ioc_tp = i.ioc_type.value if hasattr(i.ioc_type, 'value') else i.ioc_type
        records.append({
            "ID": i.id,
            "Tipo_IoC": ioc_tp,
            "Valore_Indice": i.value,
            "Grado_Attinenza_Perimetro": f"{i.relevance_score}%",
            "Livello_Minaccia": i.threat_level,
            "Fornitori_Fonti": ", ".join(i.providers or []),
            "Primo_Avvistamento": i.first_seen.strftime("%Y-%m-%d %H:%M") if i.first_seen else "",
            "Ultimo_Avvistamento": i.last_seen.strftime("%Y-%m-%d %H:%M") if i.last_seen else "",
            "Tag_TTP": ", ".join(i.tags or []),
            "Descrizione": i.description or ""
        })
    df = pd.DataFrame(records)
    csv_data = df.to_csv(index=False)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_misp_ioc_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@router.get("/vulnerabilities/pdf", response_class=HTMLResponse)
async def export_vulnerabilities_executive_report(db: Session = Depends(get_db)):
    """Generates clean HTML Printable/PDF Executive Report for Perimeter Vulnerabilities."""
    vulns = db.query(AssetVulnerability).join(CVE).join(Asset).order_by(CVE.cvss_v3_score.desc()).all()

    total_vulns = len(vulns)
    critical_count = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.CRITICAL)
    high_count = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.HIGH)
    medium_count = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.MEDIUM)

    rows_html = ""
    for v in vulns:
        cve_code = v.cve.cve_id if v.cve else "N/D"
        score = v.cve.cvss_v3_score if v.cve else 0.0
        sev = v.cve.cvss_v3_severity.value if (v.cve and v.cve.cvss_v3_severity) else "N/D"
        asset_info = f"{v.asset.vendor} {v.asset.nome}" if v.asset else "N/D"
        triage = v.triage_status.value if v.triage_status else "nuova"

        rows_html += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #2563eb;">{cve_code}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{score} ({sev})</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{asset_info}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{triage}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Report Esecutivo Vulnerabilità Perimetro</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #1e293b; }}
            h1 {{ color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; flex: 1; text-align: center; }}
            .card-title {{ font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: bold; }}
            .card-value {{ font-size: 24px; font-weight: bold; margin-top: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
            th {{ background: #f1f5f9; text-align: left; padding: 10px; border-bottom: 2px solid #cbd5e1; font-size: 12px; text-transform: uppercase; color: #475569; }}
            @media print {{ body {{ margin: 0; }} button {{ display: none; }} }}
        </style>
    </head>
    <body>
        <div style="float: right;">
            <button onclick="window.print()" style="background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                🖨️ Stampa / Salva in PDF
            </button>
        </div>
        <h1>Report Esecutivo Vulnerabilità Perimetro</h1>
        <p style="font-size: 12px; color: #64748b;">Generato il: {datetime.now().strftime('%d/%m/%Y alle %H:%M')}</p>

        <div class="summary">
            <div class="card">
                <div class="card-title">Vulnerabilità Totali</div>
                <div class="card-value" style="color: #2563eb;">{total_vulns}</div>
            </div>
            <div class="card">
                <div class="card-title">Critiche</div>
                <div class="card-value" style="color: #dc2626;">{critical_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Alte</div>
                <div class="card-value" style="color: #ea580c;">{high_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Medie</div>
                <div class="card-value" style="color: #d97706;">{medium_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    <th>CVSS v3 (Severità)</th>
                    <th>Asset Impattato</th>
                    <th>Stato Triage</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else '<tr><td colspan="4" style="text-align:center; padding: 20px; color: #94a3b8;">Nessuna vulnerabilità registrata sul perimetro.</td></tr>'}
            </tbody>
        </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
