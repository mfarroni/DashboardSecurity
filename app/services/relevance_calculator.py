from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Tuple, Optional
from app.models.models import SyslogEntry, Asset, AssetVulnerability, CVE


def calculate_ioc_relevance(db: Session, ioc_type: str, value: str, raw_data: Optional[dict] = None) -> Tuple[float, str]:
    """
    Calcola il Grado di Attinenza con il Perimetro (0.0% - 100.0%) e la motivazione.
    
    Regole:
    - 100%: Match diretto con Log Syslog o IP/Nome di un Asset del Perimetro.
    - 75%: Correlazione con CVE di un Asset del Perimetro.
    - 50%: Correlazione con Vendor/Tipo di sistema presente nel Perimetro.
    - 0-25%: Minaccia generica senza riscontro.
    """
    clean_val = value.strip()
    
    # 1. Check 100% - Syslog Match
    syslog_match = db.query(SyslogEntry).filter(
        or_(
            SyslogEntry.source_ip == clean_val,
            SyslogEntry.hostname == clean_val,
            SyslogEntry.message.ilike(f"%{clean_val}%")
        )
    ).first()
    if syslog_match:
        return (100.0, f"🔴 CRITICO - Match Diretto Syslog: Trovato riscontro negli eventi di sicurezza ({syslog_match.hostname or syslog_match.source_ip})")
    
    # Check 100% - Asset Match
    asset_match = db.query(Asset).filter(
        or_(
            Asset.nome.ilike(clean_val),
            Asset.cpe == clean_val
        )
    ).first()
    if asset_match:
        return (100.0, f"🔴 CRITICO - Match Diretto Asset: Corrisponde all'asset del perimetro '{asset_match.vendor} {asset_match.nome}'")

    # 2. Check 75% - Asset Vulnerability / CVE Correlation
    if clean_val.upper().startswith("CVE-"):
        vuln_cve = db.query(AssetVulnerability).join(CVE).filter(CVE.cve_id.ilike(clean_val)).first()
        if vuln_cve:
            return (75.0, f"🟠 ALTO - Correlato a vulnerabilità attiva sul perimetro per l'asset ID {vuln_cve.asset_id}")

    # 3. Check 50% - Vendor Match
    asset_vendors = db.query(Asset.vendor).distinct().all()
    vendors = [v[0].lower() for v in asset_vendors if v[0]]
    val_lower = clean_val.lower()
    
    for vendor in vendors:
        if len(vendor) > 2 and (vendor in val_lower or (raw_data and vendor in str(raw_data).lower())):
            return (50.0, f"🟡 MEDIO - Riguarda il vendor '{vendor.title()}' presente nei sistemi del perimetro")

    # 4. Default 0%
    return (0.0, "⚪ BASSO - Nessun riscontro rilevato con perimetro, log o vulnerabilità censite")
