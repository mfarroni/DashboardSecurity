from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, and_
from typing import List, Optional
import re
import uuid
from datetime import datetime
import pandas as pd
import io

from app.core.database import get_db
from app.models.models import SyslogEntry, Asset, ImportBatch
from app.schemas.schemas import SyslogEntryResponse, ImportBatchResponse, PaginatedResponse

router = APIRouter()


# Syslog parsing regex patterns
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)\s+(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)"
    r"\s+(?P<appname>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\[.*?\])?\s*(?P<message>.*)$"
)

# Severity mapping from PRI
PRI_SEVERITY = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug"
}

PRI_FACILITY = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "logaudit", 14: "logalert", 15: "clock",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


def parse_pri(pri: int) -> tuple:
    """Parse PRI value into facility and severity"""
    facility = pri // 8
    severity = pri % 8
    return PRI_FACILITY.get(facility, f"local{facility}"), PRI_SEVERITY.get(severity, "info")


def parse_syslog_line(line: str) -> dict:
    """Parse a single syslog line (RFC3164 or RFC5424)"""
    line = line.strip()
    if not line:
        return None
    
    # Try RFC5424 first
    match = RFC5424_PATTERN.match(line)
    if match:
        groups = match.groupdict()
        pri = int(groups["pri"])
        facility, severity = parse_pri(pri)
        
        # Parse structured data
        sd = groups.get("sd")
        parsed_sd = {}
        if sd:
            sd_pattern = re.compile(r'(\w+)="(.*?)"')
            for m in sd_pattern.finditer(sd):
                parsed_sd[m.group(1)] = m.group(2)
        
        return {
            "timestamp": parse_timestamp(groups["timestamp"]),
            "hostname": groups["hostname"] if groups["hostname"] != "-" else None,
            "source_ip": None,  # Would need additional parsing
            "facility": facility,
            "severity": severity,
            "program": groups["appname"] if groups["appname"] != "-" else None,
            "pid": int(groups["procid"]) if groups["procid"] != "-" and groups["procid"].isdigit() else None,
            "message": groups["message"],
            "parsed_fields": parsed_sd if parsed_sd else None,
            "raw_line": line,
        }
    
    # Try RFC3164
    match = RFC3164_PATTERN.match(line)
    if match:
        groups = match.groupdict()
        pri = int(groups["pri"])
        facility, severity = parse_pri(pri)
        
        return {
            "timestamp": parse_timestamp(groups["timestamp"]),
            "hostname": groups["hostname"],
            "source_ip": None,
            "facility": facility,
            "severity": severity,
            "program": groups["tag"],
            "pid": int(groups["pid"]) if groups["pid"] else None,
            "message": groups["message"],
            "parsed_fields": None,
            "raw_line": line,
        }
    
    # Fallback: try to extract timestamp and treat rest as message
    return {
        "timestamp": datetime.utcnow(),
        "hostname": None,
        "source_ip": None,
        "facility": "unknown",
        "severity": "info",
        "program": "unknown",
        "pid": None,
        "message": line,
        "parsed_fields": None,
        "raw_line": line,
    }


def parse_timestamp(ts_str: str) -> datetime:
    """Parse various timestamp formats"""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",  # RFC3339 with microseconds
        "%Y-%m-%dT%H:%M:%S%z",     # RFC3339
        "%Y-%m-%dT%H:%M:%S.%f",    # ISO with microseconds
        "%Y-%m-%dT%H:%M:%S",       # ISO
        "%b %d %H:%M:%S",          # RFC3164 (assumes current year)
        "%Y-%m-%d %H:%M:%S",       # Standard
        "%d/%b/%Y:%H:%M:%S",       # Apache style
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            # If no year in format, assume current year
            if "%Y" not in fmt and "%y" not in fmt:
                dt = dt.replace(year=datetime.utcnow().year)
            return dt
        except ValueError:
            continue
    
    return datetime.utcnow()


def match_asset_to_log(db: Session, entry: SyslogEntry) -> Optional[int]:
    """Match syslog entry to asset by hostname/IP"""
    if entry.hostname:
        # Exact match on hostname
        asset = db.query(Asset).filter(
            or_(
                Asset.nome.ilike(entry.hostname),
                Asset.nome.ilike(f"{entry.hostname}%"),
            )
        ).first()
        if asset:
            return asset.id
    
    if entry.source_ip:
        # Could match by IP if stored in asset notes or custom field
        pass
    
    return None


def find_cve_correlations(db: Session, entry: SyslogEntry) -> List[str]:
    """Find potential CVE correlations in log message"""
    message = entry.message.lower()
    cve_ids = set()
    
    # Direct CVE mentions
    cve_pattern = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
    for match in cve_pattern.finditer(message):
        cve_ids.add(match.group().upper())
    
    # Check for error patterns that might indicate exploitation
    # This is heuristic - would be enhanced with specific signatures
    exploit_keywords = [
        "exploit", "payload", "shellcode", "buffer overflow",
        "sql injection", "rce", "remote code execution",
        "privilege escalation", "authentication bypass"
    ]
    
    return list(cve_ids)


@router.get("", response_model=PaginatedResponse)
async def list_syslog(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    facility: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    asset_id: Optional[int] = None,
    has_cve: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    query = db.query(SyslogEntry)
    
    if hostname:
        query = query.filter(SyslogEntry.hostname.ilike(f"%{hostname}%"))
    if severity:
        query = query.filter(SyslogEntry.severity == severity)
    if facility:
        query = query.filter(SyslogEntry.facility == facility)
    if search:
        query = query.filter(SyslogEntry.message.ilike(f"%{search}%"))
    if start_date:
        query = query.filter(SyslogEntry.timestamp >= start_date)
    if end_date:
        query = query.filter(SyslogEntry.timestamp <= end_date)
    if asset_id:
        query = query.filter(SyslogEntry.asset_id == asset_id)
    if has_cve is not None:
        if has_cve:
            query = query.filter(SyslogEntry.matched_cve_ids.isnot(None))
        else:
            query = query.filter(SyslogEntry.matched_cve_ids.is_(None))
    
    total = query.count()
    entries = query.order_by(desc(SyslogEntry.timestamp)).offset((page - 1) * page_size).limit(page_size).all()
    
    items = [SyslogEntryResponse.model_validate(e).model_dump() for e in entries]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/stats")
async def syslog_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    total = db.query(func.count(SyslogEntry.id)).filter(SyslogEntry.timestamp >= cutoff).scalar()
    
    by_severity = dict(db.query(SyslogEntry.severity, func.count(SyslogEntry.id))
                       .filter(SyslogEntry.timestamp >= cutoff)
                       .group_by(SyslogEntry.severity).all())
    
    by_facility = dict(db.query(SyslogEntry.facility, func.count(SyslogEntry.id))
                       .filter(SyslogEntry.timestamp >= cutoff)
                       .group_by(SyslogEntry.facility).all())
    
    by_host = dict(db.query(SyslogEntry.hostname, func.count(SyslogEntry.id))
                   .filter(SyslogEntry.timestamp >= cutoff)
                   .group_by(SyslogEntry.hostname)
                   .order_by(desc(func.count(SyslogEntry.id)))
                   .limit(20).all())
    
    with_cve = db.query(func.count(SyslogEntry.id)).filter(
        SyslogEntry.timestamp >= cutoff,
        SyslogEntry.matched_cve_ids.isnot(None)
    ).scalar()
    
    return {
        "total": total,
        "by_severity": by_severity,
        "by_facility": by_facility,
        "top_hosts": by_host,
        "with_cve_mentions": with_cve,
    }


@router.post("/import", response_model=ImportBatchResponse)
async def import_syslog(
    file: UploadFile = File(...),
    batch_id: Optional[str] = Form(None),
    auto_match_assets: bool = Form(True),
    auto_find_cves: bool = Form(True),
    db: Session = Depends(get_db),
):
    """Import syslog file (plain text, one entry per line)"""
    content = await file.read()
    filename = file.filename or "unknown"
    batch_id = batch_id or str(uuid.uuid4())
    
    batch = ImportBatch(
        batch_id=batch_id,
        import_type="syslog",
        filename=filename,
        status="running",
    )
    db.add(batch)
    db.commit()
    
    try:
        text = content.decode("utf-8", errors="replace")
        lines = text.strip().split("\n")
        
        imported = 0
        failed = 0
        errors = []
        
        for idx, line in enumerate(lines):
            try:
                parsed = parse_syslog_line(line)
                if not parsed:
                    continue
                
                entry = SyslogEntry(
                    **parsed,
                    import_batch_id=batch_id,
                )
                
                # Match to asset
                if auto_match_assets:
                    asset_id = match_asset_to_log(db, entry)
                    if asset_id:
                        entry.asset_id = asset_id
                
                # Find CVE correlations
                if auto_find_cves:
                    cve_ids = find_cve_correlations(db, entry)
                    if cve_ids:
                        entry.matched_cve_ids = cve_ids
                
                db.add(entry)
                imported += 1
                
                # Commit in batches
                if imported % 1000 == 0:
                    db.commit()
                    
            except Exception as e:
                failed += 1
                errors.append(f"Line {idx+1}: {str(e)}")
        
        db.commit()
        
        batch.records_total = len(lines)
        batch.records_imported = imported
        batch.records_failed = failed
        batch.errors = errors if errors else None
        batch.completed_at = datetime.utcnow()
        batch.status = "completed" if failed == 0 else "completed_with_errors"
        db.commit()
        
    except Exception as e:
        batch.status = "failed"
        batch.errors = [str(e)]
        batch.completed_at = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=500, detail=f"Errore import: {str(e)}")
    
    return ImportBatchResponse.model_validate(batch)


@router.get("/import/history", response_model=List[ImportBatchResponse])
async def syslog_import_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    batches = db.query(ImportBatch).filter(
        ImportBatch.import_type == "syslog"
    ).order_by(desc(ImportBatch.started_at)).limit(limit).all()
    return [ImportBatchResponse.model_validate(b) for b in batches]


@router.delete("/clear")
async def clear_syslog(
    confirm: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Cancella tutti i log syslog (richiede conferma)"""
    if not confirm:
        raise HTTPException(status_code=400, detail="Conferma richiesta: passa confirm=true")
    
    count = db.query(func.count(SyslogEntry.id)).scalar()
    db.query(SyslogEntry).delete()
    db.commit()
    return {"deleted": count}