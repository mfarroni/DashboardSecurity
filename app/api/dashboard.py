from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.models.models import (
    Asset, CVE, FeedItem, AssetVulnerability, SyslogEntry, ImportBatch,
    AssetType, AssetCriticality, CVESeverity, TriagStatus, FeedSourceType
)
from app.schemas.schemas import (
    DashboardOverview, AssetWithVulnsResponse, PaginatedResponse,
    SyslogEntryResponse
)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return request.app.state.templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/perimetro", response_class=HTMLResponse)
async def perimetro_page(request: Request):
    return request.app.state.templates.TemplateResponse("perimetro.html", {"request": request})


@router.get("/vulnerabilita", response_class=HTMLResponse)
async def vulnerabilita_page(request: Request):
    return request.app.state.templates.TemplateResponse("vulnerabilita.html", {"request": request})


@router.get("/feed", response_class=HTMLResponse)
async def feed_page(request: Request):
    return request.app.state.templates.TemplateResponse("feed.html", {"request": request})


@router.get("/syslog", response_class=HTMLResponse)
async def syslog_page(request: Request):
    return request.app.state.templates.TemplateResponse("syslog.html", {"request": request})


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
async def cve_detail_page(cve_id: int, request: Request):
    return request.app.state.templates.TemplateResponse("cve_detail.html", {"request": request, "cve_id": cve_id})


@router.get("/api/overview", response_model=DashboardOverview)
async def get_overview(db: Session = Depends(get_db)):
    # Total assets
    total_assets = db.query(func.count(Asset.id)).scalar()
    
    # Assets by type
    assets_by_type = dict(db.query(Asset.tipo, func.count(Asset.id)).group_by(Asset.tipo).all())
    assets_by_type = {k.value: v for k, v in assets_by_type.items()}
    
    # Assets by criticality
    assets_by_crit = dict(db.query(Asset.criticita, func.count(Asset.id)).group_by(Asset.criticita).all())
    assets_by_crit = {k.value if k else "non_definita": v for k, v in assets_by_crit.items()}
    
    # Total CVEs
    total_cves = db.query(func.count(CVE.id)).scalar()
    
    # CVEs by severity
    cves_by_sev = dict(db.query(CVE.cvss_v3_severity, func.count(CVE.id)).group_by(CVE.cvss_v3_severity).all())
    cves_by_sev = {k.value if k else "NONE": v for k, v in cves_by_sev.items()}
    
    # New CVEs last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    new_cves_7d = db.query(func.count(CVE.id)).filter(CVE.published_date >= week_ago).scalar()
    
    # Critical CVEs affecting assets
    critical_affecting = db.query(func.count(AssetVulnerability.id.distinct())).join(CVE).filter(
        CVE.cvss_v3_severity.in_([CVESeverity.CRITICAL, CVESeverity.HIGH])
    ).scalar()
    
    # Recent feed items
    recent_feed = db.query(func.count(FeedItem.id)).filter(
        FeedItem.collected_at >= week_ago
    ).scalar()
    
    # Unread feed items (not linked to known CVE)
    unread_feed = db.query(func.count(FeedItem.id)).filter(
        FeedItem.extracted_cves.isnot(None),
        ~FeedItem.cve_matches.any()
    ).scalar()
    
    # Recent syslog
    day_ago = datetime.utcnow() - timedelta(days=1)
    recent_syslog = db.query(func.count(SyslogEntry.id)).filter(
        SyslogEntry.timestamp >= day_ago
    ).scalar()
    
    # High severity logs last 24h
    high_logs = db.query(func.count(SyslogEntry.id)).filter(
        SyslogEntry.timestamp >= day_ago,
        SyslogEntry.severity.in_(["emerg", "alert", "crit", "err", "error", "critical"])
    ).scalar()
    
    return DashboardOverview(
        total_assets=total_assets,
        assets_by_type=assets_by_type,
        assets_by_criticality=assets_by_crit,
        total_cves=total_cves,
        cves_by_severity=cves_by_sev,
        new_cves_last_7d=new_cves_7d,
        critical_cves_affecting_assets=critical_affecting,
        recent_feed_items=recent_feed,
        unread_feed_items=unread_feed,
        recent_syslog_entries=recent_syslog,
        high_severity_logs_last_24h=high_logs,
    )


@router.get("/api/perimetro", response_model=List[AssetWithVulnsResponse])
async def get_perimetro_with_vulns(
    criticita: Optional[AssetCriticality] = None,
    has_vulns: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    if criticita:
        query = query.filter(Asset.criticita == criticita)
    
    assets = query.order_by(Asset.vendor, Asset.nome).all()
    
    result = []
    for asset in assets:
        vulns = db.query(AssetVulnerability).filter(
            AssetVulnerability.asset_id == asset.id
        ).all()
        
        if has_vulns is True and not vulns:
            continue
        if has_vulns is False and vulns:
            continue
        
        vuln_responses = [AssetWithVulnsResponse.model_validate(v) for v in vulns]
        
        critical = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.CRITICAL)
        high = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.HIGH)
        medium = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.MEDIUM)
        low = sum(1 for v in vulns if v.cve and v.cve.cvss_v3_severity == CVESeverity.LOW)
        
        result.append(AssetWithVulnsResponse(
            asset=asset,
            vulnerabilities=vuln_responses,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
        ))
    
    return result


@router.get("/api/vulnerabilita", response_model=PaginatedResponse)
async def get_vulnerabilita(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[CVESeverity] = None,
    triage_status: Optional[TriagStatus] = None,
    asset_id: Optional[int] = None,
    source: Optional[str] = None,
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
):
    query = db.query(AssetVulnerability).join(CVE).join(Asset)
    
    if severity:
        query = query.filter(CVE.cvss_v3_severity == severity)
    if triage_status:
        query = query.filter(AssetVulnerability.triage_status == triage_status)
    if asset_id:
        query = query.filter(AssetVulnerability.asset_id == asset_id)
    if source:
        query = query.filter(CVE.sources.contains([source]))
    if days:
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(CVE.published_date >= cutoff)
    
    total = query.count()
    vulns = query.order_by(desc(CVE.published_date)).offset((page - 1) * page_size).limit(page_size).all()
    
    items = [AssetVulnerabilityResponse.model_validate(v).model_dump() for v in vulns]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/api/dashboard/critical-vulns", response_class=HTMLResponse)
async def get_critical_vulns(db: Session = Depends(get_db)):
    """Partial: Critical/High vulnerabilities on perimeter"""
    vulns = db.query(AssetVulnerability).join(CVE).join(Asset).filter(
        CVE.cvss_v3_severity.in_([CVESeverity.CRITICAL, CVESeverity.HIGH])
    ).order_by(desc(CVE.published_date)).limit(10).all()
    
    return request.app.state.templates.TemplateResponse("partials/critical_vulns.html", {
        "request": Request, "vulns": vulns
    })


@router.get("/api/dashboard/recent-feed", response_class=HTMLResponse)
async def get_recent_feed(request: Request, db: Session = Depends(get_db)):
    """Partial: Recent feed items"""
    week_ago = datetime.utcnow() - timedelta(days=7)
    items = db.query(FeedItem).filter(
        FeedItem.collected_at >= week_ago
    ).order_by(desc(FeedItem.collected_at)).limit(10).all()
    
    return request.app.state.templates.TemplateResponse("partials/recent_feed.html", {
        "request": request, "items": items
    })


@router.get("/api/dashboard/assets-by-type", response_class=HTMLResponse)
async def get_assets_by_type(request: Request, db: Session = Depends(get_db)):
    """Partial: Assets by type and criticality"""
    assets_by_type = dict(db.query(Asset.tipo, func.count(Asset.id)).group_by(Asset.tipo).all())
    assets_by_type = {k.value: v for k, v in assets_by_type.items()}
    
    assets_by_crit = dict(db.query(Asset.criticita, func.count(Asset.id)).group_by(Asset.criticita).all())
    assets_by_crit = {k.value if k else "non_definita": v for k, v in assets_by_crit.items()}
    
    return request.app.state.templates.TemplateResponse("partials/assets_by_type.html", {
        "request": request, 
        "assets_by_type": assets_by_type,
        "assets_by_criticality": assets_by_crit
    })


@router.get("/api/dashboard/syslog-stats", response_class=HTMLResponse)
async def get_syslog_stats(request: Request, db: Session = Depends(get_db)):
    """Partial: Syslog stats last 24h"""
    from app.api.syslog import syslog_stats
    stats = await syslog_stats(hours=24, db=db)
    
    return request.app.state.templates.TemplateResponse("partials/syslog_stats.html", {
        "request": request, "stats": stats
    })