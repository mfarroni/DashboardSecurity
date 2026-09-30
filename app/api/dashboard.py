from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.models.models import (
    Asset, CVE, FeedItem, AssetVulnerability, SyslogEntry, ImportBatch, User, UserRole,
    AssetType, AssetCriticality, CVESeverity, TriagStatus, FeedSourceType
)
from app.schemas.schemas import (
    DashboardOverview, AssetWithVulnsResponse, PaginatedResponse,
    SyslogEntryResponse, AssetVulnerabilityResponse
)
from app.api.deps import get_current_user_optional

router = APIRouter()


from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import status


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if current_user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("login.html", {"request": request})


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("dashboard.html", {"request": request, "current_user": current_user})


@router.get("/perimetro", response_class=HTMLResponse)
async def perimetro_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("perimetro.html", {"request": request, "current_user": current_user})


@router.get("/vulnerabilita", response_class=HTMLResponse)
async def vulnerabilita_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("vulnerabilita.html", {"request": request, "current_user": current_user})


@router.get("/feed", response_class=HTMLResponse)
async def feed_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("feed.html", {"request": request, "current_user": current_user})


@router.get("/syslog", response_class=HTMLResponse)
async def syslog_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("syslog.html", {"request": request, "current_user": current_user})


@router.get("/admin/users", response_class=HTMLResponse)
async def users_admin_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accesso riservato agli amministratori")
    from app.models.models import SourceRegistry
    users = db.query(User).order_by(User.id.asc()).all()
    sources = db.query(SourceRegistry).order_by(SourceRegistry.name.asc()).all()
    return request.app.state.templates.TemplateResponse("users.html", {
        "request": request,
        "current_user": current_user,
        "users": users,
        "sources": sources
    })


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
async def cve_detail_page(cve_id: int, request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return request.app.state.templates.TemplateResponse("cve_detail.html", {"request": request, "cve_id": cve_id, "current_user": current_user})


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


@router.get("/api/dashboard/overview-cards", response_class=HTMLResponse)
async def get_overview_cards(request: Request, db: Session = Depends(get_db)):
    """Partial: Overview Stats Cards for Dashboard"""
    overview = await get_overview(db=db)
    return request.app.state.templates.TemplateResponse("partials/overview_cards.html", {
        "request": request, "overview": overview
    })


@router.get("/api/perimetro")
async def get_perimetro_with_vulns(
    request: Request,
    tipo: Optional[AssetType] = None,
    criticita: Optional[AssetCriticality] = None,
    has_vulns: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    if tipo:
        query = query.filter(Asset.tipo == tipo)
    if criticita:
        query = query.filter(Asset.criticita == criticita)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                Asset.nome.ilike(search_term),
                Asset.vendor.ilike(search_term),
                Asset.versione.ilike(search_term),
                Asset.cpe.ilike(search_term),
            )
        )
    
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
        
        vuln_responses = [AssetVulnerabilityResponse.from_orm(v) for v in vulns]
        
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
    
    if request.headers.get("hx-request"):
        if not result:
            return HTMLResponse('<tr><td colspan="7" class="px-4 py-8 text-center text-gray-500">Nessun asset presente nel perimetro</td></tr>')
        html_rows = ""
        for item in result:
            asset = item.asset
            crit_badge = f'<span class="badge-{asset.criticita.value} px-2 py-0.5 rounded text-xs">{asset.criticita.value}</span>' if asset.criticita else '<span class="text-xs text-gray-400">-</span>'
            cpe_val = f'<code class="text-xs text-gray-600 bg-gray-100 px-1 py-0.5 rounded">{asset.cpe}</code>' if asset.cpe else '<span class="text-xs text-gray-400">-</span>'
            vuln_badge = f'<span class="badge-critical px-2 py-0.5 rounded text-xs">{item.critical_count + item.high_count} critiche</span>' if (item.critical_count + item.high_count) > 0 else '<span class="text-xs text-green-600">OK</span>'
            html_rows += f'''
            <tr class="table-row border-b border-gray-100">
                <td class="px-3 py-3 w-10 text-center">
                    <input type="checkbox" class="asset-checkbox rounded border-gray-300 text-blue-600 focus:ring-blue-500" value="{asset.id}" onchange="updateBulkDeleteBtn()">
                </td>
                <td class="px-4 py-3 text-sm font-medium text-gray-900">{asset.vendor} {asset.nome} <span class="text-xs text-gray-500">{asset.versione or ''}</span></td>
                <td class="px-4 py-3 text-sm text-gray-500 uppercase text-xs">{asset.tipo.value}</td>
                <td class="px-4 py-3 text-sm text-gray-500">{crit_badge}</td>
                <td class="px-4 py-3 text-sm text-gray-500">{cpe_val}</td>
                <td class="px-4 py-3 text-sm text-gray-500">{vuln_badge}</td>
                <td class="px-4 py-3 text-sm text-right">
                    <button onclick="editAsset({asset.id})" class="text-blue-600 hover:text-blue-800 text-xs mr-2" title="Modifica"><i class="fas fa-edit"></i></button>
                    <button onclick="deleteAsset({asset.id})" class="text-red-600 hover:text-red-800 text-xs" title="Elimina"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
            '''
        return HTMLResponse(html_rows)

    return result


@router.get("/api/vulnerabilita")
async def get_vulnerabilita(
    request: Request,
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
    
    if request.headers.get("hx-request"):
        if not vulns:
            return HTMLResponse('<tr><td colspan="8" class="px-4 py-8 text-center text-gray-500">Nessuna vulnerabilità trovata</td></tr>')
        html_rows = ""
        for v in vulns:
            cve_id = v.cve.cve_id if v.cve else "N/D"
            sev = v.cve.cvss_v3_severity.value if (v.cve and v.cve.cvss_v3_severity) else "NONE"
            sev_badge = f'<span class="badge-{sev.lower()} px-2 py-0.5 rounded text-xs">{sev}</span>'
            asset_name = f"{v.asset.vendor} {v.asset.nome}" if v.asset else "N/D"
            match_type = v.match_type.value if v.match_type else "-"
            triage_status_val = v.triage_status.value if v.triage_status else "nuova"
            triage_badge = f'<span class="badge-{triage_status_val} px-2 py-0.5 rounded text-xs">{triage_status_val}</span>'
            source_val = ", ".join(v.cve.sources) if (v.cve and v.cve.sources) else "NVD"
            pub_date = v.cve.published_date.strftime('%d/%m/%Y') if (v.cve and v.cve.published_date) else "N/D"
            html_rows += f'''
            <tr class="table-row border-b border-gray-100">
                <td class="px-4 py-3 text-sm font-medium text-blue-600"><a href="/cve/{v.cve_id}" class="hover:underline">{cve_id}</a></td>
                <td class="px-4 py-3 text-sm">{sev_badge}</td>
                <td class="px-4 py-3 text-sm text-gray-900">{asset_name}</td>
                <td class="px-4 py-3 text-sm text-xs text-gray-500">{match_type}</td>
                <td class="px-4 py-3 text-sm">{triage_badge}</td>
                <td class="px-4 py-3 text-sm text-xs text-gray-500">{source_val}</td>
                <td class="px-4 py-3 text-sm text-xs text-gray-500">{pub_date}</td>
                <td class="px-4 py-3 text-sm text-right">
                    <a href="/cve/{v.cve_id}" class="text-blue-600 hover:text-blue-800 text-xs"><i class="fas fa-eye"></i> Dettaglio</a>
                </td>
            </tr>
            '''
        return HTMLResponse(html_rows)

    items = [AssetVulnerabilityResponse.from_orm(v).dict() for v in vulns]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/api/dashboard/critical-vulns", response_class=HTMLResponse)
async def get_critical_vulns(request: Request, db: Session = Depends(get_db)):
    """Partial: Critical/High vulnerabilities on perimeter"""
    vulns = db.query(AssetVulnerability).join(CVE).join(Asset).filter(
        CVE.cvss_v3_severity.in_([CVESeverity.CRITICAL, CVESeverity.HIGH])
    ).order_by(desc(CVE.published_date)).limit(10).all()
    
    return request.app.state.templates.TemplateResponse("partials/critical_vulns.html", {
        "request": request, "vulns": vulns
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


@router.get("/api/dashboard/syslog-header-cards", response_class=HTMLResponse)
async def get_syslog_header_cards(request: Request, db: Session = Depends(get_db)):
    """Partial: Syslog top 4 stat cards for syslog.html"""
    from app.api.syslog import syslog_stats
    stats = await syslog_stats(hours=24, db=db)
    high_severity_count = sum(count for sev, count in stats.get("by_severity", {}).items() if sev in ['emerg', 'alert', 'crit', 'err', 'error', 'critical'])
    return request.app.state.templates.TemplateResponse("partials/syslog_header_cards.html", {
        "request": request,
        "stats": stats,
        "high_severity": high_severity_count
    })