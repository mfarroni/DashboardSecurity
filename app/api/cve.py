from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, and_
from typing import List, Optional
from datetime import datetime, timedelta
import httpx
import json
from app.core.config import settings

from app.core.database import get_db
from app.models.models import (
    CVE, Asset, AssetVulnerability, FeedItem, FeedItemCVE,
    ImportBatch, CVESeverity, TriagStatus, MatchType
)
from app.schemas.schemas import (
    CVEResponse, CVEDetailResponse, AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate, PaginatedResponse, DashboardOverview
)

router = APIRouter()


# NVD API Client
class NVDClient:
    def __init__(self):
        self.base_url = settings.nvd_api_base_url
        self.api_key = settings.nvd_api_key
        self.rate_limit = settings.nvd_rate_limit_per_30s
    
    def _headers(self):
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers
    
    async def fetch_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch single CVE from NVD"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}",
                params={"cveId": cve_id},
                headers=self._headers()
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                return vulns[0].get("cve") if vulns else None
            return None
    
    async def fetch_recent(self, days: int = 7, start_index: int = 0, results_per_page: int = 100) -> dict:
        """Fetch recent CVEs from NVD"""
        pub_start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                f"{self.base_url}",
                params={
                    "pubStartDate": pub_start,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                },
                headers=self._headers()
            )
            if resp.status_code == 200:
                return resp.json()
            return {"vulnerabilities": [], "totalResults": 0}


nvd_client = NVDClient()


def parse_nvd_cve(nvd_cve: dict) -> dict:
    """Parse NVD CVE JSON to our schema"""
    cve_id = nvd_cve.get("id", "")
    
    # Descriptions
    descriptions = nvd_cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
    
    # CVSS v3
    cvss_v3_score = None
    cvss_v3_severity = None
    cvss_v3_vector = None
    metrics = nvd_cve.get("metrics", {})
    cvss_v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_v3_list:
        cvss_data = cvss_v3_list[0].get("cvssData", {})
        cvss_v3_score = cvss_data.get("baseScore")
        cvss_v3_severity = cvss_data.get("baseSeverity")
        cvss_v3_vector = cvss_data.get("vectorString")
    
    # CVSS v2
    cvss_v2_score = None
    cvss_v2_severity = None
    cvss_v2_list = metrics.get("cvssMetricV2", [])
    if cvss_v2_list:
        cvss_data = cvss_v2_list[0].get("cvssData", {})
        cvss_v2_score = cvss_data.get("baseScore")
        cvss_v2_severity = cvss_data.get("baseSeverity")
    
    # CPE matches
    cpe_matches = []
    configurations = nvd_cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches_list = node.get("cpeMatch", [])
            for match in cpe_matches_list:
                if match.get("vulnerable"):
                    cpe_matches.append(match.get("criteria"))
    
    # References
    references = []
    for ref in nvd_cve.get("references", []):
        references.append(ref.get("url"))
    
    # Vendor advisory URL (heuristic: look for vendor.com in references)
    vendor_advisory_url = None
    for ref in references:
        if any(v in ref for v in ["advisory", "security", "bulletin", "patch"]):
            vendor_advisory_url = ref
            break
    
    # Dates
    published = nvd_cve.get("published")
    last_modified = nvd_cve.get("lastModified")
    
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_severity": cvss_v3_severity,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v2_score": cvss_v2_score,
        "cvss_v2_severity": cvss_v2_severity,
        "cpe_matches": cpe_matches if cpe_matches else None,
        "published_date": datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
        "last_modified_date": datetime.fromisoformat(last_modified.replace("Z", "+00:00")) if last_modified else None,
        "references": references if references else None,
        "vendor_advisory_url": vendor_advisory_url,
        "sources": ["nvd"],
        "nvd_fetched_at": datetime.utcnow(),
    }


@router.get("", response_model=PaginatedResponse)
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[CVESeverity] = None,
    search: Optional[str] = None,
    has_assets: Optional[bool] = None,
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
):
    query = db.query(CVE)
    
    if severity:
        query = query.filter(CVE.cvss_v3_severity == severity)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                CVE.cve_id.ilike(search_term),
                CVE.description.ilike(search_term),
            )
        )
    if has_assets is not None:
        if has_assets:
            query = query.filter(CVE.asset_matches.any())
        else:
            query = query.filter(~CVE.asset_matches.any())
    if days:
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(CVE.published_date >= cutoff)
    
    total = query.count()
    cves = query.order_by(desc(CVE.published_date)).offset((page - 1) * page_size).limit(page_size).all()
    
    # Add counts
    cve_ids = [c.id for c in cves]
    asset_counts = {}
    feed_counts = {}
    if cve_ids:
        a_counts = db.query(
            AssetVulnerability.cve_id,
            func.count(AssetVulnerability.id)
        ).filter(AssetVulnerability.cve_id.in_(cve_ids)).group_by(AssetVulnerability.cve_id).all()
        asset_counts = {cid: count for cid, count in a_counts}
        
        f_counts = db.query(
            FeedItemCVE.cve_id,
            func.count(FeedItemCVE.id)
        ).filter(FeedItemCVE.cve_id.in_(cve_ids)).group_by(FeedItemCVE.cve_id).all()
        feed_counts = {cid: count for cid, count in f_counts}
    
    items = []
    for cve in cves:
        item_dict = CVEResponse.model_validate(cve).model_dump()
        item_dict["asset_count"] = asset_counts.get(cve.id, 0)
        item_dict["feed_count"] = feed_counts.get(cve.id, 0)
        items.append(item_dict)
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{cve_id}", response_model=CVEDetailResponse)
async def get_cve_detail(cve_id: int, db: Session = Depends(get_db)):
    """Scheda dettaglio CVE compatta (3.5)"""
    cve = db.query(CVE).filter(CVE.id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE non trovata")
    
    # Asset coinvolti
    asset_links = db.query(AssetVulnerability).filter(
        AssetVulnerability.cve_id == cve_id
    ).all()
    
    affected_assets = []
    for link in asset_links:
        asset = db.query(Asset).filter(Asset.id == link.asset_id).first()
        if asset:
            affected_assets.append({
                "id": asset.id,
                "nome": asset.nome,
                "vendor": asset.vendor,
                "versione": asset.versione,
                "match_type": link.match_type.value,
                "triage_status": link.triage_status.value,
            })
    
    # Feed references
    feed_links = db.query(FeedItemCVE).filter(FeedItemCVE.cve_id == cve_id).all()
    feed_references = []
    for link in feed_links:
        feed = db.query(FeedItem).filter(FeedItem.id == link.feed_item_id).first()
        if feed:
            feed_references.append({
                "feed_item_id": feed.id,
                "title": feed.title,
                "source": feed.source.value,
                "source_name": feed.source_name,
                "url": feed.url,
                "published_at": feed.published_at,
            })
    
    result = CVEDetailResponse.model_validate(cve).model_dump()
    result["affected_assets"] = affected_assets
    result["feed_references"] = feed_references
    return result


@router.get("/by-id/{cve_id_str}", response_model=CVEDetailResponse)
async def get_cve_by_id_string(cve_id_str: str, db: Session = Depends(get_db)):
    """Lookup CVE by string ID (e.g., CVE-2024-12345)"""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id_str.upper()).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE non trovata")
    return await get_cve_detail(cve.id, db)


@router.post("/sync/nvd")
async def sync_nvd(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
):
    """Sync recent CVEs from NVD API"""
    imported = 0
    updated = 0
    errors = []
    
    # Fetch in batches
    start_index = 0
    batch_size = 100
    
    while True:
        data = await nvd_client.fetch_recent(days=days, start_index=start_index, results_per_page=batch_size)
        vulns = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        if not vulns:
            break
        
        for vuln_wrapper in vulns:
            try:
                nvd_cve = vuln_wrapper.get("cve", {})
                parsed = parse_nvd_cve(nvd_cve)
                cve_id_str = parsed["cve_id"]
                
                existing = db.query(CVE).filter(CVE.cve_id == cve_id_str).first()
                
                if existing:
                    # Update
                    for key, value in parsed.items():
                        if key != "cve_id":
                            # Merge sources
                            if key == "sources" and existing.sources:
                                sources = set(existing.sources)
                                sources.update(value)
                                setattr(existing, key, list(sources))
                            else:
                                setattr(existing, key, value)
                    existing.updated_at = datetime.utcnow()
                    updated += 1
                else:
                    # Create new
                    new_cve = CVE(**parsed)
                    db.add(new_cve)
                    imported += 1
                    
            except Exception as e:
                errors.append(f"{nvd_cve.get('id', 'unknown')}: {str(e)}")
        
        db.commit()
        start_index += batch_size
        if start_index >= total_results:
            break
    
    return {
        "imported": imported,
        "updated": updated,
        "errors": errors,
    }


@router.post("/correlate")
async def correlate_cves(db: Session = Depends(get_db)):
    """Esegue correlazione CVE ↔ Asset (CPE match + fallback testuale)"""
    from app.services.correlation import correlate_all
    return await correlate_all(db)


@router.patch("/asset-vuln/{av_id}", response_model=AssetVulnerabilityResponse)
async def update_asset_vuln_triage(
    av_id: int,
    update: AssetVulnerabilityUpdate,
    db: Session = Depends(get_db),
):
    """Aggiorna stato triage vulnerabilità su asset"""
    av = db.query(AssetVulnerability).filter(AssetVulnerability.id == av_id).first()
    if not av:
        raise HTTPException(status_code=404, detail="Link asset-CVE non trovato")
    
    if update.triage_status is not None:
        av.triage_status = update.triage_status
        av.triage_updated_at = datetime.utcnow()
        av.triage_updated_by = "user"  # TODO: utente reale
        if update.triage_status == TriagStatus.MITIGATA:
            av.acknowledged_at = datetime.utcnow()
    
    if update.triage_notes is not None:
        av.triage_notes = update.triage_notes
    
    db.commit()
    db.refresh(av)
    return AssetVulnerabilityResponse.model_validate(av)


@router.get("/asset/{asset_id}/vulnerabilities", response_model=List[AssetVulnerabilityResponse])
async def get_asset_vulnerabilities(
    asset_id: int,
    triage_status: Optional[TriagStatus] = None,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset non trovato")
    
    query = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset_id)
    if triage_status:
        query = query.filter(AssetVulnerability.triage_status == triage_status)
    
    vulns = query.order_by(desc(AssetVulnerability.detected_at)).all()
    return [AssetVulnerabilityResponse.model_validate(v) for v in vulns]


@router.post("/correlate-asset/{asset_id}")
async def correlate_asset(asset_id: int, db: Session = Depends(get_db)):
    """Correlazione per singolo asset"""
    from app.services.correlation import correlate_asset as corr_asset
    return await corr_asset(db, asset_id)


@router.get("/asset-vuln-stats")
async def asset_vuln_stats(db: Session = Depends(get_db)):
    """Statistiche correlazione asset-CVE"""
    from app.models.models import MatchType, TriagStatus
    
    # By match type
    by_match = db.query(
        AssetVulnerability.match_type,
        func.count(AssetVulnerability.id)
    ).group_by(AssetVulnerability.match_type).all()
    
    # By triage status
    by_triage = db.query(
        AssetVulnerability.triage_status,
        func.count(AssetVulnerability.id)
    ).group_by(AssetVulnerability.triage_status).all()
    
    # By severity
    by_sev = db.query(
        CVE.cvss_v3_severity,
        func.count(AssetVulnerability.id)
    ).join(CVE).group_by(CVE.cvss_v3_severity).all()
    
    return {
        "by_match_type": [{"match_type": m.value, "count": c} for m, c in by_match],
        "by_triage": [{"triage_status": t.value, "count": c} for t, c in by_triage],
        "by_severity": [{"severity": s.value if s else "NONE", "count": c} for s, c in by_sev],
    }