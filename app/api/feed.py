from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, and_
from typing import List, Optional
import pandas as pd
import io
import uuid
import re
from datetime import datetime, timedelta

from app.core.database import get_db
from app.models.models import (
    FeedItem, CVE, FeedItemCVE, ImportBatch, FeedSourceType, CVESeverity
)
from app.schemas.schemas import (
    FeedItemResponse, FeedItemCreate, CVEResponse, CVEDetailResponse,
    ImportBatchResponse, ImportPreviewResponse, PaginatedResponse
)

router = APIRouter()


# CVE regex pattern
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    """Estrae CVE-ID dal testo"""
    if not text:
        return []
    matches = CVE_PATTERN.findall(text)
    return list(set(m.upper() for m in matches))


@router.get("", response_model=PaginatedResponse)
async def list_feed_items(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source: Optional[FeedSourceType] = None,
    search: Optional[str] = None,
    has_cve: Optional[bool] = None,
    days: Optional[int] = Query(None, ge=1, le=365),
    db: Session = Depends(get_db),
):
    query = db.query(FeedItem)
    
    if source:
        query = query.filter(FeedItem.source == source)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                FeedItem.title.ilike(search_term),
                FeedItem.content.ilike(search_term),
                FeedItem.source_name.ilike(search_term),
            )
        )
    if has_cve is not None:
        if has_cve:
            query = query.filter(FeedItem.extracted_cves.isnot(None))
        else:
            query = query.filter(FeedItem.extracted_cves.is_(None))
    if days:
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(FeedItem.collected_at >= cutoff)
    
    total = query.count()
    items = query.order_by(desc(FeedItem.collected_at)).offset((page - 1) * page_size).limit(page_size).all()
    
    # Add CVE count
    item_ids = [i.id for i in items]
    cve_counts = {}
    if item_ids:
        counts = db.query(
            FeedItemCVE.feed_item_id,
            func.count(FeedItemCVE.id)
        ).filter(FeedItemCVE.feed_item_id.in_(item_ids)).group_by(FeedItemCVE.feed_item_id).all()
        cve_counts = {fid: count for fid, count in counts}
    
    result_items = []
    for item in items:
        item_dict = FeedItemResponse.model_validate(item).model_dump()
        item_dict["cve_count"] = cve_counts.get(item.id, 0)
        result_items.append(item_dict)
    
    return PaginatedResponse(
        items=result_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{item_id}", response_model=FeedItemResponse)
async def get_feed_item(item_id: int, db: Session = Depends(get_db)):
    item = db.query(FeedItem).filter(FeedItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Feed item non trovato")
    return FeedItemResponse.model_validate(item)


@router.post("/import/feedhub", response_model=ImportBatchResponse)
async def import_feedhub_file(
    file: UploadFile = File(...),
    batch_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Import feed da file JSON/CSV esportato da FeedHub"""
    import json
    
    content = await file.read()
    filename = file.filename or "unknown"
    batch_id = batch_id or str(uuid.uuid4())
    
    batch = ImportBatch(
        batch_id=batch_id,
        import_type="feedhub",
        filename=filename,
        status="running",
    )
    db.add(batch)
    db.commit()
    
    try:
        if filename.endswith(".json"):
            data = json.loads(content)
            # Supporta sia array che oggetto con chiave "items"
            items = data if isinstance(data, list) else data.get("items", [])
        elif filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content))
            items = df.to_dict("records")
        else:
            raise ValueError("Formato non supportato. Usa JSON o CSV")
        
        imported = 0
        failed = 0
        errors = []
        
        for idx, item_data in enumerate(items):
            try:
                # Estrai CVE dal contenuto
                content_text = item_data.get("content") or item_data.get("summary") or item_data.get("description") or ""
                title = item_data.get("title") or item_data.get("headline") or ""
                extracted = extract_cves(f"{title} {content_text}")
                
                feed_item = FeedItem(
                    source=FeedSourceType.FEEDHUB,
                    source_id=item_data.get("id") or item_data.get("url") or f"import_{idx}",
                    title=title,
                    url=item_data.get("url") or item_data.get("link"),
                    source_name=item_data.get("source") or item_data.get("feed_name") or "FeedHub",
                    published_at=pd.to_datetime(item_data.get("published") or item_data.get("date") or item_data.get("published_at")).to_pydatetime() if item_data.get("published") or item_data.get("date") or item_data.get("published_at") else None,
                    content=content_text,
                    summary=item_data.get("summary") or item_data.get("excerpt"),
                    tags=item_data.get("tags") or item_data.get("categories"),
                    raw_data=item_data,
                    extracted_cves=extracted if extracted else None,
                )
                db.add(feed_item)
                db.flush()  # Get ID
                
                # Link CVE se esistenti nel DB
                for cve_id_str in extracted:
                    cve = db.query(CVE).filter(CVE.cve_id == cve_id_str).first()
                    if cve:
                        link = FeedItemCVE(
                            feed_item_id=feed_item.id,
                            cve_id=cve.id,
                            extraction_method="regex",
                            context_snippet=content_text[:500] if content_text else None,
                        )
                        db.add(link)
                        # Aggiorna fonti CVE
                        if cve.sources:
                            sources = set(cve.sources)
                        else:
                            sources = set()
                        sources.add("feedhub")
                        cve.sources = list(sources)
                
                imported += 1
                
            except Exception as e:
                failed += 1
                errors.append(f"Item {idx}: {str(e)}")
        
        db.commit()
        
        batch.records_total = len(items)
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


@router.post("/import/cti", response_model=ImportBatchResponse)
async def import_cti_file(
    file: UploadFile = File(...),
    source_name: str = Form("CTI"),
    batch_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Import feed CTI (MISP, Patch Tuesday, ecc.)"""
    import json
    
    content = await file.read()
    filename = file.filename or "unknown"
    batch_id = batch_id or str(uuid.uuid4())
    
    batch = ImportBatch(
        batch_id=batch_id,
        import_type="cti",
        filename=filename,
        status="running",
    )
    db.add(batch)
    db.commit()
    
    try:
        if filename.endswith(".json"):
            data = json.loads(content)
            # Formato MISP/STIX generico
            items = data if isinstance(data, list) else data.get("objects", data.get("events", []))
        elif filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content))
            items = df.to_dict("records")
        else:
            raise ValueError("Formato non supportato. Usa JSON o CSV")
        
        imported = 0
        failed = 0
        errors = []
        
        for idx, item_data in enumerate(items):
            try:
                # Estrai CVE - cerca in vari campi comuni
                cve_fields = [
                    "cve", "cve_id", "cve_ids", "vulnerability_id", "vuln_id",
                    "attribute_value", "value", "indicator"
                ]
                extracted = set()
                for field in cve_fields:
                    val = item_data.get(field)
                    if val:
                        if isinstance(val, list):
                            for v in val:
                                extracted.update(extract_cves(str(v)))
                        else:
                            extracted.update(extract_cves(str(val)))
                
                # Anche da titolo/descrizione
                title = item_data.get("title") or item_data.get("name") or item_data.get("info") or ""
                desc = item_data.get("description") or item_data.get("desc") or ""
                extracted.update(extract_cves(f"{title} {desc}"))
                
                feed_item = FeedItem(
                    source=FeedSourceType.CTI,
                    source_id=str(item_data.get("id") or item_data.get("uuid") or f"cti_{idx}"),
                    title=title[:500] if title else f"CTI Item {idx}",
                    url=item_data.get("url") or item_data.get("link"),
                    source_name=source_name,
                    published_at=pd.to_datetime(item_data.get("timestamp") or item_data.get("date") or item_data.get("published")).to_pydatetime() if item_data.get("timestamp") or item_data.get("date") or item_data.get("published") else None,
                    content=desc,
                    summary=item_data.get("summary"),
                    tags=item_data.get("tags") or item_data.get("galaxy", []),
                    raw_data=item_data,
                    extracted_cves=list(extracted) if extracted else None,
                )
                db.add(feed_item)
                db.flush()
                
                for cve_id_str in extracted:
                    cve = db.query(CVE).filter(CVE.cve_id == cve_id_str).first()
                    if cve:
                        link = FeedItemCVE(
                            feed_item_id=feed_item.id,
                            cve_id=cve.id,
                            extraction_method="structured",
                        )
                        db.add(link)
                        if cve.sources:
                            sources = set(cve.sources)
                        else:
                            sources = set()
                        sources.add("cti")
                        cve.sources = list(sources)
                
                imported += 1
                
            except Exception as e:
                failed += 1
                errors.append(f"Item {idx}: {str(e)}")
        
        db.commit()
        
        batch.records_total = len(items)
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
async def feed_import_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    batches = db.query(ImportBatch).filter(
        ImportBatch.import_type.in_(["feedhub", "cti"])
    ).order_by(desc(ImportBatch.started_at)).limit(limit).all()
    return [ImportBatchResponse.model_validate(b) for b in batches]