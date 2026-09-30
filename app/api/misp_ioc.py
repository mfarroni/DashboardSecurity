from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from typing import List, Optional
import httpx

from app.core.database import get_db
from app.models.models import IOCEntry, IOCType, Provider, UserRole
from app.api.deps import require_role, get_current_user_optional
from app.schemas.schemas import IOCEntryResponse, PaginatedResponse
from app.services.ioc_service import process_ioc_file_import, upsert_ioc_entry, detect_ioc_type

router = APIRouter()


@router.get("", response_model=PaginatedResponse)
async def list_ioc_entries(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[IOCType] = None,
    threat_level: Optional[str] = None,
    min_relevance: Optional[float] = Query(None, ge=0.0, le=100.0),
    search: Optional[str] = None,
    provider: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(IOCEntry)

    if ioc_type:
        query = query.filter(IOCEntry.ioc_type == ioc_type)
    if threat_level:
        query = query.filter(IOCEntry.threat_level == threat_level)
    if min_relevance is not None:
        query = query.filter(IOCEntry.relevance_score >= min_relevance)
    if search:
        s = f"%{search}%"
        query = query.filter(
            or_(
                IOCEntry.value.ilike(s),
                IOCEntry.description.ilike(s)
            )
        )

    iocs = query.order_by(desc(IOCEntry.relevance_score), desc(IOCEntry.updated_at)).all()

    if provider:
        iocs = [i for i in iocs if provider in (i.providers or [])]

    total = len(iocs)
    start = (page - 1) * page_size
    paged_items = iocs[start:start + page_size]

    items = [IOCEntryResponse.from_orm(item).dict() for item in paged_items]

    if request.headers.get("hx-request"):
        if not items:
            return HTMLResponse('<tr><td colspan="7" class="px-4 py-8 text-center text-gray-500">Nessun Indice di Compromissione (IoC) registrato</td></tr>')

        html = ""
        for ioc in items:
            score = ioc["relevance_score"]
            if score >= 100:
                score_badge = f'<span class="px-2 py-0.5 rounded text-xs bg-red-100 text-red-800 font-bold">🔴 {score:.0f}% (Critico)</span>'
            elif score >= 75:
                score_badge = f'<span class="px-2 py-0.5 rounded text-xs bg-orange-100 text-orange-800 font-bold">🟠 {score:.0f}% (Alto)</span>'
            elif score >= 50:
                score_badge = f'<span class="px-2 py-0.5 rounded text-xs bg-yellow-100 text-yellow-800 font-bold">🟡 {score:.0f}% (Medio)</span>'
            else:
                score_badge = f'<span class="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">⚪ {score:.0f}%</span>'

            provs = ", ".join(ioc["providers"]) if ioc["providers"] else "-"
            tags_html = "".join([f'<span class="bg-blue-50 text-blue-700 text-xs px-1.5 py-0.5 rounded mr-1">{t}</span>' for t in (ioc.get("tags") or [])])

            html += f'''
            <tr class="table-row border-b border-gray-100 hover:bg-gray-50">
                <td class="px-3 py-3 w-10 text-center">
                    <input type="checkbox" class="ioc-checkbox rounded border-gray-300 text-blue-600 focus:ring-blue-500" value="{ioc['id']}" onchange="updateIocBulkDeleteBtn()">
                </td>
                <td class="px-4 py-3 text-xs font-semibold text-gray-700 uppercase">{ioc['ioc_type']}</td>
                <td class="px-4 py-3 text-xs font-mono font-medium text-gray-900 break-all">{ioc['value']}</td>
                <td class="px-4 py-3 text-xs text-gray-600">{provs}</td>
                <td class="px-4 py-3 text-xs text-gray-500">{tags_html or '-'}</td>
                <td class="px-4 py-3 text-xs" title="{ioc.get('relevance_reason', '')}">{score_badge}</td>
                <td class="px-4 py-3 text-xs text-right">
                    <button onclick="deleteIoc({ioc['id']})" class="text-red-600 hover:text-red-800 text-xs" title="Elimina"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
            '''
        return HTMLResponse(html)

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total > 0 else 1
    )


@router.post("/import/async", dependencies=[Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))])
async def import_misp_ioc_async(
    files: List[UploadFile] = File(...),
    provider_name: str = Form("Generico"),
    db: Session = Depends(get_db)
):
    """Importazione asincrona multi-file di IoC/MISP (JSON, STIX, CSV, TXT)"""
    total_imported = 0
    total_failed = 0
    all_errors = []

    for file in files:
        content = await file.read()
        filename = file.filename or "file.txt"
        imp, fail, errs = process_ioc_file_import(db, content, filename, provider_name)
        total_imported += imp
        total_failed += fail
        all_errors.extend(errs)

    return {
        "files_processed": len(files),
        "records_imported": total_imported,
        "records_failed": total_failed,
        "errors": all_errors[:20]
    }


@router.post("/sync/provider/{provider_id}", dependencies=[Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))])
async def sync_provider_sincrono(provider_id: int, db: Session = Depends(get_db)):
    """Interrogazione sincrona diretta al fornitore via API Key ed Endpoint URL"""
    prov = db.query(Provider).filter(Provider.id == provider_id).first()
    if not prov or not prov.is_active:
        raise HTTPException(status_code=404, detail="Fornitore non trovato o disattivato")

    if not prov.endpoint_url:
        raise HTTPException(status_code=400, detail="Endpoint URL non configurato per questo fornitore")

    headers = {}
    if prov.api_key:
        headers["Authorization"] = f"Bearer {prov.api_key}"
        headers["Authorization-Key"] = prov.api_key

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(prov.endpoint_url, headers=headers)
            if res.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Risposta server fornitore HTTP {res.status_code}")
            
            imp, fail, errs = process_ioc_file_import(db, res.content, "api_feed.json", prov.name)
            return {
                "provider": prov.name,
                "records_imported": imp,
                "records_failed": fail,
                "errors": errs
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore di connessione al fornitore: {str(e)}")


@router.delete("/{ioc_id}", status_code=204, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def delete_ioc_entry(ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOCEntry).filter(IOCEntry.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC non trovato")
    db.delete(ioc)
    db.commit()


@router.post("/bulk-delete", dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def bulk_delete_iocs(body: dict, db: Session = Depends(get_db)):
    ioc_ids = body.get("ioc_ids", [])
    if not ioc_ids:
        raise HTTPException(status_code=400, detail="Nessun IoC selezionato")
    deleted = db.query(IOCEntry).filter(IOCEntry.id.in_(ioc_ids)).delete(synchronize_session=False)
    db.commit()
    return {"deleted_count": deleted}
