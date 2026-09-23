from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.models.models import ImportBatch
from app.schemas.schemas import ImportBatchResponse, PaginatedResponse

router = APIRouter()


@router.get("", response_model=List[ImportBatchResponse])
async def list_import_batches(
    import_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(ImportBatch)
    
    if import_type:
        query = query.filter(ImportBatch.import_type == import_type)
    if status:
        query = query.filter(ImportBatch.status == status)
    
    batches = query.order_by(desc(ImportBatch.started_at)).limit(limit).all()
    return [ImportBatchResponse.model_validate(b) for b in batches]


@router.get("/{batch_id}", response_model=ImportBatchResponse)
async def get_import_batch(batch_id: str, db: Session = Depends(get_db)):
    batch = db.query(ImportBatch).filter(ImportBatch.batch_id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch non trovato")
    return ImportBatchResponse.model_validate(batch)


@router.delete("/{batch_id}")
async def delete_import_batch(batch_id: str, db: Session = Depends(get_db)):
    batch = db.query(ImportBatch).filter(ImportBatch.batch_id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch non trovato")
    
    db.delete(batch)
    db.commit()
    return {"message": "Batch eliminato"}