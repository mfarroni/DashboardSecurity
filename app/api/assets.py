from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc
from typing import List, Optional
import pandas as pd
import io
import uuid
from datetime import datetime

from app.core.database import get_db
from app.models.models import Asset, ImportBatch, AssetType, AssetCriticality
from app.schemas.schemas import (
    AssetResponse, AssetCreate, AssetUpdate, AssetImportRow,
    ImportBatchResponse, ImportPreviewResponse, PaginatedResponse
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    tipo: Optional[AssetType] = None,
    criticita: Optional[AssetCriticality] = None,
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
    
    total = query.count()
    assets = query.order_by(desc(Asset.updated_at)).offset((page - 1) * page_size).limit(page_size).all()
    
    # Add vulnerability count
    asset_ids = [a.id for a in assets]
    vuln_counts = {}
    if asset_ids:
        from app.models.models import AssetVulnerability
        counts = db.query(
            AssetVulnerability.asset_id,
            func.count(AssetVulnerability.id)
        ).filter(AssetVulnerability.asset_id.in_(asset_ids)).group_by(AssetVulnerability.asset_id).all()
        vuln_counts = {asset_id: count for asset_id, count in counts}
    
    items = []
    for asset in assets:
        asset_dict = AssetResponse.model_validate(asset).model_dump()
        asset_dict["vulnerability_count"] = vuln_counts.get(asset.id, 0)
        items.append(asset_dict)
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset non trovato")
    
    # Count vulnerabilities
    from app.models.models import AssetVulnerability
    vuln_count = db.query(func.count(AssetVulnerability.id)).filter(
        AssetVulnerability.asset_id == asset_id
    ).scalar()
    
    asset_dict = AssetResponse.model_validate(asset).model_dump()
    asset_dict["vulnerability_count"] = vuln_count
    return asset_dict


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    # Check CPE uniqueness if provided
    if asset.cpe:
        existing = db.query(Asset).filter(Asset.cpe == asset.cpe).first()
        if existing:
            raise HTTPException(status_code=400, detail="CPE già esistente")
    
    db_asset = Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return AssetResponse.model_validate(db_asset)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: int, asset_update: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset non trovato")
    
    update_data = asset_update.model_dump(exclude_unset=True)
    
    # Check CPE uniqueness if being updated
    if "cpe" in update_data and update_data["cpe"]:
        existing = db.query(Asset).filter(
            Asset.cpe == update_data["cpe"],
            Asset.id != asset_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="CPE già esistente")
    
    for field, value in update_data.items():
        setattr(asset, field, value)
    
    asset.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset non trovato")
    
    db.delete(asset)
    db.commit()


@router.post("/import/preview", response_model=ImportPreviewResponse)
async def preview_import(
    file: UploadFile = File(...),
    mapping: Optional[str] = Form(None),  # JSON string per mapping colonne
):
    """Anteprima import perimetro da CSV/Excel/JSON"""
    content = await file.read()
    filename = file.filename or "unknown"
    
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content))
        elif filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(io.BytesIO(content))
        elif filename.endswith(".json"):
            df = pd.read_json(io.BytesIO(content))
        else:
            raise HTTPException(status_code=400, detail="Formato file non supportato. Usa CSV, Excel o JSON")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Errore lettura file: {str(e)}")
    
    # Normalizza nomi colonne
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    
    # Mapping suggerito
    column_mapping = {
        "tipo": ["tipo", "type", "asset_type", "categoria"],
        "nome": ["nome", "name", "asset_name", "modello", "model"],
        "vendor": ["vendor", "produttore", "manufacturer", "fornitore"],
        "versione": ["versione", "version", "ver", "release"],
        "cpe": ["cpe", "cpe_id", "cpe23"],
        "criticita": ["criticita", "criticality", "ambito", "scope", "ambiente"],
        "note": ["note", "notes", "descrizione", "description", "commenti"],
    }
    
    suggested_mapping = {}
    for target, sources in column_mapping.items():
        for src in sources:
            if src in df.columns:
                suggested_mapping[target] = src
                break
    
    # Applica mapping custom se fornito
    if mapping:
        import json
        custom_mapping = json.loads(mapping)
        for target, source in custom_mapping.items():
            if source in df.columns:
                suggested_mapping[target] = source
    
    # Valida righe
    validation_errors = []
    required_fields = ["tipo", "nome", "vendor"]
    for idx, row in df.iterrows():
        for field in required_fields:
            col = suggested_mapping.get(field)
            if not col or pd.isna(row.get(col)):
                validation_errors.append(f"Riga {idx+2}: campo obbligatorio '{field}' mancante")
    
    # Prepara anteprima (prime 10 righe)
    preview_rows = []
    for idx, row in df.head(10).iterrows():
        preview_row = {}
        for target, source in suggested_mapping.items():
            val = row.get(source)
            preview_row[target] = None if pd.isna(val) else val
        preview_rows.append(preview_row)
    
    return ImportPreviewResponse(
        headers=list(df.columns),
        rows=preview_rows,
        row_count=len(df),
        suggested_mapping=suggested_mapping,
        validation_errors=validation_errors,
    )


@router.post("/import/execute", response_model=ImportBatchResponse)
async def execute_import(
    file: UploadFile = File(...),
    mapping: str = Form(...),  # JSON string mapping colonne
    batch_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Esegue import perimetro"""
    import json
    
    content = await file.read()
    filename = file.filename or "unknown"
    batch_id = batch_id or str(uuid.uuid4())
    
    # Crea record batch
    batch = ImportBatch(
        batch_id=batch_id,
        import_type="perimetro",
        filename=filename,
        status="running",
    )
    db.add(batch)
    db.commit()
    
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content))
        elif filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(io.BytesIO(content))
        elif filename.endswith(".json"):
            df = pd.read_json(io.BytesIO(content))
        else:
            raise ValueError("Formato file non supportato")
        
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
        column_mapping = json.loads(mapping)
        
        imported = 0
        failed = 0
        errors = []
        
        for idx, row in df.iterrows():
            try:
                asset_data = {}
                for target, source in column_mapping.items():
                    val = row.get(source)
                    if not pd.isna(val):
                        asset_data[target] = val
                
                # Valida tipo
                if asset_data.get("tipo") not in [e.value for e in AssetType]:
                    asset_data["tipo"] = AssetType.SOFTWARE  # default
                
                # Valida criticità
                if asset_data.get("criticita") and asset_data["criticita"] not in [e.value for e in AssetCriticality]:
                    asset_data["criticita"] = None
                
                # Crea asset
                asset = Asset(
                    **asset_data,
                    imported_at=datetime.utcnow(),
                    import_batch_id=batch_id,
                )
                db.add(asset)
                imported += 1
                
            except Exception as e:
                failed += 1
                errors.append(f"Riga {idx+2}: {str(e)}")
        
        db.commit()
        
        batch.records_total = len(df)
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
async def import_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    batches = db.query(ImportBatch).filter(
        ImportBatch.import_type == "perimetro"
    ).order_by(desc(ImportBatch.started_at)).limit(limit).all()
    return [ImportBatchResponse.model_validate(b) for b in batches]


@router.get("/export/current")
async def export_current_perimetro(db: Session = Depends(get_db)):
    """Esporta perimetro attuale come CSV"""
    assets = db.query(Asset).all()
    df = pd.DataFrame([{
        "tipo": a.tipo.value,
        "nome": a.nome,
        "vendor": a.vendor,
        "versione": a.versione,
        "cpe": a.cpe,
        "criticita": a.criticita.value if a.criticita else None,
        "note": a.note,
        "imported_at": a.imported_at,
        "import_batch_id": a.import_batch_id,
    } for a in assets])
    
    return df.to_csv(index=False)