from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.models.models import Provider, UserRole
from app.api.deps import require_role
from app.schemas.schemas import ProviderCreate, ProviderResponse

router = APIRouter()


@router.get("", response_model=List[ProviderResponse])
async def list_providers(
    scope: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Provider)
    if is_active is not None:
        query = query.filter(Provider.is_active == is_active)
    
    providers = query.order_by(Provider.name).all()
    if scope:
        providers = [p for p in providers if scope in (p.scopes or [])]
    
    return [ProviderResponse.from_orm(p) for p in providers]


@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Fornitore non trovato")
    return ProviderResponse.from_orm(provider)


@router.post("", response_model=ProviderResponse, status_code=201, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def create_provider(data: ProviderCreate, db: Session = Depends(get_db)):
    existing = db.query(Provider).filter(Provider.code == data.code).first()
    if existing:
        raise HTTPException(status_code=400, detail="Codice Fornitore già registrato")
    
    provider = Provider(**data.dict())
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return ProviderResponse.from_orm(provider)


@router.patch("/{provider_id}", response_model=ProviderResponse, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def update_provider(provider_id: int, data: dict, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Fornitore non trovato")
    
    if "code" in data and data["code"] != provider.code:
        existing = db.query(Provider).filter(Provider.code == data["code"]).first()
        if existing:
            raise HTTPException(status_code=400, detail="Codice Fornitore già in uso")

    for key, value in data.items():
        if hasattr(provider, key) and key != "id":
            setattr(provider, key, value)
    
    db.commit()
    db.refresh(provider)
    return ProviderResponse.from_orm(provider)


@router.delete("/{provider_id}", status_code=204, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def delete_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Fornitore non trovato")
    
    db.delete(provider)
    db.commit()
