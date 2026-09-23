from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import UserSettings

router = APIRouter()


class SettingValue(BaseModel):
    value: Any
    description: Optional[str] = None


@router.get("")
async def get_all_settings(db: Session = Depends(get_db)):
    settings = db.query(UserSettings).all()
    return {s.key: {"value": s.value, "description": s.description} for s in settings}


@router.get("/{key}")
async def get_setting(key: str, db: Session = Depends(get_db)):
    setting = db.query(UserSettings).filter(UserSettings.key == key).first()
    if not setting:
        raise HTTPException(status_code=404, detail="Impostazione non trovata")
    return {"key": setting.key, "value": setting.value, "description": setting.description}


@router.put("/{key}")
async def set_setting(key: str, data: SettingValue, db: Session = Depends(get_db)):
    setting = db.query(UserSettings).filter(UserSettings.key == key).first()
    if setting:
        setting.value = data.value
        if data.description:
            setting.description = data.description
    else:
        setting = UserSettings(key=key, value=data.value, description=data.description)
        db.add(setting)
    
    db.commit()
    db.refresh(setting)
    return {"key": setting.key, "value": setting.value, "description": setting.description}


@router.delete("/{key}")
async def delete_setting(key: str, db: Session = Depends(get_db)):
    setting = db.query(UserSettings).filter(UserSettings.key == key).first()
    if not setting:
        raise HTTPException(status_code=404, detail="Impostazione non trovata")
    
    db.delete(setting)
    db.commit()
    return {"message": "Impostazione eliminata"}


# Default settings initialization
DEFAULT_SETTINGS = {
    "correlation": {
        "value": {
            "textual_threshold": 0.7,
            "auto_correlate_on_import": True,
            "include_partial_cpe": True,
        },
        "description": "Configurazione motore di correlazione CVE-Asset"
    },
    "nvd_sync": {
        "value": {
            "enabled": True,
            "interval_hours": 6,
            "days_back": 7,
        },
        "description": "Configurazione sincronizzazione NVD"
    },
    "feedhub": {
        "value": {
            "auto_import_enabled": False,
            "import_directory": "/app/data/feedhub_imports",
        },
        "description": "Configurazione FeedHub"
    },
    "syslog": {
        "value": {
            "auto_match_assets": True,
            "auto_find_cves": True,
            "retention_days": 30,
        },
        "description": "Configurazione syslog"
    },
    "dashboard": {
        "value": {
            "refresh_interval_seconds": 30,
            "show_textual_matches": True,
            "default_page_size": 50,
        },
        "description": "Configurazione dashboard"
    },
}


@router.post("/init-defaults")
async def init_default_settings(db: Session = Depends(get_db)):
    created = 0
    for key, data in DEFAULT_SETTINGS.items():
        existing = db.query(UserSettings).filter(UserSettings.key == key).first()
        if not existing:
            setting = UserSettings(key=key, value=data["value"], description=data["description"])
            db.add(setting)
            created += 1
    db.commit()
    return {"created": created}