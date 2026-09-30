import json
import re
from datetime import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.models.models import IOCEntry, IOCType, Provider
from app.services.relevance_calculator import calculate_ioc_relevance


IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
URL_REGEX = re.compile(r'^https?://', re.IGNORECASE)


def detect_ioc_type(value: str) -> IOCType:
    val = value.strip()
    if IP_REGEX.match(val):
        return IOCType.IP
    elif MD5_REGEX.match(val):
        return IOCType.HASH_MD5
    elif SHA256_REGEX.match(val):
        return IOCType.HASH_SHA256
    elif URL_REGEX.match(val):
        return IOCType.URL
    elif DOMAIN_REGEX.match(val):
        return IOCType.DOMAIN
    elif val.startswith("rule ") or "strings:" in val or "condition:" in val:
        return IOCType.YARA
    return IOCType.OTHER


def upsert_ioc_entry(
    db: Session,
    ioc_type: IOCType,
    value: str,
    provider_name: str,
    description: str = None,
    threat_level: str = "MEDIUM",
    tags: List[str] = None,
    raw_data: Dict[str, Any] = None
) -> IOCEntry:
    val_clean = value.strip()
    if not val_clean:
        return None

    existing = db.query(IOCEntry).filter(
        IOCEntry.ioc_type == ioc_type,
        IOCEntry.value == val_clean
    ).first()

    now = datetime.utcnow()
    score, reason = calculate_ioc_relevance(db, ioc_type.value if hasattr(ioc_type, 'value') else ioc_type, val_clean, raw_data)

    if existing:
        # Merge providers list
        current_providers = existing.providers or []
        if provider_name and provider_name not in current_providers:
            current_providers.append(provider_name)
        existing.providers = current_providers

        # Merge tags
        if tags:
            current_tags = set(existing.tags or [])
            current_tags.update(tags)
            existing.tags = list(current_tags)

        existing.last_seen = now
        existing.relevance_score = score
        existing.relevance_reason = reason
        if description and not existing.description:
            existing.description = description
        if threat_level and threat_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            existing.threat_level = threat_level
        db.commit()
        db.refresh(existing)
        return existing
    else:
        new_entry = IOCEntry(
            ioc_type=ioc_type,
            value=val_clean,
            description=description or f"IoC importato da {provider_name}",
            threat_level=threat_level if threat_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM",
            tags=tags or [],
            providers=[provider_name] if provider_name else ["Generico"],
            first_seen=now,
            last_seen=now,
            raw_data=raw_data,
            relevance_score=score,
            relevance_reason=reason,
            created_at=now,
            updated_at=now
        )
        db.add(new_entry)
        db.commit()
        db.refresh(new_entry)
        return new_entry


def parse_misp_or_json_content(content_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse MISP JSON format or standard JSON array of IoCs"""
    try:
        data = json.loads(content_bytes.decode('utf-8'))
    except Exception:
        return []

    items = []
    # MISP Format: {"response": [{"Event": {"Attribute": [...]}}]} or {"Event": {"Attribute": [...]}}
    events = []
    if isinstance(data, dict):
        if "response" in data and isinstance(data["response"], list):
            events = data["response"]
        elif "Event" in data:
            events = [data]
        elif "items" in data and isinstance(data["items"], list):
            events = data["items"]

    if events:
        for ev in events:
            event_obj = ev.get("Event", ev)
            attributes = event_obj.get("Attribute", event_obj.get("attributes", []))
            tags = [t.get("name", "") for t in event_obj.get("Tag", [])]
            info = event_obj.get("info", "")
            threat_level_id = str(event_obj.get("threat_level_id", "2"))
            threat_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
            threat_lvl = threat_map.get(threat_level_id, "MEDIUM")

            for attr in attributes:
                val = attr.get("value")
                attr_type = attr.get("type", "")
                if val:
                    items.append({
                        "value": val,
                        "type": attr_type,
                        "description": f"{info} ({attr.get('comment', '')})".strip(),
                        "threat_level": threat_lvl,
                        "tags": tags,
                        "raw": attr
                    })

    # Generic JSON list
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                val = entry.get("value") or entry.get("ioc") or entry.get("indicator")
                if val:
                    items.append({
                        "value": val,
                        "type": entry.get("type", ""),
                        "description": entry.get("description", ""),
                        "threat_level": entry.get("threat_level", "MEDIUM"),
                        "tags": entry.get("tags", []),
                        "raw": entry
                    })
            elif isinstance(entry, str):
                items.append({"value": entry, "type": "", "description": "", "threat_level": "MEDIUM", "tags": []})

    return items


def process_ioc_file_import(db: Session, content_bytes: bytes, filename: str, provider_name: str) -> Tuple[int, int, List[str]]:
    """Process file import (JSON/STIX/CSV/TXT) and return (imported, failed, errors)"""
    errors = []
    imported = 0
    failed = 0

    if filename.endswith(".json"):
        parsed = parse_misp_or_json_content(content_bytes)
        for item in parsed:
            val = item["value"]
            ioc_tp = detect_ioc_type(val)
            try:
                upsert_ioc_entry(
                    db,
                    ioc_type=ioc_tp,
                    value=val,
                    provider_name=provider_name,
                    description=item.get("description"),
                    threat_level=item.get("threat_level", "MEDIUM"),
                    tags=item.get("tags"),
                    raw_data=item.get("raw")
                )
                imported += 1
            except Exception as e:
                failed += 1
                errors.append(f"Errore voce '{val}': {str(e)}")

    else: # TXT / CSV line by line
        lines = content_bytes.decode('utf-8', errors='ignore').splitlines()
        for line in lines:
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue
            # Simple CSV split if comma present
            parts = line_clean.split(",")
            val = parts[0].strip()
            if not val:
                continue
            ioc_tp = detect_ioc_type(val)
            try:
                upsert_ioc_entry(
                    db,
                    ioc_type=ioc_tp,
                    value=val,
                    provider_name=provider_name,
                    description=f"Importato da file {filename}",
                    threat_level="MEDIUM"
                )
                imported += 1
            except Exception as e:
                failed += 1
                errors.append(f"Errore riga '{val}': {str(e)}")

    return imported, failed, errors
