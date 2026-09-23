from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from typing import List, Tuple
from datetime import datetime
import re
from difflib import SequenceMatcher

from app.models.models import Asset, CVE, AssetVulnerability, MatchType, TriagStatus


def normalize_string(s: str) -> str:
    """Normalizza stringa per confronto"""
    if not s:
        return ""
    return re.sub(r"[^\w]", "", s.lower())


def similarity(a: str, b: str) -> float:
    """Calcola similarità tra due stringhe (0-1)"""
    return SequenceMatcher(None, normalize_string(a), normalize_string(b)).ratio()


def cpe_match_score(asset_cpe: str, cve_cpe: str) -> Tuple[bool, float]:
    """
    Confronta CPE asset vs CPE CVE.
    Returns: (exact_match, confidence)
    """
    if not asset_cpe or not cve_cpe:
        return False, 0.0
    
    # Parsa CPE 2.3: cpe:2.3:a:vendor:product:version:...
    # Per match esatto, vendor:product:version devono corrispondere
    try:
        asset_parts = asset_cpe.split(":")
        cve_parts = cve_cpe.split(":")
        
        if len(asset_parts) < 6 or len(cve_parts) < 6:
            return False, 0.0
        
        # vendor (index 3), product (index 4), version (index 5)
        vendor_match = asset_parts[3] == cve_parts[3] or cve_parts[3] == "*"
        product_match = asset_parts[4] == cve_parts[4] or cve_parts[4] == "*"
        version_match = asset_parts[5] == cve_parts[5] or cve_parts[5] in ["*", "-"]
        
        if vendor_match and product_match and version_match:
            return True, 1.0
        elif vendor_match and product_match:
            return False, 0.8  # Partial - same product, version wildcard
        elif vendor_match:
            return False, 0.5  # Same vendor only
        
    except Exception:
        pass
    
    return False, 0.0


def textual_match_score(asset: Asset, cve: CVE) -> float:
    """
    Fallback testuale: confronta vendor + product + version
    """
    scores = []
    
    # Vendor match
    if asset.vendor and cve.cpe_matches:
        # Estrai vendor dai CPE della CVE
        cve_vendors = set()
        for cpe in cve.cpe_matches:
            parts = cpe.split(":")
            if len(parts) > 3:
                cve_vendors.add(parts[3])
        
        if cve_vendors:
            vendor_scores = [similarity(asset.vendor, v) for v in cve_vendors]
            scores.append(max(vendor_scores))
    
    # Product match (nome asset vs product nei CPE)
    if asset.nome and cve.cpe_matches:
        cve_products = set()
        for cpe in cve.cpe_matches:
            parts = cpe.split(":")
            if len(parts) > 4:
                cve_products.add(parts[4])
        
        if cve_products:
            product_scores = [similarity(asset.nome, p) for p in cve_products]
            scores.append(max(product_scores))
    
    # Version match
    if asset.versione and cve.cpe_matches:
        cve_versions = set()
        for cpe in cve.cpe_matches:
            parts = cpe.split(":")
            if len(parts) > 5 and parts[5] not in ["*", "-"]:
                cve_versions.add(parts[5])
        
        if cve_versions:
            version_scores = [similarity(asset.versione, v) for v in cve_versions]
            scores.append(max(version_scores))
    
    # Se non ci sono CPE, prova con descrizione
    if not scores and cve.description:
        desc_lower = cve.description.lower()
        asset_terms = [asset.vendor, asset.nome, asset.versione]
        asset_terms = [t for t in asset_terms if t]
        if asset_terms:
            term_scores = [similarity(term, desc_lower) for term in asset_terms]
            scores.append(max(term_scores))
    
    return max(scores) if scores else 0.0


async def correlate_all(db: Session) -> dict:
    """
    Correlazione completa: per ogni asset, trova CVE rilevanti.
    """
    assets = db.query(Asset).all()
    cves = db.query(CVE).filter(CVE.cpe_matches.isnot(None)).all()
    
    created = 0
    updated = 0
    skipped = 0
    
    for asset in assets:
        for cve in cves:
            # Skip se già correlato
            existing = db.query(AssetVulnerability).filter(
                AssetVulnerability.asset_id == asset.id,
                AssetVulnerability.cve_id == cve.id
            ).first()
            
            if existing:
                skipped += 1
                continue
            
            match_type = None
            confidence = 0.0
            
            # 1. Try CPE exact match
            if asset.cpe and cve.cpe_matches:
                for cve_cpe in cve.cpe_matches:
                    exact, conf = cpe_match_score(asset.cpe, cve_cpe)
                    if exact:
                        match_type = MatchType.CPE_EXACT
                        confidence = 1.0
                        break
                    elif conf > 0.7 and match_type != MatchType.CPE_EXACT:
                        match_type = MatchType.CPE_PARTIAL
                        confidence = max(confidence, conf)
            
            # 2. Fallback: textual match
            if not match_type:
                text_score = textual_match_score(asset, cve)
                if text_score >= 0.7:  # Soglia configurabile
                    match_type = MatchType.TEXTUAL
                    confidence = text_score
            
            if match_type:
                av = AssetVulnerability(
                    asset_id=asset.id,
                    cve_id=cve.id,
                    match_type=match_type,
                    match_confidence=confidence if match_type == MatchType.TEXTUAL else None,
                    triage_status=TriagStatus.NEW,
                )
                db.add(av)
                created += 1
            else:
                skipped += 1
    
    db.commit()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
    }


async def correlate_asset(db: Session, asset_id: int) -> dict:
    """Correlazione per singolo asset (usato dopo import)"""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return {"error": "Asset non trovato"}
    
    cves = db.query(CVE).filter(CVE.cpe_matches.isnot(None)).all()
    created = 0
    
    for cve in cves:
        existing = db.query(AssetVulnerability).filter(
            AssetVulnerability.asset_id == asset_id,
            AssetVulnerability.cve_id == cve.id
        ).first()
        
        if existing:
            continue
        
        match_type = None
        confidence = 0.0
        
        if asset.cpe and cve.cpe_matches:
            for cve_cpe in cve.cpe_matches:
                exact, conf = cpe_match_score(asset.cpe, cve_cpe)
                if exact:
                    match_type = MatchType.CPE_EXACT
                    confidence = 1.0
                    break
                elif conf > 0.7:
                    match_type = MatchType.CPE_PARTIAL
                    confidence = max(confidence, conf)
        
        if not match_type:
            text_score = textual_match_score(asset, cve)
            if text_score >= 0.7:
                match_type = MatchType.TEXTUAL
                confidence = text_score
        
        if match_type:
            av = AssetVulnerability(
                asset_id=asset.id,
                cve_id=cve.id,
                match_type=match_type,
                match_confidence=confidence if match_type == MatchType.TEXTUAL else None,
                triage_status=TriagStatus.NEW,
            )
            db.add(av)
            created += 1
    
    db.commit()
    return {"asset_id": asset_id, "created": created}