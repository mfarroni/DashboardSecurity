from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AssetType(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"


class AssetCriticality(str, Enum):
    PRODUZIONE = "produzione"
    TEST = "test"
    DISMESSO = "dismesso"


class CVESeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class TriagStatus(str, Enum):
    NEW = "nuova"
    IN_VALUTAZIONE = "in_valutazione"
    MITIGATA = "mitigata"
    ACCETTATA = "accettata"


class MatchType(str, Enum):
    CPE_EXACT = "cpe_exact"
    CPE_PARTIAL = "cpe_partial"
    TEXTUAL = "textual"


class FeedSourceType(str, Enum):
    FEEDHUB = "feedhub"
    NVD = "nvd"
    CTI = "cti"


# Asset schemas
class AssetBase(BaseModel):
    tipo: AssetType
    nome: str = Field(..., min_length=1, max_length=255)
    vendor: str = Field(..., min_length=1, max_length=255)
    versione: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=255, regex=r"^cpe:2\.3:[aho]:([^:]*):([^:]*):([^:]*):")
    criticita: Optional[AssetCriticality] = None
    note: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    tipo: Optional[AssetType] = None
    nome: Optional[str] = Field(None, min_length=1, max_length=255)
    vendor: Optional[str] = Field(None, min_length=1, max_length=255)
    versione: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=255, regex=r"^cpe:2\.3:[aho]:([^:]*):([^:]*):([^:]*):")
    criticita: Optional[AssetCriticality] = None
    note: Optional[str] = None


class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime
    imported_at: Optional[datetime] = None
    import_batch_id: Optional[str] = None
    vulnerability_count: int = 0
    
    class Config:
        orm_mode = True


class AssetImportRow(BaseModel):
    """Row per import da CSV/Excel/JSON - mapping flessibile"""
    tipo: str
    nome: str
    vendor: str
    versione: Optional[str] = None
    cpe: Optional[str] = None
    criticita: Optional[str] = None
    note: Optional[str] = None


# FeedItem schemas
class FeedItemBase(BaseModel):
    source: FeedSourceType
    source_id: Optional[str] = None
    title: str
    url: Optional[HttpUrl] = None
    source_name: Optional[str] = None
    published_at: Optional[datetime] = None
    content: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[List[str]] = None
    raw_data: Optional[Dict[str, Any]] = None
    extracted_cves: Optional[List[str]] = None


class FeedItemCreate(FeedItemBase):
    pass


class FeedItemResponse(FeedItemBase):
    id: int
    collected_at: datetime
    cve_count: int = 0
    
    class Config:
        orm_mode = True


# CVE schemas
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,7}$"


class CVEBase(BaseModel):
    cve_id: str = Field(..., regex=CVE_ID_PATTERN)


class CVECreate(CVEBase):
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v3_severity: Optional[CVESeverity] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v2_severity: Optional[str] = None
    cpe_matches: Optional[List[str]] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    references: Optional[List[str]] = None
    vendor_advisory_url: Optional[str] = None
    sources: Optional[List[str]] = None


class CVEResponse(CVEBase):
    id: int
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[CVESeverity] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_severity: Optional[str] = None
    cpe_matches: Optional[List[str]] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    references: Optional[List[str]] = None
    vendor_advisory_url: Optional[str] = None
    sources: Optional[List[str]] = None
    created_at: datetime
    updated_at: datetime
    nvd_fetched_at: Optional[datetime] = None
    asset_count: int = 0
    feed_count: int = 0
    
    class Config:
        orm_mode = True


class CVEDetailResponse(CVEResponse):
    """Scheda dettaglio CVE compatta (3.5)"""
    affected_assets: List[Dict[str, Any]] = []
    feed_references: List[Dict[str, Any]] = []


# AssetVulnerability schemas
class AssetVulnerabilityBase(BaseModel):
    asset_id: int
    cve_id: int
    match_type: MatchType
    match_confidence: Optional[float] = Field(None, ge=0, le=1)
    triage_status: TriagStatus = TriagStatus.NEW
    triage_notes: Optional[str] = None


class AssetVulnerabilityUpdate(BaseModel):
    triage_status: Optional[TriagStatus] = None
    triage_notes: Optional[str] = None


class AssetVulnerabilityResponse(AssetVulnerabilityBase):
    id: int
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    triage_updated_at: Optional[datetime] = None
    triage_updated_by: Optional[str] = None
    asset: Optional[AssetResponse] = None
    cve: Optional[CVEResponse] = None
    
    class Config:
        orm_mode = True


# Import schemas
class ImportBatchResponse(BaseModel):
    id: int
    batch_id: str
    import_type: str
    filename: Optional[str] = None
    records_total: int
    records_imported: int
    records_failed: int
    errors: Optional[List[str]] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    
    class Config:
        orm_mode = True


class ImportPreviewResponse(BaseModel):
    """Anteprima import perimetro"""
    headers: List[str]
    rows: List[Dict[str, Any]]
    row_count: int
    suggested_mapping: Dict[str, str]
    validation_errors: List[str]


# Syslog schemas
class SyslogEntryBase(BaseModel):
    timestamp: datetime
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    facility: Optional[str] = None
    severity: Optional[str] = None
    program: Optional[str] = None
    pid: Optional[int] = None
    message: str


class SyslogEntryResponse(SyslogEntryBase):
    id: int
    parsed_fields: Optional[Dict[str, Any]] = None
    raw_line: Optional[str] = None
    asset_id: Optional[int] = None
    matched_cve_ids: Optional[List[str]] = None
    imported_at: datetime
    import_batch_id: Optional[str] = None
    asset: Optional[AssetResponse] = None
    
    class Config:
        orm_mode = True


# Dashboard schemas
class DashboardOverview(BaseModel):
    total_assets: int
    assets_by_type: Dict[str, int]
    assets_by_criticality: Dict[str, int]
    total_cves: int
    cves_by_severity: Dict[str, int]
    new_cves_last_7d: int
    critical_cves_affecting_assets: int
    recent_feed_items: int
    unread_feed_items: int
    recent_syslog_entries: int
    high_severity_logs_last_24h: int


class AssetWithVulnsResponse(BaseModel):
    asset: AssetResponse
    vulnerabilities: List[AssetVulnerabilityResponse]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


# Pagination
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int