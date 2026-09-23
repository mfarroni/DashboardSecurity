from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float, Boolean, 
    ForeignKey, Index, UniqueConstraint, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()


class AssetType(str, enum.Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"


class AssetCriticality(str, enum.Enum):
    PRODUZIONE = "produzione"
    TEST = "test"
    DISMESSO = "dismesso"


class CVESeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class TriagStatus(str, enum.Enum):
    NEW = "nuova"
    IN_VALUTAZIONE = "in_valutazione"
    MITIGATA = "mitigata"
    ACCETTATA = "accettata"


class MatchType(str, enum.Enum):
    CPE_EXACT = "cpe_exact"
    CPE_PARTIAL = "cpe_partial"
    TEXTUAL = "textual"


class FeedSourceType(str, enum.Enum):
    FEEDHUB = "feedhub"
    NVD = "nvd"
    CTI = "cti"


class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    tipo = Column(SQLEnum(AssetType), nullable=False, index=True)
    nome = Column(String(255), nullable=False, index=True)
    vendor = Column(String(255), nullable=False, index=True)
    versione = Column(String(100), nullable=True, index=True)
    cpe = Column(String(255), nullable=True, unique=True, index=True)
    criticita = Column(SQLEnum(AssetCriticality), nullable=True, index=True)
    note = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    imported_at = Column(DateTime, nullable=True)  # Quando è stato importato (per storico)
    import_batch_id = Column(String(100), nullable=True, index=True)  # Per tracciare batch di import
    
    # Relationships
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset", cascade="all, delete-orphan")
    logs = relationship("SyslogEntry", back_populates="asset", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("ix_assets_vendor_nome", "vendor", "nome"),
        Index("ix_assets_tipo_criticita", "tipo", "criticita"),
    )


class FeedItem(Base):
    __tablename__ = "feed_items"
    
    id = Column(Integer, primary_key=True, index=True)
    source = Column(SQLEnum(FeedSourceType), nullable=False, index=True)
    source_id = Column(String(255), nullable=True, index=True)  # ID originale nella fonte
    title = Column(String(500), nullable=False)
    url = Column(String(1000), nullable=True)
    source_name = Column(String(255), nullable=True, index=True)  # Nome fonte (es. "CSIRT Italia", "The Hacker News")
    published_at = Column(DateTime, nullable=True, index=True)
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # Lista di tag
    raw_data = Column(JSON, nullable=True)  # Dati grezzi originali
    
    # CVE estratte dal contenuto
    extracted_cves = Column(JSON, nullable=True)  # Lista di CVE-ID trovati
    
    # Relationships
    cve_matches = relationship("FeedItemCVE", back_populates="feed_item", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("ix_feed_items_source_published", "source", "published_at"),
        UniqueConstraint("source", "source_id", name="uq_feed_source_id"),
    )


class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)  # CVE-YYYY-NNNNN
    
    # Dati NVD canonici
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True, index=True)
    cvss_v3_severity = Column(SQLEnum(CVESeverity), nullable=True, index=True)
    cvss_v3_vector = Column(String(200), nullable=True)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v2_severity = Column(String(20), nullable=True)
    
    # CPE affected (da NVD)
    cpe_matches = Column(JSON, nullable=True)  # Lista di CPE 2.3 vulnerable
    
    # Date
    published_date = Column(DateTime, nullable=True, index=True)
    last_modified_date = Column(DateTime, nullable=True)
    
    # References
    references = Column(JSON, nullable=True)  # Lista di URL reference
    vendor_advisory_url = Column(String(1000), nullable=True)  # Link advisory ufficiale vendor
    
    # Fonti che l'hanno segnalata
    sources = Column(JSON, nullable=True)  # Lista di fonti: ["nvd", "cti", "feedhub"]
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    nvd_fetched_at = Column(DateTime, nullable=True)
    
    # Relationships
    asset_matches = relationship("AssetVulnerability", back_populates="cve", cascade="all, delete-orphan")
    feed_matches = relationship("FeedItemCVE", back_populates="cve", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("ix_cves_severity_score", "cvss_v3_severity", "cvss_v3_score"),
        Index("ix_cves_published", "published_date"),
    )


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Tipo di match
    match_type = Column(SQLEnum(MatchType), nullable=False, index=True)
    match_confidence = Column(Float, nullable=True)  # 0.0 - 1.0 per match testuali
    
    # Stato triage
    triage_status = Column(SQLEnum(TriagStatus), default=TriagStatus.NEW, nullable=False, index=True)
    triage_notes = Column(Text, nullable=True)
    triage_updated_at = Column(DateTime, nullable=True)
    triage_updated_by = Column(String(100), nullable=True)
    
    # Metadata
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")
    cve = relationship("CVE", back_populates="asset_matches")
    
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", name="uq_asset_cve"),
        Index("ix_asset_vuln_status", "asset_id", "triage_status"),
    )


class FeedItemCVE(Base):
    __tablename__ = "feed_item_cves"
    
    id = Column(Integer, primary_key=True, index=True)
    feed_item_id = Column(Integer, ForeignKey("feed_items.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Come è stata trovata la CVE nel feed
    extraction_method = Column(String(50), nullable=False)  # "regex", "structured", "manual"
    context_snippet = Column(Text, nullable=True)  # Contesto intorno alla CVE nel testo
    
    # Relationships
    feed_item = relationship("FeedItem", back_populates="cve_matches")
    cve = relationship("CVE", back_populates="feed_matches")
    
    __table_args__ = (
        UniqueConstraint("feed_item_id", "cve_id", name="uq_feed_cve"),
    )


class ImportBatch(Base):
    __tablename__ = "import_batches"
    
    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(String(100), unique=True, nullable=False, index=True)
    import_type = Column(String(50), nullable=False)  # "perimetro", "feedhub", "cti", "syslog"
    filename = Column(String(500), nullable=True)
    records_total = Column(Integer, default=0)
    records_imported = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    errors = Column(JSON, nullable=True)  # Lista di errori
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running", index=True)  # "running", "completed", "failed"
    
    __table_args__ = (
        Index("ix_import_batches_type_status", "import_type", "status"),
    )


class SyslogEntry(Base):
    __tablename__ = "syslog_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Campi syslog standard
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    facility = Column(String(50), nullable=True)
    severity = Column(String(20), nullable=True, index=True)
    program = Column(String(100), nullable=True)
    pid = Column(Integer, nullable=True)
    message = Column(Text, nullable=False)
    
    # Parsing
    parsed_fields = Column(JSON, nullable=True)  # Campi strutturati estratti (RFC 5424)
    raw_line = Column(Text, nullable=True)
    
    # Correlazione
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    matched_cve_ids = Column(JSON, nullable=True)  # CVE potenzialmente correlate
    
    # Metadata
    imported_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    import_batch_id = Column(String(100), nullable=True, index=True)
    
    # Relationships
    asset = relationship("Asset", back_populates="logs")
    
    __table_args__ = (
        Index("ix_syslog_timestamp_severity", "timestamp", "severity"),
        Index("ix_syslog_hostname_timestamp", "hostname", "timestamp"),
    )


class UserSettings(Base):
    __tablename__ = "user_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)