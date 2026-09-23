# DATA MODEL — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Ricostruzione del modello relazionale tramite ispezione del file `app/models/models.py` (Senza modifiche al DB).

---

## 1. Struttura del Database e Tabelle Rilevate

Il database relazionale contiene **8 tabelle principali** modellate tramite SQLAlchemy ORM:

```text
  ┌──────────────┐         ┌───────────────────────┐         ┌─────────────┐
  │    assets    │1       *│  asset_vulnerabilities│*       1│    cves     │
  │──────────────│─────────│───────────────────────│─────────│─────────────│
  │ id (PK)      │         │ id (PK)               │         │ id (PK)     │
  │ nome, vendor │         │ asset_id (FK)         │         │ cve_id (UQ) │
  │ cpe (UQ)     │         │ cve_id (FK)           │         │ cvss_v3_... │
  └──────┬───────┘         │ match_type, triage_...│         └──────┬──────┘
         │1                └───────────────────────┘                │1
         │                                                          │
         │*                                                         │*
  ┌──────┴───────┐                                           ┌──────┴──────┐
  │syslog_entries│                                           │feed_item_cves│
  │──────────────│                                           │─────────────│
  │ id (PK)      │                                           │ id (PK)     │
  │ asset_id (FK)│                                           │feed_item_id │
  │ message, host│                                           │ cve_id (FK) │
  └──────────────┘                                           └──────┬──────┘
                                                                    │*
                                                             ┌──────┴──────┐
  ┌──────────────┐         ┌──────────────┐                  │ feed_items  │
  │import_batches│         │user_settings │                  │─────────────│
  │──────────────│         │──────────────│                  │ id (PK)     │
  │ id (PK)      │         │ id (PK)      │                  │ source, title│
  │ batch_id (UQ)│         │ key (UQ)     │                  └─────────────┘
  └──────────────┘         └──────────────┘
```

---

## 2. Dettaglio Tabelle e Schema Relazionale

### 2.1 Tabella `assets`
- **Scopo**: Registro del perimetro degli asset aziendali (hardware e software). [CONFIRMED: `app/models/models.py#L50-L75`]
- **Campi**:
  - `id` (Integer, Primary Key)
  - `tipo` (Enum: `hardware`, `software`, NOT NULL)
  - `nome` (String 255, NOT NULL)
  - `vendor` (String 255, NOT NULL)
  - `versione` (String 100, Nullable)
  - `cpe` (String 255, Unique, Nullable)
  - `criticita` (Enum: `produzione`, `test`, `dismesso`, Nullable)
  - `note` (Text, Nullable)
  - `created_at`, `updated_at`, `imported_at` (DateTime)
  - `import_batch_id` (String 100, Nullable)
- **Indici**: `ix_assets_vendor_nome` (`vendor`, `nome`), `ix_assets_tipo_criticita` (`tipo`, `criticita`).

### 2.2 Tabella `cves`
- **Scopo**: Repository canonico delle CVE sincronizzate da NVD o estratte da feed. [CONFIRMED: `app/models/models.py#L106-L146`]
- **Campi**:
  - `id` (Integer, Primary Key)
  - `cve_id` (String 50, Unique, NOT NULL) — Formato `CVE-YYYY-NNNNN`
  - `description` (Text, Nullable)
  - `cvss_v3_score` (Float, Nullable), `cvss_v3_severity` (Enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`), `cvss_v3_vector` (String 200)
  - `cvss_v2_score` (Float), `cvss_v2_severity` (String 20)
  - `cpe_matches` (JSON, Nullable) — Lista stringhe CPE 2.3 impattate
  - `published_date`, `last_modified_date`, `nvd_fetched_at` (DateTime)
  - `references`, `sources` (JSON, Nullable)
  - `vendor_advisory_url` (String 1000, Nullable)
- **Indici**: `ix_cves_severity_score` (`cvss_v3_severity`, `cvss_v3_score`), `ix_cves_published` (`published_date`).

### 2.3 Tabella `asset_vulnerabilities` (Tabella di Correlazione / Triage)
- **Scopo**: Correlazione tra Asset e CVE riscontrate con relativo stato di triage. [CONFIRMED: `app/models/models.py#L149-L178`]
- **Campi**:
  - `id` (Integer, Primary Key)
  - `asset_id` (Integer, Foreign Key -> `assets.id` ON DELETE CASCADE)
  - `cve_id` (Integer, Foreign Key -> `cves.id` ON DELETE CASCADE)
  - `match_type` (Enum: `cpe_exact`, `cpe_partial`, `textual`)
  - `match_confidence` (Float, Nullable: 0.0 - 1.0)
  - `triage_status` (Enum: `nuova`, `in_valutazione`, `mitigata`, `accettata`, default: `nuova`)
  - `triage_notes` (Text, Nullable)
  - `triage_updated_at` (DateTime), `triage_updated_by` (String 100)
  - `detected_at`, `acknowledged_at` (DateTime)
- **Vincoli**: Unique Constraint `uq_asset_cve` (`asset_id`, `cve_id`).

### 2.4 Tabella `feed_items`
- **Scopo**: News, bollettini ed intelligence raccolti da FeedHub, NVD o CTI. [CONFIRMED: `app/models/models.py#L78-L103`]
- **Campi**:
  - `id` (Integer, Primary Key)
  - `source` (Enum: `feedhub`, `nvd`, `cti`)
  - `source_id` (String 255, Nullable)
  - `title` (String 500, NOT NULL), `url` (String 1000)
  - `source_name` (String 255)
  - `published_at`, `collected_at` (DateTime)
  - `content`, `summary` (Text)
  - `tags`, `raw_data`, `extracted_cves` (JSON)
- **Vincoli**: Unique Constraint `uq_feed_source_id` (`source`, `source_id`).

### 2.5 Tabella `feed_item_cves`
- **Scopo**: Relazione Many-to-Many tra articoli Feed ed entità CVE. [CONFIRMED: `app/models/models.py#L180-L198`]
- **Campi**: `id`, `feed_item_id` (FK), `cve_id` (FK), `extraction_method` (String 50: `regex`, `structured`, `manual`), `context_snippet` (Text).

### 2.6 Tabella `syslog_entries`
- **Scopo**: Ingestion log ed eventi di sistema in formato RFC 3164 / RFC 5424. [CONFIRMED: `app/models/models.py#L220-L254`]
- **Campi**:
  - `id` (Integer, Primary Key)
  - `timestamp` (DateTime, NOT NULL), `hostname` (String 255), `source_ip` (String 45)
  - `facility` (String 50), `severity` (String 20), `program` (String 100), `pid` (Integer)
  - `message` (Text, NOT NULL), `raw_line` (Text), `parsed_fields` (JSON)
  - `asset_id` (Integer, Foreign Key -> `assets.id` ON DELETE SET NULL)
  - `matched_cve_ids` (JSON) — Lista di CVE-ID rilevate nel messaggio log

### 2.7 Tabelle `import_batches` e `user_settings`
- **ImportBatch**: Traccia i job di importazione file con status, conteggio record importati/falliti ed eventuali errori JSON. [CONFIRMED: `app/models/models.py#L200-L218`]
- **UserSettings**: Tabella chiave-valore JSON per configurazioni persistenti dell'utente. [CONFIRMED: `app/models/models.py#L256-L263`]

---

## 3. Considerazioni su Scalabilità e Normalizzazione

- **Supporto JSON Nativo**: L'utilizzo di colonne JSON (`cpe_matches`, `references`, `raw_data`, `matched_cve_ids`) offre flessibilità per schemi dinamici ma limita la capacità di indicizzazione e la velocità di query su database SQLite rispetto a tabelle completamente normalizzate. [CONFIRMED]
- **Retention Dati Inesistente**: Nessuna procedura automatica o query di pulizia (retention policy) è definita per limitare la crescita delle tabelle `syslog_entries` o `feed_items`. [CONFIRMED]


## 4. Target schema (Architecture Gate 2.1)

La sezione precedente descrive lo schema CURRENT rilevato nel repository. Il seguente è lo schema TARGET architetturale; non è stato applicato al database.

### 4.1 Identity and authorization
- users: id, username/email unique, password_hash, is_active, created_at, updated_at, last_login_at.
- roles: id, name (ADMIN, ANALYST, READ_ONLY).
- permissions: id, resource, action.
- user_roles: user_id, role_id.
- role_permissions: role_id, permission_id.

### 4.2 Audit and operational control
- audit_logs: id, timestamp, actor_user_id, action, resource_type, resource_id, outcome, source_ip, request_id, metadata JSON. Append-oriented; no ordinary user delete/update.
- sync_runs: id, job_type/source, started_at, finished_at, status, attempt, records_read/created/updated/failed, error_summary, request_id. Unique/idempotency key where applicable.

### 4.3 Detection and alerting
- detections: id, rule_id, event/reference type, severity, confidence, evidence JSON, detected_at, status.
- alerts: id, alert_type, severity, status (NEW, ACK, INVESTIGATING, CLOSED), asset_id nullable, detection_id nullable, vulnerability_id nullable, created_at, acknowledged_at, closed_at, assigned_to.
- investigations: id, title, status, owner_user_id, created_at, updated_at, closed_at, notes. Use only if the investigation workflow is implemented; otherwise defer this table.

### 4.4 Risk
Risk scoring should be persisted as an auditable result rather than only recomputed at presentation time. A target risk_assessments table may contain asset_id, cve_id, score, methodology_version, input_snapshot JSON, calculated_at and calculated_by/job_id. Historical results are retained when the methodology version changes.

### 4.5 Retention and indexing
Retention policies must be defined before production for syslog_entries, feed_items, audit_logs and sync_runs. PostgreSQL indexes should be designed from measured query patterns. FTS/correlation indexes are implementation tasks and must not be assumed equivalent between SQLite and PostgreSQL.

### 4.6 Implementation rule
The target tables are introduced through reviewed Alembic migrations only. Existing eight tables remain unchanged until the implementation plan explicitly maps each migration and backfill. No database mutation is part of Architecture Gate 2.1.
