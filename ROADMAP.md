# ROADMAP — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Orchestratore**: Project Manager / Technical Orchestrator  
**Branch Git**: `architecture/initial-design`

---

## 1. Mappa Sintetica delle Attività per Priorità

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                            IMPLEMENTATION ROADMAP                       │
 │                                                                         │
 │  1. QUICK WINS & CRITICAL BUGS  ──► Fix `cve_detail.html` & `NameError` │
 │                                     Fix Duplicate Imports               │
 │                                                                         │
 │  2. SECURITY BLOCKERS           ──► Auth & RBAC (JWT/Passlib)           │
 │                                     CORS Hardening & Payload Size Guard │
 │                                     Secrets Mandatory Enforcement       │
 │                                     Anti-CSRF Tokens                    │
 │                                                                         │
 │  3. ARCHITECTURAL CHANGES       ──► Lifespan Background Scheduler (NVD) │
 │                                     Async File Ingestion & Parsing      │
 │                                     FTS5 / pg_trgm Index Correlation    │
 │                                                                         │
 │  4. TECHNICAL DEBT & QA         ──► Pydantic v2 Migration               │
 │                                     Full Unit & Integration Test Suite  │
 │                                     Clean Inactive Dependencies         │
 └─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Elenco Dettagliato delle Attività

### Fase 1: Quick Wins & Critical Bug Fixes
- **TASK-01: Ripristino Template `cve_detail.html`**
  - **Priority**: `CRITICAL` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Creazione del componente HTML mancante `app/templates/cve_detail.html` per la vista dettagliata CVE. [CONFIRMED: `app/api/dashboard.py#L49`]
  - **Affected Components**: `app/templates/cve_detail.html`, `app/api/dashboard.py`.
  - **Tests Required**: `test_dashboard_cve_detail_page`.

- **TASK-02: Correzione `NameError` su Partial Vulnerabilità Critiche**
  - **Priority**: `CRITICAL` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Aggiunta del parametro `request: Request` nella signature della funzione `get_critical_vulns`. [CONFIRMED: `app/api/dashboard.py#L201`]
  - **Affected Components**: `app/api/dashboard.py`.
  - **Tests Required**: `test_critical_vulns_partial`.

- **TASK-03: Rimozione Import Duplicato**
  - **Priority**: `LOW` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Pulizia dell'import di `HTMLResponse` duplicato in `app/api/dashboard.py#L2-L3`.

---

### Fase 2: Security Blockers & Hardening
- **TASK-04: Implementazione Autenticazione & RBAC**
  - **Priority**: `CRITICAL` | **Risk**: `HIGH` | **Status**: `PLANNED`
  - **Description**: Introduzione schema Utenti, hashing Bcrypt via `passlib`, generazione JWT via `python-jose` e protezione delle rotte API.
  - **Affected Components**: `app/models/models.py`, `app/api/auth.py`, `app/main.py`.
  - **Security Impact**: Risoluzione del vincolo di sicurezza principale (Access Control).

- **TASK-05: Restrizione CORS e Guardie su Upload File**
  - **Priority**: `HIGH` | **Risk**: `MEDIUM` | **Status**: `PLANNED`
  - **Description**: Sostituzione di `allow_origins=["*"]` con origini fidate ed introduzione di limite 50MB sugli upload file. [CONFIRMED: `app/main.py#L33`]
  - **Affected Components**: `app/main.py`, `app/api/assets.py`, `app/api/syslog.py`.

- **TASK-06: Obbligatorietà Secret Key in Ambiente**
  - **Priority**: `HIGH` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Arresto dell'applicazione all'avvio se `SECRET_KEY` non è definita nell'ambiente (rimozione del fallback insicuro). [CONFIRMED: `app/core/config.py#L26`]

---

### Fase 3: Modifiche Architetturali & Scalabilità
- **TASK-07: Attivazione Background Scheduler nel Lifespan**
  - **Priority**: `HIGH` | **Risk**: `MEDIUM` | **Status**: `PLANNED`
  - **Description**: Registrazione dei job di sincronizzazione automatica periodica NVD e FeedHub nel ciclo `lifespan` di FastAPI. [CONFIRMED: `app/main.py#L13`]

- **TASK-08: Ottimizzazione Correlazione via FTS Indexing**
  - **Priority**: `MEDIUM` | **Risk**: `MEDIUM` | **Status**: `PLANNED`
  - **Description**: Indicizzazione Full-Text Search (FTS5 per SQLite / `pg_trgm` per Postgres) per velocizzare la correlazione testuale Asset ↔ CVE. [CONFIRMED: `app/services/correlation.py#L20`]

---

### Fase 4: Debito Tecnico & Test Suite
- **TASK-09: Migrazione a Pydantic v2 Syntax**
  - **Priority**: `MEDIUM` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Migrazione da `orm_mode = True` a `from_attributes = True` negli schemi Pydantic. [CONFIRMED: `app/schemas/schemas.py#L79`]

- **TASK-10: Abilitazione Test Suite Completa senza Skip**
  - **Priority**: `HIGH` | **Risk**: `LOW` | **Status**: `PLANNED`
  - **Description**: Abilitazione dei test disattivati (`test_asset_crud`, `test_cve_sync_nvd`) con database di test in memoria/fixturing `pytest`. [CONFIRMED: `tests/test_api.py#L37`]
