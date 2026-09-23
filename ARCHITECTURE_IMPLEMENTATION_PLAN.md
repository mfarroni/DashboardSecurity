# ARCHITECTURE & IMPLEMENTATION PLAN — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Orchestratore**: Project Manager / Technical Orchestrator  
**Branch Git**: `architecture/initial-design`

---

## 1. Current Architecture
L'applicazione attuale si presenta come un monolito Web Server-Side Rendered basato su **FastAPI 0.104.1**, **Jinja2** e **HTMX**, affiancato da un database **SQLite** (`data/security.db`) gestito tramite **SQLAlchemy 2.0 ORM** [CONFIRMED: `app/main.py`, `app/core/database.py`].
- **Router esposti**: 7 sub-router per un totale di 47 endpoint (tra pagine HTML, partials HTMX e API REST).
- **Integrazioni esterne**: Client HTTP asincrono (`httpx`) verso **NVD REST API 2.0** per il download delle CVE, unitamente a moduli di importazione manuale multipart per FeedHub (JSON/CSV), CTI/MISP e Syslog (RFC 3164/5424).
- **Limiti attuali**: Esecuzione sincrona in-memory dell'ingestione file, accoppiamento diretto tra chiamate HTTP e motore di correlazione CPU-bound, assenza di task schedulati in background nel ciclo `lifespan` dell'applicazione.

---

## 2. Verified Findings (Evidenze Verificate nel Codice)
Le conclusioni della Discovery sono state verificate criticamente contro il repository:
1. **[CONFIRMED] Template `cve_detail.html` Mancante**: L'endpoint `/cve/{cve_id}` in `app/api/dashboard.py#L49` invoca un template inesistente su disk, generando un'eccezione runtime `TemplateNotFound` (HTTP 500).
2. **[CONFIRMED] `NameError` nell'Endpoint Partial `/api/dashboard/critical-vulns`**: La funzione `get_critical_vulns` in `app/api/dashboard.py#L201` utilizza `request.app.state.templates` senza dichiarare `request: Request` nella signature.
3. **[CONFIRMED] Assenza Totale di Autenticazione e RBAC**: Nessun middleware o dipendenza di sicurezza è configurata in `app/main.py`. Tutti gli endpoint sono liberamente accessibili e modificabili.
4. **[CONFIRMED] Wildcard CORS**: Middleware CORS in `app/main.py#L33` configurato con `allow_origins=["*"]` e `allow_credentials=True`.
5. **[CONFIRMED] Upload File In-Memory Unbounded**: Lettura completa del file tramite `file.read()` in `assets.py#L149`, `feed.py#L110`, `syslog.py#L283` senza controlli sul limite massimo di dimensione (rischio DoS RAM).
6. **[CONFIRMED] Scheduler Inattivo**: Variabili di intervallo sync NVD/Feed definite in `config.py#L44-L45`, ma nessun job è registrato all'avvio in `app/main.py`.

---

## 3. Target Architecture
L'architettura target riorganizza la piattaforma secondo una **Security Analytics Pipeline a 10 stadi disaccoppiati**:

```text
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   PRESENTATION LAYER                                    │
 │            FastAPI SSR (Jinja2/HTMX) + REST API endpoints (OpenAPI v3)                 │
 └────────────────────────────────────────────┬────────────────────────────────────────────┘
                                              │
 ┌────────────────────────────────────────────▼────────────────────────────────────────────┐
 │                              SECURITY ANALYTICS PIPELINE                                │
 │                                                                                         │
 │  1. INGESTION      ────► File Parsers (Syslog RFC3164/5424, FeedHub, MISP/CTI, Assets) │
 │  2. VALIDATION     ────► Pydantic v2 Schemas + Strict File Size & Format Guards         │
 │  3. NORMALIZATION  ────► Common Event Schema (ECS / OCSF alignment)                       │
 │  4. ENRICHMENT     ────► NVD CVE Sync, CPE Matching, IP/Domain Geo & CTI Lookup         │
 │  5. CORRELATION    ────► CPE Exact/Partial + Full-Text Search (FTS) Index Matching      │
 │  6. DETECTION      ────► Rule Engine (Sigma-like / Heuristic Detection Rules)          │
 │  7. RISK SCORING   ────► Explanable Risk Scoring Engine (CVSS + Asset Criticality + CTI) │
 │  8. ALERTING       ────► Alert Lifecycle Engine (NEW -> ACK -> INVESTIGATING -> CLOSED) │
 │  9. INVESTIGATION  ────► Graph & Timeline Drill-Down for Security Analysts             │
 │ 10. REPORTING      ────► Scheduled & On-Demand Executive Security Reports               │
 └────────────────────────────────────────────┬────────────────────────────────────────────┘
                                              │
 ┌────────────────────────────────────────────▼────────────────────────────────────────────┐
 │                                   PERSISTENCE LAYER                                     │
 │        SQLAlchemy 2.0 ORM + PostgreSQL / SQLite (con FTS5 & Index Optimization)         │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Architecture
Documentazione prodotta: [SECURITY_ARCHITECTURE.md](file:///c:/Users/m.farroni/OneDrive%20-%20anticorruzione.it/Documenti-vecchioPC/AI-Test/Opencode/DashBoard%20eventi%20CVE/SECURITY_ARCHITECTURE.md).
- **Autenticazione & RBAC**: Hashing password via `passlib[bcrypt]`, token JWT via `python-jose` e tre ruoli applicativi (`ADMIN`, `ANALYST`, `READ_ONLY`).
- **Secrets Policy**: Rimozione del valore predefinito insicuro `dev-secret-change-in-production` in `app/core/config.py`. Blocco dell'avvio se `SECRET_KEY` non è definita nell'ambiente.
- **Browser & Network Hardening**: Restrizione origini CORS via `ALLOWED_ORIGINS`, token anti-CSRF sulle rotte di scrittura (POST/PATCH/DELETE) ed introduzione di middleware Rate Limiting (`slowapi`).
- **File Upload Guard**: Limite massimo di 50MB per payload inviati ed esecuzione del parsing in background/chunking.

---

## 5. Data Architecture & Valutazione SQLite vs PostgreSQL
Documentazione prodotta: [DATA_MODEL.md](file:///c:/Users/m.farroni/OneDrive%20-%20anticorruzione.it/Documenti-vecchioPC/AI-Test/Opencode/DashBoard%20eventi%20CVE/DATA_MODEL.md).
- **Valutazione DBMS**:
  - *Problema*: Lock a livello di intero file su SQLite durante scritture parallele sostenute (`database is locked`).
  - *Decisione Architetturale*: **Architettura Ibrida (Dual Engine)**. SQLite abilitato in modalità WAL (Write-Ahead Logging) per sviluppo locale e demo; PostgreSQL predefinito per ambienti di produzione/test via `docker-compose.yml`. [Vedi [DECISIONS.md](file:///c:/Users/m.farroni/OneDrive%20-%20anticorruzione.it/Documenti-vecchioPC/AI-Test/Opencode/DashBoard%20eventi%20CVE/DECISIONS.md)].
- **Data Model**: 8 tabelle relazionali (`assets`, `feed_items`, `cves`, `asset_vulnerabilities`, `feed_item_cves`, `import_batches`, `syslog_entries`, `user_settings`) con indici ottimizzati su severità, date di pubblicazione e chiavi esterne.

---

## 6. API Architecture
Documentazione prodotta: [API_INVENTORY.md](file:///c:/Users/m.farroni/OneDrive%20-%20anticorruzione.it/Documenti-vecchioPC/AI-Test/Opencode/DashBoard%20eventi%20CVE/API_INVENTORY.md).
- Catalogati 47 endpoint suddivisi tra viste web Jinja2, partials HTMX e API REST JSON.
- Protezione di tutte le rotte di mutazione stato (`/api/assets/*`, `/api/cve/correlate`, `/api/syslog/clear`) tramite dipendenza RBAC `Depends(require_role("ADMIN"))`.

---

## 7. Threat Model (STRIDE Framework)
Documentazione prodotta: [THREAT_MODEL.md](file:///c:/Users/m.farroni/OneDrive%20-%20anticorruzione.it/Documenti-vecchioPC/AI-Test/Opencode/DashBoard%20eventi%20CVE/THREAT_MODEL.md).
- **Spoofing & Elevation of Privilege**: Mitigati da JWT Auth e ruoli RBAC.
- **Tampering & Repudiation**: Mitigati da audit log su `import_batches` e tracciamento utente reale su `triage_updated_by`.
- **Denial of Service (DoS)**: Mitigato da middleware max upload size (50MB) e rate-limiting.

---

## 8. Detection Architecture
- **Detection Rules Engine**: Regole euristiche e basate su pattern (es. estrazione regex CVE, keyword exploit nei syslog come `buffer overflow`, `RCE`, `SQL injection`).
- **Integrazione Sigma-like**: Predisposizione per l'importazione di regole di detection in formato standard.

---

## 9. Alert Architecture & Lifecycle
Definizione dello stato di vita degli Alert e Triage:
$$\text{NEW} \longrightarrow \text{IN\_VALUTAZIONE} \longrightarrow \text{MITIGATA} \mid \text{ACCETTATA}$$
- Gli alert segnalano la presenza di vulnerabilità ad alta criticità su asset di produzione con evidenze rilevate nei log.

---

## 10. Risk Model
Formula di Risk Scoring riproducibile e spiegabile:
$$\text{Risk Score} = \text{CVSS v3 Score} \times \text{Peso Criticità Asset} \times \text{Confidence Match} \times \text{Fattore CTI}$$
- **Input**: Severità CVSS NVD (0.0-10.0), criticità asset (`produzione` = 1.5, `test` = 1.0, `dismesso` = 0.1), tipo match (`cpe_exact` = 1.0, `cpe_partial` = 0.8, `textual` = 0.7), presenza di menzioni in feed CTI attivi (+0.2).

---

## 11. Test Strategy
Matrice di tracciabilità obbligatoria:
$$\text{Requisito} \longrightarrow \text{Implementazione} \longrightarrow \text{Unit/Integration Test} \longrightarrow \text{Security Test} \longrightarrow \text{Review}$$
- Abilitazione della suite `pytest` completa rimuovendo i contrassegni `@pytest.mark.skip` tramite fixturing DB in memoria.
- Test di sicurezza automatizzati su CORS, payload oversize e RBAC authorization bypass.

---

## 12. Migration Strategy
- **Senza Downtime per SQLite**: Abilitazione della modalità WAL (`PRAGMA journal_mode=WAL;`) durante `init_db()`.
- **Migrazione PostgreSQL**: Gestita tramite **Alembic** (`alembic/`) previa variazione della variabile `DATABASE_URL` nel file `.env`.

---

## 13. Implementation Phases
1. **Fase 1: Quick Wins & Bug Fixes Bloccanti** (Template `cve_detail.html`, fix `NameError` in `dashboard.py`).
2. **Fase 2: Security Blockers & Hardening** (Auth JWT/Bcrypt, RBAC, CORS, Limite Upload 50MB, Secrets Policy).
3. **Fase 3: Modifiche Architetturali & Background Scheduler** (FastAPI `lifespan` scheduler, FTS indexing).
4. **Fase 4: Refactoring Debito Tecnico & Test Suite** (Pydantic v2 syntax, test senza skip).

---

## 14. Git Branch Strategy
- **Branch Protetto**: `main`.
- **Branch Corrente di Lavoro Architetturale**: `architecture/initial-design` (pubblicato su GitHub `origin`).
- **Branch di Implementazione Futuri**: `feature/quick-wins-bugs`, `security/auth-rbac`, `refactor/background-scheduler`.

---

## 15. Risks & Mitigation
- **Rischio Breaking Changes su Frontend HTMX**: Mitigato da test integrati di render HTML su tutti gli endpoint partials.
- **Rischio Lock SQLite in Sviluppo**: Mitigato dall'attivazione della modalità WAL e `timeout=30.0` nelle opzioni di connessione SQLAlchemy.

---

## 16. Dependencies
- Nessuna nuova dipendenza esterna necessaria. Si utilizzeranno le librerie già presenti in `requirements.txt` ma attualmente inattive (`passlib[bcrypt]`, `python-jose`, `apscheduler`).

---

## 17. Human Approval Points (Punti di Approvazione Umana)
Richiesta autorizzazione esplicita prima di:
- Eseguire qualsiasi modifica al codice applicativo o commit su Git.
- Attivare o modificare la configurazione per il deployment in produzione (Proxmox / Docker).

---

## 18. Recommended Execution Order
1. **Approvazione Umana** della Target Architecture e di questo piano.
2. Creazione del branch di sviluppo `feature/quick-wins-bugs` a partire da `architecture/initial-design`.
3. Risoluzione dei 2 bug bloccanti (`cve_detail.html` e `NameError`).
4. Implementazione del modulo Auth & RBAC.
5. Esecuzione dei Security Test e Quality Gate.


## 19. Architecture Gate 2.1 resolutions

1. Scheduler: no periodic scheduler in the FastAPI Web Service. Use Render Cron Job or a single worker with idempotent NVD/Feed jobs and non-overlap controls.
2. Deployment: Vercel -> Render Web Service -> Neon PostgreSQL is the production topology. Preview and Production databases are isolated. Full controls are in DEPLOYMENT_ARCHITECTURE.md.
3. Browser auth: server-managed secure session cookie + CSRF. JWT is not stored in browser storage.
4. RBAC: named permissions back the ADMIN/ANALYST/READ_ONLY roles; see SECURITY_ARCHITECTURE.md.
5. Target data model: identity, audit, alert/detection and operational sync entities are defined as TARGET only; implementation requires Alembic migrations and explicit backfill decisions.
6. Pydantic: remain on current Pydantic v1 for the first controlled implementation; migrate to v2 as a separate refactor with tests.
7. Uploads: 50 MB is a file/request baseline complemented by streaming, parser limits, type validation, temporary-file controls and rate limiting.

## 20. Revised implementation gates

Gate A — Architecture: documentation complete and internally consistent.  
Gate B — Quick Wins: create missing CVE template, fix NameError and duplicate import, with regression tests.  
Gate C — Security: authentication/RBAC, CSRF, CORS, mandatory secrets, upload controls, security headers and audit logging.  
Gate D — PostgreSQL: compatibility tests, Alembic baseline/migrations, Neon Preview integration and only then Production migration plan.  
Gate E — Operations: Render Web Service, Render Cron/worker, health checks, logging, monitoring, backup/recovery and rollback validation.  
Gate F — Independent Review: separate security/code review followed by Release Gate and explicit human approval for production.

No production deployment is authorized by this document alone.
