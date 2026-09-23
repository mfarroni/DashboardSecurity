# TARGET ARCHITECTURE — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Ruolo**: Technical Orchestrator / Security Architect  
**Branch Git**: `architecture/initial-design`

---

## 1. Architettura Attuale vs Architettura Target

### 1.1 Architettura Attuale (Monolito Accoppiato)
L'applicazione attuale si presenta come un monolito leggero basato su FastAPI con rendering server-side (Jinja2 + HTMX) ed inserimento sincrono in-memory dei file.
- **Accoppiamento**: I router chiamano direttamente la logica ORM ed eseguono l'elaborazione dei file e la correlazione testuale all'interno del ciclo request/response HTTP.
- **Limiti**: Mancanza di elaborazione asincrona in background, potenziale blocco dei worker su file di grandi dimensioni, assenza di pipeline di ingestion e detection a stadi separati.

### 1.2 Architettura Target (Modular Security Analytics Platform)

> **Architecture Gate 2.1:** il Web Service FastAPI su Render è stateless rispetto ai job periodici. La sincronizzazione NVD/Feed è demandata a un componente scheduler dedicato, preferibilmente Render Cron Job, con job idempotenti e controllo di non sovrapposizione. Riferimento: `DEPLOYMENT_ARCHITECTURE.md`.
L'architettura target riorganizza il sistema in moduli disaccoppiati conformi alla pipeline a 10 stadi:

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
 │  2. VALIDATION     ────► Pydantic Schemas + Strict File Size & Format Guards            │
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

## 2. Valutazione Architetturale: SQLite vs PostgreSQL

### 2.1 Analisi Tecnica
- **PROBLEMA**: Lock a livello di intero database durante scritture concorrenti su SQLite (`data/security.db`) in scenari di ingestion massiva syslog + feed. [CONFIRMED: `app/core/database.py#L7-L13`]
- **EVIDENZA**: SQLite con `StaticPool` blocca le transazioni concorrenti in scrittura sollevando `OperationalError: database is locked` su carichi sostenuti.
- **OPZIONI**:
  1. *Opzione A*: Mantenere SQLite con configurazione WAL (Write-Ahead Logging) e timeout incrementati per ambienti locali/dev.
  2. *Opzione B*: Migrazione immediata ed esclusiva a PostgreSQL.
  3. *Opzione C*: Supporto Ibrido (Dual Database Engine): SQLite (con WAL) predefinito per ambienti locali/demo, PostgreSQL predefinito per ambienti di test/produzione (Proxmox/Docker).
- **TRADE-OFF**:
  - *Opzione A*: Semplice, zero dipendenze aggiuntive, ma limita la concorrenza su volumi syslog elevati.
  - *Opzione B*: Ottima concorrenza ed FTS nativo (`pg_trgm`), ma richiede un container/istanza Postgres attiva anche per sviluppo locale rapido.
  - *Opzione C*: Massima flessibilità, zero frizione per sviluppatori locali, produzione ad alte prestazioni su PostgreSQL.
- **DECISIONE**: **Opzione C (Supporto Ibrido con SQLite WAL local + PostgreSQL per produzione)**.
- **MOTIVAZIONE**: L'ORM SQLAlchemy 2.0 già astenie il layer dati (`app/core/database.py`). È sufficiente configurare la modalità WAL su SQLite per sviluppo e fornire una composizione Docker Compose con il servizio PostgreSQL per scenari di produzione.

---

## 3. Disaccoppiamento del Motore di Correlazione

- **PROBLEMA**: Il calcolo della similarità testuale tramite `difflib.SequenceMatcher` in `app/services/correlation.py` ha complessità $O(N \times M)$ in CPU durante la richiesta HTTP. [CONFIRMED: `app/services/correlation.py#L20`]
- **EVIDENZA**: Esecuzione sincrona dentro gli handler dell'API (`/api/cve/correlate`).
- **DECISIONE**:
  1. Spostare le operazioni di correlazione e sync NVD in **Task Asincroni di Background** (`FastAPI BackgroundTasks` o worker dedicato).
  2. Introdurre indicizzazione **Full-Text Search (FTS)** su SQLite (`FTS5`) e PostgreSQL (`pg_trgm`) per velocizzare i match testuali di oltre 100x.

---

## 4. Decision Log Sintetico

| Componente | Architettura Attuale | Architettura Target | Motivazione Principale |
|---|---|---|---|
| **Auth & Security** | Inesistente | FastAPI Security + Passlib/Bcrypt + JWT / Session | Blocco di sicurezza fondamentale |
| **Parsing & Ingestion** | Sincrono in-memory | Asincrono con guards su dimensioni file | Prevenzione crash OOM e DoS |
| **Correlation Engine** | Loop CPU `difflib` | FTS5 Indexing + Task Background | Scalabilità e tempi di risposta API < 200ms |
| **Scheduler** | Inattivo | Render Cron Job / worker singolo, fuori dal lifespan Web Service | Evitare duplicazione job in scaling orizzontale |
