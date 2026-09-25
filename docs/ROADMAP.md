# Security Dashboard — V1 Roadmap & Agent Context

**Stato:** APPROVATO  
**Branch di riferimento:** `architecture/initial-design`  
**Repository:** `mfarroni/DashboardSecurity`  
**Scopo:** contesto persistente per agenti e strumenti di sviluppo  
**Ultimo aggiornamento:** 2026-09-25

---

## 1. Come usare questo documento

Questo file è il **punto di ingresso operativo della roadmap V1**.

Qualsiasi agente o strumento che prenda in carico il repository deve leggerlo prima di iniziare attività di sviluppo, insieme a:

1. `docs/product/V1_SCOPE.md`
2. `docs/product/V1_IMPLEMENTATION_PLAN.md`
3. `docs/product/V1_DATA_MODEL_AND_CONTRACTS.md`
4. `ARCHITECTURE.md`
5. `SECURITY_ARCHITECTURE.md`

La roadmap definisce **l'ordine delle milestone, il loro scopo e i relativi gate**. Non autorizza automaticamente l'esecuzione di una milestone: l'agente deve verificare quale milestone è esplicitamente autorizzata dall'utente.

### Regola fondamentale

> **Un agente deve implementare esclusivamente la milestone autorizzata. Al termine deve fermarsi e attendere l'approvazione umana per la milestone successiva.**

Non è consentito dedurre dall'esistenza della roadmap che tutte le milestone siano già autorizzate.

---

## 2. Obiettivo della V1

La V1 deve rispondere alla domanda:

> **Quali vulnerabilità presenti oggi rappresentano un problema concreto per i nostri asset?**

La catena funzionale prevista è:

```
FONTI
  ↓
INGESTION
  ↓
NORMALIZZAZIONE
  ↓
ASSET
  ↓
CVE / VULNERABILITÀ
  ↓
CORRELAZIONE
  ↓
ANALISI
  ↓
TRIAGE
  ↓
REPORTING
```

La V1 deve privilegiare:

- sicurezza;
- correttezza;
- tracciabilità;
- prevedibilità;
- semplicità;
- testabilità;
- manutenibilità.

Non deve trasformarsi in uno SIEM, SOAR, CTI platform, case-management system o advanced risk engine.

---

# 3. Roadmap delle milestone

## M0 — Baseline, Quick Fixes & Test Foundation

**Obiettivo:** stabilizzare la baseline esistente prima di costruire nuove funzionalità.

### Attività principali

- verificare lo stato reale del repository;
- correggere il template CVE mancante;
- correggere il problema `request` nell'endpoint `critical-vulns`;
- correggere errori evidenti che impediscono import/startup/test;
- introdurre regression test;
- verificare startup e test suite;
- documentare blocker residui.

### NON fare in M0

- autenticazione/RBAC;
- PostgreSQL/Alembic;
- nuove funzionalità V1;
- dashboard V1;
- refactoring esteso;
- modifiche architetturali;
- modifiche al modello dati.

### Gate

**M0 → STOP → review/approvazione umana**

---

## M1 — Security Foundation + Authentication/RBAC

**Obiettivo:** costruire la base di sicurezza applicativa.

### Attività principali

- autenticazione server-side;
- session management;
- cookie Secure/HttpOnly/SameSite;
- logout/invalidation;
- ruoli ADMIN / ANALYST / READ_ONLY;
- permission-based authorization;
- 401/403 coerenti;
- CSRF;
- CORS allowlist;
- secret management;
- security headers;
- audit degli eventi di sicurezza;
- rate limiting dove necessario.

### Gate

**M1 → STOP → security review**

---

## M2 — PostgreSQL / Neon + Data Layer

**Obiettivo:** portare il modello dati verso il target PostgreSQL/Neon.

### Attività principali

- schema V1 definitivo;
- verifica SQLAlchemy;
- Alembic;
- migration baseline;
- vincoli e indici;
- compatibilità PostgreSQL;
- test PostgreSQL;
- ambiente Preview isolato;
- migration/rollback strategy.

### Entità target

- users;
- roles;
- permissions;
- user_roles;
- role_permissions;
- audit_logs;
- assets;
- software/products;
- CPE;
- CVEs;
- asset vulnerability findings;
- feed/feed items;
- imports;
- sync_runs;
- risk assessments;
- triage/status/notes.

### Gate

**M2 → STOP → schema review + PostgreSQL integration review**

---

## M3 — Asset Inventory

**Obiettivo:** rendere l'inventario degli asset una funzione V1 utilizzabile.

### Funzioni

- elenco;
- ricerca;
- filtri;
- dettaglio;
- CRUD;
- import;
- criticità;
- vendor/product/version;
- CPE;
- software/asset;
- vulnerabilità associate.

### Test

- CRUD;
- autorizzazioni;
- validazione;
- import;
- PostgreSQL;
- audit.

### Gate

**M3 → STOP → functional review**

---

## M4 — CVE / NVD

**Obiettivo:** costruire la sorgente vulnerabilità V1.

### Funzioni

- ingestione NVD;
- sync incrementale;
- sync_runs;
- ricerca CVE;
- dettaglio;
- CVSS/severità;
- CPE;
- riferimenti;
- deduplicazione/upsert;
- retry;
- osservabilità.

### Scheduler

La sincronizzazione NVD/feed **non deve essere eseguita nel lifecycle del Web Service FastAPI**.

Target:

**Render Cron Job / worker dedicato**

Requisiti:

- idempotenza;
- non sovrapposizione;
- retry controllato;
- osservabilità;
- audit.

### Gate

**M4 → STOP → integration review**

---

## M5 — Correlation: Asset ↔ Software ↔ CPE ↔ CVE

**Obiettivo:** trasformare i dati raccolti in esposizione contestualizzata.

### Pipeline

```
Asset
 ↓
Software/Product
 ↓
Version
 ↓
CPE
 ↓
CVE
 ↓
Asset Vulnerability Finding
```

### Attività

- normalizzazione;
- matching CPE;
- correlazione;
- deduplicazione;
- creazione/aggiornamento finding;
- tracciabilità del match;
- gestione dei casi non determinabili.

Principio V1:

> privilegiare precisione e spiegabilità rispetto alla sofisticazione algoritmica.

### Gate

**M5 → STOP → correlation accuracy review**

---

## M6 — Vulnerability Analysis & Triage

**Obiettivo:** permettere all'analista di trasformare una vulnerabilità in un'azione gestibile.

### Funzioni

- dettaglio finding;
- asset coinvolti;
- CVSS;
- criticità asset;
- enrichment;
- stato;
- note;
- assegnatario;
- risk score semplice;
- filtri;
- storico essenziale.

### Stati

- NEW
- ANALYZED
- ACKNOWLEDGED
- IN_PROGRESS
- RESOLVED
- NOT_AFFECTED

### Gate

**M6 → STOP → analyst usability review**

---

## M7 — Dashboard / Overview

**Obiettivo:** fornire la vista operativa "Cosa devo guardare oggi?".

### KPI

- CVE totali;
- Critical/High;
- asset vulnerabili;
- nuovi finding;
- finding in trattamento;
- trend;
- vulnerabilità rilevanti;
- accesso diretto al triage.

### Requisiti

- dati reali;
- filtri;
- drill-down;
- performance accettabile;
- nessun dato hardcoded.

### Gate

**M7 → STOP → UX/functional review**

---

## M8 — Feed & Data Import

**Obiettivo:** consolidare l'ingestion delle fonti necessarie alla V1.

### Fonti

- asset/inventory;
- FeedHub;
- CTI;
- Syslog nelle sole parti utili alla V1.

### Pipeline

```
Import
 ↓
Validation
 ↓
Normalization
 ↓
Storage
 ↓
Correlation
```

### Security

- request/file limits;
- multipart limits;
- streaming/chunking quando necessario;
- allowlist formati;
- MIME/content validation;
- temp storage controllato;
- cleanup;
- nessuna esecuzione dei file;
- rate limiting;
- audit accept/reject;
- gestione errori.

### Gate

**M8 → STOP → ingestion security review**

---

## M9 — Reporting

**Obiettivo:** produrre output operativi senza trasformare la piattaforma in una BI.

### Funzioni

- tabelle filtrabili;
- grafici essenziali;
- report Security Team;
- sintesi management;
- export realmente necessari.

### Gate

**M9 → STOP → reporting review**

---

## M10 — Production Hardening & Operations

**Obiettivo:** preparare la V1 al funzionamento controllato in produzione.

### Target

```
Internet
   ↓
Vercel
   ↓
Render Web Service
   ↓
Neon PostgreSQL

Render Cron / Worker
   ↓
NVD / Feeds
   ↓
Neon
```

### Attività

- separazione ambienti;
- Preview/Staging/Production;
- secrets;
- TLS;
- health/readiness;
- logging strutturato;
- request/correlation ID;
- monitoring;
- sync monitoring;
- audit;
- backup;
- restore test;
- migration procedure;
- rollback;
- dependency scanning;
- container/image scanning se applicabile;
- performance baseline;
- security headers;
- CORS finale.

### Gate

**M10 → STOP → release readiness review**

---

## M11 — Independent Security & Code Review

**Obiettivo:** verificare la V1 con una revisione indipendente.

### Aree

- authentication;
- authorization;
- session management;
- CSRF;
- CORS;
- upload;
- injection;
- XSS;
- SSRF;
- access control;
- secrets;
- logging/audit;
- dependency vulnerabilities;
- Docker/runtime;
- PostgreSQL;
- migrations;
- API;
- business logic;
- correlation;
- risk scoring;
- error handling.

### Output

- finding;
- severity;
- remediation;
- retest;
- release recommendation.

### Gate finale

**M11 → STOP → approvazione umana per la produzione**

---

# 4. Dependency Graph

```
M0
 │
 ▼
M1
 │
 ▼
M2
 │
 ├──────────────► M3
 │
 └──────────────► M4
                    │
                    ▼
                   M5
                    │
                    ▼
                   M6
                    │
                    ▼
                   M7

M4 ───────────────► M8
M6 ───────────────► M9

M3 + M4 + M5 + M6 + M7 + M8 + M9
                    │
                    ▼
                   M10
                    │
                    ▼
                   M11
```

**M3 e M4 possono procedere parzialmente in parallelo dopo M2**, purché modello dati e contratti siano sufficientemente stabilizzati.

---

# 5. Regola di avanzamento

Una milestone può essere considerata completata solo quando:

1. il codice previsto è completato;
2. i test previsti sono stati eseguiti;
3. non rimangono blocker non gestiti;
4. la documentazione necessaria è aggiornata;
5. l'impatto security è stato verificato;
6. il risultato è stato sottoposto a review;
7. l'utente ha approvato il passaggio.

**Il completamento tecnico di una milestone non autorizza automaticamente la successiva.**

---

# 6. Regole operative per gli agenti

Qualunque agente, incluso Antigravity, deve:

1. verificare il repository corretto;
2. verificare il branch autorizzato;
3. leggere questo documento;
4. leggere `V1_SCOPE.md`;
5. leggere `V1_IMPLEMENTATION_PLAN.md`;
6. leggere l'architecture baseline;
7. verificare lo stato reale del codice;
8. identificare la milestone esplicitamente autorizzata;
9. implementare esclusivamente quella milestone;
10. eseguire i test;
11. controllare il diff;
12. produrre un report;
13. fermarsi al gate.

### Divieti

Non deve:

- implementare milestone future;
- cambiare lo scope autonomamente;
- modificare `main` durante lo sviluppo;
- saltare milestone;
- introdurre dipendenze non motivate;
- fare refactoring estesi non necessari;
- cambiare architettura senza approvazione;
- trasformare una necessità futura in una funzionalità V1.

---

# 7. Stato operativo corrente

**Milestone autorizzata corrente: M0**

**Obiettivo corrente:** Baseline, Quick Fixes e Test Foundation.

**Branch di lavoro:** `architecture/initial-design`

**Prossimo gate:** completamento M0 → review umana.

Fino all'approvazione esplicita del passaggio successivo, gli agenti devono considerare M1 e tutte le milestone successive come **NON AUTORIZZATE**.

---

# 8. Documenti di riferimento

| Documento | Funzione |
|---|---|
| `docs/product/V1_SCOPE.md` | Scope funzionale V1 |
| `docs/product/V1_IMPLEMENTATION_PLAN.md` | Piano tecnico e milestone |
| `docs/product/V1_DATA_MODEL_AND_CONTRACTS.md` | Modello dati e contratti |
| `docs/agents/PROMPT_OPERATIVO_M0_BASELINE_QUICK_FIXES_TEST_FOUNDATION.md` | Istruzioni operative M0 |
| `ARCHITECTURE.md` | Architettura target/baseline |
| `SECURITY_ARCHITECTURE.md` | Requisiti di sicurezza |
| `PROJECT_DISCOVERY.md` | Stato/discovery iniziale del progetto |
| `CODE_ANALYSIS.md` | Analisi del codice esistente |
| `KNOWN_ISSUES.md` | Problemi noti |
| `API_INVENTORY.md` | Inventario API |

---

# 9. Principio di governance

Questo repository deve essere trattato come un progetto **agent-assisted ma human-governed**.

La roadmap è persistente e versionata.

Il codice può evolvere, ma:

**ROADMAP → MILESTONE → PROMPT OPERATIVO → IMPLEMENTAZIONE → TEST → REVIEW → APPROVAZIONE → MILESTONE SUCCESSIVA**

Nessun agente deve saltare questa catena.
