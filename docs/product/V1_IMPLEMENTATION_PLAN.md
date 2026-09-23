# Security Dashboard — V1 Implementation Plan

**Stato:** APPROVATO COME PIANO DI IMPLEMENTAZIONE  
**Fase:** Gate 2.2 — V1 Technical Implementation Plan  
**Branch:** `architecture/initial-design`  
**Data:** 2026-09-23  
**Scope di riferimento:** `docs/product/V1_SCOPE.md`

## 1. Scopo del Gate 2.2

Questo documento traduce lo scope funzionale V1 in un piano tecnico eseguibile.

Durante questo gate non deve essere implementato codice applicativo, modificato il database, modificata l'infrastruttura o avviato un deployment.

L'obiettivo è stabilire:

- ordine di implementazione;
- dipendenze tra componenti;
- deliverable di ogni milestone;
- test richiesti;
- criteri di accettazione;
- punti di arresto e approvazione umana.

## 2. Principi di implementazione

1. **V1 prima del futuro.** Le funzionalità escluse da `V1_SCOPE.md` non vengono implementate.
2. **Security by design.** Autenticazione, autorizzazione, CSRF, CORS, upload security, audit e gestione dei segreti sono prerequisiti, non attività finali.
3. **PostgreSQL come target.** SQLite resta utile per sviluppo locale controllato, ma la compatibilità con PostgreSQL/Neon deve essere verificata prima del rilascio.
4. **Incrementalità.** Ogni milestone deve produrre un incremento verificabile.
5. **Test prima del gate successivo.** Nessuna milestone si considera completata senza i test previsti.
6. **Backward compatibility dove possibile.** Le funzionalità esistenti utili alla V1 vengono riutilizzate e corrette prima di essere riscritte.
7. **Nessun over-engineering.** Preferire soluzioni semplici, leggibili, osservabili e facilmente manutenibili.
8. **Un solo cambiamento di scope alla volta.** Ogni nuova esigenza non prevista richiede classificazione e approvazione.

---

# 3. Milestone V1

## M0 — Baseline, Quick Fixes e Test Foundation

**Obiettivo:** rendere affidabile la baseline esistente prima di costruire sopra di essa.

### Attività

- verificare lo stato reale del repository rispetto alla baseline;
- risolvere il template CVE mancante;
- correggere il `request` mancante nell'endpoint dashboard;
- rimuovere import duplicati/errore evidenti;
- aggiungere regression test per i problemi corretti;
- verificare avvio applicazione e test suite;
- documentare eventuali blocker residui.

### Output

- applicazione avviabile;
- test di regressione;
- lista blocker aggiornata.

### Gate

**STOP → review umana.**

Non introdurre nuove funzionalità.

---

## M1 — Security Foundation + Authentication/RBAC

**Obiettivo:** creare la base di sicurezza necessaria prima di esporre funzionalità operative.

### Attività

- autenticazione server-side;
- session management;
- cookie Secure/HttpOnly/SameSite;
- logout e invalidazione sessione;
- RBAC;
- ruoli ADMIN / ANALYST / READ_ONLY;
- permission-based authorization;
- 401/403 coerenti;
- CSRF per richieste state-changing;
- CORS con allowlist;
- secret management;
- security headers;
- audit degli eventi di sicurezza;
- rate limiting dove necessario.

### Output

- autenticazione funzionante;
- matrice permessi applicata;
- protezione endpoint e azioni;
- test di autorizzazione e CSRF.

### Gate

**STOP → security review.**

---

## M2 — PostgreSQL / Neon + Data Layer

**Obiettivo:** rendere il modello dati pronto per il target PostgreSQL.

### Attività

- definire schema V1 definitivo;
- verificare modelli SQLAlchemy;
- introdurre Alembic;
- creare migration baseline;
- gestire timestamp, UUID/ID e vincoli;
- indici per ricerca e correlazione;
- verificare compatibilità PostgreSQL;
- test con database PostgreSQL;
- configurare ambiente Preview isolato;
- definire strategia migration/rollback.

### Entità minime previste

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
- feeds/feed items;
- imports;
- sync_runs;
- risk assessments;
- triage/status e note, secondo il modello definitivo.

### Gate

**STOP → schema review + PostgreSQL integration review.**

---

## M3 — Asset Inventory

**Obiettivo:** rendere l'asset inventory una funzione V1 realmente utilizzabile.

### Funzioni

- elenco asset;
- ricerca;
- filtri;
- dettaglio asset;
- creazione/modifica;
- import;
- criticità;
- vendor/product/version;
- CPE;
- relazione software/asset;
- vulnerabilità associate.

### Test

- CRUD;
- autorizzazioni;
- validazione;
- import;
- PostgreSQL;
- audit.

### Gate

**STOP → functional review.**

---

## M4 — CVE / NVD

**Obiettivo:** costruire la sorgente vulnerabilità V1.

### Funzioni

- ingestione NVD;
- sincronizzazione incrementale;
- gestione sync_runs;
- ricerca CVE;
- dettaglio CVE;
- CVSS/severità;
- CPE;
- riferimenti;
- date;
- deduplicazione/upsert;
- gestione errori/retry;
- osservabilità del job.

### Scheduler

La sincronizzazione non deve essere eseguita dal lifecycle del Web Service FastAPI.

Target:

**Render Cron Job / worker dedicato.**

Deve essere:

- idempotente;
- non sovrapponibile;
- osservabile;
- con retry controllato;
- con audit della sincronizzazione.

### Gate

**STOP → integration review.**

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
- tracciabilità della correlazione;
- gestione dei casi non determinabili.

La V1 deve privilegiare precisione e spiegabilità.

### Gate

**STOP → correlation accuracy review.**

---

## M6 — Vulnerability Analysis & Triage

**Obiettivo:** consentire all'analista di trasformare una vulnerabilità in un'azione gestibile.

### Funzioni

- dettaglio finding;
- asset coinvolti;
- CVSS;
- criticità asset;
- stato;
- note;
- assegnatario;
- enrichment disponibile;
- risk score semplice;
- filtri per priorità/stato;
- storico essenziale.

### Stati

- NEW;
- ANALYZED;
- ACKNOWLEDGED;
- IN_PROGRESS;
- RESOLVED;
- NOT_AFFECTED.

Gli stati possono essere affinati durante l'implementazione senza creare workflow complessi.

### Gate

**STOP → analyst usability review.**

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
- collegamenti diretti al triage.

### Requisiti

- dati reali;
- filtri;
- drill-down;
- performance accettabile;
- nessun dato hardcoded.

### Gate

**STOP → UX/functional review.**

---

## M8 — Feed e Data Import

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

### Security requirements

- limite request/file;
- limite multipart;
- streaming/chunking quando necessario;
- allowlist formati;
- validazione MIME/content;
- temp storage controllato;
- cleanup;
- nessuna esecuzione dei file;
- rate limiting;
- audit accept/reject;
- gestione errori.

### Gate

**STOP → ingestion security review.**

---

## M9 — Reporting

**Obiettivo:** produrre output operativi senza trasformare la piattaforma in una BI.

### V1

- tabelle filtrabili;
- grafici essenziali;
- report Security Team;
- sintesi management;
- export nei formati realmente necessari.

### Gate

**STOP → reporting review.**

---

## M10 — Production Hardening & Operations

**Obiettivo:** preparare la V1 al funzionamento controllato in produzione.

### Deployment target

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

- environment separation;
- Vercel Preview;
- Render staging/production;
- Neon Preview/Production;
- secrets;
- TLS;
- health/readiness;
- logging strutturato;
- correlation/request ID;
- monitoring;
- sync monitoring;
- audit logs;
- database backup;
- restore test;
- migration procedure;
- rollback procedure;
- dependency scanning;
- container/image scanning se applicabile;
- performance baseline;
- security headers;
- configurazione CORS finale.

### Gate

**STOP → release readiness review.**

---

## M11 — Independent Security & Code Review

**Obiettivo:** verificare la V1 senza assumere che i test interni siano sufficienti.

### Review

- autenticazione;
- autorizzazione;
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

- findings;
- severity;
- remediation;
- retest;
- release recommendation.

### Gate finale

**STOP → approvazione umana per produzione.**

---

# 4. Dependency Graph

```
M0
 │
 ▼
M1 ───────┐
 │        │
 ▼        │
M2 ◄──────┘
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

M3 e M4 possono procedere in parte in parallelo dopo M2, purché il modello dati e i contratti siano congelati.

---

# 5. Regola di avanzamento

Una milestone può passare alla successiva solo quando:

1. il codice previsto è completato;
2. i test previsti passano;
3. non sono presenti blocker aperti;
4. la documentazione necessaria è aggiornata;
5. l'impatto security è stato verificato;
6. il risultato è stato sottoposto a review;
7. l'utente ha approvato il passaggio.

Gli agenti devono **fermarsi al termine della milestone** quando il gate richiede approvazione umana.

---

# 6. Regola per Antigravity

Antigravity deve operare come agente esecutivo sotto controllo del piano V1.

Prima di modificare codice deve:

1. leggere `docs/product/V1_SCOPE.md`;
2. leggere questo documento;
3. leggere l'architecture baseline;
4. verificare lo stato reale del repository;
5. identificare la milestone autorizzata;
6. implementare esclusivamente quella milestone;
7. eseguire i test;
8. produrre un report delle modifiche;
9. fermarsi al gate.

È vietato:

- implementare funzionalità Future;
- cambiare scope autonomamente;
- modificare `main` durante lo sviluppo;
- saltare milestone;
- introdurre dipendenze non motivate;
- fare refactoring estesi non necessari;
- cambiare architettura senza aggiornare la documentazione e ottenere approvazione.

---

# 7. Definition of Done tecnica V1

La V1 è tecnicamente pronta quando:

- le funzioni definite in `V1_SCOPE.md` sono implementate;
- autenticazione/RBAC sono attivi;
- dati e migrazioni PostgreSQL sono verificati;
- ingestion e correlazione funzionano;
- CVE e asset sono correlati;
- triage è operativo;
- Dashboard e reporting sono funzionanti;
- upload/import sono protetti;
- test automatici e integration test sono presenti;
- dependency/security scanning è eseguito;
- backup e restore sono verificati;
- monitoring/logging sono operativi;
- independent security review è chiusa;
- nessun blocker critico/high non accettato rimane aperto;
- l'utente approva il rilascio.

---

# 8. Stato iniziale del Gate 2.2

**Gate 2.2: COMPLETATO DOCUMENTALMENTE**

Prossimo passaggio:

> **Gate 2.3 — V1 Data Model & Technical Contracts**

Prima di scrivere codice dovranno essere definiti in dettaglio:

- entità;
- relazioni;
- cardinalità;
- vincoli;
- indici;
- stati;
- API/endpoint;
- contratti input/output;
- eventi di ingestion;
- identificativi e deduplicazione;
- audit requirements.

**Nessuna implementazione applicativa è autorizzata dal presente documento.**
