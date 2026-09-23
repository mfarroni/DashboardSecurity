# Security Dashboard — V1 Data Model & Technical Contracts

**Stato:** GATE 2.3 COMPLETATO DOCUMENTALMENTE  
**Fase:** Architecture / V1 Technical Design  
**Branch:** architecture/initial-design  
**Data:** 2026-09-23  
**Riferimenti:** V1_SCOPE.md, V1_IMPLEMENTATION_PLAN.md, DATA_MODEL.md, API_INVENTORY.md, SECURITY_ARCHITECTURE.md

## 1. Obiettivo

Questo documento congela il modello dati e i contratti tecnici minimi necessari per iniziare l'implementazione della V1.

Non è un documento di implementazione dettagliata del codice. Stabilisce i confini che il codice deve rispettare.

> Prima definiamo il significato dei dati e dei contratti, poi implementiamo.

## 2. CURRENT → TARGET

Il repository dispone già di un modello funzionante con otto aree principali: asset, CVE, correlazioni asset-vulnerabilità, feed, relazioni feed-CVE, syslog, import batch e user settings.

La V1 non richiede una riscrittura totale.

Strategia:

CURRENT → riutilizzare ciò che è valido → correggere ciò che è difettoso → normalizzare ciò che serve → TARGET V1.

Il target aggiunge identity/RBAC, audit, sync tracking, asset/software/CPE, CVE, vulnerability findings, feed/import e risk/triage.

Non introdurre tabelle o servizi esclusivamente per funzionalità future.

## 3. Entità V1

### 3.1 Identity

**users**

Campi logici minimi:
- id
- username/email
- password_hash
- is_active
- created_at
- updated_at
- last_login_at

Vincoli:
- username/email univoco;
- password mai memorizzata in chiaro;
- account disattivabile senza cancellazione obbligatoria.

**roles**

Ruoli V1:
- ADMIN
- ANALYST
- READ_ONLY

**permissions**

Forma: resource + action.

Esempi:
- asset:read
- asset:write
- asset:delete
- vulnerability:read
- vulnerability:triage
- feed:import
- cve:sync
- report:export
- audit:read
- administration:manage

**user_roles / role_permissions**

Relazioni many-to-many.

Non utilizzare controlli sparsi basati esclusivamente su stringhe di ruolo.

## 4. Asset Model

### 4.1 assets

Rappresenta un'entità tecnologica appartenente al perimetro.

Campi V1:
- id
- asset_identifier
- name
- type
- vendor
- product
- version
- environment
- criticality
- status
- cpe_id quando determinabile
- notes
- created_at
- updated_at
- imported_at
- import_batch_id

Regole:
- asset_identifier deve consentire la deduplicazione;
- vendor/product/version devono essere separabili;
- CPE non è obbligatorio;
- criticità asset e severità CVE sono concetti distinti;
- asset dismesso non equivale ad asset cancellato.

### 4.2 software_products

Entità normalizzata per vendor/prodotto/versione quando utile.

Relazione logica:

Asset 1 → N SoftwareProduct

La scelta finale tra tabella normalizzata e campi direttamente su asset deve essere verificata durante M2 sulla base del codice esistente. Non creare complessità senza beneficio concreto per la V1.

### 4.3 CPE

Requisiti:
- valore normalizzato;
- validazione del formato quando possibile;
- supporto a più CPE quando necessario;
- tracciabilità della fonte.

Non assumere che ogni asset possieda un CPE affidabile.

## 5. Vulnerability Model

### 5.1 cves

Repository canonico delle vulnerabilità.

Campi V1:
- id
- cve_id
- description
- CVSS score
- CVSS severity
- CVSS vector
- published_date
- last_modified_date
- CPE matches
- references
- source
- vendor advisory
- nvd_fetched_at
- created_at
- updated_at

Vincolo fondamentale:

UNIQUE(cve_id)

### 5.2 asset_vulnerability_findings

Relazione operativa tra CVE e asset.

Campi:
- id
- asset_id
- cve_id
- match_type
- match_confidence
- detected_at
- status
- triage_notes
- assigned_to
- triage_updated_at
- triage_updated_by
- acknowledged_at
- resolved_at

Vincolo fondamentale:

UNIQUE(asset_id, cve_id)

La stessa CVE sullo stesso asset rappresenta un finding, non due record indipendenti.

Match type V1:
- CPE_EXACT
- CPE_PARTIAL
- TEXTUAL
- MANUAL

La confidence non sostituisce la decisione dell'analista.

## 6. Triage Model

Stati canonici:

NEW → ANALYZED → ACKNOWLEDGED → IN_PROGRESS → RESOLVED

Con possibilità di:
- NEW → NOT_AFFECTED
- ANALYZED → NOT_AFFECTED
- RESOLVED → IN_PROGRESS
- NOT_AFFECTED → ANALYZED

Il workflow non deve introdurre approvazioni multiple, SLA engine o case management nella V1.

## 7. Risk Assessment

Il rischio V1 è un risultato calcolabile e tracciabile.

Input possibili:
- CVSS
- criticità asset
- esposizione
- stato triage
- exploit/enrichment disponibile

Il risultato conserva almeno:
- score
- metodologia/versione
- input snapshot
- calculated_at
- calculated_by o job_id

Il risk score deve essere spiegabile e riproducibile.

## 8. Feed Model

### 8.1 feed_items

Campi:
- id
- source
- source_id
- title
- url
- source_name
- published_at
- collected_at
- content
- summary
- tags
- raw_data
- created_at
- updated_at

Vincolo:

UNIQUE(source, source_id)

Quando source_id non è disponibile deve essere definita una chiave deterministica di deduplicazione.

### 8.2 feed_item_cves

Relazione many-to-many tra feed item e CVE.

Campi:
- feed_item_id
- cve_id
- extraction_method
- context_snippet

Metodi V1:
- STRUCTURED
- REGEX
- MANUAL

## 9. Import Model

### import_batches

Ogni importazione deve produrre un identificatore e un risultato tracciabile.

Campi:
- id
- batch_id
- source
- filename/source reference
- started_at
- finished_at
- status
- records_read
- records_created
- records_updated
- records_rejected
- error_summary
- actor_user_id quando avviato da un utente

Stati:
- STARTED
- COMPLETED
- COMPLETED_WITH_ERRORS
- FAILED
- CANCELLED

L'import deve essere ripetibile senza produrre duplicati.

## 10. Sync Model

### sync_runs

Campi:
- id
- job_type
- source
- started_at
- finished_at
- status
- attempt
- records_read
- records_created
- records_updated
- records_failed
- error_summary
- idempotency_key
- request_id/job_id

Una stessa finestra di sincronizzazione non deve essere elaborata contemporaneamente da due worker.

## 11. Audit Model

### audit_logs

Campi:
- id
- timestamp
- actor_user_id
- action
- resource_type
- resource_id
- outcome
- source_ip
- request_id
- metadata JSON

Audit minimo:
- login success/failure
- logout
- authorization denied
- creazione/modifica/cancellazione asset
- triage vulnerability
- import
- sync
- export
- modifiche amministrative
- azioni di sicurezza rilevanti

Non registrare password, session cookie, token o secret.

Gli audit log sono append-oriented.

## 12. Relazioni principali

USER → USER_ROLE → ROLE → ROLE_PERMISSION → PERMISSION  
USER → AUDIT_LOG

ASSET → SOFTWARE/PRODUCT → CPE  
ASSET → ASSET_VULNERABILITY_FINDING → CVE  
CVE → FEED_ITEM_CVE → FEED_ITEM

ASSET + CVE → RISK_ASSESSMENT

IMPORT_BATCH → dati importati  
SYNC_RUN → NVD / Feed synchronization

## 13. API Contract V1

Convenzioni:
- JSON per API;
- HTML server-rendered/HTMX dove previsto;
- HTTP status semanticamente corretti;
- error response uniforme;
- pagination standardizzata;
- filtri espliciti;
- identificatori stabili;
- date ISO 8601;
- nessun errore interno dettagliato esposto al client.

Per le nuove API, quando utile:

{
  "data": {},
  "meta": {},
  "error": null
}

Per liste:

{
  "data": [],
  "meta": {
    "page": 1,
    "page_size": 50,
    "total": 0
  },
  "error": null
}

Non è necessario riscrivere tutte le API esistenti in un unico passaggio.

## 14. API V1 per dominio

### Authentication

POST /auth/login  
POST /auth/logout  
GET /auth/me

### Dashboard

GET /api/overview  
GET /api/dashboard/critical-vulns  
GET /api/dashboard/recent-feed  
GET /api/dashboard/assets-by-type

### Assets

GET /api/assets  
GET /api/assets/{asset_id}  
POST /api/assets  
PATCH /api/assets/{asset_id}  
DELETE /api/assets/{asset_id}  
POST /api/assets/import/preview  
POST /api/assets/import/execute  
GET /api/assets/import/history  
GET /api/assets/export/current

### CVE

GET /api/cve  
GET /api/cve/{cve_id}  
POST /api/cve/sync/nvd  
POST /api/cve/correlate

### Vulnerability Findings

GET /api/vulnerabilities  
GET /api/vulnerabilities/{finding_id}  
PATCH /api/vulnerabilities/{finding_id}  
GET /api/assets/{asset_id}/vulnerabilities  
GET /api/cve/{cve_id}/findings

### Feeds

GET /api/feed  
GET /api/feed/{item_id}  
POST /api/feed/import/feedhub  
POST /api/feed/import/cti  
GET /api/feed/import/history

### Administration

GET /api/admin/users  
POST /api/admin/users  
PATCH /api/admin/users/{user_id}  
GET /api/admin/roles  
GET /api/admin/permissions  
GET /api/admin/audit

Le reporting definitivo viene congelato in M9 dopo la verifica dei casi d'uso reali.

## 15. Autorizzazione API

Ogni endpoint state-changing deve seguire:

Authentication → CSRF validation → Permission check → Business validation → Persistence → Audit

Gli endpoint GET devono verificare autenticazione e permesso di lettura.

## 16. Ingestion Contracts

SOURCE → RAW INPUT → VALIDATION → NORMALIZATION → DEDUPLICATION → PERSISTENCE → CORRELATION → AUDIT/METRICS

Normalizzare almeno:
- case;
- date;
- vendor;
- product;
- version;
- CPE;
- CVE ID;
- source identifiers.

Deduplicazione:
- CVE → cve_id;
- feed → source + source_id;
- asset → identificatore stabile;
- finding → asset_id + cve_id;
- import → batch_id;
- sync → idempotency_key.

## 17. NVD Sync Contract

La sincronizzazione NVD deve:
1. acquisire una finestra temporale definita;
2. validare la risposta;
3. fare upsert delle CVE;
4. aggiornare last_modified_date;
5. registrare sync_run;
6. contabilizzare record creati/aggiornati/scartati;
7. gestire retry;
8. non produrre duplicati;
9. non bloccare il Web Service;
10. produrre log strutturati.

La sincronizzazione deve poter essere rieseguita in sicurezza.

## 18. Correlation Contract

Input:
- asset;
- software/product;
- version;
- CPE;
- CVE;
- feed/enrichment disponibili.

Output:
- zero o più vulnerability findings.

Ogni finding deve poter rispondere:

> Perché questa CVE è stata associata a questo asset?

Devono quindi essere conservati almeno:
- match_type;
- match_confidence quando disponibile;
- source/provenienza;
- timestamp.

La correlazione non deve creare finding duplicati.

## 19. Error Contract

Codici minimi:
- 400 Bad Request;
- 401 Unauthorized;
- 403 Forbidden;
- 404 Not Found;
- 409 Conflict;
- 413 Payload Too Large;
- 422 Unprocessable Entity;
- 429 Too Many Requests;
- 500/503 per errore interno o dipendenza indisponibile.

Non esporre stack trace al client.

## 20. Idempotenza

Le operazioni di ingestion e sync devono essere idempotenti.

same input + same identity = same logical result

Ripetere un import o una sincronizzazione non deve creare CVE, asset, finding o feed duplicati.

## 21. Indexing Strategy

Indici iniziali da valutare/implementare in M2:

Assets:
- identifier;
- vendor + product;
- type + criticality;
- CPE.

CVE:
- cve_id unique;
- severity + score;
- published_date;
- last_modified_date.

Findings:
- asset_id + cve_id unique;
- status;
- asset_id;
- cve_id;
- match_type.

Feed:
- source + source_id unique;
- published_at;
- source.

Audit:
- timestamp;
- actor_user_id;
- resource_type + resource_id;
- request_id.

Gli indici definitivi devono essere confermati con query reali e PostgreSQL EXPLAIN. Non creare decine di indici preventivi.

## 22. Retention

Prima della produzione devono essere definite policy per:
- syslog_entries;
- feed_items;
- audit_logs;
- sync_runs;
- import_batches.

La retention quantitativa deve essere approvata come requisito operativo.

## 23. CURRENT → TARGET migration map

Durante M2 deve essere prodotta una migration map:

CURRENT TABLE → TARGET V1 TABLE → migration → backfill se necessario → validation

Le entità CURRENT assets, cves, asset_vulnerabilities, feed_items, feed_item_cves, syslog_entries, import_batches e user_settings costituiscono la base da cui partire.

Nessun campo CURRENT deve essere eliminato senza verificare prima il suo utilizzo nel codice.

## 24. Gate 2.3 Acceptance Criteria

Gate 2.3 è completato documentalmente perché sono stati definiti:
- entità V1;
- relazioni principali;
- cardinalità logiche;
- vincoli di unicità;
- stati di triage;
- risk assessment;
- import/sync;
- audit;
- API contract;
- error contract;
- idempotenza;
- ingestion pipeline;
- NVD contract;
- correlation contract;
- indexing strategy;
- retention requirements;
- CURRENT → TARGET strategy.

Decisioni demandate a M2:
- normalizzazione definitiva software/product;
- tipi ID definitivi;
- mapping SQLAlchemy → PostgreSQL;
- indici definitivi;
- migration/backfill;
- applicazione response envelope alle API esistenti;
- schema report;
- retention quantitativa.

Queste decisioni non devono essere inventate dall'agente senza evidenza dal codice o approvazione.

## 25. Stato del progetto

Gate 2.1 — Architecture hardening: COMPLETATO  
Gate 2.2 — V1 Implementation Plan: COMPLETATO  
Gate 2.3 — Data Model & Contracts: COMPLETATO  
Next — M0 Quick Fixes: DA AUTORIZZARE

**Nessuna implementazione applicativa è autorizzata da questo documento.**

Il prossimo lavoro tecnico autorizzabile è M0, dopo esplicita approvazione umana.
