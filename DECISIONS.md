# DECISION LOG (DECISIONS.md) — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Orchestratore**: Project Manager / Technical Orchestrator  
**Branch Git**: `architecture/initial-design`

---

## Decision Record 001: Architettura Ibrida del Database (SQLite WAL local / PostgreSQL prod)

- **Date**: 2026-09-23
- **Status**: `APPROVED`
- **Context**: L'applicazione utilizza SQLite (`data/security.db`) per la persistenza dei dati. [CONFIRMED: `app/core/database.py#L7-L13`]
- **Problem**: SQLite soffre di blocchi transazionali in scrittura (`database is locked`) in presenza di ingestion concorrente di syslog ed asset su carichi elevati.
- **Options**:
  1. *Opzione A*: Solo SQLite con parametri di timeout incrementati.
  2. *Opzione B*: Migrazione obbligatoria a PostgreSQL per qualsiasi ambiente.
  3. *Opzione C*: Architettura Ibrida: SQLite in modalità Write-Ahead Logging (WAL) per ambienti locali/sviluppo, PostgreSQL per ambienti di produzione/test (Proxmox/Docker).
- **Chosen Approach**: **Opzione C (Architettura Ibrida)**.
- **Trade-offs**: Richiede il mantenimento della compatibilità SQL via SQLAlchemy 2.0 ORM senza costringere a query specifiche di un singolo motore DBMS.
- **Consequences**: Zero frizione per lo sviluppo locale senza installare servizi aggiuntivi, massima concorrenza e scalabilità in produzione con PostgreSQL via `docker-compose.yml`.

---

## Decision Record 002: Disaccoppiamento Sincronizzazioni NVD e Feed tramite Task di Background

- **Date**: 2026-09-23
- **Status**: `APPROVED`
- **Context**: I job di sincronizzazione NVD e Feed sono definiti in configurazione ma inattivi nel ciclo di vita dell'applicazione. [CONFIRMED: `app/main.py#L13`, `app/core/config.py#L44-L45`]
- **Problem**: L'esecuzione sincrona durante la chiamata API blocca la risposta dell'utente per decine di secondi.
- **Options**:
  1. Invocazione sincrona via HTTP request (attuale).
  2. Integrazione di uno scheduler in background nel `lifespan` di FastAPI (es. `APScheduler` o `FastAPI BackgroundTasks`).
- **Chosen Approach**: **Integrazione dello Scheduler nel Lifespan FastAPI**.
- **Trade-offs**: Minimo consumo di memoria aggiuntivo nel processo backend per gestire il ciclo di sincronizzazione periodica.
- **Consequences**: L'utente ottiene una risposta immediata dalle API e i dati CVE/Feed rimangono costantemente aggiornati in background.

---

## Decision Record 003: Implementazione di Autenticazione Centralizzata e RBAC

- **Date**: 2026-09-23
- **Status**: `APPROVED`
- **Context**: Assenza totale di autenticazione ed autorizzazione nel repository corrente. [CONFIRMED: `app/main.py`]
- **Problem**: Rischio critico di sicurezza ed impossibilità di impiego in ambienti aziendali.
- **Chosen Approach**: Introduzione del modulo di autenticazione con hashing `passlib[bcrypt]`, token JWT `python-jose` e controllo ruoli RBAC (`ADMIN`, `ANALYST`, `READ_ONLY`).
- **Consequences**: Rotte protette da `Depends(get_current_user)` e `Depends(require_role(...))`.
