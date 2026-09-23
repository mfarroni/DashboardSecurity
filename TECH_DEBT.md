# TECHNICAL DEBT — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Catalogazione del debito tecnico architetturale, strutturale e manutentivo.

---

## 1. Debito Tecnico Architetturale

### 1.1 Assenza del Layer di Autenticazione / Autorizzazione
- **Descrizione**: L'applicazione non prevede gestione utenti, ruoli (RBAC), né protezione per le operazioni sensibili (elimina log, modifica triage, import massivi).
- **Impatto**: Impossibilità di impiego sicuro in ambienti multi-utente o esposti in rete aziendale.
- **Classificazione**: [CONFIRMED: `app/main.py`]

### 1.2 Ingestion Synchronous & In-Memory (Rischio Improvvisi Crash OOM)
- **Descrizione**: Gli import di file CSV, Excel, JSON e Syslog avvengono interamente all'interno della richiesta HTTP e in memoria RAM.
- **Impatto**: Richieste lunghe causano il blocco del worker Uvicorn e possono provocare timeout o esaurimento della RAM con file di grandi dimensioni.
- **Soluzione Consigliata**: Spostare l'elaborazione dei file su task asincroni di background (es. FastAPI `BackgroundTasks`, Celery o Redis Queue).
- **Classificazione**: [CONFIRMED: `app/api/assets.py#L220`, `app/api/syslog.py#L274`]

### 1.3 Job di Background Inattivi nel Lifespan
- **Descrizione**: I parametri di intervallo per NVD Sync e Feed Sync sono definiti nel file `config.py`, ma nessun task schedulato è avviato nel `lifespan` di FastAPI.
- **Impatto**: La sincronizzazione automatica dei dati non avviene a meno di invocazioni manuali degli endpoint o script esterni OpenCode.
- **Classificazione**: [CONFIRMED: `app/main.py#L13-L21`, `app/core/config.py#L44-L45`]

---

## 2. Debito Tecnico di Codice e Modelli

### 2.1 Sintassi Legacy Pydantic v1
- **Descrizione**: Schemi definiti con la sintassi `orm_mode = True` anziché la moderna `from_attributes = True` di Pydantic v2.
- **Impatto**: Avvisi di deprecazione e mancato sfruttamento delle prestazioni migliorate del motore Rust di Pydantic v2.
- **Classificazione**: [CONFIRMED: `app/schemas/schemas.py#L79,L118,L165,L198`]

### 2.2 Utilizzo di `difflib.SequenceMatcher` per Correlazione Testuale
- **Descrizione**: La correlazione testuale fallback utilizza `difflib.SequenceMatcher` eseguito in CPU su ogni coppia Asset-CVE direttamente durante le chiamate DB.
- **Impatto**: Lento ed inefficiente su insiemi di dati elevati (complessità quadratica $O(N \times M)$).
- **Soluzione Consigliata**: Utilizzo di indici Full-Text Search (FTS5 in SQLite / pg_trgm in Postgres) o motori dedicati (Elasticsearch/Meilisearch).
- **Classificazione**: [CONFIRMED: `app/services/correlation.py#L20,L113-L176`]

### 2.3 Gestione SQLite Concorrente Limitata
- **Descrizione**: Configurazione SQLite con `StaticPool` in ambiente multi-thread/async.
- **Impatto**: SQLite applica lock a livello di intero file per le operazioni di scrittura. Ingestion parallele di syslog e asset provocano errori di tipo `sqlite3.OperationalError: database is locked`.
- **Classificazione**: [CONFIRMED: `app/core/database.py#L11`]
