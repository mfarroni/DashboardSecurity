# ARCHITECTURE — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Ricostruzione dell'architettura effettivamente implementata tramite ispezione codice (Senza modifiche).

---

## 1. Diagramma dell'Architettura Implementata

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT / BROWSER                              │
│         (HTML Rendered Server-Side + Dynamic Updates via HTMX)          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP / HTMX Requests
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                             FASTAPI BACKEND                             │
│                           (`app/main.py`)                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                            ROUTER API                             │  │
│  │   / (Dashboard UI)   /api/assets   /api/cve   /api/feed           │  │
│  │   /api/syslog        /api/import   /api/settings                  │  │
│  └───────────────────────────────┬───────────────────────────────────┘  │
│                                  │                                      │
│  ┌───────────────────────────────▼───────────────────────────────────┐  │
│  │                         BUSINESS LOGIC                            │  │
│  │   Correlation Engine (`app/services/correlation.py`)               │  │
│  │   NVD Client Sync (`app/api/cve.py`)                              │  │
│  │   Syslog & Feed Parsers (`app/api/syslog.py`, `app/api/feed.py`)  │  │
│  └───────────────────────────────┬───────────────────────────────────┘  │
│                                  │ SQLAlchemy ORM                       │
│                                  ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                          DATABASE LOCAL                           │  │
│  │             SQLite File (`data/security.db`) / PostgreSQL          │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ External HTTP API Calls
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           SERVIZI ESTERNI                               │
│  ┌────────────────────────┐                   ┌──────────────────────┐  │
│  │   NVD REST API v2.0    │                   │   File FeedHub / CTI │  │
│  │ (services.nvd.nist.gov)│                   │   (JSON/CSV Upload)  │  │
│  └────────────────────────┘                   └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dettaglio dei Layer Applicativi

### 2.1 Frontend Layer
- **Tecnologia**: Server-Side Rendering HTML basato su Jinja2 Templates (`app/templates/`) e aggiornamenti dinamici asincroni tramite HTMX (`app/templates/partials/`). [CONFIRMED: `app/main.py#L40-L44`, `app/api/dashboard.py#L22-L50`]
- **Pagine Web Serve**:
  - `/`: Overview Dashboard principale. [CONFIRMED: `app/api/dashboard.py#L22`]
  - `/perimetro`: Gestione Asset Inventory. [CONFIRMED: `app/api/dashboard.py#L27`]
  - `/vulnerabilita`: Matrice delle vulnerabilità ed esiti triage. [CONFIRMED: `app/api/dashboard.py#L32`]
  - `/feed`: Stream dei Feed di sicurezza ed intelligenza minacce. [CONFIRMED: `app/api/dashboard.py#L37`]
  - `/syslog`: Visualizzatore log ed eventi correlati. [CONFIRMED: `app/api/dashboard.py#L42`]
  - `/cve/{cve_id}`: Dettaglio scheda CVE. [CONFIRMED: `app/api/dashboard.py#L47`]

### 2.2 API Layer
- **Framework**: FastAPI v0.104.1. [CONFIRMED: `requirements.txt#L2`]
- **Documentazione automatica**: OpenAPI / Swagger UI disponibile all'endpoint `/docs`. [CONFIRMED: `app/main.py#L23-L28`, `tests/test_api.py#L22-L26`]
- **Routing**: 7 sub-router registrati in `app/main.py` con prefissi dedicati. [CONFIRMED: `app/main.py#L48-L54`]

### 2.3 Business Logic & Data Engine Layer
- **Correlation Engine (`app/services/correlation.py`)**:
  - `cpe_match_score`: Match esatto o parziale su stringhe CPE 2.3 (`cpe:2.3:a:vendor:product:version`). [CONFIRMED: `app/services/correlation.py#L23-L55`]
  - `textual_match_score`: Fallback basato sulla similarità di sequenze (`difflib.SequenceMatcher`) con soglia predefinita a `0.7`. [CONFIRMED: `app/services/correlation.py#L58-L110`]
- **NVD Sync Service (`app/api/cve.py`)**:
  - Client asincrono HTTP `httpx` per interrogazione API NVD v2.0 con gestione del rate-limiting (5 req/30s senza key, 50 req/30s con key). [CONFIRMED: `app/api/cve.py#L24-L68`]

### 2.4 Database Layer
- **ORM**: SQLAlchemy v2.0.30 con modello dichiarativo (`declarative_base`). [CONFIRMED: `app/core/database.py#L22`]
- **DBMS predefinito**: SQLite `sqlite:///data/security.db` configurato con `StaticPool` e `check_same_thread: False` per la concorrenza locale. [CONFIRMED: `app/core/database.py#L7-L13`]
- **Supporto PostgreSQL**: Pronta predisposizione per PostgreSQL via variabile d'ambiente `DATABASE_URL`. [CONFIRMED: `app/core/database.py#L14-L19`, `.env.example#L9`]

---

## 3. Trust Boundaries e Sicurezza Architetturale

- **Trust Boundary 1: Client ↔ Application Server**:
  - **Stato**: Inesistente / Aperto.
  - **Evidenza**: Non è implementato alcun meccansimo di Autenticazione (es. Login, JWT, Sessions) o Autorizzazione (RBAC). Chiunque possa raggiungere la porta 8000 ha accesso totale a lettura, scrittura, modifica e cancellazione dati. [CONFIRMED: assenza di middleware auth in `app/main.py`]
- **Trust Boundary 2: Application Server ↔ NVD REST API**:
  - **Stato**: Affidato a TLS / HTTPS.
  - **Evidenza**: Utilizzo di URL HTTPS `https://services.nvd.nist.gov/rest/json/cves/2.0`. API Key inviata via header HTTP `apiKey` se configurata. [CONFIRMED: `app/core/config.py#L21`, `app/api/cve.py#L30-L34`]
- **Trust Boundary 3: File Uploads ↔ Processing Engine**:
  - **Stato**: Parzialmente protetto da Pydantic / Pandas.
  - **Evidenza**: I file inviati tramite i form multipart di importazione vengono elaborati in memoria via `pandas` ed estrazione regex senza sanitizzazione preventiva delle risorse o limiti sulla dimensione del payload in ingress. [CONFIRMED: `app/api/assets.py#L143-L162`]

---

## 4. Gestione Secret, Sessioni e Logging

- **Gestione Secret**:
  - `SECRET_KEY`: Caricato da variabile d'ambiente `.env` con valore di fallback insicuro `dev-secret-change-in-production`. [CONFIRMED: `app/core/config.py#L26`]
  - `NVD_API_KEY`: Caricato da variabile d'ambiente o opzionale. [CONFIRMED: `app/core/config.py#L20`]
- **Gestione Sessioni**: NON IMPLEMENTATA. L'applicazione è priva di stato di sessione utente. [CONFIRMED]
- **Logging Applicativo**: Configurato al livello `INFO` tramite Pydantic Settings, ma non è presente un logger strutturato centralizzato (utilizzati `print()` sparsi in `main.py`). [CONFIRMED: `app/core/config.py#L25`, `app/main.py#L17,L20`]
- **Auditing**: Tracciato parzialmente solo per i batch di importazione tramite la tabella `import_batches`. [CONFIRMED: `app/models/models.py#L200-L218`]
