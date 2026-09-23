# PROJECT DISCOVERY — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Modalità**: Analisi statica e ispezione completa in sola lettura (Nessuna modifica al codice eseguita).

---

## 1. Struttura Directory e Organizzazione Repository

- **Struttura Directory principali**:
  - `app/`: Codice applicativo backend FastAPI, router API, modelli SQLAlchemy, schemi Pydantic, servizi e template Jinja2. [CONFIRMED: path `app/`]
  - `app/api/`: Endpoint REST e partials HTMX suddivisi in 7 moduli (`assets.py`, `cve.py`, `dashboard.py`, `feed.py`, `imports.py`, `settings.py`, `syslog.py`). [CONFIRMED: path `app/api/`]
  - `app/core/`: Configurazione centralizzata Pydantic (`config.py`) e inizializzazione ORM/Database (`database.py`). [CONFIRMED: path `app/core/`]
  - `app/models/`: Definizioni tabelle ed enum SQLAlchemy (`models.py`). [CONFIRMED: path `app/models/models.py`]
  - `app/schemas/`: Schemi di validazione/serializzazione Pydantic v1 (`schemas.py`). [CONFIRMED: path `app/schemas/schemas.py`]
  - `app/services/`: Logica di business per il motore di correlazione CVE ↔ Asset (`correlation.py`). [CONFIRMED: path `app/services/correlation.py`]
  - `app/templates/`: Template HTML Jinja2 (`base.html`, `dashboard.html`, `perimetro.html`, ecc.) e componenti parziali HTMX (`app/templates/partials/`). [CONFIRMED: path `app/templates/`]
  - `app/static/`: Risorse statiche (CSS/JS) per il frontend. [CONFIRMED: path `app/static/`]
  - `tests/`: Suite di test automatizzati `pytest` (`test_api.py`) e registro di non-regressione (`tests/results/test-log.md`). [CONFIRMED: path `tests/`]
  - `.opencode/`: Definizione di skill YAML e prompt per orchestratore OpenCode. [CONFIRMED: path `.opencode/`]
  - `data/`: Directory locale destinata al database SQLite (`security.db`) e sottocartelle di import (`feedhub_imports`, `perimetro_imports`, `syslog_imports`). [CONFIRMED: path `data/`]
  - `logs/`: Directory destinata ai log applicativi. [CONFIRMED: path `logs/`]

---

## 2. Linguaggi, Framework e Package Manager

- **Linguaggio Backend**: Python 3.12 (specificato nel Dockerfile `FROM python:3.12-slim`), con compatibilità 3.11/3.14 rilevata da file `.pyc`. [CONFIRMED: Dockerfile#L1, path `app/__pycache__/`]
- **Framework Web Backend**: FastAPI v0.104.1 servito da Uvicorn v0.24.0. [CONFIRMED: requirements.txt#L2-L3, app/main.py#L2,L6]
- **ORM / Database Access**: SQLAlchemy v2.0.30 con driver SQLite di default (`sqlite:///data/security.db`). [CONFIRMED: requirements.txt#L7, app/core/database.py#L7-L13]
- **Validazione Dati**: Pydantic v1.10.13. [CONFIRMED: requirements.txt#L4, app/schemas/schemas.py#L1]
- **Frontend / Templating**: Server-Side Rendering tramite Jinja2 v3.1.4 e integrazione HTMX via partial HTML. [CONFIRMED: requirements.txt#L22, app/main.py#L4,L41, app/templates/`]
- **Elaborazione Dati / Parser**: pandas v2.x (via openpyxl v3.1.5 per Excel), `httpx` v0.27.0, `requests` v2.32.3. [CONFIRMED: requirements.txt#L11,L15-L16, app/api/assets.py#L5]
- **Scheduler**: APScheduler v3.10.4 presente nelle dipendenze (non ancora collegato al ciclo di vita di FastAPI). [CONFIRMED: requirements.txt#L19, app/main.py]
- **Package Manager**: Python `pip` con specifiche in `requirements.txt`. [CONFIRMED: requirements.txt]

---

## 3. Componenti di Sistema e Architettura

- **Entry Point Applicativo**: `app/main.py` gestisce l'inizializzazione del database `init_db()`, il ciclo di vita `lifespan`, il montaggio dei file statici `/static`, l'inclusione dei 7 router API e l'endpoint di health check `/health`. [CONFIRMED: file `app/main.py`]
- **Frontend**: Architettura monolitica Server-Side Rendered basata su FastAPI + Jinja2 Templates + HTMX. [CONFIRMED: `app/templates/base.html`, `app/api/dashboard.py`]
- **Backend API**: 32 endpoint HTTP suddivisi in:
  - Dashboard & Web UI Pages (`/`, `/perimetro`, `/vulnerabilita`, `/feed`, `/syslog`)
  - Assets API (`/api/assets/*`)
  - CVE & Correlation API (`/api/cve/*`)
  - Feed API (`/api/feed/*`)
  - Syslog API (`/api/syslog/*`)
  - Imports History API (`/api/import/*`)
  - Settings API (`/api/settings/*`) [CONFIRMED: file `app/main.py#L48-L54`]
- **Database**: SQLite predefinito memorizzato in file locale `data/security.db`. Supporto dichiarato per PostgreSQL in produzione/Proxmox tramite override `DATABASE_URL`. [CONFIRMED: file `app/core/config.py#L14-L17`, `.env.example#L9`]
- **Servizi Integrati**:
  - `NVDClient`: Client HTTP asincrono per NVD REST API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`). [CONFIRMED: file `app/api/cve.py#L24-L68`]
  - `Correlation Engine`: Motore di correlazione CVE ↔ Asset basato su CPE Exact Match, CPE Partial Match e Textual Similarity. [CONFIRMED: file `app/services/correlation.py`]
  - `Syslog Parser`: Parser log per formati RFC 3164 e RFC 5424. [CONFIRMED: file `app/api/syslog.py#L19-L118`]
- **Job / Scheduler**: Configurazione presunta in `Settings` (`nvd_sync_interval_hours = 6`, `feed_sync_interval_hours = 1`), ma nessun thread o task background schedulato in automatico all'avvio in `main.py`. [CONFIRMED: file `app/core/config.py#L44-L45`, `app/main.py#L13-L21`]

---

## 4. Containerizzazione e Deployment

- **Container Docker**: `Dockerfile` basato su `python:3.12-slim`, installazione pacchetti di sistema (`gcc`, `libpq-dev`, `curl`), creazione utente non-root `appuser` (UID 1000) e comando d'avvio `uvicorn app.main:app --host 0.0.0.0 --port 8000`. [CONFIRMED: file `Dockerfile`]
- **Docker Compose**: `docker-compose.yml` definisce il servizio `security-dashboard`, binding porta 8000:8000, volumi persistenti per `./data`, `./logs`, `./config`, ed healthcheck automatizzato su `/health`. [CONFIRMED: file `docker-compose.yml`]
- **CI/CD**: Nessuna pipeline GitHub Actions o GitLab CI configurata nel repository (`.github/workflows` assente). Presenza di skill OpenCode (`.opencode/skill/`) per l'automazione dei comandi locali. [CONFIRMED: assenza di directory `.github`]
- **Configurazione Ambiente**: File `.env.example` con variabili `DATABASE_URL`, `NVD_API_KEY`, `NVD_RATE_LIMIT`, `LOG_LEVEL`, `SECRET_KEY`, `TZ`. [CONFIRMED: file `.env.example`]

---

## 5. Documentazione e Test Esistenti

- **Documentazione**: `README.md` dettagliato con descrizione architetturale, prerequisiti, quick start, comandi skill OpenCode e ciclo di vita a 3 cicli. [CONFIRMED: file `README.md`]
- **Test**: File `tests/test_api.py` contenente 4 test attivi (`test_health_check`, `test_dashboard_page`, `test_api_docs`, `test_settings_init`) e 2 test marcati `@pytest.mark.skip` (`test_asset_crud`, `test_cve_sync_nvd`). [CONFIRMED: file `tests/test_api.py`]
- **Registro Test**: File `tests/results/test-log.md` contenente il tracciamento dei test per Ciclo 1. [CONFIRMED: file `tests/results/test-log.md`]
