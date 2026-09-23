# DEPENDENCIES — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Analisi statica delle dipendenze dichiarate nel progetto (Senza aggiornamenti o modifiche eseguite).

---

## 1. Elenco Dipendenze e Versioni Dichiarate

Dipendenze estratte dal file `requirements.txt`:

```text
# Core Framework
fastapi==0.104.1
uvicorn==0.24.0
pydantic==1.10.13

# Database & ORM
sqlalchemy==2.0.30
alembic==1.13.1

# Data Processing & Import
openpyxl==3.1.5
python-magic==0.4.27

# HTTP Clients
httpx==0.27.0
requests==2.32.3

# Scheduling
apscheduler==3.10.4

# Templating & Frontend
jinja2==3.1.4

# Utilities & Config
python-dotenv==1.0.1
python-multipart==0.0.9
python-dateutil==2.9.0.post0
tqdm==4.66.4
rich==13.7.1

# Security / Crypto
passlib[bcrypt]==1.7.4
python-jose[cryptography]==3.3.0

# Testing & QA
pytest==8.2.2
pytest-asyncio==0.23.3
pytest-cov==5.0.0

# Static Analysis
mypy==1.11.1
types-requests==2.31.0.0
```

---

## 2. Valutazione e Criticità sulle Dipendenze

### 2.1 Pydantic v1 vs v2
- **Stato**: `pydantic==1.10.13` (Pydantic v1). [CONFIRMED: `requirements.txt#L4`]
- **Criticità**: FastAPI 0.104+ supporta nativamente Pydantic v2. L'uso della versione 1.10 limita le prestazioni e costringe a sintassi legacy (`orm_mode = True` in `app/schemas/schemas.py`). [CONFIRMED: `app/schemas/schemas.py#L79`]

### 2.2 Dipendenze Inattive / Ridondanti
- **`passlib` & `python-jose`**: Incluse in `requirements.txt#L32-L33`, ma nessuna funzionalità di hashing password o generazione JWT è attualmente importata o impiegata nel codice applicativo. [CONFIRMED]
- **`apscheduler`**: Inclusa in `requirements.txt#L19`, ma nessun job background o scheduler è configurato o avviato. [CONFIRMED]
- **`httpx` & `requests`**: Presenti contemporaneamente (`httpx==0.27.0`, `requests==2.32.3`). Si raccomanda di uniformare il client HTTP su `httpx`. [CONFIRMED: `requirements.txt#L15-L16`]

### 2.3 Licenze e Compliance
- Tutte le dipendenze principali utilizzano licenze open-source permissive (MIT, BSD, Apache 2.0). Nessuna libreria con licenza copyleft forte (es. GPL/AGPL) è stata riscontrata nelle dipendenze di primo livello. [CONFIRMED]

---

## 3. Ambiente di Esecuzione Runtime

- **Ambiente Container**: Docker base image `python:3.12-slim` con pacchetti Debian `gcc`, `libpq-dev`, `curl`. [CONFIRMED: `Dockerfile#L1,L6-L9`]
- **Ambiente Locale**: Cartella `.venv` presente nella root del progetto (Python 3.11 / 3.14). [CONFIRMED: `app/__pycache__/main.cpython-311.pyc`]
