# Security Dashboard — FeedHub + Perimetro CVE

Dashboard di sicurezza locale per vulnerability management: aggrega feed da FeedHub, gestisce perimetro asset (hardware/software) e correla automaticamente con CVE da NVD + feed CTI.

## 🎯 Obiettivi

1. **FeedHub ingestion** — Import manuale JSON/CSV da esportazione estensione Chrome
2. **Perimetro sicurezza** — Asset inventory importabile CSV/Excel/JSON con mapping colonne
3. **Correlazione CVE** — Match CPE esatto/parziale + fallback testuale (vendor/prodotto/versione)
4. **Dashboard** — Overview, Perimetro, Vulnerabilità, Feed, Syslog
5. **Scheda CVE compatta** — ID, descrizione rischio, link vendor advisory, badge severità CVSS
6. **Analisi syslog** — Parse RFC 3164/5424, correlazione asset, evidenziazione CVE

## 🏗️ Architettura

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Dashboard                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────────────┐  │
│  │ FeedHub │  │ Perimetro│  │   NVD   │  │    CTI Feed    │  │
│  │  Import │  │ (Assets) │  │  API 2.0│  │  (MISP, etc.)  │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └───────┬────────┘  │
│       │            │            │                │            │
│       └────────────┼────────────┼────────────────┘            │
│                    ▼                                         │
│         ┌─────────────────────┐                              │
│         │  Correlation Engine  │                              │
│         │  CPE Exact/Partial   │                              │
│         │  + Textual Fallback  │                              │
│         └──────────┬──────────┘                              │
│                    │                                         │
│         ┌──────────▼──────────┐                              │
│         │   SQLite / Postgres  │                              │
│         │  (SQLAlchemy ORM)    │                              │
│         └──────────┬──────────┘                              │
│                    │                                         │
│         ┌──────────▼──────────┐                              │
│         │   FastAPI + HTMX     │                              │
│         │   Jinja2 Templates   │                              │
│         └─────────────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisiti
- Docker + Docker Compose
- (Opzionale) NVD API Key da [nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

### Avvio

```bash
# 1. Clona e configura
cp .env.example .env
# Modifica .env se hai NVD_API_KEY

# 2. Setup completo (build + init DB + settings + test log)
opencode skill security-dashboard setup

# 3. Apri dashboard
# http://localhost:8000
```

### Primo utilizzo

```bash
# Importa perimetro asset (guidato)
opencode skill perimetro-import import-interactive ./assets.csv

# Sincronizza CVE recenti da NVD
opencode skill nvd-sync sync-recent 30

# Correla CVE ↔ Asset
opencode skill cve-correlation run-all

# Importa feed FeedHub
opencode skill feedhub-import import ./feedhub_export.json

# Importa syslog
opencode skill syslog-parser import ./logs/syslog.log
```

## 🛠️ Skill OpenCode Disponibili

| Skill | Descrizione |
|-------|-------------|
| `security-dashboard` | Comando unificato: setup, daily-sync, import-all, status, dev-reset |
| `docker-manage` | Build, up, down, logs, shell, backup, db-shell |
| `nvd-sync` | Sync NVD API 2.0 (recent, single CVE, rate-limit-info) |
| `cve-correlation` | Correlazione CPE exact/partial + textual, stats |
| `perimetro-import` | Preview, import CSV/Excel/JSON, export, history |
| `feedhub-import` | Import FeedHub export, list recent, unlinked CVEs |
| `syslog-parser` | Import syslog RFC 3164/5424, search, stats, CVE correlations |
| `test-runner` | Functional, security, regression tests + non-regression log |

### Esempi skill

```bash
# Stato sistema
opencode skill security-dashboard status

# Sync giornaliera (cron-friendly)
opencode skill security-dashboard daily-sync

# Import tutto guidato
opencode skill security-dashboard import-all

# Test suite completa
opencode skill test-runner regression
```

## 📁 Struttura Progetto

```
.
├── .opencode/skill/          # Skill OpenCode custom
│   ├── security-dashboard.yaml
│   ├── docker-manage.yaml
│   ├── nvd-sync.yaml
│   ├── cve-correlation.yaml
│   ├── perimetro-import.yaml
│   ├── feedhub-import.yaml
│   ├── syslog-parser.yaml
│   └── test-runner.yaml
├── app/
│   ├── api/                  # Endpoints FastAPI
│   │   ├── assets.py         # Perimetro CRUD + import
│   │   ├── cve.py            # CVE + correlazione + NVD sync
│   │   ├── dashboard.py      # Overview + partials HTMX
│   │   ├── feed.py           # FeedHub + CTI import
│   │   ├── imports.py        # Storico import batch
│   │   ├── settings.py       # User settings
│   │   └── syslog.py         # Syslog parse + import
│   ├── core/                 # Config, DB
│   ├── models/               # SQLAlchemy models
│   ├── schemas/              # Pydantic schemas
│   ├── services/             # Business logic (correlation)
│   ├── templates/            # Jinja2 + partials HTMX
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   └── partials/
│   └── main.py
├── tests/
│   ├── test_api.py
│   └── results/test-log.md   # Registro non-regressione
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

## 🔄 Workflow Cicli (come da specifica)

Il progetto segue **3 cicli** di sviluppo con team specializzati:

| Ciclo | Focus | Output |
|-------|-------|--------|
| 1 | Setup, modelli, API base, template | Fondazione funzionante |
| 2 | Correlazione engine, NVD sync, FeedHub/CTI import, Syslog | Core funzionale |
| 3 | Dashboard completa, triage UI, hardening, test non-regressione | Produzione-ready |

Ogni ciclo: **Analista → Sviluppo → Grafica UI/UX → Testing → Sicurezza → Esperto Cybersicurezza → Analista**

### Registro Test Non-Regressione
- File: `tests/results/test-log.md`
- Ciclo corrente: `.opencode/test-cycle.txt`
- Comandi: `test-runner init-log`, `test-runner regression`, `test-runner next-cycle`

## 🐳 Deployment Proxmox (Fase 2)

Il `docker-compose.yml` è già pronto per Proxmox:

```yaml
# Su server Proxmox (VM/container)
# 1. Copia progetto
# 2. Configura .env con NVD_API_KEY e SECRET_KEY forte
# 3. (Opzionale) Decommenta nginx + certificati TLS
# 4. docker compose up -d
```

Migrazione SQLite → PostgreSQL: cambia solo `DATABASE_URL` in `.env`.

## 📋 API Endpoints Principali

| Area | Endpoints |
|------|-----------|
| **Assets** | `GET/POST /api/assets`, `PATCH/DELETE /api/assets/{id}`, `POST /api/assets/import/*` |
| **CVE** | `GET /api/cve`, `GET /api/cve/{id}`, `POST /api/cve/sync/nvd`, `POST /api/cve/correlate` |
| **Feed** | `GET /api/feed`, `POST /api/feed/import/feedhub`, `POST /api/feed/import/cti` |
| **Dashboard** | `GET /api/dashboard/api/overview`, `GET /api/dashboard/api/perimetro`, `GET /api/dashboard/api/vulnerabilita` |
| **Syslog** | `GET /api/syslog`, `GET /api/syslog/stats`, `POST /api/syslog/import` |
| **Settings** | `GET/PUT /api/settings/{key}`, `POST /api/settings/init-defaults` |

## 🎨 UI/UX - Scheda CVE (Spec 3.5)

La scheda dettaglio CVE è un **componente riutilizzabile** (modale compatta):
- **ID CVE** + badge severità CVSS (Critica/Alta/Media/Bassa + score)
- **Descrizione rischio** — sintesi 2-3 righe, linguaggio semplice (RCE, PrivEsc, DoS...)
- **Link Advisory Vendor** — se disponibile, altrimenti nascosto
- **Estensibile** — asset coinvolti, stato triage, riferimenti feed (già implementati)

## 🔐 Sicurezza

- **NVD API Key** gestita via env var (mai in codice)
- **Input validation** Pydantic su tutti gli import
- **SQL Injection** prevenuto da SQLAlchemy ORM
- **XSS** auto-escape Jinja2 + CSP headers
- **Secrets scanning** con TruffleHog (skill `test-runner security secrets`)
- **Dependency audit** con Safety + Bandit

## 📝 Licenza

Progetto interno — Cybersecurity Vulnerability Management

---

**Prossimi step Ciclo 1:**
- [ ] Completare template: perimetro.html, vulnerabilita.html, feed.html, syslog.html
- [ ] Test API endpoints con `test-runner functional`
- [ ] Prima sync NVD reale con API key