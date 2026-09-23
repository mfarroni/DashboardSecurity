# Registro Test Non-Regressione - Security Dashboard

Formato: Cosa testato | Esito | Ciclo | Note

---

## Ciclo 1 - Setup Progetto (2026-09-22)

### Setup Infrastructure
- Docker Compose build | ✅ PASS | 1 | Container app + volumi
- Database SQLite init | ✅ PASS | 1 | Tabelle create via SQLAlchemy
- Health endpoint | ✅ PASS | 1 | GET /health returns 200
- Settings default init | ✅ PASS | 1 | POST /api/settings/init-defaults

### API Assets (Perimetro)
- GET /api/assets (list) | ⏳ PENDING | 1 | Paginazione, filtri
- POST /api/assets (create) | ⏳ PENDING | 1 | Validazione CPE unique
- PATCH /api/assets/{id} | ⏳ PENDING | 1 | Update campi
- DELETE /api/assets/{id} | ⏳ PENDING | 1 | Cascade delete vulns
- POST /api/assets/import/preview | ⏳ PENDING | 1 | CSV/Excel/JSON preview
- POST /api/assets/import/execute | ⏳ PENDING | 1 | Import con mapping
- GET /api/assets/export/current | ⏳ PENDING | 1 | Export CSV
- GET /api/assets/import/history | ⏳ PENDING | 1 | Storico batch

### API Feed (FeedHub + CTI)
- GET /api/feed (list) | ⏳ PENDING | 1 | Filtri source, search, CVE
- POST /api/feed/import/feedhub | ⏳ PENDING | 1 | Import JSON/CSV
- POST /api/feed/import/cti | ⏳ PENDING | 1 | Import MISP/PatchTuesday
- GET /api/feed/import/history | ⏳ PENDING | 1 | Storico batch

### API CVE
- GET /api/cve (list) | ⏳ PENDING | 1 | Filtri severity, search, assets
- GET /api/cve/{id} (detail) | ⏳ PENDING | 1 | Scheda compatta 3.5
- GET /api/cve/by-id/{cve_id} | ⏳ PENDING | 1 | Lookup per stringa
- POST /api/cve/sync/nvd | ⏳ PENDING | 1 | Sync NVD API 2.0
- POST /api/cve/correlate | ⏳ PENDING | 1 | Correlazione full
- POST /api/cve/correlate-asset/{id} | ⏳ PENDING | 1 | Correlazione singolo asset
- GET /api/cve/asset-vuln-stats | ⏳ PENDING | 1 | Stats correlazione
- PATCH /api/cve/asset-vuln/{id} | ⏳ PENDING | 1 | Update triage status
- GET /api/cve/asset/{id}/vulnerabilities | ⏳ PENDING | 1 | Vuln per asset

### API Dashboard
- GET /api/dashboard/api/overview | ⏳ PENDING | 1 | Statistiche overview
- GET /api/dashboard/api/perimetro | ⏳ PENDING | 1 | Asset con vuln counts
- GET /api/dashboard/api/vulnerabilita | ⏳ PENDING | 1 | Lista vuln paginata
- GET /api/dashboard/critical-vulns (HTML) | ⏳ PENDING | 1 | Partial HTMX
- GET /api/dashboard/recent-feed (HTML) | ⏳ PENDING | 1 | Partial HTMX
- GET /api/dashboard/assets-by-type (HTML) | ⏳ PENDING | 1 | Partial HTMX
- GET /api/dashboard/syslog-stats (HTML) | ⏳ PENDING | 1 | Partial HTMX

### API Syslog
- GET /api/syslog (list) | ⏳ PENDING | 1 | Filtri hostname, severity, search
- GET /api/syslog/stats | ⏳ PENDING | 1 | Stats per severità/facility/host
- POST /api/syslog/import | ⏳ PENDING | 1 | Import file syslog
- GET /api/syslog/import/history | ⏳ PENDING | 1 | Storico batch
- DELETE /api/syslog/clear | ⏳ PENDING | 1 | Clear con conferma

### API Settings
- GET /api/settings | ⏳ PENDING | 1 | Tutte le impostazioni
- GET /api/settings/{key} | ⏳ PENDING | 1 | Singola impostazione
- PUT /api/settings/{key} | ⏳ PENDING | 1 | Update impostazione
- POST /api/settings/init-defaults | ⏳ PENDING | 1 | Inizializza default

### Frontend (HTMX + Jinja2)
- Dashboard page | ⏳ PENDING | 1 | Overview cards + partials
- Perimetro page | ⏳ PENDING | 1 | Tabella asset + import
- Vulnerabilità page | ⏳ PENDING | 1 | Tabella vuln + filtri
- Feed page | ⏳ PENDING | 1 | Stream feed + CVE highlight
- Syslog page | ⏳ PENDING | 1 | Log viewer + search
- CVE Detail Modal | ⏳ PENDING | 1 | Scheda compatta 3.5

### Correlazione Engine
- CPE Exact Match | ⏳ PENDING | 1 | Match esatto CPE 2.3
- CPE Partial Match | ⏳ PENDING | 1 | Wildcard version/product
- Textual Fallback | ⏳ PENDING | 1 | Similarità vendor/prodotto/versione
- Confidence scoring | ⏳ PENDING | 1 | 0.0-1.0 per match testuali

### Sicurezza
- NVD API Key handling | ⏳ PENDING | 1 | Header apiKey, rate limit
- Input validation import | ⏳ PENDING | 1 | Sanitizzazione file upload
- SQL injection prevention | ⏳ PENDING | 1 | ORM parameterized queries
- XSS prevention templates | ⏳ PENDING | 1 | Auto-escape Jinja2