# API INVENTORY — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Catalogazione esaustiva delle rotte e degli endpoint dichiarati nel backend FastAPI.

---

## 1. Mappa Sintetica degli Endpoints per Modulo

| Modulo | N. Endpoints | Descrizione Breve |
|---|---|---|
| **System / Main** | 1 | Health check dell'applicazione |
| **Dashboard & UI** | 10 | Rotte HTML server-rendered e componenti parziali HTMX |
| **Assets (Perimetro)** | 9 | CRUD Asset, anteprima/esecuzione import ed export CSV |
| **CVE & Correlation** | 9 | Consultazione CVE, sync NVD, motore correlazione e triage |
| **Feed (FeedHub/CTI)** | 5 | Consultazione feed e import da FeedHub e MISP/CTI |
| **Syslog** | 5 | Consultazione log, statistiche, import e pulizia log |
| **Imports History** | 3 | Tracciamento e gestione batch di importazione |
| **Settings** | 5 | Gestione impostazioni utente e inizializzazione default |
| **TOTALE** | **47 rotte / endpoint** | |

---

## 2. Inventario Dettagliato di Tutti gli Endpoint

### 2.1 System & Main Routes (`app/main.py`)
1. `GET /health` -> JSON `{"status": "healthy", "service": "security-dashboard"}`. [CONFIRMED: `app/main.py#L57-L59`]

### 2.2 Dashboard Web & Partial Routes (`app/api/dashboard.py`)
2. `GET /` -> HTML Page `dashboard.html`. [CONFIRMED: `app/api/dashboard.py#L22-L24`]
3. `GET /perimetro` -> HTML Page `perimetro.html`. [CONFIRMED: `app/api/dashboard.py#L27-L29`]
4. `GET /vulnerabilita` -> HTML Page `vulnerabilita.html`. [CONFIRMED: `app/api/dashboard.py#L32-L34`]
5. `GET /feed` -> HTML Page `feed.html`. [CONFIRMED: `app/api/dashboard.py#L37-L39`]
6. `GET /syslog` -> HTML Page `syslog.html`. [CONFIRMED: `app/api/dashboard.py#L42-L44`]
7. `GET /cve/{cve_id}` -> HTML Page `cve_detail.html` (*Errore: template mancante*). [CONFIRMED: `app/api/dashboard.py#L47-L49`]
8. `GET /api/overview` -> JSON `DashboardOverview` (Statistiche generali). [CONFIRMED: `app/api/dashboard.py#L52-L116`]
9. `GET /api/perimetro` -> JSON `List[AssetWithVulnsResponse]`. [CONFIRMED: `app/api/dashboard.py#L119-L158`]
10. `GET /api/vulnerabilita` -> JSON `PaginatedResponse` (Lista vulnerabilità perimetro). [CONFIRMED: `app/api/dashboard.py#L161-L197`]
11. `GET /api/dashboard/critical-vulns` -> HTML Partial `partials/critical_vulns.html`. [CONFIRMED: `app/api/dashboard.py#L200-L209`]
12. `GET /api/dashboard/recent-feed` -> HTML Partial `partials/recent_feed.html`. [CONFIRMED: `app/api/dashboard.py#L212-L222`]
13. `GET /api/dashboard/assets-by-type` -> HTML Partial `partials/assets_by_type.html`. [CONFIRMED: `app/api/dashboard.py#L225-L238`]
14. `GET /api/dashboard/syslog-stats` -> HTML Partial `partials/syslog_stats.html`. [CONFIRMED: `app/api/dashboard.py#L241-L249`]

### 2.3 Assets / Perimetro API (`app/api/assets.py`)
15. `GET /api/assets` -> JSON `PaginatedResponse` (Lista asset filtrata). [CONFIRMED: `app/api/assets.py#L20-L72`]
16. `GET /api/assets/{asset_id}` -> JSON `AssetResponse`. [CONFIRMED: `app/api/assets.py#L75-L89`]
17. `POST /api/assets` -> JSON `AssetResponse` (Creazione nuovo asset). [CONFIRMED: `app/api/assets.py#L92-L104`]
18. `PATCH /api/assets/{asset_id}` -> JSON `AssetResponse` (Aggiornamento parziale asset). [CONFIRMED: `app/api/assets.py#L107-L130`]
19. `DELETE /api/assets/{asset_id}` -> Status 204 No Content (Eliminazione asset). [CONFIRMED: `app/api/assets.py#L133-L140`]
20. `POST /api/assets/import/preview` -> JSON `ImportPreviewResponse` (Preview CSV/Excel/JSON). [CONFIRMED: `app/api/assets.py#L143-L217`]
21. `POST /api/assets/import/execute` -> JSON `ImportBatchResponse` (Importazione effettiva). [CONFIRMED: `app/api/assets.py#L220-L307`]
22. `GET /api/assets/import/history` -> JSON `List[ImportBatchResponse]`. [CONFIRMED: `app/api/assets.py#L310-L318`]
23. `GET /api/assets/export/current` -> Content CSV (Export perimetro in formato CSV). [CONFIRMED: `app/api/assets.py#L321-L337`]

### 2.4 CVE & Correlation API (`app/api/cve.py`)
24. `GET /api/cve` -> JSON `PaginatedResponse` (Lista CVE con filtri). [CONFIRMED: `app/api/cve.py#L145-L209`]
25. `GET /api/cve/{cve_id}` -> JSON `CVEDetailResponse` (Dettaglio CVE e asset impattati). [CONFIRMED: `app/api/cve.py#L212-L255`]
26. `GET /api/cve/by-id/{cve_id_str}` -> JSON `CVEDetailResponse` (Lookup da ID stringa es. `CVE-2024-1234`). [CONFIRMED: `app/api/cve.py#L258-L264`]
27. `POST /api/cve/sync/nvd` -> JSON (Sincronizzazione API NVD 2.0). [CONFIRMED: `app/api/cve.py#L267-L328`]
28. `POST /api/cve/correlate` -> JSON (Esecuzione correlazione completa CVE ↔ Asset). [CONFIRMED: `app/api/cve.py#L331-L335`]
29. `PATCH /api/cve/asset-vuln/{av_id}` -> JSON `AssetVulnerabilityResponse` (Aggiornamento triage). [CONFIRMED: `app/api/cve.py#L338-L361`]
30. `GET /api/cve/asset/{asset_id}/vulnerabilities` -> JSON `List[AssetVulnerabilityResponse]`. [CONFIRMED: `app/api/cve.py#L364-L379`]
31. `POST /api/cve/correlate-asset/{asset_id}` -> JSON (Correlazione per singolo asset). [CONFIRMED: `app/api/cve.py#L382-L386`]
32. `GET /api/cve/asset-vuln-stats` -> JSON (Statistiche match e triage). [CONFIRMED: `app/api/cve.py#L389-L416`]

### 2.5 Feed API (`app/api/feed.py`)
33. `GET /api/feed` -> JSON `PaginatedResponse` (Lista feed items). [CONFIRMED: `app/api/feed.py#L35-L92`]
34. `GET /api/feed/{item_id}` -> JSON `FeedItemResponse`. [CONFIRMED: `app/api/feed.py#L95-L100`]
35. `POST /api/feed/import/feedhub` -> JSON `ImportBatchResponse` (Import da FeedHub export). [CONFIRMED: `app/api/feed.py#L103-L205`]
36. `POST /api/feed/import/cti` -> JSON `ImportBatchResponse` (Import feed CTI/MISP). [CONFIRMED: `app/api/feed.py#L208-L323`]
37. `GET /api/feed/import/history` -> JSON `List[ImportBatchResponse]`. [CONFIRMED: `app/api/feed.py#L326-L334`]

### 2.6 Syslog API (`app/api/syslog.py`)
38. `GET /api/syslog` -> JSON `PaginatedResponse` (Lista log filtrabile). [CONFIRMED: `app/api/syslog.py#L187-L234`]
39. `GET /api/syslog/stats` -> JSON (Statistiche log 24h/settimana). [CONFIRMED: `app/api/syslog.py#L237-L271`]
40. `POST /api/syslog/import` -> JSON `ImportBatchResponse` (Import file log RFC 3164/5424). [CONFIRMED: `app/api/syslog.py#L274-L355`]
41. `GET /api/syslog/import/history` -> JSON `List[ImportBatchResponse]`. [CONFIRMED: `app/api/syslog.py#L358-L366`]
42. `DELETE /api/syslog/clear` -> JSON `{"deleted": count}` (Svuotamento log). [CONFIRMED: `app/api/syslog.py#L369-L381`]

### 2.7 Imports History & Settings API (`app/api/imports.py`, `app/api/settings.py`)
43. `GET /api/import` -> JSON `List[ImportBatchResponse]`. [CONFIRMED: `app/api/imports.py#L14-L29`]
44. `GET /api/import/{batch_id}` -> JSON `ImportBatchResponse`. [CONFIRMED: `app/api/imports.py#L32-L37`]
45. `DELETE /api/import/{batch_id}` -> JSON `{"message": "Batch eliminato"}`. [CONFIRMED: `app/api/imports.py#L40-L48`]
46. `GET /api/settings` -> JSON (Tutte le impostazioni). [CONFIRMED: `app/api/settings.py#L17-L20`]
47. `GET /api/settings/{key}` / `PUT /api/settings/{key}` / `DELETE /api/settings/{key}` / `POST /api/settings/init-defaults`. [CONFIRMED: `app/api/settings.py#L23-L112`]
