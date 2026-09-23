# SECURITY BASELINE — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Analisi statica della sicurezza (SAST) in sola lettura (Nessun exploit o modifica eseguita).

---

## 1. Matrice Riconoscimento Vulnerabilità e Rischi

| Categoria | Presenza / Rischio | Classificazione | Evidenza nel Codice / Configurazione |
|---|---|---|---|
| **Hardcoded Secrets** | **Basso / Presente Fallback** | [CONFIRMED] | `app/core/config.py#L26`: `secret_key: str = Field(default="dev-secret-change-in-production")`. |
| **Authentication Bypass** | **CRITICO / Totale Assenza** | [CONFIRMED] | Assenza completa di middleware/endpoint di login. Tutti gli endpoint API e UI sono aperti publicamente. |
| **Authorization Bypass (IDOR/BOLA)** | **ALTO / Assenza RBAC** | [CONFIRMED] | Qualsiasi client può invocare `DELETE /api/assets/{id}`, `DELETE /api/syslog/clear`, `PATCH /api/cve/asset-vuln/{av_id}` senza restrizioni. |
| **CORS Wildcard** | **MEDIO / Misconfig** | [CONFIRMED] | `app/main.py#L31-L37`: `CORSMiddleware` configurato con `allow_origins=["*"]` e `allow_credentials=True`. |
| **SQL Injection** | **BASSO / Protetto da ORM** | [CONFIRMED] | Query costruite tramite SQLAlchemy ORM con parametri gestiti in sicurezza. Nessuna concatenazione SQL grezza individuata. |
| **Cross-Site Scripting (XSS)** | **BASSO / Protetto da Jinja2** | [CONFIRMED] | Auto-escaping attivo per default nei template Jinja2. Nessun uso di filtro `| safe` riscontrato sui dati inseriti dagli utenti. |
| **CSRF (Cross-Site Request Forgery)** | **ALTO / Mancanza Token** | [CONFIRMED] | Assenza di middleware o token CSRF sulle rotte HTTP POST/PUT/PATCH/DELETE nei form e nelle chiamate HTMX. |
| **Server-Side Request Forgery (SSRF)** | **BASSO / Endpoint Fissi** | [CONFIRMED] | Le chiamate HTTP uscenti (`NVDClient`) utilizzano URL base fisso `https://services.nvd.nist.gov/rest/json/cves/2.0`. |
| **Insecure File Upload / DoS** | **MEDIO-ALTO / Unbounded Read** | [CONFIRMED] | `app/api/assets.py#L149`, `app/api/syslog.py#L283`: `content = await file.read()` senza limite di dimensione massima del payload. |
| **Path Traversal** | **BASSO / Protetto da Pathlib** | [CONFIRMED] | I percorsi di directory sono gestiti tramite `pathlib.Path` in `config.py`. Gli upload elaborano i file in memoria senza salvare percorsi arbitrari su disco. |
| **Command Injection** | **ASSENTE** | [CONFIRMED] | Nessun utilizzo di `os.system`, `subprocess`, `eval` o `exec` nel codice applicativo `app/`. |
| **Security Headers** | **MANCANTI** | [CONFIRMED] | Assenza di header di sicurezza standard (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`). |
| **Rate Limiting Applicativo** | **PARZIALE / Solo NVD Client** | [CONFIRMED] | Rate limit presente solo verso NVD API uscente (`nvd_rate_limit_per_30s`), del tutto assente sugli endpoint FastAPI esposti agli utenti. |
| **Dipendenze Vulnerabili** | **DA VERIFICARE** | [POSSIBLE] | Utilizzo di `pydantic==1.10.13`, `jinja2==3.1.4`, `sqlalchemy==2.0.30`. È raccomandato un audit tramite `safety` o `pip-audit`. |

---

## 2. Analisi Dettagliata dei Principali Vulnerabilità

### 2.1 Assenza Totale di Autenticazione e Autorizzazione
- **Severità**: **CRITICA**
- **Descrizione**: L'applicazione non richiede alcuna forma di credenziale o token per accedere alle funzionalità o modificare lo stato del database.
- **Riferimento Codice**: `app/main.py#L48-L54` (I router sono inclusi direttamente senza dipendenze di sicurezza come `Depends(get_current_user)`).

### 2.2 Configurazioni CORS Permessive
- **Severità**: **MEDIA**
- **Descrizione**: Il middleware CORS consente richieste da qualsiasi origine con credenziali abilitate (`allow_origins=["*"]`, `allow_credentials=True`).
- **Riferimento Codice**: `app/main.py#L31-L37`.
- **Rischio**: Esposizione di dati sensibili a script di terze parti eseguiti nel browser di un utente.

### 2.3 Rischio Denial of Service su Upload File (Memory Exhaustion)
- **Severità**: **ALTA**
- **Descrizione**: La lettura del contenuto dei file inviati tramite i form avviene interamente in memoria tramite `await file.read()`.
- **Riferimento Codice**:
  - `app/api/assets.py#L149`
  - `app/api/feed.py#L110`
  - `app/api/syslog.py#L283`
- **Rischio**: L'invio ripetuto o simultaneo di file di dimensioni elevate può saturare la RAM dell'istanza backend causando l'interruzione del servizio.

### 2.4 Mancanza di Protezione Anti-CSRF
- **Severità**: **ALTA**
- **Descrizione**: Non vi è alcun meccanismo di validazione di token anti-CSRF nelle richieste di modifica stato (POST/PATCH/DELETE).
- **Riferimento Codice**: Rotte form in `app/api/assets.py`, `app/api/cve.py`, `app/api/syslog.py`.
