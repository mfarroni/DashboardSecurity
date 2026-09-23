# SECURITY ARCHITECTURE — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Ruolo**: Security Architect / DevSecOps Engineer  
**Branch Git**: `architecture/initial-design`

---

## 1. Architettura di Sicurezza e Controlli Target

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           SECURITY CONTROLS LAYER                           │
 │                                                                             │
 │  ┌───────────────────────────────────────────────────────────────────────┐  │
 │  │ 1. AUTHENTICATION & AUTHORIZATION (RBAC)                              │  │
 │  │    • User Authentication via Passlib (Bcrypt) + JWT Token / Session    │  │
 │  │    • Roles: Admin, Security Analyst, Read-Only Operator              │  │
 │  └───────────────────────────────────┬───────────────────────────────────┘  │
 │                                      │                                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────┐  │
 │  │ 2. INPUT VALIDATION & FILE UPLOAD GUARDS                              │  │
 │  │    • Pydantic v2 Strict Types & Pattern Matchers                       │  │
 │  │    • Max Upload Size Limits (e.g. 50MB per file)                       │  │
 │  │    • Streaming File Parsing (chunked reading)                         │  │
 │  └───────────────────────────────────┬───────────────────────────────────┘  │
 │                                      │                                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────┐  │
 │  │ 3. NETWORK & BROWSER SECURITY HARDEING                                │  │
 │  │    • CORS restricted to explicit trusted origins (NO wildcard *)       │  │
 │  │    • Anti-CSRF Token Validation on POST/PUT/PATCH/DELETE              │  │
 │  │    • Security Headers: CSP, X-Frame-Options, HSTS, X-Content-Type      │  │
 │  │    • Rate Limiting Middleware (slowapi / redis rate limiter)           │  │
 │  └───────────────────────────────────┬───────────────────────────────────┘  │
 │                                      │                                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────┐  │
 │  │ 4. SECRETS & AUDIT LOGGING                                            │  │
 │  │    • Mandatory environment secrets (No fallback "dev-secret")         │  │
 │  │    • Audit Logging for all write/delete actions in `import_batches`   │  │
 │  └───────────────────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Modello di Autenticazione e Ruoli (RBAC)

### 2.1 Ruoli Applicativi
- **`ADMIN`**: Gestione completa asset, perimetro, cancellazione log, configurazioni utente, esecuzione sync NVD e gestione utenti.
- **`ANALYST`**: Lettura asset, gestione stato triage vulnerabilità (`nuova`, `in_valutazione`, `mitigata`, `accettata`), aggiunta note, importzione manuale log e feed.
- **`READ_ONLY`**: Consultazione dashboard, visualizzazione asset, CVE, feed e syslog senza permessi di modifica o cancellazione.

### 2.2 Gestione Token e Password
- Hashing password tramite `passlib[bcrypt]` (già presente nelle dipendenze). [CONFIRMED: `requirements.txt#L32`]
- Generazione e verifica JWT via `python-jose` con chiave `SECRET_KEY` obbligatoria da ambiente. [CONFIRMED: `requirements.txt#L33`]

---

## 3. Politica di Gestione dei Segreti (Secrets Policy)

- **Zero Hardcoded Fallbacks**: Rimozione del valore predefinito insicuro `dev-secret-change-in-production` in `app/core/config.py`. Se `SECRET_KEY` non è presente all'avvio, l'applicazione deve arrestarsi sollevando un errore di configurazione.
- **NVD API Key**: Inviata in sicurezza tramite l'header HTTP `apiKey` nelle chiamate REST uscenti verso NVD.

---

## 4. Hardening di Rete, Browser e Middleware

### 4.1 Configurazione CORS
- Sostituzione di `allow_origins=["*"]` con una lista esplicita caricata da variabile d'ambiente (`ALLOWED_ORIGINS`).

### 4.2 Middleware Rate Limiting
- Introduzione di limite di frequenza sulle chiamate API (es. 100 req/min per utente) per proteggere da attacchi di forza bruta e Denial of Service applicativo.

### 4.3 Limite Dimensionale File Upload
- Implementazione di un middleware di verifica della dimensione massima del payload HTTP (`Content-Length` max 50MB) prima della lettura in memoria.


## 5. RBAC permission matrix (Architecture Gate 2.1)

| Capability | ADMIN | ANALYST | READ_ONLY |
|---|---:|---:|---:|
| View dashboard/CVE/feed/syslog/assets | ✓ | ✓ | ✓ |
| Create/update assets | ✓ | ✓ | - |
| Delete assets | ✓ | - | - |
| Import assets/feed/CTI/syslog | ✓ | ✓ | - |
| Run NVD/Feed sync manually | ✓ | - | - |
| Change vulnerability triage/status/notes | ✓ | ✓ | - |
| Correlate/enrich data | ✓ | ✓ | - |
| Create/modify detection rules | ✓ | ✓* | - |
| Acknowledge/assign/close alerts | ✓ | ✓ | - |
| Create/manage investigations | ✓ | ✓ | - |
| Delete/clear syslog | ✓ | - | - |
| Manage users/roles/permissions | ✓ | - | - |
| Manage application/system settings | ✓ | - | - |
| View audit logs | ✓ | ✓ | - |
| Export reports/data | ✓ | ✓ | ✓** |

* Analyst rule changes require a separate review/audit policy before enabling in production. ** Read-only export is limited to data already visible to the role.

### 5.1 Browser authentication model

The Jinja2 + HTMX browser uses server-managed authenticated sessions. The session identifier is stored only in a Secure, HttpOnly, SameSite=Lax (or stricter where compatible) cookie with bounded lifetime and explicit logout invalidation. No access token is stored in localStorage/sessionStorage. State-changing requests require a CSRF token validated server-side.

JWT is not selected as the browser storage mechanism. If future machine-to-machine APIs require JWT, that is a separate documented trust boundary and must not weaken browser session controls.

### 5.2 API authorization contract

Every protected endpoint must authenticate first and authorize the required permission second. Role checks must map to named permissions rather than scattered role-string comparisons. Unauthorized requests return 401; authenticated users lacking permission receive 403. Authentication failures and security-sensitive authorization events are auditable without logging credentials or tokens.

## 6. Upload security contract

The 50 MB value is the default maximum file size, not the complete control. Implementation must enforce: maximum HTTP request size; maximum individual multipart file size; streaming/chunked reads; parser-specific limits and bounded record counts; allowlisted content types/extensions per importer plus content validation; rejection before expensive parsing when limits are exceeded; controlled temporary storage with cleanup; no execution of uploaded content; rate limiting on import endpoints; audit record for accepted/rejected imports.

Content-Length is an early rejection optimization only and cannot be the sole protection because clients can omit or falsify it and chunked requests may not provide it.

## 7. Pydantic strategy

The current dependency is Pydantic v1.10.x. The architecture documentation must not require v2 syntax before the dependency migration. Decision: implement immediate security/bug fixes using the current Pydantic v1 contract; then perform Pydantic v2 as a separate controlled refactor with compatibility tests. Pydantic v2 is therefore not a prerequisite for the first implementation gate.
