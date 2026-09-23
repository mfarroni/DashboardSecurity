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
