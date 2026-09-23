# THREAT MODEL — Security Dashboard (DashBoard eventi CVE)

**Stato Fase**: `ARCHITECTURE`  
**Ruolo**: Security Architect / Threat Intelligence Analyst  
**Metodologia**: STRIDE Threat Modeling Framework  
**Branch Git**: `architecture/initial-design`

---

## 1. Analisi delle Minacce STRIDE

| Categoria STRIDE | Minaccia Individuata | Componente Impattato | Controlli e Mitigazioni Target |
|---|---|---|---|
| **Spoofing (Identità)** | Impersonificazione di un utente o inserimento di log non autenticati | API Endpoints / Web UI | Introduzione di autenticazione obbligatoria via JWT / Session e autenticazione sorgenti syslog. |
| **Tampering (Manomissione)** | Modifica arbitraria dei dati di triage o cancellazione log | `asset_vulnerabilities`, `syslog_entries` | Autenticazione RBAC, validazione input Pydantic v2 e audit log inalterabile. |
| **Repudiation (Disconoscimento)** | Mancanza di tracciamento delle modifiche al triage o all'asset inventory | Triage Update API (`/api/cve/asset-vuln/{id}`) | Sostituzione dell'autore fisso `"user"` con l'ID reale dell'utente autenticato ed eventuale registro audit. |
| **Information Disclosure** | Esposizione pubblica della topologia dell'infrastruttura, CVE ed asset | Dashboard Overview, `/api/perimetro` | Autenticazione obbligatoria, restrizione CORS e disattivazione `docs` Swagger in produzione. |
| **Denial of Service (DoS)** | Saturazione memoria server via upload file di grandi dimensioni | Upload Form (`/import/*`, `/syslog/import`) | Middleware limite dimensione payload (max 50MB) e parsing in streaming/background. |
| **Elevation of Privilege** | Bypass dell'autorizzazione per eseguire azioni riservate all'admin | Endpoints `DELETE /api/syslog/clear` | Controlli RBAC a livello di router/endpoint (`Depends(require_role("admin"))`). |

---

## 2. Vettori di Attacco Principali e Matrice di Rischio

```text
  [Attaccante Esterno / Rete Aziendale]
                 │
                 │ 1. Invoco endpoint non autenticato DELETE /api/syslog/clear
                 ▼
      ┌─────────────────────┐
      │  FastAPI Backend    │ ──► [Cancellazione di tutti i log di sicurezza]
      └─────────────────────┘
                 │
                 │ 2. Upload file CSV da 2GB
                 ▼
      ┌─────────────────────┐
      │ Memory Exhaustion   │ ──► [Crash dell'applicazione per OOM Kill]
      └─────────────────────┘
```

### 2.1 Valutazione dei Rischi
- **Rischio 1: Accesso Non Autenticato ed Escalation (Probabilità: ALTA, Impatto: CRITICO)**
  - *Stato Attuale*: Nessuna autenticazione. [CONFIRMED]
  - *Mitigazione*: Implementazione immediata di Login e RBAC.
- **Rischio 2: Denial of Service via Upload Massivi (Probabilità: MEDIA, Impatto: ALTO)**
  - *Stato Attuale*: `file.read()` illimitato. [CONFIRMED]
  - *Mitigazione*: Limite dimensione a 50MB + Background processing.
