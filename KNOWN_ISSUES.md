# KNOWN ISSUES — Security Dashboard (DashBoard eventi CVE)

**Stato Discovery**: completato  
**Metodologia**: Catalogazione statica di bug riscontrati, eccezioni latenti e disallineamenti di configurazione.

---

## 1. Registro Anomalie e Bug Riscontrati

### 1.1 Template `cve_detail.html` Mancante sul File System
- **Descrizione**: L'endpoint Web `/cve/{cve_id}` richiama il render del template `cve_detail.html`, che non è presente nella cartella `app/templates/`.
- **Riferimento Codice**: `app/api/dashboard.py#L49`.
- **Comportamento Atteso**: Visualizzazione della scheda dettaglio della CVE.
- **Comportamento Reale**: Eccezione runtime `jinja2.exceptions.TemplateNotFound: cve_detail.html` (HTTP 500).
- **Classificazione**: [CONFIRMED]

### 1.2 `NameError` nell'Endpoint Partial `/api/dashboard/critical-vulns`
- **Descrizione**: La funzione `get_critical_vulns` tenta di accedere all'oggetto `request.app.state.templates`, ma il parametro `request: Request` non è incluso negli argomenti della funzione.
- **Riferimento Codice**: `app/api/dashboard.py#L201` e `L207`.
- **Comportamento Atteso**: Render del partial HTML delle vulnerabilità critiche.
- **Comportamento Reale**: Errore di esecuzione Python `NameError: name 'request' is not defined` (HTTP 500).
- **Classificazione**: [CONFIRMED]

### 1.3 Test Unitari Marcati `@pytest.mark.skip`
- **Descrizione**: Nella suite di test `tests/test_api.py`, le funzioni `test_asset_crud` e `test_cve_sync_nvd` sono disabilitate con la causale *"Richiede database - run con docker compose"*.
- **Riferimento Codice**: `tests/test_api.py#L37` e `L66`.
- **Impatto**: La suite `pytest` eseguita in CI o ambiente locale valuta solo 4 test superficiali senza coprire la logica di business o l'interazione con il database.
- **Classificazione**: [CONFIRMED]

### 1.4 Hardcoded Default Secret Key
- **Descrizione**: Se la variabile `SECRET_KEY` non è valorizzata nel file `.env`, l'applicazione utilizza il valore insicuro predefinito `dev-secret-change-in-production`.
- **Riferimento Codice**: `app/core/config.py#L26`.
- **Classificazione**: [CONFIRMED]

### 1.5 Valore Fisso `"user"` per gli Aggiornamenti Triage
- **Descrizione**: Qualsiasi modifica allo stato di triage salva la stringa fissa `"user"` nella colonna `triage_updated_by`.
- **Riferimento Codice**: `app/api/cve.py#L352`.
- **Classificazione**: [CONFIRMED]
