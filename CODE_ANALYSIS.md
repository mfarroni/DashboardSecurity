# CODE ANALYSIS — Security Dashboard (DashBoard eventi CVE)

**Stato Analisi**: completato  
**Metodologia**: Ispezione statica del codice sorgente (Senza modifiche al codice).

---

## 1. Commenti TODO / FIXME / HACK Individuati

- **User Hardcoded in Triage Update**:
  - **Evidenza**: `app/api/cve.py#L352` -> `av.triage_updated_by = "user"  # TODO: utente reale`
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: L'aggiornamento dello stato di triage associa sempre la stringa fissa `"user"`, poiché non esiste un modulo di autenticazione/gestione sessioni utenti.

- **Impostazioni Predefinite per Scheduler e Sync**:
  - **Evidenza**: `app/core/config.py#L44-L45` -> `nvd_sync_interval_hours: int = 6` e `feed_sync_interval_hours: int = 1`
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: I parametri sono definiti nella configurazione ma nessun job di background (es. tramite APScheduler o Celery) è registrato all'avvio dell'applicazione FastAPI in `app/main.py`.

---

## 2. Codice Morto o Inutilizzato

- **Import Duplicato in Router Dashboard**:
  - **Evidenza**: `app/api/dashboard.py#L2-L3` -> `from fastapi.responses import HTMLResponse` importato due volte di seguito.
  - **Classificazione**: [CONFIRMED]

- **APScheduler Nelle Dipendenze ma Inattivo**:
  - **Evidenza**: `requirements.txt#L19` -> `apscheduler==3.10.4`. In nessun punto del codice applicativo (`app/`) viene importato o inizializzato `apscheduler`.
  - **Classificazione**: [CONFIRMED]

- **Passlib e Python-Jose Inattivi**:
  - **Evidenza**: `requirements.txt#L32-L33` (`passlib[bcrypt]==1.7.4`, `python-jose[cryptography]==3.3.0`). Nessun file in `app/` contiene import di `passlib` o `jose`.
  - **Classificazione**: [CONFIRMED]

- **Codice di Matching IP Non Implementato**:
  - **Evidenza**: `app/api/syslog.py#L159-L161` -> `if entry.source_ip: pass`. Il blocco di matching asset via IP sorgente contiene un semplice `pass`.
  - **Classificazione**: [CONFIRMED]

---

## 3. Template Mancanti / Riferimenti Inesistenti (Bug Latenti)

- **Template `cve_detail.html` Inesistente**:
  - **Evidenza**: `app/api/dashboard.py#L49` -> `return request.app.state.templates.TemplateResponse("cve_detail.html", {"request": request, "cve_id": cve_id})`.
  - **Verifica File System**: La directory `app/templates/` contiene solo `base.html`, `dashboard.html`, `feed.html`, `perimetro.html`, `syslog.html`, `vulnerabilita.html` e i partials. Il file `cve_detail.html` NON ESISTE.
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: Una chiamata GET all'endpoint `/cve/{cve_id}` genererà un errore runtime `jinja2.exceptions.TemplateNotFound`.

- **Uso Errato di `request` Senza Parametro nella Signature**:
  - **Evidenza**: `app/api/dashboard.py#L201` e `L207` -> la signature della funzione è `async def get_critical_vulns(db: Session = Depends(get_db)):`, ma nel corpo viene usata la variabile non definita `request.app.state.templates...`.
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: L'endpoint `/api/dashboard/critical-vulns` genererà un `NameError: name 'request' is not defined` quando invocato.

---

## 4. Gestione degli Errori e Casi Limite Insufficienti

- **Catch Generico nelle Operazioni di Sync NVD**:
  - **Evidenza**: `app/api/cve.py#L316` -> `except Exception as e: errors.append(...)`.
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: Gli errori vengono silenziati e aggiunti a una lista senza logging strutturato o distinzione tra errori di rete, parsing JSON o vincoli del DB.

- **Nessuna Gestione di Exception Timeout / ConnectionError su HTTP Client**:
  - **Evidenza**: `app/api/cve.py#L38-L65`. Le chiamate `httpx.AsyncClient` non gestiscono esplicitamente `httpx.TimeoutException` o `httpx.ConnectError`. Un malfunzionamento della rete NVD solleverà un'eccezione non gestita HTTP 500.
  - **Classificazione**: [CONFIRMED]

- **Lettura File In-Memory Senza Limiti di Dimensione**:
  - **Evidenza**: `app/api/assets.py#L149`, `app/api/feed.py#L110`, `app/api/syslog.py#L283` -> `content = await file.read()`.
  - **Classificazione**: [CONFIRMED]
  - **Impatto**: L'upload di file di grandi dimensioni (es. dump syslog da centinaia di MB o GB) caricherà l'intero contenuto nella memoria RAM del server, con rischio di Denial of Service per Esaurimento Memoria (OOM Kill).

---

## 5. Tracce di Codice Generato da IA o Automazioni

- **Skill YAML OpenCode Custom**:
  - **Evidenza**: `.opencode/skill/*.yaml` (es. `security-dashboard.yaml`, `cve-correlation.yaml`, `nvd-sync.yaml`).
  - **Classificazione**: [CONFIRMED]
  - **Note**: La struttura del repository contiene skill OpenCode appositamente create per guidare agenti AI nell'esecuzione di comandi di gestione, import e test.

- **Prompt per Ruoli Agentici**:
  - **Evidenza**: `.opencode/prompts/01-analista.md`, `02-sviluppo.md`, `03-grafica.md`.
  - **Classificazione**: [CONFIRMED]
  - **Note**: Presenza di indicazioni di ruolo strutturate per team di agenti AI (Analista, Sviluppo, Grafica/UI).

- **Struttura Boilerplate e Schemi Standardizzati**:
  - **Evidenza**: Estrema uniformità nella definizione dei router API FastAPI, schemi Pydantic e modelli SQLAlchemy, tipica di generazione guidata da LLM con prompt strutturati.
  - **Classificazione**: [LIKELY]
