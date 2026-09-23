# Security Dashboard — V1 Scope

**Stato:** APPROVATO PER V1  
**Fase:** Architecture / Product Scope  
**Branch:** `architecture/initial-design`  
**Data:** 2026-09-23

## 1. Obiettivo della V1

La V1 della Security Dashboard deve rispondere in modo semplice e operativo alla domanda:

> **Quali vulnerabilità presenti oggi rappresentano un problema concreto per i nostri asset?**

Il prodotto deve quindi raccogliere, normalizzare, correlare e presentare informazioni di sicurezza in modo che un Security Team possa individuare rapidamente le vulnerabilità rilevanti, capire quali asset sono coinvolti e gestirne il triage.

La V1 deve essere focalizzata. Le funzionalità non indispensabili a questo obiettivo non fanno parte dello scope implementativo corrente.

---

## 2. Funzioni CORE della V1

### 2.1 Dashboard / Overview

Vista iniziale con una fotografia sintetica dello stato di sicurezza.

Deve mostrare almeno:

- numero totale CVE rilevate;
- CVE Critical / High;
- numero di asset vulnerabili;
- vulnerabilità nuove/non analizzate;
- vulnerabilità in trattamento;
- trend essenziali nel tempo;
- evidenza delle vulnerabilità più rilevanti;
- collegamento rapido al dettaglio e al triage.

Principio UX:

> **"Cosa devo guardare oggi?"**

---

### 2.2 Asset Inventory

Gestione e consultazione degli asset tecnologici.

Per ogni asset devono essere rappresentabili almeno:

- identificativo/nome;
- tipologia;
- vendor;
- prodotto;
- versione;
- CPE quando disponibile;
- criticità;
- stato;
- vulnerabilità associate.

Relazione fondamentale:

**Asset → Software/Product → CPE → CVE**

---

### 2.3 CVE / Vulnerability Management

Gestione delle informazioni sulle vulnerabilità, con NVD come fonte primaria iniziale.

Funzioni V1:

- sincronizzazione/importazione CVE;
- ricerca CVE;
- filtro per severità/CVSS;
- vendor/prodotto;
- date;
- descrizione;
- riferimenti/advisory;
- CPE coinvolti;
- relazione con gli asset locali.

La CVE non deve essere considerata solo come informazione catalografica: il valore della V1 è la relazione con il patrimonio tecnologico dell'organizzazione.

---

### 2.4 Vulnerability Analysis & Triage

Funzione operativa centrale.

Per ogni vulnerabilità devono essere visualizzabili:

- CVSS/severità;
- asset coinvolti;
- numero di asset;
- criticità degli asset;
- eventuali enrichment disponibili;
- origine dell'informazione;
- stato di trattamento;
- note;
- assegnatario, quando previsto.

Stati iniziali di riferimento:

- NEW
- ANALYZED
- ACKNOWLEDGED
- IN_PROGRESS
- RESOLVED
- NOT_AFFECTED

Il modello può essere affinato durante l'implementazione, ma non deve diventare un workflow eccessivamente complesso.

---

### 2.5 Threat Intelligence / Security Feeds

Raccolta e consultazione di informazioni provenienti da fonti di sicurezza.

V1:

- NVD;
- Feed CTI già previsti dal progetto;
- eventuali fonti già supportate dal codice esistente;
- data/fonte;
- collegamento alle CVE quando disponibile;
- correlazione con asset e vulnerabilità.

La V1 **non** deve diventare una piattaforma CTI completa.

---

### 2.6 Data Import

Importazione controllata dei dati necessari al funzionamento della piattaforma.

Fonti iniziali:

- asset/inventory;
- FeedHub;
- CTI;
- Syslog, limitatamente alle capacità già presenti e utili alla correlazione.

Pipeline concettuale:

**Import → Validation → Normalization → Storage → Correlation**

La V1 deve privilegiare affidabilità e sicurezza dell'ingestion rispetto alla quantità di formati supportati.

---

### 2.7 Correlation & Enrichment

Motore di correlazione essenziale tra:

- asset;
- software/prodotti;
- CPE;
- CVE;
- feed;
- eventi disponibili.

Obiettivo:

> trasformare dati separati in informazioni contestualizzate sull'esposizione dell'organizzazione.

L'algoritmo può essere progressivo. La V1 deve privilegiare correttezza, tracciabilità e prevedibilità rispetto a sofisticazione algoritmica.

---

### 2.8 Reporting

Reporting operativo essenziale.

V1:

- dashboard filtrabili;
- tabelle;
- grafici essenziali;
- export dei dati/report dove già previsto;
- vista sintetica per Security Team;
- vista sintetica per management.

Non è richiesto un sistema BI avanzato.

---

## 3. Risk Scoring V1

È ammesso un **risk scoring semplice e trasparente**, basato su fattori documentabili, ad esempio:

- CVSS;
- criticità dell'asset;
- esposizione;
- stato della vulnerabilità;
- eventuali indicatori di exploit/enrichment disponibili.

Il metodo deve essere documentato e comprensibile.

Non implementare nella V1 un motore di risk scoring proprietario complesso o non spiegabile.

---

## 4. Navigazione V1

La struttura funzionale di riferimento è:

```text
SECURITY DASHBOARD

├── Overview
├── Assets
├── Vulnerabilities / CVE
├── Analysis & Triage
├── Threat Intelligence / Feeds
├── Data Import
├── Reports
└── Administration
```

L'interfaccia deve privilegiare:

- chiarezza;
- rapidità di consultazione;
- filtri;
- ricerca;
- evidenza della priorità;
- tracciabilità delle informazioni;
- sicurezza.

---

## 5. Funzionalità ESCLUSE dalla V1

Le seguenti capacità **NON devono essere implementate adesso**, salvo esplicita nuova autorizzazione umana:

### 5.1 SIEM completo

Non trasformare la dashboard in uno SIEM.

### 5.2 Detection Engineering avanzato

Nessun motore complesso di detection rule nella V1.

### 5.3 SOAR / automazione di risposta

Nessun playbook automatico o orchestrazione di risposta agli incidenti.

### 5.4 Case Management avanzato

Nessun sistema completo di gestione investigation/case nella V1.

Il triage delle vulnerabilità con stato, note e assegnatario è sufficiente.

### 5.5 Alerting avanzato

Non costruire un motore sofisticato di alerting.

Eventuali evidenze/alert essenziali possono essere derivate dalla dashboard.

### 5.6 Risk Engine avanzato

Nessun modello quantitativo complesso o ML-based.

### 5.7 CTI Platform completa

Non costruire una piattaforma CTI indipendente.

### 5.8 Correlation Engine avanzato

Nessun motore di correlazione estremamente complesso nella V1.

### 5.9 Funzionalità non necessarie all'obiettivo V1

Qualsiasi nuova funzionalità non esplicitamente inclusa nello scope deve essere considerata **fuori scope** e richiede approvazione umana prima dell'implementazione.

---

## 6. Principio fondamentale di progetto

La V1 deve seguire questa catena:

```text
FONTI
  ↓
INGESTION
  ↓
NORMALIZZAZIONE
  ↓
ASSET
  ↓
CVE / VULNERABILITÀ
  ↓
CORRELAZIONE
  ↓
ANALISI
  ↓
TRIAGE
  ↓
REPORTING
```

Il valore della piattaforma non è raccogliere il maggior numero possibile di dati.

È:

> **correlare le vulnerabilità alle risorse reali dell'organizzazione e rendere immediatamente comprensibile cosa richiede attenzione.**

---

## 7. Regola anti-scope-creep

Durante l'implementazione ogni nuova richiesta deve essere classificata:

- **IN SCOPE V1** → implementabile;
- **NECESSARIA PER V1** → può essere aggiunta se indispensabile al funzionamento di una funzione V1;
- **FUTURE** → non implementare;
- **AMBIGUA** → fermarsi e chiedere autorizzazione al Project Manager/utente.

Gli agenti non devono introdurre autonomamente funzionalità Future durante refactoring, UI design o implementazione.

Se una funzionalità futura è necessaria per mantenere un'architettura estendibile, si deve predisporre il punto di estensione senza implementare la funzionalità stessa.

---

## 8. Definition of Done V1

La V1 sarà considerata funzionalmente completa quando un analista potrà:

1. importare/aggiornare gli asset;
2. acquisire le CVE e i feed previsti;
3. visualizzare le vulnerabilità;
4. correlare CVE e asset;
5. identificare le vulnerabilità più rilevanti;
6. analizzarle;
7. assegnare uno stato di triage;
8. aggiungere note/contesto;
9. consultare la situazione complessiva dalla Dashboard;
10. produrre un report operativo.

Tutto il resto è fuori dalla Definition of Done della V1.

---

## 9. Governance dello scope

Questo documento è il riferimento ufficiale per lo **scope funzionale della V1**.

La roadmap futura può essere estesa successivamente, ma le funzionalità escluse non devono entrare accidentalmente nella V1.

**La priorità attuale è completare una V1 piccola, solida, sicura e realmente utilizzabile.**
