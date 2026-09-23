# Prompt Template — GRAFICA UI/UX (Interface, Accessibilità, CVE Card)

## Ruolo
Progetta interfaccia: dashboard HTMX + Jinja2, scheda CVE compatta (spec 3.5), tabelle responsive, accessibilità (WCAG 2.1 AA), dark mode ready. **Competenza cyber** per terminologia corretta.

## Prompt Base
```
AGISCI COME UI/UX DESIGNER + FRONTEND DEV — Security Dashboard.

CONTESTO:
- Specifica UI: @SPEC.md (sezioni 3.4, 3.5)
- Stack: HTMX 1.9 + Jinja2 + Tailwind CDN + Alpine.js
- Template base: @app/templates/base.html
- Partial HTMX: @app/templates/partials/
- API contracts: @app/schemas/schemas.py (response models)

REGOLE:
1. **HTMX-first** — Zero SPA, fragmenti HTML via hx-get/hx-post
2. **Scheda CVE (3.5) = componente riutilizzabile** — Non hardcodare 4 campi
3. **Accessibilità WCAG 2.1 AA** — Contrasto, focus visible, ARIA, keyboard nav
4. **Responsive** — Mobile first, tabelle scrollabili orizzontali
5. **Dark mode ready** — CSS custom properties per colori

OUTPUT:
- Template Jinja2 nuovi/modificati
- Partial HTMX per aggiornamenti live
- CSS custom (app/static/css/custom.css se serve)
- Checklist accessibilità
```

## Viste Richieste (Spec 3.4)

| Vista | Template | Partial HTMX | Note |
|-------|----------|--------------|------|
| Overview | `dashboard.html` | `overview_cards.html`, `critical_vulns.html`, `recent_feed.html`, `assets_by_type.html`, `syslog_stats.html` | Auto-refresh 30s |
| Perimetro | `perimetro.html` | Tabella asset + modal import | Filtri tipo/criticità/search |
| Vulnerabilità | `vulnerabilita.html` | Tabella vuln + paginazione | Filtri severity/triage/asset/fonte |
| Feed | `feed.html` | Tabella feed + modal import | Highlight CVE estratte |
| Syslog | `syslog.html` | Tabella log + stats cards + modal import | Filtri hostname/sev/facility/asset/CVE |
| CVE Detail | `cve_detail.html` + modal | `cve_detail_modal.html` | **Spec 3.5: compatta, laterale/modale** |

## Scheda CVE — Spec 3.5 (Componente Riutilizzabile)

### Requisiti Minimi
```html
<!-- Componente: partials/cve_card.html -->
<div class="cve-card" data-cve-id="{{ cve.cve_id }}">
  <!-- 1. ID CVE + Badge Severità -->
  <div class="flex items-center gap-2">
    <code class="font-mono text-sm">{{ cve.cve_id }}</code>
    <span class="badge-{{ severity }} px-2 py-1 rounded text-xs">
      {{ severity }} {{ score }}
    </span>
  </div>
  
  <!-- 2. Descrizione Rischio (2-3 righe, linguaggio semplice) -->
  <p class="text-sm text-gray-700 mt-1 line-clamp-3">
    {{ risk_summary }}  <!-- Es: "Remote Code Execution via deserializzazione..." -->
  </p>
  
  <!-- 3. Link Advisory Vendor (se esiste) -->
  {% if vendor_advisory_url %}
  <a href="{{ vendor_advisory_url }}" target="_blank" class="text-xs text-blue-600 hover:underline flex items-center gap-1 mt-2">
    <i class="fas fa-external-link-alt"></i> Advisory {{ vendor }}
  </a>
  {% endif %}
  
  <!-- 4. Estensibilità: slot per asset, triage, feed refs -->
  <div class="cve-card-extensions mt-2">
    {% block extensions %}{% endblock %}
  </div>
</div>
```

### Estensioni Future (non rompere layout)
- `asset-list` — Asset coinvolti con match type badge
- `triage-status` — Dropdown stato (nuova/in_valutazione/mitigata/accettata)
- `feed-refs` — Link feed che citano la CVE
- `timeline` — Date pubblicazione, modifica, detection

## Accessibilità Checklist (WCAG 2.1 AA)

### Colori & Contrasto
- [ ] Testo: 4.5:1 (normal), 3:1 (large) — usa `text-gray-900` su `bg-white`
- [ ] Badge: 3:1 min — `badge-critical` (bg-red-600/text-white) ✓
- [ ] Focus visible: `focus:ring-2 focus:ring-blue-500 focus:ring-offset-2`

### Navigazione Tastiera
- [ ] Tab order logico (header → filters → table → pagination)
- [ ] Skip link: `<a href="#main" class="sr-only focus:not-sr-only">Salta al contenuto</a>`
- [ ] Modal: Trap focus, ESC per chiudere, restore focus on close

### ARIA & Semantica
- [ ] Tabelle: `<thead>`, `<th scope="col">`, `<tbody>`
- [ ] Badge status: `aria-label="Stato: nuova"` o `role="status"`
- [ ] Live regions per HTMX: `hx-swap="innerHTML"` + `aria-live="polite"`
- [ ] Icon-only buttons: `aria-label="Chiudi modal"`

### Screen Reader
- [ ] CVE card: descrizione rischio in testo piano (no solo badge)
- [ ] Paginazione: `<nav aria-label="Paginazione vulnerabilità">`
- [ ] Form import: `<label for="file">` associati correttamente

## Tailwind + CSS Custom Properties (Dark Mode Ready)

```css
/* app/static/css/custom.css */
:root {
  --color-bg: #f9fafb;
  --color-surface: #ffffff;
  --color-text: #111827;
  --color-text-muted: #6b7280;
  --color-border: #e5e7eb;
  --color-primary: #2563eb;
  --color-critical: #dc2626;
  --color-high: #ea580c;
  --color-medium: #ca8a04;
  --color-low: #2563eb;
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #0f172a;
    --color-surface: #1e293b;
    --color-text: #f1f5f9;
    --color-text-muted: #94a3b8;
    --color-border: #334155;
  }
}

/* Applica via @apply o utility custom */
```

## Responsive Tabelle
```html
<div class="overflow-x-auto">
  <table class="w-full min-w-[800px]">
    <!-- Su mobile: scroll orizzontale, non stack -->
  </table>
</div>
```

## HTMX Patterns Usati

| Pattern | Esempio |
|---------|---------|
| Auto-refresh | `hx-get="/api/overview" hx-trigger="every 30s"` |
| Click → modal | `hx-get="/api/cve/{{id}}" hx-target="#modal-content" hx-on::after-request="openModal()"` |
| Filter → table | `hx-get="/api/vulns" hx-target="#table-body" hx-include="[id^='filter-']"` |
| Form submit | `hx-post="/import" hx-target="#result" hx-swap="innerHTML"` |
| Infinite scroll | `hx-get="/api/logs?page=2" hx-trigger="revealed" hx-swap="beforeend"` |

## Consegna Grafica per Ciclo

### Ciclo 1
- [ ] `base.html` + `dashboard.html` + partials overview
- [ ] Color system + badge severity
- [ ] CVE card component (base 4 campi)
- [ ] Accessibilità base (focus, contrast, semantic HTML)

### Ciclo 2
- [ ] `perimetro.html`, `vulnerabilita.html`, `feed.html`, `syslog.html`
- [ ] Modal import (asset, feed, syslog) con preview mapping
- [ ] CVE detail modal con estensioni (asset, triage, feed refs)
- [ ] Tabelle: sort, pagination, row click

### Ciclo 3
- [ ] Dark mode toggle + persistence
- [ ] Keyboard shortcuts (/, j/k, ESC)
- [ ] Export buttons (CSV, JSON)
- [ ] Audit accessibilità completo (axe-core)

---

## Esempio Uso
```bash
# Task: "Crea scheda CVE modulare + modal detail per vulnerabilita.html"
# Incolla prompt + specifica quali partial servono
```