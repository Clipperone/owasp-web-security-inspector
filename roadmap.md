# Roadmap

## Obiettivo

Far evolvere l'estensione da strumento di ispezione/editing a strumento di
**valutazione di sicurezza browser-side** orientato alle best practice OWASP per
cookie e session management, token/JWT, security header e transport, restando
sempre dentro ciò che il browser può osservare (nessun backend, nessuna chiamata
esterna).

Direzioni di crescita: rendere i finding più profondi e affidabili, abilitare
review comparative (snapshot/diff), migliorare triage e leggibilità, e aprire la
configurabilità — il tutto mantenendo il codice puro, testato e pubblicabile come
progetto open source.

## Stato attuale (v0.2.0)

Già disponibile:

- ispezione ed editing di cookie, token e header (regole `declarativeNetRequest`)
- decode JWT locale con controlli strutturali e stato di scadenza
- assessment OWASP Secure Headers e assessment Transport & TLS passivo
- **Assessment unificato**: sottotab `Headers`, `Transport & TLS`, `Cookies`,
  `Tokens`, `Storage` tutti attivi e alimentati dallo stesso motore
- **report unico** Markdown/JSON su tutte le categorie (`src/utils/report.ts`)
- UI servita nel **Chrome side panel** e **design system** condiviso
  (`src/sidepanel/ui`)
- motore di assessment **modularizzato** in `src/utils/assessment/`
- unit test con `vitest`, CI GitHub Actions, scaffolding OSS (`LICENSE`,
  `CONTRIBUTING.md`, `ARCHITECTURE.md`, `CHANGELOG.md`)

Per il dettaglio cronologico vedi `CHANGELOG.md` e la storia git.

## Principi di esecuzione

Per ogni intervento:

1. implementare la modifica più piccola utile
2. mantenere la logica di assessment in moduli puri, non nei componenti React
3. validare con `npm run test`, `npm run lint`, `npm run eslint`, `npm run build`
4. verificare manualmente nel side panel su almeno un sito reale
5. aggiornare `README.md`, `ARCHITECTURE.md` e `CHANGELOG.md` se il comportamento
   utente o la struttura cambiano

## Direzioni future (prioritizzate)

### M1 — Triage e leggibilità dei finding (quick win)

- barra di **postura sintetica** in cima all'Assessment: rollup severità sempre
  visibile (`High N · Medium N · Low N`), senza trasformare la vista in dashboard
- ripristino dei **filtri** per severità, categoria e "solo azionabili", più
  ricerca testuale sui finding (capacità descritta nella vecchia Fase 7 ma persa
  nel passaggio al modello a sottotab)
- conteggi e ordinamento coerenti tra UI e report

### M2 — Analisi CSP approfondita

Il check CSP attuale è superficiale (presenza di `unsafe`). Introdurre un
analizzatore per direttiva:

- `unsafe-inline` / `unsafe-eval`, sorgenti wildcard, schemi pericolosi
- assenza di `object-src`, `base-uri`, `frame-ancestors`
- uso di nonce/hash, `require-trusted-types-for` (Trusted Types), `report-to`
- finding dedicati con remediation precisa

Riferimento: OWASP Content Security Policy Cheat Sheet.

### M3 — Snapshot & Diff

Il vero salto di qualità per un reviewer.

1. snapshot manuali del contesto corrente: cookies, storage, primary response
   summary, finding di assessment
2. supporto agli snapshot tipici: pre-login, post-login, post-logout
3. vista **diff**: cookie nuovi/rimossi, token comparsi/spariti, header cambiati,
   finding nuovi/risolti
4. export del diff in Markdown

### M4 — Reportistica avanzata e verifica JWT

- export filtrato (es. solo High/Medium) e export del diff
- schema JSON stabile per riuso in CI / issue template; valutare output **SARIF**
- **verifica firma JWT** con chiave o JWKS forniti dall'utente, eseguita
  localmente via **Web Crypto** — mantiene il principio browser-side e distingue
  in modo netto "decode" da "trust verification"

### M5 — Controlli aggiuntivi osservabili dal browser

- **Subresource Integrity (SRI)**: `<script>`/`<link>` cross-origin senza
  `integrity`
- **inventario terze parti**: origini esterne contattate e cookie di terze parti
- **mixed content**, form insicuri e connessioni `ws://` resi finding espliciti
  (parte del segnale è già raccolto dal modulo Transport)

### M6 — Configurabilità e maturità prodotto

- pagina **Options**: soglie configurabili (lifetime cookie/JWT, cosa è
  "sensibile"), toggle dei check, **soppressione/acknowledge** dei finding per
  origine (oggi `ExtensionSettings` espone solo `autoDecodeTokens`)
- internazionalizzazione (`chrome.i18n`)
- tema chiaro (facilitato dalla centralizzazione in `src/sidepanel/ui/status.ts`)
- storico per-tab degli assessment

### Release

Chiudere le milestone in incrementi verificabili: validazione completa, test
manuale su siti campione, `npm run release:patch|minor`, changelog aggiornato.

## Fuori scope (browser-side only)

Da non reintrodurre, perché richiede accesso al layer TLS o chiamate di rete e
romperebbe il principio del progetto:

- verifica certificati, cipher suite e versioni di protocollo TLS
- membership nella preload list HSTS, `security.txt`, OCSP/CT
- revoca token o invalidazione sessione lato server
- forza del secret JWT e qualità del key management
- compliance formale completa (es. OWASP ASVS)

## Ordine consigliato

1. M1 — postura sintetica e filtri (massimo rapporto valore/sforzo)
2. M2 — analizzatore CSP
3. M3 — snapshot & diff
4. M4 — reportistica avanzata e verifica firma JWT
5. M5 — controlli aggiuntivi (SRI, terze parti, mixed content)
6. M6 — Options, soppressione finding, i18n, tema chiaro
