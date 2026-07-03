# Roadmap

## Obiettivo

Far evolvere l'estensione da strumento di ispezione/editing a strumento di
**valutazione di sicurezza browser-side** orientato alle best practice OWASP per
cookie e session management, token/JWT, security header e transport, restando
sempre dentro ciò che il browser può osservare (nessun backend, nessuna chiamata
esterna).

Direzioni di crescita residue: migliorare triage e leggibilità, colmare i gap di
copertura/affidabilità, abilitare review comparative (snapshot/diff), completare
la reportistica per CI e aprire la configurabilità — mantenendo il codice puro,
testato e pubblicabile come progetto open source.

## Stato attuale (v0.3.0)

Già disponibile:

- ispezione ed editing di cookie, token e header (regole `declarativeNetRequest`)
- decode JWT locale e **verifica firma JWT** offline via Web Crypto — HS/RS/PS/ES
  con secret/PEM/JWK/JWKS, algoritmo esplicito (anti algorithm-confusion),
  `alg:none` sempre rifiutato (`src/utils/jwtVerify.ts`)
- assessment OWASP Secure Headers con **analisi CSP per-direttiva**
  (`src/utils/assessment/csp.ts`): `unsafe-inline`/`unsafe-eval`, sorgenti
  wildcard e schemi insicuri, direttive difensive mancanti, nonce/hash e
  `strict-dynamic`, Trusted Types, reporting, policy `Report-Only`
- assessment Transport & TLS passivo, con controlli aggiuntivi
  (`src/utils/assessment/pageResources.ts`): **Subresource Integrity**, **mixed
  content** attivo/passivo, form insicuri, **`ws://`** su pagine HTTPS, e
  **inventario terze parti** (origini e cookie, euristica eTLD+1)
- Assessment unificato (sottotab Headers, Transport, Cookies, Tokens, Storage)
- **report unico** Markdown/JSON con **schema versionato** (`schemaVersion` `1.0`)
  ed **export filtrato per severità** (`src/utils/report.ts`)
- UI nel Chrome side panel con design system condiviso (`src/sidepanel/ui`)
- motore di assessment modularizzato in `src/utils/assessment/`
- unit test con `vitest` (69), CI GitHub Actions, scaffolding OSS

Per il dettaglio cronologico vedi `CHANGELOG.md` e la storia git.

## Principi di esecuzione

Per ogni intervento:

1. implementare la modifica più piccola utile
2. mantenere la logica di assessment in moduli puri, non nei componenti React
3. validare con `npm run test`, `npm run lint`, `npm run eslint`, `npm run build`
4. verificare manualmente nel side panel su almeno un sito reale
5. aggiornare `README.md`, `ARCHITECTURE.md` e `CHANGELOG.md` se il comportamento
   utente o la struttura cambiano

## Direzioni future (riordinate per priorità)

Le milestone CSP approfondita, verifica JWT + reportistica avanzata e controlli
osservabili aggiuntivi (SRI/mixed content/terze parti) sono state completate in
**v0.3.0** e rimosse da questo elenco. I punti **1 e 2** qui sotto sono già
implementati (in attesa di release); i punti 3–5 restano pianificati. L'ordine è
rivisto in base al rapporto valore/sforzo e all'aumento del volume di finding.

### 1. Triage e leggibilità dei finding ✅ (implementato)

- ✅ barra di **postura sintetica** in cima all'Assessment (`High · Medium · Low · Info`)
- ✅ **filtri** per severità minima e "solo azionabili" (`isActionableFinding`), più
  **ricerca testuale** sui finding
- ✅ conteggi coerenti tra UI e report: gli stessi filtri (`ReportFilter`) guidano sia
  la vista sia l'export (Copy/Download)

### 2. Copertura e affidabilità dei finding ✅ (implementato)

- ✅ **re-scan automatico** su navigazione / cambio tab (`chrome.tabs.onUpdated`/
  `onActivated`, nessun permesso `webNavigation`)
- ✅ scan **IndexedDB** oltre a `localStorage`/`sessionStorage` (Chrome 118+, fallback)
- ✅ **download del report su file** (`owasp-assessment-<host>-<ts>.md/.json`, Blob,
  nessun permesso `downloads`)
- ✅ rifiniture: claim JWT **`nbf`** (not-before) e attributo cookie
  **`Partitioned`/CHIPS**

### 3. Snapshot & Diff

Il vero salto di qualità per un reviewer.

- snapshot manuali del contesto: cookies, storage, primary response, finding
- punti tipici: pre-login, post-login, post-logout
- vista **diff**: cookie/token/header/finding comparsi, spariti o cambiati
- export del diff in Markdown (riusa il seam `filterReport` già presente)

### 4. Reportistica per CI: SARIF

- output **SARIF 2.1.0** dei finding per pipeline e code scanning; il renderer
  filtrato esiste già (`filterReport`), resta da mappare severità → `level` e
  `finding.id` → `ruleId` con un catalogo di regole

### 5. Configurabilità e maturità prodotto

- pagina **Options**: soglie configurabili (lifetime cookie/JWT, cosa è
  "sensibile"), toggle dei check, **soppressione/acknowledge** dei finding per
  origine (oggi `ExtensionSettings` espone solo `autoDecodeTokens`)
- internazionalizzazione (`chrome.i18n`)
- tema chiaro (facilitato dalla centralizzazione in `src/sidepanel/ui/status.ts`)
- storico per-tab degli assessment
- accessibilità (navigazione da tastiera / ARIA) del side panel

### Enhancement (backlog, non bloccanti)

- CSP: estendere l'analisi a `form-action`, `frame-src`, `worker-src`,
  `connect-src`, `upgrade-insecure-requests`
- SRI su risorse iniettate dinamicamente (oggi solo DOM allo scan)
- JWKS via **URL** per la verifica firma: deroga esplicita al principio "no rete",
  quindi opt-in e off di default

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
