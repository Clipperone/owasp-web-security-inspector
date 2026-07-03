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

### M2 — Analisi CSP approfondita ✅ (implementato)

Sostituito il check superficiale (presenza di `unsafe`) con un analizzatore per
direttiva in `src/utils/assessment/csp.ts` (`assessCsp`):

- `unsafe-inline` / `unsafe-eval`, sorgenti wildcard, schemi pericolosi (`http:`/`data:`/`blob:`)
- assenza di `object-src`, `base-uri`, `frame-ancestors`, `default-src`
- riconoscimento di nonce/hash e `strict-dynamic` (mitigazione), Trusted Types e reporting
- declassamento delle policy `Report-Only`; finding dedicati con remediation precisa

Riferimento: OWASP Content Security Policy Cheat Sheet.
Limiti noti: CSP via `<meta>` non osservabile dagli header; policy multiple non
intersecate (documentato nel modulo).

### M3 — Snapshot & Diff

Il vero salto di qualità per un reviewer.

1. snapshot manuali del contesto corrente: cookies, storage, primary response
   summary, finding di assessment
2. supporto agli snapshot tipici: pre-login, post-login, post-logout
3. vista **diff**: cookie nuovi/rimossi, token comparsi/spariti, header cambiati,
   finding nuovi/risolti
4. export del diff in Markdown

### M4 — Reportistica avanzata e verifica JWT ✅ (implementato, SARIF rimandato)

- ✅ export filtrato per severità (All / High+Medium / High) in Markdown/JSON
  (`filterFindings`/`filterReport`); export del diff resta legato a M3
- ✅ schema JSON stabile e versionato (`schemaVersion` `1.0`, `REPORT_SCHEMA_VERSION`)
  per riuso in CI / issue template
- ⏸️ output **SARIF** — rimandato (M4.1); il seam `filterReport` è già riusabile
- ✅ **verifica firma JWT** con secret/PEM/JWK/JWKS forniti dall'utente, eseguita
  localmente via **Web Crypto** (`src/utils/jwtVerify.ts`) — solo offline (nessuna
  chiamata di rete), algoritmo scelto esplicitamente (anti algorithm-confusion),
  `alg: none` sempre rifiutato; distingue "decode" da "trust verification"

### M5 — Controlli aggiuntivi osservabili dal browser ✅ (implementato)

Nuovi finding categoria `transport` in `src/utils/assessment/pageResources.ts`,
sotto il tab Transport:

- ✅ **Subresource Integrity (SRI)**: `<script>`/`<link>` cross-origin senza
  `integrity` (scan DOM nel content script)
- ✅ **inventario terze parti**: origini esterne e cookie di terze parti (info,
  euristica eTLD+1 in `site.ts` senza public-suffix list)
- ✅ **mixed content** attivo/passivo, form insicuri e WebSocket `ws://` resi
  finding espliciti; il segnale di downgrade è calcolato una volta sola
  (`computeDowngradeSignals`) e condiviso col pannello Transport
- WebSocket osservati via `webRequest.onBeforeRequest` (nessun nuovo permesso)

Limiti: SRI vede solo il DOM al momento dello scan; `integrityValid` è solo
formale; i WebSocket aperti prima della registrazione del listener non sono visti.

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
