# Roadmap

## Obiettivo

Trasformare l'estensione da strumento di ispezione e modifica in uno strumento di valutazione delle configurazioni applicative orientato alle best practice OWASP per:

- cookie e session management
- token e JWT storage
- security header e browser hardening
- esportazione dei finding in forma utile per review, QA e rilascio

## Stato Attuale

### Completato

- base solida di ispezione cookie, token e header
- editing cookie con validazioni pratiche su `Secure`, `SameSite`, `__Host-`, `__Secure-`
- decode JWT locale con controlli strutturali e stato di scadenza
- acquisizione response headers e summary OWASP-oriented nella tab Response Headers
- gestione centralizzata delle regole DNR nel background
- ESLint, lint TypeScript e build funzionanti
- nuova tab `Assessment` con finding automatici su cookie, storage token e header
- export del report di assessment in Markdown e JSON

### Da completare

- rendere l'assessment più profondo e più affidabile sui casi reali
- aggiungere snapshot e diff tra stati applicativi
- migliorare copertura `Set-Cookie`, `Cache-Control`, logout e cleanup sessione
- aggiungere test automatici ai moduli puri
- allineare documentazione e release alla nuova direzione del prodotto

## Principi di Esecuzione

Per ogni fase:

1. implementare la modifica più piccola utile
2. validare con `npm run eslint`, `npm run lint`, `npm run build`
3. verificare manualmente la UI del popup su almeno un sito reale
4. aggiornare README e roadmap se il comportamento utente cambia

## Fase 0 - Consolidamento Base Assessment

### Stato

- completata la parte tecnica di consolidamento
- resta consigliata la verifica manuale su siti reali prima del rilascio

### Obiettivo

Stabilizzare la nuova tab `Assessment` appena introdotta e verificarne il comportamento reale.

### Step

1. verificare manualmente la tab `Assessment` su:
   - un sito con login tradizionale a cookie
   - un sito con JWT in web storage
   - un sito con header di sicurezza maturi
2. controllare che il refresh ricarichi correttamente:
   - active tab info
   - cookies
   - storage scan
   - cached response headers
3. verificare che export Markdown e JSON siano coerenti con i finding mostrati
4. correggere eventuali falsi positivi o finding duplicati

### Output atteso

- assessment stabile
- formato report consistente
- zero errori di lint/build

### Risultato

- euristiche sensibili ristrette per ridurre falsi positivi su cookie e storage key
- export Markdown e JSON allineato ai finding visibili nel filtro corrente
- validazione eseguita con `npm run eslint`, `npm run lint`, `npm run build`

## Fase 1 - Cookie Assessment Avanzato

### Stato

- completata la parte tecnica della fase 1
- resta consigliata la verifica manuale su siti reali con login e scope multipli

### Obiettivo

Rendere la valutazione cookie utile in ottica session management review e non solo editing.

### Step

1. classificare automaticamente i cookie in categorie:
   - session/auth
   - csrf
   - preference
   - analytics/other
2. aggiungere finding per cookie sensibili con:
   - `SameSite=None` senza giustificazione chiara
   - `Path` troppo ampia
   - `Domain` troppo ampia
   - lifetime eccessiva
3. evidenziare cookie duplicati con stesso nome su scope diversi
4. aggiungere finding specifici per:
   - assenza di `__Host-` quando applicabile
   - assenza di `__Secure-` per cookie cross-site o auth rilevanti
5. mostrare una sezione riepilogativa dedicata ai cookie più critici

### Output atteso

- assessment cookie con priorità e contesto
- minore rumore sui cookie non sensibili

### Risultato

- classificazione automatica dei cookie in `session/auth`, `csrf`, `preference`, `analytics/other`
- nuovi finding per `SameSite=None`, scope `Path` ampia, scope `Domain` ampia e prefix recommendation `__Host-`/`__Secure-`
- riepilogo dedicato ai cookie osservati e ai cookie più critici nella tab `Assessment`
- validazione eseguita con `npm run eslint`, `npm run lint`, `npm run build`

## Fase 2 - Parsing e Analisi Reale di Set-Cookie

### Stato

- completata la parte tecnica della fase 2
- resta consigliata la verifica manuale su login flow, callback OAuth e API di refresh sessione

### Obiettivo

Valutare ciò che il server consegna al browser, non solo ciò che resta persistito.

### Step

1. migliorare il parsing di `Set-Cookie` per supportare meglio:
   - più attributi
   - casi edge su valori con `=`
   - più cookie nella stessa sessione di navigazione
2. associare i `Set-Cookie` ai request type rilevanti:
   - document response
   - login/auth callback
   - API response che impostano sessione
3. aggiungere finding per:
   - `Secure` mancante
   - `HttpOnly` mancante
   - `SameSite` mancante
   - `SameSite=None` senza `Secure`
4. mostrare separatamente:
   - cookie osservati nella response
   - cookie presenti nel browser jar

### Output atteso

- visione server-side observable più affidabile
- riduzione del mismatch tra response e cookie store

### Risultato

- analisi `Set-Cookie` applicata alle response rilevanti dello stesso host: document, callback/auth flow e API session-related
- finding aggiuntivi per `Set-Cookie` sensibili senza `Secure`, senza `HttpOnly`, senza `SameSite` e per `SameSite=None` senza `Secure`
- riepilogo separato nella tab `Assessment` tra cookie osservati nelle response e cookie presenti nel browser jar
- validazione eseguita con `npm run eslint`, `npm run lint`, `npm run build`

## Fase 3 - Header Assessment Esteso

### Stato

- completata la parte tecnica della fase 3
- resta consigliata la verifica manuale su document response, logout flow e response CORS credenziali

### Obiettivo

Estendere la copertura dei response headers davvero utili per una review OWASP/browser hardening.

### Step

1. aggiungere valutazione esplicita di:
   - `Cache-Control`
   - `Clear-Site-Data`
   - `Access-Control-Allow-Credentials`
   - `Vary: Origin` nei casi CORS sensibili
   - `Server`
   - `X-Powered-By`
2. distinguere meglio:
   - header mancanti
   - header presenti ma deboli
   - header presenti ma non applicabili al tipo di response
3. affinare i warning per CSP:
   - `unsafe-inline`
   - `unsafe-eval`
   - policy vuote o troppo permissive
4. aggiungere spiegazioni più precise su HSTS:
   - `max-age`
   - `includeSubDomains`
   - `preload`
5. inserire nella UI un blocco “why it matters” sintetico per i finding header più importanti

### Output atteso

- assessment header più credibile e meno superficiale
- migliore utilità per revisione di login page e app autenticata

### Risultato

- valutazione estesa di `Cache-Control`, `Clear-Site-Data`, `Access-Control-Allow-Credentials`, `Vary: Origin`, `Server` e `X-Powered-By`
- distinzione più esplicita tra header mancanti, header deboli e casi non applicabili nel traffico catturato
- warning HSTS più precisi su `max-age`, `includeSubDomains` e `preload`
- nuovo blocco `Why it matters` per i finding header nella tab `Assessment` e nel report Markdown
- validazione eseguita con `npm run eslint`, `npm run lint`, `npm run build`

## Fase 4 - Token e JWT Risk Assessment

### Stato

- completata la parte tecnica della fase 4
- resta consigliata la verifica manuale su token in cookie, `localStorage`, `sessionStorage` e input manuale nella tab Tokens

### Obiettivo

Passare dal semplice decode JWT alla valutazione del rischio lato browser.

### Step

1. classificare i token per origine:
   - cookie
   - `localStorage`
   - `sessionStorage`
   - input manuale
2. aggiungere finding per JWT con:
   - `alg=none`
   - `exp` assente
   - lifetime troppo lunga
   - claim sensibili o eccessivi
   - token scaduto ancora presente
3. aggiungere finding non-JWT per chiavi storage sensibili:
   - `access_token`
   - `refresh_token`
   - `id_token`
   - bearer-like stringhe lunghe e persistenti
4. evidenziare rischi storage-specifici:
   - `localStorage` ad alto rischio XSS/persistenza
   - `sessionStorage` a rischio medio
5. opzionale successivo:
   - supporto a verifica firma JWT tramite JWKS/public key fornita dall'utente

### Output atteso

- lettura più utile dei token reali
- chiara distinzione tra decode e trust verification

### Risultato

- classificazione dei token osservati per origine: `cookie`, `localStorage`, `sessionStorage`, con preview separata per `manual input`
- finding aggiuntivi per JWT con `alg=none`, `exp` assente, lifetime lunga, claim sensibili o payload eccessivo, token scaduto ancora presente nel contesto di review
- finding per token opachi non-JWT in storage browser e osservazione informativa per token-like cookie values
- nuova sezione `Token summary` nella tab `Assessment` e nuovo blocco `Risk preview` nella tab `Tokens` per l'input manuale
- validazione eseguita con `npm run eslint`, `npm run lint`, `npm run build`

## Fase 5 - Snapshot e Diff

### Obiettivo

Consentire review comparative tra stati applicativi, che è il vero salto di qualità per un reviewer.

### Step

1. introdurre snapshot manuali del contesto corrente:
   - cookies
   - storage entries
   - primary response summary
   - finding di assessment
2. supportare almeno tre snapshot tipici:
   - pre-login
   - post-login
   - post-logout
3. creare una vista diff per mostrare:
   - nuovi cookie
   - cookie rimossi
   - token comparsi o spariti
   - header cambiati
   - finding nuovi o risolti
4. aggiungere export diff in Markdown

### Output atteso

- strumento realmente utile per review manuale e audit rapido

## Fase 6 - Reportistica e Workflow di Review

### Obiettivo

Rendere il plugin utile anche fuori dalla singola sessione del popup.

### Step

1. strutturare il report export con sezioni fisse:
   - contesto
   - severità summary
   - finding dettagliati
   - remediation
   - limiti dell'analisi browser-side
2. aggiungere copy/export per:
   - full report
   - only high/medium findings
   - diff report
3. standardizzare il formato JSON per usi futuri:
   - issue template
   - import in CI helper
   - comparazioni tra sessioni
4. aggiungere timestamp, hostname, URL, conteggi osservati

### Output atteso

- report riusabile in review tecniche e note di rilascio

## Fase 7 - Libreria Remediation e UX di Prodotto

### Obiettivo

Migliorare il valore percepito del tool rendendo i finding più utili e più leggibili.

### Step

1. standardizzare i finding con template coerenti:
   - problema
   - impatto
   - evidenza
   - remediation
2. aggiungere badge o gruppi per:
   - auth/session
   - csrf
   - browser hardening
   - disclosure
3. introdurre filtri UI per:
   - categoria
   - severità
   - solo finding azionabili
4. migliorare naming e copy del prodotto per il rilascio:
   - meno “editor”, più “assessment”
   - evitare promesse di compliance totale

### Output atteso

- UX più professionale
- migliore aderenza al posizionamento del prodotto

## Fase 8 - Refactor e Test

### Obiettivo

Rendere il motore di assessment affidabile, testabile e facile da estendere.

### Step

1. mantenere la logica di assessment in moduli puri e non nei componenti React
2. aggiungere unit test per:
   - classificazione cookie sensibili
   - parsing `Set-Cookie`
   - valutazione header principali
   - ranking/severità finding
   - rilevamento JWT e claim sensibili
3. aggiungere fixture realistiche per:
   - sito con session cookie tradizionale
   - SPA con token in storage
   - sito con header maturi
   - sito con misconfigurazioni evidenti
4. validare regressioni su build di release

### Output atteso

- assessment più stabile
- minore rischio di regressioni e falsi positivi

## Fase 9 - Documentazione e Posizionamento Release

### Obiettivo

Allineare documentazione, README e release message alla reale capacità del plugin.

### Step

1. aggiornare README con:
   - nuova tab `Assessment`
   - spiegazione dei limiti browser-side
   - casi d'uso reali
2. preparare descrizione release orientata a:
   - OWASP-inspired browser assessment
   - session/token/header review
3. definire chiaramente cosa non viene verificato:
   - revoca token lato server
   - session rotation lato backend
   - forza del secret JWT
   - compliance formale completa
4. aggiungere screenshot o GIF del flusso assessment

### Output atteso

- documentazione coerente con il prodotto reale
- minore rischio di overclaim nel rilascio pubblico

## Fase 10 - Release Incrementale

### Obiettivo

Rilasciare in modo ordinato e verificabile.

### Step

1. chiudere le fasi 0-3 come primo rilascio utile
2. eseguire validazione completa:
   - `npm run eslint`
   - `npm run lint`
   - `npm run build`
3. test manuale su siti campione
4. aggiornare versione con:
   - `npm run release:patch`
   - oppure `npm run release:minor` se la milestone è ampia
5. produrre changelog della release

### Output atteso

- prima release chiaramente centrata su assessment browser-side

## Ordine Consigliato di Esecuzione

Se vuoi procedere in modo pragmatico, l'ordine migliore è questo:

1. Fase 0 - consolidamento assessment esistente
2. Fase 1 - cookie assessment avanzato
3. Fase 2 - parsing e analisi `Set-Cookie`
4. Fase 3 - header assessment esteso
5. Fase 4 - token risk assessment avanzato
6. Fase 5 - snapshot e diff
7. Fase 6 - reportistica strutturata
8. Fase 8 - test
9. Fase 9 - documentazione release
10. Fase 10 - rilascio

## Prossimo Step Consigliato

Il prossimo step con il miglior rapporto valore/sforzo è:

1. consolidare la nuova tab `Assessment`
2. migliorare subito l'analisi cookie e `Set-Cookie`
3. poi estendere l'assessment header su cache, CORS e disclosure

Questo ordine porta velocemente il plugin verso un rilascio credibile come strumento di valutazione OWASP-oriented.