# Roadmap

## Obiettivo

Questa roadmap serve per evolvere l'estensione a piccoli step, evitando modifiche massive e mantenendo ogni intervento facile da verificare e da revertire.

Ogni step deve essere implementato come lavoro autonomo, con scope ridotto, validazione locale e criterio di completamento chiaro.

## Regole di esecuzione

1. Implementare un solo step alla volta.
2. Evitare di mischiare bugfix, nuove feature e upgrade librerie nello stesso step.
3. Limitare ogni step a un set piccolo di file, salvo casi strettamente necessari.
4. Validare sempre con:

```bash
npm run lint
npm run build
```

5. Aggiornare README solo quando il comportamento utente cambia davvero.
6. Non introdurre refactor ampi finche' i bug funzionali principali non sono chiusi.

## Ordine di priorita'

1. Correttezza funzionale
2. UX fondamentale
3. Allineamento documentazione e prodotto
4. Manutenibilita'
5. Test
6. Aggiornamento dipendenze

## Fase 9 - Import/export di configurazione

### Obiettivo

Rendere portabili configurazioni e set di lavoro tra ambienti o sessioni.

### Scope

- Export JSON di regole header e impostazioni.
- Import JSON validato.
- Tenere i cookie fuori da questa fase, salvo requisito esplicito.

### File attesi

- `src/utils/storageUtils.ts`
- `src/popup/HeadersTab.tsx`
- eventuale nuovo helper in `src/utils/`

### Modifiche previste

- Schema semplice e versionabile.
- Validazione minima di compatibilita'.

### Validazione

1. Esportare configurazione.
2. Resettare storage locale.
3. Importare di nuovo.
4. Verificare ripristino corretto delle regole.

### Done when

- Le configurazioni principali possono essere salvate e ripristinate.

## Fase 10 - Snapshot e diff operativo

### Obiettivo

Supportare meglio debugging e test manuali ripetibili.

### Scope

- Snapshot di regole header.
- Snapshot di cookie visibili.
- Diff semplice tra stato corrente e snapshot precedente.

### File attesi

- `src/popup/CookieTab.tsx`
- `src/popup/HeadersTab.tsx`
- `src/utils/storageUtils.ts` o nuovo helper dedicato

### Modifiche previste

- Funzione semplice di salvataggio stato.
- Vista minimale del delta, senza overengineering.

### Validazione

1. Salvare snapshot.
2. Cambiare cookie o regole.
3. Verificare che il delta sia leggibile.

### Done when

- L'estensione aiuta a confrontare rapidamente prima e dopo di una modifica.

## Fase 13 - Estrazione componenti e hook piccoli

### Obiettivo

Ridurre la complessita' dei tab piu' grandi senza riscrivere l'interfaccia.

### Scope

- Estrarre solo parti stabili da CookieTab e HeadersTab.
- Evitare refactor esteso in un colpo solo.

### File attesi

- `src/popup/CookieTab.tsx`
- `src/popup/HeadersTab.tsx`
- nuovi componenti o hook in `src/popup/`

### Modifiche previste

- Estrazione di row component, toolbar component o hook locali.
- Nessuna modifica funzionale rilevante.

### Validazione

1. Regressione manuale completa dei tab interessati.
2. `npm run lint`
3. `npm run build`

### Done when

- I file principali sono piu' piccoli e leggibili senza regressioni.

## Fase 14 - Test unitari dei moduli puri

### Obiettivo

Proteggere la logica piu' stabile con test a basso costo.

### Scope

- Test per jwt utils.
- Test per cookie utils.
- Test per header utils.
- Test per exporter.

### File attesi

- file di test dedicati
- eventuale configurazione test runner

### Modifiche previste

- Scegliere un test runner leggero e compatibile con Vite.
- Non testare subito l'intera UI.

### Validazione

```bash
npm run lint
npm run build
```

Eseguire anche il comando test introdotto in questa fase.

### Done when

- Le utility piu' critiche hanno copertura minima ma utile.

## Sequenza consigliata per PR o commit

1. Fase 9
2. Fase 10
3. Fase 13
4. Fase 14

## Regola pratica per non fare modifiche massive

Se durante uno step emerge un lavoro laterale non strettamente necessario, va spostato nello step successivo piu' vicino per tema.

In particolare:

1. Non fare refactor mentre stai correggendo un bug runtime, salvo minima estrazione indispensabile.
2. Non aggiornare dipendenze mentre stai introducendo nuove feature.
3. Non riscrivere i tab grandi in un solo intervento.
4. Non aggiornare README se il comportamento finale di quello step non e' ancora stabile.

## Primo step consigliato da implementare

Partire da **Fase 9 - Import/export di configurazione**.

E' il prossimo incremento funzionale piu' isolato, con buon valore pratico e impatto limitato sull'architettura esistente.