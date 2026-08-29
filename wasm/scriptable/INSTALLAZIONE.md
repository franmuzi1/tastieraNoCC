# MusyBoard su iOS — installazione

## 1. Scriptable

App Store → cerca "Scriptable" (icona nera `{}`, di Simon B. Støvring) → Installa.
Apri l'app una volta e chiudila: crea la sua cartella locale.

## 2. File necessari

Nella cartella **locale** di Scriptable (`Su iPhone → Scriptable` nell'app File —
**mai** `iCloud Drive → Scriptable`, altrimenti la chiave privata sincronizza
sui server Apple):

- `MusyBoard.js` (questo repo, `wasm/scriptable/MusyBoard.js`)
- `musyboard_wasm.wasm` — compilato con:
  ```
  cargo build --release --target wasm32-unknown-unknown --manifest-path wasm/Cargo.toml
  ```
  si trova poi in `wasm/target/wasm32-unknown-unknown/release/musyboard_wasm.wasm`
  — copialo con **esattamente questo nome**, `MusyBoard.js` lo cerca per nome.

Se il salvataggio da un'app di messaggistica non mostra subito la cartella
giusta: vedi la nota nella cartella `wasm/poc/` su come capita di finire per
sbaglio nella cartella iCloud con lo stesso nome, e come spostarsi da lì senza
lottare con l'app File.

## 3. Primo avvio

Apri Scriptable, crea un nuovo script, incolla `MusyBoard.js`, eseguilo.
Ti chiederà di generare un'identità — accetta, poi copia la tua presentazione
e mandala al tuo contatto Android.

## 4. Comandi Rapidi

Meccanismo usato: l'azione **"Esegui script"** di Scriptable (compare nella
libreria azioni di Shortcuts una volta installata l'app) passa il suo
parametro allo script leggibile da `args.shortcutParameter`, e lo script
restituisce un risultato con `Script.setShortcutOutput(...)`.

`MusyBoard.js` riconosce l'intento da un marcatore in testa al testo
(`MB_DECRYPT:` o `MB_ENCRYPT:`) che il Comando Rapido stesso aggiunge — così
i due Comandi restano due azioni distinte, non un'unica scorciatoia che
indovina cosa fare.

**Nota sui nomi esatti delle azioni**: variano leggermente fra versioni di
iOS e lingua del dispositivo. I passaggi sotto descrivono il meccanismo —
cerca l'azione più simile per nome se qualcosa non corrisponde esattamente.
Verificalo su un dispositivo reale prima di fidartene: nessuna parte di
questa guida è stata testata su un iPhone vero.

### "Decifra MusyBoard"

1. App Comandi Rapidi → nuovo Comando Rapido → nome "Decifra MusyBoard"
2. Aggiungi l'azione **"Testo"**: scrivi `MB_DECRYPT:` nel campo, poi tocca il
   campo e inserisci la variabile del **contenuto in ingresso del Comando
   Rapido** (quella che porta il testo condiviso o dagli Appunti) subito dopo,
   cosi' il campo diventa `MB_DECRYPT:` seguito dalla variabile.
3. Aggiungi l'azione **"Esegui script"** → Scriptable → scegli lo script
   "MusyBoard" → verifica che il suo input sia il testo prodotto al passo 2
   (di solito si incatena da solo, essendo l'unica uscita del passo precedente).
4. Aggiungi l'azione **"Mostra risultato"** (o "Mostra notifica") con
   l'uscita di "Esegui script".
5. Tocca l'icona "ⓘ" del Comando Rapido → attiva **"Mostra nella condivisione"**
   (Show in Share Sheet) → tipi accettati: **Testo**. Questo lo fa comparire
   nel menu Condividi di altre app.
6. (Facoltativo) Attiva anche l'accesso dagli **Appunti** come sorgente,
   secondo quanto offre la tua versione di iOS in quella stessa schermata.

### "Cifra con MusyBoard"

1. Nuovo Comando Rapido → nome "Cifra con MusyBoard"
2. Aggiungi l'azione **"Chiedi testo"**: prompt "Testo da cifrare", e nel
   campo **"Valore predefinito"** inserisci la variabile **Appunti** — cosi'
   il campo si presenta gia' pieno se hai appena copiato qualcosa, ma resta
   modificabile.
3. Aggiungi l'azione **"Testo"**: `MB_ENCRYPT:` seguito dalla variabile con la
   risposta del passo precedente.
4. Aggiungi l'azione **"Esegui script"** → Scriptable → "MusyBoard" → input =
   il testo del passo 3.
5. Aggiungi l'azione **"Copia negli Appunti"** con l'uscita di "Esegui script".

Non serve metterlo nel menu Condividi (si avvia da Comandi Rapidi o
dalla schermata Home).

## 5. Verifica end-to-end (da fare su un iPhone vero)

1. Genera l'identita', scambia le presentazioni con un dispositivo Android
   reale (o con `cli/` sul Mac/Linux).
2. Cifra un messaggio su Android, decifralo su iOS con "Decifra MusyBoard"
   dal menu Condividi — e viceversa.
3. Chiudi Scriptable del tutto (non solo in background), riaprilo, verifica
   che una conversazione già iniziata continui a funzionare (idratazione da
   `config.json`).
4. Prova il rogo di una conversazione e verifica che le vecchie chiavi
   spariscano da `config.json`.
5. Con il telefono in modalità aereo, verifica che tutto continui a
   funzionare (conferma "nessuna rete").
6. Controlla nell'app File che `config.json` e `musyboard_wasm.wasm` stiano
   solo sotto "Su iPhone", mai sotto "iCloud Drive".
