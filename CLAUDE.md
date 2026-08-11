# keyboard-cipher — core crypto/formato

Crate Rust: cifratura e formato messaggio per una tastiera Android (fork
HeliBoard). Esposto alla JVM dal crate **separato** in `jni/`.

La separazione non è organizzativa: nel ponte JNI `unsafe` è inevitabile — i
simboli `extern "system"` dipendono dal contratto JNI, non dal type system —
mentre il core è e resta `#![forbid(unsafe_code)]`. Tenerli insieme
significherebbe rinunciare a quella garanzia proprio dove serve di più.
Regola aggiuntiva del ponte: **nessun panic può attraversare il confine**, un
unwind dentro una funzione `extern` è UB e non un crash pulito, quindi ogni
punto d'ingresso è avvolto in `catch_unwind`.

## Cosa fa e cosa non fa

- Fa: derivazione chiavi, AEAD, serializzazione del formato, encoding di
  superficie, keyring TOFU (come astrazione).
- NON fa: I/O, filesystem, rete, storage, JNI, clock di sistema, UI.
- RNG e tempo sono **iniettati** dal chiamante come parametri, mai presi da
  globali. Motivo: senza questo i vettori di test del formato non sono
  scrivibili e i test non sono deterministici.

## Modello d'uso

Messaggi one-shot, copiati e incollati dentro app di chat di terze parti.
Nessun canale di ritorno, nessun handshake, nessuno stato condiviso fra le
parti. Qualunque assunzione di interattività è sbagliata per costruzione.

## Threat model

L'avversario di riferimento è lo **scanning di massa lato piattaforma** (tipo
Chat Control / CSAR): analisi automatica e indiscriminata dei contenuti di
tutti gli utenti, con ritenzione in blocco. **Non** è un avversario mirato che
investe risorse su uno specifico utente. Questa distinzione decide gran parte
del design: difendersi da un classificatore che gira su tutto il traffico è un
problema diverso dal difendersi da un analista che guarda te.

Protegge da: chi legge il testo dentro la chat (piattaforma, server, backup
cloud, scanning automatico dei contenuti), e da manomissione del ciphertext.
Il testo in chiaro non raggiunge mai l'app di chat: la cifratura avviene nella
tastiera, prima che il contenuto entri nell'app.

NON protegge da — per scelta esplicita, non per dimenticanza:

- endpoint compromesso (keylogger, root, screenshot, accessibility service) e
  scanning a livello di OS anziché di app;
- metadati sociali: chi parla con chi resta comunque visibile alla
  piattaforma, e resterebbe visibile con qualunque design;
- il fatto stesso che si stia cifrando. **Residuo accettato**: sotto scanning
  automatico il sentinel è l'unico elemento del formato catturabile con una
  singola regex su tutto il traffico. Il pseudo-link difende dall'occhio umano,
  non da un classificatore. L'alternativa (nessun sentinel, riconoscimento per
  tentativo di decifratura) è stata valutata e scartata a favore della UX;
- correlazione fra messaggi dello stesso mittente tramite la `sender_pub` in
  chiaro. **Costo quasi nullo in questo modello**: la piattaforma conosce già
  l'identità dell'account mittente, quindi una pubkey pseudonima non le
  aggiunge informazione. Contro un avversario mirato la valutazione sarebbe
  diversa;
- compromissione futura delle chiavi long-term — **non piu', se la forward
  secrecy è accesa** (decisione I). È il rischio che la ritenzione in blocco fa
  maturare nel tempo: archivio conservato oggi + chiavi compromesse domani =
  decifratura retroattiva. Con la catena attiva le chiavi long-term non bastano
  più ad aprire nulla dal secondo messaggio in poi, allegati compresi. Resta
  scoperto solo ciò che si manda con l'interruttore spento;
- **replay** di un blob valido. Un blob resta valido per sempre e ripubblicarlo
  funziona. Priorità bassa in questo threat model, perché il replay è un'azione
  attiva e mirata, non qualcosa che emerge dallo scanning di massa. Mitigazione
  scelta (decisione C, chiusa): **timestamp di composizione dentro il cifrato**,
  mostrato in UI. Non impedisce il replay, lo rende *visibile a un umano*.

## Decisioni ferme (con motivo — non reinventare)

### Primitive

- **X25519** per l'ECDH. Diffuso, implementazioni pura-Rust mature, 32 byte.
- **XChaCha20-Poly1305** come AEAD. Nessun requisito di AES hardware, tempo
  costante in software puro. Nonce a 192 bit: obbligatorio qui, perché il
  segreto ECDH è statico per coppia (vedi sotto).
- **HKDF** per derivare la chiave AEAD dal segreto ECDH. Il segreto grezzo non
  si usa mai direttamente come chiave.
- **z-base-32** minuscolo per l'encoding di superficie. Sopravvive
  all'autocorrect: niente maiuscole, niente punteggiatura, niente caratteri
  visivamente ambigui. **Implementato in casa** (`src/encoding.rs`), non da
  crate: la spec è orientata ai bit e a noi serve solo il caso allineato ai
  byte, quindi la semantica dei bit di riempimento va decisa da noi e congelata.
- **Decodifica stretta**: si rifiutano i caratteri fuori alfabeto (maiuscole
  comprese), le lunghezze che non possono venire da byte interi, e i bit di
  riempimento finali non nulli. Motivo: senza, lo stesso blob avrebbe più
  rappresentazioni testuali distinte, e due messaggi identici potrebbero non
  risultare uguali a un confronto per stringa.
- **Vettori z-base-32.** La tabella EXAMPLES della specifica ha dieci righe, ma
  solo due sono allineate ai byte (24 bit): `F0 BF C7 -> "6n9hq"` e
  `D4 7A 04 -> "4t7ye"`. Le altre codificano quantità sub-ottetto che questa
  API non esprime. La riga a 30 bit è inoltre **difettosa nella specifica
  stessa**: la sua colonna base32 ha 7 caratteri dove 30 bit ne richiedono 6, e
  la sua z-base-32 (`6im5sd`) non corrisponde alla propria colonna base-2, che
  dà `6im54d`. Confermato indipendentemente: l'implementazione Go
  `corvus-ch/zbase32` calcola `6im54d` e annota nei propri test *"this test
  varies from what's in the spec by one character!"*. La spec non è un repo —
  è un `.txt` statico su philzimmermann.com, senza versionamento né
  manutentore — quindi non c'è un upstream da correggere.
  Non usare quella riga, in nessuna forma. La copertura sulle altre lunghezze
  viene da differential testing contro la crate `zbase32` (dev-dependency), non
  da vettori inventati.

### Mittente effimero (decisione H, chiusa)

Schema alternativo, **nello stesso tier**: la chiave nell'header e' usa-e-getta
e l'identita' del mittente non compare in chiaro. Segnalato dal bit di flag
`EPHEMERAL`, che si accompagna sempre a `SENDER_PUB` — "effimera senza chiave"
e' un header incoerente e il parser lo rifiuta.

La chiave AEAD nasce da **due scambi concatenati**:

```text
segreto = DH(effimera, destinatario) || DH(mittente, destinatario)
```

Il primo da' la mezza forward secrecy: l'effimera si butta subito, quindi chi
domani ottiene la chiave stabile del *mittente* non riapre i messaggi di ieri.
Il secondo e' la **prova d'identita'**: solo chi ha la privata del mittente puo'
produrre quel segreto, quindi il successo della decifratura dimostra chi ha
scritto.

**Perche' non una firma** (decisione H, chiusa): richiederebbe Ed25519 accanto a
X25519, cioe' una primitiva in piu' e un campo da verificare. Qui la prova viene
dalla derivazione stessa, senza aggiungere superficie.

**Come fa il destinatario a sapere chi ha scritto:** non lo sa, prova. Una
decifratura per ciascun contatto fissato; la prima che riesce identifica il
mittente. Con qualche decina di contatti non si nota. Chi non e' nel keyring non
viene riconosciuto, ed e' voluto: un mittente sconosciuto va presentato con una
card prima, altrimenti chiunque potrebbe far comparire messaggi nel keyring.
Fallendo tutte, l'errore e' `Crypto` come qualunque altro — distinguere "nessuno
dei miei contatti" da "corrotto" direbbe a chi attacca qualcosa sul keyring.

**Cosa NON risolve:** chi ottiene la chiave del **destinatario** apre tutto lo
stesso, perche' entrambi gli scambi passano di li'. Per quello serve una chiave
temporanea anche dal lato di chi riceve — ed e' la decisione I qui sotto.

**Compatibilita':** un messaggio effimero non lo apre una versione precedente.
La scelta sta quindi nel chiamante, non nel core: il core non sa che versione
abbia il destinatario, e indovinarlo produrrebbe messaggi illeggibili.

### Forward secrecy piena (decisione I, chiusa)

Chiude il buco lasciato dalla H: la chiave temporanea la mette **anche chi
riceve**. Segnalata dal bit `PREKEY`, che implica sempre `EPHEMERAL` — "prekey
senza effimera" e' un header incoerente e il parser lo rifiuta.

```text
segreto = DH(effimera, prekey_destinatario) || DH(mittente, prekey_destinatario)
```

**La prekey viaggia dentro il cifrato, non nell'header.** In chiaro sarebbe un
identificatore che cambia a ogni messaggio ma lega fra loro i due capi di una
conversazione — regalerebbe allo scanning esattamente il tipo di correlazione
che il mittente effimero toglie.

**Come parte la catena.** Il primo messaggio non puo' essere a forward secrecy
piena: una prekey dell'altro non ce l'abbiamo ancora. Ripiega sullo schema H, e
**porta comunque la propria prekey dentro il cifrato**. Da qui la regola che ha
gia' prodotto un bug: *ogni* messaggio ne porta una, anche quelli che non ne
usano una. Facendola viaggiare solo nei messaggi che gia' la usavano, la catena
non sarebbe mai partita — nessuno avrebbe mai avuto la prima.

Il ripiego **non e' un downgrade forzabile**: dipende da cosa ci ha mandato
l'altro in passato, non da cosa dichiara il messaggio in arrivo.

**Lo stato per contatto** vive in `Keyring` (`PrekeyStore` nel core: struttura
dati, nessun I/O, cosi' le tre implementazioni non ne hanno tre versioni
diverse). Se ne tengono `MAX_PREKEY_MIE` = 3, ed e' **la finestra in cui la
forward secrecy non c'e' ancora**: una sola romperebbe il caso normale — mando
due messaggi di fila, l'altro apre il secondo, il primo e' gia' morto — e molte
allungherebbero il periodo in cui un telefono sequestrato apre il passato.

**Il gesto che produce la proprieta' e' `drop_my_prekeys_older_than`**, cioe'
buttare, non cifrare. Finche' quelle chiavi esistono i messaggi che le usavano
si riaprono. Si butta il vecchio e non tutto: in un mezzo fatto di copia-incolla
i messaggi arrivano in ordine sparso di continuo.

**Cifrare non e' piu' un'operazione di sola lettura.** Genera una prekey nuova e
la mette nel keyring, quindi ogni chiamante deve persistere subito: un processo
che muore prima si porta nella tomba la chiave con cui l'altro rispondera'. Vale
per tutti e tre (tastiera, GUI, `kc`), ed e' scritto sulla firma JNI perche' da
li' non si indovina.

**Il prezzo, accettato esplicitamente dall'utente:** un messaggio si apre una
volta sola. Niente cronologia, e `kc archive` / "ricostruisci chat" non riaprono
niente di cio' che e' stato mandato cosi'. Per questo l'interruttore esiste
(uno solo, acceso di default) e il suo testo dice il prezzo, non solo il
vantaggio.

**Vale anche per gli allegati** (`encrypt_file_with`): un file senza catena e'
un buco piu' grosso di un messaggio senza — una foto vale piu' di una riga di
testo, e resta sul telefono di chi la riceve. Gli allegati usano **lo stesso
stato per contatto** dei messaggi, non uno loro: e' la stessa conversazione con
la stessa persona, e due catene separate significherebbero due volte le chiavi
da conservare e due volte le occasioni di non buttarle. `kind` resta nell'AAD
anche qui, quindi un allegato non si rilegge come messaggio nemmeno con la
catena — c'e' il test.

### Autenticazione mittente (baseline)

- `crypto_box` statico-statico: ECDH fra il nostro segreto e la pubkey del
  destinatario.
- La pubkey del **mittente** sta nell'Header **in chiaro**: serve al primo
  contatto TOFU. La correlabilità che ne deriva è **accettata**, coerentemente
  con il threat model sopra.
- L'Header deve poter migrare in futuro a "mittente effimero + claim
  d'identità firmato dentro il cifrato" **senza rompere il formato**:
  `sender_pub` è un campo **opzionale segnalato da un bit di flag**, non un
  campo assunto presente ovunque. Nessun codice deve dare per scontato che ci
  sia.

### Conseguenza operativa del segreto statico

La stessa coppia di identità produce sempre lo stesso segreto ECDH. Il nonce a
192 bit, generato a caso per ogni messaggio, è **l'unica** cosa che impedisce
il riuso di keystream. Quindi: mai contatori, mai nonce corti, mai nonce
derivati dal contenuto. Il nonce è anche il salt della HKDF, così la chiave
AEAD effettiva cambia a ogni messaggio.

### Fingerprint (decisione D, chiusa)

SHA-256 con domain separation sulla pubkey, troncata a **120 bit**, resa in
z-base-32 a gruppi di 4: **24 caratteri in 6 gruppi**. Congelato — è ciò che
due persone si leggono a voce o confrontano a schermo, e cambiarlo
invaliderebbe ogni verifica già fatta.

Perché 120 e non 96, che era la proposta iniziale: la proprietà vincolante è la
resistenza alla **seconda preimmagine** (per farsi passare per Bob serve una
chiave il cui fingerprint eguagli quello di Bob, che è fisso e non scelto
dall'attaccante), e lì 96 bit bastano. Ma la resistenza alle **collisioni** è
metà della lunghezza, e 48 bit sono alla portata di chiunque abbia delle GPU.
Oggi nessun flusso dipende dalle collisioni, perché il pin memorizza la chiave
intera e non il fingerprint — ma il formato è per sempre e una UI futura
potrebbe appoggiarcisi senza accorgersene. Il margine costa quattro caratteri.

Niente wordlist: manutenzione, localizzazione e ambiguità fonetiche non valgono
il guadagno, e l'alfabeto z-base-32 è già scelto per non essere ambiguo a
occhio.

### Identità e TOFU

- Alla prima comparsa di un peer: pin della sua pubkey, **senza etichetta**.
- **L'identità di contatto è un'etichetta locale assegnata dall'utente**
  (decisione F, chiusa). Senza, due chiavi diverse sono solo due peer diversi e
  "la chiave di Marco è cambiata" non è una frase esprimibile: il keyring è
  indicizzato sulla pubkey.
- Ne segue che **il pin non può mai essere un conflitto**. Quando arriva una
  chiave mai vista, il sistema non ha modo di sapere se sia un contatto nuovo o
  un contatto noto che ha cambiato telefono — lo sa solo l'utente. Perciò
  `PinOutcome` ha due soli casi, e il conflitto vive in `LabelOutcome`.
- Il conflitto scatta **quando si attribuisce un nome già in uso da un'altra
  chiave**: è il modello "safety number changed" di Signal, ed è anche il
  momento giusto per mostrare i due fingerprint, perché è l'unico in cui
  l'utente sta dichiarando di chi si tratta. Su conflitto **non si modifica
  nulla**: la vecchia chiave tiene il nome finché non arriva una conferma
  esplicita.
- Il conflitto è modellato come **esito** (`LabelOutcome::Conflict`), non come
  `Err`: non è un fallimento, è uno stato che richiede la UI.
- `replace_pinned` sposta l'etichetta sulla chiave nuova e **azzera
  `verified`**: una chiave nuova non è stata confrontata fuori banda, per
  definizione.
- *Residuo*: il cambio chiave non viene rilevato **automaticamente** all'arrivo
  del messaggio, ma solo quando l'utente nomina il nuovo peer. Un rilevamento
  automatico richiederebbe di dedurre l'identità dal contesto dell'app, che è
  rumoroso nel multi-contatto.

### Sentinel

- Forma: pseudo-link cosmetico, non stringa nuda.
- È **solo** estetica e plausibilità sociale a occhio umano. Non è una
  proprietà di sicurezza. Mai cliccabile, mai un dominio reale, mai una
  richiesta di rete.
- Vincolo tecnico obbligatorio: la forma **non deve essere riconosciuta dai
  linkifier** delle app di chat, altrimenti la piattaforma fa unfurl lato
  server e spedisce il blob a un terzo. In pratica: niente `://`, niente
  `www.`, niente pattern `label.tld`. Da qui `kc/`, con lo slash come
  separatore (non appartiene all'alfabeto z-base-32, quindi non è ambiguo).
- Resta in chiaro per forza: serve a riconoscere il blob prima di decifrarlo.
- **Il sentinel non contiene la versione.** Il numero di versione vive in un
  solo posto, il primo byte del body. Metterlo anche nel sentinel sarebbe una
  seconda fonte di verità, e avrebbe una conseguenza concreta: un blob prodotto
  da una futura versione 2 non verrebbe riconosciuto come nostro, e l'utente
  leggerebbe "questo testo non è cifrato" invece di "aggiorna l'app".
- **Il riconoscimento tollera spazi e contesto.** `parse` non pretende il
  sentinel a inizio stringa né il blob fino alla fine: cerca il sentinel nel
  testo e prende la sequenza massima di caratteri dell'alfabeto che segue. Le
  vie d'ingresso reali non consegnano mai testo pulito — clipboard e share
  sheet aggiungono un newline, chi seleziona a mano si porta dietro un
  "guarda: " davanti. Pretendere la stringa esatta significherebbe fallire nel
  caso più comune, e fallire con l'errore sbagliato: un blob valido con un
  `\n` in coda non è estraneo, è nostro.

### Primo contatto e scambio chiavi

- L'identita' e' UNA e vale per tutti i destinatari. Non esiste una chiave per
  contatto: il segreto per coppia si calcola, non si scambia. Qualunque UI che
  faccia sembrare il contrario e' sbagliata.
- Ogni messaggio cifrato porta gia' `sender_pub` in chiaro, quindi ricevere un
  messaggio fissa automaticamente la chiave del mittente. Resta scoperto solo
  il primissimo contatto in una sola direzione.
- Per quel caso esiste il blob **identity card**: la tastiera lo scrive
  direttamente nel campo di testo con `commitText`, l'utente preme invio.
  Niente clipboard. Asimmetria da tenere presente in tutto il progetto:
  **inserire nel campo e' nativo per un IME, leggere no** — la tastiera vede
  il campo di input, mai la cronologia della chat. Per questo la cifratura non
  passa dalla clipboard e la decifratura si'.
- Costo di bootstrap risultante: un tocco, una volta per contatto, in una sola
  direzione.
- Il QR di persona resta la via ad alta assicurazione: e' l'unica cosa che
  chiude il MITM al primo contatto, che il TOFU da solo non chiude.

### Come un blob raggiunge la tastiera

Quattro vie, tutte equivalenti per il core: consegnano una stringa, e
`handle_incoming_text` non sa da quale arriva.

1. **Clipboard** — la base, funziona ovunque. L'IME predefinito e'
   esplicitamente autorizzato a leggere la clipboard su Android 10+ ("unless
   your app is the default IME or is the app that currently has focus, your app
   cannot access clipboard data"). HeliBoard la legge gia' per la cronologia,
   quindi il costo marginale in privacy e' nullo.
   Sul toast di Android 12: compare la PRIMA volta che un'app legge dati messi
   in clipboard da un'altra app, non a ogni lettura, e
   `getPrimaryClipDescription()` non lo fa comparire mai. Quindi: polling
   passivo con `getPrimaryClipDescription()`, lettura del contenuto solo su
   gesto esplicito dell'utente.
2. **`ACTION_PROCESS_TEXT`** — un'Activity companion nello stesso APK mette
   "Decifra" nella barra di selezione del testo. Un tocco, niente clipboard.
   Funziona solo dove l'app usa la barra di selezione standard: le app con
   menu di long-press proprietario (WhatsApp) non la mostrano. Ottima dove
   c'e', inaffidabile come unica via.
3. **Share sheet (`ACTION_SEND`)** — fallback universale, piu' tocchi. Il
   testo decifrato compare in un'Activity nostra e non tocca l'app di chat.
4. **Campo di input** — se il blob e' nel campo servito dall'IME. Gratis,
   marginale in chat, utile per mail e note.

**Escluso: `NotificationListenerService`.** Darebbe decifratura automatica dei
messaggi in arrivo, ma richiede accesso a TUTTE le notifiche del dispositivo,
il che demolisce la premessa del progetto; e comunque le notifiche troncano il
testo lungo, quindi sui blob non funzionerebbe.

**Limite architetturale da mettere in conto come vincolo di prodotto:** nessuna
via da' decifratura automatica di cio' che scorre nella chat. La tastiera vede
il campo di input, mai la cronologia. Il destinatario compie un gesto
deliberato per ogni messaggio ricevuto.

### Activity companion (fork Android, non questo crate)

Le vie 2 e 3 sono intent di sistema: un `InputMethodService` non puo'
riceverli, serve un'Activity. Sta nello **stesso APK** dell'IME — stesso
processo, stessa identita', stesso keyring. Due APK significherebbero due copie
della chiave privata o un IPC su cui far viaggiare segreti.

Scheletro in `android/`, non compilato.

**Trappola da non ripetere.** Il contratto di `ACTION_PROCESS_TEXT` prevede che
l'Activity possa restituire al chiamante un testo sostitutivo via
`setResult(RESULT_OK, ... EXTRA_PROCESS_TEXT ...)`. E' l'implementazione
naturale di quell'intent ed e' la peggiore possibile qui: restituire il
plaintext lo consegna all'app di chat da cui e' partita la selezione, cioe'
proprio all'applicazione da cui il progetto esiste per tenerlo lontano. Non si
chiama mai `setResult` con dati; si esce senza risultato e il testo nell'app
chiamante resta cifrato.

Attributi obbligatori sull'Activity che mostra plaintext: `FLAG_SECURE` (prima
di qualunque `setContentView`), `noHistory`, `excludeFromRecents`,
`taskAffinity=""`, `launchMode=singleTask`. Senza `excludeFromRecents` /
`FLAG_SECURE` il sistema salva su disco uno screenshot del testo decifrato per
la schermata Recenti.

**Zero permessi. Decisione chiusa, e vale anche per `CAMERA`.** Il fork non ha
`INTERNET` ed e' la sua proprieta' principale; non ne acquista altri.

Conseguenza sul QR: **si mostra, non si scansiona.** Generare un codice non
costa permessi, leggerne uno richiede `CAMERA`, e quel permesso non si prende.
Non e' un residuo in attesa di essere colmato: e' la scelta.

Il primo contatto di persona resta comunque chiuso, perche' basta che UNO dei
due scansioni: l'altro inquadra il codice con un lettore QR qualunque, ottiene
la stringa `kc/...` e la consegna all'app dallo share sheet. Il MITM al primo
contatto si chiude lo stesso, e la tastiera resta senza permessi.

Se una sessione futura trova comodo aggiungere lo scanner: non e' una svista da
correggere, e va lasciata stare.

La UI contatti non e' nel launcher: ci si arriva dalle impostazioni della
tastiera. Un'icona sarebbe un secondo marcatore visibile del sistema e non fa
nulla che una voce nelle impostazioni non faccia gia'.

### Destinatario corrente (per app, non globale)

Una tastiera non sa con chi stai parlando. `EditorInfo` da' il package
dell'app, non la conversazione, e non esiste API per saperlo. Un accessibility
service che legge lo schermo lo direbbe ed e' **escluso**: distruggerebbe la
premessa del progetto e i permessi di HeliBoard.

Il destinatario si stabilisce in quest'ordine:

1. **implicitamente, decifrando** — chi legge e poi risponde ha gia' scelto
   leggendo. E' la leva che rende automatico il caso dominante;
2. **per memoria, per package** — un contatto per app significa zero
   interazione;
3. **esplicitamente, dalla toolbar** — fallback per il multi-contatto nella
   stessa app. Se viene usato spesso, i primi due non stanno funzionando.
   Si può selezionare solo un peer già fissato nel keyring.

Dentro la stessa app vince l'**ultimo mittente letto**. È la regola che rende
automatico il caso comune ed è anche l'unica che può sorprendere l'utente,
quindi ha un test dedicato.

**Ordine critico in `handle_incoming_text`: si decifra PRIMA di toccare il
keyring.** La decifratura riuscita è la prova che chi ha scritto possiede
davvero la privata dichiarata e che il messaggio era per noi. Fissare prima
permetterebbe a chiunque di riempire il keyring di peer inventati, o di far
comparire all'utente un falso "la chiave di Marco è cambiata" spedendo
spazzatura.

Mai indovinare. In assenza di destinatario si ritorna `UnknownPeer` e si
chiede: cifrare per la persona sbagliata e' il fallimento peggiore possibile.

### Formato

- Due tipi di blob (`Message`, `IdentityCard`) distinti da un byte `kind`
  DENTRO il body, non da sentinel diversi: dall'esterno devono essere
  indistinguibili. Un sentinel dedicato alle presentazioni sarebbe un
  marcatore in chiaro di "utente che aggancia un nuovo contatto", raccolto a
  costo zero da uno scanning di massa.
- `kind` entra nell'AAD: un messaggio non deve poter essere reinterpretato
  come blob di tipo diverso.
- I **flag non sono un campo** di `Header`: sono una funzione di
  `sender_pub.is_some()`. Due fonti di verità per lo stesso fatto
  permetterebbero di costruire un header incoerente, e un header incoerente
  fallisce l'autenticazione in modo opaco, cioè nel modo più difficile da
  diagnosticare. Perché la derivazione resti valida, `parse` **rifiuta i bit di
  flag non definiti** invece di ignorarli.
- **`parse` che ritorna `Ok` non dice nulla sull'integrità del contenuto.** Il
  ciphertext ha lunghezza variabile, quindi troncarlo produce un messaggio
  perfettamente ben formato con un ciphertext più corto, e nessun campo di
  lunghezza può smentirlo: sarebbe in chiaro, e un attaccante lo aggiusterebbe
  insieme al resto. A intercettarlo è il tag Poly1305 in decifratura, che è il
  posto giusto — l'integrità del ciphertext è competenza dell'AEAD, non del
  framing. Chi legge un `ParsedEnvelope` non deve mai dedurne che il messaggio
  sia intatto. Il parser garantisce solo che l'header sia completo e che resti
  almeno la lunghezza di un tag.
- **La identity card porta riempimento casuale in coda.** Senza, il suo body
  avrebbe lunghezza fissa (39 byte, 68 caratteri) mentre il messaggio più corto
  ne fa 127: una singola regex sulla lunghezza isolerebbe tutte e sole le
  presentazioni, su tutto il traffico, a costo zero. Sarebbe esattamente il
  marcatore "questo utente sta agganciando un nuovo contatto" che mettere
  `kind` dentro il body doveva evitare — la decisione non avrebbe prodotto
  l'effetto per cui è stata presa. Il riempimento porta la lunghezza in un
  intervallo che ricade dentro quello dei messaggi. Conseguenza: una card
  **non** ha rappresentazione testuale unica, al contrario di un messaggio. È
  voluto, la variabilità è lo scopo.
  *Residuo accettato*: su molti campioni le due distribuzioni restano
  distinguibili (le card sono uniformi, i messaggi seguono la lunghezza dei
  testi). Difende dalla regola cheap applicata a tappeto, non dall'analisi
  statistica su un utente scelto.
- *Residuo accettato*: la lunghezza del blob rivela la lunghezza del plaintext.
  Non si aggiunge nulla a ciò che la piattaforma vede comunque — senza il
  sistema vedrebbe direttamente il testo — quindi non si paga padding per
  questo.
- La identity card porta un checksum di 4 byte. Non e' autenticazione e non
  pretende di esserlo — una card puo' essere sostituita in transito, ed e'
  esattamente il rischio che il TOFU accetta. Serve contro la CORRUZIONE: una
  card troncata verrebbe fissata come chiave valida, e da quel momento ogni
  messaggio verso quel contatto fallirebbe in modo opaco senza che nessuno
  capisca perche'.
- **Timestamp di composizione in testa al plaintext, dentro il cifrato**
  (decisione C, chiusa). 8 byte, autenticati dall'AEAD senza bisogno di stare
  nell'AAD, invisibili alla piattaforma — che l'ora del messaggio la conosce
  già comunque.
  *Perché non una finestra di validità nell'AAD*, che il replay lo negherebbe
  davvero: farebbe fallire la decifratura di messaggi legittimi letti in
  ritardo, e in un sistema dove il destinatario compie un gesto deliberato per
  ogni messaggio leggere tre giorni dopo è normale. Richiederebbe inoltre un
  clock nel core, che non c'è per scelta.
  *Perché non una cache dei nonce visti*, che il replay lo bloccherebbe:
  richiede stato persistente che cresce senza limiti, e il core è stateless per
  costruzione.
  Il timestamp è **autenticato ma non verificabile**: nessuno può dimostrare
  che l'orologio del mittente fosse giusto. Va mostrato, mai usato per
  decisioni automatiche — un timestamp assurdo non è un errore, e rifiutare un
  messaggio per una data strana renderebbe il sistema inutilizzabile a chi ha
  l'ora sbagliata sul telefono.
- Byte di versione in testa.
- Marcatore di tier dentro la parte **autenticata** (AAD), per impedire
  downgrade forzato da un attaccante attivo.
- Il **tier** forward-secrecy resta non implementato: parsing riconosciuto,
  esecuzione → `TierUnsupported`. Da non confondere con la decisione I, che la
  forward secrecy la fa **dentro il tier baseline**, con i bit di flag: il tier
  e' un posto libero nel formato per uno schema futuro, non il meccanismo in
  uso.

### Errori

- Fallimento AEAD → un unico `Error::Crypto` opaco. **Mai** distinguere "tag
  non valido" da "chiave sbagliata" da "nonce corrotto": è un canale che aiuta
  l'attaccante. Nessuna sessione futura deve "migliorare la diagnostica" qui.
- Sentinel che non combacia → `NotOurBlob`, trattato come **esito normale**,
  non come errore grave: la tastiera lo usa per decidere se offrire l'azione
  "decifra".

### Segreti in memoria

- Chiavi private e plaintext: zeroize on drop, mai `Debug`/`Display`/
  `Serialize`.
- La garanzia si ferma al confine JNI: una `java.lang.String` è immutabile e
  non azzerabile. Verso la JVM si passa **`byte[]`**, mai `String`. Per questo
  l'API pubblica restituisce `Plaintext`, non `String`.

## Decisioni aperte — non implementare prima di chiuderle

Se una sessione le trova aperte, si ferma e chiede. Non sceglie per conto
proprio.

C, D, E e F sono chiuse; le loro motivazioni stanno nelle sezioni sopra.

*(La decisione E su z-base-32 è chiusa: vedi sotto.)*

### Decisione G — file cifrati (immagini e audio). **G1 CHIUSA, il resto aperto**

**G1, chiusa: sì, come documento allegato.** Si sceglie il file dall'Activity
contatti, si cifra in un contenitore binario, si consegna alla chat con lo share
sheet — che lo manda come *documento*, e i documenti Telegram e WhatsApp non li
ricomprimono. Chi riceve lo passa alla nostra app dallo share sheet.

**Residuo accettato con la chiusura di G1:** in chat si vede un allegato che non
si apre con nient'altro, ed è un marcatore molto più forte del blob di testo.
Accettato perché l'alternativa osservata è peggiore: senza questa via le foto si
mandano lo stesso, in chiaro, nella stessa conversazione.

Il resto della decisione (G2–G6) resta aperto.

**Cosa è già risolto e non è in discussione.** Il core cifra byte, non testo:
`seal` prende `&[u8]`. La crittografia non è il problema.

**Due vincoli tecnici, entrambi accertati e non aggirabili.**

1. *Un IME non può allegare un file.* Può inserire testo e, su Android 7.1+,
   immagini con `commitContent` — la via delle tastiere di GIF. Ma l'app
   ricevente tratta quel contenuto **come immagine e lo ricomprime**, e una
   ricompressione distrugge il ciphertext. L'audio non si può inserire affatto.
   Quindi qualunque soluzione passa dall'Activity companion e dallo share
   sheet, **non dalla tastiera**.
2. *Il formato attuale è testo.* z-base-32 gonfia di 1,6×, e una foto da
   500 KB diventerebbe 800 KB di caratteri. Fuori scala per un campo di chat.

**Il costo vero, che è quello che decide.** Un allegato è molto più visibile di
un messaggio di testo. Il blob testuale si nasconde dietro uno pseudo-link in
mezzo a milioni di messaggi; un documento di 300 KB che non si apre con niente
è un marcatore evidente di "queste due persone si scambiano file cifrati",
raccolto a costo zero da uno scanning automatico. È lo stesso segnale che il
riempimento casuale della identity card e il `kind` dentro il cifrato servono a
non emettere.

In più la **dimensione** rivela molto più della lunghezza di un testo, e il
file la piattaforma lo conserva.

**Da decidere, in quest'ordine:**

- G1. *Esiste?* Vedi le opzioni sotto.
- G2. Se sì: contenitore **binario** (niente z-base-32) con un `kind` nuovo
  dentro lo stesso envelope, oppure un formato di file separato.
- G3. Nome ed estensione dell'allegato: dichiarata (`.kc`), neutra (`.dat`), o
  mimetizzata. Attenzione: la mimetizzazione è una proprietà che questo
  progetto ha sempre rifiutato di contare come sicurezza — il sentinel è
  dichiaratamente solo estetica.
- G4. Destinatario: dall'Activity companion non c'è il contesto dell'app, quindi
  la scelta del contatto è **sempre esplicita**. Va confermato che sia
  accettabile.
- G5. Dove finisce il chiaro in ricezione. Proposta non negoziabile: storage
  interno dell'app, visualizzatore `FLAG_SECURE`, salvataggio fuori solo su
  gesto esplicito e con avviso — un file decifrato in Download è un file che
  finisce nel backup cloud e nella galleria.
- G6. Limite di dimensione, e se spezzare i file grandi (che moltiplica il
  marcatore, quindi probabilmente no).

## Regole di implementazione

- `#![forbid(unsafe_code)]`.
- Nessun panic in produzione: deny su `unwrap_used`, `expect_used`, `panic`,
  `indexing_slicing`, `arithmetic_side_effects`. `todo!()` è ammesso **solo**
  in fase scheletro.
- `clippy::panic` NON scatta su `todo!()`, quindi da solo non impedirebbe a un
  `todo!()` di arrivare in release. Per questo `[lints.clippy]` ha anche
  `todo = "deny"`, attivato alla fine della fase scheletro.
- Un solo `Error` pubblico per il crate (thiserror).
- Nessuna dipendenza che porti codice C se esiste alternativa pura-Rust.
- Il formato è per sempre: una volta rilasciata la versione 1, si aggiunge una
  versione nuova, non si modifica la 1.

## Test

- Vettori noti delle **primitive**: presi dalle crate upstream, non riscritti.
- Vettori del **nostro formato**: prodotti con RNG fisso e congelati come KAT.
  Un cambiamento che li rompe è un cambiamento di formato, non un refactor.
- Vettori z-base-32: presi dalla spec. **Non inventarli**: un vettore di test
  sbagliato è peggio di nessun vettore.
- Test negativi obbligatori: bit flip nel ciphertext, nell'AAD, nel byte di
  tier; versione sconosciuta; sentinel assente; input troncato; flag
  incoerenti con la lunghezza.
- Ogni parser va esercitato su input ostile. **Fatto**: `fuzz/` contiene tre
  target cargo-fuzz (richiede nightly, che c'è).
  - `decode` — `encoding::decode` non deve mai andare in panic, e se decodifica
    deve valere `encode(decode(s)) == s`.
  - `parse` — `format::parse` non deve mai andare in panic. Metà degli input
    viene prefissata col sentinel, altrimenti il fuzzer resterebbe quasi sempre
    sul ramo `NotOurBlob` senza entrare nel parsing vero.
  - `roundtrip` — costruisce blob **validi** per costruzione dall'input, li
    ri-parsa (deve tornare identico), poi li corrompe e li tronca. È il target
    che conta: raggiunge una copertura tripla rispetto a `parse`, perché quel
    target da solo dovrebbe indovinare l'encoding per arrivare ai rami
    profondi.
  - Ultima esecuzione: ~146M input complessivi, nessun crash (decode 79M,
    parse 62M, roundtrip 4M — quest'ultimo fa molto piu' lavoro per input).
  - **I target si rompono in silenzio.** `parse` e `roundtrip` costruiscono
    `Header` a mano, quindi un cambiamento del formato li fa smettere di
    *compilare* — e `cargo test` non se ne accorge, perche' `fuzz/` e' fuori
    dal workspace. Sono rimasti rotti per l'intera durata di un cambiamento di
    formato senza che niente lo segnalasse. Dopo ogni modifica a `format.rs`:
    `cargo +nightly fuzz build`, che costa pochi secondi.
  - Il corpus è in `.gitignore` (rigenerabile, cresce senza limiti); gli
    **artefatti di crash no**: quelli vanno versionati, sono la riproduzione
    di un bug.

## Stile

- Prima scheletro (moduli, firme, error types), poi implementazione. Non
  blocchi monolitici.
- Test unitari accanto a ogni funzione crypto.
- Commenti e commit in italiano.

## Comandi

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target aarch64-linux-android --release

# Crate JNI (cdylib per la JVM; fuori dal workspace del core perché usa unsafe)
cd jni && cargo build --release
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../android/jniLibs build --release

# Fuzzing (nightly; il crate in fuzz/ è fuori dal workspace del core)
cargo +nightly fuzz run decode    -- -max_total_time=150
cargo +nightly fuzz run parse     -- -max_total_time=150
cargo +nightly fuzz run roundtrip -- -max_total_time=150
```
