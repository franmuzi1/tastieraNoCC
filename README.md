# keyboard-cipher

Il core crittografico di una tastiera Android che cifra il testo **prima** che
entri nell'app di chat.

Qui c'è solo la crittografia e il formato dei messaggi. Il lato Android — un
fork di [HeliBoard](https://github.com/HeliBorg/HeliBoard) — sta in
[`tastieraNoCC-app`](https://github.com/franmuzi1/tastieraNoCC-app), e da lì
conviene partire per capire a cosa serve tutto questo.

> **Sperimentale, mai controllato da nessuno tranne chi lo ha scritto.** Nessun
> audit indipendente. Il formato non è congelato. Se stai valutando di usarlo
> dove sbagliare ha conseguenze serie: non usarlo.

---

## Cosa fa, e cosa non fa

**Fa:** derivazione delle chiavi, cifratura autenticata, serializzazione del
formato, codifica di superficie, portachiavi con memorizzazione al primo
incontro.

**Non fa:** I/O, filesystem, rete, JNI, orologio di sistema, interfaccia.
Nemmeno per sbaglio: generatore casuale e tempo sono **parametri**, mai presi
da variabili globali. Senza questo i vettori di test del formato non sarebbero
scrivibili e i test non sarebbero deterministici.

## Due crate, e non è organizzazione

| | |
|---|---|
| `src/` — `keyboard-cipher-core` | `#![forbid(unsafe_code)]` |
| `jni/` — `keyboard-cipher-jni` | il ponte verso la JVM, dove `unsafe` è inevitabile |

I simboli esportati verso Java sono `extern "system"` e la loro correttezza
dipende dal contratto JNI, non dal type system. Tenerli nello stesso crate
significherebbe rinunciare alla garanzia sull'assenza di `unsafe` ovunque,
proprio per colpa delle poche righe in cui serve di più.

Regola aggiuntiva del ponte: **nessun panic attraversa il confine.** Un unwind
dentro una funzione `extern` non è un crash pulito, è comportamento non
definito — quindi ogni punto d'ingresso è avvolto in `catch_unwind`.

## Primitive

X25519 per lo scambio, XChaCha20-Poly1305 per la cifratura autenticata,
HKDF-SHA256 per derivare la chiave.

Il segreto condiviso fra due identità è **statico**: è sempre lo stesso per
quella coppia. L'unica cosa che impedisce il riuso del keystream è il nonce a
192 bit, estratto a caso per ogni messaggio — che è anche il salt della
derivazione, così la chiave effettiva cambia a ogni messaggio. Quindi: mai
contatori, mai nonce corti, mai nonce derivati dal contenuto.

L'encoding di superficie è **z-base-32**, scritto in casa: sopravvive
all'autocorrect perché non ha maiuscole, punteggiatura né caratteri
visivamente ambigui. La decodifica è stretta — rifiuta caratteri fuori
alfabeto, lunghezze impossibili e bit di riempimento non nulli — perché
altrimenti lo stesso messaggio avrebbe più rappresentazioni testuali e due
messaggi identici potrebbero non risultare uguali a un confronto.

## Verifica

```
cargo test                                   # 62 test
cargo clippy --all-targets -- -D warnings
cargo +nightly fuzz run roundtrip -- -max_total_time=150
```

Tre target di fuzzing (`decode`, `parse`, `roundtrip`), ~48 milioni di input
nell'ultima campagna, nessun crash.

I vettori delle primitive vengono dalle crate a monte, non riscritti a mano. I
vettori del formato sono prodotti con generatore fisso e **congelati**: un
cambiamento che li rompe è un cambiamento di formato, non un refactor.

Nessun panic in produzione: `unwrap`, `expect`, `panic`, indicizzazione diretta
e aritmetica che può traboccare sono tutti errori di compilazione.

## Prima di modificare qualcosa

Leggi [`CLAUDE.md`](CLAUDE.md). Non è documentazione di cortesia: contiene le
decisioni di progetto **con il motivo per cui sono state prese**, e diverse
sembrano arbitrarie finché non si legge cosa succede a cambiarle.

Qualche esempio di cose che sembrano migliorabili e non lo sono:

- un fallimento di decifratura restituisce **un solo errore opaco**.
  Distinguere "tag non valido" da "chiave sbagliata" è un canale che aiuta chi
  attacca;
- il sentinel che riconosce i nostri messaggi **non contiene la versione**. Se
  la contenesse, un messaggio di una versione futura non verrebbe riconosciuto
  come nostro e l'utente leggerebbe "questo testo non è cifrato" invece di
  "aggiorna l'app";
- la presentazione porta **riempimento casuale**. Senza, avrebbe lunghezza
  fissa, e una sola espressione regolare isolerebbe tutte e sole le
  presentazioni su tutto il traffico;
- memorizzare una chiave nuova **non può mai essere un conflitto**. Quando
  arriva una chiave mai vista, il sistema non ha modo di sapere se sia un
  contatto nuovo o un contatto noto che ha cambiato telefono: lo sa solo
  l'utente. Per questo il conflitto vive nell'assegnazione del nome.

## Licenza

Vedi il repository dell'app.
