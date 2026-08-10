# Handoff — stato del lavoro al 2026-08-10

Documento di ripresa per una sessione nuova (anche su un altro client Claude).
Le **decisioni di progetto** stanno in `CLAUDE.md` e non si ripetono qui: quello
è il documento normativo, questo è solo lo stato di avanzamento.

Trascrizione integrale della sessione che ha prodotto tutto questo:
`~/.claude/projects/-home-user-tastieraNoCC/be48d49b-2101-4ebd-8abf-314d9dd780ba.jsonl`

---

## I due repo

| | percorso locale | remote (privato) |
|---|---|---|
| core Rust + JNI | `/home/user/tastieraNoCC` | `franmuzi1/tastieraNoCC` |
| fork HeliBoard | `/home/user/heliboard` | `franmuzi1/tastieraNoCC-app` |

Nel fork, `upstream` punta a `HeliBorg/HeliBoard` con l'URL di push
deliberatamente sabotato (`DISABILITATO_non_si_pusha_su_HeliBoard`): serve solo
a tirare gli aggiornamenti, mai a spingere.

## Ambiente

- Rust c'è (rustup 1.96.0) ma `~/.cargo/bin` **non è nel PATH**. Ogni sessione
  deve fare `export PATH="$HOME/.cargo/bin:$PATH"` prima di qualunque `cargo`.
  Sono già state sprecate due volte delle risposte a dire "cargo non è
  installato": non lo è nel PATH, è installato.
- Presenti anche `cargo-fuzz`, `cargo-ndk`, `cross`, nightly, `gh`
  (autenticato come **franmuzi1**).

## Stato: core (`/home/user/tastieraNoCC`)

**Completo, nessun `todo!()` residuo.** 62 test verdi nel core, 6 nel crate JNI,
clippy pulito con i lint di `CLAUDE.md` attivi.

| file | righe | stato |
|---|---|---|
| `src/encoding.rs` | 302 | z-base-32, decodifica canonica stretta |
| `src/format.rs` | 944 | sentinel, header, AAD, `parse`, `looks_like_blob`, KAT |
| `src/keys.rs` | 257 | `Identity`, `PublicKey`, `Fingerprint`, trait `Keyring` |
| `src/baseline.rs` | 484 | X25519 + HKDF + XChaCha20-Poly1305, `seal`/`open` |
| `src/api.rs` | 719 | `Session`, `handle_incoming_text`, destinatario per app |
| `src/error.rs` | 42 | l'unico `Error` del crate |
| `jni/src/lib.rs` | 675 | punti d'ingresso `extern "system"`, tutti in `catch_unwind` |
| `jni/src/keyring.rs` | 306 | keyring concreto + serializzazione persistibile |

`fuzz/` ha tre target (`decode`, `parse`, `roundtrip`); ultima campagna ~136M
input; ultima verifica ~48M in tre minuti, nessun crash. Il corpus è in
`.gitignore`, gli artefatti di crash no.

Tutto committato e pushato.
Unica sporcizia nel working tree: `jni/target/` (artefatti di build, andrebbero
aggiunti a `.gitignore` — `jni/target/.rustc_info.json` risulta modificato).

## Stato: fork Android (`/home/user/heliboard`)

Branch `cipher`, remote `origin` = `franmuzi1/tastieraNoCC-app`.

**L'integrazione è completa e gira su dispositivo.** Il documento di riferimento
è `CIPHER.md` nel fork: contiene lo stato punto per punto, la procedura per
riprendere a freddo, e — soprattutto — le trappole d'ambiente che costano ore.
Leggilo prima di toccare qualunque cosa lì dentro.

In sintesi, tutto fatto e verificato: ciclo di vita della chiave (Keystore +
storage), tasti in toolbar, `DecryptActivity`, clipboard, identity card, UI
contatti con conflitto di etichetta, esclusione dalla cronologia clipboard, QR.

Verificato **sul dispositivo** (emulatore API 34): ciclo cifra/decifra completo,
conflitto di etichetta in tutti e tre gli esiti, percorsi negativi (blob
corrotto, troncato, versione futura, tier non supportato).

Resta scoperto solo il margine di versione Android: API 23 e API 21–22.

### Tre bug trovati solo eseguendo

Nessuno era visibile rileggendo il codice, e tutti e tre rendevano il sistema
inutilizzabile o pericoloso per una fetta grande di utenti. Se una sessione
futura è tentata di rimuovere queste difese, sappia cosa hanno pagato:

1. **`setUnlockedDeviceRequired(true)` fallisce alla *generazione* della chiave**
   su un dispositivo senza blocco schermo (`User ECDH key missing`). Da qui il
   terzo tentativo di fallback in `CipherKeystore.generate`.
2. **Uno schermo bloccato veniva diagnosticato come identità corrotta**, e
   l'unico rimedio offerto era distruggerla. Da qui `unreadableOrLocked`.
3. **Decifrare dalla toolbar attribuiva il destinatario alla tastiera stessa**,
   non all'app di chat: la regola "decifrare stabilisce il destinatario" non
   scattava mai per la via principale. Da qui l'extra col package dell'editor,
   onorato solo se a chiamare è la stessa app.

## Cosa resta da fare

1. `jni/target/` in `.gitignore` del core.
2. Attivare `todo = "deny"` in `[lints.clippy]` (la fase scheletro è finita).
3. Provare su API 23 e su API 21–22.
4. Scanner QR, se si accetta `CAMERA` a runtime. Oggi c'è solo la generazione.
5. Build riproducibile per F-Droid: mai affrontato.

## Trappole già pagate — non ripercorrerle

- `ACTION_PROCESS_TEXT`: **mai** `setResult` con dati. Restituire il plaintext
  lo consegna proprio all'app di chat da cui il progetto esiste per tenerlo
  lontano. È l'implementazione naturale dell'intent ed è la peggiore possibile.
- La riga a 30 bit della spec z-base-32 è **difettosa nella spec stessa**. Non
  usarla in nessuna forma. Dettagli e conferma indipendente in `CLAUDE.md`.
- `chacha20poly1305` non ha una feature `xchacha20poly1305`: `XChaCha20Poly1305`
  è esportato comunque.
- `parse` che ritorna `Ok` non dice nulla sull'integrità: il ciphertext è a
  lunghezza variabile, quindi un troncamento produce un messaggio ben formato.
  A intercettarlo è il tag Poly1305, ed è il posto giusto.
- `clippy::panic` non scatta su `todo!()`.
