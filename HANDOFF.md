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

**Completo, nessun `todo!()` residuo.** 61 test verdi nel core, 6 nel crate JNI,
clippy pulito con i lint di `CLAUDE.md` attivi.

| file | righe | stato |
|---|---|---|
| `src/encoding.rs` | 302 | z-base-32, decodifica canonica stretta |
| `src/format.rs` | 921 | sentinel, header, AAD, `parse`, KAT congelati |
| `src/keys.rs` | 257 | `Identity`, `PublicKey`, `Fingerprint`, trait `Keyring` |
| `src/baseline.rs` | 484 | X25519 + HKDF + XChaCha20-Poly1305, `seal`/`open` |
| `src/api.rs` | 719 | `Session`, `handle_incoming_text`, destinatario per app |
| `src/error.rs` | 42 | l'unico `Error` del crate |
| `jni/src/lib.rs` | 675 | punti d'ingresso `extern "system"`, tutti in `catch_unwind` |
| `jni/src/keyring.rs` | 306 | keyring concreto + serializzazione persistibile |

`fuzz/` ha tre target (`decode`, `parse`, `roundtrip`); ultima campagna ~136M
input, nessun crash. Il corpus è in `.gitignore`, gli artefatti di crash no.

Tutto committato e pushato. Ultimo commit: `cfae0e0`.
Unica sporcizia nel working tree: `jni/target/` (artefatti di build, andrebbero
aggiunti a `.gitignore` — `jni/target/.rustc_info.json` risulta modificato).

## Stato: fork Android (`/home/user/heliboard`)

Due commit già fatti (`11f4c659`, `a8d0ce2b`): package `helium314.keyboard.cipher`,
voci di manifest, task Gradle che invoca `cargo ndk` e deposita i `.so` in
`src/main/jniLibs`.

**Non ancora committato** (lavoro dell'ultima parte di sessione):

- `CipherIdentity.kt` — ciclo di vita della chiave: generazione pigra,
  `CipherState` (`Ready`/`Locked`/`Unavailable`/`Unreadable`), `resetIdentity`.
  Regola centrale: **non rigenera mai l'identità da sola**, perché un guasto
  locale diventerebbe indistinguibile da un attacco agli occhi dei contatti.
- `CipherKeystore.kt` — chiave maestra AES in AndroidKeyStore,
  `setUnlockedDeviceRequired`, `wrap`/`unwrap` con AAD di dominio.
- `CipherStorage.kt` — i due file sotto `noBackupFilesDir` (non `filesDir`:
  HeliBoard ha `allowBackup="true"`, e la chiave maestra non è esportabile —
  un ripristino porterebbe due file illeggibili). Scrittura atomica con fsync.
- `CipherCore.kt`, `DecryptActivity.kt` modificati.
- `proguard-rules.pro` — `-keep` su `CipherCore` e `IncomingResult`: R8 non vede
  nessun lettore Kotlin dei campi scritti da JNI e li rimuoverebbe.

**Non è mai stato compilato**: manca la toolchain Android in questo ambiente.
La prima compilazione vera è il prossimo rischio serio.

## Cosa resta da fare

1. Committare i file Kotlin nuovi nel fork.
2. `jni/target/` in `.gitignore` del core.
3. Attivare `todo = "deny"` in `[lints.clippy]` (la fase scheletro è finita).
4. `DecryptActivity`: i `TODO` in cima sono reali e non cosmetici —
   `onNewIntent` con `launchMode=singleTask` (senza, la seconda decifratura
   viene ignorata e resta a schermo il plaintext precedente), e i messaggi
   distinti per ogni `CipherState`.
5. Prima di abilitare "copia il chiaro": escludere quel contenuto dalla
   cronologia clipboard del fork, altrimenti il plaintext ci finisce dentro e
   può essere persistito su disco.
6. Build reale dell'APK; poi il rischio build riproducibile per F-Droid, mai
   affrontato.
7. UI contatti (`ContactsActivity`) è ancora uno scheletro.

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
