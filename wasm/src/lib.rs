//! Ponte wasm verso `keyboard-cipher-core`, per l'esecuzione dentro Scriptable
//! (iOS). Stesso ruolo del crate `jni/` verso Android — vedi quel crate per il
//! pattern originale — ma con differenze dovute alla piattaforma:
//!
//! - **Nessun `catch_unwind`.** `jni/` avvolge ogni entry point perche' Android
//!   supporta l'unwinding e un panic Rust che attraversa un confine `extern`
//!   e' UB. Su `wasm32-unknown-unknown` non esiste unwinding: un panic
//!   abortisce l'istanza wasm (trap), punto — non c'e' niente da intercettare
//!   qui dentro. E' lo stesso motivo per cui il piano prescrive a JS di
//!   avvolgere ogni chiamata in `try/catch` e, su eccezione, scartare
//!   l'istanza e ricrearla da `config.json`: lo stato canonico vive sempre
//!   fuori da questo modulo.
//! - **RNG iniettato da JS, non da un `OsRng` nativo.** Vedi `rng.rs`.
//! - **Nessuna persistenza qui.** `wasm32-unknown-unknown` non ha filesystem:
//!   ogni esecuzione di Scriptable ri-idrata lo stato da `config.json`
//!   chiamando `mb_load_identity` + N × `mb_restore_peer`/
//!   `mb_restore_prekey_record` + `mb_finish_load`.
//!
//! ## Convenzioni di marshalling
//!
//! Vedi il modulo `marshal` per il protocollo (puntatori/lunghezze a 32 bit,
//! ritorni impacchettati a 64 bit) e `codec` per il layout di ogni struttura.
//! Nessun `wasm-bindgen`: JS chiama queste funzioni `extern "C"` direttamente
//! su `instance.exports`, leggendo/scrivendo `instance.exports.memory.buffer`.

mod codec;
mod keyring;
mod marshal;
mod rng;

use std::cell::RefCell;

use keyboard_cipher_core::api::Session;
use keyboard_cipher_core::keys::{Fingerprint, Identity, PublicKey};
use rand_core::RngCore;

use keyring::IosKeyring;

/// Costante fissa al posto del concetto Android di "app_package": su iOS non
/// esiste un'app da cui dedurre il destinatario, quindi non serve distinguere
/// per app — un solo slot, come fa gia' `cli/` con la propria costante `APP`.
const APP: &str = "ios-scriptable";

thread_local! {
    static SESSION: RefCell<Option<Session<IosKeyring>>> = const { RefCell::new(None) };
    /// Identita' + keyring in costruzione durante l'idratazione da
    /// `config.json`, prima che diventino una `Session` installata. Serve
    /// perche' `Session` non espone il proprio keyring in scrittura (lo
    /// mutano solo i suoi metodi, apposta — vedi il commento su
    /// `Session::keyring` nel core): per un ripristino "in blocco" bisogna
    /// costruire il keyring PRIMA di impacchettarlo in una `Session`.
    static PENDING: RefCell<Option<(Identity, IosKeyring)>> = const { RefCell::new(None) };
}

fn install_session(identity: Identity, keyring: IosKeyring) {
    SESSION.with(|cell| *cell.borrow_mut() = Some(Session::new(identity, keyring)));
}

fn with_session<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Session<IosKeyring>) -> R,
{
    SESSION.with(|cell| cell.borrow_mut().as_mut().map(f))
}

fn start_pending(identity: Identity) {
    PENDING.with(|cell| *cell.borrow_mut() = Some((identity, IosKeyring::default())));
}

fn with_pending_keyring<F>(f: F) -> Option<()>
where
    F: FnOnce(&mut IosKeyring),
{
    PENDING.with(|cell| match cell.borrow_mut().as_mut() {
        Some((_, keyring)) => {
            f(keyring);
            Some(())
        }
        None => None,
    })
}

fn finish_pending() -> Option<()> {
    match PENDING.with(|cell| cell.borrow_mut().take()) {
        Some((identity, keyring)) => {
            install_session(identity, keyring);
            Some(())
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Allocatore
// ---------------------------------------------------------------------------

/// Alloca `len` byte nella memoria lineare, per un input che JS scrivera'
/// prima di passarlo a un'altra funzione.
#[no_mangle]
pub extern "C" fn mb_alloc(len: u32) -> u32 {
    marshal::alloc(len as usize)
}

/// Libera un buffer ottenuto da [`mb_alloc`] o da un ritorno impacchettato di
/// successo. Va chiamata anche sugli input dopo l'uso, non solo sugli output.
#[no_mangle]
pub extern "C" fn mb_dealloc(ptr: u32, len: u32) {
    // SAFETY: contratto documentato su `marshal::dealloc` — vale per ogni
    // (ptr,len) restituito da questo modulo, mai per puntatori arbitrari.
    unsafe { marshal::dealloc(ptr, len) };
}

// ---------------------------------------------------------------------------
// RNG
// ---------------------------------------------------------------------------

/// Installa 32 byte di vera entropia (dal bridge WebView lato JS) come seme
/// per la prossima operazione che consuma RNG. Va chiamata prima di OGNI
/// operazione simile — non una volta sola — perche' [`rng::take`] consuma il
/// seme e non ne resta uno di riserva.
#[no_mangle]
pub extern "C" fn mb_seed_rng(ptr: u32, len: u32) -> u32 {
    if len != 32 {
        return marshal::ERR_BAD_INPUT;
    }
    // SAFETY: `len == 32` verificato sopra.
    let bytes = unsafe { marshal::read_key32(ptr) };
    rng::seed(*bytes);
    0
}

// ---------------------------------------------------------------------------
// Identita' / ciclo di vita della sessione
// ---------------------------------------------------------------------------

/// Genera una nuova identita' e installa subito una sessione con un keyring
/// vuoto (un'identita' nuova non ha contatti da ripristinare). Consuma RNG.
///
/// Ritorna 64 byte: 32 di segreto + 32 di pubblica. **Il segreto esce in
/// chiaro apposta** — e' l'unico modo per JS di poterlo persistere in
/// `config.json` — esattamente come fa `nativeGenerateSecret` in `jni/`.
#[no_mangle]
pub extern "C" fn mb_generate_identity() -> u64 {
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let identity = match Identity::from_secret_bytes(secret) {
        Ok(i) => i,
        Err(e) => return marshal::pack_core_err(e),
    };
    let public = *identity.public().as_bytes();
    install_session(identity, IosKeyring::default());

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&secret);
    out.extend_from_slice(&public);
    marshal::pack_ok(out)
}

/// Comincia il ripristino di un'identita' gia' persistita: da qui la sessione
/// NON e' ancora installata, va completata con N × [`mb_restore_peer`] /
/// [`mb_restore_prekey_record`] e infine [`mb_finish_load`].
///
/// Ritorna la chiave pubblica (32 byte) su successo.
#[no_mangle]
pub extern "C" fn mb_load_identity(secret_ptr: u32) -> u64 {
    // SAFETY: il chiamante garantisce 32 byte validi a `secret_ptr`.
    let bytes = unsafe { marshal::read_key32(secret_ptr) };
    let identity = match Identity::from_secret_bytes(*bytes) {
        Ok(i) => i,
        Err(e) => return marshal::pack_core_err(e),
    };
    let public = identity.public().as_bytes().to_vec();
    start_pending(identity);
    marshal::pack_ok(public)
}

/// Ripristina un contatto durante l'idratazione. Va chiamata dopo
/// [`mb_load_identity`] e prima di [`mb_finish_load`].
#[no_mangle]
pub extern "C" fn mb_restore_peer(ptr: u32, len: u32) -> u32 {
    // SAFETY: il chiamante garantisce `len` byte validi a `ptr`.
    let buf = unsafe { marshal::read_slice(ptr, len) };
    let Some(record) = codec::decode_peer_record(buf) else {
        return marshal::ERR_BAD_INPUT;
    };
    match with_pending_keyring(|kr| kr.restore_peer(record)) {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

/// Ripristina lo stato di catena/epoca per un contatto durante l'idratazione.
/// Stessa finestra temporale di [`mb_restore_peer`].
#[no_mangle]
pub extern "C" fn mb_restore_prekey_record(ptr: u32, len: u32) -> u32 {
    // SAFETY: il chiamante garantisce `len` byte validi a `ptr`.
    let buf = unsafe { marshal::read_slice(ptr, len) };
    let Some(record) = codec::decode_prekey_record(buf) else {
        return marshal::ERR_BAD_INPUT;
    };
    match with_pending_keyring(|kr| kr.restore_prekey(record)) {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

/// Chiude l'idratazione: installa la sessione costruita da
/// [`mb_load_identity`] + i ripristini intermedi. Da qui in poi le altre
/// funzioni (encrypt/decrypt/...) diventano utilizzabili.
#[no_mangle]
pub extern "C" fn mb_finish_load() -> u32 {
    match finish_pending() {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

// ---------------------------------------------------------------------------
// Lettura per la persistenza (riscrivere config.json)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mb_dump_peers_count() -> u32 {
    with_session(|s| u32::try_from(s.keyring().peer_records().len()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn mb_dump_peer_at(i: u32) -> u64 {
    match with_session(|s| {
        s.keyring()
            .peer_records()
            .get(i as usize)
            .map(codec::encode_peer_record)
    }) {
        Some(Some(bytes)) => marshal::pack_ok(bytes),
        Some(None) => marshal::pack_err(marshal::ERR_BAD_INPUT),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_dump_prekey_count() -> u32 {
    with_session(|s| u32::try_from(s.keyring().prekey_dump().len()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn mb_dump_prekey_at(i: u32) -> u64 {
    match with_session(|s| {
        s.keyring()
            .prekey_dump()
            .get(i as usize)
            .map(codec::encode_prekey_record)
    }) {
        Some(Some(bytes)) => marshal::pack_ok(bytes),
        Some(None) => marshal::pack_err(marshal::ERR_BAD_INPUT),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

// ---------------------------------------------------------------------------
// Identita' da mostrare / verificare
// ---------------------------------------------------------------------------

/// Blob di presentazione (`kc/...`) per il contatto Android. Consuma RNG (il
/// core lo usa per il riempimento anti-fingerprinting-di-lunghezza).
#[no_mangle]
pub extern "C" fn mb_identity_card() -> u64 {
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.identity_card(&mut rng)) {
        Some(card) => marshal::pack_ok(card.into_bytes()),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_my_fingerprint() -> u64 {
    match with_session(|s| s.my_fingerprint().display()) {
        Some(fp) => marshal::pack_ok(fp.into_bytes()),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Fingerprint di una chiave qualsiasi, non solo la propria — serve per
/// mostrare quella di un contatto appena importato. Non richiede una sessione
/// attiva: e' pura funzione della chiave.
#[no_mangle]
pub extern "C" fn mb_fingerprint_of(peer_ptr: u32) -> u64 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    marshal::pack_ok(codec::encode_fingerprint(&Fingerprint::of(&peer)))
}

// ---------------------------------------------------------------------------
// Messaggistica
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mb_set_current_peer(peer_ptr: u32) -> u32 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    match with_session(|s| s.set_current_peer(APP, &peer)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

/// Il destinatario corrente, se c'e' — per mostrarlo in UI prima di cifrare.
///
/// A differenza delle altre funzioni "producing", qui l'assenza di
/// destinatario NON e' un errore: `Session::current_peer` (`src/api.rs:1362`)
/// ritorna un `Option`, non un `Result`. Si usa `(ptr=0, len=0)` per
/// distinguerlo da un vero errore, che avrebbe sempre `len > 0` (i codici
/// stanno tutti in `1..=9` o `90..`, mai `0`).
#[no_mangle]
pub extern "C" fn mb_current_peer() -> u64 {
    match with_session(|s| s.current_peer(APP).cloned()) {
        Some(Some(peer)) => marshal::pack_ok(peer.as_bytes().to_vec()),
        Some(None) => 0, // pack(0, 0): nessun destinatario, non e' un errore.
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Cifra "a epoca" (decisione J, forward secrecy disattivata: `effimero =
/// false`) verso il destinatario corrente. Consuma RNG.
#[no_mangle]
pub extern "C" fn mb_encrypt(text_ptr: u32, text_len: u32, now_unix: i64) -> u64 {
    // SAFETY: il chiamante garantisce `text_len` byte validi a `text_ptr`.
    let plaintext = unsafe { marshal::read_slice(text_ptr, text_len) };
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.encrypt_for_app_with(APP, plaintext, now_unix, &mut rng, false)) {
        Some(Ok(blob)) => marshal::pack_ok(blob.into_bytes()),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Riconosce e apre un testo in arrivo — messaggio, rogo, o **identity card**:
/// il core instrada tutti e tre dallo stesso ingresso, quindi non serve una
/// funzione separata per importare un contatto. Il tag nel risultato (vedi
/// `codec::TAG_*`) dice di quale dei cinque casi si tratta.
#[no_mangle]
pub extern "C" fn mb_decrypt(text_ptr: u32, text_len: u32, now_unix: i64) -> u64 {
    // SAFETY: il chiamante garantisce `text_len` byte validi a `text_ptr`.
    let text = match unsafe { marshal::read_str(text_ptr, text_len) } {
        Some(t) => t,
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    match with_session(|s| s.handle_incoming_text(APP, text, now_unix)) {
        Some(Ok(item)) => marshal::pack_ok(codec::encode_incoming_item(&item)),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Rogo (decisione J): produce il blob di richiesta e distrugge subito le
/// chiavi locali per quel contatto. Consuma RNG.
#[no_mangle]
pub extern "C" fn mb_burn_conversation(peer_ptr: u32, now_unix: i64) -> u64 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.burn_conversation(&peer, now_unix, &mut rng)) {
        Some(Ok(blob)) => marshal::pack_ok(blob.into_bytes()),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_assign_label(peer_ptr: u32, label_ptr: u32, label_len: u32) -> u64 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let peer_bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*peer_bytes);
    // SAFETY: il chiamante garantisce `label_len` byte validi a `label_ptr`.
    let label = match unsafe { marshal::read_str(label_ptr, label_len) } {
        Some(l) => l,
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    match with_session(|s| s.assign_label(&peer, label)) {
        Some(Ok(outcome)) => marshal::pack_ok(codec::encode_label_outcome(&outcome)),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Conferma un cambio chiave dopo un `LabelOutcome::Conflict` mostrato
/// all'utente. Mai automatico.
#[no_mangle]
pub extern "C" fn mb_confirm_key_change(old_ptr: u32, new_ptr: u32, now_unix: i64) -> u32 {
    // SAFETY: il chiamante garantisce 32 byte validi a ciascun puntatore.
    let old = PublicKey::from_bytes(*unsafe { marshal::read_key32(old_ptr) });
    let new = PublicKey::from_bytes(*unsafe { marshal::read_key32(new_ptr) });
    match with_session(|s| s.confirm_key_change(&old, &new, now_unix)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

/// Dimentica un contatto: toglie il pin TOFU e le chiavi temporanee verso di
/// lui, e smette di usarlo come destinatario corrente. `Session::forget_peer`
/// (`src/api.rs:1177`) fa gia' entrambe le cose insieme apposta — dimenticare
/// solo dal keyring lascerebbe il destinatario corrente puntato a una chiave
/// non piu' fissata, un guasto silenzioso che si scoprirebbe solo dall'altro
/// lato. L'esito booleano ("c'era?") non serve a JS, che chiama sempre su un
/// contatto gia' scelto da un elenco: si scarta, come per gli altri stati
/// "solo esito".
#[no_mangle]
pub extern "C" fn mb_forget_peer(peer_ptr: u32) -> u32 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let peer = PublicKey::from_bytes(*unsafe { marshal::read_key32(peer_ptr) });
    match with_session(|s| s.forget_peer(&peer)) {
        Some(Ok(_)) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

#[no_mangle]
pub extern "C" fn mb_mark_verified(peer_ptr: u32) -> u32 {
    // SAFETY: il chiamante garantisce 32 byte validi a `peer_ptr`.
    let peer = PublicKey::from_bytes(*unsafe { marshal::read_key32(peer_ptr) });
    match with_session(|s| s.mark_verified(&peer)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

#[cfg(test)]
// Stessa deroga del core (`src/keys.rs`): in un test un panic e' il modo in
// cui si segnala il fallimento, non un difetto da vietare. Qui serve anche
// `expect_used` (i messaggi rendono leggibile quale asserzione e' fallita) e
// `arithmetic_side_effects` (le somme sui timestamp di prova non rischiano
// mai un overflow reale, ma il lint non lo sa distinguere).
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
