//! Convenzioni di marshalling attraverso il confine wasm/JS.
//!
//! Nessuna dipendenza da `wasm-bindgen`: JS legge/scrive direttamente nella
//! memoria lineare del modulo (`instance.exports.memory.buffer`), con puntatori
//! e lunghezze come interi a 32 bit — sono le uniche primitive che il
//! `WebAssembly` "nudo" (senza glue) sa passare, e in un `JSContext` senza DOM
//! non e' garantito nient'altro (vedi la nota su `TextEncoder` nel piano).
//!
//! ## Convenzione unica per ogni funzione che produce byte
//!
//! Ogni funzione esportata che restituisce dati variabili ritorna un `u64`
//! impacchettato `(ptr << 32) | len`:
//! - successo: `ptr` punta a `len` byte nella memoria lineare, da leggere e poi
//!   liberare con [`mb_dealloc`](crate::mb_dealloc) (esportata da `lib.rs`);
//! - errore: `ptr == 0` (mai un puntatore valido — `Box::leak` non lo produce
//!   mai) e `len` e' il codice d'errore, vedi [`code_of`].
//!
//! Le funzioni che non producono byte (solo un esito) ritornano un `u32`: `0`
//! per successo, altrimenti lo stesso codice d'errore. Questo rende inutile un
//! "ultimo errore" globale: ogni chiamata porta il proprio esito, senza stato
//! condiviso fra chiamate concorrenti (che qui non esistono, ma e' comunque
//! piu' semplice da ragionare).
//!
//! ## Codici d'errore
//!
//! `1..=9` rispecchiano l'ordine di dichiarazione di
//! `keyboard_cipher_core::error::Error` (vedi [`code_of`]). `90..` sono
//! specifici di questo ponte, non del core — casi che qui hanno bisogno di un
//! codice ma che il core non modella come `Error` (RNG non seedato, blob
//! importato che non e' una identity card, nessuna sessione attiva, testo non
//! UTF-8).

use keyboard_cipher_core::error::Error;

pub const ERR_RNG_NOT_SEEDED: u32 = 90;
pub const ERR_NO_SESSION: u32 = 92;
pub const ERR_INVALID_UTF8: u32 = 93;
/// Input malformato lato chiamante (es. seed non da 32 byte) — un bug di JS,
/// non qualcosa che i dati dell'utente possano provocare.
pub const ERR_BAD_INPUT: u32 = 94;

/// Mappa `Error` a un codice stabile per JS. Mai distinguere sotto-cause di
/// `Crypto` con codici diversi: l'opacita' e' voluta (vedi `error.rs` del
/// core).
pub fn code_of(e: &Error) -> u32 {
    match e {
        Error::Format(_) => 1,
        Error::UnsupportedVersion(_) => 2,
        Error::NotOurBlob => 3,
        Error::Decode => 4,
        Error::Crypto => 5,
        Error::UnknownPeer => 6,
        Error::TierUnsupported => 7,
        Error::OwnMessage => 8,
        Error::Keyring => 9,
    }
}

/// Alloca `len` byte azzerati nella memoria lineare e ne ritorna il puntatore.
/// Usata da JS per scrivere un input (testo, chiave) prima di passarlo a una
/// funzione che lo legge come `(ptr, len)`.
pub fn alloc(len: usize) -> u32 {
    let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
    Box::leak(boxed).as_mut_ptr() as u32
}

/// Libera un buffer ottenuto da [`alloc`] o da un qualunque ritorno
/// impacchettato di successo. `ptr == 0` non fa nulla: e' il caso di un
/// risultato d'errore, che non ha byte da liberare.
///
/// # Safety
/// Il chiamante deve passare esattamente `(ptr, len)` come restituiti da
/// [`alloc`] o da una funzione che ha impacchettato un `Vec<u8>` di quella
/// lunghezza — mai un puntatore arbitrario, mai una lunghezza diversa da
/// quella originale. E' lo stesso genere di contratto che il crate `jni/`
/// documenta per il proprio confine FFI: qui non c'e' `unsafe_code` nel core,
/// ma questo crate satellite ne ha bisogno per lo stesso motivo.
pub unsafe fn dealloc(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    // SAFETY: vedi il contratto sopra. `slice_from_raw_parts_mut` costruisce
    // il puntatore fat direttamente, senza passare da un `&mut [u8]`
    // intermedio — che asserebbe garanzie (unicita', validita') non ancora
    // vere in questo punto preciso.
    unsafe {
        let slice_ptr: *mut [u8] = std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len as usize);
        drop(Box::from_raw(slice_ptr));
    }
}

/// Impacchetta `(ptr, len)` in un unico `u64`. I puntatori wasm32 sono a 32
/// bit, quindi entrano interi nella meta' alta.
fn pack(ptr: u32, len: u32) -> u64 {
    ((ptr as u64) << 32) | (len as u64)
}

/// Sposta un `Vec<u8>` nella memoria lineare persistente (fuori dal controllo
/// di Rust finche' JS non chiama [`dealloc`]) e ne ritorna il riferimento
/// impacchettato di successo.
pub fn pack_ok(data: Vec<u8>) -> u64 {
    let boxed = data.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::leak(boxed).as_mut_ptr() as u32;
    pack(ptr, len)
}

/// Impacchetta un esito d'errore: `ptr = 0`, cosi' il chiamante lo riconosce
/// senza dover distinguere altrimenti successo da fallimento.
pub fn pack_err(code: u32) -> u64 {
    pack(0, code)
}

pub fn pack_core_err(e: Error) -> u64 {
    pack_err(code_of(&e))
}

/// Legge un buffer scritto da JS. Non consuma memoria: chi l'ha scritto
/// (tipicamente via [`alloc`]) resta responsabile di liberarla con
/// [`dealloc`] dopo la chiamata.
///
/// # Safety
/// `ptr` deve puntare a almeno `len` byte validi nella memoria lineare del
/// modulo corrente.
pub unsafe fn read_slice<'a>(ptr: u32, len: u32) -> &'a [u8] {
    // SAFETY: vedi il contratto sopra.
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// Come [`read_slice`], ma richiede che i byte siano UTF-8 valido. Ritorna
/// `None` altrimenti — il chiamante lo traduce in [`ERR_INVALID_UTF8`].
///
/// # Safety
/// Stesso contratto di [`read_slice`].
pub unsafe fn read_str<'a>(ptr: u32, len: u32) -> Option<&'a str> {
    // SAFETY: vedi il contratto sopra.
    std::str::from_utf8(unsafe { read_slice(ptr, len) }).ok()
}

/// Legge esattamente 32 byte a `ptr` (una chiave, pubblica o privata).
///
/// # Safety
/// `ptr` deve puntare a almeno 32 byte validi.
pub unsafe fn read_key32<'a>(ptr: u32) -> &'a [u8; 32] {
    // SAFETY: vedi il contratto sopra.
    unsafe { &*(ptr as *const [u8; 32]) }
}
