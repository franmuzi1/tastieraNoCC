//! `encoding::decode` su input arbitrario.
//!
//! Due invarianti:
//!   1. non va mai in panic, qualunque cosa gli si dia;
//!   2. canonicita': se decodifica, ri-codificare il risultato deve
//!      riprodurre esattamente la stringa di partenza. Senza questa, lo
//!      stesso blob avrebbe piu' rappresentazioni testuali e due messaggi
//!      identici potrebbero non risultare uguali a un confronto per stringa.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(testo) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(byte) = keyboard_cipher_core::encoding::decode(testo) {
        assert_eq!(
            keyboard_cipher_core::encoding::encode(&byte),
            testo,
            "decodifica non canonica"
        );
    }
});
