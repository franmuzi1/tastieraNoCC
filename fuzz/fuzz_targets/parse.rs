//! `format::parse` su testo arbitrario.
//!
//! Il parser e' il pezzo esposto a input completamente ostile: riceve
//! qualunque cosa passi dalla clipboard. Non deve mai andare in panic, ne'
//! con il sentinel giusto ne' senza.
//!
//! Metà degli input viene prefissata col sentinel, altrimenti il fuzzer
//! passerebbe quasi tutto il tempo sul ramo NotOurBlob senza mai entrare nel
//! parsing vero.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keyboard_cipher_core::format::{self, ParsedBlob, SENTINEL};

fuzz_target!(|data: &[u8]| {
    let Some((selettore, resto)) = data.split_first() else {
        return;
    };
    let Ok(testo) = std::str::from_utf8(resto) else {
        return;
    };

    let candidato = if selettore % 2 == 0 {
        format!("{SENTINEL}{testo}")
    } else {
        testo.to_owned()
    };

    let mut buf = Vec::new();
    if let Ok(blob) = format::parse(&candidato, &mut buf) {
        // Se parsa, i campi devono essere coerenti con cio' che il formato
        // promette: i flag sono una FUNZIONE dell'origine, non un campo, e il
        // ciphertext non e' mai piu' corto del tag.
        if let ParsedBlob::Message(envelope) = blob {
            assert!(envelope.ciphertext.len() >= format::TAG_LEN);
            let origine = &envelope.header.origin;
            // Le combinazioni impossibili non devono uscire da `parse`:
            // "effimera senza chiave" e "prekey senza effimera" sono header
            // incoerenti, e un header incoerente fallisce l'autenticazione in
            // modo opaco — il modo piu' difficile da diagnosticare.
            assert!(!(origine.is_ephemeral() && origine.key().is_none()));
            assert!(!(origine.uses_prekey() && !origine.is_ephemeral()));
            // I flag devono ricostruirsi dall'origine: e' l'invariante da cui
            // dipende il fatto che non esista una seconda fonte di verita'.
            let f = envelope.header.flags().0;
            assert_eq!(f & 0b1 != 0, origine.key().is_some());
            assert_eq!(f & 0b10 != 0, origine.is_ephemeral());
            assert_eq!(f & 0b100 != 0, origine.uses_prekey());
        }
    }
});
