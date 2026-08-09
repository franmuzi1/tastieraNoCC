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
        // promette: i flag derivano dalla presenza di sender_pub, e il
        // ciphertext non e' mai piu' corto del tag.
        if let ParsedBlob::Message(envelope) = blob {
            assert!(envelope.ciphertext.len() >= format::TAG_LEN);
            let atteso = if envelope.header.sender_pub.is_some() {
                format::Flags::SENDER_PUB
            } else {
                format::Flags::NONE
            };
            assert_eq!(envelope.header.flags(), atteso);
        }
    }
});
