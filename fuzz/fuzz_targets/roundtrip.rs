//! Round-trip strutturato: costruisce blob VALIDI da input arbitrario, poi li
//! corrompe.
//!
//! I due target precedenti raggiungono a fatica un blob ben formato, perche'
//! il fuzzer dovrebbe indovinare l'encoding. Qui i blob validi si producono
//! per costruzione, cosi' il fuzzing lavora sui rami profondi del parser
//! invece che sui rifiuti immediati.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keyboard_cipher_core::encoding;
use keyboard_cipher_core::format::{self, Header, ParsedBlob, Tier, NONCE_LEN, SENTINEL};
use keyboard_cipher_core::keys::{PublicKey, KEY_LEN};

fuzz_target!(|data: &[u8]| {
    let Some((controllo, corpo)) = data.split_first() else {
        return;
    };
    let controllo = *controllo;

    let mut chiave = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    for (slot, byte) in chiave.iter_mut().zip(corpo.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in nonce.iter_mut().zip(corpo.iter().rev()) {
        *slot = *byte;
    }

    let header = Header {
        tier: if controllo & 0b10 == 0 {
            Tier::Baseline
        } else {
            Tier::ForwardSecret
        },
        sender_pub: if controllo & 0b1 == 0 {
            Some(PublicKey::from_bytes(chiave))
        } else {
            None
        },
        nonce,
    };

    // Ciphertext di lunghezza valida costruito dall'input.
    let mut ciphertext = vec![0u8; format::TAG_LEN];
    ciphertext.extend_from_slice(corpo);
    let testo = format::serialize_message(&header, &ciphertext);

    // Un blob appena prodotto deve sempre ri-parsare identico.
    let mut buf = Vec::new();
    match format::parse(&testo, &mut buf) {
        Ok(ParsedBlob::Message(envelope)) => {
            assert_eq!(envelope.header, header);
            assert_eq!(envelope.ciphertext, &ciphertext[..]);
        }
        altro => panic!("un blob appena serializzato non ri-parsa: {:?}", altro.is_ok()),
    }

    // Ora lo si corrompe: qualunque mutazione, parse non deve andare in panic.
    let payload = testo.strip_prefix(SENTINEL).unwrap_or(&testo);
    if let Ok(mut body) = encoding::decode(payload) {
        let indice = usize::from(controllo) % body.len().max(1);
        if let Some(slot) = body.get_mut(indice) {
            *slot ^= controllo | 1;
        }
        let mutato = format!("{SENTINEL}{}", encoding::encode(&body));
        let mut buf2 = Vec::new();
        let _ = format::parse(&mutato, &mut buf2);

        // E anche troncato a ogni lunghezza.
        for taglio in [1usize, 3, 7, 16, 40] {
            if let Some(corto) = body.get(..body.len().saturating_sub(taglio)) {
                let testo = format!("{SENTINEL}{}", encoding::encode(corto));
                let mut buf3 = Vec::new();
                let _ = format::parse(&testo, &mut buf3);
            }
        }
    }
});
