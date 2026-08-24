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
use keyboard_cipher_core::format::{self, Header, Origin, ParsedBlob, Tier, NONCE_LEN, SENTINEL};
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
        // Tutte e quattro le origini, cosi' il round-trip copre anche gli
        // schemi a mittente effimero: senza, il fuzzer proverebbe solo la
        // meta' del formato che esisteva prima della catena.
        origin: match controllo % 6 {
            0 => Origin::Assente,
            1 => Origin::Mittente(PublicKey::from_bytes(chiave)),
            2 => Origin::Effimera(PublicKey::from_bytes(chiave)),
            3 => Origin::EffimeraConPrekey(PublicKey::from_bytes(chiave)),
            4 => Origin::MittenteConEpoca(PublicKey::from_bytes(chiave)),
            _ => Origin::MittenteConPrekey(PublicKey::from_bytes(chiave)),
        },
        nonce,
    };

    // Ciphertext di lunghezza valida costruito dall'input.
    let mut ciphertext = vec![0u8; format::TAG_LEN];
    ciphertext.extend_from_slice(corpo);

    // Un bit del byte di controllo sceglie la forma di GRUPPO (version 2).
    // Senza, questo target — l'unico che costruisce blob validi e quindi
    // raggiunge i rami profondi — non scriveva mai la versione 2 ne' un blocco
    // di slot: il parser dei gruppi restava fuori dal fuzzing, mentre il
    // documento dichiarava ogni parser esercitato su input ostile.
    let gruppo = controllo & 0b100 != 0;
    let testo = if gruppo {
        // Il gruppo vuole la sola effimera e almeno due slot: si costruisce un
        // blocco valido per lunghezza, riempito con l'input. Il contenuto degli
        // slot non deve essere apribile — qui si prova il PARSER, non la
        // crittografia.
        let quanti = 2 + usize::from(controllo) % (format::MAX_SLOT - 1);
        let mut slots = vec![0u8; quanti * format::SLOT_LEN];
        for (slot, byte) in slots.iter_mut().zip(corpo.iter().cycle()) {
            *slot = *byte;
        }
        let header_gruppo = Header {
            tier: header.tier,
            origin: Origin::Effimera(PublicKey::from_bytes(chiave)),
            nonce,
        };
        match format::serialize_group(&header_gruppo, &slots, &ciphertext) {
            Ok(testo) => {
                let mut buf = Vec::new();
                match format::parse(&testo, &mut buf) {
                    Ok(ParsedBlob::Group(g)) => {
                        assert_eq!(g.header, header_gruppo);
                        assert_eq!(g.slot_count(), quanti);
                        assert_eq!(g.ciphertext, &ciphertext[..]);
                    }
                    // Il tier riservato si rifiuta dopo il parsing della forma:
                    // e' un esito legittimo, non un round-trip fallito.
                    Ok(_) | Err(_) if header_gruppo.tier != Tier::Baseline => {}
                    altro => {
                        panic!("un gruppo appena serializzato non ri-parsa: {:?}", altro.is_ok())
                    }
                }
                testo
            }
            Err(_) => return,
        }
    } else {
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
        testo
    };

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
