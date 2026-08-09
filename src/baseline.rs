//! Tier baseline: cifratura stateless. L'unico tier implementato.
//!
//! Schema:
//! ```text
//! dh   = X25519(nostro_segreto, pubkey_controparte)   // statico-statico
//! key  = HKDF-SHA256(ikm = dh, salt = nonce, info = dominio || aad || recipient_pub)
//! ct   = XChaCha20-Poly1305(key, nonce, plaintext, aad)
//! ```
//!
//! Il segreto ECDH e' STATICO per ogni coppia di identita': la stessa `dh`
//! protegge tutti i messaggi fra quei due. Da qui tre vincoli non negoziabili:
//!
//!   1. Il nonce e' l'UNICA cosa che impedisce il riuso di keystream. 24 byte
//!      da CSPRNG, per ogni messaggio. Mai contatori, mai nonce corti, mai
//!      nonce derivati dal contenuto.
//!   2. Il nonce e' anche il salt della HKDF, cosi' la chiave AEAD effettiva
//!      cambia a ogni messaggio anche se `dh` non cambia mai.
//!   3. La `dh` grezza non si usa mai come chiave: passa sempre per la KDF.
//!
//! Nessuna forward secrecy: e' il baseline, e' una scelta consapevole, ed e' il
//! motivo per cui il tier FS esiste nel formato.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{self, Header, Kind, ParsedEnvelope, Tier, NONCE_LEN, TAG_LEN};
use crate::keys::{Identity, PublicKey};

/// Stringa di domain separation per la HKDF. Congelata: cambiarla cambia tutte
/// le chiavi derivate e rompe la compatibilita' con la versione 1.
const KDF_DOMAIN: &[u8] = b"keyboard-cipher/v1/baseline";

/// Lunghezza della chiave XChaCha20-Poly1305.
const AEAD_KEY_LEN: usize = 32;

/// Plaintext appena decifrato. Zeroize on drop, mai loggato, mai convertito in
/// `String` sul confine JNI (una `java.lang.String` non e' azzerabile).
///
/// L'assenza di `Debug`, `Display` e `Clone` e' deliberata.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Cifra `plaintext` per `recipient`, producendo la stringa finale pronta per
/// la chat (sentinel + z-base-32).
///
/// La pubkey del mittente finisce nell'header IN CHIARO: serve al destinatario
/// per il primo contatto TOFU. La correlabilita' che ne deriva e' accettata
/// (vedi threat model in CLAUDE.md).
///
/// L'RNG e' iniettato: serve per il nonce, e serve poterlo fissare nei KAT.
pub fn seal<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = Header {
        tier: Tier::Baseline,
        sender_pub: Some(sender.public()),
        nonce,
    };
    let aad = format::build_aad(Kind::Message, &header);

    let shared = sender.diffie_hellman(recipient)?;
    let key = derive_key(&shared, &nonce, &aad, recipient)?;

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok(format::serialize_message(&header, &ciphertext))
}

/// Inverte [`seal`].
///
/// `sender_pub` arriva dall'header quando il flag e' presente; il parametro e'
/// esplicito perche' un tier futuro lo ricavera' altrove e questa firma deve
/// reggere quella migrazione.
///
/// Ritorna [`Error::Crypto`] per qualunque fallimento AEAD, senza distinguerne
/// la causa: tag non valido, chiave sbagliata e nonce corrotto danno lo stesso
/// errore. Distinguerli darebbe a un attaccante un oracolo.
///
/// NOTA: `open` non consulta il keyring e non decide nulla sul TOFU. Decifrare
/// dice solo "chi possiede questa chiave privata ha scritto questo"; se quella
/// chiave sia quella attesa per il peer e' una domanda separata, che si pone
/// il livello [`crate::api`] dopo, con il fingerprint sotto gli occhi
/// dell'utente.
pub fn open(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    // Il rifiuto del tier riservato sta qui e non nel parser: "non lo so
    // leggere" e "non lo so eseguire" sono due cose diverse, e il chiamante
    // deve poterle distinguere per dire all'utente la cosa giusta.
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(Kind::Message, &parsed.header);
    let shared = recipient.diffie_hellman(sender_pub)?;
    let key = derive_key(&shared, &parsed.header.nonce, &aad, &recipient.public())?;

    let plaintext = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            XNonce::from_slice(&parsed.header.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok(Plaintext(Zeroizing::new(plaintext)))
}

/// Deriva la chiave AEAD dal segreto ECDH.
///
/// Il nonce fa da salt: con un segreto statico per coppia, e' questo che rende
/// la chiave effettiva diversa a ogni messaggio.
///
/// Nell'`info` entrano il dominio, l'AAD (che contiene gia' versione, kind,
/// tier, flag e pubkey del mittente) e la pubkey del DESTINATARIO. Quest'ultima
/// non e' nell'AAD e da sola non servirebbe — il segreto ECDH dipende gia' da
/// entrambe le chiavi — ma legarla esplicitamente costa zero byte sul filo e
/// non lascia il vincolo appeso a un ragionamento indiretto.
fn derive_key(
    shared: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let mut info = Vec::with_capacity(
        KDF_DOMAIN
            .len()
            .saturating_add(aad.len())
            .saturating_add(recipient.as_bytes().len()),
    );
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(aad);
    info.extend_from_slice(recipient.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
// Nei test `unwrap` e `panic!` sono il comportamento voluto.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::format::{ParsedBlob, SENTINEL};
    use hex_literal::hex;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn identita(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32]).unwrap()
    }

    /// Decifra una stringa prodotta da `seal`, prendendo il mittente
    /// dall'header come farebbe il chiamante vero.
    fn apri(destinatario: &Identity, testo: &str) -> Result<Plaintext> {
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(testo, &mut buf)? else {
            panic!("atteso un messaggio");
        };
        // Se il flag SENDER_PUB e' stato spento da una manomissione, il
        // mittente non c'e' e non c'e' niente da tentare: e' un errore, non un
        // motivo per andare in panic.
        let sender = parsed
            .header
            .sender_pub
            .clone()
            .ok_or(Error::Format("sender_pub assente"))?;
        open(destinatario, &sender, &parsed)
    }

    #[test]
    fn round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let messaggio = b"ciao, questo non lo legge la piattaforma";

        let testo = seal(&alice, &bob.public(), messaggio, &mut rng(9)).unwrap();
        assert!(testo.starts_with(SENTINEL));
        assert_eq!(apri(&bob, &testo).unwrap().as_bytes(), messaggio);
    }

    #[test]
    fn plaintext_vuoto_e_lungo() {
        let alice = identita(3);
        let bob = identita(4);

        for messaggio in [vec![], vec![0xAAu8; 4096]] {
            let testo = seal(&alice, &bob.public(), &messaggio, &mut rng(1)).unwrap();
            assert_eq!(apri(&bob, &testo).unwrap().as_bytes(), &messaggio[..]);
        }
    }

    /// Con segreto ECDH statico, due cifrature dello stesso testo devono
    /// comunque differire: se non differissero, il nonce non sarebbe fresco e
    /// il keystream verrebbe riusato.
    #[test]
    fn nonce_fresco_a_ogni_messaggio() {
        let alice = identita(5);
        let bob = identita(6);
        let mut r = rng(42);

        let uno = seal(&alice, &bob.public(), b"stesso testo", &mut r).unwrap();
        let due = seal(&alice, &bob.public(), b"stesso testo", &mut r).unwrap();
        assert_ne!(uno, due);
    }

    #[test]
    fn destinatario_sbagliato() {
        let alice = identita(7);
        let bob = identita(8);
        let carol = identita(9);

        let testo = seal(&alice, &bob.public(), b"per bob", &mut rng(3)).unwrap();
        assert!(matches!(apri(&carol, &testo), Err(Error::Crypto)));
    }

    #[test]
    fn mittente_dichiarato_sbagliato() {
        let alice = identita(10);
        let bob = identita(11);
        let mallory = identita(12);

        let testo = seal(&alice, &bob.public(), b"da alice", &mut rng(4)).unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&testo, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert!(matches!(
            open(&bob, &mallory.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Ogni singolo bit del blob e' protetto: cambiarne uno qualsiasi deve
    /// impedire la decifratura. Copre in un colpo solo ciphertext, tag, nonce,
    /// pubkey del mittente, flag e byte di tier.
    #[test]
    fn ogni_bit_flip_e_intercettato() {
        let alice = identita(13);
        let bob = identita(14);
        let testo = seal(&alice, &bob.public(), b"integro", &mut rng(5)).unwrap();

        let payload = testo.strip_prefix(SENTINEL).unwrap();
        let originale = crate::encoding::decode(payload).unwrap();

        for i in 0..originale.len() {
            for bit in 0..8u8 {
                let mut body = originale.clone();
                let Some(slot) = body.get_mut(i) else { continue };
                *slot ^= 1 << bit;
                if body == originale {
                    continue;
                }

                let mutato = format!("{SENTINEL}{}", crate::encoding::encode(&body));
                assert!(
                    apri(&bob, &mutato).is_err(),
                    "bit {bit} del byte {i} passato inosservato"
                );
            }
        }
    }

    /// Il test anti-downgrade. Portare il byte di tier da Baseline a
    /// ForwardSecret non deve produrre nulla di utile a un attaccante: il tier
    /// e' nell'AAD, quindi la manomissione e' rilevabile.
    ///
    /// Qui l'errore atteso e' `TierUnsupported` perche' `open` respinge il
    /// tier prima di arrivare all'AEAD. Il punto e' che NON decifra: se un
    /// giorno il tier FS venisse implementato, questo test dovra' continuare a
    /// fallire la decifratura, con `Crypto` invece che con `TierUnsupported`.
    #[test]
    fn downgrade_del_tier_rifiutato() {
        let alice = identita(15);
        let bob = identita(16);
        let testo = seal(&alice, &bob.public(), b"tier baseline", &mut rng(6)).unwrap();

        let payload = testo.strip_prefix(SENTINEL).unwrap();
        let mut body = crate::encoding::decode(payload).unwrap();
        // byte 2 = tier (dopo version e kind)
        *body.get_mut(2).unwrap() = Tier::ForwardSecret as u8;
        let manomesso = format!("{SENTINEL}{}", crate::encoding::encode(&body));

        assert!(matches!(apri(&bob, &manomesso), Err(Error::TierUnsupported)));
    }

    /// Una pubkey di ordine basso produce un segreto condiviso tutto zero,
    /// uguale per chiunque la usi: chi la riceve come `sender_pub` deriverebbe
    /// una chiave AEAD che qualsiasi altro puo' ricalcolare. Va rifiutata
    /// prima di derivare qualsiasi cosa.
    ///
    /// I sette punti sotto sono l'insieme completo dei punti di ordine piccolo
    /// della curva25519, nella forma usata dai test di libsodium.
    ///
    /// Nota per chi verra' dopo: `[0xFF; 32]` NON appartiene a questo insieme,
    /// per quanto sembri degenere. X25519 azzera il bit piu' alto della
    /// coordinata, quindi quei byte valgono 2^255-1, cioe' 18 modulo p: un
    /// punto di ordine pieno e perfettamente valido.
    #[test]
    fn pubkey_di_ordine_basso_rifiutata() {
        let alice = identita(17);
        let degeneri: [[u8; 32]; 7] = [
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];

        for bytes in degeneri {
            let peer = PublicKey::from_bytes(bytes);
            assert!(
                matches!(seal(&alice, &peer, b"x", &mut rng(7)), Err(Error::Crypto)),
                "pubkey degenere accettata: {bytes:02x?}"
            );
        }
    }

    /// Ancora di regressione: identita' e nonce fissi devono produrre sempre
    /// la stessa stringa. Se si rompe, e' cambiato il formato sul filo o la
    /// derivazione della chiave — cioe' la compatibilita' — non il codice.
    #[test]
    fn kat_baseline() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let bob = Identity::from_secret_bytes([0x22; 32]).unwrap();
        let testo = seal(&alice, &bob.public(), b"kat", &mut rng(0)).unwrap();
        assert_eq!(testo, KAT_BASELINE);
        assert_eq!(apri(&bob, KAT_BASELINE).unwrap().as_bytes(), b"kat");
    }

    const KAT_BASELINE: &str = "kc/yryyyym5j4ejzxu993nce3pnrybz4arqhpcjxwa69f3xy95wtrsmb739np5mtafpwdau5rnymiiqkwhgzwwm5wo3znoe55e43ubrw5w3bdyd9janhnsusijy4zkxmna";
}
