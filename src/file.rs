//! File cifrati: foto, note vocali, qualunque cosa (decisione G).
//!
//! ## Perche' non passa dal testo
//!
//! z-base-32 gonfia di 1,6x: una foto da 500 KB diventerebbe 800 KB di
//! caratteri, fuori scala per qualunque campo di chat. Un file cifrato viaggia
//! quindi come **allegato binario**, consegnato alla chat dallo share sheet e
//! non dalla tastiera — che un file non lo puo' allegare.
//!
//! ## Cosa sta dentro il cifrato
//!
//! Nome e tipo del file stanno **dentro**, non nel nome dell'allegato:
//!
//! ```text
//! timestamp(8, LE) | nome_len(2, LE) | nome | mime_len(2, LE) | mime | contenuto
//! ```
//!
//! Il timestamp lo mette [`crate::baseline`], come per i messaggi. Il resto e'
//! di questo modulo.
//!
//! Se il nome viaggiasse in chiaro, l'allegato si chiamerebbe
//! `IMG_20260810_compleanno-di-marco.jpg.kc` e racconterebbe alla piattaforma
//! quasi tutto quello che la cifratura serve a non dirle. Fuori resta un nome
//! neutro con estensione `.kc` (decisione G3): dichiara che e' un file cifrato,
//! e nient'altro.
//!
//! ## Residuo accettato, e non piccolo
//!
//! Un allegato che non si apre con niente e' un marcatore molto piu' forte del
//! blob di testo, che si nasconde in mezzo a milioni di messaggi. E la
//! **dimensione** dice molto piu' della lunghezza di un testo. Accettato con la
//! chiusura di G1, perche' l'alternativa osservata e' peggiore: senza questa
//! via le foto si mandano lo stesso, in chiaro, nella stessa conversazione.

use zeroize::Zeroizing;

use crate::baseline;
use crate::error::{Error, Result};
use crate::format::{self, ParsedEnvelope};
use crate::keys::{Identity, PublicKey};

/// Tetto alla lunghezza di nome e tipo. Sono metadati, non contenuto: oltre
/// questo sono un canale per infilare dati in un campo che nessuno guarda.
const MAX_META_LEN: usize = 512;

/// Quanto occupano i due campi di lunghezza.
const LEN_FIELD: usize = 2;

/// Nome e tipo di un file, dalla parte cifrata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMeta {
    /// Nome originale. **Da trattare come ostile**: arriva da chi ha mandato il
    /// file, e chi lo salva deve ripulirlo — un nome puo' contenere `../`, un
    /// separatore di percorso, o cinquecento caratteri.
    pub name: String,
    /// Tipo MIME dichiarato dal mittente. Serve a scegliere come mostrarlo, e
    /// vale esattamente quanto la parola di chi l'ha scritto: un `image/jpeg`
    /// non garantisce che dentro ci sia un'immagine.
    pub mime: String,
}

/// Un file decifrato.
pub struct DecryptedFile {
    pub meta: FileMeta,
    /// Azzerato alla distruzione, come ogni chiaro in questo crate.
    pub content: Zeroizing<Vec<u8>>,
    /// Autenticato ma **non verificabile**: nessuno puo' dimostrare che
    /// l'orologio del mittente fosse giusto. Si mostra, non ci si decide nulla.
    pub sent_at_unix: i64,
}

/// Cifra un file per `recipient`.
///
/// Il destinatario e' esplicito e non dedotto (decisione G4): questo percorso
/// parte da una schermata, non dalla tastiera, quindi non esiste il contesto
/// dell'app da cui indovinarlo. Ed e' anche il verso giusto in cui sbagliare —
/// mandare un file alla persona sbagliata e' irreversibile.
pub fn seal_file<R: rand_core::RngCore + rand_core::CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    meta: &FileMeta,
    content: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let name = meta.name.as_bytes();
    let mime = meta.mime.as_bytes();
    if name.len() > MAX_META_LEN || mime.len() > MAX_META_LEN {
        return Err(Error::Format("nome o tipo del file troppo lunghi"));
    }
    let name_len = u16::try_from(name.len()).map_err(|_| Error::Format("nome troppo lungo"))?;
    let mime_len = u16::try_from(mime.len()).map_err(|_| Error::Format("tipo troppo lungo"))?;

    let capacity = LEN_FIELD
        .saturating_mul(2)
        .saturating_add(name.len())
        .saturating_add(mime.len())
        .saturating_add(content.len());
    let mut inner = Zeroizing::new(Vec::with_capacity(capacity));
    inner.extend_from_slice(&name_len.to_le_bytes());
    inner.extend_from_slice(name);
    inner.extend_from_slice(&mime_len.to_le_bytes());
    inner.extend_from_slice(mime);
    inner.extend_from_slice(content);

    baseline::seal_file(sender, recipient, &inner, now_unix, rng)
}

/// Come [`seal_file`], ma con la catena di forward secrecy.
///
/// `prekey_destinatario` e' l'ultima chiave temporanea che quel contatto ci ha
/// mandato: se c'e' si ottiene la forward secrecy piena, se manca si ripiega
/// sul mittente effimero — che e' comunque meglio dello statico-statico, e fa
/// **partire** la catena portando la nostra.
///
/// Gli allegati passano dallo stesso stato dei messaggi, non da uno loro: sono
/// la stessa conversazione con la stessa persona, e due catene separate
/// significherebbero due volte le chiavi da conservare e due volte le occasioni
/// di non buttarle.
#[allow(clippy::too_many_arguments)]
pub fn seal_file_forward<R: rand_core::RngCore + rand_core::CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: Option<&PublicKey>,
    mia_prekey: &PublicKey,
    meta: &FileMeta,
    content: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let inner = componi(meta, content)?;
    match prekey_destinatario {
        Some(loro) => baseline::seal_file_forward(
            sender, recipient, loro, mia_prekey, &inner, now_unix, rng,
        ),
        None => {
            baseline::seal_file_ephemeral(sender, recipient, mia_prekey, &inner, now_unix, rng)
        }
    }
}

/// Nome, tipo e contenuto in un blocco solo, con i controlli di lunghezza.
fn componi(meta: &FileMeta, content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let name = meta.name.as_bytes();
    let mime = meta.mime.as_bytes();
    if name.len() > MAX_META_LEN || mime.len() > MAX_META_LEN {
        return Err(Error::Format("nome o tipo del file troppo lunghi"));
    }
    let name_len = u16::try_from(name.len()).map_err(|_| Error::Format("nome troppo lungo"))?;
    let mime_len = u16::try_from(mime.len()).map_err(|_| Error::Format("tipo troppo lungo"))?;
    let capacity = LEN_FIELD
        .saturating_mul(2)
        .saturating_add(name.len())
        .saturating_add(mime.len())
        .saturating_add(content.len());
    let mut inner = Zeroizing::new(Vec::with_capacity(capacity));
    inner.extend_from_slice(&name_len.to_le_bytes());
    inner.extend_from_slice(name);
    inner.extend_from_slice(&mime_len.to_le_bytes());
    inner.extend_from_slice(mime);
    inner.extend_from_slice(content);
    Ok(inner)
}

/// Legge l'involucro di un allegato senza decifrarlo.
///
/// Serve a chi riceve per sapere **da chi** arriva prima di poterlo aprire: la
/// pubkey del mittente sta nell'header in chiaro, come nei messaggi.
pub fn parse_file(bytes: &[u8]) -> Result<ParsedEnvelope<'_>> {
    format::parse_file(bytes)
}

/// Inverte [`seal_file`].
pub fn open_file(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<DecryptedFile> {
    monta(baseline::open_file(recipient, sender_pub, parsed)?)
}

/// Apre un allegato a mittente effimero **supponendo** che l'abbia mandato
/// `candidato`. Ritorna anche la sua prossima chiave temporanea.
pub fn open_file_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, DecryptedFile)> {
    let (prekey, plaintext) = baseline::open_file_ephemeral(recipient, candidato, parsed)?;
    Ok((prekey, monta(plaintext)?))
}

/// Apre un allegato a forward secrecy piena con una nostra chiave temporanea.
pub fn open_file_forward(
    mia_prekey: &crate::keys::EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, DecryptedFile)> {
    let (prekey, plaintext) =
        baseline::open_file_forward(mia_prekey, candidato, destinatario, parsed)?;
    Ok((prekey, monta(plaintext)?))
}

/// Riapre un allegato **che abbiamo mandato noi**, provando `recipient` come
/// destinatario. Vale solo senza catena, come per i messaggi.
pub fn open_file_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<DecryptedFile> {
    monta(baseline::open_file_as_sender(sender, recipient, parsed)?)
}

fn monta(plaintext: crate::baseline::Plaintext) -> Result<DecryptedFile> {
    let (meta, content) = split_inner(plaintext.as_bytes())?;
    Ok(DecryptedFile {
        meta,
        content: Zeroizing::new(content),
        sent_at_unix: plaintext.sent_at_unix(),
    })
}

/// Separa metadati e contenuto.
///
/// Tutto quello che si legge qui e' gia' **autenticato** — l'AEAD ha detto di
/// si' — quindi non puo' essere stato manomesso in transito. Puo' benissimo
/// essere assurdo lo stesso, perche' il mittente puo' aver scritto qualunque
/// cosa: per questo ogni lunghezza viene controllata contro cio' che resta,
/// invece di essere creduta.
fn split_inner(inner: &[u8]) -> Result<(FileMeta, Vec<u8>)> {
    let (name, rest) = take_field(inner)?;
    let (mime, content) = take_field(rest)?;
    let meta = FileMeta {
        name: String::from_utf8(name).map_err(|_| Error::Format("nome non e' UTF-8"))?,
        mime: String::from_utf8(mime).map_err(|_| Error::Format("tipo non e' UTF-8"))?,
    };
    Ok((meta, content.to_vec()))
}

/// `split_at` e non `split_at_checked`: quest'ultima e' stabile da Rust 1.80 e
/// il crate dichiara 1.75. La lunghezza viene controllata **prima** di ogni
/// taglio, quindi nessuno dei due puo' andare fuori intervallo.
fn take_field(bytes: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if bytes.len() < LEN_FIELD {
        return Err(Error::Format("allegato troncato"));
    }
    let (len_bytes, rest) = bytes.split_at(LEN_FIELD);
    let len = usize::from(u16::from_le_bytes([
        *len_bytes.first().ok_or(Error::Format("allegato troncato"))?,
        *len_bytes.get(1).ok_or(Error::Format("allegato troncato"))?,
    ]));
    if len > MAX_META_LEN {
        return Err(Error::Format("metadato del file troppo lungo"));
    }
    if rest.len() < len {
        return Err(Error::Format("allegato troncato"));
    }
    let (field, tail) = rest.split_at(len);
    Ok((field.to_vec(), tail))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    fn identita(seed: u8) -> Identity {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([seed; 32]);
        Identity::generate(&mut rng).unwrap()
    }

    fn meta() -> FileMeta {
        FileMeta {
            name: "compleanno di marco.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        }
    }

    #[test]
    fn round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let content = vec![0xABu8; 5000];

        let blob = seal_file(&alice, &bob.public(), &meta(), &content, 1_700_000_000, &mut rng)
            .unwrap();
        let parsed = parse_file(&blob).unwrap();
        let out = open_file(&bob, &alice.public(), &parsed).unwrap();

        assert_eq!(out.meta, meta());
        assert_eq!(out.content.as_slice(), content.as_slice());
        assert_eq!(out.sent_at_unix, 1_700_000_000);
    }

    /// Il nome viaggia dentro il cifrato: fuori non se ne deve vedere traccia.
    #[test]
    fn il_nome_non_e_in_chiaro() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"x", 1, &mut rng).unwrap();
        assert!(!blob
            .windows(6)
            .any(|w| w == b"marco." || w == b"image/"));
    }

    /// `kind` sta nell'AAD: un file non si apre come messaggio nemmeno con la
    /// chiave giusta, e un messaggio non si apre come file.
    #[test]
    fn un_file_non_e_un_messaggio() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        let parsed = parse_file(&blob).unwrap();
        assert!(matches!(
            baseline::open(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Un allegato che non e' nostro non deve somigliare a un errore di
    /// decifratura: e' un file di un altro tipo, e si dice cosi'.
    #[test]
    fn un_messaggio_non_e_un_allegato() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let testo = baseline::seal(&alice, &bob.public(), b"ciao", 1, &mut rng).unwrap();
        let body = crate::encoding::decode(testo.trim_start_matches(format::SENTINEL)).unwrap();
        assert!(matches!(parse_file(&body), Err(Error::Format(_))));
    }

    #[test]
    fn ogni_bit_flip_e_intercettato() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        for i in 0..blob.len() {
            let mut corrotto = blob.clone();
            corrotto[i] ^= 0x01;
            let aperto = parse_file(&corrotto)
                .and_then(|p| open_file(&bob, &alice.public(), &p));
            assert!(aperto.is_err(), "il bit {i} e' passato inosservato");
        }
    }

    #[test]
    fn troncato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        for len in 0..blob.len() {
            let aperto = parse_file(&blob[..len])
                .and_then(|p| open_file(&bob, &alice.public(), &p));
            assert!(aperto.is_err(), "troncato a {len} si e' aperto");
        }
    }
}
