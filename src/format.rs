//! Formato del messaggio sul filo.
//!
//! Esistono due tipi di blob, distinti da un byte `kind` DENTRO il body:
//!
//! ```text
//! SENTINEL || z-base-32( body )
//!
//! body = version(1) || kind(1) || payload
//!
//! kind = Message:
//!     tier(1) || flags(1)
//!  || [ sender_pub(32) se flags & SENDER_PUB ]
//!  || nonce(24)
//!  || ciphertext(n + 16)      // include il tag Poly1305
//!
//! kind = IdentityCard:
//!     flags(1) || public(32) || checksum(4)
//! ```
//!
//! Il discriminante sta nel body e non nel sentinel di proposito: dall'esterno
//! i due tipi sono indistinguibili. Un sentinel dedicato per le presentazioni
//! sarebbe un marcatore in chiaro di "utente che sta agganciando un nuovo
//! contatto", cioe' esattamente il genere di segnale che uno scanning di massa
//! raccoglie a costo zero. Tenerlo dentro non costa nulla.
//!
//! Overhead di un messaggio con `sender_pub` presente: 76 byte + plaintext,
//! che diventano circa 1.6x in z-base-32.

use sha2::{Digest, Sha256};

use crate::encoding;
use crate::error::{Error, Result};
use crate::keys::{PublicKey, KEY_LEN};

/// Byte di versione, primo byte del body. Una volta rilasciata, la versione 1
/// non si modifica mai: si aggiunge la 2.
pub const PROTOCOL_VERSION: u8 = 1;

/// Prefisso di riconoscimento, in chiaro per forza: serve a capire che un
/// testo qualsiasi della clipboard e' un nostro blob PRIMA di decifrarlo.
///
/// E' pseudo-link cosmetico: plausibilita' sociale a occhio umano, nessuna
/// proprieta' di sicurezza. Mai cliccabile, mai un dominio reale, mai una
/// richiesta di rete.
///
/// VINCOLO TECNICO: la forma non deve essere riconosciuta dai linkifier delle
/// app di chat, altrimenti la piattaforma fa unfurl lato server e spedisce il
/// blob a un terzo. I linkifier matchano `schema://`, `www.` e `label.tld`
/// con TLD da lista IANA; qui non c'e' nessuno dei tre. Non introdurre punti.
///
/// Lo slash non appartiene all'alfabeto z-base-32, quindi e' un separatore
/// non ambiguo rispetto al payload.
pub const SENTINEL: &str = "kc/1/";

/// Nonce XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;
/// Tag Poly1305.
pub const TAG_LEN: usize = 16;
/// Checksum tronco della identity card.
pub const CHECKSUM_LEN: usize = 4;

/// Domain separation del checksum. Congelato.
const CHECKSUM_DOMAIN: &[u8] = b"keyboard-cipher/v1/identity-card";

/// Parte fissa di un messaggio: version + kind + tier + flags.
pub const MESSAGE_PREFIX_LEN: usize = 4;
/// Parte fissa di una identity card: version + kind + flags.
pub const CARD_PREFIX_LEN: usize = 3;

/// Tipo di blob.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// Messaggio cifrato.
    Message = 0,
    /// Presentazione: "questa e' la mia chiave pubblica". Non cifrata, non
    /// autenticata — non puo' esserlo, e' il primo contatto. Serve solo a
    /// trasportare una pubkey in un formato che la tastiera riconosca.
    IdentityCard = 1,
}

impl Kind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Kind::Message),
            1 => Ok(Kind::IdentityCard),
            _ => Err(Error::Format("kind sconosciuto")),
        }
    }
}

/// Livello di protezione. Il marcatore viaggia in chiaro (serve al dispatch
/// prima di decifrare) ED entra nell'AAD: se un attaccante attivo lo altera
/// per forzare un downgrade, l'autenticazione fallisce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Tier {
    /// X25519 statico-statico + XChaCha20-Poly1305. L'unico implementato.
    Baseline = 0,
    /// Forward secrecy. RISERVATO: il parsing lo riconosce, l'esecuzione
    /// ritorna [`Error::TierUnsupported`].
    ForwardSecret = 1,
}

impl Tier {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Tier::Baseline),
            1 => Ok(Tier::ForwardSecret),
            _ => Err(Error::Format("tier sconosciuto")),
        }
    }
}

/// Bit di presenza dei campi opzionali.
///
/// Esistono per rendere migrabile il formato senza romperlo: il baseline
/// mette la pubkey del mittente in chiaro, ma un tier futuro usera' un
/// mittente effimero con il claim d'identita' firmato DENTRO il cifrato, e in
/// quel caso `sender_pub` semplicemente non c'e'.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Flags(pub u8);

impl Flags {
    pub const NONE: Flags = Flags(0);
    /// Il body contiene `sender_pub` in chiaro.
    pub const SENDER_PUB: Flags = Flags(0b0000_0001);
    /// Bit definiti nella versione 1. Tutto il resto deve essere zero.
    pub const KNOWN: Flags = Flags(0b0000_0001);

    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    fn has_unknown_bits(self) -> bool {
        self.0 & !Self::KNOWN.0 != 0
    }
}

/// Header in chiaro di un messaggio. Tutto quello che sta qui e' visibile a
/// chi intercetta: tenerlo minimo.
///
/// `flags` non e' un campo ma una funzione di `sender_pub`: due fonti di
/// verita' per lo stesso fatto sarebbero un modo per produrre un header
/// incoerente, e un header incoerente fa fallire l'autenticazione in modo
/// opaco. Un solo posto in cui la presenza e' rappresentata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub tier: Tier,
    pub sender_pub: Option<PublicKey>,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn flags(&self) -> Flags {
        if self.sender_pub.is_some() {
            Flags::SENDER_PUB
        } else {
            Flags::NONE
        }
    }
}

/// Messaggio parsato, prima della decifratura. Presta il ciphertext dal buffer
/// del chiamante invece di copiarlo.
#[derive(Debug)]
pub struct ParsedEnvelope<'a> {
    pub header: Header,
    /// Include il tag Poly1305 in coda.
    pub ciphertext: &'a [u8],
}

/// Presentazione parsata.
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityCard {
    pub version: u8,
    pub public: PublicKey,
}

/// Esito di [`parse`]: il chiamante deve gestire entrambi i casi.
#[derive(Debug)]
pub enum ParsedBlob<'a> {
    Message(ParsedEnvelope<'a>),
    IdentityCard(IdentityCard),
}

/// Dati autenticati ma non cifrati (AAD dell'AEAD).
///
/// Legano header, kind e tier al ciphertext: manometterli fa fallire
/// l'autenticazione. `kind` e' incluso perche' un messaggio non deve poter
/// essere reinterpretato come un blob di tipo diverso. `sender_pub` e' incluso
/// anche se il suo valore e' gia' implicitamente legato dalla derivazione
/// della chiave: renderlo esplicito costa nulla e non lascia il vincolo
/// dipendente da un ragionamento indiretto.
pub fn build_aad(kind: Kind, header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + KEY_LEN);
    aad.push(header.version);
    aad.push(kind as u8);
    aad.push(header.tier as u8);
    aad.push(header.flags().0);
    if let Some(sender) = &header.sender_pub {
        aad.extend_from_slice(sender.as_bytes());
    }
    aad
}

/// Serializza un messaggio e antepone il sentinel, restituendo la stringa
/// pronta per la chat.
pub fn serialize_message(header: &Header, ciphertext: &[u8]) -> String {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(header.version);
    body.push(Kind::Message as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(sender) = &header.sender_pub {
        body.extend_from_slice(sender.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Serializza una presentazione.
pub fn serialize_identity_card(public: &PublicKey) -> String {
    let mut body = Vec::with_capacity(CARD_PREFIX_LEN + KEY_LEN + CHECKSUM_LEN);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::IdentityCard as u8);
    body.push(Flags::NONE.0);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&identity_card_checksum(public));

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Checksum tronco su una identity card.
///
/// Non e' autenticazione e non pretende di esserlo: una card puo' essere
/// sostituita in transito, ed e' precisamente il rischio che il TOFU accetta.
/// Serve contro la CORRUZIONE: una card troncata o alterata dal trasporto
/// verrebbe altrimenti fissata come chiave valida, e da quel momento ogni
/// messaggio verso quel contatto fallisce in modo opaco senza che nessuno
/// capisca perche'. Quattro byte lo intercettano subito, al costo di sette
/// caratteri.
pub fn identity_card_checksum(public: &PublicKey) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(public.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; CHECKSUM_LEN];
    // `digest` e' lungo 32 byte e CHECKSUM_LEN e' 4: il taglio esiste sempre.
    if let Some(head) = digest.get(..CHECKSUM_LEN) {
        out.copy_from_slice(head);
    }
    out
}

/// Verifica il sentinel, decodifica, controlla versione e kind, estrae i
/// campi. NON decifra.
///
/// Ritorna [`Error::NotOurBlob`] se il sentinel non combacia: e' il caso
/// comune su un testo qualsiasi della clipboard, non un fallimento.
///
/// `out` e' il buffer in cui atterra il body decodificato: l'envelope presta
/// il ciphertext da li' invece di copiarlo, quindi la lifetime del risultato
/// e' quella del buffer, non quella del testo.
pub fn parse<'a>(text: &str, out: &'a mut Vec<u8>) -> Result<ParsedBlob<'a>> {
    let payload = text.strip_prefix(SENTINEL).ok_or(Error::NotOurBlob)?;
    *out = encoding::decode(payload)?;

    let mut cursor = Cursor::new(out);
    let version = cursor.take_u8()?;
    if version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let kind = Kind::from_byte(cursor.take_u8()?)?;

    match kind {
        Kind::Message => parse_message(version, cursor).map(ParsedBlob::Message),
        Kind::IdentityCard => parse_identity_card(version, cursor).map(ParsedBlob::IdentityCard),
    }
}

fn parse_message<'a>(version: u8, mut cursor: Cursor<'a>) -> Result<ParsedEnvelope<'a>> {
    let tier = Tier::from_byte(cursor.take_u8()?)?;
    let flags = Flags(cursor.take_u8()?);
    if flags.has_unknown_bits() {
        return Err(Error::Format("flag non definiti in questa versione"));
    }

    let sender_pub = if flags.contains(Flags::SENDER_PUB) {
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(cursor.take(KEY_LEN)?);
        Some(PublicKey::from_bytes(bytes))
    } else {
        None
    };

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(cursor.take(NONCE_LEN)?);

    let ciphertext = cursor.rest();
    // Sotto la lunghezza del tag non c'e' nemmeno un messaggio vuoto.
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Format("ciphertext piu' corto del tag"));
    }

    Ok(ParsedEnvelope {
        header: Header {
            version,
            tier,
            sender_pub,
            nonce,
        },
        ciphertext,
    })
}

fn parse_identity_card(version: u8, mut cursor: Cursor<'_>) -> Result<IdentityCard> {
    let flags = Flags(cursor.take_u8()?);
    // Nessun flag e' definito per le card nella versione 1.
    if flags != Flags::NONE {
        return Err(Error::Format("flag non definiti per identity card"));
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(cursor.take(KEY_LEN)?);
    let public = PublicKey::from_bytes(bytes);

    let checksum = cursor.take(CHECKSUM_LEN)?;
    if !cursor.rest().is_empty() {
        return Err(Error::Format("byte in eccesso dopo la identity card"));
    }
    // Confronto non a tempo costante di proposito: non c'e' nessun segreto in
    // gioco, la card e' interamente pubblica.
    if checksum != identity_card_checksum(&public) {
        return Err(Error::Format("checksum della identity card non torna"));
    }

    Ok(IdentityCard { version, public })
}

/// Lettore sequenziale che non puo' andare in panic: ogni prelievo oltre la
/// fine e' un errore di formato, mai un indice fuori dai limiti.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Format("lunghezza fuori scala"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Format("body troncato"))?;
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(Error::Format("body troncato"))
    }

    fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }
}

#[cfg(test)]
// Nei test `unwrap` e `panic!` sono il comportamento voluto: un esito inatteso
// deve far fallire il test rumorosamente. I divieti valgono per il codice di
// produzione.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; KEY_LEN])
    }

    fn header(sender: Option<PublicKey>) -> Header {
        Header {
            version: PROTOCOL_VERSION,
            tier: Tier::Baseline,
            sender_pub: sender,
            nonce: [7u8; NONCE_LEN],
        }
    }

    fn ciphertext() -> Vec<u8> {
        (0..40u8).collect()
    }

    #[test]
    fn round_trip_messaggio_con_sender_pub() {
        let h = header(Some(pubkey(0xAB)));
        let ct = ciphertext();
        let text = serialize_message(&h, &ct);

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header, h);
        assert_eq!(parsed.ciphertext, &ct[..]);
    }

    #[test]
    fn round_trip_messaggio_senza_sender_pub() {
        let h = header(None);
        let ct = ciphertext();
        let text = serialize_message(&h, &ct);

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header, h);
        assert_eq!(parsed.header.flags(), Flags::NONE);
        assert_eq!(parsed.ciphertext, &ct[..]);
    }

    #[test]
    fn round_trip_identity_card() {
        let key = pubkey(0x5C);
        let text = serialize_identity_card(&key);

        let mut buf = Vec::new();
        let ParsedBlob::IdentityCard(card) = parse(&text, &mut buf).unwrap() else {
            panic!("attesa una identity card");
        };
        assert_eq!(card.public, key);
        assert_eq!(card.version, PROTOCOL_VERSION);
    }

    #[test]
    fn i_due_tipi_non_si_confondono() {
        let mut buf = Vec::new();
        let msg = serialize_message(&header(Some(pubkey(1))), &ciphertext());
        assert!(matches!(
            parse(&msg, &mut buf).unwrap(),
            ParsedBlob::Message(_)
        ));

        let card = serialize_identity_card(&pubkey(1));
        assert!(matches!(
            parse(&card, &mut buf).unwrap(),
            ParsedBlob::IdentityCard(_)
        ));
    }

    #[test]
    fn testo_qualunque_non_e_nostro() {
        let mut buf = Vec::new();
        for testo in ["", "ciao", "https://esempio.it/x", "kc/2/yyyy", "KC/1/yyyy"] {
            assert!(
                matches!(parse(testo, &mut buf), Err(Error::NotOurBlob)),
                "non riconosciuto come estraneo: {testo}"
            );
        }
    }

    #[test]
    fn sentinel_giusto_ma_payload_spazzatura() {
        let mut buf = Vec::new();
        // Caratteri fuori alfabeto z-base-32.
        assert!(matches!(parse("kc/1/!!!!", &mut buf), Err(Error::Decode)));
    }

    #[test]
    fn versione_sconosciuta() {
        let mut body = vec![2u8, Kind::Message as u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(
            parse(&text, &mut buf),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn tier_riservato_si_parsa_il_rifiuto_arriva_dopo() {
        // Il parser riconosce ForwardSecret senza lamentarsi: e' `baseline` a
        // dover ritornare TierUnsupported. Confondere i due livelli
        // renderebbe impossibile distinguere "non lo so leggere" da "non lo so
        // eseguire".
        let h = Header {
            tier: Tier::ForwardSecret,
            ..header(Some(pubkey(3)))
        };
        let text = serialize_message(&h, &ciphertext());

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header.tier, Tier::ForwardSecret);
    }

    #[test]
    fn kind_e_tier_sconosciuti() {
        let mut buf = Vec::new();

        let body = vec![PROTOCOL_VERSION, 42u8];
        let text = format!("{SENTINEL}{}", encoding::encode(&body));
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));

        let mut body = vec![PROTOCOL_VERSION, Kind::Message as u8, 42u8, 0u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    #[test]
    fn flag_non_definiti_rifiutati() {
        let mut body = vec![PROTOCOL_VERSION, Kind::Message as u8, 0u8, 0b1000_0000];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    #[test]
    fn ciphertext_piu_corto_del_tag() {
        let h = header(Some(pubkey(9)));
        // Un tag Poly1305 e' 16 byte: 15 non possono essere un messaggio.
        let text = serialize_message(&h, &[0u8; TAG_LEN - 1]);

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    #[test]
    fn identity_card_corrotta() {
        let key = pubkey(0x11);
        let text = serialize_identity_card(&key);
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let mut body = encoding::decode(payload).unwrap();

        // Un bit flip in ogni posizione del corpo deve essere intercettato.
        for i in 0..body.len() {
            let Some(slot) = body.get_mut(i) else { continue };
            let original = *slot;
            *slot ^= 0b0000_0001;
            let mutated = format!("{SENTINEL}{}", encoding::encode(&body));

            let mut buf = Vec::new();
            let esito = parse(&mutated, &mut buf);
            assert!(
                !matches!(esito, Ok(ParsedBlob::IdentityCard(ref c)) if c.public == key),
                "bit flip al byte {i} passato inosservato"
            );
            if let Some(slot) = body.get_mut(i) {
                *slot = original;
            }
        }
    }

    /// Una identity card ha lunghezza fissa: ogni troncamento e' rilevabile.
    #[test]
    fn troncamento_identity_card_sempre_rifiutato() {
        let text = serialize_identity_card(&pubkey(0x22));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        for len in 0..body.len() {
            // `get` invece di slicing: la fetta esiste per costruzione, ma il
            // divieto di indicizzare vale anche nei test.
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            assert!(
                parse(&text, &mut buf).is_err(),
                "troncamento a {len} byte accettato"
            );
        }
    }

    /// Un messaggio invece ha ciphertext di lunghezza variabile, e questo
    /// impone un limite che va capito bene: **il parser non puo' accorgersi
    /// che un ciphertext e' stato troncato.**
    ///
    /// Tagliando gli ultimi byte si ottiene un messaggio perfettamente ben
    /// formato, solo con un ciphertext piu' corto. Nessun campo di lunghezza
    /// lo smentisce, e aggiungerne uno non aiuterebbe: sarebbe in chiaro e
    /// l'attaccante lo aggiusterebbe insieme al resto.
    ///
    /// A intercettarlo e' il tag Poly1305, in fase di decifratura. E' il
    /// posto giusto — l'integrita' del ciphertext e' competenza dell'AEAD, non
    /// del framing — ma significa che `parse` che ritorna `Ok` non dice nulla
    /// sull'integrita' del contenuto. Chi legge `ParsedEnvelope` non deve mai
    /// dedurne che il messaggio sia intatto.
    ///
    /// Quello che il parser garantisce e' piu' ristretto: qualunque
    /// troncamento che intacchi l'header, o che lasci meno byte del tag, viene
    /// rifiutato.
    #[test]
    fn troncamento_messaggio_rifiutato_fino_al_tag() {
        let text = serialize_message(&header(Some(pubkey(4))), &ciphertext());
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        let header_len = MESSAGE_PREFIX_LEN + KEY_LEN + NONCE_LEN;
        let soglia = header_len + TAG_LEN;

        for len in 0..body.len() {
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            let esito = parse(&text, &mut buf);

            if len < soglia {
                assert!(esito.is_err(), "troncamento a {len} byte accettato");
            } else {
                // Ben formato, ma il contenuto e' mutilato: se ne accorgera'
                // l'AEAD, non noi.
                assert!(esito.is_ok(), "troncamento a {len} byte rifiutato");
            }
        }
    }

    #[test]
    fn aad_cambia_con_ogni_campo() {
        let base = header(Some(pubkey(0x33)));
        let riferimento = build_aad(Kind::Message, &base);

        // kind
        assert_ne!(build_aad(Kind::IdentityCard, &base), riferimento);
        // tier
        let altro_tier = Header {
            tier: Tier::ForwardSecret,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_tier), riferimento);
        // version
        let altra_versione = Header {
            version: 2,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altra_versione), riferimento);
        // sender_pub, sia il valore sia la presenza (che muove anche i flag)
        let altro_sender = Header {
            sender_pub: Some(pubkey(0x44)),
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_sender), riferimento);
        let senza_sender = Header {
            sender_pub: None,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &senza_sender), riferimento);
    }

    /// L'AAD non copre il nonce, ed e' voluto: il nonce e' gia' un ingresso
    /// dell'AEAD, quindi alterarlo fa fallire l'autenticazione senza bisogno
    /// di autenticarlo una seconda volta.
    #[test]
    fn aad_non_copre_il_nonce() {
        let base = header(Some(pubkey(0x55)));
        let altro_nonce = Header {
            nonce: [9u8; NONCE_LEN],
            ..base.clone()
        };
        assert_eq!(
            build_aad(Kind::Message, &altro_nonce),
            build_aad(Kind::Message, &base)
        );
    }

    /// Ancora di regressione sul formato, non un'autorita' esterna: fissa
    /// l'esatta stringa prodotta da ingressi noti. Se si rompe, e' cambiato il
    /// formato sul filo — cioe' la compatibilita' — non il codice.
    #[test]
    fn kat_formato() {
        let h = Header {
            version: PROTOCOL_VERSION,
            tier: Tier::Baseline,
            sender_pub: Some(PublicKey::from_bytes([0x42; KEY_LEN])),
            nonce: [0x24; NONCE_LEN],
        };
        let ct: Vec<u8> = (0..32u8).collect();
        assert_eq!(serialize_message(&h, &ct), KAT_MESSAGGIO);

        let card = serialize_identity_card(&PublicKey::from_bytes([0x42; KEY_LEN]));
        assert_eq!(card, KAT_IDENTITY_CARD);
    }

    const KAT_MESSAGGIO: &str = "kc/1/yryyyyknejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nee1nejbrro1nejbrro1nejbrro1nejbrro1nejbryyyoryarywdyqnyjbefoadeqbhebnrounoktcfaadrpbs8y7daxo";
    const KAT_IDENTITY_CARD: &str =
        "kc/1/yryoyo1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nk9yhjwy";
}
