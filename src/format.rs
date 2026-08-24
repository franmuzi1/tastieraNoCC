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

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::encoding;
use crate::error::{Error, Result};
use crate::keys::{PublicKey, KEY_LEN};

/// Byte di versione, primo byte del body. Una volta rilasciata, la versione 1
/// non si modifica mai: si aggiunge la 2.
pub const PROTOCOL_VERSION: u8 = 1;

/// Il messaggio di gruppo (decisione K). **Versione e non `kind` nuovo, e non un
/// bit di flag**: un'installazione vecchia deve dire "aggiorna l'app", non
/// "messaggio corrotto", e solo il byte di versione produce
/// `UnsupportedVersion` prima di qualunque altro controllo.
pub const GROUP_VERSION: u8 = 2;

/// Chiave di contenuto incapsulata (32) piu' il tag (16).
pub const SLOT_LEN: usize = KEY_LEN + TAG_LEN;

/// Otto destinatari piu' lo slot del mittente, che serve a rileggere cio' che
/// si e' scritto: l'effimera si butta dopo l'invio.
pub const MAX_SLOT: usize = 9;

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
///
/// NON contiene la versione. Il numero di versione vive in un solo posto, il
/// primo byte del body: averlo anche qui sarebbe una seconda fonte di verita'
/// per lo stesso fatto. La conseguenza pratica e' che un blob prodotto da una
/// futura versione 2 viene comunque RICONOSCIUTO come nostro e produce
/// `UnsupportedVersion` — cioe' "aggiorna l'app" — invece di `NotOurBlob`,
/// cioe' "questo testo non e' cifrato", che sarebbe il messaggio sbagliato.
pub const SENTINEL: &str = "kc/";

/// Sotto questa lunghezza una sequenza di caratteri dell'alfabeto dopo il
/// sentinel e' quasi certamente una coincidenza dentro testo normale, non un
/// blob troncato. Serve a non classificare come "nostro ma rotto" del testo
/// che contiene per caso `kc/` seguito da qualche lettera.
const MIN_PAYLOAD_CHARS: usize = 16;

/// Intervallo entro cui viene portata, con riempimento casuale, la lunghezza
/// del body di una identity card.
///
/// Senza questo una card avrebbe SEMPRE la stessa lunghezza (39 byte, 68
/// caratteri), mentre il messaggio piu' corto ne fa 127: una singola regex
/// sulla lunghezza isolerebbe tutte e sole le presentazioni, su tutto il
/// traffico, a costo zero. Sarebbe esattamente il marcatore "questo utente sta
/// agganciando un nuovo contatto" che mettere `kind` dentro il body doveva
/// evitare — la decisione non produrrebbe l'effetto per cui e' stata presa.
///
/// L'intervallo copre le lunghezze dei messaggi con plaintext da 0 a 200 byte.
/// Residuo accettato: su molti campioni la distribuzione resta distinguibile,
/// perche' quella delle card e' uniforme e quella dei messaggi segue la
/// lunghezza dei testi. Difende dalla regola cheap applicata a tappeto, non
/// dall'analisi statistica su un utente scelto — coerentemente col threat model.
const CARD_MIN_BODY: usize = 76;
const CARD_MAX_BODY: usize = 276;

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
    /// File cifrato: foto, audio, qualunque cosa. **Non** viaggia come testo —
    /// z-base-32 gonfierebbe di 1,6x — ma come byte grezzi dentro un allegato.
    /// Il resto dell'envelope e' identico a quello di un messaggio, cosi' il
    /// parser resta uno solo e `kind` sta gia' nell'AAD: un file non puo'
    /// essere fatto passare per un messaggio, ne' viceversa.
    File = 2,
    /// **Richiesta di bruciare** (decisione J): "distruggi la chiave d'epoca
    /// con cui ci scriviamo".
    ///
    /// Non porta testo: e' il gesto, non un messaggio. Viaggia cifrato come
    /// tutto il resto, quindi solo chi ha davvero quella conversazione puo'
    /// chiederlo — ma **non e' imponibile**: chi riceve deve avere un'app che
    /// lo onora. Verso chi non collabora non esiste cancellazione a distanza,
    /// e questo formato non pretende il contrario.
    Burn = 3,
}

impl Kind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Kind::Message),
            1 => Ok(Kind::IdentityCard),
            2 => Ok(Kind::File),
            3 => Ok(Kind::Burn),
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
    /// La chiave nell'header e' **effimera**, non l'identita' del mittente.
    ///
    /// Chi riceve non sa piu' chi ha scritto prima di aver decifrato: lo
    /// scopre provando i propri contatti. La chiave AEAD si deriva da due
    /// scambi insieme — quello effimero e quello con la chiave stabile del
    /// mittente — quindi il fatto stesso che la decifratura riesca **dimostra**
    /// chi e' stato, senza bisogno di una firma.
    ///
    /// Toglie di mezzo la correlabilita': senza `sender_pub` in chiaro, due
    /// messaggi dello stesso mittente non si possono piu' legare guardando il
    /// traffico. Ed e' mezza forward secrecy: chi ottiene domani la chiave del
    /// MITTENTE non apre i messaggi di ieri, perche' l'effimera e' stata
    /// buttata. Chi ottiene quella del destinatario si', ed e' il motivo per
    /// cui questo non basta e la prekey resta da fare.
    pub const EPHEMERAL: Flags = Flags(0b0000_0010);
    /// Il messaggio usa anche una **chiave temporanea del destinatario**.
    ///
    /// E' la forward secrecy piena: quando chi riceve butta quella chiave, il
    /// messaggio non lo apre piu' nessuno — nemmeno lui. Va sempre insieme a
    /// [`Flags::EPHEMERAL`], perche' senza la chiave usa-e-getta del mittente
    /// meta' della proprieta' non ci sarebbe.
    pub const PREKEY: Flags = Flags(0b0000_0100);
    /// Il cifrato **porta** la chiave d'epoca del mittente.
    ///
    /// Distinto da [`Flags::PREKEY`], che dice l'opposto: *usare* quella del
    /// destinatario. Servono separati perche' il primo messaggio di una
    /// conversazione a epoca porta la propria senza poter usare la sua — non
    /// ce l'ha ancora — e senza questa distinzione quel messaggio sarebbe
    /// costretto a essere effimero, cioe' non rileggibile da chi l'ha scritto.
    /// E' esattamente il caso che la decisione J esiste per rendere possibile.
    ///
    /// Negli schemi effimeri la chiave viaggia comunque, e li' questo bit
    /// resta **spento**: quei blob esistono gia' in giro e dichiararlo adesso
    /// li renderebbe illeggibili.
    pub const EPOCH_OFFER: Flags = Flags(0b0000_1000);
    /// Bit definiti nella versione 1. Tutto il resto deve essere zero.
    pub const KNOWN: Flags = Flags(0b0000_1111);

    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    fn has_unknown_bits(self) -> bool {
        self.0 & !Self::KNOWN.0 != 0
    }
}

/// Che cos'e' la chiave pubblica nell'header, se c'e'.
///
/// Un tipo solo invece di una chiave piu' un flag: con due campi si potrebbe
/// scrivere "effimera" senza chiave, o una chiave senza dire cosa sia. Qui
/// quegli stati non si possono nemmeno esprimere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Nessuna chiave in chiaro. Nessuno schema attuale la produce; resta
    /// rappresentabile perche' un tier futuro potrebbe.
    Assente,
    /// La chiave del mittente, in chiaro. Serve al primo contatto TOFU, e
    /// rende i messaggi dello stesso mittente correlabili fra loro — residuo
    /// accettato nel modello di minaccia.
    Mittente(PublicKey),
    /// Una chiave **effimera**, buttata dal mittente subito dopo l'invio.
    ///
    /// Chi riceve non sa chi ha scritto finche' non decifra: lo scopre
    /// provando i propri contatti. La chiave AEAD nasce da due scambi insieme,
    /// quello effimero e quello con la chiave stabile del mittente, quindi il
    /// successo della decifratura **dimostra** chi e' stato senza firme.
    Effimera(PublicKey),
    /// Chiave effimera del mittente **piu'** l'uso di una chiave temporanea del
    /// destinatario: forward secrecy piena.
    ///
    /// La chiave AEAD nasce da due scambi che passano entrambi dalla temporanea
    /// di chi riceve. Quando lui la butta, il messaggio e' illeggibile a
    /// chiunque — compreso lui: **la cronologia non si rilegge**, ed e' il
    /// prezzo accettato con la decisione I.
    EffimeraConPrekey(PublicKey),
    /// La chiave del mittente in chiaro, e il cifrato porta la **nostra** chiave
    /// d'epoca senza usare la sua: e' il primo messaggio di una conversazione a
    /// epoca, o il primo dopo un rogo.
    ///
    /// Cifrato verso l'identita' del destinatario, come lo schema statico —
    /// quindi rileggibile da entrambi, che e' il punto della decisione J.
    MittenteConEpoca(PublicKey),
    /// La chiave del mittente in chiaro **piu'** l'uso della chiave d'epoca del
    /// destinatario: e' la **decisione J**, la conversazione bruciabile.
    ///
    /// La differenza con [`Origin::EffimeraConPrekey`] e' cio' che NON c'e':
    /// niente chiave effimera. E' esattamente quello che rende il messaggio
    /// rileggibile — anche da chi l'ha scritto, che puo' rifare la stessa
    /// derivazione — e quindi la cronologia esiste.
    ///
    /// In cambio la riservatezza non viene dal tempo ma da un gesto: finche'
    /// le due chiavi d'epoca esistono si legge, quando vengono distrutte non si
    /// legge piu', da nessuna delle due parti.
    MittenteConPrekey(PublicKey),
}

impl Origin {
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Origin::Effimera(_) | Origin::EffimeraConPrekey(_))
    }

    pub fn uses_prekey(&self) -> bool {
        matches!(
            self,
            Origin::EffimeraConPrekey(_) | Origin::MittenteConPrekey(_)
        )
    }

    /// Schema a epoca: chiave del mittente in chiaro, cifrato verso la chiave
    /// d'epoca del destinatario. Rileggibile finche' quelle chiavi esistono.
    pub fn uses_epoch(&self) -> bool {
        matches!(self, Origin::MittenteConPrekey(_))
    }

    /// Il cifrato porta la chiave d'epoca del mittente **dichiarandolo**.
    /// Gli schemi effimeri la portano comunque, ma senza il bit.
    pub fn offers_epoch(&self) -> bool {
        matches!(
            self,
            Origin::MittenteConEpoca(_) | Origin::MittenteConPrekey(_)
        )
    }

    /// Il primo messaggio di una conversazione a epoca: porta la nostra chiave
    /// ma non usa la sua, perche' non ce l'abbiamo ancora.
    pub fn is_epoch_bootstrap(&self) -> bool {
        matches!(self, Origin::MittenteConEpoca(_))
    }

    /// La chiave da mettere nel body, se c'e'.
    pub fn key(&self) -> Option<&PublicKey> {
        match self {
            Origin::Assente => None,
            Origin::Mittente(k)
            | Origin::Effimera(k)
            | Origin::EffimeraConPrekey(k)
            | Origin::MittenteConEpoca(k)
            | Origin::MittenteConPrekey(k) => Some(k),
        }
    }
}

/// Header in chiaro di un messaggio. Tutto quello che sta qui e' visibile a
/// chi intercetta: tenerlo minimo.
///
/// `flags` non e' un campo ma una funzione di `origin`: due fonti di verita'
/// per lo stesso fatto sarebbero un modo per produrre un header incoerente, e
/// un header incoerente fa fallire l'autenticazione in modo opaco. Un solo
/// posto in cui la natura della chiave e' rappresentata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub tier: Tier,
    pub origin: Origin,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn flags(&self) -> Flags {
        match self.origin {
            Origin::Assente => Flags::NONE,
            Origin::Mittente(_) => Flags::SENDER_PUB,
            Origin::Effimera(_) => Flags(Flags::SENDER_PUB.0 | Flags::EPHEMERAL.0),
            Origin::EffimeraConPrekey(_) => {
                Flags(Flags::SENDER_PUB.0 | Flags::EPHEMERAL.0 | Flags::PREKEY.0)
            }
            Origin::MittenteConEpoca(_) => Flags(Flags::SENDER_PUB.0 | Flags::EPOCH_OFFER.0),
            Origin::MittenteConPrekey(_) => {
                Flags(Flags::SENDER_PUB.0 | Flags::PREKEY.0 | Flags::EPOCH_OFFER.0)
            }
        }
    }

    /// La chiave del mittente, se l'header la dichiara come tale. `None` per
    /// una chiave effimera: quella non dice chi ha scritto, e trattarla come
    /// identita' significherebbe fissare nel keyring una chiave usa-e-getta.
    pub fn sender_pub(&self) -> Option<&PublicKey> {
        match &self.origin {
            // Nello schema a epoca la chiave e' del mittente come nel caso
            // statico: e' l'effimera a non dire chi ha scritto, non la prekey.
            Origin::Mittente(k) | Origin::MittenteConEpoca(k) | Origin::MittenteConPrekey(k) => {
                Some(k)
            }
            _ => None,
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
    pub public: PublicKey,
}

/// Esito di [`parse`]: il chiamante deve gestire entrambi i casi.
#[derive(Debug)]
pub enum ParsedBlob<'a> {
    Message(ParsedEnvelope<'a>),
    IdentityCard(IdentityCard),
    /// Una richiesta di bruciare la conversazione (decisione J). L'involucro e'
    /// identico a quello di un messaggio: cambia solo `kind`, che sta nell'AAD
    /// e quindi non e' scambiabile con un messaggio normale.
    Burn(ParsedEnvelope<'a>),
    /// Un messaggio di gruppo (decisione K, `version = 2`).
    Group(ParsedGroup<'a>),
}

/// Un messaggio di gruppo parsato.
///
/// Gli slot restano un blocco di byte e non un `Vec` di strutture: chi apre li
/// prova uno per uno e non ha niente da estrarre finche' uno non funziona.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedGroup<'a> {
    pub header: Header,
    /// `n * SLOT_LEN` byte. Il conteggio si ricava dalla lunghezza.
    pub slots: &'a [u8],
    /// Include il tag Poly1305 in coda.
    pub ciphertext: &'a [u8],
}

impl ParsedGroup<'_> {
    pub fn slot_count(&self) -> usize {
        self.slots.len() / SLOT_LEN
    }

    pub fn slot(&self, i: usize) -> Option<&[u8]> {
        let inizio = i.checked_mul(SLOT_LEN)?;
        let fine = inizio.checked_add(SLOT_LEN)?;
        self.slots.get(inizio..fine)
    }
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
    aad.push(PROTOCOL_VERSION);
    aad.push(kind as u8);
    aad.push(header.tier as u8);
    aad.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        aad.extend_from_slice(chiave.as_bytes());
    }
    aad
}

/// AAD di un messaggio di gruppo.
///
/// Oltre a cio' che lega gia' la versione 1, lega **il conteggio degli slot** e
/// — quando si sta aprendo o chiudendo uno slot — **il suo indice**. Le due
/// cose servono a difetti diversi e servono entrambe:
///
/// - senza l'indice gli slot si potrebbero **riordinare**, e uno slot spostato
///   apre lo stesso perche' la chiave non dipende dalla posizione;
/// - senza il conteggio se ne potrebbe **togliere via uno**, e il blob mutilato
///   sembrerebbe nato senza quel destinatario invece che manomesso.
///
/// `indice` e' `None` per l'AAD del payload, che e' unico e non appartiene a
/// nessuno slot.
///
/// `impronta_slot` si passa **solo** per l'AAD del payload, e lega il testo al
/// blocco degli slot cosi' com'e'. Senza, gli slot erano legati al proprio
/// indice e al conteggio ma non fra loro: sovrascrivere lo slot di una persona
/// con la copia di quello di un'altra lasciava conteggio, lunghezza e forma
/// intatti, e il blob restava perfettamente leggibile per tutti gli altri.
/// Chi sta in mezzo poteva cosi' **escludere una persona sola dalla lettura**,
/// senza che gli altri se ne accorgessero e senza che l'esclusa potesse
/// distinguere l'esclusione da un guasto.
///
/// Ora una sostituzione del genere rompe il payload per TUTTI: resta possibile
/// corrompere — un attaccante attivo puo' sempre farlo — ma diventa un guasto
/// evidente invece che una censura mirata e silenziosa.
///
/// Non serve per gli slot: al momento di chiuderli il blocco non esiste ancora,
/// e ognuno e' gia' legato al proprio indice.
pub fn build_group_aad(
    kind: Kind,
    header: &Header,
    n_slot: u8,
    indice: Option<u8>,
    impronta_slot: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + KEY_LEN + 32);
    aad.push(GROUP_VERSION);
    aad.push(kind as u8);
    aad.push(header.tier as u8);
    aad.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        aad.extend_from_slice(chiave.as_bytes());
    }
    aad.push(n_slot);
    // Il payload e gli slot non devono poter condividere un AAD: `0xFF` non e'
    // un indice valido (il tetto e' MAX_SLOT), quindi separa i due casi senza
    // aggiungere un byte di tipo.
    aad.push(indice.unwrap_or(0xFF));
    if let Some(impronta) = impronta_slot {
        aad.extend_from_slice(impronta);
    }
    aad
}

/// L'impronta del blocco degli slot, per legarlo al payload. Vedi
/// [`build_group_aad`].
pub fn impronta_slot(slots: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(slots);
    hasher.finalize().into()
}

/// Serializza un messaggio di gruppo.
///
/// `slots` e' gia' il blocco concatenato, in ordine casuale: mescolarli non e'
/// compito di questa funzione, ma di chi li costruisce — qui non c'e' RNG.
pub fn serialize_group(header: &Header, slots: &[u8], ciphertext: &[u8]) -> Result<String> {
    // Il contratto si impone invece di darlo per buono. Prima non si verificava
    // niente: un blocco di lunghezza non multipla lasciava i byte di troppo
    // dentro il ciphertext, e oltre 255 slot `u8::try_from` falliva e
    // `unwrap_or(0)` scriveva un conteggio zero — cioe' un blob che il nostro
    // stesso parser rifiuta. Un errore del chiamante diventava un blob rotto
    // invece che un `Err`, che e' il fallimento silenzioso che questo progetto
    // rifiuta altrove.
    if slots.is_empty() || slots.len() % SLOT_LEN != 0 {
        return Err(Error::Format("blocco di slot malformato"));
    }
    let n_slot = slots.len() / SLOT_LEN;
    if n_slot < 2 || n_slot > MAX_SLOT {
        return Err(Error::Format("numero di slot fuori dai limiti"));
    }
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(1)
        .saturating_add(slots.len())
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(GROUP_VERSION);
    body.push(Kind::Message as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.push(u8::try_from(n_slot).map_err(|_| Error::Format("troppi slot"))?);
    body.extend_from_slice(slots);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    Ok(out)
}

/// Serializza un messaggio e antepone il sentinel, restituendo la stringa
/// pronta per la chat.
pub fn serialize_message(header: &Header, ciphertext: &[u8]) -> String {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::Message as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Serializza una presentazione, con riempimento casuale in coda.
///
/// Il riempimento non e' decorativo: senza, ogni card avrebbe la stessa
/// identica lunghezza e sarebbe isolabile con una regex su tutto il traffico
/// (vedi [`CARD_MIN_BODY`]). E' anche il motivo per cui questa funzione vuole
/// un RNG mentre il suo equivalente per i messaggi no.
///
/// I byte di riempimento non sono coperti dal checksum e non significano
/// nulla: alterarli non cambia la chiave trasportata. Ne consegue che una card
/// NON ha una rappresentazione testuale unica, al contrario di un messaggio.
/// E' voluto — la variabilita' e' lo scopo.
pub fn serialize_identity_card<R: RngCore + CryptoRng>(public: &PublicKey, rng: &mut R) -> String {
    let base = CARD_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(CHECKSUM_LEN);
    let span = CARD_MAX_BODY
        .saturating_sub(CARD_MIN_BODY)
        .saturating_add(1);
    let offset = usize::try_from(rng.next_u32())
        .unwrap_or(0)
        .checked_rem(span)
        .unwrap_or(0);
    let target = CARD_MIN_BODY.saturating_add(offset);
    let pad_len = target.saturating_sub(base);

    let mut body = Vec::with_capacity(target);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::IdentityCard as u8);
    body.push(Flags::NONE.0);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&identity_card_checksum(public));

    let mut pad = vec![0u8; pad_len];
    rng.fill_bytes(&mut pad);
    body.extend_from_slice(&pad);

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

/// Dice se il testo *sembra* contenere un nostro blob, senza decodificarlo.
///
/// Serve a una cosa sola: decidere se vale la pena offrire l'azione
/// "decifra". Guarda il sentinel e la lunghezza minima della sequenza di
/// caratteri dell'alfabeto che segue, e si ferma li'.
///
/// **Non e' una verifica.** `true` non dice che il blob sia integro, ne' che
/// sia per noi, ne' che sia della versione giusta: un `kc/` seguito da
/// abbastanza spazzatura basta. Chi lo usa per decidere una UI va bene; chi lo
/// usasse per saltare controlli a valle si sbaglia.
///
/// Esiste come funzione separata perche' il chiamante Android deve poterlo
/// chiedere **senza effetti collaterali**: [`parse`] non ne ha, ma il gradino
/// successivo — decifrare — fissa peer nel keyring, e una funzione che risponde
/// "sembra nostro" non deve avere nessuna possibilita' di arrivarci.
#[must_use]
pub fn looks_like_blob(text: &str) -> bool {
    extract_payload(text).is_some()
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
    let payload = extract_payload(text).ok_or(Error::NotOurBlob)?;
    *out = encoding::decode(payload)?;

    let mut cursor = Cursor::new(out);
    let version = cursor.take_u8()?;
    if version != PROTOCOL_VERSION && version != GROUP_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let kind = Kind::from_byte(cursor.take_u8()?)?;

    if version == GROUP_VERSION {
        // Solo i messaggi hanno una forma di gruppo. Un rogo o una card di
        // gruppo non esistono, e accettarli qui vorrebbe dire un ramo di codice
        // che nessuno produce e nessuno prova.
        return match kind {
            Kind::Message => parse_group(cursor).map(ParsedBlob::Group),
            _ => Err(Error::Format("questo tipo non ha una forma di gruppo")),
        };
    }

    match kind {
        Kind::Message => parse_message(cursor).map(ParsedBlob::Message),
        Kind::IdentityCard => parse_identity_card(cursor).map(ParsedBlob::IdentityCard),
        // Un file non arriva mai per questa via: e' un allegato, non testo.
        // Qualcuno potrebbe comunque codificarne uno in z-base-32 e incollarlo,
        // e allora e' meglio dirgli che il blob non e' di questo tipo piuttosto
        // che tentare una decifratura che l'AAD farebbe fallire come "crypto".
        Kind::Burn => parse_message(cursor).map(ParsedBlob::Burn),
        Kind::File => Err(Error::Format("un file non si incolla come testo")),
    }
}

/// Serializza una richiesta di bruciare. Dall'esterno e' indistinguibile da un
/// messaggio: stesso sentinel, stessa forma, lunghezza nella stessa fascia.
/// Un sentinel dedicato direbbe allo scanning "qui due persone stanno
/// cancellando una conversazione", che e' esattamente il tipo di marcatore che
/// mettere `kind` dentro il cifrato serve a non emettere.
pub fn serialize_burn(header: &Header, ciphertext: &[u8]) -> String {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::Burn as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Serializza un file: stesso corpo di un messaggio, **senza** sentinel e
/// senza z-base-32.
///
/// Niente marcatore in testa, di nessun tipo. Un magic number servirebbe solo
/// a farlo riconoscere da chi scansiona i file: i primi due byte — versione e
/// `kind` — bastano a chi lo apre davvero, e non annunciano niente a chi si
/// limita a guardare.
pub fn serialize_file(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::File as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);
    body
}

/// Inverte [`serialize_file`].
///
/// Come per i messaggi, un `Ok` **non** dice niente sull'integrita' del
/// contenuto: il ciphertext ha lunghezza variabile e troncarlo produce un file
/// perfettamente ben formato. A intercettarlo e' il tag in decifratura.
pub fn parse_file(bytes: &[u8]) -> Result<ParsedEnvelope<'_>> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.take_u8()?;
    if version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    match Kind::from_byte(cursor.take_u8()?)? {
        Kind::File => parse_message(cursor),
        // Non e' un file. Non e' nemmeno un errore di formato del contenuto:
        // e' un blob di un altro tipo passato dalla porta sbagliata.
        _ => Err(Error::Format("questo allegato non e' un file cifrato")),
    }
}

/// Isola il blob dentro il testo che lo circonda.
///
/// Non pretende che il sentinel sia a inizio stringa ne' che il blob arrivi
/// fino alla fine. Le vie d'ingresso reali non lo garantiscono: la clipboard e
/// lo share sheet consegnano abitualmente un newline in coda, e chi seleziona
/// a mano prende volentieri anche un "guarda: " davanti. Pretendere una
/// stringa esatta significherebbe fallire nel caso piu' comune — e fallire con
/// l'errore sbagliato, perche' un blob valido con un `\n` finale non e'
/// "estraneo", e' nostro.
///
/// Il payload e' la sequenza massima di caratteri dell'alfabeto dopo il
/// sentinel: il primo byte estraneo la chiude. Sotto [`MIN_PAYLOAD_CHARS`] si
/// considera una coincidenza dentro testo normale, non un blob.
fn extract_payload(text: &str) -> Option<&str> {
    let start = text.find(SENTINEL)?;
    let after = text.get(start.checked_add(SENTINEL.len())?..)?;
    let end = after
        .bytes()
        .position(|b| !encoding::is_alphabet_byte(b))
        .unwrap_or(after.len());
    let payload = after.get(..end)?;
    if payload.len() < MIN_PAYLOAD_CHARS {
        return None;
    }
    Some(payload)
}

fn parse_message<'a>(mut cursor: Cursor<'a>) -> Result<ParsedEnvelope<'a>> {
    let tier = Tier::from_byte(cursor.take_u8()?)?;
    let flags = Flags(cursor.take_u8()?);
    if flags.has_unknown_bits() {
        return Err(Error::Format("flag non definiti in questa versione"));
    }

    // La natura della chiave si ricava dai flag, e i due bit non sono
    // indipendenti: "effimera" senza "chiave presente" e' un header incoerente,
    // e va rifiutato qui invece di produrre un `Origin` che non descrive il
    // body — un errore di formato e' diagnosticabile, un fallimento AEAD no.
    let ha_chiave = flags.contains(Flags::SENDER_PUB);
    let effimera = flags.contains(Flags::EPHEMERAL);
    let prekey = flags.contains(Flags::PREKEY);
    let offre = flags.contains(Flags::EPOCH_OFFER);
    if !ha_chiave && (effimera || prekey || offre) {
        return Err(Error::Format("effimera senza chiave"));
    }
    // Usare la chiave d'epoca dell'altro senza portare la propria fermerebbe
    // la conversazione al messaggio dopo: lui non avrebbe piu' niente verso cui
    // scrivere. E' incoerente allo stesso modo di "effimera senza chiave".
    if prekey && !effimera && !offre {
        return Err(Error::Format("usa un'epoca senza offrirne una"));
    }
    // Negli schemi effimeri la chiave viaggia gia' e il bit resta spento:
    // accenderlo sarebbe una seconda fonte di verita' sullo stesso fatto.
    if effimera && offre {
        return Err(Error::Format("un'effimera porta gia' la propria chiave"));
    }
    // "Prekey senza effimera" NON e' piu' incoerente: dalla decisione J e' lo
    // schema a epoca, dove l'assenza dell'effimera e' cio' che rende il
    // messaggio rileggibile. Restava rifiutato per una ragione che non vale
    // piu': allora significava soltanto "meta' della forward secrecy
    // dichiarata e non fatta".
    let origin = if !ha_chiave {
        Origin::Assente
    } else {
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(cursor.take(KEY_LEN)?);
        let chiave = PublicKey::from_bytes(bytes);
        match (effimera, prekey, offre) {
            (false, false, false) => Origin::Mittente(chiave),
            (false, false, true) => Origin::MittenteConEpoca(chiave),
            (false, true, _) => Origin::MittenteConPrekey(chiave),
            (true, false, _) => Origin::Effimera(chiave),
            (true, true, _) => Origin::EffimeraConPrekey(chiave),
        }
    };

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(cursor.take(NONCE_LEN)?);

    let ciphertext = cursor.rest();
    // Sotto la lunghezza del tag non c'e' nemmeno un messaggio vuoto.
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Format("ciphertext piu' corto del tag"));
    }

    Ok(ParsedEnvelope {
        header: Header { tier, origin, nonce },
        ciphertext,
    })
}

/// Parsa un messaggio di gruppo (`version = 2`).
///
/// L'header e' quello della versione 1 e si rilegge con le stesse regole: la
/// forma del gruppo aggiunge in coda, non cambia cio' che c'era.
fn parse_group<'a>(mut cursor: Cursor<'a>) -> Result<ParsedGroup<'a>> {
    let tier = Tier::from_byte(cursor.take_u8()?)?;
    let flags = Flags(cursor.take_u8()?);
    if flags.has_unknown_bits() {
        return Err(Error::Format("flag non definiti in questa versione"));
    }
    // Il gruppo ha una forma sola: chiave effimera del mittente, niente
    // prechiavi. Non e' una restrizione arbitraria — un gruppo NON ha forward
    // secrecy per decisione (K1), quindi i bit della catena qui non
    // significherebbero niente, e accettarli vorrebbe dire un header che
    // dichiara una proprieta' che il formato non ha.
    if !flags.contains(Flags::SENDER_PUB)
        || !flags.contains(Flags::EPHEMERAL)
        || flags.contains(Flags::PREKEY)
        || flags.contains(Flags::EPOCH_OFFER)
    {
        return Err(Error::Format("un gruppo vuole la sola effimera"));
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(cursor.take(KEY_LEN)?);
    let origin = Origin::Effimera(PublicKey::from_bytes(bytes));

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(cursor.take(NONCE_LEN)?);

    let n_slot = usize::from(cursor.take_u8()?);
    // **Meno di due slot non e' un gruppo.** Il mittente ha sempre uno slot suo
    // (K2), quindi un gruppo legittimo ne ha almeno due: uno per lui e uno per
    // qualcun altro. Un blob da uno slot puo' nascere solo da un client
    // modificato, e serviva a una cosa sola — presentarsi come messaggio a due
    // pur essendo un `version = 2` senza forward secrecy, cioe' aggirare la
    // condizione che rende accettabile tutto il resto della decisione K.
    if n_slot < 2 {
        return Err(Error::Format("un gruppo vuole almeno due slot"));
    }
    if n_slot > MAX_SLOT {
        return Err(Error::Format("troppi destinatari"));
    }
    // `take` fallisce se i byte non ci sono tutti: il conteggio dichiarato e la
    // lunghezza reale devono coincidere, altrimenti un blob troncato
    // sembrerebbe un gruppo piu' piccolo.
    let slots = cursor.take(n_slot.saturating_mul(SLOT_LEN))?;

    let ciphertext = cursor.rest();
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Format("ciphertext piu' corto del tag"));
    }

    Ok(ParsedGroup {
        header: Header { tier, origin, nonce },
        slots,
        ciphertext,
    })
}

fn parse_identity_card(mut cursor: Cursor<'_>) -> Result<IdentityCard> {
    let flags = Flags(cursor.take_u8()?);
    // Nessun flag e' definito per le card nella versione 1.
    if flags != Flags::NONE {
        return Err(Error::Format("flag non definiti per identity card"));
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(cursor.take(KEY_LEN)?);
    let public = PublicKey::from_bytes(bytes);

    let checksum = cursor.take(CHECKSUM_LEN)?;
    // Quello che resta e' riempimento: si ignora. Non c'e' un controllo sui
    // "byte in eccesso" perche' i byte in eccesso sono la funzione, non un
    // difetto — sono cio' che impedisce alle card di avere tutte la stessa
    // lunghezza.
    //
    // Confronto non a tempo costante di proposito: non c'e' nessun segreto in
    // gioco, la card e' interamente pubblica.
    if checksum != identity_card_checksum(&public) {
        return Err(Error::Format("checksum della identity card non torna"));
    }

    Ok(IdentityCard { public })
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
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    #[test]
    fn looks_like_blob_riconosce_senza_promettere() {
        // Sentinel piu' abbastanza caratteri dell'alfabeto: basta.
        assert!(looks_like_blob("kc/ybndrfg8ejkmcpqx"));
        // Tollera il contesto, come parse: le vie d'ingresso reali non
        // consegnano mai testo pulito.
        assert!(looks_like_blob("guarda: kc/ybndrfg8ejkmcpqx\n"));

        // Niente sentinel.
        assert!(!looks_like_blob("un messaggio qualunque"));
        // Sentinel ma coda troppo corta per essere un blob.
        assert!(!looks_like_blob("kc/ybnd"));
        // Sentinel seguito da caratteri fuori alfabeto.
        assert!(!looks_like_blob("kc/MAIUSCOLE"));

        // NON e' una verifica: spazzatura di lunghezza sufficiente passa.
        // E' voluto — serve solo a decidere se offrire l'azione "decifra" —
        // e questo test esiste perche' nessuno lo scambi per un controllo.
        assert!(looks_like_blob("kc/yyyyyyyyyyyyyyyyyyyy"));
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; KEY_LEN])
    }

    fn header(sender: Option<PublicKey>) -> Header {
        Header {
            tier: Tier::Baseline,
            origin: match sender {
                Some(k) => Origin::Mittente(k),
                None => Origin::Assente,
            },
            nonce: [7u8; NONCE_LEN],
        }
    }

    fn ciphertext() -> Vec<u8> {
        (0..40u8).collect()
    }

    fn card_body_len() -> usize {
        CARD_PREFIX_LEN + KEY_LEN + CHECKSUM_LEN
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
        let text = serialize_identity_card(&key, &mut rng(1));

        let mut buf = Vec::new();
        let ParsedBlob::IdentityCard(card) = parse(&text, &mut buf).unwrap() else {
            panic!("attesa una identity card");
        };
        assert_eq!(card.public, key);
    }

    /// Il rilievo che ha motivato il riempimento: senza, ogni card era lunga
    /// esattamente 68 caratteri e il messaggio piu' corto 127, quindi una
    /// singola regex sulla lunghezza isolava tutte e sole le presentazioni.
    ///
    /// Qui si verifica che (a) le card non abbiano piu' una lunghezza fissa e
    /// (b) il loro intervallo ricada dentro quello dei messaggi.
    #[test]
    fn le_card_non_hanno_lunghezza_fissa() {
        let key = pubkey(0x77);
        let mut r = rng(2);
        let mut lunghezze = std::collections::BTreeSet::new();
        for _ in 0..200 {
            lunghezze.insert(serialize_identity_card(&key, &mut r).len());
        }
        assert!(
            lunghezze.len() > 50,
            "solo {} lunghezze distinte: il riempimento non sta variando",
            lunghezze.len()
        );

        let msg_corto = serialize_message(&header(Some(pubkey(1))), &[0u8; TAG_LEN]).len();
        let msg_lungo = serialize_message(&header(Some(pubkey(1))), &[0u8; 200 + TAG_LEN]).len();
        let (min, max) = (
            *lunghezze.iter().next().unwrap(),
            *lunghezze.iter().next_back().unwrap(),
        );
        assert!(
            min >= msg_corto && max <= msg_lungo,
            "card in {min}..{max}, messaggi in {msg_corto}..{msg_lungo}: gli intervalli non si sovrappongono"
        );
    }

    #[test]
    fn i_due_tipi_non_si_confondono() {
        let mut buf = Vec::new();
        let msg = serialize_message(&header(Some(pubkey(1))), &ciphertext());
        assert!(matches!(
            parse(&msg, &mut buf).unwrap(),
            ParsedBlob::Message(_)
        ));

        let card = serialize_identity_card(&pubkey(1), &mut rng(3));
        assert!(matches!(
            parse(&card, &mut buf).unwrap(),
            ParsedBlob::IdentityCard(_)
        ));
    }

    #[test]
    fn testo_qualunque_non_e_nostro() {
        let mut buf = Vec::new();
        for testo in [
            "",
            "ciao",
            "https://esempio.it/x",
            "KC/1/yyyyyyyyyyyyyyyyyyyy",
            "guarda qui kc/ e poi basta",
        ] {
            assert!(
                matches!(parse(testo, &mut buf), Err(Error::NotOurBlob)),
                "non riconosciuto come estraneo: {testo}"
            );
        }
    }

    /// Il testo che arriva dalle vie reali non e' mai pulito: la clipboard e lo
    /// share sheet aggiungono un newline, chi seleziona a mano si porta dietro
    /// il contesto. Un blob valido dentro tutto questo resta valido.
    #[test]
    fn tollera_spazi_e_contesto() {
        let h = header(Some(pubkey(0x3D)));
        let ct = ciphertext();
        let blob = serialize_message(&h, &ct);

        for testo in [
            format!("{blob}\n"),
            format!("{blob}\r\n"),
            format!("{blob} "),
            format!("  {blob}  "),
            format!("guarda: {blob}"),
            format!("{blob} che ne dici?"),
            format!("[14:32] Marco:\n{blob}\n\n"),
        ] {
            let mut buf = Vec::new();
            let ParsedBlob::Message(parsed) = parse(&testo, &mut buf).unwrap_or_else(|e| {
                panic!("rifiutato con {e:?}: {testo:?}");
            }) else {
                panic!("atteso un messaggio");
            };
            assert_eq!(parsed.ciphertext, &ct[..]);
        }
    }

    /// Un blob troncato resta NOSTRO: puo' essere rotto, ma non deve mai
    /// diventare "questo testo non e' cifrato". La distinzione conta perche' la
    /// UI ci costruisce sopra due messaggi molto diversi, e il taglio in coda
    /// e' il modo piu' comune in cui un incollaggio va storto.
    ///
    /// Nota: NON si asserisce che sia un errore. Tagliare la coda di un
    /// messaggio accorcia il ciphertext e produce un blob ancora ben formato —
    /// se ne accorge il tag Poly1305, non il parser.
    #[test]
    fn blob_troncato_resta_riconoscibile() {
        let blob = serialize_message(&header(Some(pubkey(2))), &ciphertext());

        for taglio in 1..=8usize {
            let tagliato = blob.get(..blob.len().saturating_sub(taglio)).unwrap();
            let mut buf = Vec::new();
            assert!(
                !matches!(parse(tagliato, &mut buf), Err(Error::NotOurBlob)),
                "taglio di {taglio} caratteri: classificato come non nostro"
            );
        }
    }

    /// Con il sentinel privo di versione, un blob di una versione futura viene
    /// riconosciuto come nostro: l'utente deve leggere "aggiorna l'app", non
    /// "questo testo non e' cifrato".
    ///
    /// La 3 e non la 2: la 2 e' il messaggio di gruppo, e da quando esiste non
    /// e' piu' un esempio di versione futura. Questo test e' cambiato insieme
    /// al formato, ed e' il modo giusto di accorgersene — se avesse continuato
    /// a passare avrebbe voluto dire che il gruppo non veniva riconosciuto.
    #[test]
    fn versione_futura_riconosciuta_come_nostra() {
        let mut body = vec![3u8, Kind::Message as u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(
            parse(&text, &mut buf),
            Err(Error::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn tier_riservato_si_parsa_il_rifiuto_arriva_dopo() {
        // Il parser riconosce ForwardSecret senza lamentarsi: e' `baseline` a
        // dover ritornare TierUnsupported. Confondere i due livelli renderebbe
        // impossibile distinguere "non lo so leggere" da "non lo so eseguire".
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

        let mut body = vec![PROTOCOL_VERSION, 42u8];
        body.extend_from_slice(&[0u8; 64]);
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

    /// Test negativo obbligatorio di CLAUDE.md: flag incoerenti con la
    /// lunghezza. SENDER_PUB acceso ma nel body non c'e' spazio per i 32 byte.
    #[test]
    fn flag_sender_pub_incoerente_con_la_lunghezza() {
        let mut body = vec![
            PROTOCOL_VERSION,
            Kind::Message as u8,
            Tier::Baseline as u8,
            Flags::SENDER_PUB.0,
        ];
        // Meno dei 32 byte di chiave, figurarsi nonce e ciphertext.
        body.extend_from_slice(&[0u8; 20]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    #[test]
    fn ciphertext_piu_corto_del_tag() {
        let h = header(Some(pubkey(9)));
        let text = serialize_message(&h, &[0u8; TAG_LEN - 1]);

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    /// Ogni bit della parte SIGNIFICATIVA di una card, ribaltato uno alla
    /// volta, non deve mai produrre una card.
    ///
    /// L'asserzione e' su "nessuna card esce", non su "il risultato e' un
    /// errore": ribaltare il bit di `kind` trasforma la card in un messaggio
    /// sintatticamente valido, che pero' e' innocuo — nessuna chiave sbagliata
    /// viene fissata. Cio' contro cui il checksum esiste e' esattamente che
    /// venga fissata una chiave corrotta.
    ///
    /// Il riempimento e' escluso di proposito: non e' coperto dal checksum e
    /// alterarlo non deve cambiare nulla. E' il test successivo a fissarlo.
    #[test]
    fn nessun_bit_flip_produce_una_card() {
        let key = pubkey(0x11);
        let text = serialize_identity_card(&key, &mut rng(4));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let originale = encoding::decode(payload).unwrap();

        for i in 0..card_body_len() {
            for bit in 0..8u8 {
                let mut body = originale.clone();
                let Some(slot) = body.get_mut(i) else { continue };
                *slot ^= 1 << bit;

                let mutato = format!("{SENTINEL}{}", encoding::encode(&body));
                let mut buf = Vec::new();
                assert!(
                    !matches!(parse(&mutato, &mut buf), Ok(ParsedBlob::IdentityCard(_))),
                    "bit {bit} del byte {i} passato inosservato"
                );
            }
        }
    }

    #[test]
    fn il_riempimento_non_influenza_la_chiave() {
        let key = pubkey(0x12);
        let text = serialize_identity_card(&key, &mut rng(5));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let mut body = encoding::decode(payload).unwrap();
        assert!(body.len() > card_body_len(), "questa card non ha riempimento");

        for i in card_body_len()..body.len() {
            let Some(slot) = body.get_mut(i) else { continue };
            *slot ^= 0xFF;
        }
        let mutato = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        let ParsedBlob::IdentityCard(card) = parse(&mutato, &mut buf).unwrap() else {
            panic!("attesa una identity card");
        };
        assert_eq!(card.public, key);
    }

    #[test]
    fn troncamento_card_sotto_la_parte_significativa() {
        let text = serialize_identity_card(&pubkey(0x22), &mut rng(6));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        for len in 0..card_body_len() {
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            assert!(
                !matches!(parse(&text, &mut buf), Ok(ParsedBlob::IdentityCard(_))),
                "troncamento a {len} byte accettato come card"
            );
        }
    }

    /// Un messaggio ha ciphertext di lunghezza variabile, e questo impone un
    /// limite che va capito bene: **il parser non puo' accorgersi che un
    /// ciphertext e' stato troncato.**
    ///
    /// Tagliando gli ultimi byte si ottiene un messaggio perfettamente ben
    /// formato, solo con un ciphertext piu' corto. Nessun campo di lunghezza lo
    /// smentisce, e aggiungerne uno non aiuterebbe: sarebbe in chiaro e
    /// l'attaccante lo aggiusterebbe insieme al resto.
    ///
    /// A intercettarlo e' il tag Poly1305, in decifratura. E' il posto giusto,
    /// ma significa che `parse` che ritorna `Ok` non dice nulla sull'integrita'
    /// del contenuto.
    #[test]
    fn troncamento_messaggio_rifiutato_fino_al_tag() {
        let text = serialize_message(&header(Some(pubkey(4))), &ciphertext());
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        let soglia = MESSAGE_PREFIX_LEN + KEY_LEN + NONCE_LEN + TAG_LEN;

        for len in 0..body.len() {
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            let esito = parse(&text, &mut buf);

            if len < soglia {
                assert!(esito.is_err(), "troncamento a {len} byte accettato");
            } else {
                assert!(esito.is_ok(), "troncamento a {len} byte rifiutato");
            }
        }
    }

    /// La versione non compare piu' fra i casi: non e' un campo libero di
    /// `Header`, e' la costante del crate. Non e' costruibile un header con
    /// versione incoerente.
    #[test]
    fn aad_cambia_con_ogni_campo() {
        let base = header(Some(pubkey(0x33)));
        let riferimento = build_aad(Kind::Message, &base);

        assert_ne!(build_aad(Kind::IdentityCard, &base), riferimento);

        let altro_tier = Header {
            tier: Tier::ForwardSecret,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_tier), riferimento);

        let altro_sender = Header {
            origin: Origin::Mittente(pubkey(0x44)),
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_sender), riferimento);

        let senza_sender = Header {
            origin: Origin::Assente,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &senza_sender), riferimento);
    }

    /// L'AAD non copre il nonce, ed e' voluto: il nonce e' gia' un ingresso
    /// dell'AEAD, quindi alterarlo fa fallire l'autenticazione senza bisogno di
    /// autenticarlo una seconda volta.
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
            tier: Tier::Baseline,
            origin: Origin::Mittente(PublicKey::from_bytes([0x42; KEY_LEN])),
            nonce: [0x24; NONCE_LEN],
        };
        let ct: Vec<u8> = (0..32u8).collect();
        assert_eq!(serialize_message(&h, &ct), KAT_MESSAGGIO);

        let card = serialize_identity_card(&PublicKey::from_bytes([0x42; KEY_LEN]), &mut rng(0));
        assert_eq!(card, KAT_IDENTITY_CARD);
    }

    const KAT_MESSAGGIO: &str = "kc/yryyyyknejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nee1nejbrro1nejbrro1nejbrro1nejbrro1nejbryyyoryarywdyqnyjbefoadeqbhebnrounoktcfaadrpbs8y7daxo";
    const KAT_IDENTITY_CARD: &str = "kc/yryoyo1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nk9yhjwfy6r63yon7pm1i8bi7fn67rgpawng64gieg5zh3n5zbzd7wok3xteiq1rpqh1qyx7a5bfdq41dzd4bkgfbdubaxpujsmzgmbw9y9u5hikt8b7jtqwzxt314nyp3c81uenehp1s1rsgkc9df5u47ww5qemsuuurho6iqr35y7ga88kud5e9fbeoi64fiuoow84mxfgs6mejwduggjo";
}
