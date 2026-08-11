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
use crate::format::{self, Header, Kind, Origin, ParsedEnvelope, Tier, NONCE_LEN, TAG_LEN};
use crate::keys::{Ephemeral, EphemeralSecret, Identity, PublicKey, KEY_LEN};

/// Stringa di domain separation per la HKDF. Congelata: cambiarla cambia tutte
/// le chiavi derivate e rompe la compatibilita' con la versione 1.
const KDF_DOMAIN: &[u8] = b"keyboard-cipher/v1/baseline";

/// Lunghezza della chiave XChaCha20-Poly1305.
const AEAD_KEY_LEN: usize = 32;

/// Timestamp di composizione, in testa al plaintext DENTRO il cifrato.
///
/// E' la risposta al replay (decisione C). Non lo impedisce — un blob valido
/// resta valido per sempre — ma lo rende VISIBILE: chi riceve vede la data in
/// cui il messaggio e' stato scritto accanto a una conversazione in cui
/// compare oggi.
///
/// Perche' non una finestra di validita' nell'AAD, che il replay lo negherebbe
/// davvero: farebbe fallire la decifratura di messaggi legittimi letti in
/// ritardo. In un sistema dove il destinatario compie un gesto deliberato per
/// ogni messaggio, leggere tre giorni dopo e' normale, non un attacco. E
/// richiederebbe un clock nel core, che non c'e' per scelta.
///
/// Sta DENTRO il cifrato, quindi non aggiunge metadati alla piattaforma — che
/// l'ora del messaggio la conosce gia' — ed e' autenticato dall'AEAD senza
/// bisogno di finire nell'AAD.
///
/// Scartata anche una cache dei nonce gia' visti, che il replay lo bloccherebbe
/// per davvero: richiede stato persistente che cresce senza limiti, e il core
/// e' stateless per costruzione.
const TIMESTAMP_LEN: usize = 8;

/// Plaintext appena decifrato. Zeroize on drop, mai loggato, mai convertito in
/// `String` sul confine JNI (una `java.lang.String` non e' azzerabile).
///
/// L'assenza di `Debug`, `Display` e `Clone` e' deliberata.
pub struct Plaintext {
    testo: Zeroizing<Vec<u8>>,
    sent_at_unix: i64,
}

impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.testo
    }

    pub fn len(&self) -> usize {
        self.testo.len()
    }

    pub fn is_empty(&self) -> bool {
        self.testo.is_empty()
    }

    /// Quando il mittente ha composto il messaggio, secondo il suo orologio.
    ///
    /// E' autenticato — sta dentro il cifrato — ma **non e' verificato**:
    /// nessuno puo' dimostrare che l'orologio del mittente fosse giusto. Serve
    /// a mostrare all'utente una data accanto al messaggio, cosi' un blob
    /// ripubblicato mesi dopo si nota. Non usarlo per decisioni automatiche.
    pub fn sent_at_unix(&self) -> i64 {
        self.sent_at_unix
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
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = seal_inner(Kind::Message, sender, recipient, plaintext, now_unix, rng)?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// Come [`seal`] ma per un file: stesso schema, `kind` diverso, e il risultato
/// sono byte grezzi invece di testo.
///
/// `kind` entra nell'AAD, quindi un file non puo' essere riaperto come
/// messaggio nemmeno da chi possiede la chiave giusta: la separazione non
/// dipende dal contenitore, e' autenticata.
pub fn seal_file<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = seal_inner(Kind::File, sender, recipient, plaintext, now_unix, rng)?;
    Ok(format::serialize_file(&header, &ciphertext))
}

fn seal_inner<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::Mittente(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);

    let shared = sender.diffie_hellman(recipient)?;
    let key = derive_key(&shared, &nonce, &aad, recipient)?;

    // Il timestamp viaggia in testa al plaintext, quindi dentro il cifrato.
    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN.saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Cifra con **mittente effimero**: la chiave nell'header e' usa-e-getta e la
/// tua identita' non compare in chiaro.
///
/// La chiave AEAD nasce da due scambi messi insieme:
///
/// ```text
/// segreto = DH(effimera, destinatario) || DH(mittente, destinatario)
/// ```
///
/// Il primo da' la mezza forward secrecy: l'effimera viene buttata subito,
/// quindi chi domani ottiene la tua chiave stabile non riapre i messaggi di
/// ieri. Il secondo e' la prova d'identita': solo chi possiede la privata del
/// mittente puo' produrre quel segreto, quindi il fatto stesso che la
/// decifratura riesca dimostra chi ha scritto — **senza firme**, che
/// richiederebbero una primitiva in piu' e un campo da verificare.
///
/// Resta scoperto il caso opposto: chi ottiene la chiave del **destinatario**
/// apre tutto lo stesso, perche' entrambi gli scambi passano da li'. Per
/// quello serve una chiave temporanea anche dal lato di chi riceve, che e' una
/// decisione a parte.
pub fn seal_ephemeral<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = sigilla_effimero(
        Kind::Message,
        sender,
        recipient,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// [`seal_ephemeral`] per un allegato: stessa derivazione, framing binario.
pub fn seal_file_ephemeral<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = sigilla_effimero(
        Kind::File,
        sender,
        recipient,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_file(&header, &ciphertext))
}

/// Il corpo comune. `kind` entra nell'AAD, quindi un allegato non puo' essere
/// riletto come messaggio ne' viceversa.
#[allow(clippy::too_many_arguments)]
fn sigilla_effimero<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let effimera = Ephemeral::generate(rng)?;

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::Effimera(effimera.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_ephemeral_key(
        &*effimera.diffie_hellman(recipient)?,
        &*sender.diffie_hellman(recipient)?,
        &nonce,
        &aad,
        recipient,
    )?;

    // La prekey viaggia anche qui, ed e' cio' che fa **partire** la catena:
    // senza, chi riceve non avrebbe mai una nostra chiave temporanea da usare,
    // e la forward secrecy piena non comincerebbe mai. Sta dentro il cifrato
    // perche' va autenticata: in chiaro, chiunque potrebbe sostituirla e
    // dirottare tutta la conversazione successiva.
    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_prekey.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Prova ad aprire un messaggio a mittente effimero **supponendo** che l'abbia
/// scritto `candidato`.
///
/// Chi riceve non sa chi ha scritto: chiama questa per ciascuno dei propri
/// contatti finche' una riesce. Il fallimento e' [`Error::Crypto`] come
/// qualunque altro, e non distingue "non e' lui" da "messaggio corrotto" —
/// distinguerli darebbe a chi attacca un oracolo su chi c'e' nel keyring.
pub fn open_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_effimero(Kind::Message, recipient, candidato, parsed)
}

/// [`open_ephemeral`] per un allegato.
pub fn open_file_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_effimero(Kind::File, recipient, candidato, parsed)
}

fn apri_effimero(
    kind: Kind,
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    let Origin::Effimera(effimera) = &parsed.header.origin else {
        return Err(Error::Crypto);
    };
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_ephemeral_key(
        &*recipient.diffie_hellman(effimera)?,
        &*recipient.diffie_hellman(candidato)?,
        &parsed.header.nonce,
        &aad,
        &recipient.public(),
    )?;

    let aperto = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );
    stacca_prekey(&aperto)
}

/// Separa timestamp, prekey del mittente e testo.
fn stacca_prekey(aperto: &[u8]) -> Result<(PublicKey, Plaintext)> {
    let inizio = TIMESTAMP_LEN;
    let fine = inizio.saturating_add(KEY_LEN);
    let chiave = aperto
        .get(inizio..fine)
        .ok_or(Error::Format("plaintext senza prekey: mittente malformato"))?;
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(chiave);

    let mut senza = Zeroizing::new(Vec::with_capacity(aperto.len()));
    senza.extend_from_slice(aperto.get(..inizio).unwrap_or(&[]));
    senza.extend_from_slice(aperto.get(fine..).unwrap_or(&[]));
    Ok((PublicKey::from_bytes(bytes), stacca_timestamp(&senza)?))
}

/// Cifra con **forward secrecy piena**: effimera del mittente e chiave
/// temporanea del destinatario.
///
/// ```text
/// segreto = DH(effimera, prekey) || DH(mittente, prekey)
/// ```
///
/// Entrambi gli scambi passano dalla **prekey del destinatario**. Quando lui la
/// butta, il messaggio non lo apre piu' nessuno: ne' un avversario che abbia le
/// chiavi stabili di tutti e due, ne' lui stesso. E' la forward secrecy vera, e
/// il prezzo e' che **la cronologia non si rilegge** (decisione I).
///
/// Il secondo scambio resta la prova d'identita': solo chi ha la privata del
/// mittente lo puo' produrre.
///
/// `mia_prekey` viaggia **dentro** il cifrato, in testa al plaintext: e' la
/// chiave con cui il destinatario rispondera', e va autenticata — se viaggiasse
/// in chiaro, chiunque potrebbe sostituirla e dirottare la conversazione
/// successiva.
pub fn seal_forward<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = sigilla_avanti(
        Kind::Message,
        sender,
        recipient,
        prekey_destinatario,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// [`seal_forward`] per un allegato.
#[allow(clippy::too_many_arguments)]
pub fn seal_file_forward<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = sigilla_avanti(
        Kind::File,
        sender,
        recipient,
        prekey_destinatario,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_file(&header, &ciphertext))
}

#[allow(clippy::too_many_arguments)]
fn sigilla_avanti<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let effimera = Ephemeral::generate(rng)?;

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::EffimeraConPrekey(effimera.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_ephemeral_key(
        &*effimera.diffie_hellman(prekey_destinatario)?,
        &*sender.diffie_hellman(prekey_destinatario)?,
        &nonce,
        &aad,
        recipient,
    )?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_prekey.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Prova ad aprire un messaggio a forward secrecy piena, supponendo che
/// l'abbia scritto `candidato` e che abbia usato la nostra prekey `mia_prekey`.
///
/// Ritorna anche la **prossima prekey del mittente**, presa da dentro il
/// cifrato: e' quella con cui rispondere, ed e' autenticata dall'AEAD.
pub fn open_forward(
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_avanti(Kind::Message, mia_prekey, candidato, destinatario, parsed)
}

/// [`open_forward`] per un allegato.
pub fn open_file_forward(
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_avanti(Kind::File, mia_prekey, candidato, destinatario, parsed)
}

fn apri_avanti(
    kind: Kind,
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    let Origin::EffimeraConPrekey(effimera) = &parsed.header.origin else {
        return Err(Error::Crypto);
    };
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_ephemeral_key(
        &*mia_prekey.diffie_hellman(effimera)?,
        &*mia_prekey.diffie_hellman(candidato)?,
        &parsed.header.nonce,
        &aad,
        destinatario,
    )?;

    let aperto = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    // Timestamp, poi la prekey del mittente, poi il testo. Tutto autenticato:
    // se qui manca qualcosa e' il mittente ad aver prodotto un plaintext
    // malformato, non un attacco.
    stacca_prekey(&aperto)
}

/// Come [`derive_key`], ma il materiale iniziale sono i due segreti in fila.
///
/// Concatenati e non sommati o mescolati: HKDF e' fatto per prendere materiale
/// grezzo di lunghezza qualunque, e qualsiasi combinazione inventata qui
/// sarebbe una primitiva nuova senza motivo.
fn derive_ephemeral_key(
    dh_effimero: &[u8; 32],
    dh_statico: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let mut materiale = Zeroizing::new(Vec::with_capacity(64));
    materiale.extend_from_slice(dh_effimero);
    materiale.extend_from_slice(dh_statico);

    let mut info = Vec::with_capacity(
        KDF_DOMAIN
            .len()
            .saturating_add(aad.len())
            .saturating_add(recipient.as_bytes().len()),
    );
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(aad);
    info.extend_from_slice(recipient.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &materiale);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(key)
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
    open_inner(Kind::Message, recipient, sender_pub, parsed)
}

/// Inverte [`seal_file`]. Vedi [`open`] per tutto il resto: cambia solo il
/// `kind`, che essendo nell'AAD rende i due percorsi non intercambiabili.
pub fn open_file(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    open_inner(Kind::File, recipient, sender_pub, parsed)
}

/// Cifra **a epoca** (decisione J): chiave del mittente in chiaro, cifrato
/// verso la chiave d'epoca del destinatario.
///
/// Niente effimera, ed e' il punto: senza, la derivazione si puo' rifare, e
/// quindi il messaggio si rilegge — anche da chi l'ha scritto. La riservatezza
/// non viene dal tempo ma da un gesto: quando una delle due chiavi d'epoca
/// viene distrutta, quel messaggio non si apre piu' da quel lato.
///
/// `mia_epoca` viaggia dentro il cifrato come nelle altre modalita': e' cosi'
/// che l'altro sa verso quale chiave scriverci.
pub fn seal_epoch<R: RngCore + CryptoRng>(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_a_epoca(
        Kind::Message,
        sender,
        epoca_destinatario,
        mia_epoca,
        plaintext,
        now_unix,
        rng,
    )
}

/// Una richiesta di rogo verso la chiave d'epoca dell'altro. Stessa
/// derivazione, `kind` diverso — e `kind` sta nell'AAD, quindi un rogo non e'
/// un messaggio travestito ne' viceversa.
#[allow(clippy::too_many_arguments)]
pub fn seal_burn_epoch<R: RngCore + CryptoRng>(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_a_epoca(
        Kind::Burn,
        sender,
        epoca_destinatario,
        mia_epoca,
        &[],
        now_unix,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn sigilla_a_epoca<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::MittenteConPrekey(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_key(
        &*sender.diffie_hellman(epoca_destinatario)?,
        &nonce,
        &aad,
        epoca_destinatario,
    )?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_epoca.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Apre un messaggio a epoca **ricevuto**: serve la nostra chiave d'epoca.
///
/// Distruggendola, questo smette di funzionare per sempre. E' l'unica cosa
/// che rende la cancellazione reale invece che cosmetica.
pub fn open_epoch(
    mia_epoca: &EphemeralSecret,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca(
        &*mia_epoca.diffie_hellman(mittente)?,
        &mia_epoca.public(),
        parsed,
    )
}

/// Apre un messaggio a epoca **che abbiamo scritto noi**, con la chiave
/// d'epoca del destinatario che avevamo conservato.
///
/// Quando la buttiamo, non rileggiamo piu' cio' che gli abbiamo mandato: e' la
/// meta' del "brucia" che riguarda noi.
pub fn open_epoch_as_sender(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca(
        &*sender.diffie_hellman(epoca_destinatario)?,
        epoca_destinatario,
        parsed,
    )
}

fn apri_epoca(
    shared: &[u8; KEY_LEN],
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if !parsed.header.origin.uses_epoch() {
        return Err(Error::Crypto);
    }
    apri_epoca_con(Kind::Message, shared, epoca_destinatario, parsed)
}

fn apri_epoca_con(
    kind: Kind,
    shared: &[u8; KEY_LEN],
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_key(shared, &parsed.header.nonce, &aad, epoca_destinatario)?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_prekey(&inner)
}

/// Il **primo** messaggio di una conversazione a epoca: cifrato verso
/// l'identita' del destinatario, come lo schema statico, ma porta la nostra
/// chiave d'epoca dentro il cifrato.
///
/// E' cio' che fa partire la conversazione senza handshake, e resta
/// rileggibile da entrambi — al contrario del ripiego effimero, che sarebbe
/// stato la scelta ovvia e avrebbe reso non rileggibile proprio il primo
/// messaggio di ogni conversazione.
pub fn seal_epoch_bootstrap<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_verso_identita(
        Kind::Message,
        sender,
        recipient,
        mia_epoca,
        plaintext,
        now_unix,
        rng,
    )
}

/// Apre un bootstrap a epoca **ricevuto**: serve solo la nostra identita'.
pub fn open_epoch_bootstrap(
    recipient: &Identity,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(
        Kind::Message,
        &*recipient.diffie_hellman(mittente)?,
        &recipient.public(),
        parsed,
    )
}

/// Apre un bootstrap a epoca **che abbiamo scritto noi**.
pub fn open_epoch_bootstrap_as_sender(
    sender: &Identity,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(
        Kind::Message,
        &*sender.diffie_hellman(destinatario)?,
        destinatario,
        parsed,
    )
}

#[allow(clippy::too_many_arguments)]
fn sigilla_verso_identita<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::MittenteConEpoca(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_key(&*sender.diffie_hellman(recipient)?, &nonce, &aad, recipient)?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_epoca.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok((header, ciphertext))
}

/// La richiesta di rogo quando non abbiamo una chiave d'epoca dell'altro:
/// cifrata verso la sua identita', che abbiamo sempre.
///
/// Serve al caso in cui abbiamo gia' bruciato noi per primi e vogliamo comunque
/// chiederglielo. Porta la nostra chiave d'epoca nuova, cosi' la conversazione
/// puo' ripartire subito dopo.
pub fn seal_burn_static<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_verso_identita(Kind::Burn, sender, recipient, mia_epoca, &[], now_unix, rng)
}

/// Verifica una richiesta di rogo arrivata nello schema statico.
pub fn open_burn_static(
    recipient: &Identity,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_rogo(
        &*recipient.diffie_hellman(mittente)?,
        &recipient.public(),
        parsed,
    )
}

/// Verifica una richiesta di rogo cifrata verso la nostra chiave d'epoca.
pub fn open_burn_epoch(
    mia_epoca: &EphemeralSecret,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_rogo(
        &*mia_epoca.diffie_hellman(mittente)?,
        &mia_epoca.public(),
        parsed,
    )
}

fn apri_rogo(
    shared: &[u8; KEY_LEN],
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(Kind::Burn, shared, destinatario, parsed)
}

/// Riapre un messaggio **che abbiamo scritto noi**, provando `recipient` come
/// destinatario.
///
/// Funziona perche' il segreto ECDH e' simmetrico: chi cifra ha la propria
/// privata e la pubblica dell'altro, cioe' esattamente cio' che serve a rifare
/// la stessa chiave. Non e' una scorciatoia e non indebolisce niente — chi ha
/// la nostra privata puo' farlo comunque, ed e' precisamente la proprieta' che
/// la forward secrecy spenta non promette.
///
/// **Vale solo senza forward secrecy.** Con la catena accesa la chiave
/// usa-e-getta e' stata distrutta subito dopo aver cifrato, e questo non ha
/// nessun equivalente: e' il senso dell'interruttore.
///
/// Chi era il destinatario non e' scritto da nessuna parte, quindi il chiamante
/// prova i propri contatti — come fa gia' per i mittenti effimeri.
pub fn open_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    apri_come_mittente(Kind::Message, sender, recipient, parsed)
}

/// [`open_as_sender`] per un allegato. Un messaggio nostro si rilegge e una
/// foto nostra no sarebbe una differenza che nessuno saprebbe spiegare.
pub fn open_file_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    apri_come_mittente(Kind::File, sender, recipient, parsed)
}

fn apri_come_mittente(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let shared = sender.diffie_hellman(recipient)?;
    let key = derive_key(&shared, &parsed.header.nonce, &aad, recipient)?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_timestamp(&inner)
}

fn open_inner(
    kind: Kind,
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

    let aad = format::build_aad(kind, &parsed.header);
    let shared = recipient.diffie_hellman(sender_pub)?;
    let key = derive_key(&shared, &parsed.header.nonce, &aad, &recipient.public())?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_timestamp(&inner)
}

/// Separa il timestamp dal testo, in coda a una decifratura riuscita.
///
/// Il tag ha gia' autenticato tutto: se qui manca il timestamp e' il mittente
/// ad aver prodotto un plaintext malformato, non un attacco.
fn stacca_timestamp(inner: &[u8]) -> Result<Plaintext> {
    let stampa = inner.get(..TIMESTAMP_LEN).ok_or(Error::Format(
        "plaintext senza timestamp: mittente malformato",
    ))?;
    let mut bytes = [0u8; TIMESTAMP_LEN];
    bytes.copy_from_slice(stampa);
    let testo = inner.get(TIMESTAMP_LEN..).unwrap_or(&[]).to_vec();

    Ok(Plaintext {
        testo: Zeroizing::new(testo),
        sent_at_unix: i64::from_le_bytes(bytes),
    })
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
            .sender_pub()
            .ok_or(Error::Format("sender_pub assente"))?;
        open(destinatario, sender, &parsed)
    }

    #[test]
    fn round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let messaggio = b"ciao, questo non lo legge la piattaforma";

        let testo = seal(&alice, &bob.public(), messaggio, 1_700_000_000, &mut rng(9)).unwrap();
        assert!(testo.starts_with(SENTINEL));
        assert_eq!(apri(&bob, &testo).unwrap().as_bytes(), messaggio);
    }

    #[test]
    fn plaintext_vuoto_e_lungo() {
        let alice = identita(3);
        let bob = identita(4);

        for messaggio in [vec![], vec![0xAAu8; 4096]] {
            let testo = seal(&alice, &bob.public(), &messaggio, 1_700_000_000, &mut rng(1)).unwrap();
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

        let uno = seal(&alice, &bob.public(), b"stesso testo", 1_700_000_000, &mut r).unwrap();
        let due = seal(&alice, &bob.public(), b"stesso testo", 1_700_000_000, &mut r).unwrap();
        assert_ne!(uno, due);
    }

    #[test]
    fn destinatario_sbagliato() {
        let alice = identita(7);
        let bob = identita(8);
        let carol = identita(9);

        let testo = seal(&alice, &bob.public(), b"per bob", 1_700_000_000, &mut rng(3)).unwrap();
        assert!(matches!(apri(&carol, &testo), Err(Error::Crypto)));
    }

    #[test]
    fn mittente_dichiarato_sbagliato() {
        let alice = identita(10);
        let bob = identita(11);
        let mallory = identita(12);

        let testo = seal(&alice, &bob.public(), b"da alice", 1_700_000_000, &mut rng(4)).unwrap();
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
    /// Il giro completo dello schema a mittente effimero.
    #[test]
    fn effimero_round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let mia = prekey(4);
        let blob =
            seal_ephemeral(&alice, &bob.public(), &mia.public(), b"ciao", 99, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        let (prekey_ricevuta, aperto) = open_ephemeral(&bob, &alice.public(), &parsed).unwrap();
        assert_eq!(aperto.as_bytes(), b"ciao");
        assert_eq!(aperto.sent_at_unix(), 99);
        // Anche il messaggio a meta' porta la prekey: e' cosi' che la catena
        // parte, altrimenti la forward secrecy piena non comincerebbe mai.
        assert_eq!(prekey_ricevuta, mia.public());
    }

    /// La chiave di Alice non compare da nessuna parte in chiaro: e' cio' che
    /// toglie la correlabilita' fra i suoi messaggi.
    #[test]
    fn effimero_non_mostra_il_mittente() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let blob = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        assert!(parsed.header.sender_pub().is_none());
        assert!(parsed.header.origin.is_ephemeral());
        let effimera = parsed.header.origin.key().unwrap();
        assert_ne!(effimera, &alice.public());
        assert!(!buf.windows(32).any(|w| w == alice.public().as_bytes()));
    }

    /// Provare con la chiave sbagliata fallisce: e' cio' che rende la
    /// decifratura a tentativi una prova d'identita' e non un'ipotesi.
    #[test]
    fn effimero_col_candidato_sbagliato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let carol = identita(3);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let blob = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        assert!(matches!(
            open_ephemeral(&bob, &carol.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Due messaggi identici non producono lo stesso blob, e nemmeno la stessa
    /// chiave effimera: se si ripetesse, la forward secrecy non ci sarebbe.
    #[test]
    fn effimero_ogni_messaggio_ha_la_sua_chiave() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let uno = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        let due = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        assert_ne!(uno, due);

        let (mut a, mut b) = (Vec::new(), Vec::new());
        let ParsedBlob::Message(p1) = format::parse(&uno, &mut a).unwrap() else { panic!() };
        let ParsedBlob::Message(p2) = format::parse(&due, &mut b).unwrap() else { panic!() };
        assert_ne!(p1.header.origin.key(), p2.header.origin.key());
    }

    /// Un messaggio effimero non si apre con la strada normale, e viceversa:
    /// i flag entrano nell'AAD, quindi le due forme non sono intercambiabili.
    #[test]
    fn effimero_e_normale_non_si_scambiano() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);

        let effimero = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&effimero, &mut buf).unwrap() else {
            panic!()
        };
        assert!(matches!(open(&bob, &alice.public(), &parsed), Err(Error::Crypto)));

        let normale = seal(&alice, &bob.public(), b"ciao", 1, &mut rng).unwrap();
        let mut buf2 = Vec::new();
        let ParsedBlob::Message(p2) = format::parse(&normale, &mut buf2).unwrap() else {
            panic!()
        };
        assert!(matches!(
            open_ephemeral(&bob, &alice.public(), &p2),
            Err(Error::Crypto)
        ));
    }

    fn prekey(seed: u8) -> EphemeralSecret {
        EphemeralSecret::from_bytes([seed; 32])
    }

    /// Giro completo della forward secrecy piena, con la prekey di risposta
    /// che torna dal cifrato.
    #[test]
    fn forward_round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let prekey_bob = prekey(9);
        let prekey_alice = prekey(8);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);

        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey_alice.public(),
            b"ciao",
            77,
            &mut rng,
        )
        .unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        let (prossima, aperto) =
            open_forward(&prekey_bob, &alice.public(), &bob.public(), &parsed).unwrap();
        assert_eq!(aperto.as_bytes(), b"ciao");
        assert_eq!(aperto.sent_at_unix(), 77);
        // La prekey con cui Bob rispondera' e' quella che Alice ha messo dentro
        // il cifrato, quindi autenticata: nessuno ha potuto sostituirla.
        assert_eq!(prossima, prekey_alice.public());
    }

    /// **La proprieta' che giustifica tutto.** Senza la prekey del destinatario
    /// il messaggio non si apre — nemmeno avendo entrambe le chiavi stabili.
    #[test]
    fn buttata_la_prekey_il_messaggio_e_morto() {
        let alice = identita(1);
        let bob = identita(2);
        let prekey_bob = prekey(9);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey(8).public(),
            b"segreto",
            1,
            &mut rng,
        )
        .unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        // Bob ha buttato quella prekey e ne ha un'altra: la sua identita' non
        // basta piu'.
        let altra = prekey(77);
        assert!(matches!(
            open_forward(&altra, &alice.public(), &bob.public(), &parsed),
            Err(Error::Crypto)
        ));
        // E nemmeno la strada senza prekey funziona, perche' i flag stanno
        // nell'AAD.
        assert!(matches!(
            open_ephemeral(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
        assert!(matches!(
            open(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Il mittente resta dimostrato: con il candidato sbagliato non si apre.
    #[test]
    fn forward_col_candidato_sbagliato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let carol = identita(3);
        let prekey_bob = prekey(9);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey(8).public(),
            b"ciao",
            1,
            &mut rng,
        )
        .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        assert!(matches!(
            open_forward(&prekey_bob, &carol.public(), &bob.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn ogni_bit_flip_e_intercettato() {
        let alice = identita(13);
        let bob = identita(14);
        let testo = seal(&alice, &bob.public(), b"integro", 1_700_000_000, &mut rng(5)).unwrap();

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
        let testo = seal(&alice, &bob.public(), b"tier baseline", 1_700_000_000, &mut rng(6)).unwrap();

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
                matches!(seal(&alice, &peer, b"x", 1_700_000_000, &mut rng(7)), Err(Error::Crypto)),
                "pubkey degenere accettata: {bytes:02x?}"
            );
        }
    }

    /// Il timestamp sopravvive al giro ed e' autenticato: alterarlo richiede
    /// alterare il ciphertext, che il tag intercetta.
    #[test]
    fn timestamp_autenticato_e_recuperato() {
        let alice = identita(20);
        let bob = identita(21);
        let quando = 1_735_689_600i64; // 2025-01-01

        let testo = seal(&alice, &bob.public(), b"con data", quando, &mut rng(11)).unwrap();
        let aperto = apri(&bob, &testo).unwrap();
        assert_eq!(aperto.as_bytes(), b"con data");
        assert_eq!(aperto.sent_at_unix(), quando);
    }

    /// Il timestamp non allunga il blob piu' di quanto dichiara: 8 byte, non
    /// un campo a lunghezza variabile che sposterebbe le lunghezze in modo
    /// dipendente dal contenuto.
    #[test]
    fn il_timestamp_costa_otto_byte() {
        let alice = identita(22);
        let bob = identita(23);

        let corto = seal(&alice, &bob.public(), b"", 0, &mut rng(12)).unwrap();
        let payload = corto.strip_prefix(SENTINEL).unwrap();
        let body = crate::encoding::decode(payload).unwrap();
        let atteso = crate::format::MESSAGE_PREFIX_LEN
            + crate::keys::KEY_LEN
            + NONCE_LEN
            + TIMESTAMP_LEN
            + TAG_LEN;
        assert_eq!(body.len(), atteso);
    }

    /// Un timestamp assurdo non e' un errore: nessuno puo' dimostrare che
    /// l'orologio del mittente fosse giusto, e rifiutare un messaggio per una
    /// data strana significherebbe rendere il sistema inutilizzabile a chi ha
    /// l'ora sbagliata sul telefono.
    #[test]
    fn timestamp_assurdo_non_e_un_errore() {
        let alice = identita(24);
        let bob = identita(25);

        for quando in [i64::MIN, -1, 0, i64::MAX] {
            let testo = seal(&alice, &bob.public(), b"x", quando, &mut rng(13)).unwrap();
            assert_eq!(apri(&bob, &testo).unwrap().sent_at_unix(), quando);
        }
    }

    /// Ancora di regressione: identita' e nonce fissi devono produrre sempre
    /// la stessa stringa. Se si rompe, e' cambiato il formato sul filo o la
    /// derivazione della chiave — cioe' la compatibilita' — non il codice.
    #[test]
    fn kat_baseline() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let bob = Identity::from_secret_bytes([0x22; 32]).unwrap();
        let testo = seal(&alice, &bob.public(), b"kat", 1_700_000_000, &mut rng(0)).unwrap();
        assert_eq!(testo, KAT_BASELINE);
        assert_eq!(apri(&bob, KAT_BASELINE).unwrap().as_bytes(), b"kat");
    }

    const KAT_BASELINE: &str = "kc/yryyyym5j4ejzxu993nce3pnrybz4arqhpcjxwa69f3xy95wtrsmb739np5mtafpwdau5rnymiiqkwhgzwwm5wo3znoe55e4w7jg53deymgkw548czgbcg9oe759w8g6shbp8mx46g5y";
}
