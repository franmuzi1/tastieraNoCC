//! Identita', chiavi, keyring TOFU.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Lunghezza di una chiave X25519, pubblica o privata.
pub const KEY_LEN: usize = 32;

/// Chiave pubblica X25519. Sicura da mostrare e serializzare.
///
/// Wrapper opaco sui 32 byte grezzi: il tipo della crate crypto non trapela
/// nell'API pubblica, cosi' cambiarla non e' un breaking change.
///
/// NOTA: non c'e' validazione qui, ed e' corretto — X25519 accetta qualunque
/// sequenza di 32 byte. Il controllo che serve non e' sulla chiave ma sul
/// RISULTATO dello scambio: una pubkey di ordine basso produce un segreto
/// condiviso tutto zero, uguale per chiunque. Va rifiutato in `baseline`, dopo
/// il Diffie-Hellman, non qui.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Chiave privata X25519. Mai `Debug`/`Display`/`Serialize` in chiaro:
/// l'assenza di quelle impl e' deliberata, non una dimenticanza.
/// `StaticSecret` azzera il proprio contenuto quando viene rilasciata.
///
/// A riposo viene persistita cifrata; la chiave di storage vive in Android
/// Keystore, fuori da questo crate.
pub struct SecretKey(StaticSecret);

/// La nostra identita': coppia long-term. Una sola, valida verso tutti i
/// destinatari — non esiste una chiave per contatto.
pub struct Identity {
    secret: SecretKey,
    public: PublicKey,
}

impl Identity {
    /// Genera una nuova identita' dall'RNG fornito.
    ///
    /// L'RNG e' un parametro, non una globale: serve a rendere i test
    /// deterministici e i vettori riproducibili. In produzione il chiamante
    /// passa il CSPRNG dell'OS; mai un PRNG seedato in-app.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Result<Self> {
        let secret = StaticSecret::random_from_rng(rng);
        Ok(Self::from_static_secret(secret))
    }

    /// Ricostruisce un'identita' da materiale di chiave gia' persistito.
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Result<Self> {
        Ok(Self::from_static_secret(StaticSecret::from(bytes)))
    }

    fn from_static_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from_bytes(XPublicKey::from(&secret).to_bytes());
        Self {
            secret: SecretKey(secret),
            public,
        }
    }

    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public)
    }

    /// Segreto condiviso X25519 con `peer`.
    ///
    /// Interno al crate: il tipo della crate crypto non deve comparire
    /// nell'API pubblica, e il controllo qui sotto non deve poter essere
    /// saltato da un chiamante che faccia il DH per conto proprio.
    ///
    /// RIFIUTA i punti di ordine basso. Non e' pedanteria: una pubkey di
    /// ordine basso produce un segreto condiviso tutto zero, identico per
    /// CHIUNQUE la usi. Chi la spedisce come `sender_pub` ottiene una chiave
    /// AEAD che qualsiasi altro puo' derivare. X25519 non lo impedisce da
    /// solo — accetta qualunque sequenza di 32 byte — quindi il controllo va
    /// fatto sul risultato, ed e' qui l'unico punto in cui puo' stare.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.secret.0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// Domain separation del fingerprint. Congelato.
const FINGERPRINT_DOMAIN: &[u8] = b"keyboard-cipher/v1/fingerprint";

/// 120 bit, cioe' 24 caratteri z-base-32 in 6 gruppi da 4.
pub const FINGERPRINT_LEN: usize = 15;

/// Impronta stabile di una pubkey, per la verifica manuale fuori banda.
///
/// SHA-256 con domain separation, troncata a 120 bit, resa in z-base-32 a
/// gruppi di 4. **Una volta rilasciato questo formato non cambia piu'**: e' cio'
/// che due persone si leggono a voce o confrontano a schermo, e cambiarlo
/// invaliderebbe ogni verifica gia' fatta.
///
/// Perche' 120 e non 96. La proprieta' vincolante e' la resistenza alla
/// SECONDA PREIMMAGINE: per farsi passare per Bob, un attaccante deve produrre
/// una chiave il cui fingerprint eguagli quello di Bob, che e' fisso e non
/// scelto da lui. La' 96 bit sono gia' abbondanti. Ma la resistenza alle
/// COLLISIONI e' meta' della lunghezza, e 48 bit sono alla portata di chiunque
/// abbia delle GPU. Oggi nessun flusso dipende dalle collisioni, perche' il pin
/// memorizza la chiave intera e non il fingerprint — ma il formato e' per
/// sempre e una UI futura potrebbe appoggiarcisi senza accorgersene. Il margine
/// costa quattro caratteri.
///
/// Niente wordlist: manutenzione, localizzazione e ambiguita' fonetiche non
/// valgono il guadagno, e l'alfabeto z-base-32 e' gia' scelto per non essere
/// ambiguo a occhio.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    pub fn of(public: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(public.as_bytes());
        let digest = hasher.finalize();

        let mut out = [0u8; FINGERPRINT_LEN];
        // SHA-256 produce 32 byte e FINGERPRINT_LEN e' 15: il taglio esiste.
        if let Some(head) = digest.get(..FINGERPRINT_LEN) {
            out.copy_from_slice(head);
        }
        Self(out)
    }

    /// Rappresentazione da mostrare all'utente: 24 caratteri in 6 gruppi da 4.
    /// I gruppi servono a rendere possibile il confronto a occhio, che senza
    /// non si fa.
    pub fn display(&self) -> String {
        let encoded = crate::encoding::encode(&self.0);
        let mut out = String::with_capacity(encoded.len().saturating_add(5));
        for (i, c) in encoded.chars().enumerate() {
            if i != 0 && i.checked_rem(4) == Some(0) {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }
}

/// Record TOFU per un peer.
pub struct PeerRecord {
    pub public: PublicKey,
    /// Solo per audit e UX. Non ha alcun ruolo di sicurezza.
    pub first_seen_unix: i64,
    /// `true` se l'utente ha confrontato il fingerprint fuori banda.
    pub verified: bool,
}

/// Esito di un tentativo di pin. Il conflitto NON e' un `Err`: e' uno stato
/// legittimo che richiede una decisione dell'utente, quindi deve poter
/// risalire alla UI senza passare per il canale d'errore.
pub enum PinOutcome {
    /// Peer mai visto prima: fissato ora.
    Pinned,
    /// Gia' presente con la stessa chiave: nessuna azione.
    AlreadyPinned,
    /// Gia' presente con chiave DIVERSA. Possibile MITM, oppure il peer ha
    /// semplicemente reinstallato. Modello "safety number changed" di Signal:
    /// mostrare entrambi i fingerprint e chiedere conferma esplicita.
    /// Finche' l'utente non conferma, la vecchia chiave resta quella fissata.
    Conflict {
        existing: Fingerprint,
        incoming: Fingerprint,
    },
}

/// Keyring TOFU. Lo storage cifrato sta fuori dal core; qui c'e' solo
/// l'astrazione contro cui il core lavora.
///
/// Object-safe di proposito: il layer Android lo usera' dietro `dyn Keyring`.
/// Niente `-> impl Iterator` nei metodi, che romperebbe la object safety.
pub trait Keyring {
    /// Registra il peer se nuovo. Non sovrascrive mai in silenzio: su chiave
    /// diversa ritorna [`PinOutcome::Conflict`] e lascia intatto il record.
    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome>;

    /// Sostituisce la chiave fissata dopo una conferma ESPLICITA dell'utente.
    /// Unico punto in cui un pin puo' essere sovrascritto. Non chiamarlo mai
    /// in automatico dopo un [`PinOutcome::Conflict`].
    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()>;

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>>;

    /// Marca un peer come verificato fuori banda (fingerprint confrontato).
    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()>;
}

#[cfg(test)]
mod tests {
    // - generate() con RNG a seme fisso e' riproducibile
    // - SecretKey non implementa Debug/Display/Serialize (test di compilazione)
    // - fingerprint stabile: vettore congelato pubkey -> stringa
    // - tofu_pin: nuovo -> Pinned; stesso -> AlreadyPinned; diverso -> Conflict
    // - dopo un Conflict il record memorizzato NON e' cambiato
}
