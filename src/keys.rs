//! Identita', chiavi, keyring TOFU.

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
        todo!()
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

/// Impronta stabile di una pubkey, per la verifica manuale fuori banda.
///
/// DECISIONE D (aperta, vedi CLAUDE.md): proposta corrente SHA-256 con domain
/// separation, troncata a 96 bit, resa in z-base-32 a gruppi di 4 caratteri.
/// 96 bit sta sopra il minimo ragionevole per un confronto a voce o a occhio.
/// Niente wordlist: manutenzione, localizzazione e ambiguita' fonetiche non
/// valgono il guadagno. Una volta rilasciato, questo formato non cambia piu'.
#[derive(Clone, PartialEq, Eq)]
pub struct Fingerprint(/* [u8; 12] */);

impl Fingerprint {
    pub fn of(public: &PublicKey) -> Self {
        todo!()
    }

    /// Rappresentazione da mostrare all'utente, gia' raggruppata.
    pub fn display(&self) -> String {
        todo!()
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
