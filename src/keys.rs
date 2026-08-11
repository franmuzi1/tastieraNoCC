//! Identita', chiavi, keyring TOFU.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

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

    /// I byte grezzi del segreto, per il **solo** backup cifrato.
    ///
    /// `pub(crate)` e non `pub`, ed e' una distinzione che vale la pena
    /// difendere: fuori da questo crate non esiste alcun modo di estrarre la
    /// chiave privata da un'`Identity`. Chi la persiste l'ha ricevuta alla
    /// generazione e se l'e' tenuta; da qui in poi non esce piu'.
    ///
    /// L'unico chiamante e' [`crate::backup`], che la cifra con una passphrase
    /// prima che tocchi qualunque cosa. Se un giorno servisse un secondo
    /// chiamante, e' il momento di chiedersi perche'.
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.secret.0.to_bytes())
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

/// Coppia effimera: vive il tempo di cifrare un messaggio e poi sparisce.
///
/// Il segreto non esce mai da qui e viene azzerato alla distruzione: e' cio'
/// che rende il messaggio illeggibile anche a chi domani ottenesse la chiave
/// stabile del mittente. Se questo segreto venisse conservato, la mezza
/// forward secrecy che lo giustifica non ci sarebbe.
pub struct Ephemeral {
    secret: SecretKey,
    public: PublicKey,
}

impl Ephemeral {
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        // Il seme non serve piu': `StaticSecret` ne ha fatto una copia sua.
        bytes.zeroize();
        let public = PublicKey(XPublicKey::from(&secret).to_bytes());
        Ok(Self {
            secret: SecretKey(secret),
            public,
        })
    }

    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.secret.0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// La parte privata di una chiave temporanea, che si conserva finche' serve.
///
/// Esiste separata da [`Ephemeral`] perche' i due usi sono opposti: l'effimera
/// del mittente si butta **subito**, questa il destinatario la tiene finche'
/// non ha letto — e la butta appena letto, ed e' quel gesto a produrre la
/// forward secrecy. Tenerla per sempre significherebbe non averla.
pub struct EphemeralSecret(SecretKey);

impl EphemeralSecret {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretKey(StaticSecret::from(bytes)))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(XPublicKey::from(&self.0 .0).to_bytes())
    }

    /// I byte, per poterla **persistere**. E' l'unico punto in cui una privata
    /// esce dal crate, e vale solo per le temporanee: quella d'identita' non ha
    /// nulla di simile, apposta.
    pub fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0 .0.to_bytes())
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.0 .0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub public: PublicKey,
    /// Nome dato dall'utente. **E' l'identita' di contatto**: senza, due
    /// chiavi diverse sono solo due peer diversi e "la chiave di Marco e'
    /// cambiata" non e' una frase esprimibile.
    ///
    /// `None` finche' l'utente non si pronuncia: il sistema non puo' sapere
    /// chi sia una chiave mai vista.
    pub label: Option<String>,
    /// Solo per audit e UX. Non ha alcun ruolo di sicurezza.
    pub first_seen_unix: i64,
    /// `true` se l'utente ha confrontato il fingerprint fuori banda.
    pub verified: bool,
}

/// Esito di un tentativo di pin.
///
/// Non contiene un caso di conflitto, e non e' una dimenticanza: al momento in
/// cui una chiave mai vista arriva, il sistema non ha modo di sapere se sia un
/// contatto nuovo o un contatto noto che ha cambiato telefono. Solo l'utente
/// lo sa. Il conflitto vive quindi in [`LabelOutcome`], cioe' nel momento in
/// cui l'utente attribuisce un nome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// Peer mai visto prima: fissato ora, senza etichetta.
    Pinned,
    /// Gia' presente con la stessa chiave: nessuna azione.
    AlreadyPinned,
}

/// Esito dell'attribuzione di un'etichetta a una chiave.
///
/// Il conflitto NON e' un `Err`: e' uno stato legittimo che richiede una
/// decisione dell'utente, quindi deve poter risalire alla UI senza passare per
/// il canale d'errore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelOutcome {
    /// Etichetta libera, o gia' di questa stessa chiave.
    Assigned,
    /// **Questa e' la "safety number changed" di Signal.** L'etichetta
    /// appartiene gia' a un'altra chiave: o il contatto ha reinstallato, o
    /// qualcuno si sta interponendo. Mostrare entrambi i fingerprint e chiedere
    /// conferma esplicita. Finche' l'utente non si pronuncia, la vecchia chiave
    /// resta quella etichettata e nulla viene sovrascritto.
    Conflict {
        existing: PublicKey,
        existing_fingerprint: Fingerprint,
        incoming_fingerprint: Fingerprint,
    },
}

/// Keyring TOFU. Lo storage cifrato sta fuori dal core; qui c'e' solo
/// l'astrazione contro cui il core lavora.
///
/// Object-safe di proposito: il layer Android lo usera' dietro `dyn Keyring`.
/// Niente `-> impl Iterator` nei metodi, che romperebbe la object safety.
/// Quante nostre chiavi temporanee si tengono per ogni contatto.
///
/// Non e' un parametro da regolare a gusto: e' **la finestra dentro cui la
/// forward secrecy non c'e' ancora**. Tenerne una sola romperebbe il caso
/// normale — mando due messaggi di fila, l'altro apre il secondo, il primo e'
/// gia' morto — e tenerne molte allungherebbe il periodo in cui un telefono
/// sequestrato apre i messaggi passati. Tre copre i messaggi in viaggio senza
/// diventare un archivio.
pub const MAX_PREKEY_MIE: usize = 3;

/// Lo stato per contatto della catena di forward secrecy.
///
/// Sta nel core, che non fa I/O, perche' e' **struttura dati e basta**: chi la
/// usa la salva come vuole. Il motivo per cui esiste e' che le tre
/// implementazioni di [`Keyring`] — telefono, riga di comando, test — hanno
/// bisogno esattamente della stessa logica, e tre copie di questa logica
/// sarebbero tre modi diversi di sbagliare la parte che decide se un messaggio
/// vecchio si riapre.
///
/// `Vec` e non `HashMap`: [`PublicKey`] non implementa `Hash` apposta.
#[derive(Default)]
pub struct PrekeyStore {
    /// L'ultima chiave temporanea che il peer ci ha mandato. Pubblica.
    loro: Vec<(PublicKey, PublicKey)>,
    /// Le nostre, private, dalla piu' recente. Azzerate quando cadono.
    mie: Vec<(PublicKey, Vec<Zeroizing<[u8; KEY_LEN]>>)>,
}

impl PrekeyStore {
    pub fn peer_prekey(&self, peer: &PublicKey) -> Option<PublicKey> {
        self.loro
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, k)| k.clone())
    }

    pub fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) {
        match self.loro.iter_mut().find(|(p, _)| p == peer) {
            Some((_, k)) => *k = prekey.clone(),
            None => self.loro.push((peer.clone(), prekey.clone())),
        }
    }

    pub fn my_prekeys(&self, peer: &PublicKey) -> Vec<[u8; KEY_LEN]> {
        self.mie
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, v)| v.iter().map(|s| **s).collect())
            .unwrap_or_default()
    }

    pub fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) {
        match self.mie.iter_mut().find(|(p, _)| p == peer) {
            Some((_, v)) => {
                v.insert(0, Zeroizing::new(secret));
                // `truncate` fa cadere le eccedenti, e cadendo si azzerano.
                v.truncate(MAX_PREKEY_MIE);
            }
            None => self.mie.push((peer.clone(), vec![Zeroizing::new(secret)])),
        }
    }

    /// Vedi [`Keyring::drop_my_prekeys_older_than`]. Se la chiave indicata non
    /// c'e' piu' non si butta niente: significa che e' gia' caduta, e trattare
    /// "non trovata" come "buttale tutte" cancellerebbe anche le piu' recenti.
    pub fn drop_my_prekeys_older_than(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) {
        if let Some((_, v)) = self.mie.iter_mut().find(|(p, _)| p == peer) {
            if let Some(i) = v.iter().position(|s| &**s == secret) {
                v.truncate(i.saturating_add(1));
            }
        }
    }

    /// Chi dimentica un contatto deve chiamarla: senza, le chiavi private
    /// temporanee verso quella persona resterebbero su disco dopo che l'utente
    /// ha chiesto di cancellarla.
    pub fn forget(&mut self, peer: &PublicKey) {
        self.loro.retain(|(p, _)| p != peer);
        self.mie.retain(|(p, _)| p != peer);
    }

    /// Per chi deve scrivere lo stato su disco.
    pub fn dump(&self) -> Vec<(PublicKey, Option<PublicKey>, Vec<[u8; KEY_LEN]>)> {
        let mut fuori: Vec<(PublicKey, Option<PublicKey>, Vec<[u8; KEY_LEN]>)> = Vec::new();
        for (peer, loro) in &self.loro {
            fuori.push((peer.clone(), Some(loro.clone()), self.my_prekeys(peer)));
        }
        for (peer, _) in &self.mie {
            if !fuori.iter().any(|(p, _, _)| p == peer) {
                fuori.push((peer.clone(), None, self.my_prekeys(peer)));
            }
        }
        fuori
    }

    /// Per chi lo rilegge. Le nostre chiavi vanno passate dalla piu' recente,
    /// cioe' nell'ordine in cui [`Self::dump`] le ha restituite: l'ordine e'
    /// significativo, e' quello che decide cosa cade.
    pub fn restore(&mut self, peer: &PublicKey, loro: Option<PublicKey>, mie: Vec<[u8; KEY_LEN]>) {
        if let Some(k) = loro {
            self.set_peer_prekey(peer, &k);
        }
        if !mie.is_empty() {
            let mut v: Vec<Zeroizing<[u8; KEY_LEN]>> =
                mie.into_iter().map(Zeroizing::new).collect();
            v.truncate(MAX_PREKEY_MIE);
            match self.mie.iter_mut().find(|(p, _)| p == peer) {
                Some((_, dentro)) => *dentro = v,
                None => self.mie.push((peer.clone(), v)),
            }
        }
    }
}

pub trait Keyring {
    /// Registra il peer se nuovo, senza etichetta.
    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome>;

    /// Attribuisce un nome a una chiave gia' fissata.
    ///
    /// E' qui che il TOFU diventa capace di dire "la chiave di Marco e'
    /// cambiata": se l'etichetta appartiene a un'altra chiave, ritorna
    /// [`LabelOutcome::Conflict`] e **non modifica niente**.
    fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome>;

    /// Sposta etichetta e identita' di contatto dalla vecchia chiave alla
    /// nuova, dopo conferma ESPLICITA dell'utente. Unico punto in cui un pin
    /// puo' essere sovrascritto. Non chiamarlo mai in automatico dopo un
    /// [`LabelOutcome::Conflict`].
    ///
    /// Il flag `verified` NON si eredita: una chiave nuova non e' stata
    /// verificata fuori banda, per definizione.
    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()>;

    /// Dimentica un peer. `Ok(true)` se c'era.
    ///
    /// Non serve al flusso della tastiera — li' dimenticare una chiave non ha
    /// mai senso — ma serve a chi guarda l'elenco dei contatti, che altrimenti
    /// puo' solo allungarsi.
    ///
    /// **Chi la chiama deve aver gia' avvertito l'utente:** si perde il pin, e
    /// il prossimo messaggio da quella persona ricompare come mittente mai
    /// visto e viene rifissato in silenzio. E' indistinguibile da qualcuno che
    /// si spaccia per lei, cioe' si riapre esattamente la finestra che il pin
    /// serviva a chiudere.
    fn forget(&mut self, peer: &PublicKey) -> Result<bool>;

    /// L'ultima chiave temporanea che il peer ci ha mandato, con cui gli si
    /// scrive. `None` finche' non ne ha mandata nessuna.
    fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>>;

    fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()>;

    /// Le nostre chiavi temporanee ancora valide verso quel peer, dalla piu'
    /// recente. Sono privatissime e vanno persistite: senza, un riavvio
    /// renderebbe illeggibili i messaggi gia' in viaggio.
    fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<[u8; KEY_LEN]>>;

    /// Aggiunge una nostra chiave temporanea, tenendo solo le ultime poche.
    fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()>;

    /// Butta le nostre chiavi temporanee piu' vecchie di quella indicata.
    ///
    /// **E' il gesto che produce la forward secrecy**: finche' quelle chiavi
    /// esistono, i messaggi che le usavano restano apribili. Si butta il
    /// vecchio e non tutto, cosi' due messaggi mandati con la stessa chiave
    /// restano leggibili anche se arrivano in ordine sparso — cosa che in un
    /// mezzo fatto di copia-incolla succede spesso.
    fn drop_my_prekeys_older_than(
        &mut self,
        peer: &PublicKey,
        secret: &[u8; KEY_LEN],
    ) -> Result<()>;

    /// Le chiavi fissate, per chi deve provarle tutte.
    ///
    /// Serve ai messaggi a mittente effimero: chi riceve non sa chi ha
    /// scritto, e lo scopre tentando. Ritorna un `Vec` e non un iteratore
    /// perche' il trait deve restare object-safe.
    fn peers(&self) -> Result<Vec<PublicKey>>;

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>>;

    /// Marca un peer come verificato fuori banda (fingerprint confrontato).
    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()>;
}

#[cfg(test)]
// I divieti valgono per il codice di produzione: in un test un panic e' il
// modo in cui si segnala il fallimento.
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PublicKey {
        PublicKey::from_bytes([n; KEY_LEN])
    }

    /// Il caso normale: mando due messaggi di fila, l'altro apre il secondo, e
    /// il primo deve restare apribile. E' la ragione per cui non se ne tiene
    /// una sola.
    #[test]
    fn buttare_il_vecchio_non_e_buttare_tutto() {
        let mut store = PrekeyStore::default();
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.push_my_prekey(&peer(1), [11; KEY_LEN]);
        store.push_my_prekey(&peer(1), [12; KEY_LEN]);

        // La piu' recente per prima: e' l'ordine in cui si prova ad aprire.
        assert_eq!(store.my_prekeys(&peer(1))[0], [12; KEY_LEN]);

        // Arriva un messaggio cifrato con la penultima: cade solo cio' che e'
        // piu' vecchio di lei.
        store.drop_my_prekeys_older_than(&peer(1), &[11; KEY_LEN]);
        assert_eq!(
            store.my_prekeys(&peer(1)),
            vec![[12; KEY_LEN], [11; KEY_LEN]]
        );
    }

    /// Se la chiave indicata e' gia' caduta non si butta niente: trattare "non
    /// trovata" come "buttale tutte" ucciderebbe anche i messaggi in viaggio.
    #[test]
    fn una_chiave_gia_caduta_non_ne_trascina_altre() {
        let mut store = PrekeyStore::default();
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.drop_my_prekeys_older_than(&peer(1), &[99; KEY_LEN]);
        assert_eq!(store.my_prekeys(&peer(1)), vec![[10; KEY_LEN]]);
    }

    #[test]
    fn la_finestra_non_diventa_un_archivio() {
        let mut store = PrekeyStore::default();
        for i in 0..10u8 {
            store.push_my_prekey(&peer(1), [i; KEY_LEN]);
        }
        assert_eq!(store.my_prekeys(&peer(1)).len(), MAX_PREKEY_MIE);
        assert_eq!(store.my_prekeys(&peer(1))[0], [9; KEY_LEN]);
    }

    /// Dimenticare un contatto deve portarsi via anche le chiavi private verso
    /// di lui, altrimenti restano su disco dopo che l'utente ha cancellato.
    #[test]
    fn dimenticare_porta_via_anche_le_chiavi() {
        let mut store = PrekeyStore::default();
        store.set_peer_prekey(&peer(1), &peer(50));
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.set_peer_prekey(&peer(2), &peer(51));

        store.forget(&peer(1));
        assert!(store.peer_prekey(&peer(1)).is_none());
        assert!(store.my_prekeys(&peer(1)).is_empty());
        assert_eq!(store.peer_prekey(&peer(2)), Some(peer(51)));
    }

    /// Un riavvio non deve rendere illeggibili i messaggi gia' in viaggio:
    /// l'ordine sopravvive, ed e' l'ordine che decide cosa cade.
    #[test]
    fn lo_stato_sopravvive_al_giro_su_disco() {
        let mut store = PrekeyStore::default();
        store.set_peer_prekey(&peer(1), &peer(50));
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.push_my_prekey(&peer(1), [11; KEY_LEN]);
        // Un contatto che ci ha scritto ma a cui non abbiamo ancora risposto:
        // ha una chiave loro e nessuna nostra.
        store.set_peer_prekey(&peer(2), &peer(51));
        // E uno a cui abbiamo scritto per primi: nostre e basta.
        store.push_my_prekey(&peer(3), [30; KEY_LEN]);

        let mut riletto = PrekeyStore::default();
        for (chi, loro, mie) in store.dump() {
            riletto.restore(&chi, loro, mie);
        }

        assert_eq!(riletto.peer_prekey(&peer(1)), Some(peer(50)));
        assert_eq!(
            riletto.my_prekeys(&peer(1)),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(riletto.peer_prekey(&peer(2)), Some(peer(51)));
        assert!(riletto.my_prekeys(&peer(2)).is_empty());
        assert!(riletto.peer_prekey(&peer(3)).is_none());
        assert_eq!(riletto.my_prekeys(&peer(3)), vec![[30; KEY_LEN]]);
    }

    // - generate() con RNG a seme fisso e' riproducibile
    // - SecretKey non implementa Debug/Display/Serialize (test di compilazione)
    // - fingerprint stabile: vettore congelato pubkey -> stringa
    // - tofu_pin: nuovo -> Pinned; stesso -> AlreadyPinned
    // - assign_label su etichetta libera -> Assigned
    // - assign_label su etichetta di un'altra chiave -> Conflict
    // - dopo un Conflict il record memorizzato NON e' cambiato
    // - replace_pinned sposta l'etichetta e azzera `verified`
}
