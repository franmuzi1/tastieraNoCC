//! Superficie che il layer JNI chiamera' (confine Rust/JVM).
//!
//! Il crate JNI dipende da questo e contiene i `#[no_mangle] extern "C"`: qui
//! non ce ne sono. La JVM passa e riceve solo plaintext e ciphertext; chiavi
//! private e keyring restano da questa parte del confine.
//!
//! Regola sui segreti: verso la JVM si restituisce `byte[]`, mai `String`.
//! Una `java.lang.String` e' immutabile e non azzerabile, quindi un plaintext
//! che ci finisce dentro resta in heap fino alla GC. Per questo i tipi qui
//! espongono [`Plaintext`] e non `String`.
//!
//! # Perche' il destinatario corrente e' per-app
//!
//! Una tastiera non sa con chi stai parlando: `EditorInfo` le da' il package
//! dell'app, non la conversazione, e non esiste API per saperlo. L'unica cosa
//! che glielo direbbe e' un accessibility service che legge lo schermo, ed e'
//! esclusa: distruggerebbe la premessa del progetto.
//!
//! Quindi il destinatario si stabilisce per approssimazioni, in quest'ordine:
//!
//!   1. implicitamente, decifrando: chi legge un messaggio e poi risponde —
//!      cioe' quasi tutti, quasi sempre — non sceglie mai nulla, ha gia'
//!      scelto leggendo;
//!   2. per memoria, ricordando l'ultimo peer usato in QUELL'app: chi tiene un
//!      contatto per app non tocca mai niente;
//!   3. esplicitamente, dalla toolbar, per il caso multi-contatto nella stessa
//!      app.
//!
//! Il terzo e' il fallback e va progettato come tale: se gli utenti lo usano
//! spesso, vuol dire che i primi due non stanno funzionando. Quello che NON si
//! fa mai e' indovinare: cifrare per la persona sbagliata e' il fallimento
//! peggiore possibile, quindi in assenza di peer si ritorna
//! [`crate::Error::UnknownPeer`] e si chiede.

use std::collections::HashMap;

use crate::baseline::Plaintext;
use crate::error::Result;
use crate::keys::{Fingerprint, Identity, Keyring, PinOutcome, PublicKey};

/// Stato vivo del core, posseduto dal layer JNI per la durata della sessione.
pub struct Session<K: Keyring> {
    identity: Identity,
    keyring: K,
    /// Destinatario corrente per package Android (`com.whatsapp`, ...).
    /// Volutamente NON persistito qui: e' stato di sessione, e lo storage sta
    /// fuori dal core.
    current_peer: HashMap<String, PublicKey>,
}

/// Stato TOFU del mittente di un messaggio appena decifrato. Guida cosa
/// mostrare all'utente: la decifratura riuscita non implica che il mittente
/// sia quello atteso.
pub enum SenderStatus {
    /// Mai visto prima: e' stato fissato ora.
    New,
    /// Corrisponde alla chiave gia' fissata.
    Known { verified: bool },
    /// Corrisponde a un peer noto ma con chiave DIVERSA da quella fissata.
    /// La UI deve fermarsi qui e chiedere conferma mostrando entrambi i
    /// fingerprint; il messaggio si mostra solo dopo la scelta dell'utente.
    Conflict {
        existing: Fingerprint,
        incoming: Fingerprint,
    },
}

/// Esito di una decifratura riuscita.
pub struct DecryptedMessage {
    pub sender: PublicKey,
    pub sender_status: SenderStatus,
    pub plaintext: Plaintext,
}

/// Cosa e' risultato essere il testo in arrivo.
pub enum IncomingItem {
    Message(DecryptedMessage),
    /// Una presentazione: nessun messaggio da mostrare, solo una chiave da
    /// fissare. La UI mostra il fingerprint e l'esito del pin.
    IdentityCard {
        peer: PublicKey,
        fingerprint: Fingerprint,
        outcome: PinOutcome,
    },
}

impl<K: Keyring> Session<K> {
    pub fn new(identity: Identity, keyring: K) -> Self {
        todo!()
    }

    /// Blob di presentazione da inserire nel campo di testo.
    ///
    /// Non passa dalla clipboard: la tastiera lo scrive direttamente nel campo
    /// che sta servendo (`commitText`), l'utente preme invio. E' la ragione per
    /// cui il bootstrap costa un tocco e non un copia-incolla — inserire e'
    /// nativo per un IME, leggere no.
    ///
    /// La chiave e' UNA, la stessa per tutti i destinatari: non esiste una
    /// presentazione per contatto.
    pub fn identity_card(&self) -> String {
        todo!()
    }

    pub fn my_fingerprint(&self) -> Fingerprint {
        todo!()
    }

    /// Riconosce e gestisce un testo arbitrario in arrivo.
    ///
    /// Volutamente neutra rispetto al trasporto: le quattro vie con cui un
    /// blob puo' raggiungere la tastiera (clipboard, `ACTION_PROCESS_TEXT`,
    /// share sheet, campo di input) consegnano tutte la stessa stringa, e il
    /// core non deve sapere da quale arriva.
    ///
    /// Ritorna `Error::NotOurBlob` se il sentinel non combacia: esito normale,
    /// e' il caso della stragrande maggioranza dei testi. La tastiera lo usa
    /// per decidere se mostrare o meno l'azione "decifra".
    ///
    /// Effetti collaterali voluti, entrambi legati ad `app_package`:
    ///   - un mittente mai visto viene fissato (TOFU);
    ///   - il mittente diventa il destinatario corrente per quell'app, cosi'
    ///     la risposta non richiede nessuna scelta.
    ///
    /// In caso di [`SenderStatus::Conflict`] nessuno dei due effetti avviene:
    /// il pin resta quello vecchio e il destinatario corrente non cambia,
    /// finche' l'utente non si pronuncia con [`Self::confirm_key_change`].
    ///
    /// `now_unix` e' iniettato perche' il core non legge il clock di sistema.
    pub fn handle_incoming_text(
        &mut self,
        app_package: &str,
        text: &str,
        now_unix: i64,
    ) -> Result<IncomingItem> {
        todo!()
    }

    /// Cifra un testo verso il destinatario corrente dell'app indicata.
    ///
    /// Ritorna `UnknownPeer` se per quell'app non c'e' un destinatario: la UI
    /// deve chiedere, mai indovinare.
    pub fn encrypt_for_app<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        app_package: &str,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<String> {
        todo!()
    }

    pub fn current_peer(&self, app_package: &str) -> Option<&PublicKey> {
        todo!()
    }

    /// Scelta esplicita dalla toolbar. Il peer deve essere gia' nel keyring.
    pub fn set_current_peer(&mut self, app_package: &str, peer: &PublicKey) -> Result<()> {
        todo!()
    }

    /// Conferma esplicita dell'utente dopo un [`SenderStatus::Conflict`] o un
    /// [`PinOutcome::Conflict`]. Unico percorso che sovrascrive un pin. Mai
    /// chiamato in automatico.
    pub fn confirm_key_change(
        &mut self,
        old: &PublicKey,
        new: &PublicKey,
        now_unix: i64,
    ) -> Result<()> {
        todo!()
    }

    /// Marca un peer come verificato dopo che l'utente ha confrontato il
    /// fingerprint fuori banda. E' l'unica cosa che chiude il MITM al primo
    /// contatto, che il TOFU da solo non chiude.
    pub fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    // Riconoscimento:
    // - testo normale -> NotOurBlob
    // - identity card -> IncomingItem::IdentityCard, peer fissato
    // - messaggio -> IncomingItem::Message
    //
    // TOFU:
    // - peer nuovo -> SenderStatus::New e il peer risulta fissato dopo
    // - stesso peer, secondo messaggio -> SenderStatus::Known
    // - peer noto che cambia chiave -> Conflict, e il pin NON e' cambiato:
    //   solo confirm_key_change lo sostituisce
    // - dopo un Conflict il destinatario corrente NON e' cambiato
    //
    // Destinatario per app:
    // - encrypt_for_app senza peer per quell'app -> UnknownPeer
    // - decifrare un messaggio in com.whatsapp imposta il peer SOLO per
    //   com.whatsapp: org.thoughtcrime.securesms resta intatto
    // - il peer resta dopo la decifratura di un messaggio da un altro mittente
    //   nella stessa app? NO: l'ultimo mittente letto vince. Test esplicito,
    //   perche' e' la regola che rende automatico il caso comune ed e' anche
    //   quella che puo' sorprendere.
    //
    // Tier:
    // - blob con tier ForwardSecret -> TierUnsupported (non Crypto)
}
