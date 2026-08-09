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
//! [`Error::UnknownPeer`] e si chiede.

use std::collections::HashMap;

use rand_core::{CryptoRng, RngCore};

use crate::baseline::{self, Plaintext};
use crate::error::{Error, Result};
use crate::format::{self, ParsedBlob};
use crate::keys::{Fingerprint, Identity, Keyring, LabelOutcome, PinOutcome, PublicKey};

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
#[derive(Debug, PartialEq, Eq)]
pub enum SenderStatus {
    /// Chiave mai vista: fissata ora, **senza etichetta**. La UI dovrebbe
    /// chiedere all'utente chi sia — ed e' li' che un eventuale cambio di
    /// chiave viene alla luce, perche' attribuire un'etichetta gia' in uso
    /// produce un [`LabelOutcome::Conflict`].
    New,
    /// Chiave gia' fissata. `label` è `None` se l'utente non l'ha mai
    /// nominata.
    Known {
        label: Option<String>,
        verified: bool,
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
        Self {
            identity,
            keyring,
            current_peer: HashMap::new(),
        }
    }

    /// Blob di presentazione da inserire nel campo di testo.
    ///
    /// Non passa dalla clipboard: la tastiera lo scrive direttamente nel campo
    /// che sta servendo (`commitText`), l'utente preme invio. E' la ragione per
    /// cui il bootstrap costa un tocco e non un copia-incolla — inserire e'
    /// nativo per un IME, leggere no.
    ///
    /// La chiave e' UNA, la stessa per tutti i destinatari: non esiste una
    /// presentazione per contatto. L'RNG serve al riempimento che impedisce
    /// alle card di avere tutte la stessa lunghezza.
    pub fn identity_card<R: RngCore + CryptoRng>(&self, rng: &mut R) -> String {
        format::serialize_identity_card(&self.identity.public(), rng)
    }

    pub fn my_fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// Accesso in sola lettura al keyring, per chi deve persisterlo o
    /// mostrarne il contenuto. La mutazione passa solo dai metodi di
    /// [`Session`], cosi' il pin non puo' essere modificato scavalcando le
    /// regole TOFU.
    pub fn keyring(&self) -> &K {
        &self.keyring
    }

    /// Riconosce e gestisce un testo arbitrario in arrivo.
    ///
    /// Volutamente neutra rispetto al trasporto: le quattro vie con cui un
    /// blob puo' raggiungere la tastiera (clipboard, `ACTION_PROCESS_TEXT`,
    /// share sheet, campo di input) consegnano tutte la stessa stringa, e il
    /// core non deve sapere da quale arriva.
    ///
    /// Ritorna [`Error::NotOurBlob`] se il sentinel non combacia: esito
    /// normale, e' il caso della stragrande maggioranza dei testi. La tastiera
    /// lo usa per decidere se mostrare o meno l'azione "decifra".
    ///
    /// `now_unix` e' iniettato perche' il core non legge il clock di sistema.
    pub fn handle_incoming_text(
        &mut self,
        app_package: &str,
        text: &str,
        now_unix: i64,
    ) -> Result<IncomingItem> {
        let mut buf = Vec::new();
        match format::parse(text, &mut buf)? {
            ParsedBlob::Message(parsed) => {
                let sender = parsed
                    .header
                    .sender_pub
                    .clone()
                    .ok_or(Error::Format("messaggio senza pubkey del mittente"))?;

                // ORDINE CRITICO: si decifra PRIMA di toccare il keyring.
                //
                // La decifratura riuscita e' la prova che chi ha scritto
                // possiede davvero la privata di `sender`, e che il messaggio
                // era destinato a noi. Fissare la chiave prima significherebbe
                // permettere a chiunque di riempire il keyring di peer
                // inventati, o peggio di provocare un falso conflitto su un
                // contatto reale spedendo spazzatura firmata con una chiave
                // qualsiasi. La UI mostrerebbe "la chiave di Marco e'
                // cambiata" a comando di un estraneo.
                let plaintext = baseline::open(&self.identity, &sender, &parsed)?;

                let sender_status = self.pin_and_classify(&sender, now_unix)?;

                // Il mittente appena letto diventa il destinatario per questa
                // app: e' la leva che rende automatico il caso dominante,
                // leggo e rispondo.
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());

                Ok(IncomingItem::Message(DecryptedMessage {
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::IdentityCard(card) => {
                let outcome = self.keyring.tofu_pin(&card.public, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), card.public.clone());
                Ok(IncomingItem::IdentityCard {
                    fingerprint: Fingerprint::of(&card.public),
                    peer: card.public,
                    outcome,
                })
            }
        }
    }

    /// Fissa il mittente e traduce l'esito in stato da mostrare.
    fn pin_and_classify(&mut self, sender: &PublicKey, now_unix: i64) -> Result<SenderStatus> {
        match self.keyring.tofu_pin(sender, now_unix)? {
            PinOutcome::Pinned => Ok(SenderStatus::New),
            PinOutcome::AlreadyPinned => {
                let record = self.keyring.get(sender)?;
                Ok(SenderStatus::Known {
                    label: record.as_ref().and_then(|r| r.label.clone()),
                    verified: record.map(|r| r.verified).unwrap_or(false),
                })
            }
        }
    }

    /// Attribuisce un nome a una chiave: e' il punto in cui il TOFU acquista
    /// la capacita' di dire "la chiave di Marco e' cambiata".
    ///
    /// Su [`LabelOutcome::Conflict`] non modifica nulla: sta alla UI mostrare
    /// i due fingerprint e, solo se l'utente conferma, chiamare
    /// [`Self::confirm_key_change`].
    pub fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome> {
        self.keyring.assign_label(peer, label)
    }

    /// Cifra un testo verso il destinatario corrente dell'app indicata.
    ///
    /// Ritorna [`Error::UnknownPeer`] se per quell'app non c'e' un
    /// destinatario: la UI deve chiedere, mai indovinare.
    pub fn encrypt_for_app<R: RngCore + CryptoRng>(
        &self,
        app_package: &str,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        let peer = self.current_peer.get(app_package).ok_or(Error::UnknownPeer)?;
        baseline::seal(&self.identity, peer, plaintext, now_unix, rng)
    }

    pub fn current_peer(&self, app_package: &str) -> Option<&PublicKey> {
        self.current_peer.get(app_package)
    }

    /// Scelta esplicita dalla toolbar. Il peer deve essere gia' nel keyring:
    /// non si cifra verso una chiave che non e' mai stata fissata.
    pub fn set_current_peer(&mut self, app_package: &str, peer: &PublicKey) -> Result<()> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        self.current_peer
            .insert(app_package.to_owned(), peer.clone());
        Ok(())
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
        self.keyring.replace_pinned(old, new, now_unix)?;
        // Il destinatario corrente puntava alla vecchia chiave: va aggiornato
        // ovunque, o la prossima risposta partirebbe cifrata per una chiave
        // che l'utente ha appena dichiarato superata.
        for peer in self.current_peer.values_mut() {
            if peer == old {
                *peer = new.clone();
            }
        }
        Ok(())
    }

    /// Marca un peer come verificato dopo che l'utente ha confrontato il
    /// fingerprint fuori banda. E' l'unica cosa che chiude il MITM al primo
    /// contatto, che il TOFU da solo non chiude.
    pub fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        self.keyring.mark_verified(peer)
    }
}

#[cfg(test)]
// Nei test `unwrap` e `panic!` sono il comportamento voluto.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::keys::{LabelOutcome, PeerRecord};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Keyring in memoria. Lo storage vero sta fuori dal crate; qui serve solo
    /// qualcosa che rispetti il contratto.
    #[derive(Default)]
    struct KeyringInMemoria {
        peers: Vec<PeerRecord>,
    }

    impl Keyring for KeyringInMemoria {
        fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
            if self.peers.iter().any(|r| &r.public == peer) {
                return Ok(PinOutcome::AlreadyPinned);
            }
            self.peers.push(PeerRecord {
                public: peer.clone(),
                label: None,
                first_seen_unix: now_unix,
                verified: false,
            });
            Ok(PinOutcome::Pinned)
        }

        fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome> {
            if let Some(altro) = self
                .peers
                .iter()
                .find(|r| r.label.as_deref() == Some(label) && &r.public != peer)
            {
                return Ok(LabelOutcome::Conflict {
                    existing: altro.public.clone(),
                    existing_fingerprint: Fingerprint::of(&altro.public),
                    incoming_fingerprint: Fingerprint::of(peer),
                });
            }
            match self.peers.iter_mut().find(|r| &r.public == peer) {
                Some(record) => {
                    record.label = Some(label.to_owned());
                    Ok(LabelOutcome::Assigned)
                }
                None => Err(Error::UnknownPeer),
            }
        }

        fn replace_pinned(
            &mut self,
            old: &PublicKey,
            new: &PublicKey,
            now_unix: i64,
        ) -> Result<()> {
            let etichetta = self
                .peers
                .iter()
                .find(|r| &r.public == old)
                .and_then(|r| r.label.clone());
            self.peers.retain(|r| &r.public != old);
            self.peers.retain(|r| &r.public != new);
            self.peers.push(PeerRecord {
                public: new.clone(),
                label: etichetta,
                first_seen_unix: now_unix,
                // Una chiave nuova non e' stata verificata fuori banda.
                verified: false,
            });
            Ok(())
        }

        fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>> {
            Ok(self.peers.iter().find(|r| &r.public == peer).cloned())
        }

        fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
            match self.peers.iter_mut().find(|r| &r.public == peer) {
                Some(record) => {
                    record.verified = true;
                    Ok(())
                }
                None => Err(Error::UnknownPeer),
            }
        }
    }

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn sessione(seed: u8) -> Session<KeyringInMemoria> {
        Session::new(
            Identity::from_secret_bytes([seed; 32]).unwrap(),
            KeyringInMemoria::default(),
        )
    }

    const WHATSAPP: &str = "com.whatsapp";
    const SIGNAL: &str = "org.thoughtcrime.securesms";

    #[test]
    fn testo_normale_non_e_nostro() {
        let mut bob = sessione(2);
        for testo in ["", "ciao come stai", "https://esempio.it"] {
            assert!(matches!(
                bob.handle_incoming_text(WHATSAPP, testo, 0),
                Err(Error::NotOurBlob)
            ));
        }
    }

    #[test]
    fn messaggio_da_peer_nuovo_lo_fissa() {
        let alice = sessione(1);
        let mut bob = sessione(2);

        let blob = crate::baseline::seal(
            &Identity::from_secret_bytes([1; 32]).unwrap(),
            &bob.identity.public(),
            b"primo contatto",
            1_700_000_000,
            &mut rng(9),
        )
        .unwrap();

        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob, 100).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(msg.sender_status, SenderStatus::New);
        assert_eq!(msg.plaintext.as_bytes(), b"primo contatto");
        assert_eq!(msg.sender, alice.identity.public());

        // Il mittente e' diventato il destinatario corrente per quell'app.
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));
    }

    #[test]
    fn secondo_messaggio_dallo_stesso_peer_e_noto() {
        let mut bob = sessione(2);
        let alice_id = Identity::from_secret_bytes([1; 32]).unwrap();

        for _ in 0..2 {
            let blob =
                crate::baseline::seal(&alice_id, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(9)).unwrap();
            let _ = bob.handle_incoming_text(WHATSAPP, &blob, 100).unwrap();
        }

        let blob =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"y", 1_700_000_000, &mut rng(8)).unwrap();
        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob, 200).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(
            msg.sender_status,
            SenderStatus::Known {
                label: None,
                verified: false
            }
        );
    }

    /// Il destinatario e' per app, non globale: chi tiene un contatto per app
    /// non deve toccare mai niente, e leggere in una non deve spostare l'altra.
    #[test]
    fn il_destinatario_e_per_app() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol = Identity::from_secret_bytes([3; 32]).unwrap();

        let da_alice =
            crate::baseline::seal(&alice, &bob.identity.public(), b"a", 1_700_000_000, &mut rng(1)).unwrap();
        let da_carol =
            crate::baseline::seal(&carol, &bob.identity.public(), b"c", 1_700_000_000, &mut rng(2)).unwrap();

        bob.handle_incoming_text(WHATSAPP, &da_alice, 1).unwrap();
        bob.handle_incoming_text(SIGNAL, &da_carol, 2).unwrap();

        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
        assert_eq!(bob.current_peer(SIGNAL), Some(&carol.public()));
    }

    /// Dentro la stessa app vince l'ultimo mittente letto. E' la regola che
    /// rende automatico il caso comune ed e' anche quella che puo' sorprendere,
    /// quindi e' inchiodata qui.
    #[test]
    fn nella_stessa_app_vince_l_ultimo_letto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol = Identity::from_secret_bytes([3; 32]).unwrap();

        let da_alice =
            crate::baseline::seal(&alice, &bob.identity.public(), b"a", 1_700_000_000, &mut rng(1)).unwrap();
        let da_carol =
            crate::baseline::seal(&carol, &bob.identity.public(), b"c", 1_700_000_000, &mut rng(2)).unwrap();

        bob.handle_incoming_text(WHATSAPP, &da_alice, 1).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
        bob.handle_incoming_text(WHATSAPP, &da_carol, 2).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&carol.public()));
    }

    #[test]
    fn identity_card_fissa_la_chiave_e_sceglie_il_destinatario() {
        let alice = sessione(1);
        let mut bob = sessione(2);

        let card = alice.identity_card(&mut rng(7));
        let IncomingItem::IdentityCard {
            peer,
            fingerprint,
            outcome,
        } = bob.handle_incoming_text(WHATSAPP, &card, 50).unwrap()
        else {
            panic!("attesa una identity card");
        };

        assert_eq!(peer, alice.identity.public());
        assert_eq!(fingerprint, alice.my_fingerprint());
        assert!(matches!(outcome, PinOutcome::Pinned));
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));
    }

    /// Il ciclo completo di bootstrap: Alice si presenta, Bob la fissa e
    /// risponde cifrato senza scegliere nulla, Alice legge.
    #[test]
    fn bootstrap_completo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);

        let card = alice.identity_card(&mut rng(7));
        bob.handle_incoming_text(WHATSAPP, &card, 1).unwrap();

        let risposta = bob
            .encrypt_for_app(WHATSAPP, b"ricevuto", 1_700_000_000, &mut rng(4))
            .unwrap();

        let IncomingItem::Message(msg) = alice
            .handle_incoming_text(WHATSAPP, &risposta, 2)
            .unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(msg.plaintext.as_bytes(), b"ricevuto");
        assert_eq!(msg.sender_status, SenderStatus::New);
        // E ora anche Alice sa a chi rispondere, senza aver scelto niente.
        assert_eq!(alice.current_peer(WHATSAPP), Some(&bob.identity.public()));
    }

    #[test]
    fn senza_destinatario_non_si_indovina() {
        let bob = sessione(2);
        assert!(matches!(
            bob.encrypt_for_app(WHATSAPP, b"per chi?", 1_700_000_000, &mut rng(1)),
            Err(Error::UnknownPeer)
        ));
    }

    #[test]
    fn destinatario_esplicito_solo_se_gia_noto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();

        // Mai visto: non si puo' selezionare.
        assert!(matches!(
            bob.set_current_peer(WHATSAPP, &alice.public()),
            Err(Error::UnknownPeer)
        ));

        bob.keyring.tofu_pin(&alice.public(), 0).unwrap();
        bob.set_current_peer(WHATSAPP, &alice.public()).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
    }

    /// Un messaggio che non decifra NON deve lasciare traccia nel keyring.
    ///
    /// E' la ragione per cui si decifra prima di fissare: altrimenti chiunque
    /// potrebbe riempire il keyring di peer inventati spedendo spazzatura, o
    /// far comparire all'utente un falso "la chiave e' cambiata".
    #[test]
    fn messaggio_non_decifrabile_non_tocca_il_keyring() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol_pub = Identity::from_secret_bytes([3; 32]).unwrap().public();

        // Messaggio di Alice destinato a Carol: Bob non lo puo' aprire.
        let blob = crate::baseline::seal(&alice, &carol_pub, b"non per bob", 1_700_000_000, &mut rng(5)).unwrap();

        assert!(matches!(
            bob.handle_incoming_text(WHATSAPP, &blob, 1),
            Err(Error::Crypto)
        ));
        assert!(bob.keyring.get(&alice.public()).unwrap().is_none());
        assert_eq!(bob.current_peer(WHATSAPP), None);
    }

    #[test]
    fn tier_riservato_non_e_un_errore_crypto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let blob =
            crate::baseline::seal(&alice, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(6)).unwrap();

        // Alza il byte di tier a ForwardSecret.
        let payload = blob.strip_prefix(format::SENTINEL).unwrap();
        let mut body = crate::encoding::decode(payload).unwrap();
        *body.get_mut(2).unwrap() = format::Tier::ForwardSecret as u8;
        let manomesso = format!("{}{}", format::SENTINEL, crate::encoding::encode(&body));

        assert!(matches!(
            bob.handle_incoming_text(WHATSAPP, &manomesso, 1),
            Err(Error::TierUnsupported)
        ));
    }

    #[test]
    fn conferma_del_cambio_chiave_sposta_anche_il_destinatario() {
        let mut bob = sessione(2);
        let vecchia = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let nuova = Identity::from_secret_bytes([4; 32]).unwrap().public();

        bob.keyring.tofu_pin(&vecchia, 0).unwrap();
        bob.set_current_peer(WHATSAPP, &vecchia).unwrap();

        bob.confirm_key_change(&vecchia, &nuova, 10).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&nuova));
        assert!(bob.keyring.get(&vecchia).unwrap().is_none());
    }

    #[test]
    fn verifica_fuori_banda() {
        let mut bob = sessione(2);
        let alice_id = Identity::from_secret_bytes([1; 32]).unwrap();

        let blob =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(9)).unwrap();
        bob.handle_incoming_text(WHATSAPP, &blob, 1).unwrap();
        bob.mark_verified(&alice_id.public()).unwrap();

        let blob2 =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"y", 1_700_000_000, &mut rng(8)).unwrap();
        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob2, 2).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(
            msg.sender_status,
            SenderStatus::Known {
                label: None,
                verified: true
            }
        );
    }

    /// L'etichetta e' l'identita' di contatto, e attribuirla e' il momento in
    /// cui il TOFU acquista la capacita' di dire "la chiave di Marco e'
    /// cambiata". Prima di questa scelta il conflitto non era esprimibile:
    /// due chiavi diverse erano semplicemente due peer diversi.
    #[test]
    fn etichetta_duplicata_e_un_conflitto() {
        let mut bob = sessione(2);
        let marco = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let finto_marco = Identity::from_secret_bytes([9; 32]).unwrap().public();

        bob.keyring.tofu_pin(&marco, 1).unwrap();
        bob.keyring.tofu_pin(&finto_marco, 2).unwrap();

        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);

        let esito = bob.assign_label(&finto_marco, "Marco").unwrap();
        let LabelOutcome::Conflict {
            existing,
            existing_fingerprint,
            incoming_fingerprint,
        } = esito
        else {
            panic!("atteso un conflitto");
        };
        assert_eq!(existing, marco);
        assert_eq!(existing_fingerprint, Fingerprint::of(&marco));
        assert_eq!(incoming_fingerprint, Fingerprint::of(&finto_marco));

        // Nulla e' stato modificato: la vecchia chiave tiene ancora il nome.
        assert_eq!(
            bob.keyring.get(&marco).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(bob.keyring.get(&finto_marco).unwrap().unwrap().label.is_none());
    }

    #[test]
    fn rietichettare_la_stessa_chiave_non_e_un_conflitto() {
        let mut bob = sessione(2);
        let marco = Identity::from_secret_bytes([1; 32]).unwrap().public();
        bob.keyring.tofu_pin(&marco, 1).unwrap();

        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);
        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);
        assert_eq!(
            bob.assign_label(&marco, "Marco R.").unwrap(),
            LabelOutcome::Assigned
        );
    }

    /// La conferma sposta il nome sulla chiave nuova e NON eredita la
    /// verifica: una chiave nuova non e' stata confrontata fuori banda.
    #[test]
    fn la_conferma_sposta_etichetta_e_azzera_la_verifica() {
        let mut bob = sessione(2);
        let vecchia = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let nuova = Identity::from_secret_bytes([9; 32]).unwrap().public();

        bob.keyring.tofu_pin(&vecchia, 1).unwrap();
        bob.assign_label(&vecchia, "Marco").unwrap();
        bob.mark_verified(&vecchia).unwrap();
        bob.set_current_peer(WHATSAPP, &vecchia).unwrap();

        bob.confirm_key_change(&vecchia, &nuova, 10).unwrap();

        let record = bob.keyring.get(&nuova).unwrap().unwrap();
        assert_eq!(record.label.as_deref(), Some("Marco"));
        assert!(!record.verified, "la verifica non si eredita");
        assert!(bob.keyring.get(&vecchia).unwrap().is_none());
        assert_eq!(bob.current_peer(WHATSAPP), Some(&nuova));
    }

    /// Il fingerprint e' stabile per sempre: 24 caratteri in 6 gruppi da 4.
    /// Se questo test cambia, ogni verifica gia' fatta dagli utenti e' invalida.
    #[test]
    fn kat_fingerprint() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let mostrato = alice.fingerprint().display();

        assert_eq!(mostrato.len(), 29, "24 caratteri + 5 spazi");
        assert_eq!(mostrato.split(' ').count(), 6);
        assert!(mostrato.split(' ').all(|g| g.len() == 4));
        assert_eq!(mostrato, KAT_FINGERPRINT);
    }

    const KAT_FINGERPRINT: &str = "st8b 8gnj bz97 raos onxs ugao";
}
