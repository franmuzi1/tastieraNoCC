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
use crate::file::{self, DecryptedFile, FileMeta};
use crate::error::{Error, Result};
use crate::format::{self, ParsedBlob};
use crate::keys::{self, Fingerprint, Identity, Keyring, LabelOutcome, PinOutcome, PublicKey};

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
    /// Chi ha costruito il messaggio.
    ///
    /// **Per un gruppo (`destinatari > 1`) questo NON e' l'autore del testo**,
    /// ed e' una distinzione che l'interfaccia deve rispettare (decisione K6).
    /// Aprire uno slot prova che chi l'ha fatto conosceva
    /// `DH(mittente, destinatario)`, quindi il campo non e' falso: e' solo
    /// insufficiente. Il payload e' cifrato con una chiave che tutti i membri
    /// hanno, e chiunque di loro puo' riscriverlo tenendo gli slot originali.
    ///
    /// Serve a sapere con chi si sta parlando, non a dire chi ha scritto.
    pub sender: PublicKey,
    pub sender_status: SenderStatus,
    pub plaintext: Plaintext,
    /// Questo messaggio veniva da un **gruppo**.
    ///
    /// Un flag esplicito e non una soglia sul conteggio, ed e' una correzione:
    /// prima si deduceva da `destinatari > 1`, e un blob costruito con un solo
    /// slot si presentava come un normale messaggio a due — pur essendo un
    /// `version = 2` senza forward secrecy. Saltava cosi' la condizione che
    /// accompagna la decisione K1, quella che il documento chiama "cio' che
    /// rende accettabile tutto il resto". Un numero non e' una semantica.
    ///
    /// Ora il parser rifiuta i gruppi sotto i due slot, ma il flag resta:
    /// dedurre un fatto da una soglia e' fragile una volta e lo sara' ancora.
    pub gruppo: bool,
    /// Quanti slot aveva il blob, cioe' quante persone potevano leggerlo,
    /// mittente compreso. **`0` quando [gruppo] e' falso**, perche' li' il
    /// numero non descrive niente che valga la pena mostrare.
    pub destinatari: usize,
}

/// Perche' un messaggio nostro a epoca non si e' riaperto.
///
/// La domanda che l'utente si fa e' «e allora il mio contatto dov'e' finito?»,
/// e per anni la risposta e' stata quella sbagliata: il codice di errore era
/// uno solo, e l'app lo traduceva con l'unica causa che quel codice aveva
/// quando e' nato — «quel contatto non e' piu' nella tua lista». Nella via a
/// epoca e' quasi sempre falso.
///
/// Le cause vere sono tre, e si distinguono con quello che si sa gia' qui,
/// senza tentare nessuna decifratura in piu':
///
///  - **nessun contatto in rubrica**: allora si', non c'e' a chi. E' l'unico
///    caso in cui il vecchio avviso diceva il vero;
///  - **bootstrap**: il primo messaggio di una conversazione si riapre con le
///    sole identita', che non cambiano e non scadono. Se fallisce per tutti i
///    contatti, il destinatario non e' fra loro;
///  - **tutto il resto**: si riapriva con la chiave d'epoca del destinatario,
///    che e' una sola per contatto e viene sovrascritta — o cancellata da un
///    rogo. Il contatto c'e' ancora, la chiave di allora no.
fn perche_non_si_riapre(bootstrap: bool, contatti: usize) -> Error {
    if contatti == 0 || bootstrap {
        Error::OwnMessage
    } else {
        Error::OwnMessageKeyGone
    }
}

/// Un segreto nuovo per una chiave temporanea.
fn nuovo_segreto<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Un allegato decifrato, con lo stato TOFU di chi l'ha mandato.
pub struct IncomingFile {
    /// Chi l'ha mandato — **oppure**, quando `nostro` e' vero, a chi l'abbiamo
    /// mandato noi. Un campo solo perche' e' sempre "l'altra persona": chi
    /// mostra il risultato sa gia' da `nostro` come chiamarla.
    pub sender: PublicKey,
    pub sender_status: SenderStatus,
    pub file: DecryptedFile,
    /// L'abbiamo mandato noi e l'abbiamo riaperto. Solo senza forward secrecy.
    pub nostro: bool,
}

/// Cosa e' risultato essere il testo in arrivo.
pub enum IncomingItem {
    Message(DecryptedMessage),
    /// Un messaggio **nostro**, riaperto. Capita ricopiando cio' che si e'
    /// appena mandato, ed e' un caso da presentare come tale: qui non c'e' un
    /// mittente da mostrare, c'e' un destinatario.
    ///
    /// Esiste solo senza forward secrecy. Con la catena accesa la chiave non
    /// esiste piu' e non c'e' niente da riaprire — per nessuno.
    OwnMessage {
        recipient: PublicKey,
        recipient_label: Option<String>,
        plaintext: Plaintext,
    },
    /// L'altro ha chiesto di bruciare, e l'abbiamo fatto: le chiavi con cui si
    /// leggeva quella conversazione non esistono piu' da questo lato.
    ///
    /// Non c'e' testo da mostrare — e' un gesto, non un messaggio.
    /// Un rogo ricevuto. `sent_at_unix` e' l'ora che il MITTENTE ha scritto
    /// dentro il cifrato: autenticata, non verificabile, e va **mostrata** —
    /// mai usata per decidere da soli (decisione C).
    ///
    /// Portarla fin qui serve a una cosa precisa: un blob di rogo resta valido
    /// per sempre, quindi chi l'ha visto passare in chat puo' reincollarlo piu'
    /// tardi e distruggere la conversazione che nel frattempo era ripartita.
    /// Non lo si puo' impedire senza rifiutare per data, che la decisione C
    /// vieta. Lo si puo' rendere VISIBILE: una richiesta di agosto che arriva a
    /// novembre si vede, se la data e' a schermo. Prima non lo era.
    Burned {
        peer: PublicKey,
        sent_at_unix: i64,
    },
    /// Una presentazione: nessun messaggio da mostrare, solo una chiave da
    /// fissare. La UI mostra il fingerprint e l'esito del pin.
    /// La propria card, riaperta. Non si fissa niente: vedi il perche' nel
    /// ramo che la produce.
    OwnIdentityCard { fingerprint: Fingerprint },
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

    /// L'identita' della sessione, per il backup cifrato.
    ///
    /// Esporla non apre buchi: da fuori dal crate un'[`Identity`] non lascia
    /// estrarre la chiave privata — l'accessore ai byte grezzi e'
    /// `pub(crate)` e ha un solo chiamante, [`crate::backup`].
    pub fn identity(&self) -> &Identity {
        &self.identity
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
            // Un rogo si riconosce dal kind, che sta nell'AAD: non e' un
            // messaggio travestito, e un messaggio non puo' diventarlo.
            ParsedBlob::Burn(parsed) => {
                let (peer, sent_at_unix) = self.mittente_di_un_rogo(&parsed)?;
                // Un rogo gia' onorato non si rifa'. Un blob resta valido per
                // sempre: chi l'ha visto passare in chat poteva reincollarlo
                // mesi dopo e distruggere la conversazione ripartita nel
                // frattempo.
                //
                // Non e' un giudizio sulla data, che la decisione C vieta —
                // sarebbe "questa data e' troppo vecchia, non ti credo". E'
                // rifiutare di **rifare** una cosa gia' fatta, confrontando con
                // cio' che abbiamo gia' onorato da lui.
                //
                // Si risponde `Crypto` e non un errore suo: distinguere direbbe
                // a chi ripubblica che il blob era buono e che l'aveva gia'
                // usato qualcun altro.
                // Anche qui il confronto si fa sul **minore** fra la data
                // dichiarata e la nostra, per la stessa ragione di
                // `ricorda_prekey` e `ricorda_epoca_del_peer` — ed e' il caso
                // in cui il difetto sarebbe stato peggiore.
                //
                // Una richiesta di rogo datata nel futuro avrebbe spinto
                // `burned_at` avanti di anni, e da quel momento **ogni rogo
                // successivo di quella persona sarebbe stato rifiutato**: la
                // sola operazione distruttiva del sistema smetteva di
                // funzionare, in silenzio, e con l'errore opaco che non
                // distingue "gia' fatto" da "non valido". Chi avesse chiesto di
                // bruciare una conversazione avrebbe creduto di averlo fatto.
                //
                // Tagliando a `now_unix` la difesa dal replay resta intera — un
                // blob vecchio ha una data vecchia comunque la si guardi —
                // mentre una data assurda non puo' piu' disattivare la funzione.
                let quando = sent_at_unix.min(now_unix);
                if quando <= self.keyring.burned_at(&peer)? {
                    return Err(Error::Crypto);
                }
                self.keyring.set_burned_at(&peer, quando)?;
                self.keyring.burn_conversation(&peer)?;
                Ok(IncomingItem::Burned { peer, sent_at_unix })
            }
            ParsedBlob::Message(parsed)
                if parsed.header.origin.uses_epoch()
                    || parsed.header.origin.is_epoch_bootstrap() =>
            {
                let (peer, plaintext, nostro) = self.apri_a_epoca(&parsed, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), peer.clone());
                if nostro {
                    let recipient_label = self.keyring.get(&peer)?.and_then(|r| r.label);
                    return Ok(IncomingItem::OwnMessage {
                        recipient: peer,
                        recipient_label,
                        plaintext,
                    });
                }
                let sender_status = self.pin_and_classify(&peer, now_unix)?;
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender: peer,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) if parsed.header.origin.uses_prekey() => {
                let (sender, plaintext) = self.prova_con_le_prekey(&parsed, now_unix)?;
                let sender_status = self.pin_and_classify(&sender, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) if parsed.header.origin.is_ephemeral() => {
                // Mittente effimero: chi ha scritto non e' dichiarato, si
                // scopre provando. La prima chiave che apre il messaggio E'
                // il mittente, perche' la derivazione richiede la sua privata.
                let (sender, prekey, plaintext) = self.prova_i_contatti(&parsed)?;
                // Da qui in poi gli si puo' rispondere con la forward secrecy
                // piena: la catena e' partita.
                self.ricorda_prekey(&sender, &prekey, plaintext.sent_at_unix(), now_unix)?;
                let sender_status = self.pin_and_classify(&sender, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) => {
                let sender = parsed
                    .header
                    .sender_pub()
                    .cloned()
                    .ok_or(Error::Format("messaggio senza pubkey del mittente"))?;

                // L'abbiamo scritto noi: si riapre provando i nostri contatti
                // come DESTINATARI, che e' l'unica cosa che l'header non dice.
                // Si riconosce da un campo in chiaro, prima di tentare
                // qualunque decifratura, quindi non e' una deduzione da un
                // fallimento AEAD e non intacca l'opacita' di `Crypto`.
                if sender == self.identity.public() {
                    return self.riapri_un_mio_messaggio(app_package, &parsed);
                }

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
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            // I messaggi di gruppo (decisione K) arrivano qui, e per ora il
            // livello superiore non li sa ancora aprire: il formato e la
            // crittografia esistono e sono provati, il resto — scelta dei
            // destinatari, gruppi salvati, ponte verso Android — no. Un errore
            // esplicito e' meglio di un `unreachable!()`: se un blob di gruppo
            // arriva prima che la strada sia finita, si vuole un messaggio, non
            // un processo che muore.
            ParsedBlob::Group(parsed) => {
                let (mittente, plaintext) = self.apri_di_gruppo(&parsed)?;
                // Se ad aprire e' stata la nostra chiave stiamo rileggendo un
                // messaggio nostro: **non si fissa niente**. Senza questa
                // guardia `tofu_pin` metteva l'utente fra i propri contatti —
                // la rubrica che mente, lo stesso difetto gia' corretto per le
                // presentazioni — e l'interfaccia riceveva "mittente mai visto"
                // su un messaggio scritto da lei.
                //
                // Gli altri percorsi la guardia ce l'hanno gia': quello statico
                // intercetta il proprio mittente prima di decifrare, quello a
                // epoca usa il flag `nostro`. Il gruppo era l'unico senza.
                let sender_status = if mittente == self.identity.public() {
                    // Non `New`, che farebbe chiedere "chi e'?" su una frase
                    // propria. Per un gruppo l'autore non si mostra comunque
                    // (K6), quindi qui non si sta affermando niente all'utente.
                    SenderStatus::Known {
                        label: None,
                        verified: false,
                    }
                } else {
                    self.pin_and_classify(&mittente, now_unix)?
                };
                // **Non si tocca il destinatario corrente**, e non e' una
                // dimenticanza. La regola "decifrare stabilisce con chi si
                // parla" vale fra due persone; qui l'altro capo e' un gruppo, e
                // scegliere il solo mittente farebbe partire la risposta a lui
                // in privato — dentro la chat dove tutti gli altri la
                // aspettano. Il gruppo lo sceglie chi scrive, sopra di qui.
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: true,
                    destinatari: parsed.slot_count(),
                    sender: mittente,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::IdentityCard(card) => {
                // Si fissa la chiave, e NIENTE ALTRO.
                //
                // In particolare non si tocca il destinatario corrente, anche
                // se sarebbe comodo. Una identity card non e' autenticata — per
                // costruzione, e' il primo contatto — quindi chiunque puo'
                // fabbricarne una con la propria chiave e farla arrivare alla
                // vittima: dall'esterno e' indistinguibile da un messaggio.
                // Se bastasse decifrarla per diventare il destinatario, un
                // estraneo deciderebbe per chi la vittima cifra, e il messaggio
                // successivo andrebbe a lui.
                //
                // La regola che autorizza la selezione implicita e' un'altra:
                // la decifratura RIUSCITA di un messaggio prova che chi ha
                // scritto possiede la privata dichiarata. Una card non prova
                // niente, quindi non decide niente. Il pin resta, perche' e' il
                // TOFU e il suo rischio e' quello dichiarato; la scelta del
                // destinatario passa da un gesto esplicito dell'utente
                // (`set_current_peer`).
                // La propria card non si fissa. Copiare la propria chiave e
                // riaprirla creava un contatto che e' se stessi: un nome nella
                // rubrica a cui si puo' perfino scegliere di cifrare, senza che
                // niente lo dica. Non e' un buco di sicurezza — la chiave e'
                // gia' nostra e non si impara niente — ma e' una rubrica che
                // mente, e da qui in poi "per chi sto cifrando" non ha piu' una
                // risposta affidabile.
                //
                // Si distingue dal caso "gia' nota" e non ci si appoggia:
                // sono due frasi diverse da dire all'utente, e "questa chiave
                // ce l'hai gia'" per la propria chiave sarebbe vera e inutile.
                if card.public == self.identity.public() {
                    return Ok(IncomingItem::OwnIdentityCard {
                        fingerprint: Fingerprint::of(&card.public),
                    });
                }
                let outcome = self.keyring.tofu_pin(&card.public, now_unix)?;
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
        &mut self,
        app_package: &str,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        self.encrypt_for_app_with(app_package, plaintext, now_unix, rng, false)
    }

    /// Come [`Self::encrypt_for_app`], scegliendo se usare il mittente
    /// effimero.
    ///
    /// La scelta e' del chiamante e non del core perche' e' una questione di
    /// **compatibilita'**, non di crittografia: un messaggio a mittente
    /// effimero non lo apre una versione precedente, quindi finche' l'altro
    /// lato non e' aggiornato va lasciato spento. Il core non sa che versione
    /// abbia il destinatario, e indovinarlo produrrebbe messaggi illeggibili.
    pub fn encrypt_for_app_with<R: RngCore + CryptoRng>(
        &mut self,
        app_package: &str,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
        effimero: bool,
    ) -> Result<String> {
        let peer = self
            .current_peer
            .get(app_package)
            .ok_or(Error::UnknownPeer)?
            .clone();
        if !effimero {
            return self.cifra_a_epoca(&peer, plaintext, now_unix, rng);
        }

        // Con una chiave temporanea del destinatario si fa la forward secrecy
        // piena; senza — primo messaggio, o lui non ha ancora risposto — si
        // ripiega su quella a meta', che protegge comunque cio' che mandiamo.
        // Il ripiego non e' un downgrade forzabile: dipende da cosa CI ha
        // mandato lui, non da cosa dichiara il messaggio.
        match self.keyring.peer_prekey(&peer)?.filter(|k| self.identity.diffie_hellman(k).is_ok()) {
            Some(sua_prekey) => {
                let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
                let blob = baseline::seal_forward(
                    &self.identity,
                    &peer,
                    &sua_prekey,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                // Si conserva DOPO aver cifrato: se la cifratura fallisse,
                // avremmo salvato una chiave che non serve a niente.
                self.keyring.push_my_prekey(&peer, *mia.to_bytes())?;
                Ok(blob)
            }
            None => {
                // Anche il ripiego porta una nostra chiave temporanea: e' cio'
                // che fa PARTIRE la catena. Senza, chi riceve non avrebbe mai
                // una nostra prekey e la forward secrecy piena non comincerebbe
                // mai — il primo messaggio resterebbe l'unico schema per sempre.
                let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
                let blob = baseline::seal_ephemeral(
                    &self.identity,
                    &peer,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                self.keyring.push_my_prekey(&peer, *mia.to_bytes())?;
                Ok(blob)
            }
        }
    }

    /// Cifra un file per un peer **scelto esplicitamente** (decisione G4).
    ///
    /// Niente `app_package` e niente destinatario implicito: questo percorso
    /// parte da una schermata, non dalla tastiera, quindi il contesto da cui
    /// dedurre con chi si sta parlando non esiste. Ed e' anche il verso giusto
    /// in cui sbagliare — un file mandato alla persona sbagliata non si ritira.
    ///
    /// Il peer deve essere gia' nel keyring: non si cifra verso una chiave mai
    /// vista, che e' la stessa regola di [`Self::set_current_peer`].
    pub fn encrypt_file<R: RngCore + CryptoRng>(
        &self,
        peer: &PublicKey,
        meta: &FileMeta,
        content: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        file::seal_file(&self.identity, peer, meta, content, now_unix, rng)
    }

    /// [`Self::encrypt_file`] con la catena di forward secrecy.
    ///
    /// Un allegato senza catena e' un buco piu' grosso di un messaggio senza:
    /// una foto vale piu' di una riga di testo, e resta sul telefono di chi la
    /// riceve. Con `forward = false` si torna allo statico-statico, per chi
    /// scrive a una versione vecchia.
    ///
    /// **Usa lo stesso stato dei messaggi**, non uno suo: e' la stessa
    /// conversazione con la stessa persona, e due catene separate
    /// significherebbero due volte le chiavi da conservare e due volte le
    /// occasioni di non buttarle.
    pub fn encrypt_file_with<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        meta: &FileMeta,
        content: &[u8],
        now_unix: i64,
        rng: &mut R,
        forward: bool,
    ) -> Result<Vec<u8>> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        if !forward {
            return file::seal_file(&self.identity, peer, meta, content, now_unix, rng);
        }
        // Il `filter` non e' ridondante con `ricorda_prekey`: uno stato salvato
        // da una versione precedente puo' gia' contenere una chiave inservibile,
        // e li' l'unica cosa sensata e' ripiegare invece di non poter piu'
        // mandare niente a quella persona.
        let sua = self
            .keyring
            .peer_prekey(peer)?
            .filter(|k| self.identity.diffie_hellman(k).is_ok());
        let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
        let blob = file::seal_file_forward(
            &self.identity,
            peer,
            sua.as_ref(),
            &mia.public(),
            meta,
            content,
            now_unix,
            rng,
        )?;
        // Dopo aver cifrato: se fallisse, avremmo salvato una chiave inutile.
        self.keyring.push_my_prekey(peer, *mia.to_bytes())?;
        Ok(blob)
    }

    /// Apre un allegato ricevuto.
    ///
    /// Stesso ordine critico dei messaggi: **si decifra prima di toccare il
    /// keyring**. La decifratura riuscita e' la prova che chi ha mandato il
    /// file possiede la privata dichiarata; fissare prima permetterebbe a
    /// chiunque di riempire il keyring spedendo un allegato qualsiasi.
    ///
    /// A differenza di un messaggio **non sceglie nessun destinatario**: qui
    /// non c'e' un'app di provenienza a cui attribuirlo, e indovinarla sarebbe
    /// il modo per far cifrare il messaggio successivo alla persona sbagliata.
    pub fn handle_incoming_file(&mut self, bytes: &[u8], now_unix: i64) -> Result<IncomingFile> {
        let parsed = file::parse_file(bytes)?;

        // Come per i messaggi: se il mittente e' effimero non c'e' scritto chi
        // ha mandato il file, e lo si scopre provando i propri contatti. Chi
        // non e' nel keyring resta sconosciuto, ed e' voluto — altrimenti
        // chiunque potrebbe farsi fissare spedendo un allegato.
        let (sender, decrypted) = if parsed.header.origin.uses_prekey() {
            self.prova_le_prekey_sul_file(&parsed, now_unix)?
        } else if parsed.header.origin.is_ephemeral() {
            let (chi, prekey, aperto) = self.prova_i_contatti_sul_file(&parsed)?;
            self.ricorda_prekey(&chi, &prekey, aperto.sent_at_unix, now_unix)?;
            (chi, aperto)
        } else {
            let sender = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("allegato senza pubkey del mittente"))?;
            // L'abbiamo mandato noi: si riapre provando i contatti come
            // destinatari, esattamente come per un messaggio. Un messaggio
            // nostro rileggibile e una foto nostra no sarebbe una differenza
            // che nessuno saprebbe spiegare.
            if sender == self.identity.public() {
                for candidato in self.keyring.peers()? {
                    let Ok(aperto) =
                        file::open_file_as_sender(&self.identity, &candidato, &parsed)
                    else {
                        continue;
                    };
                    let sender_status = self.pin_and_classify(&candidato, now_unix)?;
                    return Ok(IncomingFile {
                        sender: candidato,
                        sender_status,
                        file: aperto,
                        nostro: true,
                    });
                }
                return Err(Error::OwnMessage);
            }
            let aperto = file::open_file(&self.identity, &sender, &parsed)?;
            (sender, aperto)
        };
        let sender_status = self.pin_and_classify(&sender, now_unix)?;

        Ok(IncomingFile {
            sender,
            sender_status,
            file: decrypted,
            nostro: false,
        })
    }

    /// Riapre un messaggio nostro provando i contatti come destinatari.
    ///
    /// **Non tocca il pin e non fissa niente:** il mittente siamo noi, non c'e'
    /// nessuna chiave nuova da fissare. Sposta pero' il destinatario corrente
    /// dell'app, ed e' la stessa regola di sempre — chi rilegge cio' che ha
    /// mandato a Marco sta guardando la conversazione con Marco.
    ///
    /// Fallendo tutti, [`Error::OwnMessage`]: sappiamo che e' nostro perche'
    /// c'e' scritto, ma il destinatario non e' piu' fra i contatti — succede se
    /// e' stato dimenticato.
    fn riapri_un_mio_messaggio(
        &mut self,
        app_package: &str,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<IncomingItem> {
        for candidato in self.keyring.peers()? {
            let Ok(plaintext) = baseline::open_as_sender(&self.identity, &candidato, parsed) else {
                continue;
            };
            let recipient_label = self
                .keyring
                .get(&candidato)?
                .and_then(|record| record.label);
            self.current_peer
                .insert(app_package.to_owned(), candidato.clone());
            return Ok(IncomingItem::OwnMessage {
                recipient: candidato,
                recipient_label,
                plaintext,
            });
        }
        Err(Error::OwnMessage)
    }

    /// Cifra **a epoca** (decisione J): la conversazione resta leggibile finche'
    /// non la si brucia.
    ///
    /// Due casi, e la differenza sta solo in cosa abbiamo gia':
    ///
    /// - se il contatto ci ha gia' mandato la sua chiave d'epoca, si cifra
    ///   verso quella. Il messaggio e' rileggibile da entrambi, e muore per
    ///   entrambi quando le due chiavi vengono distrutte;
    /// - se non ce l'abbiamo — primo messaggio, o subito dopo un "brucia" — si
    ///   usa lo schema a mittente effimero, che **porta la nostra chiave
    ///   d'epoca** senza aver bisogno della sua. E' il modo in cui la
    ///   conversazione riparte da sola dopo un rogo, senza handshake e senza
    ///   canale di ritorno: qui non ce n'e' uno.
    ///
    /// Il prezzo di quel ripiego: **quel singolo messaggio non lo rileggiamo**,
    /// perche' l'effimera se n'e' andata. Uno per conversazione, e uno dopo
    /// ogni rogo.
    fn cifra_a_epoca<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        let mia = self.mia_epoca(peer, rng)?;
        // L'EPOCA del contatto, non la sua prechiave. Prima erano lo stesso
        // campo, e con la forward secrecy accesa dall'altra parte si finiva per
        // cifrare verso una chiave la cui privata lui cerca fra le prekey —
        // dove non c'e'.
        match self.epoca_del_peer(peer)? {
            Some(sua) => {
                let (header, ciphertext) = baseline::seal_epoch(
                    &self.identity,
                    &sua,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                Ok(format::serialize_message(&header, &ciphertext))
            }
            None => {
                let (header, ciphertext) = baseline::seal_epoch_bootstrap(
                    &self.identity,
                    peer,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                Ok(format::serialize_message(&header, &ciphertext))
            }
        }
    }

    /// La nostra chiave d'epoca verso quel contatto, creandola se non c'e'.
    ///
    /// **Non se ne fa una nuova a ogni messaggio**, ed e' l'unica differenza
    /// meccanica con la catena: e' quella che fa esistere la cronologia. Cambia
    /// solo quando si brucia.
    fn mia_epoca<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        rng: &mut R,
    ) -> Result<keys::EphemeralSecret> {
        // Prima si prendeva `my_prekeys(peer).first()`, cioe' la piu' recente
        // della CATENA. Due sbagli in una riga: l'epoca cambiava ogni volta che
        // la catena avanzava — e l'epoca che cambia e' un'epoca che non c'e' —
        // e leggere un messaggio a forward secrecy la buttava del tutto,
        // rendendo illeggibile la conversazione bruciabile senza che nessuno
        // avesse bruciato. La sonda e' `leggere_un_messaggio_non_brucia_l_epoca`.
        if let Some(segreto) = self.keyring.my_epoch(peer)? {
            return Ok(keys::EphemeralSecret::from_bytes(*segreto));
        }
        let nuova = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
        self.keyring.set_my_epoch(peer, *nuova.to_bytes())?;
        Ok(nuova)
    }

    /// **Brucia la conversazione** con un contatto (decisione J).
    ///
    /// Fa due cose diverse, e vale la pena non confonderle:
    ///
    /// 1. **da questo lato e' definitivo**: le chiavi con cui si leggeva quella
    ///    conversazione vengono distrutte, e non tornano. Nessun messaggio
    ///    scambiato prima si riapre piu' qui;
    /// 2. **dall'altro lato e' una richiesta**. Il blob restituito va
    ///    consegnato all'altra persona; se la sua app lo onora, distrugge le
    ///    proprie. Non e' imponibile: chi vuole tenersi i messaggi puo'
    ///    farlo, e la piattaforma ha comunque il proprio cifrato. Questa
    ///    funzione non promette il contrario.
    ///
    /// Il blob si produce **prima** di distruggere: dopo, la chiave per
    /// cifrarlo non ci sarebbe piu'.
    pub fn burn_conversation<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        let richiesta = self.cifra_richiesta_di_rogo(peer, now_unix, rng)?;
        self.keyring.burn_conversation(peer)?;
        Ok(richiesta)
    }

    fn cifra_richiesta_di_rogo<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        let mia = self.mia_epoca(peer, rng)?;
        let sua = self.epoca_del_peer(peer)?;
        // Senza una sua chiave d'epoca non c'e' niente da bruciare dall'altra
        // parte, ma la richiesta si manda lo stesso: cifrata verso la sua
        // identita', cosi' funziona anche se lui ha gia' bruciato per primo.
        let (header, ciphertext) = match sua {
            Some(sua) => baseline::seal_burn_epoch(
                &self.identity,
                &sua,
                &mia.public(),
                now_unix,
                rng,
            )?,
            None => baseline::seal_burn_static(&self.identity, peer, &mia.public(), now_unix, rng)?,
        };
        Ok(format::serialize_burn(&header, &ciphertext))
    }

    /// Memorizza la chiave temporanea di un peer **dopo averla controllata**.
    ///
    /// Una pubkey X25519 di ordine basso produce un segreto condiviso tutto
    /// zero, e la libreria lo rifiuta: se una finisse nel keyring, ogni
    /// messaggio futuro verso quel contatto fallirebbe: per sempre, con un
    /// errore opaco, e senza che l'utente possa capire perche' il lucchetto ha
    /// smesso di funzionare con una persona sola.
    ///
    /// La prekey viaggia dentro il cifrato, quindi solo quel contatto puo'
    /// spedircene una: non e' un attacco da estraneo, e' un contatto che si
    /// disabilita da solo. Sarebbe comunque il modo peggiore di rompersi, e
    /// costa una riga rifiutarla all'ingresso invece di inciamparci dopo.
    ///
    /// Rifiutandola si tiene quella di prima, e la conversazione continua.
    /// Prende nota della **prechiave** che il contatto ci ha mandato.
    ///
    /// `quando` e' l'orologio di chi ha scritto, preso da dentro il cifrato.
    /// Materiale piu' vecchio di quello che abbiamo gia' accettato da LUI si
    /// scarta: un blob resta valido per sempre, e rileggerne uno vecchio
    /// reinstallava la chiave di allora — dopo un rogo, l'epoca che lui aveva
    /// distrutto, e da quel momento i nostri messaggi gli arrivavano
    /// illeggibili senza che nessuno dei due potesse accorgersene.
    ///
    /// Non e' un giudizio sul suo orologio, che la decisione C vieta: e' un
    /// confronto con cio' che avevamo gia' accettato da lui.
    ///
    /// **`adesso` e' il nostro orologio, e serve.** Il commento qui sopra aveva
    /// considerato il caso dell'orologio che torna indietro — il peggio e' che
    /// il prossimo scambio venga ignorato finche' non recupera — ma non quello
    /// che va avanti, che e' molto peggio: una data nel futuro spinge `seen_at`
    /// avanti di anni, e da li' in poi **tutto** viene scartato per sempre.
    ///
    /// `seen_at` e' in comune con [`Self::ricorda_epoca_del_peer`], quindi
    /// avvelenarlo da qui avvelena anche le epoche. Correggere solo l'altra
    /// funzione non sarebbe servito a niente.
    fn ricorda_prekey(
        &mut self,
        peer: &PublicKey,
        prekey: &PublicKey,
        quando: i64,
        adesso: i64,
    ) -> Result<()> {
        if self.identity.diffie_hellman(prekey).is_err() {
            return Ok(());
        }
        let quando = quando.min(adesso);
        if quando < self.keyring.seen_at(peer)? {
            return Ok(());
        }
        self.keyring.set_seen_at(peer, quando)?;
        self.keyring.set_peer_prekey(peer, prekey)
    }

    /// Prende nota della **chiave d'epoca** del contatto.
    ///
    /// Va in un campo suo e non in quello della prechiave: una ruota e si
    /// butta, l'altra no. Mescolate, chi cifrava con la forward secrecy accesa
    /// ripescava l'epoca e ci cifrava contro come se fosse una prechiave — e
    /// chi riceveva non apriva piu' niente, perche' la privata di quella chiave
    /// sta nella sua epoca e non fra le sue prekey.
    ///
    /// Stessa regola di recenza di [`Self::ricorda_prekey`].
    /// L'epoca del contatto, con il ripiego sullo stato salvato prima che
    /// avesse un campo suo.
    ///
    /// Il ripiego non indovina: quello che c'e' nella prechiave e' una chiave
    /// che il contatto ci ha mandato davvero, e prima della separazione era
    /// **anche** l'unico posto in cui la sua epoca finiva. Si esaurisce da solo
    /// quando lui ce ne manda una nuova.
    fn epoca_del_peer(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        if let Some(epoca) = self.keyring.peer_epoch(peer)? {
            if self.identity.diffie_hellman(&epoca).is_ok() {
                return Ok(Some(epoca));
            }
        }
        Ok(self
            .keyring
            .peer_prekey(peer)?
            .filter(|k| self.identity.diffie_hellman(k).is_ok()))
    }

    /// `quando` e' il timestamp **dichiarato dal mittente**; `adesso` e' il
    /// nostro. Servono tutti e due, e il secondo mancava.
    ///
    /// Il confronto con `seen_at` esiste per impedire un ritorno indietro: un
    /// blob vecchio ripubblicato non deve riportare in vita un'epoca che il
    /// mittente ha gia' cambiato. E' la stessa famiglia di difese di `rogo_a`,
    /// ed e' giusta.
    ///
    /// Ma il valore su cui si appoggiava veniva **solo** dall'orologio di chi
    /// scrive, che la decisione C definisce «autenticato ma non verificabile» e
    /// su cui vieta di prendere decisioni automatiche. Qui una decisione
    /// automatica c'era, e il guasto che produceva era permanente: bastava un
    /// messaggio datato nel futuro — un telefono con l'ora sbagliata, cosa che
    /// capita — perche' `seen_at` saltasse in avanti di anni. Da quel momento
    /// **ogni** epoca successiva veniva scartata in silenzio, chi scriveva
    /// continuava a cifrare verso un'epoca morta, e i suoi messaggi non si
    /// aprivano piu'. Nessuno aveva fatto niente, e non c'era modo di uscirne.
    ///
    /// La correzione e' prendere il minore dei due. Il ritorno indietro resta
    /// bloccato — un blob vecchio ha una data vecchia comunque la si guardi —
    /// mentre una data nel futuro non puo' piu' avvelenare lo stato, perche'
    /// viene tagliata a quando l'abbiamo ricevuta davvero.
    ///
    /// Segnalato da un'utente reale, con la catena spenta: i suoi messaggi «a
    /// volte» non si aprivano a chi li riceveva.
    fn ricorda_epoca_del_peer(
        &mut self,
        peer: &PublicKey,
        epoca: &PublicKey,
        quando: i64,
        adesso: i64,
    ) -> Result<()> {
        if self.identity.diffie_hellman(epoca).is_err() {
            return Ok(());
        }
        let quando = quando.min(adesso);
        if quando < self.keyring.seen_at(peer)? {
            return Ok(());
        }
        self.keyring.set_seen_at(peer, quando)?;
        self.keyring.set_peer_epoch(peer, epoca)
    }

    /// Apre un messaggio a epoca. Il terzo valore dice se l'abbiamo scritto noi.
    ///
    /// La chiave del mittente e' in chiaro, quindi non serve provare i
    /// contatti: si sa gia' chi ha scritto. Serve solo la chiave d'epoca
    /// giusta, e se e' stata bruciata non c'e' piu' niente da fare.
    fn apri_a_epoca(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, Plaintext, bool)> {
        let mittente = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("messaggio a epoca senza mittente"))?;

        let bootstrap = parsed.header.origin.is_epoch_bootstrap();

        // L'abbiamo scritto noi: si riapre con la chiave d'epoca del
        // destinatario che avevamo conservato — o, se era il primo messaggio,
        // con la sua identita'. Bruciando sparisce anche questa possibilita',
        // ed e' meta' del senso del gesto.
        if mittente == self.identity.public() {
            let mut contatti = 0usize;
            for candidato in self.keyring.peers()? {
                contatti = contatti.saturating_add(1);
                let aperto = if bootstrap {
                    baseline::open_epoch_bootstrap_as_sender(&self.identity, &candidato, parsed)
                } else {
                    let Some(sua) = self.epoca_del_peer(&candidato)? else {
                        continue;
                    };
                    baseline::open_epoch_as_sender(&self.identity, &sua, parsed)
                };
                if let Ok((_, plaintext)) = aperto {
                    return Ok((candidato, plaintext, true));
                }
            }
            return Err(perche_non_si_riapre(bootstrap, contatti));
        }

        // Il primo messaggio di una conversazione arriva cifrato verso la
        // nostra identita': non serve nessuna chiave d'epoca nostra, ed e'
        // esattamente il motivo per cui la conversazione puo' ripartire dopo
        // un rogo senza che nessuno debba rimandare una presentazione.
        if bootstrap {
            let (sua_epoca, plaintext) =
                baseline::open_epoch_bootstrap(&self.identity, &mittente, parsed)?;
            self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
            return Ok((mittente, plaintext, false));
        }

        // La nostra epoca, che ora ha un posto suo e non e' piu' la piu' recente
        // della catena. **Non si butta niente**: qui la cronologia deve
        // restare, ed e' l'unica differenza operativa con la catena.
        if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
            let mia = keys::EphemeralSecret::from_bytes(*segreto);
            if let Ok((sua_epoca, plaintext)) = baseline::open_epoch(&mia, &mittente, parsed) {
                self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
                return Ok((mittente, plaintext, false));
            }
        }

        // Ripiego per lo stato salvato PRIMA che l'epoca avesse un posto suo,
        // quando viveva dentro la catena. Senza, aggiornare l'app renderebbe
        // illeggibili le conversazioni bruciabili gia' in corso — che e' lo
        // stesso danno che questa correzione elimina, arrivato da un'altra
        // parte. Non indovina quale prekey fosse l'epoca: le prova, e sono
        // chiavi che esistono comunque. Si esaurisce da solo quando le vecchie
        // prekey cadono.
        for segreto in self.keyring.my_prekeys(&mittente)? {
            let mia = keys::EphemeralSecret::from_bytes(*segreto);
            let Ok((sua_epoca, plaintext)) = baseline::open_epoch(&mia, &mittente, parsed) else {
                continue;
            };
            // Si adotta come epoca, e si toglie dalla catena: da qui in avanti
            // sta in UN posto solo. Lasciandolo in tutti e due,
            // `drop_my_prekeys_older_than` ne avrebbe toccato uno, e un segreto
            // che la forward secrecy dichiara distrutto sarebbe rimasto sul
            // disco come epoca.
            //
            // **Ma solo se un'epoca non c'e' gia'**, e la guardia mancava.
            //
            // Questo ripiego serve a migrare uno stato salvato prima che
            // l'epoca avesse un posto suo: per definizione, li' un'epoca non
            // c'e'. Senza la guardia bastava pero' un blob vecchio
            // ripubblicato, cifrato verso una prechiave ancora in catena, per
            // far fallire il percorso normale e finire qui — e
            // `set_my_epoca` sovrascrive senza chiedere. L'epoca corrente
            // veniva sostituita da una di mesi prima, in silenzio, e da quel
            // momento tutti quelli che cifravano verso quella vera non
            // venivano piu' letti.
            //
            // Stessa famiglia degli altri tre difetti corretti qui accanto: uno
            // stato che degrada in modo irreversibile per colpa di un ingresso
            // che non controlliamo. E la coda minima delle prechiavi, appena
            // introdotta, lo rendeva **piu'** raggiungibile, non meno: tiene in
            // vita piu' a lungo proprio le chiavi che questo ciclo prova.
            //
            // Il messaggio si legge lo stesso: aprirlo non fa danno, adottarlo
            // si'.
            if self.keyring.my_epoch(&mittente)?.is_none() {
                self.keyring.set_my_epoch(&mittente, *segreto)?;
                self.keyring.forget_my_prekey(&mittente, &segreto)?;
            }
            self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
            return Ok((mittente, plaintext, false));
        }
        Err(Error::Crypto)
    }

    /// Apre un messaggio di gruppo provando i contatti fissati.
    ///
    /// L'header porta la sola effimera, quindi chi ha scritto non e' scritto da
    /// nessuna parte: come per i messaggi effimeri si prova, e come per quelli
    /// **il mittente deve gia' essere fra i contatti**. Un gruppo da uno
    /// sconosciuto non si apre, ed e' coerente: senza la sua identita' la
    /// chiave dello slot non si ricava nemmeno.
    ///
    /// La propria identita' e' fra i candidati, in coda: e' cosi' che si
    /// rilegge cio' che si e' scritto. In coda e non in testa perche' il caso
    /// comune e' ricevere, non rileggere.
    fn apri_di_gruppo(
        &mut self,
        parsed: &crate::format::ParsedGroup<'_>,
    ) -> Result<(PublicKey, Plaintext)> {
        for candidato in self.keyring.peers()? {
            if let Ok(aperto) = baseline::open_group(&self.identity, &candidato, parsed) {
                return Ok((candidato, aperto));
            }
        }
        let mio = self.identity.public();
        if let Ok(aperto) = baseline::open_group(&self.identity, &mio, parsed) {
            return Ok((mio, aperto));
        }
        Err(Error::Crypto)
    }

    /// Cifra per piu' destinatari (decisione K).
    ///
    /// I destinatari li sceglie chi chiama, sempre e per intero: non esiste un
    /// "gruppo corrente" che si stabilisca leggendo, come succede fra due
    /// persone. Il motivo e' lo stesso per cui un allegato vuole la scelta
    /// esplicita — un messaggio mandato al gruppo sbagliato non si ritira — con
    /// in piu' che qui gli sbagliati sarebbero molti insieme.
    ///
    /// **Non ha forward secrecy**, per decisione: chi mostra il risultato deve
    /// dirlo.
    pub fn encrypt_group<R: RngCore + CryptoRng>(
        &mut self,
        destinatari: &[PublicKey],
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        // Si cifra solo verso contatti fissati: verso una chiave mai vista non
        // si saprebbe nemmeno se e' la persona giusta, e in un gruppo l'errore
        // si moltiplica.
        for chiave in destinatari {
            if self.keyring.get(chiave)?.is_none() {
                return Err(Error::UnknownPeer);
            }
        }
        let (header, slots, ciphertext) =
            baseline::seal_group(&self.identity, destinatari, plaintext, now_unix, rng)?;
        crate::format::serialize_group(&header, &slots, &ciphertext)
    }

    /// Chi ha chiesto il rogo. Si **decifra** per saperlo: senza, chiunque
    /// potrebbe cancellare le conversazioni altrui spedendo un blob a caso.
    fn mittente_di_un_rogo(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, i64)> {
        if parsed.header.origin.uses_epoch() {
            let mittente = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("rogo senza mittente"))?;
            // La nostra epoca, dal posto suo. Il ripiego sulla catena e' per
            // lo stato salvato prima della separazione: senza, un rogo in
            // arrivo dopo l'aggiornamento non si aprirebbe, e un rogo che non
            // si apre e' una richiesta di distruzione che si perde in silenzio.
            if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, aperto)) = baseline::open_burn_epoch(&mia, &mittente, parsed) {
                    return Ok((mittente, aperto.sent_at_unix()));
                }
            }
            for segreto in self.keyring.my_prekeys(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, aperto)) = baseline::open_burn_epoch(&mia, &mittente, parsed) {
                    return Ok((mittente, aperto.sent_at_unix()));
                }
            }
            return Err(Error::Crypto);
        }
        // Chi chiede il rogo senza avere una nostra chiave d'epoca lo cifra
        // verso la nostra identita': succede quando avevamo gia' bruciato noi.
        let mittente = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("rogo senza mittente"))?;
        // Si decifra PRIMA di guardare il keyring, e il fallito non si
        // distingue: prima l'ordine era invertito e l'errore diverso —
        // `UnknownPeer` per un mittente non fissato, `Crypto` per un blob che
        // non si apre. Bastava spedire un rogo qualsiasi con una pubkey
        // candidata per sapere dall'errore se quella persona e' fra i contatti
        // della vittima, senza avere nessuna chiave. E' l'oracolo di
        // appartenenza che il threat model vieta, e costava zero costruirlo.
        //
        // Decifrare prima non e' solo per l'oracolo: e' anche l'unica prova che
        // chi chiede il rogo possieda davvero quella privata.
        let (_, aperto) = baseline::open_burn_static(&self.identity, &mittente, parsed)
            .map_err(|_| Error::Crypto)?;
        if self.keyring.get(&mittente)?.is_none() {
            return Err(Error::Crypto);
        }
        Ok((mittente, aperto.sent_at_unix()))
    }

    /// [`Self::prova_i_contatti`] per gli allegati.
    fn prova_i_contatti_sul_file(
        &self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, PublicKey, file::DecryptedFile)> {
        for candidato in self.keyring.peers()? {
            if let Ok((prekey, aperto)) =
                file::open_file_ephemeral(&self.identity, &candidato, parsed)
            {
                return Ok((candidato, prekey, aperto));
            }
        }
        Err(Error::Crypto)
    }

    /// [`Self::prova_con_le_prekey`] per gli allegati: stessa catena, stesso
    /// gesto di buttare le chiavi vecchie.
    fn prova_le_prekey_sul_file(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, file::DecryptedFile)> {
        let mio = self.identity.public();
        for candidato in self.keyring.peers()? {
            for segreto in self.keyring.my_prekeys(&candidato)? {
                let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                let Ok((prossima, aperto)) =
                    file::open_file_forward(&prekey, &candidato, &mio, parsed)
                else {
                    continue;
                };
                self.ricorda_prekey(&candidato, &prossima, aperto.sent_at_unix, adesso)?;
                self.keyring
                    .drop_my_prekeys_older_than(&candidato, &segreto)?;
                return Ok((candidato, aperto));
            }
        }
        Err(Error::Crypto)
    }

    /// Dimentica un peer, e smette di usarlo come destinatario.
    ///
    /// Togliere la seconda parte sarebbe un guasto silenzioso: il contatto
    /// sparisce dall'elenco ma si continua a cifrare verso quella chiave,
    /// perche' il destinatario corrente e' una mappa a parte. Si scoprirebbe
    /// solo dall'altro lato, quando qualcuno riceve messaggi che non doveva.
    pub fn forget_peer(&mut self, peer: &PublicKey) -> Result<bool> {
        let c_era = self.keyring.forget(peer)?;
        self.current_peer.retain(|_, corrente| corrente != peer);
        Ok(c_era)
    }

    /// Prova ad aprire un messaggio a mittente effimero con ciascun contatto.
    ///
    /// Costa una decifratura per contatto, e con qualche decina di contatti
    /// non si nota. Chi non e' nel keyring non viene riconosciuto: e' voluto,
    /// perche' un mittente sconosciuto va presentato con una card prima —
    /// altrimenti chiunque potrebbe far comparire messaggi nel keyring.
    ///
    /// Fallendo tutte, l'errore e' [`Error::Crypto`] come qualunque altro
    /// fallimento: non si distingue "nessuno dei miei contatti" da "messaggio
    /// corrotto", perche' distinguerli direbbe a chi attacca qualcosa sul
    /// contenuto del keyring.
    fn prova_i_contatti(
        &self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, PublicKey, Plaintext)> {
        for candidato in self.keyring.peers()? {
            if let Ok((prekey, plaintext)) =
                baseline::open_ephemeral(&self.identity, &candidato, parsed)
            {
                return Ok((candidato, prekey, plaintext));
            }
        }
        Err(Error::Crypto)
    }

    /// Come [`Self::prova_i_contatti`], per i messaggi a forward secrecy piena:
    /// si provano i contatti **per ciascuna** delle nostre chiavi temporanee.
    ///
    /// Poche moltiplicate per pochi: qualche decina di tentativi, ciascuno un
    /// AEAD su un messaggio breve.
    ///
    /// Quando uno riesce si fanno due cose, e sono le due che mandano avanti la
    /// catena: si prende nota della prossima chiave del mittente, e si buttano
    /// le nostre piu' vecchie di quella appena usata. Da quel momento i
    /// messaggi che le usavano non si riaprono piu' — nemmeno per noi.
    fn prova_con_le_prekey(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, Plaintext)> {
        let mio = self.identity.public();
        for candidato in self.keyring.peers()? {
            for segreto in self.keyring.my_prekeys(&candidato)? {
                let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                let Ok((prossima, plaintext)) =
                    baseline::open_forward(&prekey, &candidato, &mio, parsed)
                else {
                    continue;
                };
                self.ricorda_prekey(&candidato, &prossima, plaintext.sent_at_unix(), adesso)?;
                self.keyring
                    .drop_my_prekeys_older_than(&candidato, &segreto)?;
                return Ok((candidato, plaintext));
            }
        }
        Err(Error::Crypto)
    }

    /// Apre un messaggio **senza toccare il keyring**, per leggere un archivio.
    ///
    /// La differenza con [`Self::handle_incoming_text`] non e' una comodita':
    /// un'esportazione di chat contiene qualunque cosa, anche messaggi di
    /// conversazioni diverse o fabbricati, e fissare chiavi leggendo un file
    /// sarebbe un modo per riempirsi il keyring senza accorgersene — e per
    /// vedersi comparire un falso "la chiave di Marco e' cambiata".
    ///
    /// Legge e basta: nessun pin, nessun destinatario scelto, nessuno stato
    /// modificato.
    pub fn open_archived(&self, text: &str) -> Result<(PublicKey, Plaintext)> {
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(text, &mut buf)? else {
            return Err(Error::Format("non e' un messaggio"));
        };
        // Schema a epoca: si legge finche' le chiavi esistono, e leggere un
        // archivio non le tocca — come per la catena, e per la stessa ragione.
        if parsed.header.origin.uses_epoch() || parsed.header.origin.is_epoch_bootstrap() {
            let bootstrap = parsed.header.origin.is_epoch_bootstrap();
            let mittente = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("messaggio a epoca senza mittente"))?;
            if mittente == self.identity.public() {
                let mut contatti = 0usize;
                for candidato in self.keyring.peers()? {
                    contatti = contatti.saturating_add(1);
                    let aperto = if bootstrap {
                        baseline::open_epoch_bootstrap_as_sender(&self.identity, &candidato, &parsed)
                    } else {
                        let Some(sua) = self.epoca_del_peer(&candidato)? else {
                            continue;
                        };
                        baseline::open_epoch_as_sender(&self.identity, &sua, &parsed)
                    };
                    if let Ok((_, plaintext)) = aperto {
                        return Ok((candidato, plaintext));
                    }
                }
                return Err(perche_non_si_riapre(bootstrap, contatti));
            }
            if bootstrap {
                let (_, plaintext) =
                    baseline::open_epoch_bootstrap(&self.identity, &mittente, &parsed)?;
                return Ok((mittente, plaintext));
            }
            // La nostra epoca, dal posto suo. Mancava, e la conseguenza era
            // grossa: lo stesso blob si apriva dalla tastiera e dava
            // `Error::Crypto` dall'archivio. Cioe' la **cronologia** — l'unica
            // cosa che si compra rinunciando alla forward secrecy — non era
            // ricostruibile proprio per i messaggi ricevuti.
            //
            // E' la stessa dimenticanza gia' corretta nella via di lettura:
            // separando l'epoca dalla catena si e' aggiornato chi legge un
            // messaggio in arrivo e non chi rilegge un archivio.
            if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, plaintext)) = baseline::open_epoch(&mia, &mittente, &parsed) {
                    return Ok((mittente, plaintext));
                }
            }
            // Ripiego per lo stato salvato prima della separazione, come nella
            // via di lettura.
            for segreto in self.keyring.my_prekeys(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, plaintext)) = baseline::open_epoch(&mia, &mittente, &parsed) {
                    return Ok((mittente, plaintext));
                }
            }
            return Err(Error::Crypto);
        }
        if parsed.header.origin.uses_prekey() {
            // Le chiavi ancora vive si possono usare: sono nostre e le abbiamo
            // gia'. Cade solo cio' che la catena ha gia' buttato, che e'
            // esattamente la proprieta' — non un limite da aggirare.
            //
            // **Non fa avanzare la catena.** Leggere un archivio non e'
            // ricevere un messaggio: se buttasse le chiavi vecchie, aprire una
            // vecchia conversazione ucciderebbe i messaggi ancora in viaggio, e
            // fissare la prossima chiave del mittente da un file lascerebbe a
            // chiunque ci mandi un'esportazione il modo di dirottare la
            // conversazione successiva.
            let mio = self.identity.public();
            for candidato in self.keyring.peers()? {
                for segreto in self.keyring.my_prekeys(&candidato)? {
                    let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                    if let Ok((_, plaintext)) =
                        baseline::open_forward(&prekey, &candidato, &mio, &parsed)
                    {
                        return Ok((candidato, plaintext));
                    }
                }
            }
            return Err(Error::Crypto);
        }
        if parsed.header.origin.is_ephemeral() {
            let (mittente, _, plaintext) = self.prova_i_contatti(&parsed)?;
            return Ok((mittente, plaintext));
        }
        let sender = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("messaggio senza pubkey del mittente"))?;
        // In un'esportazione di chat meta' dei messaggi sono NOSTRI. Senza
        // questo ramo, "ricostruisci" mostrerebbe solo cio' che abbiamo
        // ricevuto e lascerebbe chiuso tutto quello che abbiamo scritto — che
        // e' meta' della conversazione, e la meta' che l'utente sa gia' di
        // poter leggere.
        if sender == self.identity.public() {
            for candidato in self.keyring.peers()? {
                if let Ok(plaintext) =
                    baseline::open_as_sender(&self.identity, &candidato, &parsed)
                {
                    return Ok((candidato, plaintext));
                }
            }
            return Err(Error::OwnMessage);
        }
        let plaintext = baseline::open(&self.identity, &sender, &parsed)?;
        Ok((sender, plaintext))
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
        prekey: crate::keys::PrekeyStore,
    }

    impl Keyring for KeyringInMemoria {
        fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
            Ok(self.prekey.peer_prekey(peer))
        }

        fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()> {
            self.prekey.set_peer_prekey(peer, prekey);
            Ok(())
        }

        fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<zeroize::Zeroizing<[u8; 32]>>> {
            Ok(self.prekey.my_prekeys(peer))
        }

        fn my_epoch(&self, peer: &PublicKey) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
            Ok(self.prekey.my_epoch(peer))
        }

        fn peer_epoch(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
            Ok(self.prekey.peer_epoch(peer))
        }

        fn set_peer_epoch(&mut self, peer: &PublicKey, epoca: &PublicKey) -> Result<()> {
            self.prekey.set_peer_epoch(peer, epoca);
            Ok(())
        }

        fn seen_at(&self, peer: &PublicKey) -> Result<i64> {
            Ok(self.prekey.seen_at(peer))
        }

        fn set_seen_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
            self.prekey.set_seen_at(peer, quando);
            Ok(())
        }

        fn burned_at(&self, peer: &PublicKey) -> Result<i64> {
            Ok(self.prekey.burned_at(peer))
        }

        fn set_burned_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
            self.prekey.set_burned_at(peer, quando);
            Ok(())
        }

        fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; 32]) -> Result<()> {
            self.prekey.forget_my_prekey(peer, secret);
            Ok(())
        }

        fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; 32]) -> Result<()> {
            self.prekey.set_my_epoch(peer, secret);
            Ok(())
        }

        fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; 32]) -> Result<()> {
            self.prekey.push_my_prekey(peer, secret);
            Ok(())
        }

        fn drop_my_prekeys_older_than(
            &mut self,
            peer: &PublicKey,
            secret: &[u8; 32],
        ) -> Result<()> {
            self.prekey.drop_my_prekeys_older_than(peer, secret);
            Ok(())
        }

        fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()> {
            self.prekey.burn(peer);
            Ok(())
        }

        fn peers(&self) -> Result<Vec<PublicKey>> {
            Ok(self.peers.iter().map(|p| p.public.clone()).collect())
        }

        fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
            match self.peers.iter().position(|p| &p.public == peer) {
                Some(i) => {
                    self.peers.remove(i);
                    self.prekey.forget(peer);
                    Ok(true)
                }
                None => Ok(false),
            }
        }

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

    /// Copiare la propria chiave e riaprirla creava un contatto che e' se
    /// stessi: una rubrica che mente, e da li' in poi "per chi sto cifrando"
    /// non ha piu' una risposta affidabile.
    /// Il giro completo di un gruppo, dal livello che lo usera' davvero.
    #[test]
    fn un_gruppo_si_apre_da_tutti_e_dice_quanti_erano() {
        let mut alice = sessione(1);
        let mut babbo = sessione(2);
        let mut mamma = sessione(3);
        let chiave_alice = alice.identity.public();
        let chiave_babbo = babbo.identity.public();
        let chiave_mamma = mamma.identity.public();

        // Si conoscono: un gruppo verso chi non e' fissato non si manda, e da
        // chi non e' fissato non si apre.
        alice.keyring.tofu_pin(&chiave_babbo, 1).unwrap();
        alice.keyring.tofu_pin(&chiave_mamma, 1).unwrap();
        babbo.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        mamma.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let blob = alice
            .encrypt_group(
                &[chiave_babbo.clone(), chiave_mamma.clone()],
                b"ci vediamo domenica",
                50,
                &mut rng(4),
            )
            .unwrap();

        for chi in [&mut babbo, &mut mamma] {
            let IncomingItem::Message(messaggio) =
                chi.handle_incoming_text(WHATSAPP, &blob, 51).unwrap()
            else {
                panic!("atteso un messaggio")
            };
            assert_eq!(messaggio.plaintext.as_bytes(), b"ci vediamo domenica");
            assert_eq!(messaggio.sender, chiave_alice);
            // Tre slot: babbo, mamma e Alice. Serve a dire in interfaccia che
            // un messaggio di gruppo non ha forward secrecy.
            assert!(messaggio.gruppo);
            assert_eq!(messaggio.destinatari, 3);
        }

        // Alice rilegge il suo.
        let IncomingItem::Message(riletto) =
            alice.handle_incoming_text(WHATSAPP, &blob, 52).unwrap()
        else {
            panic!("atteso un messaggio")
        };
        assert_eq!(riletto.plaintext.as_bytes(), b"ci vediamo domenica");

        // LA RIGA CHE CONTA: leggere un messaggio di gruppo NON sceglie il
        // mittente come destinatario. Altrimenti la risposta partirebbe in
        // privato a lui, dentro la chat dove tutti aspettano di leggerla.
        assert_eq!(babbo.current_peer(WHATSAPP), None);
    }

    /// Rileggere un proprio messaggio di gruppo non deve mettere l'utente fra
    /// i propri contatti: e' la rubrica che mente, gia' corretta altrove.
    /// Lo stesso blob deve aprirsi dalla tastiera E dall'archivio: la
    /// cronologia e' l'unica cosa che si compra rinunciando alla forward
    /// secrecy, e non serve a niente se e' ricostruibile solo a meta'.
    #[test]
    fn l_archivio_apre_quel_che_apre_la_tastiera() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Apertura bruciabile, cosi' Bob impara l'epoca di Alice e le risponde.
        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();
        let risposta = bob
            .encrypt_for_app_with(WHATSAPP, b"ci sono", 12, &mut rng(2), false)
            .unwrap();

        // Dalla tastiera si apre.
        alice.handle_incoming_text(WHATSAPP, &risposta, 13).unwrap();
        // E dall'archivio pure: prima qui usciva Error::Crypto.
        let (chi, aperto) = alice.open_archived(&risposta).unwrap();
        assert_eq!(chi, chiave_bob);
        assert_eq!(aperto.as_bytes(), b"ci sono");
    }

    #[test]
    fn rileggere_un_proprio_gruppo_non_fissa_se_stessi() {
        let mut alice = sessione(1);
        let babbo = sessione(2).identity.public();
        alice.keyring.tofu_pin(&babbo, 1).unwrap();
        let quanti_prima = alice.keyring.peers().unwrap().len();

        let blob = alice
            .encrypt_group(&[babbo], b"ciao a tutti", 50, &mut rng(6))
            .unwrap();
        let IncomingItem::Message(riletto) =
            alice.handle_incoming_text(WHATSAPP, &blob, 51).unwrap()
        else {
            panic!("atteso un messaggio")
        };

        assert_eq!(riletto.plaintext.as_bytes(), b"ciao a tutti");
        assert!(riletto.gruppo);
        assert_eq!(riletto.sender, alice.identity.public());
        // LA RIGA CHE CONTA: la rubrica non e' cresciuta.
        assert_eq!(alice.keyring.peers().unwrap().len(), quanti_prima);
        // E non si chiede "chi e'?" su una frase propria.
        assert!(matches!(riletto.sender_status, SenderStatus::Known { .. }));
    }

    /// L'altra meta' della condizione 1 di K1: mandare e aprire un messaggio di
    /// gruppo non deve toccare lo stato da cui dipende la forward secrecy a
    /// due.
    ///
    /// E' la sostanza della condizione — «il gruppo non deve poter indebolire
    /// il dialogo a due» — e senza test era affidata all'attenzione di chi
    /// scriveva il codice, che e' esattamente cio' che la decisione diceva di
    /// non fare.
    ///
    /// Se un giorno qualcuno provasse a dare forward secrecy ai gruppi
    /// attaccandosi alle prechiavi esistenti (la via che K1 vieta, motivo 2:
    /// non c'e' un distributore), questo test si accorgerebbe che la catena a
    /// due si e' mossa.
    /// Il caso segnalato da un'utente reale, e bastano **due** messaggi.
    ///
    /// Lei ne manda due, cifrati con due prechiavi diverse di chi riceve. Lui
    /// apre prima il secondo. Prima della coda minima il primo — mai aperto —
    /// diventava illeggibile per sempre.
    ///
    /// Non serve nessuna raffica: serve solo leggere in ordine diverso da
    /// quello di invio, che in un mezzo fatto di copia-incolla e' la norma.
    #[test]
    fn due_messaggi_letti_fuori_ordine_si_aprono_tutti_e_due() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob scrive due volte: due prechiavi sue, la seconda piu' recente.
        let b1 = bob
            .encrypt_for_app_with("app", b"uno", 10, &mut rng(1), true)
            .unwrap();
        let b2 = bob
            .encrypt_for_app_with("app", b"due", 11, &mut rng(2), true)
            .unwrap();

        // Alice legge il primo e risponde con la prechiave che ha appena visto.
        alice.handle_incoming_text("app", &b1, 12).unwrap();
        let a1 = alice
            .encrypt_for_app_with("app", b"rispondo a uno", 13, &mut rng(3), true)
            .unwrap();

        // Poi legge il secondo e risponde di nuovo, con una piu' recente.
        alice.handle_incoming_text("app", &b2, 14).unwrap();
        let a2 = alice
            .encrypt_for_app_with("app", b"rispondo a due", 15, &mut rng(4), true)
            .unwrap();

        // Bob apre prima la SECONDA risposta.
        assert!(bob.handle_incoming_text("app", &a2, 16).is_ok());

        // E poi la prima, che era arrivata prima ed e' ancora li'.
        let esito = bob.handle_incoming_text("app", &a1, 17);
        assert!(esito.is_ok(), "la prima risposta non si apre: {:?}", esito.err());
    }

    /// Un solo messaggio con l'orologio avanti avvelena lo stato **per
    /// sempre**.
    ///
    /// `ricorda_epoca_del_peer` rifiuta le epoche piu' vecchie di `seen_at`, e
    /// `seen_at` viene dal timestamp **dichiarato dal mittente**, che la
    /// decisione C definisce autenticato ma non verificabile. Basta che un
    /// messaggio arrivi datato nel futuro — un telefono con l'ora sbagliata, e
    /// capita — e da li' in poi ogni epoca nuova viene ignorata in silenzio.
    ///
    /// Da fuori: i messaggi di chi scrive smettono di aprirsi a chi li riceve,
    /// senza che nessuno abbia fatto niente.
    #[test]
    fn un_orologio_avanti_non_blocca_le_epoche_future() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob scrive con l'orologio sballato: dice di essere nel 2050.
        let futuro = 2_500_000_000;
        let sballato = bob
            .encrypt_for_app_with("app", b"ciao", futuro, &mut rng(1), false)
            .unwrap();
        alice.handle_incoming_text("app", &sballato, 100).unwrap();

        // Bob rimette l'ora giusta e brucia la conversazione: epoca nuova.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let corretto = bob
            .encrypt_for_app_with("app", b"di nuovo", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &corretto, 201).unwrap();

        // Alice deve aver imparato l'epoca nuova: altrimenti cifra verso quella
        // bruciata e Bob non apre piu' niente.
        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 202, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 203);
        assert!(esito.is_ok(), "Bob non apre la risposta: {:?}", esito.err());
    }

    /// Il contrappeso del test qui sopra: **un blob vecchio ripubblicato non
    /// riporta indietro l'epoca**.
    ///
    /// E' la difesa che il confronto con `seen_at` esiste per dare, e la
    /// correzione sull'orologio non deve averla tolta. Un messaggio vecchio ha
    /// una data vecchia comunque la si guardi — prendendo il minore fra la data
    /// dichiarata e la nostra, resta vecchia — quindi viene ancora scartato.
    #[test]
    fn un_messaggio_vecchio_ripubblicato_non_riporta_indietro_l_epoca() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Un messaggio di Bob di molto tempo fa, che Alice si tiene da parte.
        let vecchio = bob
            .encrypt_for_app_with("app", b"antico", 100, &mut rng(1), false)
            .unwrap();

        // Bob cambia epoca e scrive di nuovo; Alice legge e impara la nuova.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let nuovo = bob
            .encrypt_for_app_with("app", b"recente", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &nuovo, 201).unwrap();

        // Ora qualcuno ripubblica quello vecchio. Alice lo apre — e' un blob
        // valido — ma NON deve tornare all'epoca di allora.
        let _ = alice.handle_incoming_text("app", &vecchio, 300);

        // La prova: la sua risposta deve ancora aprirsi.
        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 301, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 302);
        assert!(
            esito.is_ok(),
            "l'epoca e' tornata indietro: {:?}",
            esito.err()
        );
    }

    /// Una richiesta di rogo datata nel futuro non deve **disattivare i roghi
    /// futuri**.
    ///
    /// Terzo punto della stessa famiglia — `burned_at`, come `seen_at` — e il
    /// piu' grave: qui a smettere di funzionare sarebbe la sola operazione
    /// distruttiva del sistema, in silenzio, con l'errore opaco che non
    /// distingue "gia' fatto" da "non valido". Chi chiede di bruciare una
    /// conversazione crederebbe di averlo fatto.
    #[test]
    fn un_rogo_datato_nel_futuro_non_blocca_i_roghi_dopo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();

        // Bob brucia con l'orologio sballato.
        let futuro = 2_500_000_000;
        let primo = bob.burn_conversation(&ka, futuro, &mut rng(1)).unwrap();
        assert!(matches!(
            alice.handle_incoming_text("app", &primo, 100),
            Ok(IncomingItem::Burned { .. })
        ));

        // Bob rimette l'ora e brucia di nuovo, piu' tardi. Deve essere onorato.
        let secondo = bob.burn_conversation(&ka, 200, &mut rng(2)).unwrap();
        assert!(
            matches!(
                alice.handle_incoming_text("app", &secondo, 201),
                Ok(IncomingItem::Burned { .. })
            ),
            "il secondo rogo e' stato rifiutato: la funzione era disattivata"
        );
    }

    /// Lo stesso avvelenamento, ma per la via delle **prechiavi**.
    ///
    /// `seen_at` e' in comune fra `ricorda_prekey` e `ricorda_epoca_del_peer`,
    /// quindi correggere solo la seconda non sarebbe servito a niente: un
    /// messaggio a catena datato nel futuro avvelenava anche le epoche.
    #[test]
    fn un_orologio_avanti_sulla_catena_non_avvelena_le_epoche() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob scrive CON la catena e con l'orologio sballato: passa da
        // `ricorda_prekey`, che e' l'altra porta su `seen_at`.
        let futuro = 2_500_000_000;
        let sballato = bob
            .encrypt_for_app_with("app", b"ciao", futuro, &mut rng(1), true)
            .unwrap();
        alice.handle_incoming_text("app", &sballato, 100).unwrap();

        // Poi cambia epoca e scrive senza catena, con l'ora giusta.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let corretto = bob
            .encrypt_for_app_with("app", b"di nuovo", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &corretto, 201).unwrap();

        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 202, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 203);
        assert!(esito.is_ok(), "Bob non apre la risposta: {:?}", esito.err());
    }

    #[test]
    fn un_gruppo_non_tocca_la_catena_a_due() {
        let mut alice = sessione(1);
        let mut babbo = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_babbo = babbo.identity.public();
        alice.keyring.tofu_pin(&chiave_babbo, 1).unwrap();
        babbo.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        // Si costruisce prima uno stato a due vero: un messaggio con la catena
        // accesa mette una prechiave nel keyring di chi manda.
        alice.set_current_peer("app", &chiave_babbo).unwrap();
        let a_due = alice
            .encrypt_for_app_with("app", b"a due", 10, &mut rng(1), true)
            .unwrap();
        babbo.handle_incoming_text("app", &a_due, 11).unwrap();

        let prima_alice = alice.keyring.my_prekeys(&chiave_babbo).unwrap();
        let prima_babbo = babbo.keyring.my_prekeys(&chiave_alice).unwrap();
        let epoca_prima = alice.keyring.my_epoch(&chiave_babbo).unwrap();
        assert!(!prima_alice.is_empty(), "lo stato a due deve esistere");

        // Ora il gruppo, fra le stesse persone.
        let blob = alice
            .encrypt_group(
                std::slice::from_ref(&chiave_babbo),
                b"di gruppo",
                20,
                &mut rng(2),
            )
            .unwrap();
        babbo.handle_incoming_text("app", &blob, 21).unwrap();

        assert_eq!(
            alice.keyring.my_prekeys(&chiave_babbo).unwrap(),
            prima_alice,
            "cifrare un gruppo ha mosso la catena di chi manda"
        );
        assert_eq!(
            babbo.keyring.my_prekeys(&chiave_alice).unwrap(),
            prima_babbo,
            "aprire un gruppo ha mosso la catena di chi legge"
        );
        assert_eq!(
            alice.keyring.my_epoch(&chiave_babbo).unwrap(),
            epoca_prima,
            "il gruppo ha toccato la chiave d'epoca"
        );
    }

    /// Un gruppo da uno slot solo si presentava come un messaggio a due: un
    /// `version = 2` senza forward secrecy con la faccia di uno che ce l'ha.
    #[test]
    fn un_gruppo_da_uno_slot_non_esiste() {
        let mut alice = sessione(1);
        let mia = alice.identity.public();
        alice.keyring.tofu_pin(&mia, 1).unwrap();
        // Unico destinatario: se stessa. Dopo la dedup resterebbe uno slot.
        assert!(alice
            .encrypt_group(&[mia], b"ciao", 1, &mut rng(7))
            .is_err());
    }

    #[test]
    fn un_gruppo_verso_uno_sconosciuto_non_parte() {
        let mut alice = sessione(1);
        let estraneo = sessione(9).identity.public();
        assert!(matches!(
            alice.encrypt_group(&[estraneo], b"ciao", 1, &mut rng(5)),
            Err(Error::UnknownPeer)
        ));
    }

    /// SONDA. Due persone con l'interruttore impostato in modo diverso — uno
    /// lo lascia acceso (il default), l'altro lo spegne per avere la cronologia
    /// — devono potersi scrivere in tutti e due i versi.
    ///
    /// Prima no: l'epoca del contatto finiva nello stesso campo della sua
    /// prechiave, e chi cifrava con la forward secrecy accesa ci cifrava contro
    /// come se fosse una prechiave. Chi riceveva cercava la privata fra le
    /// proprie prekey — dove non c'e' — e ogni risposta era persa, per sempre,
    /// con `Error::Crypto`: lo stesso errore di un blob rovinato.
    #[test]
    fn interruttori_diversi_si_parlano_lo_stesso() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Alice tiene la forward secrecy SPENTA: vuole la cronologia.
        // Bob la tiene ACCESA, che e' il default.
        for giro in 0..3i64 {
            let da_alice = alice
                .encrypt_for_app_with(WHATSAPP, b"da alice", 100 + giro, &mut rng(1), false)
                .unwrap();
            let IncomingItem::Message(letto) =
                bob.handle_incoming_text(WHATSAPP, &da_alice, 101 + giro).unwrap()
            else {
                panic!("Bob non ha letto il messaggio di Alice al giro {giro}")
            };
            assert_eq!(letto.plaintext.as_bytes(), b"da alice");

            let da_bob = bob
                .encrypt_for_app_with(WHATSAPP, b"da bob", 102 + giro, &mut rng(2), true)
                .unwrap();
            // LA RIGA CHE CONTA: prima qui usciva Error::Crypto, ogni volta.
            let esito = alice.handle_incoming_text(WHATSAPP, &da_bob, 103 + giro);
            let IncomingItem::Message(risposta) = esito.unwrap() else {
                panic!("Alice non ha letto la risposta di Bob al giro {giro}")
            };
            assert_eq!(risposta.plaintext.as_bytes(), b"da bob");
        }
    }

    /// SONDA. Un rogo gia' onorato non si rifa': il blob resta valido per
    /// sempre, e chi l'ha visto passare poteva reincollarlo per distruggere la
    /// conversazione ripartita nel frattempo.
    #[test]
    fn un_rogo_ripubblicato_non_brucia_di_nuovo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();

        let richiesta = alice.burn_conversation(&chiave_bob, 12, &mut rng(7)).unwrap();
        // La prima volta si onora.
        let esito = bob.handle_incoming_text(WHATSAPP, &richiesta, 13).unwrap();
        assert!(matches!(esito, IncomingItem::Burned { .. }));

        // La conversazione riparte.
        let nuova = alice
            .encrypt_for_app_with(WHATSAPP, b"ricominciamo", 20, &mut rng(3), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &nuova, 21).unwrap();

        // Lo stesso blob di rogo, reincollato: NON deve bruciare la
        // conversazione nuova.
        assert!(bob.handle_incoming_text(WHATSAPP, &richiesta, 22).is_err());
        // E la conversazione nuova regge: si legge ancora.
        assert!(bob.open_archived(&nuova).is_ok());
    }

    /// SONDA (decisione J). L'epoca non deve ruotare: e' cio' che fa esistere la
    /// cronologia. Se vive nella stessa lista della catena di forward secrecy,
    /// leggere un messaggio la butta — e la conversazione diventa illeggibile
    /// senza che nessuno abbia bruciato.
    #[test]
    fn leggere_un_messaggio_non_brucia_l_epoca() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_bob = bob.identity.public();
        let chiave_alice = alice.identity.public();
        // Si conoscono gia': il primo contatto non e' cio' che si sta provando.
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // 1. Alice apre in modalita' bruciabile: nasce la sua epoca e la offre.
        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();

        // 2. Bob risponde bruciabile, cifrando verso l'epoca di Alice.
        let verso_epoca = bob
            .encrypt_for_app_with(WHATSAPP, b"prima risposta", 12, &mut rng(2), false)
            .unwrap();

        // 3. Nel frattempo si scambiano un messaggio a forward secrecy piena.
        let effimero = alice
            .encrypt_for_app_with(WHATSAPP, b"effimero", 13, &mut rng(3), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &effimero, 14).unwrap();
        let risposta_effimera = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta effimera", 15, &mut rng(4), true)
            .unwrap();
        alice
            .handle_incoming_text(WHATSAPP, &risposta_effimera, 16)
            .unwrap();

        // 4. LA RIGA CHE CONTA. Nessuno ha bruciato niente: il messaggio
        //    bruciabile di Bob deve ancora aprirsi.
        let esito = alice.handle_incoming_text(WHATSAPP, &verso_epoca, 17);
        assert!(
            esito.is_ok(),
            "l'epoca e' stata buttata leggendo un altro messaggio: {:?}",
            esito.err(),
        );
    }

    #[test]
    fn la_propria_card_non_diventa_un_contatto() {
        let mut alice = sessione(1);
        let card = alice.identity_card(&mut rng(7));

        let esito = alice.handle_incoming_text(WHATSAPP, &card, 50).unwrap();
        let IncomingItem::OwnIdentityCard { fingerprint } = esito else {
            panic!("attesa la propria card, non un contatto");
        };
        assert_eq!(fingerprint, alice.my_fingerprint());

        // La riga che conta: la rubrica non e' cresciuta. Riconoscerla e poi
        // fissarla lo stesso sarebbe il difetto con un messaggio piu' gentile.
        assert!(alice.keyring.peers().unwrap().is_empty());
        // E non si e' scelto niente come destinatario.
        assert_eq!(alice.current_peer(WHATSAPP), None);
    }

    #[test]
    fn identity_card_fissa_la_chiave_ma_non_sceglie_il_destinatario() {
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

        // LA RIGA CHE CONTA. Una card non e' autenticata: chiunque puo'
        // fabbricarne una con la propria chiave e farla arrivare alla vittima.
        // Se bastasse decifrarla per diventare il destinatario, un estraneo
        // deciderebbe per chi la vittima cifra.
        assert_eq!(bob.current_peer(WHATSAPP), None);
    }

    /// Un estraneo non deve poter dirottare una conversazione gia' stabilita
    /// mandando la propria presentazione.
    #[test]
    fn una_card_non_dirotta_il_destinatario_gia_scelto() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let estraneo = sessione(9);

        // Bob e Alice si parlano gia': Bob ha letto un messaggio di Alice, e
        // questo — la decifratura riuscita — e' cio' che autorizza la scelta
        // automatica del destinatario.
        alice.keyring.tofu_pin(&bob.identity.public(), 5).unwrap();
        alice
            .set_current_peer(WHATSAPP, &bob.identity.public())
            .unwrap();
        let msg = alice
            .encrypt_for_app(WHATSAPP, b"ciao", 10, &mut rng(3))
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &msg, 11).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));

        // Arriva la card di uno sconosciuto e Bob la decifra.
        let card = estraneo.identity_card(&mut rng(8));
        bob.handle_incoming_text(WHATSAPP, &card, 12).unwrap();

        // Il destinatario deve essere ancora Alice.
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));
    }

    /// Il ciclo completo di bootstrap: Alice si presenta, Bob la fissa,
    /// SCEGLIE di rispondere a lei, e Alice legge.
    ///
    /// Quella scelta e' un gesto dell'utente e non un automatismo: una card non
    /// e' autenticata, quindi non puo' decidere per chi si cifra. Da qui in poi
    /// pero' l'automatismo vale, perche' Alice stabilisce il destinatario
    /// decifrando un messaggio vero.
    #[test]
    fn bootstrap_completo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);

        let card = alice.identity_card(&mut rng(7));
        bob.handle_incoming_text(WHATSAPP, &card, 1).unwrap();

        // Il gesto esplicito che la card non fa al posto suo.
        bob.set_current_peer(WHATSAPP, &alice.identity.public())
            .unwrap();

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

    /// La catena: il primo messaggio parte a meta' e porta gia' la chiave con
    /// cui il prossimo sara' pieno.
    #[test]
    fn la_catena_parte_col_primo_messaggio() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();

        // Si conoscono: senza, un mittente effimero non e' riconoscibile.
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // Primo messaggio: Alice non ha una chiave temporanea di Bob, quindi
        // ripiega sulla forward secrecy a meta' — ma porta gia' la propria.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        assert!(
            bob.keyring.peer_prekey(&chiave_alice).unwrap().is_some(),
            "il primo messaggio deve far partire la catena"
        );

        // La risposta di Bob usa quella chiave: forward secrecy piena.
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta", 12, &mut rng(8), true)
            .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&due, &mut buf).unwrap() else {
            panic!()
        };
        let piena = parsed.header.origin.uses_prekey();
        assert!(piena, "la risposta doveva essere a forward secrecy piena");

        let letto = alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        let IncomingItem::Message(messaggio) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(messaggio.plaintext.as_bytes(), b"risposta");
        assert_eq!(messaggio.sender, chiave_bob);
    }

    /// Un allegato deve avere la stessa catena di un messaggio: una foto vale
    /// piu' di una riga di testo, e resta sul telefono di chi la riceve.
    #[test]
    fn anche_gli_allegati_hanno_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let meta = crate::file::FileMeta {
            name: "foto.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        };

        // Primo allegato: nessuna chiave di Bob, quindi mittente effimero —
        // ma porta gia' la propria, e la catena parte.
        let uno = alice
            .encrypt_file_with(&chiave_bob, &meta, b"contenuto", 10, &mut rng(9), true)
            .unwrap();
        let letto = bob.handle_incoming_file(&uno, 11).unwrap();
        assert_eq!(letto.sender, chiave_alice);
        assert_eq!(letto.file.meta.name, "foto.jpg");
        assert_eq!(&*letto.file.content, b"contenuto");
        assert!(
            bob.keyring.peer_prekey(&chiave_alice).unwrap().is_some(),
            "anche un allegato deve far partire la catena"
        );

        // La risposta di Bob usa quella chiave: forward secrecy piena.
        let due = bob
            .encrypt_file_with(&chiave_alice, &meta, b"risposta", 12, &mut rng(8), true)
            .unwrap();
        let piena = crate::file::parse_file(&due).unwrap().header.origin.uses_prekey();
        assert!(piena, "il secondo allegato doveva essere a forward secrecy piena");

        let letto = alice.handle_incoming_file(&due, 13).unwrap();
        assert_eq!(letto.sender, chiave_bob);
        assert_eq!(&*letto.file.content, b"risposta");
    }

    /// Un allegato non deve poter essere riletto come messaggio: `kind` sta
    /// nell'AAD anche negli schemi a mittente effimero, e se ci finisse solo in
    /// quelli statici questo test lo direbbe.
    #[test]
    fn un_allegato_non_e_un_messaggio_nemmeno_con_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let meta = crate::file::FileMeta {
            name: "a".to_owned(),
            mime: "b".to_owned(),
        };
        let allegato = alice
            .encrypt_file_with(&chiave_bob, &meta, b"segreto", 10, &mut rng(9), true)
            .unwrap();

        // Stesso corpo, riservito come messaggio: l'AAD non torna.
        let come_messaggio = {
            let parsed = crate::file::parse_file(&allegato).unwrap();
            format::serialize_message(&parsed.header, parsed.ciphertext)
        };
        assert!(bob.handle_incoming_text(WHATSAPP, &come_messaggio, 11).is_err());
    }

    /// Ricopiare un proprio messaggio gia' mandato capita, e non deve
    /// somigliare a un guasto.
    #[test]
    fn un_mio_messaggio_si_riapre_solo_senza_catena() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // Senza forward secrecy si riapre: il segreto ECDH e' simmetrico, e
        // il destinatario si trova provando i contatti.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(9), false)
            .unwrap();
        let letto = alice.handle_incoming_text(WHATSAPP, &mio, 11).unwrap();
        let IncomingItem::OwnMessage {
            recipient,
            plaintext,
            ..
        } = letto
        else {
            panic!("doveva essere un messaggio nostro")
        };
        assert_eq!(recipient, chiave_bob);
        assert_eq!(plaintext.as_bytes(), b"ciao");

        // Con la forward secrecy la nostra chiave NON c'e', per costruzione:
        // resta un fallimento opaco, ed e' giusto cosi'. Se un giorno questo
        // test cominciasse a dare OwnMessage, vorrebbe dire che l'identita' del
        // mittente e' tornata visibile nell'header.
        let effimero = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 12, &mut rng(8), true)
            .unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &effimero, 13),
            Err(Error::Crypto)
        ));
    }

    /// **Il caso segnalato da chi usa l'app**, e la ragione per cui esiste
    /// [`Error::OwnMessageKeyGone`].
    ///
    /// Chi scrive ha la forward secrecy spenta, chi riceve ce l'ha accesa. Il
    /// messaggio parte allora verso la **prechiave** del destinatario — e'
    /// [`Session::epoca_del_peer`] che ripiega li' quando una chiave d'epoca
    /// non c'e' — e quella prechiave avanza a ogni messaggio che lui manda.
    /// Due sue risposte dopo, il mittente rilegge cio' che ha scritto e non si
    /// riapre piu'.
    ///
    /// Fin qui e' il funzionamento previsto. Il difetto stava nell'avviso: il
    /// core aveva un codice solo, e l'app lo traduceva con «quel contatto non
    /// e' piu' nella tua lista» — mentre il contatto e' li', intatto, e
    /// continua a ricevere i messaggi nuovi. Chi lo leggeva andava a cercare un
    /// guasto nella rubrica.
    #[test]
    fn un_mio_messaggio_verso_una_prechiave_avanzata_non_incolpa_la_rubrica() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Bob scrive per primo CON forward secrecy: Alice si segna la sua
        // prechiave, che e' l'unica chiave effimera di Bob che conosce.
        let da_bob = bob
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(9), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &da_bob, 11).unwrap();

        // Alice risponde SENZA: cifra a epoca, e l'epoca del destinatario e'
        // la prechiave di Bob, perche' un'epoca vera lui non l'ha mai mandata.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"la mia risposta", 12, &mut rng(8), false)
            .unwrap();
        // Appena scritto si rilegge ancora: la chiave e' quella di adesso.
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 13),
            Ok(IncomingItem::OwnMessage { .. })
        ));
        assert!(bob.handle_incoming_text(WHATSAPP, &mio, 14).is_ok());

        // Bob risponde ancora, e la sua catena avanza: Alice si segna la
        // prechiave nuova al posto di quella verso cui aveva cifrato.
        let ancora_bob = bob
            .encrypt_for_app_with(WHATSAPP, b"e ancora", 15, &mut rng(7), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &ancora_bob, 16).unwrap();

        // Da qui il messaggio di Alice non si riapre. Deve dirlo per quello
        // che e': il contatto c'e' ancora.
        assert!(
            alice.keyring.get(&chiave_bob).unwrap().is_some(),
            "il contatto non e' stato toccato da niente"
        );
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 17),
            Err(Error::OwnMessageKeyGone)
        ));
        // E la stessa risposta dall'archivio, che ha una via sua e la
        // sbagliava allo stesso modo.
        assert!(matches!(
            alice.open_archived(&mio),
            Err(Error::OwnMessageKeyGone)
        ));
    }

    /// L'altra meta': dove la rubrica **e'** la causa, l'avviso non deve
    /// cambiare. Un messaggio di apertura si riapre con le sole identita', che
    /// non scadono e non avanzano: se fallisce per tutti i contatti, il
    /// destinatario non e' fra loro davvero.
    #[test]
    fn un_mio_messaggio_di_apertura_incolpa_la_rubrica_e_ha_ragione() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let carol = sessione(3);
        let chiave_bob = bob.identity().public();
        let chiave_carol = carol.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // Primo messaggio della conversazione: bootstrap, cifrato verso
        // l'identita' di Bob.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"apriamo", 10, &mut rng(9), false)
            .unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 11),
            Ok(IncomingItem::OwnMessage { .. })
        ));

        // Alice dimentica Bob e tiene Carol: la rubrica non e' vuota, ma chi
        // poteva aprirlo non c'e' piu'.
        assert!(alice.forget_peer(&chiave_bob).unwrap());
        alice.keyring.tofu_pin(&chiave_carol, 12).unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 13),
            Err(Error::OwnMessage)
        ));
    }

    /// Meta' di una chat esportata l'abbiamo scritta noi: se restasse chiusa,
    /// "ricostruisci" mostrerebbe una conversazione a senso unico.
    #[test]
    fn l_archivio_riapre_anche_i_miei_messaggi() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"scritto da me", 10, &mut rng(9), false)
            .unwrap();
        let (chi, testo) = alice.open_archived(&mio).unwrap();
        // Il "chi" e' il destinatario: in una conversazione a due e' cio' che
        // serve a mettere il messaggio nella colonna giusta.
        assert_eq!(chi, chiave_bob);
        assert_eq!(testo.as_bytes(), b"scritto da me");
    }

    /// Mandare piu' messaggi di fila prima che l'altro risponda e' la norma in
    /// chat, non un caso limite. Chi risponde usa l'ultima chiave che **ha
    /// visto**: se ne abbiamo gia' buttate di piu' recenti, la sua risposta non
    /// si apre. Con la finestra a 3 bastavano quattro messaggi.
    #[test]
    fn molti_messaggi_di_fila_non_rompono_la_risposta() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Alice scrive molte volte di fila, ben oltre la vecchia finestra.
        let mut mandati = Vec::new();
        for i in 0..20u8 {
            mandati.push(
                alice
                    .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(i), true)
                    .unwrap(),
            );
        }
        // Bob legge solo il PRIMO — gli altri sono ancora da leggere.
        let primo = mandati.first().unwrap();
        bob.handle_incoming_text(WHATSAPP, primo, 11).unwrap();
        // E risponde.
        let risposta = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta", 12, &mut rng(99), true)
            .unwrap();

        let letto = alice.handle_incoming_text(WHATSAPP, &risposta, 13).unwrap();
        let IncomingItem::Message(messaggio) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(messaggio.plaintext.as_bytes(), b"risposta");
    }

    /// Una chiave temporanea inservibile non deve poter zittire una
    /// conversazione: si ripiega, non si smette di poter scrivere.
    #[test]
    fn una_prekey_inservibile_non_ci_zittisce() {
        let mut alice = sessione(1);
        let chiave_bob = sessione(2).identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        // Punto di ordine basso: il DH con questa da' un segreto tutto zero.
        let veleno = PublicKey::from_bytes([0u8; 32]);
        alice.keyring.set_peer_prekey(&chiave_bob, &veleno).unwrap();

        // Un contatto non deve poterci impedire di scrivergli.
        let blob = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), true)
            .unwrap();
        // Ha ripiegato sullo schema a meta', non sulla catena avvelenata.
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        assert!(!parsed.header.origin.uses_prekey());

        // E una prekey inservibile in arrivo non entra proprio nel keyring.
        let mut carla = sessione(3);
        let chiave_carla = carla.identity().public();
        alice.keyring.tofu_pin(&chiave_carla, 1).unwrap();
        carla.keyring.tofu_pin(&alice.identity().public(), 1).unwrap();
        carla.set_current_peer(WHATSAPP, &alice.identity().public()).unwrap();
        alice.ricorda_prekey(&chiave_carla, &veleno, 1, 1).unwrap();
        assert!(alice.keyring.peer_prekey(&chiave_carla).unwrap().is_none());
    }

    /// Un allegato nostro si rilegge come un messaggio nostro: senza catena
    /// si puo', e la differenza fra i due sarebbe inspiegabile.
    #[test]
    fn anche_un_allegato_mio_si_riapre() {
        let mut alice = sessione(1);
        let chiave_bob = sessione(2).identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        let meta = crate::file::FileMeta {
            name: "a.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        };
        let mio = alice
            .encrypt_file_with(&chiave_bob, &meta, b"foto", 10, &mut rng(1), false)
            .unwrap();
        let letto = alice.handle_incoming_file(&mio, 11).unwrap();
        assert!(letto.nostro, "e' un allegato nostro, non ricevuto");
        assert_eq!(letto.sender, chiave_bob, "il peer e' il destinatario");
        assert_eq!(&*letto.file.content, b"foto");

        // Con la catena accesa resta chiuso, come per i messaggi.
        let con_catena = alice
            .encrypt_file_with(&chiave_bob, &meta, b"foto", 12, &mut rng(2), true)
            .unwrap();
        assert!(alice.handle_incoming_file(&con_catena, 13).is_err());
    }

    /// **Dimenticare un contatto non cancella niente**, e vale la pena che sia
    /// scritto in un test invece che scoperto per caso.
    ///
    /// Senza catena la chiave di lettura non e' memorizzata da nessuna parte:
    /// si **ricalcola** dalla nostra identita' e dalla pubkey del mittente, che
    /// viaggia in chiaro dentro il messaggio stesso. Togliere il pin toglie il
    /// nome, non la capacita' di leggere. Chiunque prenda il telefono e trovi
    /// un vecchio blob lo apre lo stesso.
    ///
    /// Ne segue che una funzione "brucia questa conversazione" **non puo'**
    /// essere costruita sul solo keyring: richiede una chiave per contatto che
    /// oggi esiste solo con la catena accesa.
    #[test]
    fn dimenticare_un_contatto_non_cancella_i_suoi_messaggi() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Bob scrive ad Alice senza forward secrecy.
        let messaggio = bob
            .encrypt_for_app_with(WHATSAPP, b"vecchio segreto", 10, &mut rng(1), false)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &messaggio, 11).unwrap();

        // Alice dimentica Bob: pin via, chiavi temporanee via.
        assert!(alice.forget_peer(&chiave_bob).unwrap());

        // Si riapre lo stesso: la chiave si ricalcola, non si conserva.
        let (chi, testo) = alice.open_archived(&messaggio).unwrap();
        assert_eq!(chi, chiave_bob);
        assert_eq!(testo.as_bytes(), b"vecchio segreto");
    }

    /// **Decisione J.** Senza catena la conversazione si rilegge — da entrambi
    /// — finche' non la si brucia; e bruciandola sparisce da entrambi.
    #[test]
    fn bruciare_rende_illeggibile_da_tutte_e_due_le_parti() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Primo messaggio: nessuna chiave d'epoca dell'altro, quindi bootstrap.
        // Deve essere rileggibile lo stesso — e' il punto della decisione.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &uno, 11),
            Ok(IncomingItem::OwnMessage { .. })
        ));

        // Risposta: ora Bob ha la chiave d'epoca di Alice e la usa.
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), false)
            .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(p) = format::parse(&due, &mut buf).unwrap() else {
            panic!()
        };
        let a_epoca = p.header.origin.uses_epoch();
        assert!(a_epoca, "la risposta doveva usare la chiave d'epoca");

        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        // E si rilegge quante volte si vuole: qui la cronologia esiste.
        alice.handle_incoming_text(WHATSAPP, &due, 14).unwrap();
        assert!(bob.open_archived(&due).is_ok(), "Bob rilegge cio' che ha scritto");

        // Alice brucia. Da questo lato e' definitivo, subito.
        let richiesta = alice.burn_conversation(&chiave_bob, 15, &mut rng(7)).unwrap();
        assert!(alice.handle_incoming_text(WHATSAPP, &due, 16).is_err());

        // Bob riceve la richiesta e la onora: sparisce anche dal suo lato.
        let esito = bob.handle_incoming_text(WHATSAPP, &richiesta, 17).unwrap();
        let IncomingItem::Burned { peer, .. } = esito else {
            panic!("doveva essere un rogo")
        };
        assert_eq!(peer, chiave_alice);
        assert!(bob.open_archived(&due).is_err(), "il messaggio a epoca e' morto");

        // **RESIDUO, e va guardato in faccia:** il messaggio di apertura NON
        // brucia, per nessuno dei due. E' cifrato verso l'identita' di Bob,
        // perche' quando e' partito non esisteva ancora nient'altro di
        // condiviso — e l'identita' sopravvive al rogo per definizione.
        //
        // Non e' aggiustabile dentro questo schema: qualunque messaggio che un
        // destinatario possa aprire senza stato precedente e' apribile con la
        // sola chiave d'identita', quindi resta apribile anche dopo. Si chiude
        // solo mettendo una chiave d'epoca nella presentazione, cosi' che un
        // messaggio di apertura non serva piu'.
        assert!(bob.open_archived(&uno).is_ok(), "il residuo, documentato");
        assert!(alice.open_archived(&uno).is_ok(), "vale anche per chi scrive");

        // Il contatto resta: e' la conversazione a essere bruciata, non lui.
        assert!(bob.keyring.get(&chiave_alice).unwrap().is_some());

        // E si puo' ricominciare da capo, senza rimandare nessuna
        // presentazione: il primo messaggio riparte dal bootstrap.
        let tre = bob
            .encrypt_for_app_with(WHATSAPP, b"ricominciamo", 18, &mut rng(6), false)
            .unwrap();
        let letto = alice.handle_incoming_text(WHATSAPP, &tre, 19).unwrap();
        let IncomingItem::Message(m) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(m.plaintext.as_bytes(), b"ricominciamo");
    }

    /// Un rogo non si spedisce a nome d'altri: chi non ha la conversazione non
    /// puo' cancellarla. Senza questo, chiunque potrebbe azzerare le chat
    /// altrui spedendo un blob a caso.
    #[test]
    fn un_estraneo_non_puo_bruciare_le_conversazioni_altrui() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let mut mallory = sessione(3);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();

        // Mallory conosce Bob e prova a bruciare la sua conversazione.
        mallory.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        let falso = mallory.burn_conversation(&chiave_bob, 12, &mut rng(5)).unwrap();
        assert!(bob.handle_incoming_text(WHATSAPP, &falso, 13).is_err());

        // La conversazione con Alice e' intatta.
        assert!(bob.open_archived(&uno).is_ok());
    }

    /// Leggere un archivio non deve far avanzare la catena: se lo facesse,
    /// aprire una conversazione vecchia ucciderebbe i messaggi ancora in
    /// viaggio, e una esportazione ricevuta da chiunque potrebbe dirottare la
    /// conversazione successiva.
    #[test]
    fn leggere_un_archivio_non_muove_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        let tre = alice
            .encrypt_for_app_with(WHATSAPP, b"terzo", 14, &mut rng(7), true)
            .unwrap();

        // Bob non l'ha ancora letto: la chiave c'e' ancora, quindi l'archivio
        // lo apre.
        let prima = bob.keyring.my_prekeys(&chiave_alice).unwrap();
        let (chi, testo) = bob.open_archived(&tre).unwrap();
        assert_eq!(chi, chiave_alice);
        assert_eq!(testo.as_bytes(), b"terzo");

        // E dopo averlo letto dall'archivio, niente e' cambiato.
        assert_eq!(bob.keyring.my_prekeys(&chiave_alice).unwrap(), prima);
        assert!(bob.handle_incoming_text(WHATSAPP, &tre, 15).is_ok());
    }

    /// **Il prezzo accettato:** quando la catena avanza *abbastanza*, i
    /// messaggi vecchi non si riaprono piu' — nemmeno per chi li ha ricevuti.
    ///
    /// «Abbastanza» e' la parola nuova, ed e' [`keys::CODA_MINIMA`]: le otto
    /// chiavi piu' recenti sopravvivono a una lettura, quindi entro quella
    /// finestra un messaggio si riapre. Oltre, muore come prima.
    ///
    /// La finestra non e' un ripensamento sulla forward secrecy: e' il prezzo
    /// pagato per un difetto peggiore, cioe' messaggi mai letti che
    /// diventavano illeggibili perche' se ne era aperto uno piu' recente. Sta
    /// scritto per esteso sulla costante.
    #[test]
    fn la_cronologia_non_si_rilegge() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Si scrivono a turni finche' la catena e' partita da entrambi i lati.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();

        // Alice risponde: usa la prekey di Bob, e Bob leggendola butta le
        // proprie chiavi piu' vecchie.
        let tre = alice
            .encrypt_for_app_with(WHATSAPP, b"terzo", 14, &mut rng(7), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &tre, 15).unwrap();
        let quattro = bob
            .encrypt_for_app_with(WHATSAPP, b"quarto", 16, &mut rng(6), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &quattro, 17).unwrap();
        let cinque = alice
            .encrypt_for_app_with(WHATSAPP, b"quinto", 18, &mut rng(5), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &cinque, 19).unwrap();

        // Entro la coda minima il terzo si riapre ancora: e' la finestra, ed
        // e' voluta.
        assert!(bob.handle_incoming_text(WHATSAPP, &tre, 20).is_ok());

        // Ma la finestra scorre, e a farla scorrere e' **Bob**: le chiavi in
        // gioco sono le sue, e ne nasce una a ogni messaggio che manda lui.
        let mut ultimo = String::new();
        for i in 0..(crate::keys::CODA_MINIMA + 2) {
            let n = i64::try_from(i).unwrap();
            ultimo = bob
                .encrypt_for_app_with(WHATSAPP, b"ancora", 30 + n, &mut rng(7), true)
                .unwrap();
        }
        // Alice legge l'ultimo, cosi' impara la chiave piu' recente, e
        // risponde usando quella.
        alice.handle_incoming_text(WHATSAPP, &ultimo, 50).unwrap();
        let recente = alice
            .encrypt_for_app_with(WHATSAPP, b"con la nuova", 51, &mut rng(8), true)
            .unwrap();
        // Leggendola, Bob tiene la usata piu' le sette successive: la chiave
        // del terzo e' ormai troppo indietro e cade.
        bob.handle_incoming_text(WHATSAPP, &recente, 52).unwrap();

        // Adesso e' morto, come prima.
        assert!(
            bob.handle_incoming_text(WHATSAPP, &tre, 60).is_err(),
            "la catena e' avanzata oltre la coda: quel messaggio doveva morire"
        );
    }

    #[test]
    fn senza_destinatario_non_si_indovina() {
        let mut bob = sessione(2);
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
