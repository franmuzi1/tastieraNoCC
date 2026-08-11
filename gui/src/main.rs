//! App da scrivania: cifra e decifra i messaggi della tastiera.
//!
//! ## A cosa serve
//!
//! Dal telefono la tastiera cifra dentro la chat. Dal computer non c'e' una
//! tastiera che possa farlo, quindi serve un posto dove incollare un blob per
//! leggerlo e dove scrivere un messaggio per cifrarlo. Questa e' quella cosa,
//! ed e' anche una **seconda identita' vera**: il telefono e il computer sono
//! due persone diverse per il sistema, con due chiavi diverse.
//!
//! ## Cosa condivide con `kc`
//!
//! Lo **stesso file di stato**, tramite lo stesso modulo. Due implementazioni
//! dello stesso formato sarebbero due fonti di verita', e la prima volta che
//! divergono l'identita' e' persa — cioe' non si decifra piu' niente di quanto
//! si e' ricevuto. Chi usa l'app e chi usa la riga di comando lavorano sulla
//! stessa identita' e sugli stessi contatti.
//!
//! ## Cosa NON fa, per scelta
//!
//! Non parla con il telefono e non sa che esista: l'unico canale fra le due
//! parti e' chi copia e incolla. Nessuna rete, nessun accoppiamento, niente da
//! configurare.
//!
//! *Limite dichiarato:* la chiave privata sta in chiaro nel file di stato,
//! protetta dai soli permessi del filesystem. Sul telefono la avvolge Android
//! Keystore, qui non c'e' niente di equivalente — e chiedere una passphrase a
//! ogni avvio renderebbe scomodo proprio l'uso per cui l'app esiste. Vale come
//! strumento, non come identita' su cui contare quanto quella del telefono.

use eframe::egui;
use keyboard_cipher_cli::store::{self, FileKeyring, State};
use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::format::SENTINEL;
use keyboard_cipher_core::keys::{Fingerprint, LabelOutcome, PinOutcome, PublicKey};
use rand_core::OsRng;

/// Nome dell'app per il core. Sul telefono il destinatario e' per applicazione;
/// qui di applicazione ce n'e' una sola, e la si sceglie a mano ogni volta.
const APP: &str = "gui";

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 620.0])
            .with_min_inner_size([520.0, 420.0])
            .with_title("Tastiera cifrata"),
        ..Default::default()
    };
    eframe::run_native(
        "Tastiera cifrata",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Scheda {
    Scrivi,
    Leggi,
    Contatti,
    Archivio,
}

struct Contatto {
    chiave: PublicKey,
    nome: Option<String>,
    fingerprint: String,
    verificato: bool,
}

struct App {
    /// `None` finche' non esiste un'identita': la si crea dall'app.
    identita: Option<String>,
    contatti: Vec<Contatto>,
    scheda: Scheda,

    destinatario: Option<usize>,
    messaggio: String,
    incollato: String,
    letto: Option<Letto>,

    /// Ultimo esito da mostrare. `errore` decide solo il colore: il testo dice
    /// gia' cosa e' successo.
    avviso: Option<(String, bool)>,
    nuovo_nome: String,
    conflitto: Option<Conflitto>,
    /// Contatto che si sta per dimenticare, in attesa di conferma.
    da_dimenticare: Option<usize>,

    /// Forward secrecy: una chiave temporanea nuova a ogni messaggio, e le
    /// vecchie buttate quando arriva una risposta. Accesa di default, come sul
    /// telefono. Spegnerla serve a chi vuole poter rileggere: con questa
    /// accesa "ricostruisci chat" non riapre niente, per costruzione.
    forward_secrecy: bool,

    /// Guardare gli appunti per accorgersi dei messaggi copiati altrove.
    sorveglia_appunti: bool,
    /// Tenere la finestra sopra le altre: per leggere senza uscire dalla chat.
    sempre_sopra: bool,
    appunti: Option<arboard::Clipboard>,
    /// L'ultimo contenuto gia' esaminato, per non rifare il lavoro a ogni giro.
    ultimo_appunto: String,

    /// La conversazione ricostruita da un'esportazione.
    archivio: Vec<RigaArchivio>,
    archivio_da: Option<String>,
    archivio_trovati: usize,
}

/// Un messaggio ricostruito da un'esportazione di chat.
struct RigaArchivio {
    quando: String,
    chi: String,
    testo: String,
    /// `false` quando il blob c'era ma non si e' aperto: puo' essere di
    /// un'altra conversazione, per un altro destinatario, o cifrato con una
    /// chiave che non esiste piu'.
    aperto: bool,
}

struct Letto {
    /// Chi ha scritto — **oppure** a chi abbiamo scritto noi, se `nostro`.
    mittente: String,
    fingerprint: String,
    verificato: bool,
    quando: String,
    testo: String,
    /// L'abbiamo scritto noi e l'abbiamo riaperto: succede solo senza forward
    /// secrecy, e va detto, altrimenti "da: Marco" su un messaggio nostro
    /// sarebbe semplicemente falso.
    nostro: bool,
}

/// Due chiavi che rivendicano lo stesso nome. **Non e' un errore**: e' lo stato
/// che richiede una decisione, e finche' l'utente non si pronuncia non si
/// modifica niente.
struct Conflitto {
    nome: String,
    vecchia: PublicKey,
    nuova: PublicKey,
    fingerprint_vecchia: String,
    fingerprint_nuova: String,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            identita: None,
            contatti: Vec::new(),
            scheda: Scheda::Scrivi,
            destinatario: None,
            messaggio: String::new(),
            incollato: String::new(),
            letto: None,
            avviso: None,
            nuovo_nome: String::new(),
            conflitto: None,
            da_dimenticare: None,
            forward_secrecy: true,
            sorveglia_appunti: true,
            sempre_sopra: false,
            appunti: arboard::Clipboard::new().ok(),
            ultimo_appunto: String::new(),
            archivio: Vec::new(),
            archivio_da: None,
            archivio_trovati: 0,
        };
        app.ricarica();
        app
    }

    /// Rilegge tutto dal disco.
    ///
    /// Si rilegge a ogni operazione invece di tenere una copia viva: il file e'
    /// piccolo, e `kc` puo' averlo cambiato nel frattempo. Una copia in memoria
    /// che diverge da quella su disco e' il modo piu' rapido per sovrascrivere
    /// un contatto appena aggiunto dall'altro lato.
    fn ricarica(&mut self) {
        let percorso = store::state_path();
        let stato = match State::load(&percorso) {
            Ok(Some(stato)) => stato,
            Ok(None) => {
                self.identita = None;
                self.contatti.clear();
                return;
            }
            Err(e) => {
                self.avviso = Some((format!("stato illeggibile: {e}"), true));
                return;
            }
        };
        self.identita = Some(stato.identity.fingerprint().display());
        self.contatti = stato
            .keyring
            .peers()
            .iter()
            .map(|p| Contatto {
                chiave: p.public.clone(),
                nome: p.label.clone(),
                fingerprint: Fingerprint::of(&p.public).display(),
                verificato: p.verified,
            })
            .collect();
        if self.destinatario.is_some_and(|i| i >= self.contatti.len()) {
            self.destinatario = None;
        }
    }

    fn stato(&mut self) -> Option<State> {
        match State::load(&store::state_path()) {
            Ok(Some(stato)) => Some(stato),
            Ok(None) => {
                self.avviso = Some(("Nessuna identita': creala prima.".to_owned(), true));
                None
            }
            Err(e) => {
                self.avviso = Some((format!("stato illeggibile: {e}"), true));
                None
            }
        }
    }

    fn salva(&mut self, secret: &[u8; 32], keyring: &FileKeyring) {
        if let Err(e) = store::save(&store::state_path(), secret, keyring) {
            self.avviso = Some((format!("non riesco a scrivere lo stato: {e}"), true));
        }
    }

    fn crea_identita(&mut self) {
        use rand_core::RngCore;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        // Si costruisce l'identita' prima di scrivere: un segreto che non si
        // ricarica sarebbe uno stato inservibile creato in silenzio.
        match State::create(secret) {
            Ok(stato) => {
                self.salva(&secret, &stato.keyring);
                self.ricarica();
                self.avviso = Some(("Identita' creata.".to_owned(), false));
            }
            Err(e) => self.avviso = Some((format!("segreto non valido: {e}"), true)),
        }
    }

    fn presentazione(&mut self, ctx: &egui::Context) {
        let Some(stato) = self.stato() else { return };
        let session = Session::new(stato.identity, stato.keyring);
        let card = session.identity_card(&mut OsRng);
        ctx.copy_text(card);
        self.avviso = Some((
            "Presentazione copiata: incollala nella chat.".to_owned(),
            false,
        ));
    }

    fn cifra(&mut self, ctx: &egui::Context) {
        let Some(indice) = self.destinatario else {
            self.avviso = Some(("Scegli prima a chi stai scrivendo.".to_owned(), true));
            return;
        };
        let Some(contatto) = self.contatti.get(indice) else {
            self.avviso = Some(("Contatto non piu' valido.".to_owned(), true));
            return;
        };
        if self.messaggio.trim().is_empty() {
            self.avviso = Some(("Niente da cifrare.".to_owned(), true));
            return;
        }
        let chiave = contatto.chiave.clone();
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        if let Err(e) = session.set_current_peer(APP, &chiave) {
            self.avviso = Some((format!("{e}"), true));
            return;
        }
        match session.encrypt_for_app_with(
            APP,
            self.messaggio.as_bytes(),
            adesso(),
            &mut OsRng,
            self.forward_secrecy,
        ) {
            Ok(blob) => {
                // Su disco subito: con la forward secrecy accesa cifrare
                // genera una chiave temporanea nuova, e non salvarla
                // significa non poter aprire la risposta.
                self.salva(&secret, session.keyring());
                ctx.copy_text(blob);
                self.messaggio.clear();
                self.avviso = Some((
                    "Messaggio cifrato e copiato: incollalo nella chat.".to_owned(),
                    false,
                ));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    fn decifra(&mut self) {
        if self.incollato.trim().is_empty() {
            self.avviso = Some(("Incolla prima un messaggio.".to_owned(), true));
            return;
        }
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        // Il core decifra PRIMA di toccare il keyring: la decifratura riuscita
        // e' la prova che chi ha scritto possiede la privata dichiarata.
        match session.handle_incoming_text(APP, &self.incollato, adesso()) {
            Ok(IncomingItem::Message(messaggio)) => {
                let (nome, verificato) = match &messaggio.sender_status {
                    SenderStatus::New => ("mittente mai visto, ora fissato".to_owned(), false),
                    SenderStatus::Known { label, verified } => (
                        label.clone().unwrap_or_else(|| "(senza nome)".to_owned()),
                        *verified,
                    ),
                };
                let testo = String::from_utf8_lossy(messaggio.plaintext.as_bytes()).into_owned();
                self.letto = Some(Letto {
                    mittente: nome,
                    fingerprint: Fingerprint::of(&messaggio.sender).display(),
                    verificato,
                    quando: data(messaggio.plaintext.sent_at_unix()),
                    testo,
                    nostro: false,
                });
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.avviso = None;
            }
            Ok(IncomingItem::Burned { peer }) => {
                let nome = self
                    .contatti
                    .iter()
                    .find(|c| c.chiave == peer)
                    .map(etichetta)
                    .unwrap_or_else(|| "quel contatto".to_owned());
                self.salva(&secret, session.keyring());
                self.letto = None;
                self.incollato.clear();
                self.ricarica();
                self.avviso = Some((
                    format!(
                        "Conversazione con {nome} bruciata: non si rilegge piu'. \
                         Il contatto resta, il prossimo messaggio riparte da capo."
                    ),
                    false,
                ));
            }
            Ok(IncomingItem::OwnMessage {
                recipient,
                recipient_label,
                plaintext,
            }) => {
                let testo = String::from_utf8_lossy(plaintext.as_bytes()).into_owned();
                self.letto = Some(Letto {
                    mittente: recipient_label.unwrap_or_else(|| "(senza nome)".to_owned()),
                    fingerprint: Fingerprint::of(&recipient).display(),
                    // Niente spunta: su un messaggio nostro non c'e' nessuna
                    // identita' da verificare.
                    verificato: false,
                    quando: data(plaintext.sent_at_unix()),
                    testo,
                    nostro: true,
                });
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.avviso = None;
            }
            Ok(IncomingItem::IdentityCard {
                fingerprint,
                outcome,
                ..
            }) => {
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.scheda = Scheda::Contatti;
                let cosa = match outcome {
                    PinOutcome::Pinned => "Nuovo contatto, chiave memorizzata",
                    PinOutcome::AlreadyPinned => "Chiave gia' nota",
                };
                self.avviso = Some((
                    format!("{cosa}: {}. Confrontalo di persona.", fingerprint.display()),
                    false,
                ));
            }
            Err(e) => {
                self.letto = None;
                self.avviso = Some((format!("{e}"), true));
            }
        }
    }

    fn rinomina(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let nome = self.nuovo_nome.trim().to_owned();
        if nome.is_empty() {
            self.avviso = Some(("Scrivi un nome.".to_owned(), true));
            return;
        }
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.assign_label(&chiave, &nome) {
            Ok(LabelOutcome::Assigned) => {
                self.salva(&secret, session.keyring());
                self.nuovo_nome.clear();
                self.ricarica();
                self.avviso = Some((format!("Ora si chiama {nome}."), false));
            }
            // Il "safety number changed" di Signal. Non si tocca niente finche'
            // l'utente non decide: la vecchia chiave tiene il nome.
            Ok(LabelOutcome::Conflict {
                existing,
                existing_fingerprint,
                incoming_fingerprint,
            }) => {
                self.conflitto = Some(Conflitto {
                    nome,
                    vecchia: existing,
                    nuova: chiave,
                    fingerprint_vecchia: existing_fingerprint.display(),
                    fingerprint_nuova: incoming_fingerprint.display(),
                });
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    fn conferma_conflitto(&mut self) {
        let Some(conflitto) = self.conflitto.take() else { return };
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.confirm_key_change(&conflitto.vecchia, &conflitto.nuova, adesso()) {
            Ok(()) => {
                self.salva(&secret, session.keyring());
                self.ricarica();
                self.avviso = Some((
                    format!(
                        "{} ora e' la chiave nuova. La verifica di persona e' stata azzerata.",
                        conflitto.nome
                    ),
                    false,
                ));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    /// Dimentica un contatto, dopo conferma.
    ///
    /// La conferma non e' cortesia: cancellare un contatto **perde il pin**, e
    /// il prossimo messaggio da quella persona verra' rifissato in silenzio
    /// come se fosse nuovo. Cioe' si riapre la finestra che il pin serviva a
    /// chiudere, e si perde anche "confrontato di persona". Chi lo fa deve
    /// saperlo prima, non scoprirlo dopo.
    fn dimentica(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let nome = contatto
            .nome
            .clone()
            .unwrap_or_else(|| contatto.fingerprint.clone());
        let Some(mut stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        if !stato.keyring.remove(&chiave) {
            self.avviso = Some(("Quel contatto non c'e' piu'.".to_owned(), true));
            return;
        }
        self.salva(&secret, &stato.keyring);
        self.destinatario = None;
        self.ricarica();
        self.avviso = Some((format!("{nome} dimenticato."), false));
    }

    fn verifica(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.mark_verified(&chiave) {
            Ok(()) => {
                self.salva(&secret, session.keyring());
                self.ricarica();
                self.avviso = Some(("Segnato come confrontato di persona.".to_owned(), false));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }
}

impl App {
    /// Ricostruisce una conversazione da un'esportazione di chat.
    ///
    /// Non si analizza il formato dell'esportazione — Telegram, Signal,
    /// WhatsApp e Instagram ne hanno uno ciascuno, e cambiano a ogni loro
    /// aggiornamento. Si cerca il **sentinel** ovunque compaia, esattamente
    /// come fa la tastiera dentro un testo qualunque: cosi' funziona con
    /// qualsiasi formato, anche futuro, purche' i messaggi ci siano come testo.
    ///
    /// **Non tocca il keyring.** Un archivio puo' contenere qualunque cosa,
    /// anche messaggi fabbricati: fissare chiavi leggendo un file sarebbe un
    /// modo per riempirsi i contatti senza accorgersene, e per vedersi
    /// comparire un falso "la chiave di Marco e' cambiata".
    fn ricostruisci(&mut self, percorso: std::path::PathBuf) {
        let Ok(testo) = std::fs::read_to_string(&percorso) else {
            self.avviso = Some((
                "Non riesco a leggere quel file. Se e' un archivio compresso, \
                 estrailo prima."
                    .to_owned(),
                true,
            ));
            return;
        };
        let Some(stato) = self.stato() else { return };
        let session = Session::new(stato.identity, stato.keyring);

        self.archivio.clear();
        self.archivio_trovati = 0;
        let mut resto = testo.as_str();
        while let Some(inizio) = resto.find(SENTINEL) {
            let dopo = resto.get(inizio..).unwrap_or("");
            let fine = dopo
                .char_indices()
                .position(|(i, c)| i >= SENTINEL.len() && !c.is_ascii_alphanumeric())
                .unwrap_or(dopo.len());
            let blob = dopo.get(..fine).unwrap_or("");
            resto = dopo.get(fine.max(SENTINEL.len())..).unwrap_or("");
            self.archivio_trovati += 1;

            match session.open_archived(blob) {
                Ok((mittente, plaintext)) => {
                    let nome = keyboard_cipher_core::keys::Keyring::get(session.keyring(), &mittente)
                        .ok()
                        .flatten()
                        .and_then(|r| r.label)
                        .unwrap_or_else(|| Fingerprint::of(&mittente).display());
                    self.archivio.push(RigaArchivio {
                        quando: data(plaintext.sent_at_unix()),
                        chi: nome,
                        testo: String::from_utf8_lossy(plaintext.as_bytes()).into_owned(),
                        aperto: true,
                    });
                }
                Err(_) => self.archivio.push(RigaArchivio {
                    quando: String::new(),
                    chi: String::new(),
                    testo: "(non decifrabile)".to_owned(),
                    aperto: false,
                }),
            }
        }
        self.archivio_da = percorso
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        self.avviso = None;
    }

    /// Guarda negli appunti se e' comparso un nostro messaggio.
    ///
    /// Toglie l'ultimo passaggio a mano: copi il messaggio da Telegram e
    /// l'app lo ha gia' aperto, senza che tu debba tornare qui e incollare.
    ///
    /// **Cosa guarda e cosa no.** Cerca solo il sentinel. Tutto il resto viene
    /// scartato senza essere letto oltre, senza essere salvato e senza uscire
    /// da questa funzione: se copi una password, qui non succede niente e non
    /// resta niente. E' comunque una lettura degli appunti mentre l'app e'
    /// aperta, quindi si puo' spegnere — la casella e' li' accanto, non
    /// sepolta in un menu.
    fn guarda_appunti(&mut self, ctx: &egui::Context) {
        if !self.sorveglia_appunti {
            return;
        }
        let Some(appunti) = self.appunti.as_mut() else { return };
        let Ok(testo) = appunti.get_text() else { return };
        if testo == self.ultimo_appunto {
            return;
        }
        self.ultimo_appunto = testo.clone();
        if !testo.contains(SENTINEL) {
            return;
        }
        self.incollato = testo;
        self.scheda = Scheda::Leggi;
        self.decifra();
        // La finestra si porta davanti da sola: chi ha appena copiato sta
        // guardando la chat, non questa app, e un messaggio decifrato dentro
        // una finestra coperta non l'ha letto nessuno.
        //
        // Si porta davanti e basta: il chiaro **non** torna negli appunti e non
        // finisce nel campo dell'app di chat. Quel campo appartiene all'app —
        // scriverci il messaggio in chiaro significherebbe consegnarglielo, che
        // e' esattamente cio' che questo sistema esiste per non fare, e
        // basterebbe un invio distratto per rispedirlo a tutti in chiaro.
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.guarda_appunti(ctx);
        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(if self.sempre_sopra {
            egui::WindowLevel::AlwaysOnTop
        } else {
            egui::WindowLevel::Normal
        }));
        // Senza questo l'app si ridisegna solo quando la tocchi, e degli
        // appunti si accorgerebbe soltanto al primo movimento del mouse.
        ctx.request_repaint_after(std::time::Duration::from_millis(700));
        egui::TopBottomPanel::top("intestazione").show(ctx, |ui| {
            ui.add_space(8.0);
            match self.identita.clone() {
                Some(fingerprint) => {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("La tua chiave:");
                        ui.monospace(&fingerprint);
                        if ui.button("Copia la presentazione").clicked() {
                            self.presentazione(ctx);
                        }
                    });
                    ui.small(
                        "Leggi questo codice a voce a chi vuoi contattare: se combacia, \
                         nessuno si e' interposto.",
                    );
                }
                None => {
                    ui.label("Non hai ancora un'identita' su questo computer.");
                    if ui.button("Crea l'identita'").clicked() {
                        self.crea_identita();
                    }
                }
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.scheda, Scheda::Scrivi, "Scrivi");
                ui.selectable_value(&mut self.scheda, Scheda::Leggi, "Leggi");
                ui.selectable_value(&mut self.scheda, Scheda::Contatti, "Contatti");
                ui.selectable_value(&mut self.scheda, Scheda::Archivio, "Archivio");
            });
            ui.add_space(4.0);
        });

        if let Some((testo, errore)) = self.avviso.clone() {
            egui::TopBottomPanel::bottom("avviso").show(ctx, |ui| {
                ui.add_space(6.0);
                let colore = if errore {
                    egui::Color32::from_rgb(200, 80, 80)
                } else {
                    egui::Color32::from_rgb(90, 150, 90)
                };
                ui.colored_label(colore, testo);
                ui.add_space(6.0);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.scheda {
            Scheda::Scrivi => self.scheda_scrivi(ui, ctx),
            Scheda::Leggi => self.scheda_leggi(ui),
            Scheda::Contatti => self.scheda_contatti(ui),
            Scheda::Archivio => self.scheda_archivio(ui),
        });

        self.finestra_conflitto(ctx);
        self.finestra_dimentica(ctx);
    }
}

impl App {
    fn scheda_scrivi(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.contatti.is_empty() {
            ui.label(
                "Nessun contatto. Fatti mandare la presentazione di qualcuno e incollala \
                 in «Leggi», oppure manda la tua con il pulsante qui sopra.",
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.label("A chi scrivi:");
            let scelto = self
                .destinatario
                .and_then(|i| self.contatti.get(i))
                .map(etichetta)
                .unwrap_or_else(|| "— scegli —".to_owned());
            egui::ComboBox::from_id_salt("destinatario")
                .selected_text(scelto)
                .show_ui(ui, |ui| {
                    for (i, contatto) in self.contatti.iter().enumerate() {
                        ui.selectable_value(&mut self.destinatario, Some(i), etichetta(contatto));
                    }
                });
        });
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.messaggio)
                .desired_rows(10)
                .desired_width(f32::INFINITY)
                .hint_text("Scrivi qui il messaggio in chiaro"),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Cifra e copia").clicked() {
                self.cifra(ctx);
            }
            ui.add_space(16.0);
            ui.checkbox(&mut self.forward_secrecy, "Forward secrecy")
                .on_hover_text(
                    "Ogni messaggio porta una chiave nuova, e leggere una risposta butta le \
                     vecchie. Chi ti prende il computer domani non apre i messaggi di oggi — \
                     e non li apri piu' nemmeno tu: con questa accesa «Ricostruisci chat» \
                     non riapre niente.",
                );
        });
    }

    fn scheda_leggi(&mut self, ui: &mut egui::Ui) {
        ui.label("Incolla qui il messaggio ricevuto:");
        let campo = ui.add(
            egui::TextEdit::multiline(&mut self.incollato)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .hint_text("kc/…"),
        );
        // Se quello che hai incollato e' un nostro messaggio, si decifra da
        // solo: chiedere di premere un pulsante quando la risposta e' gia'
        // certa e' un passaggio che non serve a niente. Il riconoscimento e'
        // lo stesso della tastiera — il sentinel — e non tocca il keyring:
        // se non e' nostro, non succede niente.
        if campo.changed() && self.incollato.contains(SENTINEL) {
            self.decifra();
        }
        ui.add_space(8.0);
        if ui.button("Decifra").clicked() {
            self.decifra();
        }
        ui.add_space(4.0);
        ui.checkbox(
            &mut self.sorveglia_appunti,
            "Apri da solo i messaggi che copio",
        )
        .on_hover_text(
            "Guarda negli appunti mentre l'app e' aperta, e cerca soltanto i \
             messaggi di questa tastiera. Tutto il resto viene scartato senza \
             essere salvato.",
        );
        ui.checkbox(&mut self.sempre_sopra, "Tieni la finestra sopra le altre")
            .on_hover_text(
                "Per leggere senza uscire dalla chat. Il messaggio decifrato \
                 resta qui: non torna negli appunti e non entra nel campo di \
                 scrittura dell'app, dove un invio distratto lo rispedirebbe in \
                 chiaro.",
            );
        if let Some(letto) = &self.letto {
            ui.add_space(12.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(if letto.nostro { "A:" } else { "Da:" });
                ui.strong(&letto.mittente);
                if letto.verificato {
                    ui.label("✓ confrontato di persona");
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Chiave:");
                ui.monospace(&letto.fingerprint);
            });
            // Autenticato ma NON verificabile: nessuno puo' dimostrare che
            // l'orologio del mittente fosse giusto. Si mostra, non ci si decide
            // niente.
            if letto.nostro {
                ui.small(format!("Scritto il {} — l'hai scritto tu", letto.quando));
                ui.small(
                    "Si riapre perche' la forward secrecy era spenta: con quella accesa \
                     non sarebbe possibile, nemmeno per te.",
                );
            } else {
                ui.small(format!("Scritto il {} (secondo il mittente)", letto.quando));
            }
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(&letto.testo).size(15.0)).wrap(),
                );
            });
        }
    }

    fn scheda_contatti(&mut self, ui: &mut egui::Ui) {
        if self.contatti.is_empty() {
            ui.label("Nessun contatto ancora.");
            return;
        }
        let mut da_rinominare: Option<usize> = None;
        let mut da_verificare: Option<usize> = None;
        let mut da_dimenticare: Option<usize> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, contatto) in self.contatti.iter().enumerate() {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(contatto.nome.clone().unwrap_or_else(|| "(senza nome)".into()));
                        if contatto.verificato {
                            ui.label("✓");
                        }
                    });
                    ui.monospace(&contatto.fingerprint);
                    ui.horizontal(|ui| {
                        if ui.button("Dai un nome").clicked() {
                            da_rinominare = Some(i);
                        }
                        if ui.button("Ho confrontato di persona").clicked() {
                            da_verificare = Some(i);
                        }
                        if ui.button("Dimentica").clicked() {
                            da_dimenticare = Some(i);
                        }
                    });
                });
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Nome:");
            ui.text_edit_singleline(&mut self.nuovo_nome);
        });
        if let Some(i) = da_rinominare {
            self.rinomina(i);
        }
        if let Some(i) = da_verificare {
            self.verifica(i);
        }
        if let Some(i) = da_dimenticare {
            self.da_dimenticare = Some(i);
        }
    }

    /// Conferma prima di dimenticare, con la conseguenza scritta per esteso.
    fn finestra_dimentica(&mut self, ctx: &egui::Context) {
        let Some(indice) = self.da_dimenticare else { return };
        let Some(contatto) = self.contatti.get(indice) else {
            self.da_dimenticare = None;
            return;
        };
        let nome = contatto
            .nome
            .clone()
            .unwrap_or_else(|| "(senza nome)".to_owned());
        let fingerprint = contatto.fingerprint.clone();
        let mut conferma = false;
        let mut annulla = false;
        egui::Window::new("Dimenticare questo contatto?")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.strong(&nome);
                ui.monospace(&fingerprint);
                ui.add_space(8.0);
                ui.label(
                    "Perdi il collegamento fra questa chiave e questa persona. Il prossimo \
                     messaggio che ti manda ricomparira' come mittente mai visto e verra' \
                     memorizzato di nuovo senza dire niente: e' la stessa cosa che vedresti \
                     se qualcuno si stesse spacciando per lei.",
                );
                ui.add_space(4.0);
                ui.small(
                    "Si perde anche «confrontato di persona», e per riaverlo bisogna \
                     riconfrontare il codice.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Annulla").clicked() {
                        annulla = true;
                    }
                    if ui.button("Dimentica").clicked() {
                        conferma = true;
                    }
                });
            });
        if annulla {
            self.da_dimenticare = None;
        }
        if conferma {
            self.da_dimenticare = None;
            self.dimentica(indice);
        }
    }

    fn scheda_archivio(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "Apri l'esportazione di una conversazione — Telegram, Signal, WhatsApp, \
             Instagram: qualunque formato, purche' i messaggi ci siano come testo.",
        );
        ui.add_space(8.0);
        if ui.button("Ricostruisci una chat…").clicked() {
            if let Some(percorso) = rfd::FileDialog::new()
                .add_filter("Esportazioni", &["html", "json", "txt", "htm", "csv", "md"])
                .add_filter("Qualunque file", &["*"])
                .pick_file()
            {
                self.ricostruisci(percorso);
            }
        }
        if let Some(da) = &self.archivio_da {
            ui.add_space(8.0);
            let aperti = self.archivio.iter().filter(|r| r.aperto).count();
            ui.label(format!(
                "{da}: {aperti} messaggi aperti su {} trovati.",
                self.archivio_trovati
            ));
            ui.add_space(4.0);
            // Con la forward secrecy accesa le chiavi dei messaggi vecchi non
            // esistono piu', ed e' il prezzo dichiarato di quella scelta: qui
            // si dice, invece di lasciar credere a un guasto.
            if aperti < self.archivio_trovati {
                ui.small(
                    "Quelli non decifrabili possono essere di un'altra conversazione, \
                     diretti a qualcun altro, oppure cifrati con forward secrecy: in \
                     quel caso la chiave non esiste piu' e non tornera'.",
                );
            }
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for riga in &self.archivio {
                    if riga.aperto {
                        ui.horizontal_wrapped(|ui| {
                            ui.small(&riga.quando);
                            ui.strong(&riga.chi);
                        });
                        ui.add(egui::Label::new(&riga.testo).wrap());
                    } else {
                        ui.weak(&riga.testo);
                    }
                    ui.add_space(6.0);
                }
            });
        }
    }

    /// La schermata che decide se qualcuno si sta interponendo.
    ///
    /// I due codici stanno **uno sopra l'altro** apposta: e' l'unico momento in
    /// cui l'utente puo' accorgersi di un attacco, e per accorgersene deve
    /// poterli confrontare senza cambiare finestra.
    fn finestra_conflitto(&mut self, ctx: &egui::Context) {
        let Some(conflitto) = &self.conflitto else { return };
        let nome = conflitto.nome.clone();
        let vecchia = conflitto.fingerprint_vecchia.clone();
        let nuova = conflitto.fingerprint_nuova.clone();
        let mut conferma = false;
        let mut annulla = false;
        egui::Window::new("Quel nome e' gia' di un'altra chiave")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "«{nome}» appartiene gia' a una chiave diversa. Non ho cambiato niente."
                ));
                ui.add_space(8.0);
                ui.label("Quella che ha il nome:");
                ui.monospace(&vecchia);
                ui.label("Quella nuova:");
                ui.monospace(&nuova);
                ui.add_space(8.0);
                ui.small(
                    "Se ha cambiato telefono e' normale. Se non lo sa, qualcuno si sta \
                     interponendo: confrontate il codice di persona prima di confermare.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Annulla").clicked() {
                        annulla = true;
                    }
                    if ui.button("E' lui, sposta il nome").clicked() {
                        conferma = true;
                    }
                });
            });
        if annulla {
            self.conflitto = None;
        }
        if conferma {
            self.conferma_conflitto();
        }
    }
}

fn etichetta(contatto: &Contatto) -> String {
    match &contatto.nome {
        Some(nome) if contatto.verificato => format!("{nome} ✓"),
        Some(nome) => nome.clone(),
        None => format!("(senza nome) {}", contatto.fingerprint),
    }
}

fn adesso() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Data leggibile in UTC, con l'algoritmo civile di Hinnant.
///
/// UTC e non ora locale, ed e' voluto: il timestamp e' autenticato ma **non
/// verificabile**, e mostrarlo nel fuso di chi legge suggerirebbe una
/// precisione che non c'e'.
fn data(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{day:02}/{month:02}/{year} {:02}:{:02} UTC",
        secs / 3_600,
        (secs % 3_600) / 60
    )
}
