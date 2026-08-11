//! `kc` — l'altra parte, da riga di comando.
//!
//! Serve a provare la tastiera **da soli**. Con il solo telefono si puo' cifrare
//! verso se stessi, il che prova il giro cifra/decifra e non prova niente di
//! cio' che richiede due identita' distinte: presentazione, primo contatto,
//! cambio chiave, conflitto di etichetta, destinatario sbagliato. Quelli sono
//! anche i percorsi dove i guasti fanno piu' danno.
//!
//! Uso tipico con i messaggi salvati di Telegram: `kc card` produce la
//! presentazione, la si incolla nella chat e la si decifra col telefono; da li'
//! in poi i due lati si scrivono, e ogni blob passa dagli appunti.
//!
//! Non fa I/O di rete, non parla con il telefono, non sa che il telefono
//! esista: l'unico canale fra le due parti sei tu che copi e incolli.

mod store;

use std::io::Read;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::file::FileMeta;
use keyboard_cipher_core::keys::{Fingerprint, LabelOutcome, PinOutcome, PublicKey};
use rand_core::{OsRng, RngCore};
use store::{FileKeyring, State};

const APP: &str = "cli";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kc: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest: &[String] = args.get(1..).unwrap_or(&[]);

    match command {
        "init" => cmd_init(rest),
        "id" => cmd_id(),
        "card" => cmd_card(),
        "contacts" => cmd_contacts(),
        "name" => cmd_name(rest),
        "verify" => cmd_verify(rest),
        "encrypt" => cmd_encrypt(rest),
        "decrypt" => cmd_decrypt(rest),
        "sealfile" => cmd_sealfile(rest),
        "openfile" => cmd_openfile(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("comando sconosciuto: {other}\n\n{USAGE}")),
    }
}

const USAGE: &str = "\
kc — l'altra parte di keyboard-cipher, per provare la tastiera da soli.

  kc init [--force]        crea l'identita'
  kc id                    fingerprint e percorso dello stato
  kc card                  la propria presentazione, da incollare in chat
  kc contacts              elenco dei contatti
  kc name <chi> <nome>     attribuisce un nome a una chiave
  kc verify <chi>          segna il fingerprint come confrontato di persona
  kc encrypt --to <chi> [testo]   cifra (se manca il testo, legge da stdin)
  kc decrypt [blob]        decifra un messaggio o fissa una presentazione
  kc sealfile --to <chi> <file>    cifra un file, scrive <file>.kc
  kc openfile <file.kc> [dove]     apre un allegato cifrato

<chi> e' un nome, un indice di `kc contacts`, o l'inizio di un fingerprint.

Lo stato sta in $KC_HOME oppure in ~/.local/share/keyboard-cipher/state, con
permessi 0600. La chiave privata e' in chiaro: sul telefono la protegge Android
Keystore, qui non c'e' niente di equivalente. E' uno strumento per provare —
questa identita' non vale quanto quella del telefono.
";

// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load() -> Result<State, String> {
    let path = store::state_path();
    match State::load(&path).map_err(|e| format!("stato illeggibile ({}): {e}", path.display()))? {
        Some(state) => Ok(state),
        None => Err(format!(
            "nessuna identita' in {}. Creala con `kc init`.",
            path.display()
        )),
    }
}

// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<(), String> {
    let path = store::state_path();
    let force = args.iter().any(|a| a == "--force");
    let existing = State::load(&path).map_err(|e| format!("stato illeggibile: {e}"))?;
    if existing.is_some() && !force {
        return Err(format!(
            "esiste gia' un'identita' in {}. `--force` la sostituisce, e i \
             messaggi ricevuti finora non saranno piu' decifrabili.",
            path.display()
        ));
    }

    // OsRng: entropia dell'OS. Mai un PRNG seedato in-app.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    // Si costruisce l'identita' prima di scrivere: un segreto che non si
    // ricarica sarebbe uno stato inservibile creato in silenzio.
    let state = State::create(secret).map_err(|e| format!("segreto non valido: {e}"))?;
    store::save(&path, &secret, &state.keyring)
        .map_err(|e| format!("non riesco a scrivere {}: {e}", path.display()))?;
    println!("identita' creata: {}", state.identity.fingerprint().display());
    println!("stato: {}", path.display());
    Ok(())
}

fn cmd_id() -> Result<(), String> {
    let state = load()?;
    println!("fingerprint: {}", state.identity.fingerprint().display());
    println!("stato:       {}", store::state_path().display());
    println!("contatti:    {}", state.keyring.peers().len());
    Ok(())
}

fn cmd_card() -> Result<(), String> {
    let state = load()?;
    let session = Session::new(state.identity, state.keyring);
    println!("{}", session.identity_card(&mut OsRng));
    Ok(())
}

fn cmd_contacts() -> Result<(), String> {
    let state = load()?;
    if state.keyring.peers().is_empty() {
        println!("nessun contatto. Decifra una presentazione con `kc decrypt`.");
        return Ok(());
    }
    for (i, peer) in state.keyring.peers().iter().enumerate() {
        let name = peer.label.as_deref().unwrap_or("(senza nome)");
        let mark = if peer.verified { " ✓" } else { "" };
        println!(
            "{i}. {name}{mark}\n   {}",
            Fingerprint::of(&peer.public).display()
        );
    }
    Ok(())
}

fn cmd_name(args: &[String]) -> Result<(), String> {
    let who = args.first().ok_or("manca <chi>. Vedi `kc help`.")?;
    let label = args.get(1).ok_or("manca il nome. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let mut session = Session::new(state.identity, state.keyring);
    let outcome = session
        .assign_label(&peer, label)
        .map_err(|e| format!("{e}"))?;
    match outcome {
        LabelOutcome::Assigned => {
            persist(&secret, &session)?;
            println!("ora si chiama {label}.");
        }
        // Non e' un errore: e' lo stato che richiede una decisione. Qui non si
        // modifica niente, e la vecchia chiave tiene il nome.
        LabelOutcome::Conflict {
            existing_fingerprint,
            incoming_fingerprint,
            ..
        } => {
            println!("«{label}» appartiene gia' a un'altra chiave. Non ho cambiato nulla.");
            println!("  quella che ha il nome: {}", existing_fingerprint.display());
            println!("  quella nuova:          {}", incoming_fingerprint.display());
            println!(
                "\nSe {label} ha cambiato telefono e' normale. Se non lo sa,\n\
                 qualcuno si sta interponendo: confrontate il codice di persona."
            );
        }
    }
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let who = args.first().ok_or("manca <chi>. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let mut session = Session::new(state.identity, state.keyring);
    session.mark_verified(&peer).map_err(|e| format!("{e}"))?;
    persist(&secret, &session)?;
    println!("segnato come verificato di persona.");
    Ok(())
}

fn cmd_encrypt(args: &[String]) -> Result<(), String> {
    let mut who: Option<&str> = None;
    let mut text: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "--to" | "-t" => {
                who = args.get(i.saturating_add(1)).map(String::as_str);
                i = i.saturating_add(2);
            }
            other => {
                text.push(other);
                i = i.saturating_add(1);
            }
        }
    }
    let who = who.ok_or("manca --to <chi>. Vedi `kc help`.")?;
    let state = load()?;
    let peer = resolve(&state.keyring, who)?;

    let plaintext = if text.is_empty() {
        read_stdin()?
    } else {
        text.join(" ")
    };
    if plaintext.trim().is_empty() {
        return Err("niente da cifrare".to_owned());
    }

    let mut session = Session::new(state.identity, state.keyring);
    session
        .set_current_peer(APP, &peer)
        .map_err(|e| format!("{e}"))?;
    let blob = session
        .encrypt_for_app(APP, plaintext.as_bytes(), now_unix(), &mut OsRng)
        .map_err(|e| format!("{e}"))?;
    println!("{blob}");
    Ok(())
}

fn cmd_decrypt(args: &[String]) -> Result<(), String> {
    let input = if args.is_empty() {
        read_stdin()?
    } else {
        args.join(" ")
    };
    let state = load()?;
    let secret = state.secret_bytes();
    let mut session = Session::new(state.identity, state.keyring);
    // Si decifra PRIMA di toccare il keyring, ed e' il core a garantirlo: la
    // decifratura riuscita e' la prova che chi ha scritto possiede la privata
    // dichiarata. Fissare prima permetterebbe a chiunque di riempire il
    // keyring di peer inventati.
    let item = session
        .handle_incoming_text(APP, &input, now_unix())
        .map_err(|e| format!("{e}"))?;
    match item {
        IncomingItem::Message(message) => {
            let who = match &message.sender_status {
                SenderStatus::New => "mittente mai visto, ora fissato".to_owned(),
                SenderStatus::Known { label, verified } => {
                    let name = label.clone().unwrap_or_else(|| "(senza nome)".to_owned());
                    if *verified {
                        format!("{name} ✓")
                    } else {
                        name
                    }
                }
            };
            persist(&secret, &session)?;
            println!("da:       {who}");
            println!("chiave:   {}", Fingerprint::of(&message.sender).display());
            // Autenticato ma NON verificabile: nessuno puo' dimostrare che
            // l'orologio del mittente fosse giusto. Si mostra, non si usa per
            // decidere niente.
            println!(
                "scritto:  {} (secondo il mittente)",
                format_unix(message.plaintext.sent_at_unix())
            );
            println!();
            match std::str::from_utf8(message.plaintext.as_bytes()) {
                Ok(text) => println!("{text}"),
                Err(_) => println!("(il messaggio non e' testo UTF-8)"),
            }
        }
        IncomingItem::IdentityCard {
            fingerprint,
            outcome,
            ..
        } => {
            persist(&secret, &session)?;
            match outcome {
                PinOutcome::Pinned => println!("nuovo contatto, chiave fissata."),
                PinOutcome::AlreadyPinned => println!("chiave gia' nota."),
            }
            println!("{}", fingerprint.display());
            println!("\nConfronta il codice di persona, poi dagli un nome con `kc name`.");
        }
    }
    Ok(())
}

/// Cifra un file. Il risultato e' **binario**, non testo: z-base-32 gonfierebbe
/// di 1,6x una cosa che va allegata e non incollata.
///
/// Nome e tipo del file finiscono **dentro** il cifrato; fuori resta un nome
/// neutro. Se il nome viaggiasse in chiaro, l'allegato si chiamerebbe
/// `compleanno-di-marco.jpg.kc` e racconterebbe da solo quasi tutto.
fn cmd_sealfile(args: &[String]) -> Result<(), String> {
    let mut who: Option<&str> = None;
    let mut percorso: Option<&str> = None;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "--to" | "-t" => {
                who = args.get(i.saturating_add(1)).map(String::as_str);
                i = i.saturating_add(2);
            }
            altro => {
                percorso = Some(altro);
                i = i.saturating_add(1);
            }
        }
    }
    let who = who.ok_or("manca --to <chi>. Vedi `kc help`.")?;
    let percorso = percorso.ok_or("manca il file da cifrare.")?;
    let contenuto = std::fs::read(percorso).map_err(|e| format!("{percorso}: {e}"))?;

    let state = load()?;
    let peer = resolve(&state.keyring, who)?;
    let nome = std::path::Path::new(percorso)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "allegato".to_owned());
    let meta = FileMeta {
        name: nome,
        // Il tipo si dichiara, non si indovina: qui non c'e' una tabella dei
        // tipi e inventarne una sarebbe peggio che dire "non lo so".
        mime: "application/octet-stream".to_owned(),
    };
    let session = Session::new(state.identity, state.keyring);
    let blob = session
        .encrypt_file(&peer, &meta, &contenuto, now_unix(), &mut OsRng)
        .map_err(|e| format!("{e}"))?;

    let uscita = format!("{percorso}.kc");
    std::fs::write(&uscita, &blob).map_err(|e| format!("{uscita}: {e}"))?;
    println!("{uscita} ({} byte)", blob.len());
    Ok(())
}

/// Apre un allegato cifrato. Senza `dove`, scrive accanto al file con il nome
/// originale, che sta dentro il cifrato.
fn cmd_openfile(args: &[String]) -> Result<(), String> {
    let percorso = args.first().ok_or("manca il file da aprire.")?;
    let blob = std::fs::read(percorso).map_err(|e| format!("{percorso}: {e}"))?;
    let state = load()?;
    let secret = state.secret_bytes();
    let mut session = Session::new(state.identity, state.keyring);
    let incoming = session
        .handle_incoming_file(&blob, now_unix())
        .map_err(|e| format!("{e}"))?;

    let chi = match &incoming.sender_status {
        SenderStatus::New => "mittente mai visto, ora fissato".to_owned(),
        SenderStatus::Known { label, verified } => {
            let nome = label.clone().unwrap_or_else(|| "(senza nome)".to_owned());
            if *verified { format!("{nome} ✓") } else { nome }
        }
    };
    persist(&secret, &session)?;

    // Il nome arriva da chi ha mandato il file: autenticato, non credibile.
    // Si tiene solo l'ultimo segmento, cosi' un nome con `../` o un separatore
    // non puo' scrivere fuori dalla cartella scelta.
    let nome_pulito = incoming
        .file
        .meta
        .name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("allegato")
        .to_owned();
    let destinazione = match args.get(1) {
        Some(dove) => std::path::PathBuf::from(dove),
        None => std::path::Path::new(percorso)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(&nome_pulito),
    };
    std::fs::write(&destinazione, &incoming.file.content)
        .map_err(|e| format!("{}: {e}", destinazione.display()))?;

    println!("da:       {chi}");
    println!("chiave:   {}", Fingerprint::of(&incoming.sender).display());
    println!("scritto:  {} (secondo il mittente)", format_unix(incoming.file.sent_at_unix));
    println!("nome:     {} ({})", incoming.file.meta.name, incoming.file.meta.mime);
    println!("salvato:  {}", destinazione.display());
    Ok(())
}

// ---------------------------------------------------------------------------

/// Data leggibile, in UTC.
///
/// Fatta a mano invece di tirarsi dietro una dipendenza per le date: serve una
/// riga sola, e in un progetto che dichiara di non prendere dipendenze inutili
/// sarebbe una contraddizione presa per comodita'.
///
/// UTC e non ora locale, ed e' voluto: il timestamp e' **autenticato ma non
/// verificabile** — nessuno puo' dimostrare che l'orologio del mittente fosse
/// giusto — quindi mostrarlo nel fuso di chi legge suggerirebbe una precisione
/// che non c'e'. Si mostra, non si usa per decidere niente.
///
/// `allow(arithmetic_side_effects)`: l'algoritmo e' quello civile di Hinnant e
/// lavora su valori limitati da `ts`, che e' un `i64` di secondi. Nessuna delle
/// operazioni puo' traboccare per date rappresentabili.
#[allow(clippy::arithmetic_side_effects)]
fn format_unix(ts: i64) -> String {
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

/// Salva lo stato dopo un'operazione che ha toccato il keyring.
///
/// Vuole il segreto perche' a questo punto l'identita' e' dentro la `Session`,
/// che se n'e' presa possesso, e `Identity` non restituisce la propria chiave
/// privata — per come deve essere. Chi chiama se l'e' copiato prima.
fn persist(secret: &[u8; 32], session: &Session<FileKeyring>) -> Result<(), String> {
    let path = store::state_path();
    store::save(&path, secret, session.keyring())
        .map_err(|e| format!("non riesco a scrivere {}: {e}", path.display()))
}

/// Trova un peer da un nome, un indice di `kc contacts`, o l'inizio di un
/// fingerprint (gli spazi si possono omettere).
fn resolve(keyring: &FileKeyring, who: &str) -> Result<PublicKey, String> {
    let peers = keyring.peers();
    if let Some(peer) = peers.iter().find(|p| p.label.as_deref() == Some(who)) {
        return Ok(peer.public.clone());
    }
    if let Ok(index) = who.parse::<usize>() {
        if let Some(peer) = peers.get(index) {
            return Ok(peer.public.clone());
        }
    }
    let needle: String = who.chars().filter(|c| !c.is_whitespace()).collect();
    if !needle.is_empty() {
        let matching: Vec<&keyboard_cipher_core::keys::PeerRecord> = peers
            .iter()
            .filter(|p| {
                Fingerprint::of(&p.public)
                    .display()
                    .replace(' ', "")
                    .starts_with(&needle)
            })
            .collect();
        match matching.as_slice() {
            [single] => return Ok(single.public.clone()),
            [] => {}
            // Mai indovinare: cifrare per la persona sbagliata e' il
            // fallimento peggiore che questo sistema possa produrre.
            _ => return Err(format!("«{who}» corrisponde a piu' contatti")),
        }
    }
    Err(format!(
        "«{who}» non e' un contatto. Vedi `kc contacts`."
    ))
}

fn read_stdin() -> Result<String, String> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("non riesco a leggere da stdin: {e}"))?;
    Ok(buffer)
}
