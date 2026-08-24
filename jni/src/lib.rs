//! Ponte JNI fra `keyboard-cipher-core` e la JVM Android.
//!
//! Qui vive tutto l'`unsafe` del progetto, e non e' molto: i simboli
//! `extern "system"` che la JVM chiama. Il core resta
//! `#![forbid(unsafe_code)]` — e' l'intera ragione per cui i due crate sono
//! separati.
//!
//! # Regole del confine
//!
//! - **I segreti attraversano come `byte[]`, mai come `String`.** Una
//!   `java.lang.String` e' immutabile: non e' azzerabile e resta in heap fino
//!   alla GC. Il chiamante Kotlin azzera l'array appena ha finito.
//! - **La chiave privata non attraversa mai** dopo l'inizializzazione. Resta
//!   in Rust; la JVM manipola solo plaintext in entrata e blob in uscita.
//! - **Nessun panic puo' attraversare il confine.** Un unwind dentro una
//!   funzione `extern` e' comportamento indefinito, non un crash pulito. Ogni
//!   punto d'ingresso e' avvolto in `catch_unwind`. Il core non dovrebbe
//!   andare in panic — e' compilato con `panic`, `unwrap_used`,
//!   `indexing_slicing` e `arithmetic_side_effects` in deny — ma "non
//!   dovrebbe" non e' una garanzia sufficiente quando l'alternativa e' UB.
//! - **Un fallimento crypto e' un solo codice.** Il core non distingue le
//!   cause apposta; questo strato non deve reintrodurre la distinzione.
//!
//! # Perche' lo stato e' globale e non un handle
//!
//! L'alternativa idiomatica sarebbe restituire alla JVM un `Box::into_raw`
//! come `jlong`. Qui e' pericolosa: Android distrugge e ricrea l'
//! `InputMethodService` con molta liberta', e un handle sopravvissuto a un
//! ciclo di vita e' un use-after-free consegnato al chiamante. Esiste
//! esattamente UNA identita' per dispositivo, quindi il singleton e' anche il
//! modello onesto.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use jni::objects::{JByteArray, JClass, JIntArray, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use rand_core::OsRng;
use zeroize::Zeroizing;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::file::FileMeta;
use keyboard_cipher_core::error::Error;
use keyboard_cipher_core::keys::{Identity, Keyring, LabelOutcome, PinOutcome, PublicKey, KEY_LEN};

mod keyring;
use keyring::MemoryKeyring;

/// Codici restituiti alla JVM. Stabili: Kotlin ci fa `when`.
mod code {
    use super::jint;
    pub const OK: jint = 0;
    /// Non e' un nostro blob. Esito NORMALE, non un errore.
    pub const NOT_OUR_BLOB: jint = 1;
    pub const FORMAT: jint = 2;
    pub const UNSUPPORTED_VERSION: jint = 3;
    pub const DECODE: jint = 4;
    /// Qualunque fallimento crypto. Nessun dettaglio, per costruzione.
    pub const CRYPTO: jint = 5;
    pub const UNKNOWN_PEER: jint = 6;
    pub const TIER_UNSUPPORTED: jint = 7;
    pub const KEYRING: jint = 8;
    /// Sessione non inizializzata, errore JNI, o panic intercettato.
    pub const INTERNAL: jint = 9;
    /// L'abbiamo scritto noi: puo' aprirlo solo il destinatario. Esito
    /// NORMALE, non un guasto — capita ricopiando un proprio messaggio.
    pub const OWN_MESSAGE: jint = 10;

    /// Esiti di `handleIncomingText`, quando il codice e' OK.
    pub const ITEM_MESSAGE: jint = 0;
    pub const ITEM_IDENTITY_CARD: jint = 1;
    /// Allegato cifrato. Vedi `nativeDecryptFile`.
    pub const ITEM_FILE: jint = 2;
    /// Un messaggio nostro, riaperto. `senderKey` e l'etichetta sono quelli
    /// del DESTINATARIO: qui non c'e' un mittente da mostrare.
    pub const ITEM_OWN_MESSAGE: jint = 3;
    /// Un allegato nostro, riaperto. Come sopra: il peer e' il destinatario.
    pub const ITEM_OWN_FILE: jint = 4;
    /// L'altro ha chiesto di bruciare la conversazione, e l'abbiamo fatto.
    /// Non c'e' testo: e' un gesto, non un messaggio.
    pub const ITEM_BURNED: jint = 5;
    /// La propria card, riaperta: non e' stato fissato nessun contatto.
    pub const ITEM_OWN_IDENTITY_CARD: jint = 6;

    /// Esiti di `assignLabel`.
    pub const LABEL_ASSIGNED: jint = 0;
    /// L'etichetta appartiene gia' a un'altra chiave: "safety number changed".
    pub const LABEL_CONFLICT: jint = 1;
}

fn code_of(error: &Error) -> jint {
    match error {
        Error::NotOurBlob => code::NOT_OUR_BLOB,
        Error::Format(_) => code::FORMAT,
        Error::UnsupportedVersion(_) => code::UNSUPPORTED_VERSION,
        Error::Decode => code::DECODE,
        Error::Crypto => code::CRYPTO,
        Error::UnknownPeer => code::UNKNOWN_PEER,
        Error::TierUnsupported => code::TIER_UNSUPPORTED,
        Error::OwnMessage => code::OWN_MESSAGE,
        Error::Keyring => code::KEYRING,
    }
}

/// Stato unico del processo.
static SESSION: OnceLock<Mutex<Option<Session<MemoryKeyring>>>> = OnceLock::new();

fn session_slot() -> &'static Mutex<Option<Session<MemoryKeyring>>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Esegue `body` con la sessione, se inizializzata.
///
/// Un mutex avvelenato da un panic precedente viene recuperato invece di
/// propagare: a quel punto il danno e' gia' fatto e restituire un errore e'
/// piu' utile che rendere la tastiera inutilizzabile fino al riavvio.
fn with_session<T, F>(body: F) -> Result<T, jint>
where
    F: FnOnce(&mut Session<MemoryKeyring>) -> Result<T, Error>,
{
    let mut guard = match session_slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let session = guard.as_mut().ok_or(code::INTERNAL)?;
    body(session).map_err(|error| code_of(&error))
}

/// Barriera contro l'unwind verso la JVM.
fn guard<T, F: FnOnce() -> T>(fallback: T, body: F) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Spegne un'eccezione Java rimasta accesa, e va chiamata su OGNI errore di una
/// chiamata JNI.
///
/// Il motivo e' che l'errore lo si scopre due volte. Quando una chiamata JNI
/// fallisce — memoria finita mentre si alloca una stringa, un array troppo
/// grande — la JVM **arma un'eccezione sul thread** e la lascia li'; il valore
/// di ritorno e' solo la seconda copia della notizia. Restituire `null` senza
/// spegnerla non chiude niente: l'eccezione resta armata sul thread e scoppia
/// alla prima chiamata Java successiva, cioe' **lontano da qui**, addosso a
/// codice che non ha sbagliato niente. Peggio: nel frattempo altre chiamate JNI
/// hanno comportamento indefinito, perche' il contratto vieta di proseguire con
/// un'eccezione pendente.
///
/// Percio' il ponte la spegne subito e riporta il guasto **solo** con il valore
/// di ritorno, che e' l'unico canale che questo confine dichiara di usare. Il
/// difetto era in tutte e quattro le funzioni qui sotto, non solo in quelle che
/// scrivono: `get_string` e `convert_byte_array` armano un'eccezione esattamente
/// come `new_string`.
///
/// Se `exception_clear` fallisce a sua volta non resta niente da fare — non
/// c'e' un canale piu' in basso a cui riportarlo — e si prosegue: il valore di
/// ritorno dice comunque che l'operazione non e' riuscita.
fn spegni_eccezione(env: &JNIEnv) {
    let _ = env.exception_clear();
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String, jint> {
    env.get_string(value).map(|s| s.into()).map_err(|_| {
        spegni_eccezione(env);
        code::INTERNAL
    })
}

fn new_string(env: &JNIEnv, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            spegni_eccezione(env);
            std::ptr::null_mut()
        }
    }
}

fn new_byte_array(env: &JNIEnv, value: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(value) {
        Ok(array) => array.into_raw(),
        Err(_) => {
            spegni_eccezione(env);
            std::ptr::null_mut()
        }
    }
}

/// Come `read_bytes`, ma per cio' che non deve restare in memoria: chiavi
/// private, passphrase, chiaro dei messaggi e degli allegati.
///
/// La differenza con `read_bytes` e' solo il `Zeroizing`, e per questo esistono
/// due funzioni invece di un parametro: il tipo di ritorno **dice** se quel che
/// entra e' un segreto, e chi legge non deve andare a vedere come viene usato
/// piu' avanti.
///
/// Azzerare a mano funzionava — e in quattro punti si faceva — ma e' una
/// disciplina che regge finche' nessuno infila un `return` in mezzo: la
/// scrittura sta in fondo alla funzione, e un'uscita anticipata la salta senza
/// che niente lo segnali. Col `Zeroizing` la garanzia sta nel `Drop`, quindi
/// vale per ogni via d'uscita, comprese quelle scritte domani.
///
/// **Copre solo la copia Rust.** Quella dentro l'array Java resta viva e la
/// deve azzerare il chiamante: da qui non e' raggiungibile, ed e' scritto sulle
/// firme che ricevono segreti.
fn read_secret_bytes(env: &mut JNIEnv, value: &JByteArray) -> Result<Zeroizing<Vec<u8>>, jint> {
    read_bytes(env, value).map(Zeroizing::new)
}

/// Deposita il motivo del fallimento nell'array d'uscita, se il chiamante ne
/// ha passato uno.
///
/// Serve alle funzioni che restituiscono un puntatore: `null` e' l'unica cosa
/// che possono dire, e da solo mette tutte le cause nello stesso mucchio. Il
/// chiamante che voglia sapere **perche'** passa un `int[1]`; chi non lo vuole
/// passa `null` e non paga niente.
///
/// Perche' un parametro d'uscita e non un "ultimo errore" da interrogare dopo:
/// un ultimo-errore e' stato globale, e con piu' thread che chiamano il ponte
/// non e' detto che quello che si legge sia il proprio. Questo e' il contrario
/// — vive nella chiamata — ed e' lo stesso schema che `nativeDecryptFile` e
/// `nativeImportBackup` usano gia' per i loro risultati.
///
/// Se la scrittura fallisce non si fa niente: il `null` di ritorno dice
/// comunque che l'operazione non e' riuscita, e un errore nel riportare un
/// errore non deve diventare un secondo guasto. `spegni_eccezione` c'e' perche'
/// un array troppo corto arma un'eccezione che va spenta subito.
fn motivo(env: &mut JNIEnv, out: &JIntArray, codice: jint) {
    if out.is_null() {
        return;
    }
    if env.set_int_array_region(out, 0, &[codice]).is_err() {
        spegni_eccezione(env);
    }
}

fn read_bytes(env: &mut JNIEnv, value: &JByteArray) -> Result<Vec<u8>, jint> {
    env.convert_byte_array(value).map_err(|_| {
        spegni_eccezione(env);
        code::INTERNAL
    })
}

fn read_key(env: &mut JNIEnv, value: &JByteArray) -> Result<PublicKey, jint> {
    let bytes = read_bytes(env, value)?;
    let mut key = [0u8; KEY_LEN];
    if bytes.len() != KEY_LEN {
        return Err(code::FORMAT);
    }
    key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(key))
}

// ============================================================================
// Ciclo di vita dell'identita'
// ============================================================================

/// Genera una nuova identita' e restituisce i 32 byte del segreto, che la JVM
/// deve cifrare con Android Keystore e persistere.
///
/// E' l'UNICO momento in cui la chiave privata attraversa il confine. Il
/// chiamante azzera l'array subito dopo averlo consegnato allo storage.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeGenerateSecret(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        use rand_core::RngCore;

        // OsRng: entropia dell'OS. Mai un PRNG seedato in-app.
        //
        // `Zeroizing` e non due `secret.zeroize()` a mano: le uscite qui sono
        // due e le azzeravano entrambe, ma e' la forma che si rompe in
        // silenzio quando qualcuno ne aggiunge una terza. Qui l'azzeramento
        // e' nel `Drop`.
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *secret);
        // Verifica che i byte producano un'identita' valida prima di
        // consegnarli allo storage: un segreto che non si ricarica sarebbe un
        // guasto permanente e silenzioso.
        if Identity::from_secret_bytes(*secret).is_err() {
            return std::ptr::null_mut();
        }
        new_byte_array(&env, &*secret)
    })
}

/// Inizializza la sessione con un segreto persistito e un keyring esportato.
/// `keyringBlob` puo' essere vuoto al primo avvio.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    secret: JByteArray,
    keyring_blob: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        // Segreto e blob del keyring sono entrambi materiale di chiave: il
        // primo e' l'identita', il secondo contiene le chiavi temporanee e le
        // chiavi d'epoca di ogni contatto. Senza `Zeroizing` restavano in heap
        // fino al riuso dell'allocazione, e questa e' la funzione che viene
        // chiamata a ogni avvio del processo.
        let bytes = match read_secret_bytes(&mut env, &secret) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        if bytes.len() != KEY_LEN {
            return code::FORMAT;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        let identity = match Identity::from_secret_bytes(*key) {
            Ok(identity) => identity,
            Err(error) => return code_of(&error),
        };

        let blob = match read_secret_bytes(&mut env, &keyring_blob) {
            Ok(blob) => blob,
            Err(codice) => return codice,
        };
        let keyring = if blob.is_empty() {
            MemoryKeyring::new()
        } else {
            match MemoryKeyring::import(&blob) {
                Ok(keyring) => keyring,
                Err(error) => return code_of(&error),
            }
        };

        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(Session::new(identity, keyring));
        code::OK
    })
}

// ============================================================================
// Operazioni
// ============================================================================

/// Dimentica un peer.
///
/// Il chiamante deve avere gia' avvertito l'utente: si perde il pin, e il
/// prossimo messaggio da quella persona verra' rifissato in silenzio come se
/// fosse nuovo — indistinguibile da qualcuno che si spaccia per lei.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeForgetPeer(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let Ok(chiave) = read_key(&mut env, &peer) else {
            return code::FORMAT;
        };
        // Passa da Session e non dal keyring: dimenticare deve togliere il
        // peer anche dai destinatari correnti, altrimenti sparisce dall'elenco
        // e si continua a cifrare verso quella chiave — un guasto che si
        // scoprirebbe solo dall'altro lato.
        match with_session(|session| session.forget_peer(&chiave)) {
            Ok(_) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Come si chiama il destinatario per questa app, da mostrare nella tastiera.
///
/// L'etichetta se c'e', altrimenti il fingerprint: due contatti senza nome
/// sono distinguibili solo da quello. `null` se non c'e' nessun destinatario —
/// che e' un'informazione, non un errore, e la tastiera la mostra come tale.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeCurrentPeerName(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let Ok(package) = read_string(&mut env, &app_package) else {
            return std::ptr::null_mut();
        };
        let nome = with_session(|session| {
            let Some(peer) = session.current_peer(&package) else {
                return Ok(None);
            };
            let etichetta = Keyring::get(session.keyring(), peer)?
                .and_then(|record| record.label)
                .unwrap_or_else(|| keyboard_cipher_core::keys::Fingerprint::of(peer).display());
            Ok(Some(etichetta))
        });
        match nome {
            Ok(Some(nome)) => new_string(&env, nome.as_str()),
            _ => std::ptr::null_mut(),
        }
    })
}

/// C'e' un destinatario per questa app?
///
/// Serve alla tastiera per distinguere "non so a chi cifrare" da "la cifratura
/// e' fallita": sono due cose che l'utente deve poter risolvere in modi
/// diversi, e senza questa domanda si vedono uguali — cioe' come un tasto che
/// non fa niente.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeHasCurrentPeer(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
) -> jboolean {
    guard(0, || {
        let Ok(package) = read_string(&mut env, &app_package) else {
            return 0;
        };
        let presente = with_session(|session| Ok(session.current_peer(&package).is_some()));
        jboolean::from(presente.unwrap_or(false))
    })
}

/// Cifra un file per un peer scelto esplicitamente.
///
/// Il contenuto attraversa il confine come `byte[]`, e il chiamante lo azzera
/// appena consegnato: una `java.lang.String` non sarebbe azzerabile, e un file
/// non e' testo comunque.
///
/// Niente destinatario implicito (decisione G4): questo percorso parte da una
/// schermata, non dalla tastiera, quindi il contesto dell'app da cui dedurlo
/// non esiste — e un file mandato alla persona sbagliata non si ritira.
///
/// Con `forward` diverso da zero **modifica il keyring**, come
/// `nativeEncryptForApp`: chi chiama deve persistere subito.
///
/// `errorOut` e' un `int[1]` facoltativo — passare `null` per non riceverlo —
/// dove finisce il motivo quando il ritorno e' `null`. Prima il `null` era uno
/// solo per cause diverse: `UNKNOWN_PEER` (il destinatario non e' piu' nella
/// rubrica, cosa che capita se lo si dimentica dopo aver scelto il file),
/// `FORMAT` (il file non ci sta) e i guasti veri finivano tutti nello stesso
/// mucchio, e l'utente leggeva la stessa frase in tutti e tre i casi — di cui
/// almeno uno lui puo' risolvere.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptFile(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    name: JString,
    mime: JString,
    content: JByteArray,
    now_unix: jlong,
    forward: jboolean,
    error_out: JIntArray,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let chiave = match read_key(&mut env, &peer) {
            Ok(chiave) => chiave,
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                return std::ptr::null_mut();
            }
        };
        let Ok(nome) = read_string(&mut env, &name) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        let Ok(tipo) = read_string(&mut env, &mime) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        // Il contenuto del file e' chiaro come il testo di un messaggio, e
        // ne passa molto di piu': fino al tetto della decisione G6.
        let Ok(bytes) = read_secret_bytes(&mut env, &content) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        let meta = FileMeta { name: nome, mime: tipo };
        let esito = with_session(|session| {
            session.encrypt_file_with(&chiave, &meta, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        match esito {
            Ok(blob) => new_byte_array(&env, &blob),
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                std::ptr::null_mut()
            }
        }
    })
}

/// Apre un allegato ricevuto e riempie `result`.
///
/// Come per i messaggi, il core decifra **prima** di toccare il keyring: la
/// decifratura riuscita e' la prova che chi ha mandato il file possiede la
/// privata dichiarata.
///
/// **Anche aprire modifica il keyring, e anche qui si persiste subito.** Il
/// contratto della persistenza era scritto solo sulle firme che cifrano, e
/// suggeriva quindi il contrario: che leggere fosse un'operazione innocua. Non
/// lo e', per tre motivi distinti, e ciascuno lascerebbe un danno diverso se il
/// processo morisse prima del salvataggio:
///
/// - un mittente mai visto viene **fissato** (TOFU). Non persistendolo, la
///   volta dopo verrebbe fissato di nuovo in silenzio — cioe' un cambio di
///   chiave non verrebbe mai notato;
/// - aprire un messaggio a forward secrecy **butta** le proprie chiavi
///   temporanee piu' vecchie (decisione I: e' la lettura a buttare, non la
///   risposta). Non persistendolo, le chiavi buttate tornano al riavvio e la
///   proprieta' che l'interruttore promette non c'e';
/// - un rogo (decisione J) **distrugge** la chiave d'epoca. Non persistendolo,
///   la conversazione bruciata resuscita al riavvio, dopo che all'utente e'
///   stato detto che era finita. E' il peggiore dei tre, perche' l'interfaccia
///   ha gia' dichiarato una cosa che il disco smentisce.
///
/// # Il chiaro che finisce in `result`
///
/// Il campo del testo e' un `byte[]` e non una `String` per lo stesso motivo di
/// sempre: una `java.lang.String` e' immutabile e non si azzera. Ma il ponte
/// non puo' azzerarlo — appartiene al chiamante — quindi **e' il chiamante che
/// lo azzera appena l'ha mostrato o salvato**, come fa gia' con quello che
/// consegna in cifratura. Detto qui perche' dalla firma non si indovina: e'
/// l'unico posto di questo file dove un segreto viaggia verso la JVM invece che
/// verso il core.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeDecryptFile(
    mut env: JNIEnv,
    _class: JClass,
    blob: JByteArray,
    now_unix: jlong,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let bytes = match read_bytes(&mut env, &blob) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let esito = with_session(|session| session.handle_incoming_file(&bytes, now_unix));
        let incoming = match esito {
            Ok(incoming) => incoming,
            Err(codice) => return codice,
        };

        let (etichetta, verificato) = match &incoming.sender_status {
            SenderStatus::New => (None, false),
            SenderStatus::Known { label, verified } => (label.clone(), *verified),
        };
        let genere = if incoming.nostro {
            code::ITEM_OWN_FILE
        } else {
            code::ITEM_FILE
        };
        if env
            .set_field(&result, "kind", "I", genere.into())
            .is_err()
            || env
                .set_field(&result, "verified", "I", jint::from(verificato).into())
                .is_err()
        {
            return code::INTERNAL;
        }
        let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&incoming.sender);
        if !fill_strings(&mut env, &result, &fingerprint.display(), etichetta.as_deref()) {
            return code::INTERNAL;
        }
        if env
            .set_field(
                &result,
                "sentAtUnix",
                "J",
                jni::objects::JValue::Long(incoming.file.sent_at_unix),
            )
            .is_err()
        {
            return code::INTERNAL;
        }
        let Ok(chiave) = env.byte_array_from_slice(incoming.sender.as_bytes()) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "senderKey", "[B", (&chiave).into())
            .is_err()
        {
            return code::INTERNAL;
        }
        // Nome e tipo arrivano da chi ha mandato il file: autenticati, non
        // credibili. Chi li usa per salvare deve ripulirli — un nome puo'
        // contenere `../` o un separatore di percorso.
        let Ok(nome) = env.new_string(&incoming.file.meta.name) else {
            return code::INTERNAL;
        };
        let Ok(tipo) = env.new_string(&incoming.file.meta.mime) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "fileName", "Ljava/lang/String;", (&nome).into())
            .is_err()
            || env
                .set_field(&result, "fileMime", "Ljava/lang/String;", (&tipo).into())
                .is_err()
        {
            return code::INTERNAL;
        }
        let Ok(contenuto) = env.byte_array_from_slice(&incoming.file.content) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "fileContent", "[B", (&contenuto).into())
            .is_err()
        {
            return code::INTERNAL;
        }
        code::OK
    })
}

/// Blob di presentazione da inserire nel campo con `commitText`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeIdentityCard(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        match with_session(|session| Ok(session.identity_card(&mut OsRng))) {
            Ok(card) => new_string(&env, &card),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Fingerprint della nostra identita', gia' formattato per la UI.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeMyFingerprint(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        match with_session(|session| Ok(session.my_fingerprint().display())) {
            Ok(fingerprint) => new_string(&env, &fingerprint),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Esporta identita' e portachiavi cifrati con una passphrase.
///
/// La passphrase arriva come `byte[]` e **non** come `String`: una
/// `java.lang.String` e' immutabile, non azzerabile, e resta in heap fino alla
/// GC. Chi chiama azzera l'array appena ha finito.
///
/// Ritorna il blob del backup, oppure `null`. Il `null` copre tutti i
/// fallimenti insieme, ed e' voluto: qui non c'e' niente di utile da
/// distinguere per il chiamante.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeExportBackup(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let pass = match read_secret_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };
        let esito = with_session(|session| {
            // Anche il keyring esportato e' materiale di chiave, non solo la
            // passphrase: ci sono dentro le chiavi temporanee e le chiavi
            // d'epoca di ogni contatto.
            let keyring = Zeroizing::new(session.keyring().export());
            keyboard_cipher_core::backup::export(
                session.identity(),
                &keyring,
                &pass,
                &mut OsRng,
            )
        });
        match esito {
            Ok(blob) => new_byte_array(&env, &blob),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Apre un backup e **sostituisce** identita' e portachiavi correnti.
///
/// Distruttivo: da qui in poi l'identita' precedente non e' piu' raggiungibile
/// da questa sessione. Chi chiama deve aver gia' chiesto conferma all'utente e
/// deve persistere subito il risultato, altrimenti alla morte del processo si
/// ritrova la vecchia identita' su disco e la nuova in memoria — cioe' due
/// stati diversi della stessa cosa.
///
/// I 32 byte del segreto vengono scritti in `secretOut`, che il chiamante
/// alloca e azzera appena l'ha cifrato per lo storage. Non esiste un modo di
/// far uscire il segreto senza che qualcuno lo tenga in mano: la scelta e' fra
/// questo e non avere backup.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeImportBackup(
    mut env: JNIEnv,
    _class: JClass,
    blob: JByteArray,
    passphrase: JByteArray,
    secret_out: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let dati = match read_bytes(&mut env, &blob) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let pass = match read_secret_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let aperto = match keyboard_cipher_core::backup::import(&dati, &pass) {
            Ok(aperto) => aperto,
            Err(error) => return code_of(&error),
        };

        let identity = match Identity::from_secret_bytes(*aperto.secret) {
            Ok(identity) => identity,
            Err(error) => return code_of(&error),
        };
        let keyring = if aperto.keyring.is_empty() {
            MemoryKeyring::new()
        } else {
            match MemoryKeyring::import(&aperto.keyring) {
                Ok(keyring) => keyring,
                Err(error) => return code_of(&error),
            }
        };

        // Il segreto esce PRIMA di sostituire la sessione: se la scrittura
        // nell'array fallisce, meglio lasciare tutto com'era che ritrovarsi
        // un'identita' viva in memoria e nessun modo di persisterla.
        // Lunghezza controllata prima di scrivere: un array piu' corto
        // farebbe sollevare un'eccezione JNI che resterebbe pendente sul
        // thread e verrebbe lanciata al ritorno in Java, dove il chiamante si
        // aspetta un codice di ritorno.
        if env.get_array_length(&secret_out).unwrap_or(0) != KEY_LEN as jint {
            return code::FORMAT;
        }
        // Zeroizing: e' una copia dei 32 byte della chiave privata, e senza
        // resterebbe in heap fino al riuso dell'allocazione. Ovunque altro in
        // questo file la disciplina e' rispettata; qui mancava.
        let temporaneo = zeroize::Zeroizing::new(
            aperto.secret.iter().map(|b| *b as i8).collect::<Vec<i8>>(),
        );
        if env
            .set_byte_array_region(&secret_out, 0, &temporaneo)
            .is_err()
        {
            return code::INTERNAL;
        }

        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(Session::new(identity, keyring));
        code::OK
    })
}

/// Dice se il testo *sembra* contenere un nostro blob. Nessuna decifratura,
/// nessun accesso al keyring, nessun effetto collaterale.
///
/// Esiste per la UI: serve a decidere se accendere un indizio o offrire
/// l'azione "decifra". NON e' una verifica — `true` non dice che il blob sia
/// integro, ne' che sia per noi.
///
/// A differenza di tutte le altre entry, questa NON richiede una sessione
/// inizializzata: guarda solo la forma del testo. Cosi' la si puo' chiamare
/// prima di generare l'identita', che e' esattamente quando serve.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeLooksLikeOurBlob(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jboolean {
    guard(0, || {
        let testo = match read_string(&mut env, &text) {
            Ok(testo) => testo,
            Err(_) => return 0,
        };
        u8::from(keyboard_cipher_core::format::looks_like_blob(&testo))
    })
}

/// Cifra verso il destinatario corrente dell'app. `null` se non c'e'.
///
/// Con `forward` diverso da zero **modifica il keyring**: ci mette una chiave
/// temporanea nuova. Chi chiama deve esportarlo e persisterlo subito, altrimenti
/// la risposta arrivera' cifrata verso una chiave che non esiste piu'.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptForApp(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    plaintext: JByteArray,
    now_unix: jlong,
    forward: jboolean,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let nullo: jstring = std::ptr::null_mut();
        let Ok(package) = read_string(&mut env, &app_package) else {
            return nullo;
        };
        let Ok(bytes) = read_secret_bytes(&mut env, &plaintext) else {
            return nullo;
        };

        let esito = with_session(|session| {
            session.encrypt_for_app_with(&package, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        match esito {
            Ok(blob) => new_string(&env, &blob),
            Err(_) => nullo,
        }
    })
}

/// Cifra per piu' destinatari (decisione K).
///
/// Le chiavi arrivano **concatenate** in un solo `byte[]`, 32 byte ciascuna,
/// invece che come `byte[][]`. Un array di array attraverso JNI vuole un
/// riferimento locale per riga e un ciclo che li rilascia: piu' codice `unsafe`
/// per trasportare la stessa cosa. Il conteggio si ricava dalla lunghezza, e
/// una lunghezza non multipla di 32 e' un errore del chiamante, non un gruppo
/// strano.
///
/// **Non ha forward secrecy**, per decisione: chi mostra il risultato deve
/// dirlo all'utente.
///
/// `errorOut` e' un `int[1]` facoltativo — `null` per non riceverlo — dove
/// finisce il motivo quando il ritorno e' `null`. Serve soprattutto per
/// `UNKNOWN_PEER`: un gruppo salvato tiene le chiavi dei membri, ma un membro
/// puo' essere stato dimenticato dopo, e allora il gruppo non si cifra piu'.
/// E' l'unico fallimento che l'utente puo' aggiustare da solo, e prima gli
/// veniva mostrato con la stessa frase di un guasto interno.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptGroup(
    mut env: JNIEnv,
    _class: JClass,
    peers: JByteArray,
    plaintext: JByteArray,
    now_unix: jlong,
    error_out: JIntArray,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let nullo: jstring = std::ptr::null_mut();
        let Ok(chiavi) = read_bytes(&mut env, &peers) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return nullo;
        };
        if chiavi.is_empty() || chiavi.len() % KEY_LEN != 0 {
            motivo(&mut env, &error_out, code::FORMAT);
            return nullo;
        }
        let destinatari: Vec<keyboard_cipher_core::keys::PublicKey> = chiavi
            .chunks_exact(KEY_LEN)
            .map(|pezzo| {
                let mut bytes = [0u8; KEY_LEN];
                bytes.copy_from_slice(pezzo);
                keyboard_cipher_core::keys::PublicKey::from_bytes(bytes)
            })
            .collect();

        let Ok(bytes) = read_secret_bytes(&mut env, &plaintext) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return nullo;
        };
        let esito = with_session(|session| {
            session.encrypt_group(&destinatari, &bytes, now_unix, &mut OsRng)
        });
        match esito {
            Ok(blob) => new_string(&env, &blob),
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                nullo
            }
        }
    })
}

/// Punto d'ingresso unico per tutte e quattro le vie con cui un blob puo'
/// arrivare (clipboard, `ACTION_PROCESS_TEXT`, share sheet, campo di input).
///
/// Riempie l'oggetto `result` passato dal chiamante invece di costruirne uno:
/// costruire oggetti da JNI richiede risolvere classe e firma del costruttore
/// a runtime, e ogni errore diventa un'eccezione lanciata in mezzo a
/// un'operazione crypto. Riempire campi di un oggetto gia' allocato dal lato
/// Java e' piu' noioso e molto piu' difficile da sbagliare.
///
/// **Non e' una lettura: modifica il keyring, e chi chiama persiste subito.**
/// Fissa un mittente mai visto, butta le proprie chiavi temporanee piu' vecchie
/// di quella usata, e su un rogo distrugge la chiave d'epoca. I tre danni che
/// si prendono non persistendo sono elencati per esteso su `nativeDecryptFile`,
/// che e' la stessa cosa per gli allegati.
///
/// Il testo aperto arriva in `result` come `byte[]`, e **lo azzera il
/// chiamante** appena l'ha mostrato: da qui non e' piu' raggiungibile.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeHandleIncomingText(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    text: JString,
    now_unix: jlong,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let package = match read_string(&mut env, &app_package) {
            Ok(package) => package,
            Err(codice) => return codice,
        };
        let testo = match read_string(&mut env, &text) {
            Ok(testo) => testo,
            Err(codice) => return codice,
        };

        let esito = with_session(|session| session.handle_incoming_text(&package, &testo, now_unix));
        let item = match esito {
            Ok(item) => item,
            Err(codice) => return codice,
        };

        let mut set_int = |campo: &str, valore: jint| {
            env.set_field(&result, campo, "I", valore.into()).is_ok()
        };

        match item {
            IncomingItem::Message(message) => {
                let (etichetta, verificato) = match &message.sender_status {
                    SenderStatus::New => (None, false),
                    SenderStatus::Known { label, verified } => (label.clone(), *verified),
                };

                if !set_int("kind", code::ITEM_MESSAGE)
                    || !set_int("verified", jint::from(verificato))
                    // Quante persone potevano leggerlo, mittente compreso. Uno
                    // per un messaggio a due. Serve all'interfaccia per dire
                    // che un messaggio di gruppo NON ha forward secrecy: e' la
                    // condizione che accompagna la decisione K1, e senza questo
                    // numero non e' esprimibile.
                    // Un flag esplicito, non una soglia sul conteggio: un blob
                    // con un solo slot si presentava come messaggio a due pur
                    // essendo un gruppo senza forward secrecy.
                    || !set_int("isGroup", jint::from(message.gruppo))
                    || !set_int(
                        "recipientCount",
                        jint::try_from(message.destinatari).unwrap_or(0),
                    )
                {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&message.sender);
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    etichetta.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                // Data di composizione dichiarata dal mittente. Autenticata ma
                // NON verificabile: serve a far notare all'utente un blob
                // ripubblicato, non a decidere niente in automatico.
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(message.plaintext.sent_at_unix()),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // La pubkey serve al chiamante per etichettare il mittente o
                // selezionarlo come destinatario.
                let Ok(chiave) = env.byte_array_from_slice(message.sender.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // Il plaintext esce come byte[]: mai String.
                let Ok(array) = env.byte_array_from_slice(message.plaintext.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "plaintext", "[B", (&array).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::Burned { peer, sent_at_unix } => {
                if !set_int("kind", code::ITEM_BURNED) || !set_int("verified", 0) {
                    return code::INTERNAL;
                }
                // La data della richiesta, che prima si perdeva qui. Un blob di
                // rogo resta valido per sempre: chi l'ha visto passare in chat
                // puo' reincollarlo mesi dopo e distruggere la conversazione
                // ripartita nel frattempo. Rifiutarlo per la data e' vietato
                // dalla decisione C — un timestamp non e' verificabile — ma
                // mostrarla rende il replay visibile a chi legge.
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(sent_at_unix),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&peer);
                let etichetta = session_label(&peer).unwrap_or_default();
                if !fill_strings(&mut env, &result, &fingerprint.display(), etichetta.as_deref()) {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(peer.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::OwnMessage {
                recipient,
                recipient_label,
                plaintext,
            } => {
                // Si riempiono gli stessi campi di un messaggio, ma il peer e'
                // il destinatario. Un campo in piu' significherebbe due modi di
                // dire "l'altra persona" nello stesso oggetto, ed e' il
                // chiamante a sapere gia' dal `kind` come presentarlo.
                if !set_int("kind", code::ITEM_OWN_MESSAGE) || !set_int("verified", 0) {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&recipient);
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    recipient_label.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(plaintext.sent_at_unix()),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(recipient.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let Ok(array) = env.byte_array_from_slice(plaintext.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "plaintext", "[B", (&array).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::IdentityCard {
                peer,
                fingerprint,
                outcome,
            } => {
                let nuovo = matches!(outcome, PinOutcome::Pinned);
                // `verified` resta 0. Significa "confrontato di persona", ed e'
                // l'unico segnale anti-MITM del sistema: accenderlo perche' la
                // chiave era gia' fissata lo renderebbe ottenibile a comando —
                // basterebbe mandare la stessa card due volte per far comparire
                // il segno di spunta accanto a una chiave mai verificata.
                if !set_int("kind", code::ITEM_IDENTITY_CARD)
                    || !set_int("alreadyPinned", jint::from(!nuovo))
                    || !set_int("verified", 0)
                {
                    return code::INTERNAL;
                }
                // L'etichetta ci vuole: e' il ramo che dice "questa chiave ce
                // l'hai gia'", e senza il nome con cui e' salvata la frase e'
                // vera e inservibile — l'utente vede un'impronta e non sa a chi
                // appartenga. Passava `None` da sempre, quindi la schermata
                // aveva il posto per il nome e non lo riceveva mai.
                let etichetta = session_label(&peer).unwrap_or_default();
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    etichetta.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(peer.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::OwnIdentityCard { fingerprint } => {
                // Nessun `senderKey`: non c'e' nessun peer, e riempirlo con la
                // propria chiave inviterebbe a trattarla come un contatto —
                // che e' esattamente il difetto da cui nasce questo ramo.
                if !set_int("kind", code::ITEM_OWN_IDENTITY_CARD)
                    || !set_int("alreadyPinned", 0)
                    || !set_int("verified", 0)
                {
                    return code::INTERNAL;
                }
                if !fill_strings(&mut env, &result, &fingerprint.display(), None) {
                    return code::INTERNAL;
                }
                code::OK
            }
        }
    })
}

/// Riempie i campi stringa del risultato: fingerprint del mittente e, se
/// c'e', l'etichetta con cui l'utente lo ha nominato.
fn fill_strings(
    env: &mut JNIEnv,
    result: &JObject,
    sender: &str,
    label: Option<&str>,
) -> bool {
    let Ok(sender_obj) = env.new_string(sender) else {
        return false;
    };
    if env
        .set_field(
            result,
            "senderFingerprint",
            "Ljava/lang/String;",
            (&sender_obj).into(),
        )
        .is_err()
    {
        return false;
    }
    if let Some(label) = label {
        let Ok(label_obj) = env.new_string(label) else {
            return false;
        };
        if env
            .set_field(
                result,
                "senderLabel",
                "Ljava/lang/String;",
                (&label_obj).into(),
            )
            .is_err()
        {
            return false;
        }
    }
    true
}

/// Selezione esplicita del destinatario dalla toolbar.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeSetCurrentPeer(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let package = match read_string(&mut env, &app_package) {
            Ok(package) => package,
            Err(codice) => return codice,
        };
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.set_current_peer(&package, &key)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Sostituisce un pin dopo conferma ESPLICITA dell'utente. Non va mai
/// chiamata in automatico dopo un conflitto.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeConfirmKeyChange(
    mut env: JNIEnv,
    _class: JClass,
    old_peer: JByteArray,
    new_peer: JByteArray,
    now_unix: jlong,
) -> jint {
    guard(code::INTERNAL, || {
        let old = match read_key(&mut env, &old_peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        let new = match read_key(&mut env, &new_peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.confirm_key_change(&old, &new, now_unix)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Marca un peer come verificato fuori banda (fingerprint confrontato).
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeMarkVerified(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.mark_verified(&key)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Esporta il keyring perche' la JVM lo cifri e lo persista.
///
/// **Contiene chiavi PRIVATE**: le prekey della catena di forward secrecy
/// stanno in coda al blob. Fino all'audit del 23 agosto 2026 questa riga
/// diceva il contrario — "non contiene segreti, sono tutte chiavi pubbliche" —
/// ed e' su quella frase che si e' appoggiato chi ha servito lo stesso blob a
/// `nativeListPeers`, per la schermata contatti.
///
/// Quindi: questo blob va cifrato prima di toccare il disco, e non va dato a
/// nessuno che debba solo leggere dei nomi (per quello c'e' `export_pubblico`).
/// Anche il solo elenco dei peer resterebbe da proteggere comunque — con chi
/// parli e' il metadato che tutto il progetto cerca di non regalare — ma non e'
/// piu' quello il motivo principale.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeExportKeyring(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some(session) => new_byte_array(&env, &session.keyring().export()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Nome del peer. Riprende il lucchetto della sessione invece di riusare quello
/// del chiamante: qui non siamo dentro un'operazione crypto, quindi il costo e'
/// nullo e il codice resta leggibile.
fn session_label(
    peer: &keyboard_cipher_core::keys::PublicKey,
) -> keyboard_cipher_core::Result<Option<String>> {
    let mut guard = match session_slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match guard.as_mut() {
        Some(session) => Ok(session.keyring().get(peer)?.and_then(|r| r.label)),
        None => Ok(None),
    }
}

/// **Brucia la conversazione** con un peer (decisione J).
///
/// Ritorna il blob da consegnare all'altra persona, oppure `null`. Da questo
/// lato l'effetto e' gia' avvenuto quando la funzione ritorna: **il chiamante
/// deve persistere subito**, altrimenti un processo che muore lascia le chiavi
/// su disco e il rogo non e' avvenuto.
///
/// Dall'altro lato e' una richiesta, non un comando: chi riceve deve avere
/// un'app che la onora. Non raccontarlo come cancellazione garantita.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeBurnConversation(
    env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    now_unix: jlong,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let mut env = env;
        let nullo: jstring = std::ptr::null_mut();
        let Ok(chiave) = read_key(&mut env, &peer) else {
            return nullo;
        };
        let esito =
            with_session(|session| session.burn_conversation(&chiave, now_unix, &mut OsRng));
        match esito {
            // Se la stringa non si riesce a costruire, il rogo E' GIA'
            // AVVENUTO: le chiavi sono distrutte e non tornano. Restituire
            // `null` — come si faceva — dice al chiamante "non riuscito", e
            // l'utente si vede un errore su un'operazione irreversibile che ha
            // funzionato: la conversazione e' bruciata e lui crede di no.
            //
            // Quindi tre esiti e non due: `null` = non bruciato, stringa vuota
            // = bruciato ma senza richiesta da consegnare all'altro, stringa
            // piena = tutto fatto. E' scritto anche sul lato Kotlin.
            Ok(blob) => {
                let costruita = new_string(&env, &blob);
                if costruita.is_null() {
                    new_string(&env, "")
                } else {
                    costruita
                }
            }
            Err(_) => nullo,
        }
    })
}

/// Elenco dei peer noti per la UI contatti, **nello stesso blob** di
/// `nativeExportKeyring`.
///
/// Riusare il formato di storage per la UI e' comodo e ha un costo che va
/// tenuto presente: `PeerList.parse` lato Kotlin e' un secondo lettore di
/// questo formato, e cambiarlo lo rompe senza che niente qui lo segnali. Si
/// manifesta come "Cifratura non disponibile" nella schermata contatti, cioe'
/// come un guasto che sembra della crypto ed e' del parser. E' successo con la
/// versione 2: se questo formato cambia ancora, quel file va aggiornato
/// insieme.
///
/// **Qui NON esce nessuna chiave privata**, e non e' sempre stato vero. Fino
/// all'audit del 23 agosto 2026 questa funzione aveva il corpo identico a
/// `nativeExportKeyring`, cioe' serviva il blob di persistenza: ogni apertura
/// della schermata contatti copiava le prekey private in un `byte[]` della JVM
/// — che nessuno azzera, e che nessuno aveva motivo di sospettare — per
/// estrarne dei nomi. Ora si serve `export_pubblico`, che si ferma prima della
/// catena.
///
/// Se un giorno servisse qui un dato in piu', si aggiunge a `export_pubblico`.
/// Tornare a `export()` perche' "tanto c'e' gia'" e' esattamente il passo che
/// ha prodotto il difetto.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeListPeers(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some(session) => new_byte_array(&env, &session.keyring().export_pubblico()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Fingerprint di una pubkey qualsiasi, gia' formattato.
///
/// Non richiede che il peer sia nel keyring: serve anche a mostrare la chiave
/// entrante durante un conflitto, che per definizione non e' fissata.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeFingerprintOf(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jstring {
    guard(std::ptr::null_mut(), || match read_key(&mut env, &peer) {
        Ok(key) => {
            let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&key);
            new_string(&env, &fingerprint.display())
        }
        Err(_) => std::ptr::null_mut(),
    })
}

/// Attribuisce un nome a una chiave gia' fissata.
///
/// E' il punto in cui il TOFU acquista la capacita' di dire "la chiave di
/// Marco e' cambiata": senza un'identita' di contatto indipendente dalla
/// chiave, due chiavi diverse sarebbero solo due peer diversi.
///
/// Su conflitto NON modifica nulla e riempie `result` con i due fingerprint
/// da mostrare. Solo se l'utente conferma si chiama
/// `nativeConfirmKeyChange`; mai in automatico.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeAssignLabel(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    label: JString,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        let nome = match read_string(&mut env, &label) {
            Ok(nome) => nome,
            Err(codice) => return codice,
        };

        let esito = with_session(|session| session.assign_label(&key, &nome));
        let esito = match esito {
            Ok(esito) => esito,
            Err(codice) => return codice,
        };

        match esito {
            LabelOutcome::Assigned => {
                if env
                    .set_field(&result, "kind", "I", code::LABEL_ASSIGNED.into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            LabelOutcome::Conflict {
                existing,
                existing_fingerprint,
                incoming_fingerprint,
            } => {
                if env
                    .set_field(&result, "kind", "I", code::LABEL_CONFLICT.into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                if !fill_strings(&mut env, &result, &incoming_fingerprint.display(), None) {
                    return code::INTERNAL;
                }
                let Ok(esistente) = env.new_string(existing_fingerprint.display()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(
                        &result,
                        "existingFingerprint",
                        "Ljava/lang/String;",
                        (&esistente).into(),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // La chiave gia' etichettata serve a `nativeConfirmKeyChange`.
                let Ok(chiave) = env.byte_array_from_slice(existing.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "existingKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
        }
    })
}
