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

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use rand_core::OsRng;

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

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String, jint> {
    env.get_string(value)
        .map(|s| s.into())
        .map_err(|_| code::INTERNAL)
}

fn new_string(env: &JNIEnv, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn new_byte_array(env: &JNIEnv, value: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(value) {
        Ok(array) => array.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_bytes(env: &mut JNIEnv, value: &JByteArray) -> Result<Vec<u8>, jint> {
    env.convert_byte_array(value).map_err(|_| code::INTERNAL)
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
        use zeroize::Zeroize;

        // OsRng: entropia dell'OS. Mai un PRNG seedato in-app.
        let mut secret = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut secret);
        // Verifica che i byte producano un'identita' valida prima di
        // consegnarli allo storage: un segreto che non si ricarica sarebbe un
        // guasto permanente e silenzioso.
        if Identity::from_secret_bytes(secret).is_err() {
            secret.zeroize();
            return std::ptr::null_mut();
        }
        let array = new_byte_array(&env, &secret);
        secret.zeroize();
        array
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
        let bytes = match read_bytes(&mut env, &secret) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        if bytes.len() != KEY_LEN {
            return code::FORMAT;
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        let identity = match Identity::from_secret_bytes(key) {
            Ok(identity) => identity,
            Err(error) => return code_of(&error),
        };

        let blob = match read_bytes(&mut env, &keyring_blob) {
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
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let Ok(chiave) = read_key(&mut env, &peer) else {
            return std::ptr::null_mut();
        };
        let Ok(nome) = read_string(&mut env, &name) else {
            return std::ptr::null_mut();
        };
        let Ok(tipo) = read_string(&mut env, &mime) else {
            return std::ptr::null_mut();
        };
        let Ok(bytes) = read_bytes(&mut env, &content) else {
            return std::ptr::null_mut();
        };
        let meta = FileMeta { name: nome, mime: tipo };
        let esito = with_session(|session| {
            session.encrypt_file_with(&chiave, &meta, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        match esito {
            Ok(blob) => new_byte_array(&env, &blob),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Apre un allegato ricevuto e riempie `result`.
///
/// Come per i messaggi, il core decifra **prima** di toccare il keyring: la
/// decifratura riuscita e' la prova che chi ha mandato il file possiede la
/// privata dichiarata.
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
        use zeroize::Zeroize;
        let mut pass = match read_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };
        let esito = with_session(|session| {
            let keyring = session.keyring().export();
            keyboard_cipher_core::backup::export(
                session.identity(),
                &keyring,
                &pass,
                &mut OsRng,
            )
        });
        // La copia della passphrase che vive in questo stack e' nostra: la
        // azzeriamo noi, senza aspettare il chiamante.
        // `as_mut_slice()` e non `pass.zeroize()`: l'impl di Zeroize per Vec
        // dipende dalla feature `alloc`, quella per gli slice no. Il risultato
        // e' identico — e resta una scrittura che il compilatore non puo'
        // eliminare, che e' il motivo per cui non si usa `fill(0)`.
        pass.as_mut_slice().zeroize();
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
        use zeroize::Zeroize;
        let mut pass = match read_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let aperto = keyboard_cipher_core::backup::import(&dati, &pass);
        // `as_mut_slice()` e non `pass.zeroize()`: l'impl di Zeroize per Vec
        // dipende dalla feature `alloc`, quella per gli slice no. Il risultato
        // e' identico — e resta una scrittura che il compilatore non puo'
        // eliminare, che e' il motivo per cui non si usa `fill(0)`.
        pass.as_mut_slice().zeroize();
        let aperto = match aperto {
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
        let Ok(mut bytes) = read_bytes(&mut env, &plaintext) else {
            return nullo;
        };

        let esito = with_session(|session| {
            session.encrypt_for_app_with(&package, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        // La copia Rust del plaintext sparisce subito; quella Java la azzera
        // il chiamante.
        use zeroize::Zeroize;
        bytes.zeroize();

        match esito {
            Ok(blob) => new_string(&env, &blob),
            Err(_) => nullo,
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
                if !fill_strings(&mut env, &result, &fingerprint.display(), None) {
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
/// Non contiene segreti — sono tutte chiavi pubbliche — ma va comunque
/// protetto: l'elenco dei peer con cui parli e' esattamente il metadato che il
/// progetto cerca di non regalare.
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
            Some(session) => new_byte_array(&env, &session.keyring().export()),
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
