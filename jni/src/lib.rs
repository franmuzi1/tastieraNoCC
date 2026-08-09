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
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use rand_core::OsRng;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::error::Error;
use keyboard_cipher_core::keys::{Identity, LabelOutcome, PinOutcome, PublicKey, KEY_LEN};

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

    /// Esiti di `handleIncomingText`, quando il codice e' OK.
    pub const ITEM_MESSAGE: jint = 0;
    pub const ITEM_IDENTITY_CARD: jint = 1;

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

/// Cifra verso il destinatario corrente dell'app. `null` se non c'e'.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptForApp(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    plaintext: JByteArray,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let nullo: jstring = std::ptr::null_mut();
        let Ok(package) = read_string(&mut env, &app_package) else {
            return nullo;
        };
        let Ok(mut bytes) = read_bytes(&mut env, &plaintext) else {
            return nullo;
        };

        let esito = with_session(|session| session.encrypt_for_app(&package, &bytes, &mut OsRng));
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
            IncomingItem::IdentityCard {
                peer,
                fingerprint,
                outcome,
            } => {
                let nuovo = matches!(outcome, PinOutcome::Pinned);
                if !set_int("kind", code::ITEM_IDENTITY_CARD)
                    || !set_int("verified", jint::from(!nuovo))
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

/// Elenco dei peer noti per la UI contatti, nello stesso formato di
/// `nativeExportKeyring`: record a lunghezza fissa che Kotlin scorre senza
/// bisogno di un parser.
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
