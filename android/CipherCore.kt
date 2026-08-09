package helium314.keyboard.cipher

/**
 * Ponte verso il core Rust.
 *
 * SCHELETRO: le firme ci sono, il lato Rust no. Serve un crate
 * `keyboard-cipher-jni` che dipenda da `keyboard-cipher-core` e contenga i
 * `#[no_mangle] extern "C"`. Il core non ne contiene di proposito.
 *
 * Regole del confine, non negoziabili:
 *
 *  - i segreti attraversano come `ByteArray`, mai come `String`. Una
 *    `java.lang.String` e' immutabile: non e' azzerabile e resta in heap fino
 *    alla GC. Il chiamante azzera l'array appena ha finito;
 *  - la chiave privata non attraversa mai. Resta in Rust; la JVM manipola solo
 *    plaintext in entrata e ciphertext in uscita;
 *  - un fallimento crypto e' un solo codice d'errore. Il core non distingue le
 *    cause apposta, e questo strato non deve reintrodurre la distinzione.
 *
 * Le operazioni sono X25519 piu' un AEAD su testi corti: microsecondi. Si
 * possono chiamare dal main thread senza problemi.
 */
object CipherCore {

    init {
        System.loadLibrary("keyboard_cipher_jni")
    }

    /** Esiti di [handleIncomingText]. Rispecchia `api::IncomingItem` piu' gli errori. */
    enum class Outcome {
        /** Non e' un nostro blob. Esito normale, non un errore. */
        NOT_OUR_BLOB,
        MESSAGE,
        IDENTITY_CARD,
        /** Chiave diversa da quella fissata: serve una decisione dell'utente. */
        KEY_CONFLICT,
        TIER_UNSUPPORTED,
        /** Qualunque fallimento crypto. Nessun dettaglio, per costruzione. */
        CRYPTO_ERROR,
    }

    class IncomingResult(
        @JvmField val outcome: Outcome,
        /** Valorizzato solo se [outcome] è [Outcome.MESSAGE]. Da azzerare dopo l'uso. */
        @JvmField val plaintext: ByteArray?,
        /** Fingerprint del mittente o della card, già formattato per la UI. */
        @JvmField val senderFingerprint: String?,
        /** Fingerprint già fissato, valorizzato solo su [Outcome.KEY_CONFLICT]. */
        @JvmField val existingFingerprint: String?,
    )

    /**
     * Punto d'ingresso unico per tutte e quattro le vie (clipboard,
     * `ACTION_PROCESS_TEXT`, share sheet, campo di input). Il core non sa da
     * quale arriva, e non deve saperlo.
     *
     * @param appPackage package dell'app di chat, per il destinatario corrente
     *   per-app. Da `EditorInfo.packageName` nell'IME, da `referrer` o
     *   `callingActivity` nell'Activity — e da stringa vuota se non
     *   determinabile, il che disabilita la selezione implicita del peer.
     */
    external fun handleIncomingText(
        appPackage: String,
        text: String,
        nowUnix: Long,
    ): IncomingResult

    /** Ritorna il blob cifrato, o null se per quell'app non c'e' un destinatario. */
    external fun encryptForApp(appPackage: String, plaintext: ByteArray): String?

    /** Blob di presentazione da inserire nel campo con `commitText`. */
    external fun identityCard(): String

    external fun myFingerprint(): String

    /** Sostituisce un pin. Solo dopo conferma esplicita dell'utente. */
    external fun confirmKeyChange(oldPeer: ByteArray, newPeer: ByteArray, nowUnix: Long): Boolean

    external fun markVerified(peer: ByteArray): Boolean
}
