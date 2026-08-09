package helium314.keyboard.cipher

/**
 * Ponte verso il core Rust (crate `keyboard-cipher-jni`).
 *
 * Regole del confine, non negoziabili:
 *
 *  - i segreti attraversano come `ByteArray`, mai come `String`. Una
 *    `java.lang.String` e' immutabile: non e' azzerabile e resta in heap fino
 *    alla GC. Il chiamante azzera l'array appena ha finito;
 *  - la chiave privata attraversa UNA sola volta, alla generazione. Poi resta
 *    in Rust; la JVM manipola solo plaintext in entrata e blob in uscita;
 *  - un fallimento crypto e' un solo codice. Il core non distingue le cause
 *    apposta, e questo strato non deve reintrodurre la distinzione.
 *
 * Le operazioni sono X25519 piu' un AEAD su testi corti: microsecondi. Si
 * possono chiamare dal main thread senza problemi.
 */
object CipherCore {

    init {
        System.loadLibrary("keyboard_cipher_jni")
    }

    // Codici di ritorno. Devono restare allineati a `mod code` in
    // jni/src/lib.rs: sono un contratto ABI, non una convenzione.
    const val OK = 0
    /** Non e' un nostro blob. Esito NORMALE, non un errore. */
    const val NOT_OUR_BLOB = 1
    const val FORMAT = 2
    const val UNSUPPORTED_VERSION = 3
    const val DECODE = 4
    /** Qualunque fallimento crypto. Nessun dettaglio, per costruzione. */
    const val CRYPTO = 5
    const val UNKNOWN_PEER = 6
    const val TIER_UNSUPPORTED = 7
    const val KEYRING = 8
    /** Sessione non inizializzata, errore JNI, o panic intercettato in Rust. */
    const val INTERNAL = 9

    // Valori del campo `kind` di [IncomingResult], validi solo se il codice e' OK.
    const val KIND_MESSAGE = 0
    const val KIND_IDENTITY_CARD = 1
    /** Chiave diversa da quella fissata: serve una decisione dell'utente. */
    const val KIND_KEY_CONFLICT = 2

    /**
     * Riempito dal lato Rust invece di essere costruito la': allocare oggetti
     * da JNI richiede risolvere classe e firma del costruttore a runtime, e
     * ogni errore diventa un'eccezione lanciata in mezzo a un'operazione
     * crypto. I campi sono `@JvmField` perche' JNI scrive sui campi, non
     * attraverso i setter.
     */
    class IncomingResult {
        @JvmField var kind: Int = -1
        @JvmField var verified: Int = 0
        /** Valorizzato solo se [kind] e' [KIND_MESSAGE]. Da azzerare dopo l'uso. */
        @JvmField var plaintext: ByteArray? = null
        @JvmField var senderFingerprint: String? = null
        /** Valorizzato solo su [KIND_KEY_CONFLICT]. */
        @JvmField var existingFingerprint: String? = null
    }

    /**
     * Genera un nuovo segreto di identita'. E' l'unico momento in cui la
     * chiave privata attraversa il confine: va cifrata con Android Keystore,
     * persistita, e l'array azzerato subito dopo.
     */
    external fun nativeGenerateSecret(): ByteArray?

    /**
     * Inizializza la sessione. `keyringBlob` puo' essere vuoto al primo avvio.
     * Ritorna uno dei codici sopra.
     */
    external fun nativeInit(secret: ByteArray, keyringBlob: ByteArray): Int

    /** Blob di presentazione da inserire nel campo con `commitText`. */
    external fun nativeIdentityCard(): String?

    external fun nativeMyFingerprint(): String?

    /**
     * Punto d'ingresso unico per tutte e quattro le vie (clipboard,
     * `ACTION_PROCESS_TEXT`, share sheet, campo di input). Il core non sa da
     * quale arriva, e non deve saperlo.
     *
     * @param appPackage da `EditorInfo.packageName` nell'IME; nell'Activity da
     *   `callingActivity` o `referrer`. Stringa vuota se non determinabile, il
     *   che disabilita la selezione implicita del destinatario — meglio
     *   chiedere che attribuire il messaggio all'app sbagliata.
     * @param result oggetto gia' allocato che il lato Rust riempie.
     */
    external fun nativeHandleIncomingText(
        appPackage: String,
        text: String,
        nowUnix: Long,
        result: IncomingResult,
    ): Int

    /** Ritorna il blob cifrato, o null se per quell'app non c'e' un destinatario. */
    external fun nativeEncryptForApp(appPackage: String, plaintext: ByteArray): String?

    external fun nativeSetCurrentPeer(appPackage: String, peer: ByteArray): Int

    /** Sostituisce un pin. SOLO dopo conferma esplicita dell'utente. */
    external fun nativeConfirmKeyChange(oldPeer: ByteArray, newPeer: ByteArray, nowUnix: Long): Int

    external fun nativeMarkVerified(peer: ByteArray): Int

    /**
     * Keyring serializzato, da cifrare e persistere. Non contiene segreti —
     * sono tutte chiavi pubbliche — ma va comunque protetto: l'elenco dei peer
     * con cui parli e' esattamente il metadato che il progetto cerca di non
     * regalare.
     */
    external fun nativeExportKeyring(): ByteArray?

    /**
     * Stesso formato di [nativeExportKeyring]: record a lunghezza fissa,
     * 32 byte di pubkey + 8 di timestamp + 1 di "verificato", dopo un'intestazione
     * di 5 byte. Kotlin li scorre senza bisogno di un parser.
     */
    external fun nativeListPeers(): ByteArray?

    /**
     * Fingerprint di una pubkey qualsiasi, gia' formattato. Non richiede che
     * il peer sia nel keyring: serve anche a mostrare la chiave entrante
     * durante un conflitto, che per definizione non e' fissata.
     */
    external fun nativeFingerprintOf(peer: ByteArray): String?
}
