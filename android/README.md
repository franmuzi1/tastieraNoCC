# Activity companion — da innestare nel fork HeliBoard

Questi file non sono un progetto Android a sé: sono lo scheletro dei pezzi da
aggiungere al fork. Nessuno di essi è stato compilato — qui non c'è né un
checkout di HeliBoard né una toolchain Android.

Il package usato è `helium314.keyboard.cipher`, cioè un sottopackage di quello
di HeliBoard. Va allineato all'`applicationId` che il fork adotterà.

## Perché un'Activity e non solo l'IME

L'IME copre due delle quattro vie d'ingresso (clipboard, campo di input). Le
altre due — `ACTION_PROCESS_TEXT` e share sheet — richiedono per forza
un'Activity, perché sono intent di sistema e un `InputMethodService` non può
riceverli.

L'Activity sta nello **stesso APK** dell'IME: stesso processo, stessa identità,
stesso keyring. Non è una seconda app e non deve diventarlo — due APK
significherebbero due copie della chiave privata o un IPC su cui far viaggiare
segreti.

## File

| File | Cosa fa |
|---|---|
| `AndroidManifest.snippet.xml` | intent filter e attributi di sicurezza da unire al manifest del fork |
| `DecryptActivity.kt` | riceve testo da `ACTION_PROCESS_TEXT` e `ACTION_SEND`, mostra il chiaro |
| `ContactsActivity.kt` | gestione peer, fingerprint, conflitti di chiave, propria identity card |
| `CipherCore.kt` | dichiarazioni JNI verso il crate Rust |

## Dipendenza mancante

`CipherCore.kt` dichiara i metodi nativi ma il lato Rust del ponte non esiste
ancora: serve un crate `keyboard-cipher-jni` separato, che dipenda da
`keyboard-cipher-core` e contenga i `#[no_mangle] extern "C"`. Il core non ne
contiene e non deve contenerne.
