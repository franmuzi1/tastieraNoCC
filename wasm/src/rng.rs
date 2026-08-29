//! RNG iniettato da JS, mai generato qui dentro.
//!
//! Il core vuole un `RngCore + CryptoRng` per ogni operazione che ne ha
//! bisogno (`Identity::from_secret_bytes` non ne serve, ma `identity_card`,
//! `encrypt_for_app_with`, `burn_conversation` si'). Su `wasm32-unknown-unknown`
//! non esiste un CSPRNG di sistema raggiungibile da qui: l'entropia vera arriva
//! da JS (bridge via WebView, vedi il piano), un blocco di 32 byte alla volta,
//! **prima** di ogni chiamata che la consuma — mai un seme riusato fra due
//! operazioni diverse, per non restringere lo spazio di ricerca se in una
//! stessa esecuzione si generano piu' chiavi.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use std::cell::RefCell;

thread_local! {
    /// `Option`: `None` finche' JS non ha chiamato `mb_seed_rng`, e di nuovo
    /// `None` subito dopo che un'operazione l'ha consumato — cosi' un secondo
    /// uso senza un nuovo seed fallisce in modo esplicito invece di riusare
    /// silenziosamente lo stream precedente.
    static SEME: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
}

/// Chiamata da `mb_seed_rng`: installa un nuovo generatore da 32 byte di vera
/// entropia. Sovrascrive un eventuale seme non consumato — non dovrebbe mai
/// succedere lato JS ben scritto, ma non e' un errore da rifiutare: il seme
/// vecchio semplicemente sparisce senza essere stato usato.
pub fn seed(bytes: [u8; 32]) {
    SEME.with(|cell| {
        *cell.borrow_mut() = Some(ChaCha20Rng::from_seed(bytes));
    });
}

/// Consuma il generatore corrente. `None` se non e' stato seedato (o e' gia'
/// stato consumato da un'operazione precedente): il chiamante deve trattarlo
/// come un errore da riportare a JS, mai come "usa un seme di riserva".
pub fn take() -> Option<ChaCha20Rng> {
    SEME.with(|cell| cell.borrow_mut().take())
}
