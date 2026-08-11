//! keyboard-cipher core — cifratura/formato per IME Android (via JNI).
//!
//! Decisioni di design congelate: vedi CLAUDE.md. In sintesi:
//!   - Baseline: X25519 + XChaCha20-Poly1305.
//!   - Identita': TOFU, con la pubkey del mittente in chiaro **solo** negli
//!     schemi statici.
//!   - Forward secrecy dentro il tier baseline, segnalata dai bit di flag: una
//!     chiave usa-e-getta per messaggio, piu' una chiave temporanea del
//!     destinatario che viaggia dentro il cifrato. Il gesto che la produce e'
//!     buttare le chiavi vecchie, non cifrare.
//!   - Encoding di superficie: z-base-32.
//!   - Versione in testa, tier dentro l'AAD (anti-downgrade).
//!   - Il **tier** forward-secrecy resta un posto libero nel formato, non
//!     implementato: da non confondere con la forward secrecy qui sopra.
//!
//! Threat model: scanning di massa lato piattaforma, non avversario mirato.
//!
//! Questo crate non fa I/O. RNG e tempo sono iniettati dal chiamante: senza,
//! i vettori di test del formato non sarebbero scrivibili.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod api;
pub mod backup;
pub mod baseline;
pub mod encoding;
pub mod error;
pub mod file;
pub mod format;
pub mod keys;

pub use error::{Error, Result};
