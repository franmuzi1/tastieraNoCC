//! keyboard-cipher core — cifratura/formato per IME Android (via JNI).
//!
//! SCHELETRO: moduli, firme, error types. Nessuna implementazione.
//!
//! Decisioni di design congelate: vedi CLAUDE.md. In sintesi:
//!   - Baseline: X25519 statico-statico + XChaCha20-Poly1305, stateless.
//!   - Identita': TOFU, pubkey del mittente in-band e in chiaro.
//!   - Encoding di superficie: z-base-32.
//!   - Versione in testa, tier dentro l'AAD (anti-downgrade).
//!   - Tier forward-secrecy: previsto nel formato, NON implementato.
//!
//! Threat model: scanning di massa lato piattaforma, non avversario mirato.
//!
//! Questo crate non fa I/O. RNG e tempo sono iniettati dal chiamante.

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
