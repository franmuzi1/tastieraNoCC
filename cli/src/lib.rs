//! La parte riusabile di `kc`: lo stato su disco e il keyring.
//!
//! Esiste come libreria perche' l'app con finestra e la riga di comando devono
//! leggere e scrivere lo **stesso** file. Due implementazioni dello stesso
//! formato sarebbero due fonti di verita', e la prima volta che divergono
//! l'utente perde l'identita' — che qui significa non poter piu' decifrare
//! niente di quanto ha ricevuto.

pub mod store;
