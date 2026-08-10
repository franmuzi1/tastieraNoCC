//! Backup dell'identita': la chiave privata e il portachiavi, cifrati con una
//! passphrase, in una forma che puo' uscire dal dispositivo.
//!
//! # Perche' non basta il Keystore
//!
//! Sul telefono il segreto e' protetto da una chiave in Android Keystore, che
//! non e' esportabile: e' esattamente cio' che serve li' — e il motivo per cui
//! un backup non puo' usarla. Un file cifrato con una chiave che non lascia il
//! dispositivo e' un file che nessun altro dispositivo potra' mai aprire.
//!
//! Quindi la protezione qui dipende **solo** da quello che l'utente sa. E'
//! un'informazione da dare all'utente, non da nascondere: un backup con una
//! passphrase debole e' un backup debole, punto.
//!
//! # La cosa che questo modulo esiste per evitare
//!
//! Senza backup, chi cambia telefono o cancella i dati dell'app perde
//! l'identita' — e ogni suo contatto vede un cambio chiave, cioe' lo stesso
//! segnale che indica un tentativo di impersonazione. Il guasto e' silenzioso,
//! permanente, e certo che prima o poi capiti a chiunque.
//!
//! # Formato
//!
//! ```text
//! versione(1) | salt(16) | m_cost(4 BE) | t_cost(4 BE) | p_cost(1) |
//! nonce(24) | ciphertext( segreto(32) || portachiavi ) + tag(16)
//! ```
//!
//! L'intestazione viaggia **in chiaro** — versione, salt e parametri servono
//! per rifare la derivazione — ma entra per intero come dato autenticato della
//! cifratura, quindi non e' modificabile.
//!
//! Senza quella autenticazione l'attacco sarebbe immediato: si riscrivono i
//! parametri a `m=8, t=1`, il file resta apribile con la stessa passphrase, e
//! provarle tutte costa migliaia di volte meno. La vittima non se ne
//! accorgerebbe mai, perche' dal suo lato il backup continuerebbe a funzionare.

use crate::error::{Error, Result};
use crate::keys::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Versione del contenitore di backup. Indipendente da quella dei messaggi:
/// sono due formati con vite diverse.
const VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SECRET_LEN: usize = 32;

/// Intestazione in chiaro: versione, salt e i tre parametri di Argon2.
const HEADER_LEN: usize = 1 + SALT_LEN + 4 + 4 + 1;

/// Costo di memoria, in KiB. 64 MiB.
///
/// E' il parametro che decide quanto costa provare una passphrase, ed e' anche
/// quello che puo' far fallire l'operazione su un telefono economico. 64 MiB e'
/// il compromesso: abbastanza da rendere il calcolo per tentativo costoso anche
/// su GPU — dove la memoria e' il collo di bottiglia, non il calcolo — e
/// abbastanza poco da non far morire un dispositivo con 2 GB di RAM.
///
/// Non e' congelato: sta nel file, quindi alzarlo in futuro non rompe i backup
/// gia' fatti, che si riaprono coi parametri con cui sono stati scritti.
const M_COST: u32 = 65_536;

/// Numero di passate.
const T_COST: u32 = 3;

/// Parallelismo. Uno: su un telefono i core sono pochi e occupati, e alzarlo
/// avvantaggia piu' chi attacca — che ne ha molti — di chi si difende.
const P_COST: u32 = 1;

/// Separazione di dominio: la chiave derivata qui non deve poter coincidere
/// con nessun'altra del progetto, nemmeno se un giorno qualcuno riusasse la
/// stessa passphrase altrove.
const AD: &[u8] = b"keyboard-cipher/v1/backup";

/// Contenuto di un backup aperto.
///
/// **Non implementa `Debug`**, e non deve: contiene la chiave privata in
/// chiaro, e un `{:?}` finito in un log la scriverebbe su disco. E' il motivo
/// per cui i test qui sotto non possono usare `unwrap()` su un `Result<Backup>`
/// — piccolo fastidio, garanzia grande.
///
/// Entrambi i campi sono azzerati quando la struttura viene distrutta: il
/// segreto perche' e' la chiave privata, il portachiavi perche' e' l'elenco
/// delle persone con cui si parla.
pub struct Backup {
    /// I 32 byte del segreto di identita'.
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
    /// Il portachiavi serializzato, opaco per questo modulo.
    pub keyring: Zeroizing<Vec<u8>>,
}

/// Cifra identita' e portachiavi con una passphrase.
///
/// `keyring` e' trattato come byte opachi: la sua serializzazione appartiene a
/// chi lo implementa, non a questo modulo.
///
/// # Errori
///
/// [`Error::Crypto`] se la derivazione o la cifratura falliscono. Non c'e'
/// nessun caso in cui il chiamante possa distinguere quale delle due, ed e'
/// voluto.
pub fn export<R: RngCore + CryptoRng>(
    identity: &Identity,
    keyring: &[u8],
    passphrase: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = header_bytes(&salt, M_COST, T_COST, P_COST);
    let key = derive(passphrase, &salt, M_COST, T_COST, P_COST)?;

    // Il chiaro e' segreto(32) || portachiavi. Vive in un Zeroizing perche'
    // contiene la chiave privata in forma grezza.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SECRET_LEN.saturating_add(keyring.len()),
    ));
    plaintext.extend_from_slice(identity.secret_bytes().as_ref());
    plaintext.extend_from_slice(keyring);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto)?;

    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(NONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Apre un backup.
///
/// # Errori
///
/// - [`Error::Format`] se il file e' troppo corto o mal formato;
/// - [`Error::UnsupportedVersion`] per una versione futura — cosi' l'utente
///   legge "aggiorna l'app" invece di "passphrase sbagliata", che lo manderebbe
///   a cercare un errore che non ha commesso;
/// - [`Error::Crypto`] per tutto il resto, **passphrase sbagliata compresa**.
///   La distinzione fra "passphrase errata" e "file manomesso" non e'
///   esprimibile con una cifratura autenticata, e non deve esserlo: sarebbe un
///   oracolo per chi prova le passphrase.
pub fn import(blob: &[u8], passphrase: &[u8]) -> Result<Backup> {
    let minimo = HEADER_LEN
        .saturating_add(NONCE_LEN)
        .saturating_add(SECRET_LEN)
        .saturating_add(TAG_LEN);
    if blob.len() < minimo {
        return Err(Error::Format("backup troppo corto"));
    }
    let header = blob.get(..HEADER_LEN).ok_or(Error::Format("intestazione"))?;

    let versione = *header.first().ok_or(Error::Format("versione"))?;
    if versione != VERSION {
        return Err(Error::UnsupportedVersion(versione));
    }

    let salt: [u8; SALT_LEN] = header
        .get(1..1 + SALT_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("salt"))?;
    let m_cost = be_u32(header, 1 + SALT_LEN)?;
    let t_cost = be_u32(header, 1 + SALT_LEN + 4)?;
    let p_cost = u32::from(*header.get(1 + SALT_LEN + 8).ok_or(Error::Format("p_cost"))?);

    // Un file puo' chiedere parametri arbitrari, e Argon2 li onorerebbe: un
    // m_cost da 4 GiB non e' un attacco crittografico ma fa morire il processo.
    // Il tetto e' generoso rispetto a quello che scriviamo noi, cosi' resta
    // spazio per alzare i costi in futuro senza rendere illeggibili i file
    // vecchi.
    if m_cost > 1_048_576 || t_cost > 16 || p_cost == 0 || p_cost > 16 {
        return Err(Error::Format("parametri di derivazione fuori scala"));
    }

    let nonce: [u8; NONCE_LEN] = blob
        .get(HEADER_LEN..HEADER_LEN + NONCE_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("nonce"))?;
    let ciphertext = blob
        .get(HEADER_LEN + NONCE_LEN..)
        .ok_or(Error::Format("ciphertext"))?;

    let key = derive(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    let secret: [u8; SECRET_LEN] = plaintext
        .get(..SECRET_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("segreto"))?;
    // Passaggio dal costruttore dell'identita'. Oggi non puo' fallire — per
    // X25519 qualunque sequenza di 32 byte e' un segreto valido dopo il
    // clamping, e non c'e' niente da validare: i controlli sui punti di ordine
    // basso riguardano la chiave PUBBLICA del peer, non la propria privata.
    // Resta qui perche' se un giorno il costruttore acquistasse una
    // validazione, il backup la erediterebbe senza che nessuno se ne ricordi.
    Identity::from_secret_bytes(secret)?;

    let keyring = plaintext
        .get(SECRET_LEN..)
        .ok_or(Error::Format("portachiavi"))?
        .to_vec();

    Ok(Backup {
        secret: Zeroizing::new(secret),
        keyring: Zeroizing::new(keyring),
    })
}

fn header_bytes(salt: &[u8; SALT_LEN], m: u32, t: u32, p: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push(VERSION);
    header.extend_from_slice(salt);
    header.extend_from_slice(&m.to_be_bytes());
    header.extend_from_slice(&t.to_be_bytes());
    header.push(p as u8);
    header
}

fn be_u32(buf: &[u8], at: usize) -> Result<u32> {
    let quattro: [u8; 4] = buf
        .get(at..at.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("intero a 32 bit"))?;
    Ok(u32::from_be_bytes(quattro))
}

fn derive(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(m, t, p, Some(KEY_LEN)).map_err(|_| Error::Crypto)?;
    // La costante di dominio entra come "secret" di Argon2 — quello che in
    // letteratura si chiama pepper. Non e' un segreto (sta nel sorgente): serve
    // solo a garantire che questa derivazione non possa mai coincidere con
    // un'altra fatta altrove con la stessa passphrase e lo stesso salt.
    let argon = Argon2::new_with_secret(AD, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| Error::Crypto)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // I test usano parametri MINIMI: con quelli veri ogni derivazione costa
    // 64 MiB e decine di millisecondi, e la suite diventerebbe troppo lenta per
    // essere eseguita a ogni modifica — cioe' smetterebbe di essere eseguita.
    // I parametri stanno nel file, quindi questa scorciatoia non falsa niente
    // del formato.
    fn export_veloce(identity: &Identity, keyring: &[u8], pass: &[u8], seed: u8) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let header = header_bytes(&salt, 8, 1, 1);
        let key = derive(pass, &salt, 8, 1, 1).unwrap();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(identity.secret_bytes().as_ref());
        plaintext.extend_from_slice(keyring);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        let mut out = header;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// `Backup` non implementa `Debug`, quindi `unwrap()` non compila: e' la
    /// stessa regola che tiene le chiavi private fuori dai log.
    fn apri(blob: &[u8], pass: &[u8]) -> Backup {
        match import(blob, pass) {
            Ok(b) => b,
            Err(_) => panic!("il backup doveva aprirsi"),
        }
    }

    fn identita(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32]).unwrap()
    }

    #[test]
    fn andata_e_ritorno() {
        let id = identita(7);
        let keyring = b"portachiavi finto".as_slice();
        let blob = export_veloce(&id, keyring, b"passphrase corretta", 1);

        let aperto = apri(&blob, b"passphrase corretta");
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
        assert_eq!(aperto.keyring.as_slice(), keyring);
    }

    #[test]
    fn passphrase_sbagliata_e_manomissione_danno_lo_stesso_errore() {
        let id = identita(9);
        let blob = export_veloce(&id, b"kr", b"giusta", 2);

        let per_passphrase = match import(&blob, b"sbagliata") {
            Err(e) => e,
            Ok(_) => panic!("non doveva aprirsi"),
        };
        let mut corrotto = blob.clone();
        let ultimo = corrotto.len() - 1;
        corrotto[ultimo] ^= 1;
        let per_manomissione = match import(&corrotto, b"giusta") {
            Err(e) => e,
            Ok(_) => panic!("non doveva aprirsi"),
        };

        // Devono essere indistinguibili: un errore che dice "la passphrase e'
        // giusta ma il file e' rotto" direbbe anche, a chi prova le passphrase,
        // che quella era giusta.
        assert!(matches!(per_passphrase, Error::Crypto));
        assert!(matches!(per_manomissione, Error::Crypto));
    }

    #[test]
    fn i_parametri_sono_autenticati() {
        let id = identita(3);
        let mut blob = export_veloce(&id, b"kr", b"pass", 4);
        // Abbassare il costo di derivazione e' l'attacco ovvio: il file si
        // aprirebbe lo stesso e la passphrase costerebbe molto meno da provare.
        // m=16 invece del 8 con cui e' stato scritto: basta che sia DIVERSO.
        blob[1 + SALT_LEN..1 + SALT_LEN + 4].copy_from_slice(&16u32.to_be_bytes());
        assert!(import(&blob, b"pass").is_err());
    }

    #[test]
    fn versione_futura_non_dice_passphrase_sbagliata() {
        let id = identita(5);
        let mut blob = export_veloce(&id, b"kr", b"pass", 6);
        blob[0] = 2;
        assert!(matches!(
            import(&blob, b"pass"),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn parametri_assurdi_rifiutati_senza_provarci() {
        let id = identita(11);
        let mut blob = export_veloce(&id, b"kr", b"pass", 8);
        // 4 GiB di costo di memoria: non e' un attacco crittografico, e' un modo
        // di far morire il processo di chi apre il file.
        blob[1 + SALT_LEN..1 + SALT_LEN + 4].copy_from_slice(&4_194_304u32.to_be_bytes());
        assert!(matches!(import(&blob, b"pass"), Err(Error::Format(_))));
    }

    #[test]
    fn troncato() {
        let id = identita(13);
        let blob = export_veloce(&id, b"kr", b"pass", 10);
        for taglio in [0, 1, HEADER_LEN, HEADER_LEN + NONCE_LEN] {
            assert!(import(&blob[..taglio], b"pass").is_err());
        }
    }

    #[test]
    fn portachiavi_vuoto() {
        // Caso reale: si esporta prima di aver mai parlato con qualcuno.
        let id = identita(15);
        let blob = export_veloce(&id, b"", b"pass", 12);
        let aperto = apri(&blob, b"pass");
        assert!(aperto.keyring.is_empty());
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
    }

    #[test]
    fn export_vero_usa_i_parametri_veri() {
        // Un solo test con i parametri di produzione: verifica che il costo
        // scelto sia effettivamente sostenibile e che il giro completo funzioni.
        let mut rng = ChaCha20Rng::from_seed([21; 32]);
        let id = identita(17);
        let blob = export(&id, b"portachiavi", b"una passphrase lunga", &mut rng).unwrap();
        assert_eq!(blob[0], VERSION);
        assert_eq!(be_u32(&blob, 1 + SALT_LEN).unwrap(), M_COST);
        let aperto = apri(&blob, b"una passphrase lunga");
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
        assert_eq!(aperto.keyring.as_slice(), b"portachiavi");
    }

    #[test]
    fn due_export_dello_stesso_segreto_sono_diversi() {
        // Salt e nonce sono estratti a caso: due backup della stessa identita'
        // non devono essere confrontabili fra loro.
        let id = identita(19);
        let a = export_veloce(&id, b"kr", b"pass", 30);
        let b = export_veloce(&id, b"kr", b"pass", 31);
        assert_ne!(a, b);
    }


}
