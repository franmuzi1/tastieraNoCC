//! Keyring in memoria, con serializzazione per la persistenza lato Java.
//!
//! Il core lavora contro il trait [`Keyring`]; lo storage vero sta fuori. Qui
//! il keyring vive in memoria e viene esportato/importato come `byte[]`: la
//! JVM lo cifra con una chiave in Android Keystore e lo scrive su disco.
//!
//! Perche' non chiamare Java a ogni accesso: sarebbero upcall JNI dentro il
//! percorso di decifratura, con la JVM che puo' lanciare eccezioni in mezzo a
//! un'operazione crypto. Meglio un blocco unico, caricato all'avvio e
//! risalvato quando cambia.
//!
//! Il formato di questo blob NON e' il formato sul filo: e' storage locale, e
//! puo' cambiare fra versioni dell'app senza rompere niente.

use keyboard_cipher_core::error::{Error, Result};
use keyboard_cipher_core::keys::{
    Fingerprint, Keyring, LabelOutcome, PeerRecord, PinOutcome, PrekeyStore, PublicKey, KEY_LEN,
    MAX_PREKEY_MIE,
};

/// La 2 aggiunge la catena di forward secrecy in coda.
///
/// **Si scrive la 2 e si leggono entrambe.** Chi aggiorna l'app ha gia' un
/// keyring versione 1 su disco: rifiutarlo significherebbe cancellare i
/// contatti di tutti a un aggiornamento, cioe' ri-fissare ogni chiave al
/// prossimo messaggio — accettare in silenzio un eventuale MITM, che e'
/// esattamente cio' che l'errore su blob corrotto serve a evitare.
const STORAGE_VERSION: u8 = 2;
const STORAGE_VERSION_SENZA_CATENA: u8 = 1;
/// pubkey + first_seen(i64) + verified(u8) + lunghezza etichetta(u16)
const RECORD_LEN: usize = KEY_LEN + 8 + 1 + 2;
/// Un'etichetta e' un nome scelto dall'utente, non un campo libero di rete.
const MAX_LABEL_LEN: usize = 256;

#[derive(Default)]
pub struct MemoryKeyring {
    peers: Vec<PeerRecord>,
    /// Contiene chiavi PRIVATE temporanee. Questo blob e' gia' cifrato dalla
    /// JVM con una chiave in Android Keystore prima di toccare il disco: e' la
    /// stessa protezione dell'identita', e serve, perche' finche' queste
    /// chiavi esistono i messaggi che le usavano si riaprono.
    prekey: PrekeyStore,
}

impl MemoryKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializza per la persistenza lato Java.
    pub fn export(&self) -> Vec<u8> {
        let capacity = self
            .peers
            .len()
            .saturating_mul(RECORD_LEN)
            .saturating_add(5);
        let mut out = Vec::with_capacity(capacity);
        out.push(STORAGE_VERSION);
        let count = u32::try_from(self.peers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for record in &self.peers {
            out.extend_from_slice(record.public.as_bytes());
            out.extend_from_slice(&record.first_seen_unix.to_le_bytes());
            out.push(u8::from(record.verified));
            let etichetta = record.label.as_deref().unwrap_or("").as_bytes();
            let len = u16::try_from(etichetta.len()).unwrap_or(0);
            out.extend_from_slice(&len.to_le_bytes());
            if len != 0 {
                out.extend_from_slice(etichetta);
            }
        }
        let catena = self.prekey.dump();
        let quante = u32::try_from(catena.len()).unwrap_or(0);
        out.extend_from_slice(&quante.to_le_bytes());
        for (chi, loro, mie) in catena.iter().take(quante as usize) {
            out.extend_from_slice(chi.as_bytes());
            match loro {
                Some(k) => {
                    out.push(1);
                    out.extend_from_slice(k.as_bytes());
                }
                // Un contatto a cui abbiamo scritto per primi non ha ancora
                // una chiave sua.
                None => out.push(0),
            }
            let quante_mie = u8::try_from(mie.len()).unwrap_or(0);
            out.push(quante_mie);
            for segreto in mie.iter().take(usize::from(quante_mie)) {
                out.extend_from_slice(segreto);
            }
        }
        out
    }

    /// Ricostruisce da un blob prodotto da [`Self::export`].
    ///
    /// Un blob corrotto e' un errore, non una perdita silenziosa: se il
    /// keyring non si carica, l'utente deve saperlo. Ripartire da zero in
    /// silenzio significherebbe ri-fissare tutte le chiavi al prossimo
    /// messaggio, cioe' accettare senza chiedere un eventuale MITM.
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes.iter().copied();
        let version = cursor.next().ok_or(Error::Keyring)?;
        if version != STORAGE_VERSION && version != STORAGE_VERSION_SENZA_CATENA {
            return Err(Error::Keyring);
        }

        let mut count_bytes = [0u8; 4];
        for slot in count_bytes.iter_mut() {
            *slot = cursor.next().ok_or(Error::Keyring)?;
        }
        let count = usize::try_from(u32::from_le_bytes(count_bytes)).map_err(|_| Error::Keyring)?;

        let mut peers = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let mut key = [0u8; KEY_LEN];
            for slot in key.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let mut seen = [0u8; 8];
            for slot in seen.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let verified = cursor.next().ok_or(Error::Keyring)?;

            let mut len_bytes = [0u8; 2];
            for slot in len_bytes.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let len = usize::from(u16::from_le_bytes(len_bytes));
            if len > MAX_LABEL_LEN {
                return Err(Error::Keyring);
            }
            let mut etichetta = Vec::with_capacity(len);
            for _ in 0..len {
                etichetta.push(cursor.next().ok_or(Error::Keyring)?);
            }
            // Un'etichetta non valida in UTF-8 e' storage corrotto, non un
            // nome strano: meglio rifiutare che mostrare caratteri di
            // sostituzione al posto del nome di un contatto.
            let label = if len == 0 {
                None
            } else {
                Some(String::from_utf8(etichetta).map_err(|_| Error::Keyring)?)
            };

            peers.push(PeerRecord {
                public: PublicKey::from_bytes(key),
                label,
                first_seen_unix: i64::from_le_bytes(seen),
                verified: verified != 0,
            });
        }
        let mut prekey = PrekeyStore::default();
        if version == STORAGE_VERSION {
            let mut quante_bytes = [0u8; 4];
            for slot in quante_bytes.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let quante =
                usize::try_from(u32::from_le_bytes(quante_bytes)).map_err(|_| Error::Keyring)?;
            for _ in 0..quante {
                let chi = PublicKey::from_bytes(prendi_chiave(&mut cursor)?);
                let loro = match cursor.next().ok_or(Error::Keyring)? {
                    0 => None,
                    1 => Some(PublicKey::from_bytes(prendi_chiave(&mut cursor)?)),
                    _ => return Err(Error::Keyring),
                };
                let quante_mie = usize::from(cursor.next().ok_or(Error::Keyring)?);
                if quante_mie > MAX_PREKEY_MIE {
                    return Err(Error::Keyring);
                }
                let mut mie = Vec::with_capacity(quante_mie);
                for _ in 0..quante_mie {
                    mie.push(prendi_chiave(&mut cursor)?);
                }
                prekey.restore(&chi, loro, mie);
            }
        }
        if cursor.next().is_some() {
            return Err(Error::Keyring);
        }
        Ok(Self { peers, prekey })
    }

    #[cfg(test)]
    fn catena(&self) -> &PrekeyStore {
        &self.prekey
    }

    fn find(&self, peer: &PublicKey) -> Option<&PeerRecord> {
        self.peers.iter().find(|record| &record.public == peer)
    }
}

impl Keyring for MemoryKeyring {
    fn peers(&self) -> Result<Vec<PublicKey>> {
        Ok(self.peers.iter().map(|p| p.public.clone()).collect())
    }

    fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
        match self.peers.iter().position(|p| &p.public == peer) {
            Some(indice) => {
                self.peers.remove(indice);
                // Anche le chiavi temporanee: restare dopo che l'utente ha
                // cancellato il contatto sarebbe il contrario di cio' che ha
                // chiesto.
                self.prekey.forget(peer);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
        if self.find(peer).is_some() {
            return Ok(PinOutcome::AlreadyPinned);
        }
        self.peers.push(PeerRecord {
            public: peer.clone(),
            label: None,
            first_seen_unix: now_unix,
            verified: false,
        });
        Ok(PinOutcome::Pinned)
    }

    fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome> {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(Error::Format("etichetta vuota o troppo lunga"));
        }
        if let Some(altro) = self
            .peers
            .iter()
            .find(|record| record.label.as_deref() == Some(label) && &record.public != peer)
        {
            return Ok(LabelOutcome::Conflict {
                existing: altro.public.clone(),
                existing_fingerprint: Fingerprint::of(&altro.public),
                incoming_fingerprint: Fingerprint::of(peer),
            });
        }
        match self
            .peers
            .iter_mut()
            .find(|record| &record.public == peer)
        {
            Some(record) => {
                record.label = Some(label.to_owned());
                Ok(LabelOutcome::Assigned)
            }
            None => Err(Error::UnknownPeer),
        }
    }

    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()> {
        let etichetta = self
            .find(old)
            .and_then(|record| record.label.clone());
        self.peers.retain(|record| &record.public != old);
        self.peers.retain(|record| &record.public != new);
        self.peers.push(PeerRecord {
            public: new.clone(),
            label: etichetta,
            first_seen_unix: now_unix,
            // Una chiave nuova non e' stata verificata fuori banda.
            verified: false,
        });
        Ok(())
    }

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>> {
        Ok(self.find(peer).cloned())
    }

    fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        Ok(self.prekey.peer_prekey(peer))
    }

    fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()> {
        self.prekey.set_peer_prekey(peer, prekey);
        Ok(())
    }

    fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<[u8; KEY_LEN]>> {
        Ok(self.prekey.my_prekeys(peer))
    }

    fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.push_my_prekey(peer, secret);
        Ok(())
    }

    fn drop_my_prekeys_older_than(
        &mut self,
        peer: &PublicKey,
        secret: &[u8; KEY_LEN],
    ) -> Result<()> {
        self.prekey.drop_my_prekeys_older_than(peer, secret);
        Ok(())
    }

    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        match self
            .peers
            .iter_mut()
            .find(|record| &record.public == peer)
        {
            Some(record) => {
                record.verified = true;
                Ok(())
            }
            None => Err(Error::UnknownPeer),
        }
    }
}

fn prendi_chiave(cursor: &mut impl Iterator<Item = u8>) -> Result<[u8; KEY_LEN]> {
    let mut chiave = [0u8; KEY_LEN];
    for slot in chiave.iter_mut() {
        *slot = cursor.next().ok_or(Error::Keyring)?;
    }
    Ok(chiave)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; KEY_LEN])
    }

    #[test]
    fn round_trip_vuoto() {
        let vuoto = MemoryKeyring::new();
        let ricostruito = MemoryKeyring::import(&vuoto.export()).unwrap();
        assert!(ricostruito.peers.is_empty());
    }

    #[test]
    fn round_trip_con_peer() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.tofu_pin(&key(2), 200).unwrap();
        keyring.assign_label(&key(2), "Marco è qui ✓").unwrap();
        keyring.mark_verified(&key(2)).unwrap();

        let ricostruito = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(ricostruito.peers.len(), 2);
        assert!(!ricostruito.get(&key(1)).unwrap().unwrap().verified);
        let secondo = ricostruito.get(&key(2)).unwrap().unwrap();
        assert!(secondo.verified);
        assert_eq!(secondo.first_seen_unix, 200);
        // UTF-8 non ASCII deve sopravvivere al round-trip.
        assert_eq!(secondo.label.as_deref(), Some("Marco è qui ✓"));
    }

    /// Chi aggiorna l'app ha un keyring versione 1 su disco. Deve continuare a
    /// caricarsi: rifiutarlo cancellerebbe i contatti di tutti, e il prossimo
    /// messaggio ri-fisserebbe ogni chiave senza chiedere niente a nessuno.
    #[test]
    fn un_keyring_di_prima_si_carica_ancora() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();

        // Un blob versione 1 e' un versione 2 senza la coda della catena.
        let mut vecchio = keyring.export();
        let taglio = vecchio.len().checked_sub(4).unwrap();
        vecchio.truncate(taglio);
        *vecchio.first_mut().unwrap() = 1;

        let riletto = MemoryKeyring::import(&vecchio).unwrap();
        assert_eq!(
            riletto.get(&key(1)).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(riletto.peer_prekey(&key(1)).unwrap().is_none());
    }

    /// La catena deve sopravvivere al giro su disco **nel suo ordine**: e'
    /// l'ordine che decide quali messaggi in viaggio restano apribili.
    #[test]
    fn la_catena_sopravvive_al_round_trip() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.tofu_pin(&key(2), 200).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();
        keyring.push_my_prekey(&key(1), [11; KEY_LEN]).unwrap();
        // Contatto a cui abbiamo scritto per primi: nessuna chiave sua.
        keyring.push_my_prekey(&key(2), [20; KEY_LEN]).unwrap();

        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(riletto.peer_prekey(&key(1)).unwrap(), Some(key(50)));
        assert_eq!(
            riletto.my_prekeys(&key(1)).unwrap(),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(riletto.peer_prekey(&key(2)).unwrap(), None);
        assert_eq!(riletto.my_prekeys(&key(2)).unwrap(), vec![[20; KEY_LEN]]);
        assert_eq!(riletto.catena().dump().len(), 2);
    }

    /// Dimenticare un contatto porta via anche le sue chiavi temporanee, che
    /// altrimenti resterebbero nel blob salvato su disco.
    #[test]
    fn dimenticare_svuota_anche_la_catena() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();

        assert!(keyring.forget(&key(1)).unwrap());
        assert!(keyring.catena().dump().is_empty());
        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert!(riletto.my_prekeys(&key(1)).unwrap().is_empty());
    }

    /// Un blob corrotto deve fallire, non degradare a keyring vuoto.
    #[test]
    fn blob_corrotto_e_un_errore() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();
        let buono = keyring.export();

        for taglio in 1..buono.len() {
            let corto = buono.get(..taglio).unwrap();
            assert!(
                MemoryKeyring::import(corto).is_err(),
                "troncamento a {taglio} accettato"
            );
        }

        let mut lungo = buono.clone();
        lungo.push(0);
        assert!(MemoryKeyring::import(&lungo).is_err());

        let mut versione_sbagliata = buono;
        if let Some(first) = versione_sbagliata.first_mut() {
            *first = 99;
        }
        assert!(MemoryKeyring::import(&versione_sbagliata).is_err());
    }

    #[test]
    fn niente_panic_su_input_arbitrario() {
        for len in 0..200usize {
            let spazzatura: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31)) as u8).collect();
            let _ = MemoryKeyring::import(&spazzatura);
        }
    }

    #[test]
    fn etichetta_duplicata_e_un_conflitto() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.tofu_pin(&key(2), 2).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();

        let esito = keyring.assign_label(&key(2), "Marco").unwrap();
        assert!(matches!(esito, LabelOutcome::Conflict { .. }));
        // Niente e' cambiato.
        assert_eq!(
            keyring.get(&key(1)).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(keyring.get(&key(2)).unwrap().unwrap().label.is_none());
    }

    #[test]
    fn la_conferma_sposta_etichetta_e_azzera_la_verifica() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();
        keyring.mark_verified(&key(1)).unwrap();

        keyring.replace_pinned(&key(1), &key(2), 10).unwrap();
        let record = keyring.get(&key(2)).unwrap().unwrap();
        assert_eq!(record.label.as_deref(), Some("Marco"));
        assert!(!record.verified, "la verifica non si eredita");
        assert!(keyring.get(&key(1)).unwrap().is_none());
    }
}
