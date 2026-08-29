//! Keyring in memoria per la sessione wasm.
//!
//! Stessa logica di `jni::MemoryKeyring` (peers: `Vec<PeerRecord>` +
//! `PrekeyStore`), copiata qui perche' quel tipo vive in un crate satellite
//! diverso, non riesportabile. Nessuna persistenza qui dentro: `config.json`
//! e' responsabilita' di `MusyBoard.js`, non di questo crate — il modulo wasm
//! non ha filesystem, ogni esecuzione di Scriptable ri-idrata lo stato da capo
//! tramite [`IosKeyring::restore_peer`]/[`IosKeyring::restore_prekey`] e lo
//! rilegge con [`IosKeyring::peer_records`]/[`IosKeyring::prekey_dump`].

use keyboard_cipher_core::error::{Error, Result};
use keyboard_cipher_core::keys::{
    Fingerprint, KEY_LEN, Keyring, LabelOutcome, PeerRecord, PinOutcome, PrekeyRecord,
    PrekeyStore, PublicKey,
};
use zeroize::Zeroizing;

/// Un'etichetta e' un nome scelto dall'utente, non un campo libero di rete.
const MAX_LABEL_LEN: usize = 256;

#[derive(Default)]
pub struct IosKeyring {
    peers: Vec<PeerRecord>,
    prekey: PrekeyStore,
}

impl IosKeyring {
    fn find(&self, peer: &PublicKey) -> Option<&PeerRecord> {
        self.peers.iter().find(|record| &record.public == peer)
    }

    /// Inserisce un `PeerRecord` gia' completo, per l'idratazione da
    /// `config.json`. A differenza di `tofu_pin` non tocca `first_seen_unix`
    /// ne' `label`: sono valori gia' decisi in passato, non da questa
    /// esecuzione.
    pub fn restore_peer(&mut self, record: PeerRecord) {
        self.peers.retain(|r| r.public != record.public);
        self.peers.push(record);
    }

    /// Inserisce lo stato di catena/epoca per un contatto, per l'idratazione
    /// da `config.json`. Delega a `PrekeyStore::restore`, che decide da solo
    /// quali campi applicare (un campo assente nel record non cancella quello
    /// gia' presente — vedi il commento su `PrekeyStore::restore`).
    pub fn restore_prekey(&mut self, record: PrekeyRecord) {
        self.prekey.restore(record);
    }

    /// I contatti fissati, per riscrivere `config.json`.
    pub fn peer_records(&self) -> &[PeerRecord] {
        &self.peers
    }

    /// Lo stato di catena/epoca per contatto, per riscrivere `config.json`.
    pub fn prekey_dump(&self) -> Vec<PrekeyRecord> {
        self.prekey.dump()
    }
}

impl Keyring for IosKeyring {
    fn peers(&self) -> Result<Vec<PublicKey>> {
        Ok(self.peers.iter().map(|p| p.public.clone()).collect())
    }

    fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
        let prima = self.peers.len();
        self.peers.retain(|p| &p.public != peer);
        if self.peers.len() == prima {
            return Ok(false);
        }
        self.prekey.forget(peer);
        Ok(true)
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
        match self.peers.iter_mut().find(|record| &record.public == peer) {
            Some(record) => {
                record.label = Some(label.to_owned());
                Ok(LabelOutcome::Assigned)
            }
            None => Err(Error::UnknownPeer),
        }
    }

    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()> {
        let etichetta = self.find(old).and_then(|record| record.label.clone());
        self.peers.retain(|record| &record.public != old);
        self.peers.retain(|record| &record.public != new);
        self.peers.push(PeerRecord {
            public: new.clone(),
            label: etichetta,
            first_seen_unix: now_unix,
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

    fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(self.prekey.my_prekeys(peer))
    }

    fn my_epoch(&self, peer: &PublicKey) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(self.prekey.my_epoch(peer))
    }

    fn peer_epoch(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        Ok(self.prekey.peer_epoch(peer))
    }

    fn set_peer_epoch(&mut self, peer: &PublicKey, epoca: &PublicKey) -> Result<()> {
        self.prekey.set_peer_epoch(peer, epoca);
        Ok(())
    }

    fn seen_at(&self, peer: &PublicKey) -> Result<i64> {
        Ok(self.prekey.seen_at(peer))
    }

    fn set_seen_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
        self.prekey.set_seen_at(peer, quando);
        Ok(())
    }

    fn burned_at(&self, peer: &PublicKey) -> Result<i64> {
        Ok(self.prekey.burned_at(peer))
    }

    fn set_burned_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
        self.prekey.set_burned_at(peer, quando);
        Ok(())
    }

    fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) -> Result<()> {
        self.prekey.forget_my_prekey(peer, secret);
        Ok(())
    }

    fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.set_my_epoch(peer, secret);
        Ok(())
    }

    fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.push_my_prekey(peer, secret);
        Ok(())
    }

    fn drop_my_prekeys_older_than(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) -> Result<()> {
        self.prekey.drop_my_prekeys_older_than(peer, secret);
        Ok(())
    }

    fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()> {
        self.prekey.burn(peer);
        Ok(())
    }

    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        match self.peers.iter_mut().find(|record| &record.public == peer) {
            Some(record) => {
                record.verified = true;
                Ok(())
            }
            None => Err(Error::UnknownPeer),
        }
    }
}
