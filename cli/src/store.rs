//! Stato su disco: identita' e keyring.
//!
//! ## Il formato e' solo suo
//!
//! Non combacia con quello del telefono, e non deve. Questo binario e' una
//! **parte diversa**: ha una sua identita', un suo elenco di contatti, e con
//! l'Android scambia solo blob `kc/…`. I due file di stato non si incontrano
//! mai, quindi allinearli sarebbe lavoro per una compatibilita' che nessuno
//! usera' — e due implementazioni dello stesso formato sono due fonti di
//! verita', che questo progetto evita ovunque.
//!
//! ## Il segreto sta in chiaro
//!
//! Sul telefono la chiave privata e' avvolta da Android Keystore. Qui non c'e'
//! niente di equivalente: il file e' protetto dai soli permessi Unix (`0600`).
//!
//! E' una scelta, non una dimenticanza: e' uno strumento per provare, e
//! l'alternativa — chiedere una passphrase a ogni comando — renderebbe scomodo
//! proprio l'uso per cui esiste. La conseguenza va detta e sta anche nel
//! `--help`: **questa identita' non vale quanto quella del telefono.** Non
//! usarla per conversazioni vere.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use keyboard_cipher_core::encoding;
use keyboard_cipher_core::keys::{
    Fingerprint, Identity, Keyring, LabelOutcome, PeerRecord, PinOutcome, PrekeyStore, PublicKey,
    KEY_LEN,
};
use keyboard_cipher_core::{Error, Result};
use zeroize::Zeroizing;

const MAGIC: &str = "keyboard-cipher-cli 1";

/// Dove vive lo stato. `KC_HOME` ha la precedenza, cosi' si possono tenere piu'
/// identita' affiancate — che e' esattamente cio' che serve per provare un
/// conflitto di chiave senza cancellare la propria.
pub fn state_path() -> PathBuf {
    if let Ok(dir) = std::env::var("KC_HOME") {
        return PathBuf::from(dir).join("state");
    }
    // Windows non ha XDG ne' HOME: senza questo il file finirebbe nella
    // directory corrente, cioe' in un posto diverso a seconda di da dove si
    // avvia il programma — e l'identita' sembrerebbe sparita.
    if let Ok(dir) = std::env::var("APPDATA") {
        return PathBuf::from(dir).join("keyboard-cipher").join("state");
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_owned()))
                .join(".local")
                .join("share")
        });
    base.join("keyboard-cipher").join("state")
}

/// Keyring concreto: un elenco in memoria, salvato dal chiamante.
///
/// L'ordine dei record e' quello di inserimento e non va riordinato: i comandi
/// accettano l'indice mostrato da `kc contacts`, e un elenco che si riordina da
/// solo farebbe applicare a un contatto un'operazione pensata per un altro.
#[derive(Default)]
pub struct FileKeyring {
    peers: Vec<PeerRecord>,
    /// La catena di forward secrecy. La logica sta nel core: qui c'e' solo il
    /// giro su disco, che e' l'unica parte che riguarda questo binario.
    pub(crate) prekey: PrekeyStore,
}

impl FileKeyring {
    pub fn peers(&self) -> &[PeerRecord] {
        &self.peers
    }

    fn position(&self, peer: &PublicKey) -> Option<usize> {
        self.peers.iter().position(|p| &p.public == peer)
    }

    /// Vedi [`Keyring::forget`]. Resta anche come metodo proprio perche' la
    /// app la usa senza costruire una `Session`.
    ///
    /// Non passa dal trait `Keyring` del core, che non prevede la
    /// cancellazione, e non e' una dimenticanza del core: dal lato tastiera
    /// dimenticare una chiave non serve a niente e puo' fare danno. Qui invece
    /// e' una schermata con un elenco, e un elenco che si puo' solo allungare
    /// diventa inservibile.
    ///
    /// **Conseguenza da dire a chi lo fa:** si perde il pin. Il prossimo
    /// messaggio da quella persona ricompare come mittente mai visto e viene
    /// rifissato in silenzio — cioe' si riapre la finestra di attacco che il
    /// pin serviva a chiudere, e si perde anche l'eventuale "confrontato di
    /// persona". Cancellare un contatto non e' come cancellare una riga da una
    /// rubrica.
    pub fn remove(&mut self, peer: &PublicKey) -> bool {
        match self.position(peer) {
            Some(indice) => {
                self.peers.remove(indice);
                // Anche le chiavi temporanee verso di lui: restare su disco
                // dopo che l'utente ha cancellato il contatto sarebbe il
                // contrario di quello che ha chiesto.
                self.prekey.forget(peer);
                true
            }
            None => false,
        }
    }
}

impl Keyring for FileKeyring {
    fn my_epoch(&self, peer: &PublicKey) -> Result<Option<[u8; KEY_LEN]>> {
        Ok(self.prekey.my_epoch(peer))
    }

    fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.set_my_epoch(peer, secret);
        Ok(())
    }

    fn peers(&self) -> Result<Vec<PublicKey>> {
        Ok(self.peers.iter().map(|p| p.public.clone()).collect())
    }

    fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
        Ok(self.remove(peer))
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

    fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()> {
        self.prekey.burn(peer);
        Ok(())
    }

    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
        if self.position(peer).is_some() {
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
        // Il conflitto si cerca PRIMA di toccare qualunque cosa: su conflitto
        // non si modifica nulla, la vecchia chiave tiene il nome finche' non
        // arriva una conferma esplicita.
        if let Some(other) = self
            .peers
            .iter()
            .find(|p| p.label.as_deref() == Some(label) && &p.public != peer)
        {
            return Ok(LabelOutcome::Conflict {
                existing: other.public.clone(),
                existing_fingerprint: Fingerprint::of(&other.public),
                incoming_fingerprint: Fingerprint::of(peer),
            });
        }
        let index = self.position(peer).ok_or(Error::UnknownPeer)?;
        match self.peers.get_mut(index) {
            Some(record) => {
                record.label = Some(label.to_owned());
                Ok(LabelOutcome::Assigned)
            }
            None => Err(Error::Keyring),
        }
    }

    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()> {
        let old_index = self.position(old).ok_or(Error::UnknownPeer)?;
        let label = match self.peers.get(old_index) {
            Some(record) => record.label.clone(),
            None => return Err(Error::Keyring),
        };
        if let Some(record) = self.peers.get_mut(old_index) {
            record.label = None;
        }
        match self.position(new) {
            Some(index) => {
                if let Some(record) = self.peers.get_mut(index) {
                    record.label = label;
                    // Una chiave nuova non e' stata confrontata fuori banda,
                    // per definizione.
                    record.verified = false;
                }
            }
            None => self.peers.push(PeerRecord {
                public: new.clone(),
                label,
                first_seen_unix: now_unix,
                verified: false,
            }),
        }
        Ok(())
    }

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>> {
        Ok(self.position(peer).and_then(|i| self.peers.get(i)).cloned())
    }

    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        let index = self.position(peer).ok_or(Error::UnknownPeer)?;
        match self.peers.get_mut(index) {
            Some(record) => {
                record.verified = true;
                Ok(())
            }
            None => Err(Error::Keyring),
        }
    }
}

/// Tutto lo stato: chi sono io, e chi conosco.
///
/// Il segreto resta accanto all'identita' perche' `Identity` non lo restituisce
/// — ed e' giusto cosi': una chiave privata che si puo' rileggere da chiunque
/// abbia l'oggetto e' una chiave che finisce in un log. Qui serve solo per
/// riscriverlo su disco, e per quello basta averlo tenuto da parte.
pub struct State {
    pub identity: Identity,
    pub keyring: FileKeyring,
    secret: Zeroizing<[u8; KEY_LEN]>,
}

impl State {
    /// Copia dei byte del segreto, da conservare prima che [`Identity`] finisca
    /// dentro una `Session` — che ne prende possesso.
    pub fn secret_bytes(&self) -> [u8; KEY_LEN] {
        *self.secret
    }

    pub fn create(secret: [u8; KEY_LEN]) -> Result<Self> {
        Ok(Self {
            identity: Identity::from_secret_bytes(secret)?,
            keyring: FileKeyring::default(),
            secret: Zeroizing::new(secret),
        })
    }

    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(parse(&text))
    }

}

/// Scrive identita' e contatti.
///
/// Funzione libera e non metodo: dopo un'operazione l'identita' e il keyring
/// vivono dentro una `Session`, che se ne e' presa possesso, quindi non esiste
/// piu' uno `State` da cui chiamare un metodo. I due pezzi si passano
/// separatamente perche' e' cosi' che si trovano in quel momento.
pub fn save(path: &Path, secret: &[u8; KEY_LEN], keyring: &FileKeyring) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::from(MAGIC);
    out.push('\n');
    out.push_str("secret ");
    out.push_str(&encoding::encode(secret));
    out.push('\n');
    for peer in keyring.peers() {
        out.push_str("peer ");
        out.push_str(&encoding::encode(peer.public.as_bytes()));
        out.push(' ');
        out.push_str(&peer.first_seen_unix.to_string());
        out.push(' ');
        out.push(if peer.verified { '1' } else { '0' });
        out.push(' ');
        out.push_str(peer.label.as_deref().unwrap_or(""));
        out.push('\n');
    }
    // Le righe `chain` stanno DOPO le `peer` e non dentro: un binario piu'
    // vecchio le ignora (il parser scarta le righe che non conosce) e continua
    // a funzionare senza forward secrecy piena, invece di rifiutare il file e
    // far sparire l'identita'.
    //
    // Qui c'e' materiale privato in chiaro, come il segreto d'identita' due
    // righe sopra: stesso file, stessi permessi, stessa avvertenza.
    for (chi, loro, mie, epoca) in keyring.prekey.dump() {
        // Riga a parte e non una colonna in coda a `chain`: un lettore vecchio
        // scarta le righe che non conosce, mentre una colonna in piu' su una
        // riga nota la leggerebbe come una prekey — cioe' userebbe l'epoca come
        // chiave della catena e la butterebbe alla prima lettura. Il difetto
        // che questa riga esiste per riparare, reintrodotto dal formato.
        if let Some(k) = epoca {
            out.push_str("epoch ");
            out.push_str(&encoding::encode(chi.as_bytes()));
            out.push(' ');
            out.push_str(&encoding::encode(&k));
            out.push('\n');
        }
        out.push_str("chain ");
        out.push_str(&encoding::encode(chi.as_bytes()));
        out.push(' ');
        out.push_str(&match loro {
            Some(k) => encoding::encode(k.as_bytes()),
            // Un contatto a cui abbiamo scritto per primi non ha ancora una
            // loro chiave: il trattino tiene la posizione della colonna.
            None => "-".to_owned(),
        });
        for segreto in mie.iter() {
            out.push(' ');
            out.push_str(&encoding::encode(segreto));
        }
        out.push('\n');
    }
    // Scrittura atomica: un file di stato troncato a meta' e' un'identita'
    // persa, e qui non c'e' nessun backup dietro.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, out)?;
    restrict(&tmp)?;
    fs::rename(&tmp, path)?;
    restrict(path)
}

/// Solo il proprietario. Contiene una chiave privata in chiaro.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Un file illeggibile diventa `None`, cioe' "non c'e' nessuna identita'".
///
/// Sembra permissivo e non lo e': chi chiama non rigenera mai da solo. Vedi la
/// nota in `main`, ed e' la stessa regola del lato Android — un guasto locale
/// non deve diventare indistinguibile da un attacco.
fn chiave(testo: &str) -> Option<PublicKey> {
    let bytes = encoding::decode(testo).ok()?;
    let bytes: [u8; KEY_LEN] = bytes.as_slice().try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

fn segreto_da(testo: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = encoding::decode(testo).ok()?;
    bytes.as_slice().try_into().ok()
}

fn parse(text: &str) -> Option<State> {
    let mut lines = text.lines();
    if lines.next()? != MAGIC {
        return None;
    }
    let mut secret: Option<[u8; KEY_LEN]> = None;
    let mut keyring = FileKeyring::default();
    for line in lines {
        let mut parts = line.splitn(2, ' ');
        match (parts.next(), parts.next()) {
            (Some("secret"), Some(rest)) => {
                let bytes = encoding::decode(rest.trim()).ok()?;
                secret = Some(bytes.as_slice().try_into().ok()?);
            }
            (Some("peer"), Some(rest)) => {
                let mut fields = rest.splitn(4, ' ');
                let public = encoding::decode(fields.next()?).ok()?;
                let public: [u8; KEY_LEN] = public.as_slice().try_into().ok()?;
                let first_seen_unix = fields.next()?.parse().ok()?;
                let verified = fields.next()? == "1";
                let label = fields.next().unwrap_or("").trim();
                keyring.peers.push(PeerRecord {
                    public: PublicKey::from_bytes(public),
                    label: if label.is_empty() {
                        None
                    } else {
                        Some(label.to_owned())
                    },
                    first_seen_unix,
                    verified,
                });
            }
            // Una riga rotta qui costa la catena di quel contatto, non
            // l'identita': niente `?`, che uscirebbe da `parse` con `None` e
            // farebbe sparire tutto. Il peggio che succede e' che il prossimo
            // messaggio verso quella persona riparta a meta' forward secrecy,
            // che e' esattamente il caso del primo contatto.
            (Some("chain"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let Some(chi) = campi.next().and_then(chiave) {
                    let loro = match campi.next() {
                        Some("-") | None => None,
                        Some(testo) => chiave(testo),
                    };
                    let mie = campi.filter_map(segreto_da).collect();
                    // L'epoca arriva dalla sua riga, che puo' venire prima o
                    // dopo questa: qui non si tocca.
                    keyring.prekey.restore(&chi, loro, mie, None);
                }
            }
            // Riga introdotta quando l'epoca ha smesso di vivere dentro la
            // catena. Uno stato scritto prima non ce l'ha, e riparte senza:
            // il ripiego nel core la ritrova fra le prekey vecchie.
            (Some("epoch"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let (Some(chi), Some(k)) = (
                    campi.next().and_then(chiave),
                    campi.next().and_then(segreto_da),
                ) {
                    keyring.prekey.set_my_epoch(&chi, k);
                }
            }
            _ => {}
        }
    }
    let secret = secret?;
    Some(State {
        identity: Identity::from_secret_bytes(secret).ok()?,
        keyring,
        secret: Zeroizing::new(secret),
    })
}

#[cfg(test)]
// I divieti valgono per il codice di produzione: in un test un panic e'
// il modo in cui si segnala il fallimento.
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn secret() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    fn peer(n: u8) -> PublicKey {
        PublicKey::from_bytes([n; KEY_LEN])
    }

    #[test]
    fn round_trip_con_contatti() {
        let dir = std::env::temp_dir().join(format!("kc-test-{}", std::process::id()));
        let path = dir.join("state");
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 111).unwrap();
        keyring.tofu_pin(&peer(2), 222).unwrap();
        keyring.assign_label(&peer(1), "nome con spazi").unwrap();
        keyring.mark_verified(&peer(2)).unwrap();

        save(&path, &secret(), &keyring).unwrap();
        let loaded = State::load(&path).unwrap().unwrap();

        assert_eq!(loaded.secret_bytes(), secret());
        let peers = loaded.keyring.peers();
        assert_eq!(peers.len(), 2);
        // L'etichetta puo' contenere spazi: e' l'ultimo campo della riga
        // apposta, e un formato che la spezzasse rinominerebbe i contatti.
        assert_eq!(peers[0].label.as_deref(), Some("nome con spazi"));
        assert_eq!(peers[0].first_seen_unix, 111);
        assert!(!peers[0].verified);
        assert_eq!(peers[1].label, None);
        assert!(peers[1].verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un riavvio non deve uccidere i messaggi gia' in viaggio: le chiavi
    /// temporanee devono sopravvivere al giro su disco, **nel loro ordine**.
    #[test]
    fn la_catena_sopravvive_al_riavvio() {
        let dir = std::env::temp_dir().join(format!("kc-chain-{}", std::process::id()));
        let path = dir.join("state");
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 111).unwrap();
        keyring.tofu_pin(&peer(2), 222).unwrap();
        keyring.set_peer_prekey(&peer(1), &peer(50)).unwrap();
        keyring.push_my_prekey(&peer(1), [10; KEY_LEN]).unwrap();
        keyring.push_my_prekey(&peer(1), [11; KEY_LEN]).unwrap();
        // Contatto a cui abbiamo scritto per primi: nessuna chiave sua.
        keyring.push_my_prekey(&peer(2), [20; KEY_LEN]).unwrap();

        save(&path, &secret(), &keyring).unwrap();
        let loaded = State::load(&path).unwrap().unwrap();

        assert_eq!(loaded.keyring.peer_prekey(&peer(1)).unwrap(), Some(peer(50)));
        assert_eq!(
            loaded.keyring.my_prekeys(&peer(1)).unwrap(),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(loaded.keyring.peer_prekey(&peer(2)).unwrap(), None);
        assert_eq!(
            loaded.keyring.my_prekeys(&peer(2)).unwrap(),
            vec![[20; KEY_LEN]]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Una riga `chain` illeggibile costa la catena di quel contatto, non
    /// l'identita': il file resta caricabile.
    #[test]
    fn una_catena_corrotta_non_fa_sparire_l_identita() {
        let testo = format!(
            "{MAGIC}\nsecret {}\nchain ??? -\n",
            encoding::encode(&secret())
        );
        let stato = parse(&testo).unwrap();
        assert_eq!(stato.secret_bytes(), secret());
    }

    #[test]
    fn file_estraneo_non_e_uno_stato() {
        assert!(parse("tutt'altro\nsecret aaaa\n").is_none());
    }

    /// Senza segreto non c'e' identita', e mezzo stato e' peggio di nessuno:
    /// caricarlo darebbe un keyring valido attaccato a una chiave che non c'e'.
    #[test]
    fn stato_senza_segreto_non_si_carica() {
        assert!(parse(&format!("{MAGIC}\npeer ybnd 1 0 tizio\n")).is_none());
    }

    #[test]
    fn dimenticare_un_contatto_lo_toglie_e_lascia_gli_altri() {
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 1).unwrap();
        keyring.tofu_pin(&peer(2), 2).unwrap();
        keyring.assign_label(&peer(2), "marco").unwrap();

        assert!(keyring.remove(&peer(1)));
        // Due volte non e' un errore: la seconda dice solo che non c'era.
        assert!(!keyring.remove(&peer(1)));
        assert_eq!(keyring.peers().len(), 1);
        assert_eq!(keyring.peers()[0].label.as_deref(), Some("marco"));
    }

    #[test]
    fn etichetta_gia_in_uso_e_un_conflitto_e_non_cambia_niente() {
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 1).unwrap();
        keyring.tofu_pin(&peer(2), 2).unwrap();
        keyring.assign_label(&peer(1), "marco").unwrap();

        match keyring.assign_label(&peer(2), "marco").unwrap() {
            LabelOutcome::Conflict { existing, .. } => assert_eq!(existing, peer(1)),
            LabelOutcome::Assigned => panic!("doveva essere un conflitto"),
        }
        // Il punto del conflitto: la vecchia chiave tiene il nome.
        assert_eq!(keyring.peers()[0].label.as_deref(), Some("marco"));
        assert_eq!(keyring.peers()[1].label, None);
    }
}
