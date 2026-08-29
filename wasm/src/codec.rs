//! Layout binario dei dati che attraversano il confine wasm/JS — la parte
//! "cosa significano i byte", sopra le primitive di [`crate::marshal`].
//!
//! Ogni intero multi-byte e' little-endian. Nessun tipo qui dentro implementa
//! `Serialize` (il core non ha `serde`, per scelta — vedi CLAUDE.md), quindi
//! la codifica e' scritta a mano una volta sola qui, con un lettore/scrittore
//! che non indicizza mai direttamente uno slice (`clippy::indexing_slicing`
//! e' `deny` in questo crate, come nel core).

use keyboard_cipher_core::baseline::Plaintext;
use keyboard_cipher_core::keys::{Fingerprint, LabelOutcome, PeerRecord, PinOutcome, PrekeyRecord, PublicKey};
use zeroize::Zeroizing;

/// Lettore che non va mai in panic su un input troncato: ogni metodo ritorna
/// `None` invece di indicizzare oltre la fine.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|s| s.first().copied())
    }

    pub fn u16_le(&mut self) -> Option<u16> {
        let arr: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_le_bytes(arr))
    }

    pub fn i64_le(&mut self) -> Option<i64> {
        let arr: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(i64::from_le_bytes(arr))
    }

    pub fn key32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    pub fn str_u16(&mut self) -> Option<&'a str> {
        let len = self.u16_le()? as usize;
        let raw = self.take(len)?;
        std::str::from_utf8(raw).ok()
    }
}

/// Scrittore append-only: nessuna operazione qui puo' fallire o andare in
/// overflow, quindi non ritorna `Result`.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16_le(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32_le(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64_le(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Stringa preceduta da lunghezza `u16`. Usata solo per stringhe che il
    /// core stesso produce (etichette sotto 256 byte, fingerprint fissi a 29
    /// caratteri ASCII): mai per input arbitrario non validato altrove.
    pub fn str_u16(&mut self, s: &str) -> &mut Self {
        let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
        // Se mai capitasse una stringa piu' lunga di 65535 byte (non dovrebbe:
        // le etichette sono limitate a 256 in `assign_label`), si tronca sul
        // confine di lunghezza dichiarato invece di scrivere byte che la
        // lunghezza premessa non copre.
        let cut = s.as_bytes().get(..len as usize).unwrap_or(s.as_bytes());
        self.u16_le(u16::try_from(cut.len()).unwrap_or(0));
        self.bytes(cut);
        self
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

pub fn encode_peer_record(r: &PeerRecord) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(r.public.as_bytes());
    w.i64_le(r.first_seen_unix);
    w.u8(u8::from(r.verified));
    match &r.label {
        Some(label) => {
            w.str_u16(label);
        }
        None => {
            w.u16_le(0);
        }
    }
    w.into_vec()
}

pub fn decode_peer_record(buf: &[u8]) -> Option<PeerRecord> {
    let mut r = Reader::new(buf);
    let public = PublicKey::from_bytes(r.key32()?);
    let first_seen_unix = r.i64_le()?;
    let verified = r.u8()? != 0;
    // Lunghezza zero e "nessuna etichetta" coincidono: `assign_label` rifiuta
    // le etichette vuote, quindi una stringa vuota qui non e' mai stata scelta
    // da un utente — puo' solo significare `None`.
    let label = match r.str_u16()? {
        "" => None,
        s => Some(s.to_owned()),
    };
    Some(PeerRecord {
        public,
        label,
        first_seen_unix,
        verified,
    })
}

/// `mie` come `mie_count(1) | (32 byte)*mie_count` — `MAX_PREKEY_MIE` e' 32,
/// quindi un solo byte per il conteggio basta e avanza.
pub fn encode_prekey_record(r: &PrekeyRecord) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(r.peer.as_bytes());

    match &r.sua_prekey {
        Some(k) => {
            w.u8(1).bytes(k.as_bytes());
        }
        None => {
            w.u8(0);
        }
    }

    let count = u8::try_from(r.mie.len()).unwrap_or(u8::MAX);
    w.u8(count);
    for secret in r.mie.iter().take(count as usize) {
        w.bytes(secret.as_slice());
    }

    match &r.mia_epoca {
        Some(k) => {
            w.u8(1).bytes(k.as_slice());
        }
        None => {
            w.u8(0);
        }
    }

    match &r.sua_epoca {
        Some(k) => {
            w.u8(1).bytes(k.as_bytes());
        }
        None => {
            w.u8(0);
        }
    }

    w.i64_le(r.visto_a);
    w.i64_le(r.rogo_a);
    w.into_vec()
}

pub fn decode_prekey_record(buf: &[u8]) -> Option<PrekeyRecord> {
    let mut r = Reader::new(buf);
    let peer = PublicKey::from_bytes(r.key32()?);

    let has_sua_prekey = r.u8()?;
    let sua_prekey = if has_sua_prekey == 1 {
        Some(PublicKey::from_bytes(r.key32()?))
    } else {
        None
    };

    let count = r.u8()?;
    let mut mie = Vec::with_capacity(count as usize);
    for _ in 0..count {
        mie.push(Zeroizing::new(r.key32()?));
    }

    let has_mia_epoca = r.u8()?;
    let mia_epoca = if has_mia_epoca == 1 {
        Some(Zeroizing::new(r.key32()?))
    } else {
        None
    };

    let has_sua_epoca = r.u8()?;
    let sua_epoca = if has_sua_epoca == 1 {
        Some(PublicKey::from_bytes(r.key32()?))
    } else {
        None
    };

    let visto_a = r.i64_le()?;
    let rogo_a = r.i64_le()?;

    Some(PrekeyRecord {
        peer,
        sua_prekey,
        mie,
        mia_epoca,
        sua_epoca,
        visto_a,
        rogo_a,
    })
}

fn write_plaintext(w: &mut Writer, p: &Plaintext) {
    w.i64_le(p.sent_at_unix());
    let bytes = p.as_bytes();
    w.u32_le(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    w.bytes(bytes);
}

/// Tag di `IncomingItem`, condiviso col lato JS (deve restare in questo
/// ordine, e' parte del protocollo).
pub const TAG_MESSAGE: u8 = 0;
pub const TAG_OWN_MESSAGE: u8 = 1;
pub const TAG_BURNED: u8 = 2;
pub const TAG_OWN_IDENTITY_CARD: u8 = 3;
pub const TAG_IDENTITY_CARD: u8 = 4;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus};

pub fn encode_incoming_item(item: &IncomingItem) -> Vec<u8> {
    let mut w = Writer::new();
    match item {
        IncomingItem::Message(msg) => {
            w.u8(TAG_MESSAGE);
            w.bytes(msg.sender.as_bytes());
            match &msg.sender_status {
                SenderStatus::New => {
                    w.u8(0);
                }
                SenderStatus::Known { label, verified } => {
                    w.u8(1);
                    w.u8(u8::from(*verified));
                    match label {
                        Some(l) => {
                            w.str_u16(l);
                        }
                        None => {
                            w.u16_le(0);
                        }
                    }
                }
            }
            w.u8(u8::from(msg.gruppo));
            w.u32_le(u32::try_from(msg.destinatari).unwrap_or(u32::MAX));
            write_plaintext(&mut w, &msg.plaintext);
        }
        IncomingItem::OwnMessage {
            recipient,
            recipient_label,
            plaintext,
        } => {
            w.u8(TAG_OWN_MESSAGE);
            w.bytes(recipient.as_bytes());
            match recipient_label {
                Some(l) => {
                    w.str_u16(l);
                }
                None => {
                    w.u16_le(0);
                }
            }
            write_plaintext(&mut w, plaintext);
        }
        IncomingItem::Burned { peer, sent_at_unix } => {
            w.u8(TAG_BURNED);
            w.bytes(peer.as_bytes());
            w.i64_le(*sent_at_unix);
        }
        IncomingItem::OwnIdentityCard { fingerprint } => {
            w.u8(TAG_OWN_IDENTITY_CARD);
            w.str_u16(&fingerprint.display());
        }
        IncomingItem::IdentityCard {
            peer,
            fingerprint,
            outcome,
        } => {
            w.u8(TAG_IDENTITY_CARD);
            w.bytes(peer.as_bytes());
            w.str_u16(&fingerprint.display());
            w.u8(match outcome {
                PinOutcome::Pinned => 0,
                PinOutcome::AlreadyPinned => 1,
            });
        }
    }
    w.into_vec()
}

pub fn encode_label_outcome(outcome: &LabelOutcome) -> Vec<u8> {
    let mut w = Writer::new();
    match outcome {
        LabelOutcome::Assigned => {
            w.u8(0);
        }
        LabelOutcome::Conflict {
            existing,
            existing_fingerprint,
            incoming_fingerprint,
        } => {
            w.u8(1);
            w.bytes(existing.as_bytes());
            w.str_u16(&existing_fingerprint.display());
            w.str_u16(&incoming_fingerprint.display());
        }
    }
    w.into_vec()
}

pub fn encode_fingerprint(fp: &Fingerprint) -> Vec<u8> {
    fp.display().into_bytes()
}
