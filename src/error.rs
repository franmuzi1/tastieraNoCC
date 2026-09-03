//! Un solo error type pubblico per il crate. Nessun panic.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("formato non valido: {0}")]
    Format(&'static str),

    #[error("versione di protocollo non supportata: {0}")]
    UnsupportedVersion(u8),

    /// Il testo non e' un blob di questo sistema. Esito NORMALE, non un
    /// fallimento: la tastiera lo usa per decidere se offrire l'azione
    /// "decifra" su un testo qualsiasi preso dalla clipboard.
    #[error("sentinel non riconosciuto: il testo non e' un blob di questo sistema")]
    NotOurBlob,

    #[error("decodifica z-base-32 fallita")]
    Decode,

    /// Errore VOLUTAMENTE opaco. Non distinguere mai "tag non valido" da
    /// "chiave sbagliata" da "nonce corrotto" verso il chiamante: e' un canale
    /// che aiuta un attaccante. Un solo errore per ogni fallimento AEAD.
    /// Non aggiungere varianti piu' specifiche "per migliorare la diagnostica".
    #[error("decifratura/autenticazione fallita")]
    Crypto,

    /// Il messaggio dichiara un mittente che non e' nel keyring e l'operazione
    /// richiesta esigeva un peer gia' fissato.
    #[error("peer sconosciuto per questa operazione")]
    UnknownPeer,

    /// Es. arriva un messaggio di tier forte ma il supporto FS non e' compilato.
    #[error("tier non supportato dalla build corrente")]
    TierUnsupported,

    /// Il blob dichiara come mittente la NOSTRA chiave: e' un messaggio che
    /// abbiamo scritto noi, e solo il destinatario puo' aprirlo.
    ///
    /// **Non viola l'opacita' di [`Error::Crypto`]**, e la distinzione va fatta
    /// prima di tentare la decifratura, non dopo: si guarda un campo in chiaro
    /// dell'header, che chiunque legge comunque. Chi fabbricasse un blob con la
    /// nostra pubkey dentro non imparerebbe nulla che non ci abbia messo lui.
    ///
    /// Esiste perche' il caso capita davvero — si manda un messaggio e poi lo
    /// si ricopia — e presentarlo come fallimento crypto fa sembrare guasto
    /// cio' che e' il funzionamento previsto.
    #[error("questo messaggio l'hai scritto tu: puo' aprirlo solo il destinatario")]
    OwnMessage,

    /// Come [`Error::OwnMessage`], ma la causa e' un'altra e la differenza si
    /// vede tutta nell'avviso che l'utente legge.
    ///
    /// [`Error::OwnMessage`] nasce dove la riapertura passa dalle **identita'**
    /// — lo schema baseline, il bootstrap d'epoca, gli allegati — e li'
    /// fallire per tutti i contatti significa davvero una cosa sola: il
    /// destinatario non e' piu' nel keyring.
    ///
    /// Questa nasce invece dove la riapertura passa da una chiave **effimera
    /// del destinatario** — un messaggio a epoca non-bootstrap si riapre solo
    /// con la chiave d'epoca verso cui era stato sigillato. Quella chiave e'
    /// una sola per contatto e viene sovrascritta: se lui aveva la forward
    /// secrecy accesa, [`crate::api::Session`] aveva ripiegato sulla sua
    /// prechiave, che avanza a ogni messaggio che lui manda. Il contatto e'
    /// ancora li', la chiave di allora no.
    ///
    /// Ci arriva anche chi ha bruciato la conversazione, ed e' la stessa frase:
    /// la chiave verso cui il messaggio era cifrato non esiste piu'.
    ///
    /// **Perche' non e' una crepa nell'opacita' di [`Error::Crypto`].** La
    /// distinzione si fa su un campo in chiaro dell'header — «il mittente sono
    /// io» e «lo schema e' a epoca» — prima di qualunque tentativo di
    /// decifratura, e non dice niente sul perche' un AEAD abbia fallito.
    #[error("questo messaggio l'hai scritto tu, e la chiave verso cui era cifrato non c'e' piu'")]
    OwnMessageKeyGone,

    /// L'implementazione di [`crate::keys::Keyring`] sta fuori dal core (storage
    /// cifrato lato Android): i suoi fallimenti risalgono qui senza dettagli.
    #[error("errore del keyring")]
    Keyring,
}

pub type Result<T> = core::result::Result<T, Error>;
