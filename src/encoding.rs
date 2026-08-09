//! z-base-32 (Zooko): encoding di superficie.
//!
//! Scelto perche' sopravvive all'autocorrect delle tastiere e alla lettura
//! umana: solo minuscole, niente punteggiatura, niente caratteri
//! visivamente ambigui.
//!
//! La specifica originale e' orientata ai BIT e sa codificare quantita'
//! sub-ottetto. Qui serve solo il caso allineato ai byte, quindi l'API prende
//! e restituisce byte interi: l'ultimo carattere porta bit di riempimento a
//! zero, e in decodifica quei bit devono essere zero (vedi [`decode`]).

use crate::error::{Error, Result};

/// Alfabeto z-base-32. L'ordine NON e' quello di base32 RFC 4648: i simboli
/// piu' leggibili occupano le posizioni piu' frequenti. Non riordinare.
pub const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Sentinella per "carattere non nell'alfabeto" nella tabella inversa.
const INVALID: u8 = 0xFF;

/// Tabella di decodifica, costruita dall'alfabeto a compile time cosi' le due
/// direzioni non possono divergere.
// `i` e' limitato a 0..32 dalla condizione del while e ALPHABET ha 32
// elementi; l'indice in `table` e' un u8 promosso, e `table` ne ha 256. Nessuna
// delle due indicizzazioni puo' uscire dai limiti, e la valutazione avviene a
// compile time: un errore qui non compilerebbe, non andrebbe in panic a runtime.
#[allow(clippy::indexing_slicing)]
const DECODE_TABLE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0usize;
    while i < 32 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Lunghezza in caratteri dell'encoding di `bytes` byte: `ceil(bytes * 8 / 5)`.
///
/// Satura invece di andare in overflow: un input cosi' grande non e'
/// rappresentabile in memoria, ma la funzione resta totale.
const fn encoded_len(bytes: usize) -> usize {
    match bytes.checked_mul(8) {
        Some(bits) => match bits.checked_add(4) {
            Some(padded) => padded / 5,
            None => usize::MAX,
        },
        None => usize::MAX,
    }
}

/// Una stringa di `n` caratteri e' una codifica valida di byte interi solo se
/// `n` e' esattamente la lunghezza prodotta da qualche numero di byte.
///
/// Serve a rifiutare le stringhe con un carattere finale che non porta dati:
/// 3 caratteri, per esempio, codificherebbero 1 byte piu' 7 bit di nulla, e 1
/// byte si scrive con 2 caratteri. Senza questo controllo esisterebbero piu'
/// stringhe distinte che decodificano allo stesso blob.
const fn is_canonical_len(n: usize) -> bool {
    match n.checked_mul(5) {
        Some(bits) => encoded_len(bits / 8) == n,
        None => false,
    }
}

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(bytes.len()));
    // Accumulatore MSB-first. Contiene al massimo 4 bit residui + 8 nuovi = 12,
    // quindi u16 basta e lo shift non perde mai bit.
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;

    for &byte in bytes {
        acc = (acc << 8) | u16::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol((acc >> bits) as u8));
        }
    }
    if bits > 0 {
        // Bit di riempimento a zero in coda.
        out.push(symbol((acc << (5u8.saturating_sub(bits))) as u8));
    }
    out
}

/// Decodifica stretta: un solo encoding valido per ogni input.
///
/// Rifiuta, tutti con [`Error::Decode`]:
///   - caratteri fuori alfabeto, maiuscole comprese;
///   - lunghezze che non possono venire da byte interi;
///   - bit di riempimento finali non nulli.
///
/// La strettezza non e' pedanteria: senza, lo stesso blob avrebbe piu'
/// rappresentazioni testuali distinte, e due messaggi identici potrebbero non
/// risultare uguali a un confronto per stringa.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let raw = s.as_bytes();
    if !is_canonical_len(raw.len()) {
        return Err(Error::Decode);
    }

    let mut out = Vec::with_capacity(raw.len().saturating_mul(5) / 8);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;

    for &c in raw {
        let value = value_of(c)?;
        acc = (acc << 5) | u16::from(value);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push((acc >> bits) as u8);
        }
    }

    // I bit residui sono riempimento e devono essere zero.
    let residual_mask = (1u16 << bits).saturating_sub(1);
    if acc & residual_mask != 0 {
        return Err(Error::Decode);
    }
    Ok(out)
}

/// Simbolo per un valore a 5 bit.
fn symbol(value: u8) -> char {
    let index = usize::from(value & 0x1F);
    // `index` e' < 32 per la maschera e ALPHABET ha esattamente 32 elementi:
    // l'indicizzazione non puo' uscire dai limiti.
    #[allow(clippy::indexing_slicing)]
    char::from(ALPHABET[index])
}

/// Il byte appartiene all'alfabeto z-base-32?
///
/// Serve a chi deve isolare un blob dentro testo arbitrario: l'alfabeto e'
/// tutto ASCII, quindi fermarsi al primo byte estraneo cade sempre su un
/// confine di carattere valido.
pub fn is_alphabet_byte(b: u8) -> bool {
    value_of(b).is_ok()
}

/// Valore a 5 bit di un carattere, o [`Error::Decode`] se fuori alfabeto.
fn value_of(c: u8) -> Result<u8> {
    // `c` e' un u8 e DECODE_TABLE ha 256 elementi: sempre in range.
    #[allow(clippy::indexing_slicing)]
    let value = DECODE_TABLE[usize::from(c)];
    if value == INVALID {
        Err(Error::Decode)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
// Nei test `unwrap` e' il comportamento voluto: un `Err` inatteso deve far
// fallire il test rumorosamente. Il divieto vale per il codice di produzione.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// L'alfabeto e' copiato dalla specifica. Se questo test cambia, e'
    /// cambiato il formato sul filo, non il codice.
    #[test]
    fn alfabeto_della_specifica() {
        assert_eq!(ALPHABET, b"ybndrfg8ejkmcpqxot1uwisza345h769");
    }

    /// Vettori presi dalla tabella EXAMPLES della specifica z-base-32.
    ///
    /// La tabella ha dieci righe ma solo queste due sono allineate ai byte
    /// (24 bit = 3 byte); le altre codificano quantita' sub-ottetto (1, 2, 10,
    /// 20, 30 bit) che questa API non esprime.
    ///
    /// La riga a 30 bit e' inoltre difettosa nella specifica stessa: la sua
    /// colonna base32 ha 7 caratteri dove 30 bit ne richiedono 6, e la sua
    /// z-base-32 ("6im5sd") non corrisponde alla propria colonna base-2, che
    /// da' "6im54d". Non e' utilizzabile come vettore in nessuna forma.
    #[test]
    fn vettori_della_specifica() {
        // 24 bit: 111100001011111111000111
        assert_eq!(encode(&[0xF0, 0xBF, 0xC7]), "6n9hq");
        assert_eq!(decode("6n9hq").unwrap(), vec![0xF0, 0xBF, 0xC7]);

        // 24 bit: 110101000111101000000100
        assert_eq!(encode(&[0xD4, 0x7A, 0x04]), "4t7ye");
        assert_eq!(decode("4t7ye").unwrap(), vec![0xD4, 0x7A, 0x04]);
    }

    #[test]
    fn vuoto() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trip_ogni_lunghezza() {
        for len in 0..=64usize {
            let input: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(37) ^ 0xA5) as u8).collect();
            let encoded = encode(&input);
            assert_eq!(encoded.len(), encoded_len(len), "lunghezza attesa, len={len}");
            assert_eq!(decode(&encoded).unwrap(), input, "round-trip, len={len}");
        }
    }

    /// Differential testing contro un'implementazione indipendente, per tutte
    /// le lunghezze che la specifica non copre. Non e' un'autorita' come i
    /// vettori, ma e' l'unica verifica onesta disponibile: confrontarsi con la
    /// propria implementazione non dimostrerebbe niente.
    #[test]
    fn concorde_con_implementazione_indipendente() {
        for len in 0..=64usize {
            let input: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(101) ^ 0x3C) as u8).collect();
            let nostro = encode(&input);
            let loro = zbase32::encode_full_bytes(&input);
            assert_eq!(nostro, loro, "encode diverge, len={len}");
            // Anche la direzione inversa: decodifichiamo l'output altrui, non
            // solo il nostro. Il round-trip su se stessi non escluderebbe due
            // errori simmetrici.
            assert_eq!(decode(&loro).unwrap(), input, "decode diverge, len={len}");
        }
    }

    #[test]
    fn rifiuta_maiuscole() {
        // "6N9HQ" e' la stessa cosa a occhio umano ma non e' canonica.
        assert!(matches!(decode("6N9HQ"), Err(Error::Decode)));
    }

    #[test]
    fn rifiuta_caratteri_fuori_alfabeto() {
        // 'l', 'v', '0', '2' sono esclusi dall'alfabeto proprio perche'
        // confondibili con '1', 'u', 'o', 'z'.
        for bad in ["6n9hl", "6n9hv", "6n9h0", "6n9h2", "6n9h ", "6n9h/"] {
            assert!(matches!(decode(bad), Err(Error::Decode)), "accettato: {bad}");
        }
    }

    #[test]
    fn rifiuta_lunghezze_non_canoniche() {
        // 1 e 3 caratteri non possono venire da byte interi: 1 byte -> 2
        // caratteri, 2 byte -> 4.
        for bad in ["y", "yyy", "yyyyyy", "yyyyyyyyy"] {
            assert!(matches!(decode(bad), Err(Error::Decode)), "accettato: {bad}");
        }
    }

    #[test]
    fn rifiuta_bit_di_riempimento_non_nulli() {
        // [0x00] -> "yy": due caratteri, 10 bit, di cui 2 di riempimento.
        assert_eq!(encode(&[0x00]), "yy");
        // 'b' = 1: accende un bit di riempimento. Decodificherebbe allo stesso
        // byte 0x00, ed e' esattamente la malleabilita' che va esclusa.
        assert!(matches!(decode("yb"), Err(Error::Decode)));
        assert_eq!(decode("yy").unwrap(), vec![0x00]);
    }

    /// Canonicita' dimostrata per esaurimento, non per campioni.
    ///
    /// Per ogni stringa possibile sull'alfabeto di lunghezza 2 e 4 caratteri:
    /// o la decodifica fallisce, o ri-codificare il risultato riproduce
    /// esattamente la stringa di partenza. Non esistono due stringhe distinte
    /// che decodificano allo stesso blob.
    ///
    /// I conteggi sono la verifica indipendente: 2 caratteri codificano
    /// esattamente 1 byte, quindi devono passare esattamente 256 stringhe su
    /// 32^2; 4 caratteri codificano 2 byte, quindi 65_536 su 32^4. Se il
    /// controllo sui bit di riempimento fosse assente, passerebbero tutte.
    ///
    /// Questo e' cio' che un vettore in piu' non avrebbe potuto dare: un
    /// vettore prova un punto, questo prova l'intero spazio.
    #[test]
    fn canonicita_esaustiva() {
        for (chars, attesi) in [(2usize, 256usize), (4, 65_536)] {
            let mut passate = 0usize;
            let mut buf = vec![0u8; chars];
            for n in 0..32usize.pow(chars as u32) {
                let mut rest = n;
                for slot in buf.iter_mut() {
                    *slot = ALPHABET.get(rest % 32).copied().unwrap_or(b'y');
                    rest /= 32;
                }
                let s = std::str::from_utf8(&buf).unwrap();
                if let Ok(decoded) = decode(s) {
                    assert_eq!(encode(&decoded), s, "codifica non canonica: {s}");
                    passate += 1;
                }
            }
            assert_eq!(passate, attesi, "stringhe accettate a {chars} caratteri");
        }
    }

    #[test]
    fn nessun_panic_su_input_arbitrario() {
        // Include UTF-8 multibyte, che rende len() in byte diverso dal numero
        // di caratteri: deve fallire, non andare in panic.
        for s in ["", "y", "!!!!", "6n9hq6n9hq", "ààà", "\u{1F600}", "6n9hq\0"] {
            let _ = decode(s);
        }
    }
}
