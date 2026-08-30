// MusyBoard per Scriptable (iOS)
//
// App unica: mostra un menu interattivo se lanciata dall'icona di Scriptable,
// oppure gestisce cifratura/decifratura al volo se lanciata da uno dei due
// Comandi Rapidi ("Decifra MusyBoard" / "Cifra con MusyBoard" — vedi in fondo
// a questo file per come sono fatti). Non serve nessun altro script: i due
// Comandi Rapidi passano qui un parametro con un marcatore in testa
// ("MB_DECRYPT:" o "MB_ENCRYPT:"), aggiunto da un'azione "Testo" dentro il
// Comando Rapido stesso — vedi in fondo.
//
// PREREQUISITI, da avere gia' pronti in QUESTA stessa cartella locale di
// Scriptable (FileManager.local(), MAI la cartella iCloud — la chiave privata
// finirebbe sincronizzata sui server Apple):
//   - musyboard_wasm.wasm   (il modulo compilato dal crate wasm/)
//
// Questo script crea da solo, al primo avvio, "config.json" nella stessa
// cartella: contiene l'identita' (chiave privata IN CHIARO — nessun
// equivalente di Android Keystore in questo MVP, e' un rischio accettato
// esplicitamente, vedi il piano) e lo stato dei contatti/catena.
//
// Nessuna richiesta di rete in questo script. Punto fermo: se un giorno serve
// aggiungerne una, e' un cambiamento da valutare apposta, non da fare qui
// dentro senza dirlo.

// -----------------------------------------------------------------------
// Percorsi
// -----------------------------------------------------------------------

// Calcolati alla prima chiamata, non al caricamento del file: `FileManager`
// e' un globale Scriptable, assente per costruzione quando questo file viene
// caricato altrove (es. `test-codec.js`) solo per le funzioni pure che non
// toccano il filesystem.
let files = null;
let CONFIG_PATH = null;
let WASM_PATH = null;

function ensurePaths() {
  if (files) return;
  files = FileManager.local();
  CONFIG_PATH = files.joinPath(files.documentsDirectory(), "config.json");
  WASM_PATH = files.joinPath(files.documentsDirectory(), "musyboard_wasm.wasm");
}

// -----------------------------------------------------------------------
// UTF-8 e Base64 scritti a mano.
//
// Deliberatamente NIENTE `TextEncoder`/`TextDecoder`/`atob`/`btoa`: sono API
// del DOM/Web, non del motore JavaScript in se', e in un JSContext senza
// WebView (che e' quello che esegue questo script) non e' garantito che
// esistano — la stessa ragione per cui l'entropia passa da una WebView
// nascosta e non da un ipotetico `crypto` globale. Qui invece bastano
// `Uint8Array`/`DataView`/`String.fromCodePoint`, che sono parte del
// linguaggio (ECMAScript), non del browser.
// -----------------------------------------------------------------------

function utf8Encode(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.codePointAt(i);
    if (code > 0xffff) i++; // e' una coppia di surrogati: consumata in un colpo
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

function utf8Decode(bytes) {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    if (b0 < 0x80) {
      out += String.fromCodePoint(b0);
    } else if ((b0 & 0xe0) === 0xc0) {
      const b1 = bytes[i++];
      out += String.fromCodePoint(((b0 & 0x1f) << 6) | (b1 & 0x3f));
    } else if ((b0 & 0xf0) === 0xe0) {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      out += String.fromCodePoint(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
    } else {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      const b3 = bytes[i++];
      out += String.fromCodePoint(
        ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)
      );
    }
  }
  return out;
}

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64Encode(bytes) {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64_CHARS[(n >> 18) & 63] +
      B64_CHARS[(n >> 12) & 63] +
      B64_CHARS[(n >> 6) & 63] +
      B64_CHARS[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + "==";
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + B64_CHARS[(n >> 6) & 63] + "=";
  }
  return out;
}

function base64Decode(str) {
  const clean = str.replace(/[^A-Za-z0-9+/]/g, "");
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const val = B64_CHARS.indexOf(ch);
    if (val === -1) continue;
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// -----------------------------------------------------------------------
// Encoder QR code, offline, scritto a mano — nessuna libreria, nessuna rete.
//
// Solo modo byte, livello di correzione errori M, maschera fissa 0 (mask
// pattern 0, formula (riga+colonna) mod 2 == 0). Una maschera fissa e' una
// scelta legittima dello standard — ISO/IEC 18004 non impone di provarle
// tutte e scegliere la migliore, solo di applicarne UNA e dichiararla
// correttamente nei bit di formato; scegliere sempre la 0 evita di dover
// implementare anche il punteggio di leggibilita' delle otto varianti.
//
// Le tabelle numeriche qui sotto (correzione errori per versione, posizioni
// dei pattern di allineamento, bit di formato/versione precalcolati, tabelle
// GF(256)) sono valori dello standard ISO/IEC 18004, non espressione
// creativa: estratte a macchina da una libreria di riferimento (mai
// ritrascritte a mano, per azzerare il rischio di un refuso in una tabella
// Reed-Solomon) e poi verificate — matrice per matrice, con maschera forzata
// alla stessa, livello EC forzato (la libreria di riferimento lo alza da
// sola se i dati sono corti, e va disattivato per un confronto onesto) —
// contro quella stessa libreria per ~400 input di prova (lunghezze 0-1000,
// contenuto sia strutturato sia casuale, tutte le versioni 1-20 coperte).
// Il primo giro di verifica ha trovato QUATTRO bug reali, nessuno deducibile
// solo guardando il codice: l'ordine fra riserva dell'area formato e timing
// pattern; un errore di indicizzazione traducendo `matrix[-i][8]` di Python
// (dove `a[-0]` e' un caso speciale, `a[-0]==a[0]`); una mutazione della
// variabile di controllo del `for` di piazzamento che in JS influenza il
// decremento successivo (in Python no, il `range` e' gia' calcolato); e un
// riempimento "al byte" che va applicato SEMPRE, anche quando i dati sono
// gia' allineati (aggiunge un byte intero di zeri, non zero byte). Ognuno,
// da solo, avrebbe prodotto un QR che sembra valido e non scansiona. Il
// codice di posizionamento (`qrPlaceModules`) segue fedelmente l'algoritmo a
// "zigzag" descritto nella specifica (§7.7.3), citata anche nel commento
// della funzione.
//
// QR_ECC_M[versione] = [[n_blocchi, codeword_totali_per_blocco, codeword_dati_per_blocco], ...]
// (una o due voci: alcune versioni hanno blocchi di due dimensioni diverse)
const QR_ECC_M = {
  1: [[1, 26, 16]],
  2: [[1, 44, 28]],
  3: [[1, 70, 44]],
  4: [[2, 50, 32]],
  5: [[2, 67, 43]],
  6: [[4, 43, 27]],
  7: [[4, 49, 31]],
  8: [[2, 60, 38], [2, 61, 39]],
  9: [[3, 58, 36], [2, 59, 37]],
  10: [[4, 69, 43], [1, 70, 44]],
  11: [[1, 80, 50], [4, 81, 51]],
  12: [[6, 58, 36], [2, 59, 37]],
  13: [[8, 59, 37], [1, 60, 38]],
  14: [[4, 64, 40], [5, 65, 41]],
  15: [[5, 65, 41], [5, 66, 42]],
  16: [[7, 73, 45], [3, 74, 46]],
  17: [[10, 74, 46], [1, 75, 47]],
  18: [[9, 69, 43], [4, 70, 44]],
  19: [[3, 70, 44], [11, 71, 45]],
  20: [[3, 67, 41], [13, 68, 42]],
};

// Indicizzato per VERSIONE reale (non versione-2): la versione 1 non compare
// apposta, non ha pattern di allineamento — verificato sulla matrice reale
// di una libreria di riferimento, non assunto dalla memoria della specifica.
const QR_ALIGNMENT_POS = {
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
  11: [6, 30, 54],
  12: [6, 32, 58],
  13: [6, 34, 62],
  14: [6, 26, 46, 66],
  15: [6, 26, 48, 70],
  16: [6, 26, 50, 74],
  17: [6, 30, 54, 78],
  18: [6, 30, 56, 82],
  19: [6, 30, 58, 86],
  20: [6, 34, 62, 90],
};

// 32 valori (indice = livello_EC<<3 | maschera), gia' con BCH(15,5) e XOR
// della maschera di formato 0x5412 applicati — per il livello M, livello_EC
// vale 0, quindi con maschera fissa 0 l'indice usato e' sempre 0.
const QR_FORMAT_INFO = [
  21522, 20773, 24188, 23371, 17913, 16590, 20375, 19104, 30660, 29427,
  32170, 30877, 26159, 25368, 27713, 26998, 5769, 5054, 7399, 6608, 1890,
  597, 3340, 2107, 13663, 12392, 16177, 14854, 9396, 8579, 11994, 11245,
];

// Indice = versione-7 (18 bit, BCH(18,6)), per versioni 7-40.
const QR_VERSION_INFO = [
  31892, 34236, 39577, 42195, 48118, 51042, 55367, 58893, 63784, 68472,
  70749, 76311, 79154, 84390, 87683, 92361, 96236, 102084, 102881, 110507,
  110734, 117786, 119615, 126325, 127568, 133589, 136944, 141498, 145311,
  150283, 152622, 158308, 161089, 167017,
];

const QR_GALOIS_EXP = [1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1];
const QR_GALOIS_LOG = [0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246, 108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175];

function qrGfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return QR_GALOIS_EXP[(QR_GALOIS_LOG[a] + QR_GALOIS_LOG[b]) % 255];
}

function qrRsGeneratorPoly(degree) {
  let g = [1];
  for (let i = 0; i < degree; i++) {
    const root = QR_GALOIS_EXP[i];
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j];
      next[j + 1] ^= qrGfMul(g[j], root);
    }
    g = next;
  }
  return g;
}

function qrRsComputeEcc(dataBytes, eccLen) {
  const gen = qrRsGeneratorPoly(eccLen);
  const remainder = dataBytes.concat(new Array(eccLen).fill(0));
  for (let i = 0; i < dataBytes.length; i++) {
    const coef = remainder[i];
    if (coef === 0) continue;
    for (let j = 0; j < gen.length; j++) {
      remainder[i + j] ^= qrGfMul(gen[j], coef);
    }
  }
  return remainder.slice(dataBytes.length);
}

class QrBitBuffer {
  constructor() {
    this.bits = [];
  }
  push(value, length) {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  }
  get length() {
    return this.bits.length;
  }
}

function qrCharCountBits(version) {
  return version <= 9 ? 8 : 16; // modo byte
}

function qrDataCapacityBits(version) {
  const groups = QR_ECC_M[version];
  let totalData = 0;
  for (const [nBlocks, , nData] of groups) totalData += nBlocks * nData;
  return totalData * 8;
}

function qrPickVersion(byteLen) {
  for (let v = 1; v <= 20; v++) {
    const headerBits = 4 + qrCharCountBits(v);
    if (headerBits + byteLen * 8 <= qrDataCapacityBits(v)) return v;
  }
  throw new Error("testo troppo lungo per un QR code (livello M, fino a versione 20)");
}

function qrBuildDataCodewords(version, dataBytes) {
  const bb = new QrBitBuffer();
  bb.push(0b0100, 4); // indicatore di modo: byte
  bb.push(dataBytes.length, qrCharCountBits(version));
  for (const b of dataBytes) bb.push(b, 8);

  const capacityBits = qrDataCapacityBits(version);
  const termLen = Math.min(4, Math.max(0, capacityBits - bb.length));
  bb.push(0, termLen);
  // Allineamento al byte: SEMPRE `8 - (lunghezza mod 8)` bit — che fa 8, un
  // byte intero, non 0, quando i dati sono gia' allineati. Verificato contro
  // una libreria di riferimento: non e' un "se serve", e' incondizionato.
  // Limitato dalla capacita' residua per non sforare mai, nel caso limite in
  // cui il terminatore sia gia' stato troncato per mancanza di spazio.
  const padToByte = Math.min(8 - (bb.length % 8), capacityBits - bb.length);
  if (padToByte > 0) bb.push(0, padToByte);

  const padBytes = [0xec, 0x11];
  let p = 0;
  while (bb.length < capacityBits) {
    bb.push(padBytes[p % 2], 8);
    p++;
  }

  const bytes = [];
  for (let i = 0; i < bb.length; i += 8) {
    let byte = 0;
    for (let k = 0; k < 8; k++) byte = (byte << 1) | bb.bits[i + k];
    bytes.push(byte);
  }
  return bytes;
}

// Divide in blocchi, calcola l'ECC per ciascuno, interfoglia dati e poi ECC
// (ISO/IEC 18004 §7.5), e aggiunge i bit di riempimento finali (§7.6) —
// necessari solo per alcune versioni, dove i moduli disponibili non sono un
// multiplo esatto di 8.
function qrBuildFinalBits(version, dataCodewords) {
  const groups = QR_ECC_M[version];
  const eccLen = groups[0][1] - groups[0][2];

  const dataBlocks = [];
  const eccBlocks = [];
  let offset = 0;
  for (const [nBlocks, , nData] of groups) {
    for (let b = 0; b < nBlocks; b++) {
      const block = dataCodewords.slice(offset, offset + nData);
      offset += nData;
      dataBlocks.push(block);
      eccBlocks.push(qrRsComputeEcc(block, eccLen));
    }
  }

  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  const codewords = [];
  for (let col = 0; col < maxDataLen; col++) {
    for (const block of dataBlocks) {
      if (col < block.length) codewords.push(block[col]);
    }
  }
  for (let col = 0; col < eccLen; col++) {
    for (const block of eccBlocks) {
      codewords.push(block[col]);
    }
  }

  const bits = [];
  for (const cw of codewords) {
    for (let i = 7; i >= 0; i--) bits.push((cw >>> i) & 1);
  }

  const remainderTable = {
    2: 7, 3: 7, 4: 7, 5: 7, 6: 7,
    14: 3, 15: 3, 16: 3, 17: 3, 18: 3, 19: 3, 20: 3,
    21: 4, 22: 4, 23: 4, 24: 4, 25: 4, 26: 4, 27: 4,
  };
  const remainder = remainderTable[version] || 0;
  for (let i = 0; i < remainder; i++) bits.push(0);
  return bits;
}

// Costruisce la matrice vuota con i pattern fissi (finder, separatori,
// timing, allineamento) gia' posizionati, e un secondo array parallelo
// `isData` che segna quali celle restano libere per i dati — serve dopo,
// per sapere a quali celle applicare la maschera (il modulo scuro e le aree
// di formato/versione NON si mascherano mai).
function qrBuildBaseMatrix(version) {
  const size = version * 4 + 17;
  const m = [];
  for (let i = 0; i < size; i++) m.push(new Array(size).fill(2)); // 2 = libero

  // ORDINE — verificato contro una libreria di riferimento, non deducibile
  // "a occhio" dalla sola specifica: riservare l'area di formato/versione
  // PRIMA del timing pattern, non dopo. Il timing pattern attraversa infatti
  // l'incrocio (riga 6, colonna 8) e (riga 8, colonna 6): riservarlo dopo
  // cancellerebbe per sbaglio il bit di timing gia' scritto li'.
  // Occhio: qui la specifica di riferimento indicizza con `matrix[-i][8]` e
  // `i` parte da 0 — in Python `a[-0]` E' `a[0]` (caso speciale), quindi lo
  // specchio vero comincia solo da i=1, sull'indice `size-i`, non
  // `size-1-i`. Un errore qui aveva riservato la cella di troppo (col12/riga
  // 8 invece che col13), trovato solo confrontando le celle dati cella per
  // cella con una libreria di riferimento — non deducibile a occhio.
  for (let i = 0; i < 9; i++) {
    m[i][8] = 0;
    m[8][i] = 0;
  }
  for (let i = 1; i < 9; i++) {
    m[size - i][8] = 0;
    m[8][size - i] = 0;
  }
  if (version >= 7) {
    for (let i = 0; i < 6; i++) {
      m[size - 11][i] = 0;
      m[size - 10][i] = 0;
      m[size - 9][i] = 0;
      m[i][size - 11] = 0;
      m[i][size - 10] = 0;
      m[i][size - 9] = 0;
    }
  }

  // Timing pattern: righe/colonne 6, alternato, a partire da scuro in
  // posizione 8 (dopo i finder pattern con separatore) — scrive SOPRA la
  // riserva appena fatta nell'incrocio con la striscia di formato.
  for (let i = 8; i < size - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0;
    m[6][i] = bit;
    m[i][6] = bit;
  }

  // Finder pattern 7x7 + separatore, nei tre angoli (non in basso a destra).
  const finderPattern = [
    [1, 1, 1, 1, 1, 1, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 1, 1, 1, 1, 1, 1],
  ];
  function placeFinder(topRow, topCol) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = topRow + r;
        const cc = topCol + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
          m[rr][cc] = finderPattern[r][c];
        } else {
          m[rr][cc] = 0; // separatore, sempre chiaro
        }
      }
    }
  }
  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Pattern di allineamento (assenti in versione 1).
  const positions = QR_ALIGNMENT_POS[version];
  if (positions) {
    const alignPattern = [
      [1, 1, 1, 1, 1],
      [1, 0, 0, 0, 1],
      [1, 0, 1, 0, 1],
      [1, 0, 0, 0, 1],
      [1, 1, 1, 1, 1],
    ];
    const minPos = positions[0];
    const maxPos = positions[positions.length - 1];
    const finderCorners = new Set([`${minPos},${minPos}`, `${minPos},${maxPos}`, `${maxPos},${minPos}`]);
    for (const x of positions) {
      for (const y of positions) {
        if (finderCorners.has(`${x},${y}`)) continue;
        const i0 = x - 2;
        const j0 = y - 2;
        for (let r = 0; r < 5; r++) {
          for (let c = 0; c < 5; c++) {
            m[i0 + r][j0 + c] = alignPattern[r][c];
          }
        }
      }
    }
  }

  // Il modulo scuro (m[size-8][8]) NON si scrive qui: coincide esattamente
  // con l'ultima cella toccata dal ciclo di `qrWriteFormatInfo` (i=7, il suo
  // specchio `size-1-i`), e nel riferimento vince chi scrive DOPO — il
  // modulo scuro, non il ciclo. Scriverlo qui verrebbe silenziosamente
  // sovrascritto piu' tardi. Resta comunque fuori dall'area dati: la riserva
  // generica qui sopra (`m[size-i][8]=0` per i=8) gia' lo esclude.

  const isData = m.map((row) => row.map((v) => v === 2));
  return { m, isData, size };
}

// Posiziona i bit dati/ECC nella matrice seguendo il percorso "a zigzag" di
// ISO/IEC 18004 §7.7.3: colonne larghe due moduli, da destra a sinistra,
// alternando su e giu', saltando la colonna del timing pattern.
function qrPlaceModules(m, isData, size, bits) {
  let idx = 0;
  // `rightBase` e' il puro controllo del ciclo (decrementa di 2 ogni volta,
  // punto). L'aggiustamento "salta la colonna del timing pattern" vive in
  // `right`, una variabile SEPARATA: mutare la variabile di controllo di un
  // `for` dentro il suo stesso corpo, in JS, influenza il decremento
  // successivo (a differenza del `range()` di Python, gia' calcolato in
  // anticipo) — un bug reale, trovato solo confrontando la matrice con una
  // libreria di riferimento, non deducibile guardando il codice.
  for (let rightBase = size - 1; rightBase > 0; rightBase -= 2) {
    let right = rightBase;
    if (right <= 6) right -= 1;
    for (let vertical = 0; vertical < size; vertical++) {
      for (let z = 0; z < 2; z++) {
        const col = right - z;
        let upwards = (right & 2) === 0;
        if (col < 6) upwards = !upwards;
        const row = upwards ? size - 1 - vertical : vertical;
        if (isData[row][col] && idx < bits.length) {
          m[row][col] = bits[idx];
          idx++;
        }
      }
    }
  }
}

function qrApplyMask(m, isData, size) {
  for (let i = 0; i < size; i++) {
    for (let j = 0; j < size; j++) {
      if (isData[i][j] && (i + j) % 2 === 0) {
        m[i][j] ^= 1;
      }
    }
  }
}

function qrWriteFormatInfo(m, size) {
  // Livello M, maschera 0: fmt = (0 << 3) | 0 = 0.
  const formatInfo = QR_FORMAT_INFO[0];
  let voffset = 0;
  let hoffset = 0;
  for (let i = 0; i < 8; i++) {
    const vbit = (formatInfo >>> i) & 1;
    const hbit = (formatInfo >>> (14 - i)) & 1;
    if (i === 6) {
      voffset = 1;
      hoffset = 1;
    }
    m[i + voffset][8] = vbit;
    m[8][i + hoffset] = hbit;
    m[8][size - 1 - i] = vbit;
    m[size - 1 - i][8] = hbit;
  }
  // Scritto DOPO il ciclo apposta: coincide con l'ultima cella che il ciclo
  // stesso ha appena toccato (i=7), e qui deve vincere il modulo scuro.
  m[size - 8][8] = 1;
}

function qrWriteVersionInfo(m, size, version) {
  if (version < 7) return;
  const versionInfo = QR_VERSION_INFO[version - 7];
  for (let i = 0; i < 6; i++) {
    const bit1 = (versionInfo >>> (i * 3)) & 1;
    const bit2 = (versionInfo >>> (i * 3 + 1)) & 1;
    const bit3 = (versionInfo >>> (i * 3 + 2)) & 1;
    m[size - 11][i] = bit1;
    m[size - 10][i] = bit2;
    m[size - 9][i] = bit3;
    m[i][size - 11] = bit1;
    m[i][size - 10] = bit2;
    m[i][size - 9] = bit3;
  }
}

/** Codifica `text` (UTF-8) in un QR code. Ritorna `{ version, size, matrix }`
 * dove `matrix` e' un array di array di 0/1 (1 = modulo scuro). Solo modo
 * byte, livello M, maschera fissa 0 — vedi il commento in testa al file. */
function qrEncodeText(text) {
  const dataBytes = Array.from(utf8Encode(text));
  const version = qrPickVersion(dataBytes.length);
  const dataCodewords = qrBuildDataCodewords(version, dataBytes);
  const bits = qrBuildFinalBits(version, dataCodewords);
  const { m, isData, size } = qrBuildBaseMatrix(version);
  qrPlaceModules(m, isData, size, bits);
  qrApplyMask(m, isData, size);
  qrWriteFormatInfo(m, size);
  qrWriteVersionInfo(m, size, version);
  return { version, size, matrix: m };
}

// -----------------------------------------------------------------------
// Lettore/scrittore binario — stesso ruolo di `Reader`/`Writer` in
// wasm/src/codec.rs. Il layout DEVE restare identico su entrambi i lati: se
// cambia uno, cambia anche l'altro, nello stesso commit.
// -----------------------------------------------------------------------

class ByteReader {
  constructor(buf) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.pos = 0;
  }
  u8() {
    const v = this.buf[this.pos];
    this.pos += 1;
    return v;
  }
  u16() {
    const v = this.view.getUint16(this.pos, true);
    this.pos += 2;
    return v;
  }
  u32() {
    const v = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }
  i64() {
    const v = this.view.getBigInt64(this.pos, true);
    this.pos += 8;
    return Number(v);
  }
  key32() {
    return this.bytes(32);
  }
  bytes(n) {
    const v = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  strU16() {
    const len = this.u16();
    return utf8Decode(this.bytes(len));
  }
}

class ByteWriter {
  constructor() {
    this.parts = [];
  }
  u8(v) {
    this.parts.push(new Uint8Array([v & 0xff]));
    return this;
  }
  u16(v) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.parts.push(b);
    return this;
  }
  i64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
    this.parts.push(b);
    return this;
  }
  bytes(b) {
    this.parts.push(b);
    return this;
  }
  strU16(s) {
    const enc = utf8Encode(s);
    this.u16(enc.length);
    this.parts.push(enc);
    return this;
  }
  toBytes() {
    return concatBytes(this.parts);
  }
}

// -----------------------------------------------------------------------
// Codifica dei record persistiti — rispecchia esattamente
// wasm/src/codec.rs::{encode,decode}_{peer,prekey}_record.
// -----------------------------------------------------------------------

function encodePeerRecordJs(rec) {
  const w = new ByteWriter();
  w.bytes(rec.public).i64(rec.first_seen_unix).u8(rec.verified ? 1 : 0);
  if (rec.label) {
    w.strU16(rec.label);
  } else {
    w.u16(0);
  }
  return w.toBytes();
}

function decodePeerRecordJs(buf) {
  const r = new ByteReader(buf);
  const public_ = r.key32();
  const first_seen_unix = r.i64();
  const verified = r.u8() !== 0;
  const label = r.strU16();
  return { public: public_, first_seen_unix, verified, label: label === "" ? null : label };
}

function encodePrekeyRecordJs(rec) {
  const w = new ByteWriter();
  w.bytes(rec.peer);
  if (rec.sua_prekey) {
    w.u8(1).bytes(rec.sua_prekey);
  } else {
    w.u8(0);
  }
  const mie = rec.mie || [];
  w.u8(mie.length);
  for (const k of mie) w.bytes(k);
  if (rec.mia_epoca) {
    w.u8(1).bytes(rec.mia_epoca);
  } else {
    w.u8(0);
  }
  if (rec.sua_epoca) {
    w.u8(1).bytes(rec.sua_epoca);
  } else {
    w.u8(0);
  }
  w.i64(rec.visto_a).i64(rec.rogo_a);
  return w.toBytes();
}

function decodePrekeyRecordJs(buf) {
  const r = new ByteReader(buf);
  const peer = r.key32();
  const sua_prekey = r.u8() === 1 ? r.key32() : null;
  const count = r.u8();
  const mie = [];
  for (let i = 0; i < count; i++) mie.push(r.key32());
  const mia_epoca = r.u8() === 1 ? r.key32() : null;
  const sua_epoca = r.u8() === 1 ? r.key32() : null;
  const visto_a = r.i64();
  const rogo_a = r.i64();
  return { peer, sua_prekey, mie, mia_epoca, sua_epoca, visto_a, rogo_a };
}

// Tag di `IncomingItem` — rispecchia wasm/src/codec.rs::TAG_*.
const TAG_MESSAGE = 0;
const TAG_OWN_MESSAGE = 1;
const TAG_BURNED = 2;
const TAG_OWN_IDENTITY_CARD = 3;
const TAG_IDENTITY_CARD = 4;

function decodeIncomingItem(buf) {
  const r = new ByteReader(buf);
  const tag = r.u8();
  switch (tag) {
    case TAG_MESSAGE: {
      const sender = r.key32();
      const statusTag = r.u8();
      let senderStatus;
      if (statusTag === 0) {
        senderStatus = { kind: "new" };
      } else {
        const verified = r.u8() !== 0;
        const label = r.strU16();
        senderStatus = { kind: "known", verified, label: label === "" ? null : label };
      }
      const gruppo = r.u8() !== 0;
      const destinatari = r.u32();
      const sentAtUnix = r.i64();
      const plaintextLen = r.u32();
      const text = utf8Decode(r.bytes(plaintextLen));
      return { tag: "message", sender, senderStatus, gruppo, destinatari, sentAtUnix, text };
    }
    case TAG_OWN_MESSAGE: {
      const recipient = r.key32();
      const label = r.strU16();
      const sentAtUnix = r.i64();
      const plaintextLen = r.u32();
      const text = utf8Decode(r.bytes(plaintextLen));
      return {
        tag: "ownMessage",
        recipient,
        recipientLabel: label === "" ? null : label,
        sentAtUnix,
        text,
      };
    }
    case TAG_BURNED: {
      const peer = r.key32();
      const sentAtUnix = r.i64();
      return { tag: "burned", peer, sentAtUnix };
    }
    case TAG_OWN_IDENTITY_CARD: {
      const fingerprint = r.strU16();
      return { tag: "ownIdentityCard", fingerprint };
    }
    case TAG_IDENTITY_CARD: {
      const peer = r.key32();
      const fingerprint = r.strU16();
      const outcome = r.u8() === 0 ? "pinned" : "alreadyPinned";
      return { tag: "identityCard", peer, fingerprint, outcome };
    }
    default:
      throw new Error("tag IncomingItem sconosciuto: " + tag);
  }
}

function decodeLabelOutcome(buf) {
  const r = new ByteReader(buf);
  const tag = r.u8();
  if (tag === 0) return { kind: "assigned" };
  const existing = r.key32();
  const existingFingerprint = r.strU16();
  const incomingFingerprint = r.strU16();
  return { kind: "conflict", existing, existingFingerprint, incomingFingerprint };
}

// -----------------------------------------------------------------------
// Ponte verso il modulo wasm — stesso protocollo di wasm/src/marshal.rs.
// -----------------------------------------------------------------------

const ERROR_MESSAGES = {
  1: "formato non valido",
  2: "versione non supportata da questa app: aggiornala",
  3: "questo testo non è cifrato con MusyBoard",
  4: "decodifica fallita: il testo è corrotto o incompleto",
  5: "decifratura fallita: chiave sbagliata o testo manomesso",
  6: "nessun destinatario selezionato: scegli un contatto prima di cifrare",
  7: "livello di cifratura non supportato da questa versione dell'app",
  8: "questo messaggio l'hai scritto tu: può aprirlo solo il destinatario",
  9: "errore interno del portachiavi",
  90: "generatore casuale non pronto (bug interno)",
  92: "nessuna identità caricata: aprila prima da MusyBoard",
  93: "testo non valido",
  94: "dati malformati (bug interno)",
};

class MusyBoardError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] || "errore sconosciuto (codice " + code + ")");
    this.code = code;
  }
}

let wasm = null;

async function loadWasmModule() {
  if (wasm) return;
  ensurePaths();
  if (!files.fileExists(WASM_PATH)) {
    throw new Error(
      "musyboard_wasm.wasm non trovato in " +
        WASM_PATH +
        " — copialo nella cartella LOCALE di Scriptable (non iCloud) prima di continuare."
    );
  }
  const data = files.read(WASM_PATH);
  const bytes = new Uint8Array(data.getBytes());
  const { instance } = await WebAssembly.instantiate(bytes, {});
  wasm = instance;
}

function memBuffer() {
  // Va riletto a ogni uso, mai tenuto in cache: se la memoria wasm cresce
  // (`memory.grow`), l'`ArrayBuffer` precedente si "stacca" e diventa
  // inutilizzabile — `instance.exports.memory.buffer` dopo una crescita e' un
  // oggetto NUOVO.
  return new Uint8Array(wasm.exports.memory.buffer);
}

function writeBytes(bytes) {
  const ptr = wasm.exports.mb_alloc(bytes.length);
  memBuffer().set(bytes, ptr);
  return { ptr, len: bytes.length };
}

function writeStr(str) {
  return writeBytes(utf8Encode(str));
}

function readMemory(ptr, len) {
  return memBuffer().slice(ptr, ptr + len);
}

function unpackU64(bigResult) {
  const ptr = Number(bigResult >> 32n) >>> 0;
  const len = Number(bigResult & 0xffffffffn) >>> 0;
  return { ptr, len };
}

/** Chiama una funzione che ritorna un `u64` impacchettato e restituisce i
 * byte del risultato, o lancia `MusyBoardError` su esito d'errore. */
function callProducing(fn, ...args) {
  const packed = fn(...args);
  const { ptr, len } = unpackU64(packed);
  if (ptr === 0) {
    throw new MusyBoardError(len);
  }
  const bytes = readMemory(ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
  return bytes;
}

/** Come `callProducing`, ma `(ptr=0, len=0)` significa "nessun dato" e
 * ritorna `null` invece di lanciare — per funzioni come `mb_current_peer`
 * dove l'assenza non è un errore. Un `(ptr=0, len>0)` resta un errore vero. */
function callProducingOptional(fn, ...args) {
  const packed = fn(...args);
  const { ptr, len } = unpackU64(packed);
  if (ptr === 0 && len === 0) return null;
  if (ptr === 0) {
    throw new MusyBoardError(len);
  }
  const bytes = readMemory(ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
  return bytes;
}

/** Chiama una funzione che ritorna solo un codice `u32` (0 = successo). */
function callStatus(fn, ...args) {
  const code = fn(...args);
  if (code !== 0) {
    throw new MusyBoardError(code);
  }
}

function nowUnixBig() {
  return BigInt(Math.floor(Date.now() / 1000));
}

// -----------------------------------------------------------------------
// Entropia — bridge via WebView nascosta (confermato funzionante in Fase 0:
// ~1-2ms per 32 byte). Va richiamato prima di OGNI operazione che consuma
// RNG lato Rust: `mb_seed_rng` scarta il seme dopo un solo uso apposta, cosi'
// non capita mai di riusarlo per due chiavi diverse nella stessa esecuzione.
// -----------------------------------------------------------------------

async function freshEntropy32() {
  const wv = new WebView();
  await wv.loadHTML("<html></html>");
  const json = await wv.evaluateJavaScript(
    "JSON.stringify(Array.from(crypto.getRandomValues(new Uint8Array(32))))",
    false
  );
  return new Uint8Array(JSON.parse(json));
}

async function seedRng() {
  const entropy = await freshEntropy32();
  const { ptr, len } = writeBytes(entropy);
  callStatus(wasm.exports.mb_seed_rng, ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
}

// -----------------------------------------------------------------------
// Stato di sessione (in memoria, per la durata di QUESTA esecuzione).
// -----------------------------------------------------------------------

let identityLoaded = false;
let currentSecret = null;
let currentPublic = null;
let currentSettings = { app_package_constant: "ios-scriptable", effimero_default: false };

function loadConfigFile() {
  ensurePaths();
  if (!files.fileExists(CONFIG_PATH)) return null;
  return JSON.parse(files.readString(CONFIG_PATH));
}

function saveConfigFile(state) {
  ensurePaths();
  files.writeString(CONFIG_PATH, JSON.stringify(state, null, 2));
}

function stateContactToJson(rec) {
  return {
    public_b64: base64Encode(rec.public),
    label: rec.label,
    first_seen_unix: rec.first_seen_unix,
    verified: rec.verified,
  };
}

function jsonToStateContact(obj) {
  return {
    public: base64Decode(obj.public_b64),
    label: obj.label || null,
    first_seen_unix: obj.first_seen_unix,
    verified: !!obj.verified,
  };
}

function ratchetToJson(rec) {
  return {
    peer_public_b64: base64Encode(rec.peer),
    peer_prekey_b64: rec.sua_prekey ? base64Encode(rec.sua_prekey) : null,
    my_prekeys_b64: rec.mie.map(base64Encode),
    my_epoch_secret_b64: rec.mia_epoca ? base64Encode(rec.mia_epoca) : null,
    peer_epoch_public_b64: rec.sua_epoca ? base64Encode(rec.sua_epoca) : null,
    seen_at_unix: rec.visto_a,
    burned_at_unix: rec.rogo_a,
  };
}

function jsonToRatchet(obj) {
  return {
    peer: base64Decode(obj.peer_public_b64),
    sua_prekey: obj.peer_prekey_b64 ? base64Decode(obj.peer_prekey_b64) : null,
    mie: (obj.my_prekeys_b64 || []).map(base64Decode),
    mia_epoca: obj.my_epoch_secret_b64 ? base64Decode(obj.my_epoch_secret_b64) : null,
    sua_epoca: obj.peer_epoch_public_b64 ? base64Decode(obj.peer_epoch_public_b64) : null,
    visto_a: obj.seen_at_unix,
    rogo_a: obj.burned_at_unix,
  };
}

function hydrateFromConfig(config) {
  const secret = base64Decode(config.my_identity.secret_b64);
  const { ptr } = writeBytes(secret);
  callProducing(wasm.exports.mb_load_identity, ptr); // avvia lo stato "pending"
  wasm.exports.mb_dealloc(ptr, 32);

  for (const c of config.contacts || []) {
    const bytes = encodePeerRecordJs(jsonToStateContact(c));
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_peer, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  for (const rs of config.ratchet_state || []) {
    const bytes = encodePrekeyRecordJs(jsonToRatchet(rs));
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_prekey_record, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  callStatus(wasm.exports.mb_finish_load);
}

function dumpToConfig() {
  const peersCount = wasm.exports.mb_dump_peers_count();
  const contacts = [];
  for (let i = 0; i < peersCount; i++) {
    const bytes = callProducing(wasm.exports.mb_dump_peer_at, i);
    contacts.push(stateContactToJson(decodePeerRecordJs(bytes)));
  }
  const prekeyCount = wasm.exports.mb_dump_prekey_count();
  const ratchet_state = [];
  for (let i = 0; i < prekeyCount; i++) {
    const bytes = callProducing(wasm.exports.mb_dump_prekey_at, i);
    ratchet_state.push(ratchetToJson(decodePrekeyRecordJs(bytes)));
  }
  return {
    schema_version: 1,
    my_identity: {
      secret_b64: base64Encode(currentSecret),
      public_b64: base64Encode(currentPublic),
    },
    contacts,
    ratchet_state,
    settings: currentSettings,
  };
}

function persistAll() {
  saveConfigFile(dumpToConfig());
}

async function bootstrap() {
  await loadWasmModule();
  const config = loadConfigFile();
  if (config && config.my_identity) {
    currentSecret = base64Decode(config.my_identity.secret_b64);
    currentPublic = base64Decode(config.my_identity.public_b64);
    currentSettings = config.settings || currentSettings;
    hydrateFromConfig(config);
    identityLoaded = true;
  }
}

// -----------------------------------------------------------------------
// Operazioni di alto livello (wrapper sui mb_* del modulo wasm).
// -----------------------------------------------------------------------

async function generateIdentity() {
  await seedRng();
  const bytes = callProducing(wasm.exports.mb_generate_identity);
  return { secret: bytes.slice(0, 32), public: bytes.slice(32, 64) };
}

async function getIdentityCard() {
  await seedRng();
  const bytes = callProducing(wasm.exports.mb_identity_card);
  return utf8Decode(bytes);
}

function myFingerprint() {
  const bytes = callProducing(wasm.exports.mb_my_fingerprint);
  return utf8Decode(bytes);
}

function fingerprintOf(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    return utf8Decode(callProducing(wasm.exports.mb_fingerprint_of, ptr));
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function listContacts() {
  const count = wasm.exports.mb_dump_peers_count();
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(decodePeerRecordJs(callProducing(wasm.exports.mb_dump_peer_at, i)));
  }
  return out;
}

function setCurrentPeer(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_set_current_peer, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

/** Byte della chiave pubblica del destinatario corrente, o `null` se non
 * ce n'è uno impostato. */
function getCurrentPeer() {
  return callProducingOptional(wasm.exports.mb_current_peer);
}

async function encryptText(text) {
  await seedRng();
  const { ptr, len } = writeStr(text);
  try {
    return utf8Decode(callProducing(wasm.exports.mb_encrypt, ptr, len, nowUnixBig()));
  } finally {
    wasm.exports.mb_dealloc(ptr, len);
  }
}

function decryptText(text) {
  const { ptr, len } = writeStr(text);
  try {
    return decodeIncomingItem(callProducing(wasm.exports.mb_decrypt, ptr, len, nowUnixBig()));
  } finally {
    wasm.exports.mb_dealloc(ptr, len);
  }
}

async function burnConversation(peerBytes) {
  await seedRng();
  const { ptr } = writeBytes(peerBytes);
  try {
    return utf8Decode(
      callProducing(wasm.exports.mb_burn_conversation, ptr, nowUnixBig())
    );
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function assignLabel(peerBytes, label) {
  const p = writeBytes(peerBytes);
  const l = writeStr(label);
  try {
    return decodeLabelOutcome(
      callProducing(wasm.exports.mb_assign_label, p.ptr, l.ptr, l.len)
    );
  } finally {
    wasm.exports.mb_dealloc(p.ptr, 32);
    wasm.exports.mb_dealloc(l.ptr, l.len);
  }
}

function confirmKeyChange(oldBytes, newBytes) {
  const o = writeBytes(oldBytes);
  const n = writeBytes(newBytes);
  try {
    callStatus(wasm.exports.mb_confirm_key_change, o.ptr, n.ptr, nowUnixBig());
  } finally {
    wasm.exports.mb_dealloc(o.ptr, 32);
    wasm.exports.mb_dealloc(n.ptr, 32);
  }
}

function forgetPeer(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_forget_peer, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function markVerified(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_mark_verified, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

// -----------------------------------------------------------------------
// UI — Alert-based. Niente UITable: con pochi contatti un Alert a bottoni e'
// piu' semplice da tenere corretto senza poter testare dal vivo ogni schermo
// prima del primo giro su un iPhone reale.
// -----------------------------------------------------------------------

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function showMessage(title, message) {
  const a = new Alert();
  a.title = title;
  a.message = message;
  a.addAction("Ok");
  await a.present();
}

async function showError(e) {
  await showMessage("Errore", e && e.message ? e.message : String(e));
}

async function screenIdentity() {
  if (!identityLoaded) {
    const confirm = new Alert();
    confirm.title = "Nessuna identità";
    confirm.message = "Vuoi generarne una nuova adesso?";
    confirm.addAction("Genera");
    confirm.addCancelAction("Annulla");
    if ((await confirm.present()) !== 0) return;
    const { secret, public: pub } = await generateIdentity();
    currentSecret = secret;
    currentPublic = pub;
    identityLoaded = true;
    persistAll();
  }

  const card = await getIdentityCard();
  const a = new Alert();
  a.title = "La mia presentazione";
  a.message =
    "Fingerprint: " +
    myFingerprint() +
    "\n\n" +
    card +
    "\n\nInvia questo testo al tuo contatto Android perché ti aggiunga.";
  a.addAction("Copia presentazione");
  a.addAction("Rigenera identità (ATTENZIONE)");
  a.addCancelAction("Chiudi");
  const choice = await a.present();
  if (choice === 0) {
    Pasteboard.copy(card);
  } else if (choice === 1) {
    const warn = new Alert();
    warn.title = "Sei sicuro?";
    warn.message =
      "Rigenerare l'identità rende illeggibili TUTTE le conversazioni esistenti, e i tuoi contatti smetteranno di riconoscerti. Non si può annullare.";
    warn.addDestructiveAction("Rigenera comunque");
    warn.addCancelAction("Annulla");
    if ((await warn.present()) === 0) {
      const { secret, public: pub } = await generateIdentity();
      currentSecret = secret;
      currentPublic = pub;
      persistAll();
    }
  }
}

async function handleLabelConflict(outcome, newPeerBytes) {
  const a = new Alert();
  a.title = "Nome già usato";
  a.message =
    "Questo nome è già assegnato a un'altra chiave.\n\nEsistente: " +
    outcome.existingFingerprint +
    "\nNuova: " +
    outcome.incomingFingerprint +
    "\n\nÈ la stessa persona con un telefono nuovo?";
  a.addDestructiveAction("Sì, sostituisci");
  a.addCancelAction("No, lascia stare");
  if ((await a.present()) === 0) {
    confirmKeyChange(outcome.existing, newPeerBytes);
  }
}

async function importContactFlow() {
  const a = new Alert();
  a.title = "Importa contatto";
  a.message = "Incolla qui la presentazione (kc/...) ricevuta dal tuo contatto Android.";
  a.addTextField("kc/...", "");
  a.addAction("Importa");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const text = a.textFieldValue(0);
  if (!text) return;

  try {
    const item = decryptText(text);
    if (item.tag === "ownIdentityCard") {
      await showMessage("È la tua presentazione", "Hai incollato la tua stessa card, non quella di un contatto.");
      return;
    }
    if (item.tag !== "identityCard") {
      await showMessage("Non è una presentazione", "Il testo incollato non è una identity card MusyBoard.");
      return;
    }
    persistAll(); // il pin TOFU è già avvenuto dentro mb_decrypt

    const nameAlert = new Alert();
    nameAlert.title = "Nome contatto";
    nameAlert.message = "Fingerprint: " + item.fingerprint + "\n\nCome si chiama?";
    nameAlert.addTextField("Nome", "");
    nameAlert.addAction("Salva");
    nameAlert.addCancelAction("Salta per ora");
    if ((await nameAlert.present()) === 0) {
      const label = nameAlert.textFieldValue(0);
      if (label) {
        const outcome = assignLabel(item.peer, label);
        if (outcome.kind === "conflict") {
          await handleLabelConflict(outcome, item.peer);
        }
      }
    }
    persistAll();
  } catch (e) {
    await showError(e);
  }
}

async function burnFlow(contact) {
  const warn = new Alert();
  warn.title = "Bruciare la conversazione?";
  warn.message =
    "Le chiavi con cui leggi i messaggi di " +
    (contact.label || "questo contatto") +
    " verranno distrutte QUI. È anche una richiesta per lui: se la sua app la onora, farà lo stesso dal suo lato. Non è recuperabile.";
  warn.addDestructiveAction("Brucia");
  warn.addCancelAction("Annulla");
  if ((await warn.present()) !== 0) return;
  try {
    const blob = await burnConversation(contact.public);
    persistAll();
    const result = new Alert();
    result.title = "Richiesta di rogo";
    result.message = blob + "\n\nInviala al tuo contatto perché distrugga anche lui la conversazione.";
    result.addAction("Copia");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(blob);
  } catch (e) {
    await showError(e);
  }
}

async function contactDetail(contact) {
  const a = new Alert();
  a.title = contact.label || "(senza nome)";
  a.message =
    "Fingerprint: " +
    fingerprintOf(contact.public) +
    (contact.verified
      ? "\n\n✓ Verificato"
      : "\n\nNon verificato — confronta il fingerprint di persona o su un altro canale prima di fidarti.");
  a.addAction("Segna come verificato");
  a.addAction("Imposta come destinatario per Cifra");
  a.addAction("Brucia conversazione");
  a.addDestructiveAction("Dimentica contatto");
  a.addCancelAction("Indietro");
  const choice = await a.present();
  if (choice === 0) {
    markVerified(contact.public);
    persistAll();
  } else if (choice === 1) {
    setCurrentPeer(contact.public);
    await showMessage("Fatto", "Ora 'Cifra un messaggio' scriverà a " + (contact.label || "questo contatto") + ".");
  } else if (choice === 2) {
    await burnFlow(contact);
  } else if (choice === 3) {
    await forgetFlow(contact);
  }
}

async function forgetFlow(contact) {
  const warn = new Alert();
  warn.title = "Dimenticare questo contatto?";
  warn.message =
    "Perdi il nome e il pin di sicurezza di " +
    (contact.label || "questo contatto") +
    ". Se scrive di nuovo, tornerà a comparire come mittente mai visto e verrà fissato di nuovo in silenzio — indistinguibile da qualcuno che si spacciasse per lui. Non è recuperabile.";
  warn.addDestructiveAction("Dimentica");
  warn.addCancelAction("Annulla");
  if ((await warn.present()) !== 0) return;
  forgetPeer(contact.public);
  persistAll();
}

async function screenContacts() {
  while (true) {
    const contacts = listContacts();
    const a = new Alert();
    a.title = "Contatti (" + contacts.length + ")";
    for (const c of contacts) {
      a.addAction((c.label || "(senza nome)") + (c.verified ? " ✓" : ""));
    }
    a.addAction("+ Importa nuovo contatto");
    a.addCancelAction("Indietro");
    const choice = await a.present();
    if (choice === -1) return;
    if (choice === contacts.length) {
      await importContactFlow();
      continue;
    }
    await contactDetail(contacts[choice]);
  }
}

async function showDecryptedResult(item) {
  if (item.tag === "message" || item.tag === "ownMessage") {
    const html =
      "<html><body style='font-family: -apple-system, sans-serif; font-size: 20px; " +
      "padding: 24px; word-wrap: break-word; white-space: pre-wrap;'>" +
      escapeHtml(item.text) +
      "</body></html>";
    const wv = new WebView();
    await wv.loadHTML(html);
    await wv.present(true);
  } else if (item.tag === "identityCard" || item.tag === "ownIdentityCard") {
    await showMessage(
      "Presentazione",
      "Questo testo è una identity card, non un messaggio. Usa 'Contatti → Importa' per aggiungerla."
    );
  } else if (item.tag === "burned") {
    await showMessage("Richiesta di rogo ricevuta", "Le chiavi per questa conversazione sono state distrutte.");
  }
}

async function screenDecrypt() {
  const a = new Alert();
  a.title = "Decifra";
  a.message = "Incolla il testo cifrato, o lascia vuoto per leggerlo dagli Appunti.";
  a.addTextField("kc/...", "");
  a.addAction("Decifra");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  let text = a.textFieldValue(0);
  if (!text) text = Pasteboard.paste() || "";
  if (!text) {
    await showMessage("Niente da decifrare", "Il campo e gli Appunti sono vuoti.");
    return;
  }
  try {
    const item = decryptText(text);
    persistAll();
    await showDecryptedResult(item);
  } catch (e) {
    await showError(e);
  }
}

async function pickContact(title) {
  const contacts = listContacts();
  if (contacts.length === 0) {
    await showMessage("Nessun contatto", "Importa prima un contatto da 'Contatti'.");
    return null;
  }
  const pick = new Alert();
  pick.title = title;
  for (const c of contacts) pick.addAction(c.label || "(senza nome)");
  pick.addCancelAction("Annulla");
  const idx = await pick.present();
  return idx === -1 ? null : contacts[idx];
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function findContactByPublic(publicBytes) {
  return listContacts().find((c) => bytesEqual(c.public, publicBytes)) || null;
}

async function screenEncrypt() {
  let contact = null;
  const currentPublic = getCurrentPeer();
  if (currentPublic) {
    const known = findContactByPublic(currentPublic);
    if (known) {
      const a = new Alert();
      a.title = "Destinatario";
      a.message = "Continui a scrivere a " + (known.label || "(senza nome)") + "?";
      a.addAction("Sì, continua");
      a.addAction("Scegli un altro contatto");
      a.addCancelAction("Annulla");
      const choice = await a.present();
      if (choice === -1) return;
      if (choice === 0) contact = known;
    }
  }
  if (!contact) {
    contact = await pickContact("Cifra per...");
    if (!contact) return;
    setCurrentPeer(contact.public);
  }

  const a = new Alert();
  a.title = "Testo da cifrare";
  a.addTextField("Scrivi qui...", "");
  a.addAction("Cifra");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const text = a.textFieldValue(0);
  if (!text) return;
  try {
    const blob = await encryptText(text);
    persistAll();
    const result = new Alert();
    result.title = "Cifrato";
    result.message = blob;
    result.addAction("Copia negli Appunti");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(blob);
  } catch (e) {
    await showError(e);
  }
}

async function mainMenu() {
  while (true) {
    const a = new Alert();
    a.title = "MusyBoard";
    a.message = identityLoaded ? "Io: " + myFingerprint() : "Nessuna identità caricata";
    a.addAction("La mia identità");
    a.addAction("Contatti");
    a.addAction("Decifra un messaggio");
    a.addAction("Cifra un messaggio");
    a.addCancelAction("Chiudi");
    const choice = await a.present();
    if (choice === -1) return;
    try {
      if (choice === 0) await screenIdentity();
      else if (choice === 1) await screenContacts();
      else if (choice === 2) await screenDecrypt();
      else if (choice === 3) await screenEncrypt();
    } catch (e) {
      await showError(e);
    }
  }
}

// -----------------------------------------------------------------------
// Ingresso dai Comandi Rapidi.
//
// I due Comandi Rapidi ("Decifra MusyBoard", "Cifra con MusyBoard") passano
// qui il loro testo preceduto da un marcatore ("MB_DECRYPT:"/"MB_ENCRYPT:"),
// aggiunto da un'azione "Testo" dentro il Comando Rapido stesso — vedi le
// istruzioni di installazione fornite a parte. Il marcatore distingue
// l'intento senza dover indovinare dal contenuto: due Comandi Rapidi restano
// due azioni distinte, come richiesto, non un'unica scorciatoia che tenta di
// indovinare cosa fare.
// -----------------------------------------------------------------------

const MARKER_DECRYPT = "MB_DECRYPT:";
const MARKER_ENCRYPT = "MB_ENCRYPT:";

function describeError(e) {
  return e && e.message ? e.message : String(e);
}

function formatIncomingItemForShortcut(item) {
  if (item.tag === "message" || item.tag === "ownMessage") return item.text;
  if (item.tag === "identityCard") return "[presentazione ricevuta — apri MusyBoard per importarla]";
  if (item.tag === "ownIdentityCard") return "[questa è la tua stessa presentazione]";
  if (item.tag === "burned") return "[richiesta di rogo ricevuta ed eseguita]";
  return "[esito sconosciuto]";
}

async function ensureCurrentPeerForShortcut() {
  const contacts = listContacts();
  if (contacts.length === 0) {
    throw new Error("nessun contatto salvato: apri MusyBoard e importane uno prima");
  }
  if (contacts.length === 1) {
    setCurrentPeer(contacts[0].public);
    return;
  }
  const chosen = await pickContact("Cifra per...");
  if (!chosen) throw new Error("annullato");
  setCurrentPeer(chosen.public);
}

async function shortcutsEntry() {
  const param = args.shortcutParameter;
  if (typeof param !== "string") return false;

  if (param.indexOf(MARKER_DECRYPT) === 0) {
    const text = param.slice(MARKER_DECRYPT.length);
    try {
      const item = decryptText(text);
      persistAll();
      Script.setShortcutOutput(formatIncomingItemForShortcut(item));
    } catch (e) {
      Script.setShortcutOutput("[errore MusyBoard: " + describeError(e) + "]");
    }
    return true;
  }

  if (param.indexOf(MARKER_ENCRYPT) === 0) {
    const text = param.slice(MARKER_ENCRYPT.length);
    try {
      if (!identityLoaded) throw new MusyBoardError(92);
      await ensureCurrentPeerForShortcut();
      const blob = await encryptText(text);
      persistAll();
      Script.setShortcutOutput(blob);
    } catch (e) {
      Script.setShortcutOutput("[errore MusyBoard: " + describeError(e) + "]");
    }
    return true;
  }

  return false;
}

// -----------------------------------------------------------------------
// Punto d'ingresso.
// -----------------------------------------------------------------------

async function main() {
  await bootstrap();
  const handled = await shortcutsEntry();
  if (handled) {
    Script.complete();
    return;
  }
  if (!identityLoaded) {
    await screenIdentity();
  }
  await mainMenu();
  Script.complete();
}

// La guardia su `FileManager` (globale Scriptable, mai presente altrove)
// lascia questo file caricabile da un motore JS qualunque senza avviare
// l'app: e' cosi' che `wasm/scriptable/test-codec.js` verifica la logica
// pura (encoding, ByteReader/Writer, codec) fuori da Scriptable, senza
// tenerne una seconda copia che potrebbe disallinearsi.
if (typeof FileManager !== "undefined") {
  await main();
}
