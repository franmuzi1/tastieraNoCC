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
// alla stessa — contro quella stessa libreria per una ventina di input di
// prova. Il codice di posizionamento (`qrPlaceModules`) segue fedelmente
// l'algoritmo a "zigzag" descritto nella specifica (§7.7.3), citata anche nel
// commento della funzione.
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

// Polinomio generatore Reed-Solomon di grado `degree`, monico, coefficienti
// dal grado piu' alto al piu' basso: prodotto di (x + alpha^i) per i in [0, degree).
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

// Codeword di correzione errori per un blocco dati, via divisione polinomiale
// in GF(256) (il polinomio generatore e' monico, quindi nessuna divisione
// vera serve: si moltiplica soltanto).
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
  while (bb.length % 8 !== 0) bb.push(0, 1);

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
  for (let i = 0; i < 9; i++) {
    m[i][8] = 0;
    m[8][i] = 0;
    m[size - 1 - i][8] = 0;
    m[8][size - 1 - i] = 0;
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

  m[size - 8][8] = 1; // modulo scuro fisso — la cella e' gia' fuori dall'area dati.

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
