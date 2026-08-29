// Test della logica pura di MusyBoard.js (encoding UTF-8/Base64,
// ByteReader/Writer, codec dei record) — FUORI da Scriptable.
//
// Non e' eseguibile da solo: usa le funzioni definite in MusyBoard.js
// (encodePeerRecordJs, decodeIncomingItem, ecc.), che vanno caricate prima di
// questo file nello stesso contesto JS. MusyBoard.js e' scritto apposta per
// permetterlo: la sua unica chiamata "attiva" (`await main()`, in fondo al
// file) e' dietro `if (typeof FileManager !== "undefined")`, che fuori da
// Scriptable e' sempre falso — quindi caricarlo in un motore JS qualunque
// definisce tutte le funzioni senza tentare di aprire file o mostrare UI.
//
// Come lanciarlo (qualunque motore JS con supporto a classi/BigInt/DataView,
// es. Node 14+, o QuickJS):
//
//   1. concatenare MusyBoard.js e questo file (in quest'ordine)
//   2. eseguire il risultato
//
// Es. con Node: `cat MusyBoard.js test-codec.js | node --input-type=module`
// (serve `--input-type=module` SOLO se MusyBoard.js contiene ancora un
// `await main()` di primo livello non raggiungibile — altrimenti un normale
// `node` con top-level await supportato basta).
//
// I vettori esadecimali qui sotto sono un KAT cross-linguaggio: generati da
// `cargo test kat_vettori_per_js -- --nocapture --ignored` nel crate
// `wasm/`. Se il layout binario in `wasm/src/codec.rs` cambia, questi vettori
// vanno rigenerati — stesso principio dei KAT del core (CLAUDE.md).

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// `print` esiste nelle shell di alcuni motori (QuickJS, d8, jsc) ma non in
// Node, che usa `console.log`. Se manca gia' un `print` globale, ne creiamo
// uno che ci appoggia sopra.
if (typeof print === "undefined") {
  globalThis.print = function (s) {
    console.log(s);
  };
}

let passed = 0;
let failed = 0;

function check(name, cond) {
  if (cond) {
    passed++;
  } else {
    failed++;
    print("FALLITO: " + name);
  }
}

// -----------------------------------------------------------------------
// Vettori KAT (da `cargo test kat_vettori_per_js -- --nocapture --ignored`)
// -----------------------------------------------------------------------

const PEER_CON_ETICHETTA = "010101010101010101010101010101010101010101010101010101010101010100f15365000000000105004d6172636f";
const PEER_SENZA_ETICHETTA = "0202020202020202020202020202020202020202020202020202020202020202ffffffffffffffff000000";
const PREKEY_PIENO = "0303030303030303030303030303030303030303030303030303030303030303013232323232323232323232323232323232323232323232323232323232323232020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c013c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c0146464646464646464646464646464646464646464646464646464646464646466f00000000000000ffffffffffffffff";
const PREKEY_VUOTO = "04040404040404040404040404040404040404040404040404040404040404040000000000000000000000800000000000000080";
const INCOMING_MESSAGE = "00ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d5901000000000000000040420f00000000000a0000006369616f206d6f6e646f";
const OWN_IDENTITY_CARD = "031d00717177702062626a792072656b742070757a6720746d637920697a7077";

// -----------------------------------------------------------------------
// PeerRecord
// -----------------------------------------------------------------------

{
  const bytes = hexToBytes(PEER_CON_ETICHETTA);
  const rec = decodePeerRecordJs(bytes);
  check("peer con etichetta: label", rec.label === "Marco");
  check("peer con etichetta: verified", rec.verified === true);
  check("peer con etichetta: first_seen_unix", rec.first_seen_unix === 1700000000);
  check(
    "peer con etichetta: round-trip encode",
    bytesEqual(encodePeerRecordJs(rec), bytes)
  );
}

{
  const bytes = hexToBytes(PEER_SENZA_ETICHETTA);
  const rec = decodePeerRecordJs(bytes);
  check("peer senza etichetta: label e' null", rec.label === null);
  check("peer senza etichetta: verified", rec.verified === false);
  check("peer senza etichetta: first_seen_unix negativo", rec.first_seen_unix === -1);
  check(
    "peer senza etichetta: round-trip encode",
    bytesEqual(encodePeerRecordJs(rec), bytes)
  );
}

// -----------------------------------------------------------------------
// PrekeyRecord
// -----------------------------------------------------------------------

{
  const bytes = hexToBytes(PREKEY_PIENO);
  const rec = decodePrekeyRecordJs(bytes);
  check("prekey pieno: sua_prekey presente", rec.sua_prekey !== null && rec.sua_prekey[0] === 50);
  check("prekey pieno: due mie", rec.mie.length === 2);
  check("prekey pieno: mia[0][0]", rec.mie[0][0] === 11);
  check("prekey pieno: mia[1][0]", rec.mie[1][0] === 12);
  check("prekey pieno: mia_epoca presente", rec.mia_epoca !== null && rec.mia_epoca[0] === 60);
  check("prekey pieno: sua_epoca presente", rec.sua_epoca !== null && rec.sua_epoca[0] === 70);
  check("prekey pieno: visto_a", rec.visto_a === 111);
  check("prekey pieno: rogo_a negativo", rec.rogo_a === -1);
  check(
    "prekey pieno: round-trip encode",
    bytesEqual(encodePrekeyRecordJs(rec), bytes)
  );
}

{
  const bytes = hexToBytes(PREKEY_VUOTO);
  const rec = decodePrekeyRecordJs(bytes);
  check("prekey vuoto: sua_prekey assente", rec.sua_prekey === null);
  check("prekey vuoto: nessuna mia", rec.mie.length === 0);
  check("prekey vuoto: mia_epoca assente", rec.mia_epoca === null);
  check("prekey vuoto: sua_epoca assente", rec.sua_epoca === null);
  check("prekey vuoto: visto_a i64::MIN", rec.visto_a === -9223372036854775808);
  check(
    "prekey vuoto: round-trip encode",
    bytesEqual(encodePrekeyRecordJs(rec), bytes)
  );
}

// -----------------------------------------------------------------------
// IncomingItem (solo decodifica: l'encoding di questo tipo avviene solo lato
// Rust — JS non lo ricostruisce mai).
// -----------------------------------------------------------------------

{
  const item = decodeIncomingItem(hexToBytes(INCOMING_MESSAGE));
  check("message: tag", item.tag === "message");
  check("message: testo", item.text === "ciao mondo");
  check("message: gruppo", item.gruppo === false);
  check("message: destinatari", item.destinatari === 0);
  check("message: sender_status known", item.senderStatus.kind === "known");
  check("message: non verificato", item.senderStatus.verified === false);
  check("message: sentAtUnix", item.sentAtUnix === 1000000);
}

{
  const item = decodeIncomingItem(hexToBytes(OWN_IDENTITY_CARD));
  check("own identity card: tag", item.tag === "ownIdentityCard");
  check("own identity card: fingerprint non vuoto", item.fingerprint.length > 0);
}

// -----------------------------------------------------------------------
// UTF-8 e Base64 — proprieta' generali, non vettori congelati.
// -----------------------------------------------------------------------

{
  const casi = ["", "a", "ciao", "società", "🙂🔒", "日本語"];
  for (const s of casi) {
    const bytes = utf8Encode(s);
    const tornato = utf8Decode(bytes);
    check("utf8 round-trip: " + JSON.stringify(s), tornato === s);
  }
}

{
  const casi = [
    new Uint8Array([]),
    new Uint8Array([0]),
    new Uint8Array([1, 2, 3]),
    new Uint8Array([1, 2, 3, 4]),
    new Uint8Array([1, 2, 3, 4, 5]),
    new Uint8Array(32).map((_, i) => i * 7),
  ];
  for (const bytes of casi) {
    const encoded = base64Encode(bytes);
    const tornato = base64Decode(encoded);
    check("base64 round-trip len=" + bytes.length, bytesEqual(tornato, bytes));
  }
}

print("");
print(passed + " passati, " + failed + " falliti");
if (failed > 0) {
  throw new Error(failed + " test falliti");
}
