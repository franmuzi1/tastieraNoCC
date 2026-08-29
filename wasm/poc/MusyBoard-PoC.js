// MusyBoard — Proof of Concept (Fase 0)
//
// Verifica le tre condizioni bloccanti prima di costruire il resto:
//   0.1 — WebAssembly esiste nel runtime di Scriptable?
//   0.2 — un .wasm minimo carica e gira?
//   0.3 — il bridge di entropia via WebView funziona?
//
// Prerequisito: copiare "musyboard_wasm_poc.wasm" nella stessa cartella
// locale di Scriptable in cui vive questo script (FileManager.local(),
// MAI la cartella iCloud). In Scriptable: apri questo script una volta,
// poi usa l'app Files per portare il .wasm accanto ad esso — o incollalo
// con "Aggiungi file" dal picker di Scriptable stesso.

const risultati = [];

function segna(nome, ok, dettaglio) {
  risultati.push(`${ok ? "✅" : "❌"} ${nome}\n${dettaglio}`);
}

async function test01_wasmEsiste() {
  try {
    if (typeof WebAssembly === "undefined") {
      segna("0.1 WebAssembly presente", false, "typeof WebAssembly === 'undefined'");
      return false;
    }
    segna("0.1 WebAssembly presente", true, "typeof WebAssembly === 'object'/'function' — ok");
    return true;
  } catch (e) {
    segna("0.1 WebAssembly presente", false, String(e));
    return false;
  }
}

async function test02_caricaWasm() {
  try {
    const fm = FileManager.local();
    const dir = fm.documentsDirectory();
    const path = fm.joinPath(dir, "musyboard_wasm_poc.wasm");

    if (!fm.fileExists(path)) {
      segna(
        "0.2 Carica .wasm minimo",
        false,
        `File non trovato: ${path}\nCopia musyboard_wasm_poc.wasm nella cartella locale di Scriptable prima di rilanciare.`
      );
      return false;
    }

    const data = fm.read(path);
    const byteArray = data.getBytes(); // [Number], 0-255
    const bytes = new Uint8Array(byteArray);

    const { instance } = await WebAssembly.instantiate(bytes, {});
    const somma = instance.exports.add(2, 3);

    if (somma !== 5) {
      segna("0.2 Carica .wasm minimo", false, `add(2,3) ha restituito ${somma}, atteso 5`);
      return false;
    }
    segna("0.2 Carica .wasm minimo", true, `Istanziato, memoria esportata, add(2,3) = ${somma}`);
    return true;
  } catch (e) {
    segna("0.2 Carica .wasm minimo", false, String(e));
    return false;
  }
}

async function test03_bridgeEntropia() {
  try {
    const wv = new WebView();
    await wv.loadHTML("<html></html>");

    const t0 = Date.now();
    const json = await wv.evaluateJavaScript(
      "JSON.stringify(Array.from(crypto.getRandomValues(new Uint8Array(32))))",
      false
    );
    const t1 = Date.now();

    const byte1 = JSON.parse(json);
    if (!Array.isArray(byte1) || byte1.length !== 32) {
      segna("0.3 Bridge entropia", false, `Risposta inattesa: ${json}`);
      return false;
    }

    // Seconda chiamata: i byte devono cambiare, altrimenti non è vera entropia.
    const json2 = await wv.evaluateJavaScript(
      "JSON.stringify(Array.from(crypto.getRandomValues(new Uint8Array(32))))",
      false
    );
    const byte2 = JSON.parse(json2);
    const identici = JSON.stringify(byte1) === JSON.stringify(byte2);

    if (identici) {
      segna("0.3 Bridge entropia", false, "Due chiamate hanno restituito gli STESSI byte — non è vera entropia.");
      return false;
    }

    segna(
      "0.3 Bridge entropia",
      true,
      `32 byte ottenuti in ${t1 - t0} ms, due chiamate danno risultati diversi.\nPrimi byte: [${byte1.slice(0, 6).join(", ")}, ...]`
    );
    return true;
  } catch (e) {
    segna("0.3 Bridge entropia", false, String(e));
    return false;
  }
}

async function main() {
  const ok1 = await test01_wasmEsiste();
  // Se manca WebAssembly, il test 0.2 non ha senso ma lo tentiamo comunque
  // per completezza del report.
  const ok2 = await test02_caricaWasm();
  const ok3 = await test03_bridgeEntropia();

  const report = risultati.join("\n\n");
  console.log(report);

  const alert = new Alert();
  alert.title = ok1 && ok2 && ok3 ? "PoC: tutto ok" : "PoC: qualcosa non va";
  alert.message = report;
  alert.addAction("Copia report negli Appunti");
  alert.addCancelAction("Chiudi");
  const scelta = await alert.present();
  if (scelta === 0) {
    Pasteboard.copy(report);
  }
}

await main();
