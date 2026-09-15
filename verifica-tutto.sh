#!/usr/bin/env bash
# Verifica il core e TUTTI quelli che dipendono da lui, in un comando solo.
#
#   ./verifica-tutto.sh            completo
#   ./verifica-tutto.sh --rapido   senza fuzz build e senza lint Android
#
# ## Perche' esiste
#
# `cargo test` qui dentro compila il core e basta. I suoi consumatori sono
# altri cinque, e nessuno viene toccato quando si prova il core:
#
#   jni/  cli/  gui/        crate separati, fuori dal workspace di proposito
#   ../MusyBoard-Android    il fork della tastiera, compila jni/ con cargo ndk
#   ../MusyBoard-iOS        il ponte WebAssembly, in un altro repo
#
# E' costato due volte in due settimane. Una variante nuova di `Error` e' stata
# adeguata in `jni/`, che sta accanto, e non nel ponte iOS, che sta altrove: il
# ponte ha smesso di compilare e nessuno se n'e' accorto. Poi un cambiamento
# del core ha cambiato il binario wasm, e la copia in `dist/` — quella che si
# trasferisce sull'iPhone — e' rimasta quella vecchia.
#
# ## Cosa promette l'esito, e cosa no
#
#   0  tutto eseguito e tutto verde
#   1  qualcosa e' fallito: si ferma al primo, dice quale e mostra la coda
#   2  verde, ma almeno un progetto NON e' stato controllato
#
# Il 2 esiste perche' un "tutto verde" che ha saltato un progetto significa
# "non ho guardato", e detto con la stessa faccia di "ho guardato" e' peggio di
# niente.
#
# Lo script **non corregge niente**: una verifica che modifica cio' che verifica
# non verifica piu'. Quando sa la correzione, la stampa.
#
# NON esegue i test strumentati Android: servono un emulatore acceso e
# sostituiscono l'identita' del dispositivo. Si lanciano a parte, e il
# riepilogo finale lo ricorda.

set -uo pipefail

CORE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID="${MUSY_ANDROID:-$CORE/../MusyBoard-Android}"
IOS="${MUSY_IOS:-$CORE/../MusyBoard-iOS}"
JSPY="${MUSY_JSPY:-$HOME/jstest-venv/bin/python}"
export PATH="$PATH:$HOME/.cargo/bin"

RAPIDO=0
[ "${1:-}" = "--rapido" ] && RAPIDO=1

LOG="$(mktemp -d)"
SALTATI=()
NON_ESEGUITI=()

if [ -t 1 ]; then V=$'\e[32m'; R=$'\e[31m'; G=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else V= R= G= B= N=; fi

testa() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }

# passo NOME CARTELLA COMANDO...
# Esegue, scrive tutto nel log, e al primo fallimento si ferma.
passo() {
  local nome="$1" dir="$2"; shift 2
  local file="$LOG/$(printf '%s' "$nome" | tr -c 'A-Za-z0-9' '_').log"
  local inizio=$SECONDS
  printf '  %-58s' "$nome"
  if (cd "$dir" && "$@") >"$file" 2>&1; then
    printf '%sok%s  %ss\n' "$V" "$N" "$((SECONDS - inizio))"
  else
    printf '%sFALLITO%s\n\n' "$R" "$N"
    tail -n 30 "$file" | sed 's/^/    | /'
    printf '\n  Log completo: %s\n' "$file"
    printf '\n%sROSSO%s — si ferma qui: "%s".\n' "$R" "$N" "$nome"
    exit 1
  fi
}

salta() {
  SALTATI+=("$1 — $2")
  printf '  %sSALTATO%s %s — %s\n' "$G" "$N" "$1" "$2"
}

versione() {
  local sporco=""
  [ -n "$(git -C "$1" status --porcelain 2>/dev/null)" ] && sporco=" + modifiche non committate"
  printf '%s%s' "$(git -C "$1" log --format=%h -1 2>/dev/null || echo '?')" "$sporco"
}

printf '%sVerifica di core, ponti e app%s\n' "$B" "$N"
printf '  core     %s\n' "$(versione "$CORE")"
[ -d "$ANDROID" ] && printf '  Android  %s\n' "$(versione "$ANDROID")"
[ -d "$IOS" ] && printf '  iOS      %s\n' "$(versione "$IOS")"
[ "$RAPIDO" = 1 ] && printf '  %smodalita rapida%s: niente fuzz build, niente lint Android\n' "$G" "$N"

# ---------------------------------------------------------------------------
testa "core"
passo "test" "$CORE" cargo test
passo "clippy" "$CORE" cargo clippy --all-targets -- -D warnings
if [ "$RAPIDO" = 1 ]; then
  NON_ESEGUITI+=("fuzz build del core")
else
  # I target di fuzzing costruiscono `Header` a mano e sono fuori dal
  # workspace: un cambiamento del formato li rompe e `cargo test` non lo vede.
  passo "fuzz build (nightly)" "$CORE" cargo +nightly fuzz build
fi

# ---------------------------------------------------------------------------
testa "ponti nel repo del core"
passo "jni: test" "$CORE/jni" cargo test --release
passo "jni: clippy" "$CORE/jni" cargo clippy --all-targets -- -D warnings
passo "cli: test" "$CORE/cli" cargo test
passo "cli: clippy" "$CORE/cli" cargo clippy --all-targets -- -D warnings
passo "gui: test" "$CORE/gui" cargo test
passo "gui: clippy" "$CORE/gui" cargo clippy --all-targets -- -D warnings

# ---------------------------------------------------------------------------
testa "MusyBoard-iOS"
if [ ! -f "$IOS/Cargo.toml" ]; then
  salta "MusyBoard-iOS" "non trovato in $IOS (MUSY_IOS per indicarlo)"
else
  WASM="$IOS/target/wasm32-unknown-unknown/release/musyboard_wasm.wasm"
  passo "test" "$IOS" cargo test
  passo "clippy" "$IOS" cargo clippy --all-targets -- -D warnings
  passo "build wasm32" "$IOS" cargo build --release --target wasm32-unknown-unknown

  # Zero import e' la condizione verificata su un iPhone vero nella Fase 0:
  # con una sezione import, `WebAssembly.instantiate(bytes, {})` smette di
  # bastare e il modulo non carica dentro Scriptable. Si camminano le sezioni
  # invece di cercare stringhe, che e' come ci si sbaglia.
  passo "binario senza import" "$IOS" python3 - "$WASM" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
if d[:4] != b'\x00asm':
    sys.exit("non e' un modulo wasm")
def leb(i):
    r = s = 0
    while True:
        x = d[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, i
i, esporti = 8, 0
while i < len(d):
    sid = d[i]; size, i = leb(i + 1)
    if sid == 2:
        sys.exit("il binario ha una sezione import: Scriptable non lo carichera' con import vuoti")
    if sid == 7:
        esporti, _ = leb(i)
    i += size
print(len(d), "byte,", esporti, "export, nessun import")
PY

  if [ -x "$JSPY" ] && "$JSPY" -c 'import quickjs' 2>/dev/null; then
    for t in "$IOS"/scriptable/test-*.js; do
      passo "JS: $(basename "$t")" "$IOS" "$JSPY" - scriptable/MusyBoard.js "$t" <<'PY'
import re, sys, quickjs
sorgente = open(sys.argv[1]).read() + open(sys.argv[2]).read()
ctx = quickjs.Context()
out = []
ctx.add_callable('__out', lambda s: out.append(s))
ctx.eval('var print = function(s){ __out(String(s)); };')
try:
    ctx.eval('(async function(){' + sorgente + '})()')
except Exception as e:
    out.append('ECCEZIONE: ' + str(e))
print('\n'.join(out))
# Si pretende la riga di riepilogo con zero falliti. Un errore imprevisto a
# meta' file interrompe l'esecuzione prima di stamparla, quindi niente riga
# vuol dire rosso: il silenzio non passa per un successo.
esiti = [re.search(r'(\d+) passati, (\d+) falliti', o) for o in out]
esiti = [m for m in esiti if m]
if not esiti or int(esiti[-1].group(2)) != 0 or int(esiti[-1].group(1)) == 0:
    sys.exit(1)
PY
    done
  else
    salta "test JS di MusyBoard-iOS" "QuickJS non trovato ($JSPY con il modulo quickjs)"
  fi

  # `dist/` e' una copia deliberata, non si aggiorna da sola: e' il file che
  # finisce sull'iPhone, quindi deve essere quello appena costruito.
  passo "dist/ allineato al binario appena costruito" "$IOS" bash -c '
    a=$(sha256sum "'"$WASM"'" | cut -d" " -f1)
    b=$(sha256sum dist/musyboard_wasm.wasm | cut -d" " -f1)
    [ "$a" = "$b" ] && exit 0
    echo "dist/musyboard_wasm.wasm non e il binario appena costruito."
    echo "Sull iPhone finirebbe una versione che non corrisponde al sorgente."
    echo
    echo "Per allinearlo:"
    echo "  cp target/wasm32-unknown-unknown/release/musyboard_wasm.wasm dist/"
    exit 1'
fi

# ---------------------------------------------------------------------------
testa "MusyBoard-Android"
if [ ! -f "$ANDROID/gradlew" ]; then
  salta "MusyBoard-Android" "non trovato in $ANDROID (MUSY_ANDROID per indicarlo)"
else
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
  if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(ls -d "$HOME"/jdks/jdk-21* 2>/dev/null | head -n 1)"
    export JAVA_HOME
  fi
  if [ ! -d "$ANDROID_HOME" ] || [ -z "$JAVA_HOME" ] || [ ! -d "$JAVA_HOME" ]; then
    salta "MusyBoard-Android" "ANDROID_HOME o JAVA_HOME non trovati"
  else
    # `runTests` e non `debug`: e' la variante che HeliBoard ha creato apposta
    # per i test, e salta quelli scritti per documentare difetti noti a monte
    # (`...Fails`), che nella variante debug falliscono per costruzione.
    # `-PsenzaRete` toglie XLinkTest, che interroga siti di terzi: puo'
    # diventare rosso senza che sia cambiato niente qui. Il riepilogo lo dice.
    # Niente `--quiet`, cosi' in caso di rosso la coda mostra quali test.
    passo "test JVM (Robolectric compreso)" "$ANDROID" ./gradlew :app:testRunTestsUnitTest -PsenzaRete
    NON_ESEGUITI+=("controlli dei link su internet (XLinkTest): dipendono da siti di terzi")
    # assembleDebug ricompila jni/ con cargo ndk dal core affiancato, e prima di
    # impacchettare controlla che nel manifest unito non sia entrato nessun
    # permesso fuori lista — INTERNET compreso.
    passo "APK (ricompila jni, controlla i permessi)" "$ANDROID" ./gradlew --quiet :app:assembleDebug
    if [ "$RAPIDO" = 1 ]; then
      NON_ESEGUITI+=("lint Android")
    else
      passo "lint di release" "$ANDROID" ./gradlew --quiet :app:lintVitalRelease
    fi
  fi
fi
NON_ESEGUITI+=("test strumentati Android (servono un emulatore, e sostituiscono l'identita')")

# ---------------------------------------------------------------------------
printf '\n'
for n in "${NON_ESEGUITI[@]}"; do printf '  non eseguiti: %s\n' "$n"; done
if [ "${#SALTATI[@]}" -gt 0 ]; then
  printf '\n%sVERDE, MA NON COMPLETO%s — %s da controllare:\n' "$G" "$N" "${#SALTATI[@]}"
  for s in "${SALTATI[@]}"; do printf '  - %s\n' "$s"; done
  exit 2
fi
printf '\n%sVERDE%s — core, ponti e app reggono insieme.\n' "$V" "$N"
exit 0
