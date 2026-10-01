# Audit scope, code map and how to build

## Repositories

| Repository | Role | License |
|---|---|---|
| `github.com/franmuzi1/tastieraNoCC` | Rust core (crypto, format, keyring logic) and JNI bridge | GPL-3.0-only |
| `github.com/franmuzi1/tastieraNoCC-app` (branch `cipher`) | Android app: HeliBoard fork + encryption UI | GPL-3.0 |

The exact commits under review are listed in [README.md](README.md).

## In scope

### A. Rust core (`tastieraNoCC/src/`), primary target

About 9,500 lines including inline unit tests and long design comments.

| File | Lines | Contents |
|---|---:|---|
| `baseline.rs` | 2268 | All sealing/opening schemes (§5 of PROTOCOL.md), KDFs, group construction |
| `api.rs` | 3352 | `Session`: scheme selection, incoming dispatch, trial decryption over contacts, prekey/epoch/burn state transitions, TOFU pinning |
| `format.rs` | 1554 | Envelope parsing/serialisation, flags, AAD, identity card |
| `keys.rs` | 973 | Identity, ephemeral and prekey secrets, low-order check, fingerprint, prekey store |
| `backup.rs` | 511 | Argon2id + XChaCha20-Poly1305 backup container |
| `file.rs` | 391 | Attachment metadata framing |
| `encoding.rs` | 302 | z-base-32 (strict) |
| `error.rs`, `lib.rs` | 121 | Error type, crate root |

Properties to check against the code: `#![forbid(unsafe_code)]`; clippy denies
`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
`arithmetic_side_effects`, `todo`; secrets are `Zeroizing` and have no
`Debug`/`Display`.

### B. JNI bridge (`tastieraNoCC/jni/`)

| File | Lines | Contents |
|---|---:|---|
| `jni/src/lib.rs` | 1604 | `extern "system"` entry points, each wrapped in `catch_unwind`; secrets cross as `byte[]` |
| `jni/src/keyring.rs` | 776 | On-disk serialisation of the keyring used by Android (versioned; epoch stored in its own field) |

This is the only place where `unsafe` is unavoidable.

### C. Android code that touches secrets or plaintext

In `tastieraNoCC-app`, `app/src/main/java/helium314/keyboard/cipher/`
(about 8,300 lines for the files below):

| File | Why it matters |
|---|---|
| `CipherKeystore.kt`, `CipherStorage.kt`, `CipherIdentity.kt` | At-rest protection of identity and keyring (AES-GCM key in Android Keystore), load/persist, backup import/export |
| `CipherCore.kt` | Kotlin side of the JNI contract (`IncomingResult` written from Rust) |
| `CipherCompose.kt` | The plaintext composition buffer inside the keyboard ("compose row"): which app owns it, when it is cleared, suppression on password and non-message fields |
| `CipherActions.kt` | Encrypt/deliver to the app field, send-plain, decrypt, clipboard auto-open, multipart messages |
| `CipherParti.kt` | Queue of pending ciphertext parts persisted to disk |
| `CipherPanel.kt`, `CipherSchermoProtetto.kt`, `DecryptActivity.kt` | Where plaintext is shown; `FLAG_SECURE` handling |
| `CipherHandoff.kt` | Token proving which app a decrypt request came from (recipient attribution) |
| `CipherFields.kt` | Classification of input fields (password, search, etc.) |
| `CipherFiles.kt`, `CipherFileProvider.kt` | Attachments: cache handling, share intents |
| `CipherNotification.kt`, `CipherKeepAlive.kt` | Notification carrying a blob; foreground service |
| `ContactsActivity.kt`, `RecipientActivity.kt` | Contact pinning, labels, verification, recipient choice, backup UI |

Hooks into HeliBoard: `latin/LatinIME.java` (the input connection is
redirected to the compose buffer: `getCurrentInputConnection`,
`onUpdateSelection`, `onCipherSelectionChanged`, `onCipherTargetChanged`,
`onWindowShown`) and the clipboard listener in `ClipboardHistoryManager`.

## Out of scope

- The rest of HeliBoard (layouts, dictionaries, suggestions, settings UI).
- `cli/` and `gui/` (desktop tools that use the same core) and the iOS bridge.
- The `android/` folder of the core repository: an old, unbuilt skeleton.
  It still contains prebuilt `.so` files that are **not** used by the app,
  which builds the library from source.
- Anything in the threat model's "out of scope" list (endpoint compromise,
  metadata, quantum adversary).

## Building and testing

Requirements: stable Rust (the tree was last built with rustc 1.96), a
nightly toolchain only for fuzzing, and for Android: JDK 21, Android SDK,
NDK 28.0.13004108, `cargo-ndk`.

```sh
# Core
cd tastieraNoCC
cargo test                       # 136 unit tests, including frozen KATs
cargo clippy --all-targets

# JNI bridge (separate workspace)
cd jni && cargo test && cd ..

# Fuzzing (cargo-fuzz, nightly). Targets: decode, parse, roundtrip
cargo +nightly fuzz run roundtrip   # builds valid blobs of every format, then mutates them
cargo +nightly fuzz run parse
cargo +nightly fuzz run decode

# Everything that depends on the core (core, jni, cli, gui, Android, iOS)
./verifica-tutto.sh
```

```sh
# Android app (expects the core checked out next to it as ../tastieraNoCC,
# or pass -PcipherCorePath=/path/to/tastieraNoCC)
cd tastieraNoCC-app
export ANDROID_HOME=/path/to/sdk JAVA_HOME=/path/to/jdk-21
./gradlew :app:assembleDebug                         # builds the Rust .so with cargo-ndk, then the APK
./gradlew :app:testRunTestsUnitTest -PsenzaRete      # JVM tests, excluding known-broken upstream tests
./gradlew :app:connectedDebugNoMinifyAndroidTest     # instrumented tests (Keystore, backup, part queue)
```

The last recorded fuzzing run: about 146 million inputs in total (decode 79M,
parse 62M, roundtrip 4M), with no crashes. Crash artefacts, if any, are kept
under `fuzz/artifacts/`.

## Design documents

- [PROTOCOL.md](PROTOCOL.md): byte-level specification, written for this audit
  from the code.
- [THREAT_MODEL.md](THREAT_MODEL.md).
- [KNOWN_ISSUES.md](KNOWN_ISSUES.md): accepted residual risks, open questions,
  and discrepancies found while preparing this package.
- `CLAUDE.md` in the core repository: the full design log with the rationale
  for every closed decision (in Italian). Decisions are referred to by letter
  (C, D, F, G, H, I, J, K, L) in the code and in these documents.
- `CIPHER.md` in the app repository: Android-side design notes (in Italian).
