# MusyBoard / keyboard-cipher: security audit package

## The project in one paragraph

MusyBoard is an Android keyboard (a fork of the open-source HeliBoard) that
encrypts messages **inside the keyboard**, before the text reaches the chat
app, so that WhatsApp, Telegram, SMS or any other app only ever sees
ciphertext. The reference adversary is platform-side mass scanning of chat
content with bulk retention, such as the EU "Chat Control" proposal. The
cryptography lives in a small Rust core (X25519, XChaCha20-Poly1305,
HKDF-SHA-256, Argon2id for backups) with optional forward secrecy, a
re-readable "burnable" conversation mode, encrypted attachments and group
messages. The app has no `INTERNET` permission. Both repositories are
GPL-licensed and public.

## What we are asking for

A review of the **cryptographic design and its implementation** in the Rust
core and JNI bridge, and of the **Android code paths that handle keys or
plaintext**. See [SCOPE.md](SCOPE.md) for the exact files. The design has never
been reviewed externally.

The questions we care most about are at the end of
[THREAT_MODEL.md](THREAT_MODEL.md) and in section 2 of
[KNOWN_ISSUES.md](KNOWN_ISSUES.md). In short: can a message be encrypted for,
or attributed to, the wrong person; can one scheme or blob kind be confused for
another; can attacker-controlled values poison per-contact state; and does the
forward-secrecy bookkeeping really destroy what it claims to.

## Documents

| File | Contents |
|---|---|
| [PROTOCOL.md](PROTOCOL.md) | Byte-level specification of every format and scheme, written from the code |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Adversary, what is and is not protected, device assumptions, priorities |
| [SCOPE.md](SCOPE.md) | Repositories, files in scope with sizes, build/test/fuzz instructions |
| [KNOWN_ISSUES.md](KNOWN_ISSUES.md) | Accepted residual risks, open questions, open Android items, discrepancies |
| [PRECHECKS.md](PRECHECKS.md) | Results of the automated checks run before the audit |

## Versions under review

| Component | Reference |
|---|---|
| Rust core and JNI bridge | `franmuzi1/tastieraNoCC`, tag `audit-2026-10` |
| Android app | `franmuzi1/tastieraNoCC-app`, tag `v0.18.7-dev1` (branch `cipher`) |

The format is versioned and frozen per version (KAT-protected). If the audit
leads to changes, they will be made on top of these tags so that every finding
can be traced to the exact code it refers to.

## Size

- Rust core: about 9,500 lines in `src/` (including inline tests and long
  design comments), 136 unit tests, 3 fuzz targets.
- JNI bridge: about 2,400 lines.
- Android code in scope: about 8,300 lines of Kotlin, plus small hooks in
  HeliBoard's `LatinIME.java`.

## Contact

Maintainer: GitHub [`franmuzi1`](https://github.com/franmuzi1). Please report
vulnerabilities privately first, through GitHub's private vulnerability
reporting on either repository; we will publish the audit report and the
fixes.
