# Automated checks run before the audit

Run on 2026-10-01 against the versions listed in [README.md](README.md).

| Check | Core (`tastieraNoCC`) | JNI bridge (`jni/`) |
|---|---|---|
| `cargo test` | 136 passed, 0 failed | 13 passed, 0 failed |
| `cargo clippy --all-targets` (crate lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `todo`) | clean | clean |
| `cargo audit` (RustSec, 1278 advisories) | no findings (48 crates) | no findings (70 crates) |
| `cargo deny check advisories bans licenses sources` | ok | ok |

`cargo deny` reports only duplicate versions of build-time crates (`syn`, and
in `jni/` also `thiserror`, `thiserror-impl`, `windows-sys`). All third-party
licenses are MIT, Apache-2.0 (with or without LLVM exception), BSD-1/3-Clause,
Unlicense or Unicode-3.0, all compatible with GPL-3.0. The configuration used
is:

```toml
[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause",
         "BSD-1-Clause", "Unlicense", "Unicode-3.0", "GPL-3.0-only"]
[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

## Fuzzing

`cargo +nightly fuzz`, 120 seconds per target on 2026-10-01, no crashes and no
artefacts:

| Target | Runs |
|---|---:|
| `roundtrip` (builds valid blobs of every format, re-parses, then corrupts and truncates them) | 612,077 |
| `parse` | 38,409,521 |
| `decode` | 61,960,761 |

Earlier longer campaign recorded in `CLAUDE.md`: about 146 million inputs in
total, no crashes.

## Android

- JVM unit tests: 211/211 passing (`testRunTestsUnitTest -PsenzaRete`, which
  excludes upstream HeliBoard tests that were already broken and tests that
  need the network).
- `lintVitalRelease`: passing.
- Instrumented tests (Keystore, backup round trip, part queue): last run
  2026-09-04, 9/9 passing.
