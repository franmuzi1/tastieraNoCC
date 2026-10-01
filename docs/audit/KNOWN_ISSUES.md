# Known issues, accepted risks and open questions

This file lists what we already know, so the audit time goes to what we do
not. "Accepted" means a deliberate decision recorded in `CLAUDE.md`; we are
still interested in arguments that a decision is wrong.

## 1. Accepted residual risks (by design)

| # | Residual | Where decided |
|---|---|---|
| R1 | `kc/` sentinel makes encrypted traffic matchable by one regex | Threat model, "Sentinel" |
| R2 | Sender public key in clear in static and epoch schemes, so messages from the same sender are linkable | Threat model; decision H removes it only for ephemeral/forward-secrecy schemes |
| R3 | Blob length reveals plaintext length (no padding except identity cards) | "Formato" |
| R4 | Identity cards remain statistically distinguishable over many samples (uniform length vs. text-like lengths) | "Formato" |
| R5 | Replay of any valid blob, including burn requests; only the composition time is shown | Decisions C and J |
| R6 | The 8 most recent prekeys survive a read (`CODA_MINIMA = 8`), so up to 8 already-read forward-secrecy messages can be reopened by someone who seizes the device | Decision I |
| R7 | The first message of an epoch conversation is encrypted to the identity and survives a burn | Decision J |
| R8 | Group messages have no forward secrecy and no author authentication (any member can forge a message that other members attribute to someone else) | Decision K1, K6 |
| R9 | Group size is visible from blob length (no decoy slots) | Decision K4 |
| R10 | Attachments are visible as `.kc` files of a given size | Decision G |
| R11 | Key change of a contact is not detected automatically on arrival, only when the user assigns the existing name to the new key | "Identità e TOFU" |
| R12 | No post-quantum protection; tier `2` reserved | Decision L |
| R13 | Plaintext in the Android UI layer lives in `String`/`CharSequence` and cannot be zeroized | "Segreti in memoria" |

## 2. Questions we would like answered

1. **Static vs. epoch-bootstrap key equivalence.** Schemes `0x01` and `0x09`
   derive the same AEAD key from the same inputs; only the flags byte in the
   AAD differs, and that byte is the one the blob declares. We rely on every
   opening function checking the expected scheme internally. Is there any path
   (core, JNI, CLI, GUI) that opens one as the other?
2. **Trial decryption cost.** A forward-secrecy blob that opens with nothing
   costs, in the worst case, `contacts × 64 × 2` X25519 operations (see the
   commit that raised `MAX_PREKEY_MIE` from 32 to 64). Is this a practical
   denial-of-service on a phone, given that blobs arrive by copy-paste?
3. **Auto-pinning on the static path.** A static (`0x01`) or epoch-bootstrap
   message from an unknown key is decrypted, its key is pinned without a label,
   and it becomes the current recipient for that app ("decrypting sets the
   recipient"). This is intended TOFU behaviour. Is the resulting UX safe
   against someone who pastes a blob from a fresh key into a chat?
4. **Group slot nonces.** `nonce_i = nonce XOR (i + 1)` on the last byte, with
   per-slot keys from a dedicated HKDF domain. We believe nonce reuse needs both
   the same member twice and the same index, which deduplication prevents.
   Please confirm.
5. **Group shuffle.** Fisher-Yates using `next_u32() % (i + 1)` with `i ≤ 8`.
   The modulo bias is negligible at this size; we mention it only for
   completeness.
6. **Backup parameter bounds.** On import, Argon2 parameters are bounded above
   (memory exhaustion) but **not below**. A backup we export always uses the
   defaults, and editing the header makes the file fail to open. A weak file
   could only come from someone else's tool. Should import also enforce a
   minimum?
7. **Epoch state and the burn timestamp.** `burned_at` and `seen_at` compare
   against `min(claimed time, local now)`. Four bugs of this "self-poisoning
   state" family were found and fixed. Are there more?

## 3. Android integration: open items

From an internal emulator audit on 2026-10-01 (report in Italian, not in the
repository; available on request). Fixed items are in release 0.18.6/0.18.7 but **not yet
verified on a physical device**.

| Item | Status |
|---|---|
| Recipient is per **app**, not per **conversation**: in an app with several chats (WhatsApp, Telegram) a half-written draft follows you into another chat, and the label under the compose row is the only guard against encrypting for the wrong person | **Open**, design decision pending |
| Draft plaintext stays in the keyboard's memory when you switch to an app where the compose row is suppressed | Open, intended so far |
| Turning the compose row off leaked the last word being composed into the app's field | Fixed in 0.18.6 |
| Text already delivered to the field was pulled back into the compose row after an app switch | Fixed in 0.18.6 |
| Fields that silently truncate (Android Messages, 2000 characters) left a truncated, undecryptable blob in the field | Fixed in 0.18.6 (truncation detected, per-app limit learned, message split) |
| Wrong explanation shown when a blob fails to open (shape classification) | Fixed in 0.18.6 |
| Auto-open of a copied blob could show an empty keyboard (fixed-delay window check) | Fixed in 0.18.7, root cause inferred, not reproduced |
| Not exercised in that audit: password and search fields, groups, attachments, "forget contact", burn, part queue across a forced stop, two different contacts in one app | Untested |
| API 21–22 (the app's `minSdk` is 21, but encryption needs API 23 and reports itself unavailable below) | Untested |

## 4. Discrepancies found while preparing this package

- `CLAUDE.md` stated `MAX_PREKEY_MIE = 32`; the code has had 64 since commit
  `f53d057`. Fixed in the document together with this package.
- `HANDOFF.md` in the core repository is a historical hand-off note from
  August 2026; its test counts and to-do list are out of date (for example
  `todo = "deny"` is already active). Treat `CLAUDE.md` and the code as current.
- The core repository's `android/` folder holds an unbuilt skeleton and
  prebuilt `.so` files that the app does not use.
- Until 2026-10-01 the core repository had no license file. It is now
  GPL-3.0-only.

## 5. Previous reviews

None external. All review so far has been internal (the author, with AI-assisted
code review and emulator testing). The fuzzing and KAT discipline is described
in `CLAUDE.md`, section "Test".
