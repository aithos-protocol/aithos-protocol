# @aithos/data-crypto — Changelog

## 0.1.2 — 2026-05-30

### Added

- **Append-only deposit primitives** (`spec/data/04-mandates.md` §4.2.3bis).
  `wrapDEKForRecipient` / `unwrapDEKForRecipient` seal a record's DEK to the
  owner's X25519 public key (distinct HKDF salt `aithos-data-dek-deposit-wrap-v1`
  and AAD domain bound to subject/collection/record/recipient).
  `encryptRecordForRecipient` / `decryptDepositedRecord` are the record-level
  helpers: a depositor encrypts and discards the DEK (no read capability),
  and only the owner's private `#data-kex` key recovers it.
- `RecordPayload` now carries either `dek_wrapped_for_cmk` (owner /
  read-write-delegate path) or `dek_wrapped_for_owner` (deposit path); the CMK
  decrypt/rewrap paths reject the deposit shape (and vice-versa) with precise
  error codes.

## 0.1.0 — 2026-05-14

Initial POC release. Validates the data sub-protocol cryptographic
construction described in `spec/data/02-key-hierarchy.md`.

### Added

- `generateCMK`, `wrapCMKForRecipient`, `unwrapCMK` — Collection Master Key
  primitives using X25519-HKDF-SHA256-AEAD wraps.
- `generateDEK`, `wrapDEKForCMK`, `unwrapDEKFromCMK` — Data Encryption Key
  primitives using XChaCha20-Poly1305 under the CMK.
- `encryptRecord`, `decryptRecord`, `rewrapRecordDEK` — Record-level
  encryption with AAD binding to `(subject_did, collection_name,
  record_id)`.
- `createCollection`, `authorizeApp`, `revokeApp`, `rotateCMK` — Collection
  lifecycle operations.
- Full Node:test suite covering:
  - CMK roundtrip
  - Record encrypt/decrypt for small and large payloads
  - Authorize app + decrypt as the newly-authorized app
  - Duplicate / unauthorized authorization rejection
  - Revoke + CMK rotation flow
  - AAD binding enforcement (cross-record / cross-collection /
    cross-subject replay rejected, tampered ciphertext detected)
- Benchmark suite documenting per-operation latency.

### Status

POC scope. No persistence, no RPC wrapping, no mandate verification
(reused from `@aithos/protocol-core` when integrated). The next jalon
(Backend MVP AWS) consumes these primitives in Lambda handlers.

### Performance baseline (Linux, Node 22)

| Operation | Latency |
|---|---|
| createCollection | ~2 ms |
| unwrap CMK | ~1 ms |
| **authorizeApp (O(1))** | ~3 ms |
| encrypt 1 KB record | ~0.1 ms |
| decrypt 1 KB record | ~0.07 ms |
| encrypt 10 KB record | ~0.8 ms |
| decrypt 10 KB record | ~0.6 ms |
| rotateCMK with 1000 records | ~21 ms |

Numbers are indicative; reproduce with `npm run bench`.
