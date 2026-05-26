# Changelog

All notable changes to `@aithos/assets-crypto` will be documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the v0.x line subject to alpha-period API drift.

## [Unreleased]

## [0.1.0-alpha.1] — 2026-05-21

Initial alpha release.

### Added

- AMK (Asset Master Key) generation via the system CSPRNG (`generateAMK`).
- X25519-HKDF-SHA256-AEAD wrap construction addressed to a recipient's
  X25519 public key (`wrapAMKForRecipient`).
- Matching unwrap with AAD-binding verification (`unwrapAMK`). AAD
  binds to `(asset_urn, recipient_did_url)` to prevent cross-asset and
  cross-recipient replay.
- Asset bytes encryption with XChaCha20-Poly1305 IETF in the canonical
  nonce-prefix on-disk layout (`encryptAssetBytes`). Returns the blob
  ready to PUT to S3 plus the metadata fields
  (`sha256_of_plaintext_hex`, `size_bytes`, `nonce_b64`).
- Matching decrypt with optional plaintext SHA-256 verification
  (`decryptAssetBytes`).
- Public-regime SHA-256 verification helpers (`plaintextSha256Hex`,
  `verifyPlaintextHash`).
- Wire-format types (`AssetMetadata`, `AMKEnvelope`, `WrapEntry`,
  `AssetReference`, `AttachedContext`, `StorageDescriptor`,
  `AssetState`).
- `AssetsCryptoError` class with error codes mapping to
  `spec/assets/05-api-primitives.md` §5.5.
- 19 test vectors covering the scenarios in
  `spec/assets/02-key-hierarchy.md` §2.8: roundtrips, AAD bindings,
  AMK rotation, tampered ciphertext rejection, recipient binding,
  empty plaintext edge case, deterministic encryption with explicit
  nonce.

[Unreleased]: https://github.com/aithos-protocol/aithos-protocol/compare/assets-crypto-0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/aithos-protocol/aithos-protocol/releases/tag/assets-crypto-0.1.0-alpha.1
