# Changelog

All notable changes to `@aithos/protocol-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-04-28

### License
- Switched from **Apache-2.0** to **Business Source License 1.1** (**BUSL-1.1**).
  **Change Date:** 2030-12-31. **Change License:** Apache-2.0. See `LICENSE`.
  Artifacts previously published under Apache-2.0 remain under that license for
  anyone who obtained those versions.

## [0.3.1] — 2026-04-22

Purely additive point release. No behaviour changes on existing APIs; new
exports unlock the pluggable-backend story for `@aithos/mcp@0.4.0` and the
remote-platform adapter `@innoesate/aithos-platform-mcp-remote`.

### Added
- **Signed-envelope helpers** (spec §11). `signEnvelope`,
  `signEnvelopeWithMandate`, and `verifyEnvelope` (the 9-step §11.4 check).
  `envelopeParamsHash`, `ENVELOPE_VERSION`, `ROOT_ONLY_DIRECT_METHODS`,
  `NEVER_DELEGABLE_METHODS`, and `delegateMultibaseFromSeed` are also
  exported. Pure logic: replay state, DID resolution and revocation lookups
  are injected through a `VerifyEnvelopeContext`, so the same code runs in
  the CLI, the reference Lambda, and any other host.
- **Pluggable storage backend** — `AithosStorage` interface (resource-oriented,
  async, handle-based) lets hosts that embed the protocol swap the default
  filesystem keystore for a remote or in-memory implementation.
- **`FilesystemStorage`** — the default backend that wraps the existing
  `~/.aithos/` helpers. Re-exports cover every existing CLI entry point, so
  no behaviour change for current consumers.
- **Write-auth plumbing** — `WriteAuth`, `SectionWriteResult`,
  `AddSectionArgs`, `ModifySectionArgs` types are promoted to public exports
  so pluggable storage implementations can type their own write paths.

### Protocol
- No spec change. §11 envelope logic was spec-first; this release just
  provides the reference implementation.

## [0.3.0] — 2026-04-22

**Breaking release.** Gamma log format break: per-entry asymmetric envelopes
replace the single-file symmetric seal.

### Added
- **Per-entry envelope format** (spec §10.5.1′). Each gamma entry carries its
  own `payload_ct` + `nonce` + a list of `envelopes`
  (X25519-HKDF-SHA256-AEAD + XChaCha20-Poly1305), one per recipient on
  `manifest.gamma.readers`. Entries also carry a `public_header`
  (unencrypted metadata: op, zone, timestamps, hashes, authored_by) that
  makes integrity verification possible without any key material.
- **`gamma.read` scope** — the new capability for joining
  `manifest.gamma.readers`. `hasGammaReadScope()` is the single predicate
  that gates the readers-list rewrap in `issueMandateWithRewrap`.
- **Forward-only readers contract** on `manifest.gamma.readers`
  (spec §10.5.4′). Envelopes are sealed at append time and never
  retro-sealed, so a reader added at edition N only sees entries emitted
  at or after edition N.
- **Integrity-only verification tier** (spec §10.14.2′). `verifyGammaLog`
  can run without any DEK or seed, walking per-entry hashes, Ed25519
  signatures, the prev-hash chain and the manifest anchor. Decryption is
  opportunistic — entries without an envelope for the caller are flagged
  `_access_denied: true` rather than throwing.
- **`readGammaLogForAuthor` / `gammaHeadForAuthor`** — the author-aware
  read surface used by `aithos gamma show/verify --mandate`.

### Changed
- **`issueMandateWithRewrap`** no longer implicitly grants gamma access.
  Zone DEK rewrap runs for any `ethos.read.<zone>` / `ethos.write.<zone>`
  scope; the readers-list entry is added ONLY when `gamma.read` is in
  the scope list. This is the v0.3 decoupling property (task #14).
- **Gamma file on disk** is now `{ "aithos-gamma-file": "0.3.0", entries: [ … ] }`.
  The old flat `{ ciphertext, nonce, aad, recipients }` envelope is gone.
- **Mandate version handshake** widened to accept `0.3.0` in addition to
  `0.1.0` and `0.2.1`.

### Protocol
- Spec source: `spec/drafts/gamma-v0.3-per-entry-envelopes.md`. The
  reference implementation in this package matches it section-for-section:
  the envelope builder, the per-entry hash (`§10.5.1′`), the
  access-denied marker (`§10.5.3′`), the forward-only readers property
  (`§10.5.4′`), the integrity tier (`§10.14.2′`).

### Migration
- `0.2.x` gamma bundles are **not** compatible. Re-author under `0.3.0`.

## [0.2.1] — 2026-04-22

Point release supporting mandate-driven writes against a tracked identity.

### Added
- `Author` abstraction: `OwnerAuthor | DelegateAuthor` threads through
  `persistEdition` and all mutation APIs.
- `authorized_by` field on zone / manifest / gamma signatures, set to the
  mandate id when a delegate authored the edition.
- Mandate `v0.2.1` with `grantee.pubkey` (multibase Ed25519) + RFC 7748
  §4.1 Edwards→Montgomery key conversion for X25519 DEK wraps.
- `issueMandateWithRewrap` — bumps a fresh edition + re-encrypts zone
  DEKs to include the delegate.
- `repinAfterRevocation` — rotates zone DEKs on revocation so the revoked
  delegate can no longer decrypt post-revocation editions.
- `keystoreDelegateResolver` — reusable delegate-pubkey resolver for
  stateless bundle verification (CLI, MCP, third-party verifiers).
- On-disk-bytes hash check for the public zone (previously rendered,
  which broke carry-forward editions).

## [0.2.0] — 2026-04-21

Breaking release. Section history moves from per-section `revisions[]` to
the signed gamma log. See `spec/10-gamma.md`.
