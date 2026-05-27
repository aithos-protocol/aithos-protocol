# Changelog

All notable changes to `@aithos/protocol-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-05-27

Purely additive minor release introducing the **sponsorship primitive**
defined in `spec/drafts/sponsorship-mandate-v0.1.md` (draft §13). No
existing API changes shape or behaviour. The new surface is **experimental
until §13 is promoted to a normative chapter**; expect minor breaks to the
sponsorship-specific types before v1.0.

### Added
- **Sponsorship mandates** (draft §13.3). New module
  `@aithos/protocol-core/sponsorship`:
  - `SponsorshipMandate` — signed by a sponsor declaring it will absorb
    the cost of operations performed by consumers within explicit budget
    and scope. Includes `audience` (open or list), `scopes`,
    `allowed_methods`, optional `allowed_models`, a `budget` object
    (per-user, per-day, lifetime pool caps in an authority-defined `unit`),
    and an `accounting_authority` pointer (DID + endpoint).
  - `createSponsorshipMandate`, `verifySponsorshipMandate`,
    `sponsorshipMandateHash` (canonical SHA-256 used for envelope binding).
- **Consumption receipts** (draft §13.5). `ConsumptionReceipt` — signed by
  the accounting authority on every debit, binding `(sponsor, consumer,
  envelope, amount)` into one attestation. `createConsumptionReceipt`,
  `verifyConsumptionReceipt`. Carries `funded_by ∈ { "sponsored",
  "purchase", "grant" }`.
- **Sponsorship revocations** (draft §13.9). `createSponsorshipRevocation`
  reuses the existing `Revocation` shape with the new `mandate_kind`
  discriminator set to `"sponsorship-mandate"`.
- **Eligibility decision** (draft §13.7). `evaluateEligibility(input)` —
  pure routing function used by an authority to decide whether a candidate
  sponsorship covers a call. Returns `{ ok, reason }` where `reason`
  enumerates: `ok | expired | not_yet_valid | method_blocked |
  model_blocked | audience_excluded | per_user_cap_reached |
  per_user_window_cap_reached | per_day_cap_reached | pool_cap_reached |
  wallet_insufficient`.

### Changed (back-compatible, additive only)
- **`SignedEnvelope`** carries an optional `sponsorship?: { id, hash }`
  field. When present, the authority MUST verify the indicated sponsorship
  is eligible; when absent, the authority MAY auto-discover. The field is
  inside the signing bytes — an attacker cannot attach it after signing.
- **`Revocation`** carries an optional `mandate_kind?: "action" |
  "sponsorship-mandate"`. Absent ≡ `"action"` for back-compat with all
  prior revocation lists.
- **`signEnvelope` / `signEnvelopeWithMandate`** accept an optional
  `sponsorship` argument that is propagated into the signed envelope.

### Protocol
- New draft chapter: `spec/drafts/sponsorship-mandate-v0.1.md` (586 lines).
  Targets a new chapter §13 on promotion, with cross-references to §4
  (mandates), §10 (platform primitives), §11 (signed envelopes), and the
  v0.3 gamma draft (for V2 receipt anchoring).

### Notes
- The new `unit` field on `SponsorshipBudget` deliberately leaves the
  unit of account uninterpreted by the protocol. The reserved value
  `"aithos.mc"` denotes the platform microcredit, but authorities MAY
  accept any string (e.g. `"openai.tokens"`). This keeps the protocol
  free of any embedded currency or pricing assumption.
- Receipts are stored canonically at the authority in v0.1. V0.2 will
  introduce gamma-log anchoring (pending the `gamma-v0.3-per-entry-envelopes`
  draft landing and a `SponsorshipAcceptance` draft to grant the authority
  `gamma.write` on each party's log).

## [0.5.1] — 2026-05-01

### Fixed
- `package.json` `homepage`, `repository.url`, and `bugs.url` now point at
  `github.com/aithos-protocol/aithos-protocol` (the canonical org-level repo).
  Previous releases lingered on `github.com/Math1987/aithos-protocol` from a
  transient state of the move into the `aithos-protocol` GitHub org. This is
  metadata-only — no code changes.

## [0.5.0] — 2026-04-30

### License
- Reverted from **BUSL-1.1** back to **Apache-2.0**. The reference packages
  are once again under a permissive OSI-approved license, immediately and
  irrevocably for the `0.x` line. Rationale: at zero traction, BUSL costs more
  in adoption friction (excluded from distros, OSI-only enterprise policies,
  community pushback) than it protects. For a protocol, adoption *is* value.
  See ADR-0007 in `ARCHITECTURE-DECISIONS.md`.
- Source-file SPDX headers, package.json `license` fields, and per-package
  `LICENSE` files are all aligned on `Apache-2.0`.
- Version 0.4.0 (published under BUSL-1.1) remains under BUSL-1.1 for anyone
  who already obtained it.

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
