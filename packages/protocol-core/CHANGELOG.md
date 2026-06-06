# Changelog

All notable changes to `@aithos/protocol-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] — 2026-06-06

### Added

- **Encrypted `self` index (circle-clear / self-private).** The `self` zone
  hides its section titles from the host: titles/tags move out of the clear
  section descriptors into a per-zone `index_cipher` (XChaCha20-Poly1305 over
  `jcs(IndexEntry[])`, sealed to `#self-kex`; AAD = `"aithos-index-v1\0" ‖
  subject_did ‖ "\0" ‖ zone`). Structural fields stay clear so a keyless host
  still verifies integrity/presence/orphans. New `BundleZoneV2.index_encrypted` +
  `index_cipher`, `SectionDescriptor.title` now optional (absent on `self`),
  `ZONE_INDEX_ENCRYPTED` policy, `encryptZoneIndex` / `decryptZoneIndex` /
  `indexAad` / `readZoneIndex`. `authorBundleV03` seals the self index;
  `verifyBundleV03` enforces the per-zone index policy and (with the key)
  cross-checks the decrypted index against the clear section list. Tests B16/B16b.
- **Gamma op `bundle.migrate.v0.3`** reserved in the `GammaOp` vocabulary so
  strict verifiers accept the entry the keystore-native migration will emit
  (spec §3.10.3′; emitter ships with that work).
- **Bundle format v0.3 — per-section encryption** (opt-in; spec draft
  `spec/drafts/bundle-v0.3-per-section-encryption.md`). Every zone is split into
  independently-addressed per-section blobs: `public/<id>.md` plaintext,
  `circle|self/<id>.enc` ciphertext under a fresh per-section DEK. New
  `bundle-v03.ts`: `BundleZoneV2` / `SectionDescriptor` / `SectionCipher` types,
  per-section AEAD (`encryptSection` / `decryptSection`), unified `writeSection` /
  `readSection`, `buildManifestV2` + `authorBundleV03` with **byte-identical
  carry-forward** of unchanged sections (a one-section edit rewrites one blob), and
  `verifyBundleV03` implementing §3.8′ checks 1–8. `verifyBundleAtPath` now
  dispatches `aithos: "0.3.0"` bundles to the v0.3 verifier.
- **v0.2 ↔ v0.3 boundary** (`bundle-migrate.ts`): `decodeBundleV02` compat read
  (§3.10.2′), `readBundleSections` unified reader (dispatches on the `aithos`
  marker), and `migrateBundleV02ToV03` one-shot migration (§3.10.3′) that splits a
  v0.2 bundle into per-section blobs and chains the migration edition back to the
  unchanged v0.2 predecessor (no historical re-encryption — §3.10.4′).
- `AITHOS_VERSION_V03 = "0.3.0"` constant; `wrapDek` / `unwrapDek` exported so the
  v0.3 path reuses the identical X25519-HKDF-SHA256-AEAD key wrap.
- Conformance tests **B1–B15** (§3.12′) — the full v0.3 test matrix. Suite is
  115/115.

### Notes

- The per-section AEAD AAD binds `subject_did ‖ section_id`, **not** the draft's
  per-edition `bundle_id` — so unchanged sections carry forward byte-identical
  across editions (B3); cross-edition replay resistance is supplied by the manifest
  signature + `edition.prev_hash` chain. Spec §3.4.3′, the B5 row (now
  cross-subject), and the §3.11′ threat-model table were updated to match.
- **Backward compatible.** The on-disk bundle format version (`AITHOS_VERSION` /
  the manifest `aithos` field) stays at `0.2.0`: v0.3 is opt-in and read+written
  alongside v0.2, which remains the write default. The format default flips to
  `0.3.0` in a later release once v0.3 is promoted to normative.
- Deferred: the migration's `bundle.migrate.v0.3` gamma entry (part of the
  gamma-v0.3 op vocabulary, tracked separately).

## [0.6.6] — 2026-06-01

### Added

- **Optional dedicated `#data` sphere** on identities (spec/data/02-key-hierarchy.md
  §2.2). `Identity` gains an optional `data?: KeyPair`; `createIdentity` is now
  eager — new identities carry a `#data` keypair from creation. `writeIdentityToDisk`
  seals a `data.sealed.json`; `loadIdentity` loads it when present. `buildDidDocument`
  appends a `#data` verificationMethod + a `#data-kex` keyAgreement entry **after**
  the three Ethos spheres (the canonical 3-sphere shape is preserved for identities
  without a data key). `StoredSeed.role` widened to `SeedRole = "root" | Sphere | "data"`.

  Purpose: owner data/asset PDS envelopes will sign under `#data` so the root key
  stays cold and the data key can rotate independently — the convention the data
  sub-protocol always intended (until now the PDS forced `#root` via a resolver stub).

  **Backward compatible**: the field is optional. Identities, recovery files, and
  keystores created before this release (root/public/circle/self only) still load
  and operate; their DID document keeps exactly the three Ethos verification methods
  and verifies unchanged. No envelope wire-format change — all 96 conformance + byte
  snapshot tests pass, plus 4 new `#data` tests.

## [0.6.5] — 2026-06-01

### Fixed

- **`encoding.ts` is now `Buffer`-free so the verify/sign path runs in the
  browser.** 0.6.4 made the verify path *bundle* without `node:` built-ins, but
  `base64url` / `base64urlDecode` / `sha256Hex` still called the Node-only
  `Buffer` global, so at runtime a browser app throws `Buffer is not defined`
  the first time it signs an envelope (e.g. the example app's data flow). These
  now use the cross-platform `btoa`/`atob` and manual hex, producing
  byte-identical output (verified against `Buffer` over hundreds of random
  vectors, plus a sign→verify roundtrip). No wire-format change.

## [0.6.4] — 2026-06-01

### Changed

- **Verification path is now browser-bundleable (no `node:` imports).** The
  envelope/mandate verify graph (`envelope.ts` → `mandate.ts` → `did.ts` +
  `encoding.ts`) no longer statically imports `node:fs`/`node:path`/`node:crypto`.
  Previously `envelope.ts` pulled `base64url`/`verifyMandate` from modules that
  also carried the filesystem keystore, so a browser bundler (Vite/Rollup) would
  externalize node built-ins and fail with errors like _"join is not exported by
  __vite-browser-external"_ even though the keystore is never called client-side.
  Now:
  - New `encoding.ts` holds `base64url` / `base64urlDecode` / `sha256Hex`
    (node-free). Re-exported from `identity.ts` for backward compatibility.
  - `signWithSphere` / `sphereDidUrl` / `rootDid` moved to `did.ts` (they operate
    purely on an in-memory `Identity`). Internal callers updated.
  - The mandate filesystem keystore (`writeMandate`, `loadMandate`,
    `writeRevocation`, `loadRevocation`, `findRevocation`) moved to a new
    node-only `mandate-store.ts`. Still re-exported from the package barrel, so
    CLI imports are unchanged.
  - `mandate.ts` now sources its CSPRNG from `@noble/hashes/utils`
    (cross-platform) instead of `node:crypto`.
  - `ed.etc.sha512Sync` is set inline in the verify-path modules so sync
    sign/verify works without relying on a side effect of importing the
    node-only `identity.ts`. `sideEffects` now whitelists those modules so the
    setup is never tree-shaken.
- New subpath exports `./encoding` and `./mandate-store`.

  No public API removed and no wire-format change: all 96 conformance + byte
  snapshot tests pass unchanged. Purely a module-boundary refactor so the same
  verify code bundles in the browser.

## [0.6.3] — 2026-05-31

### Added

- **Pluggable async signer for envelopes (`signEnvelopeWith`).** A seed-free
  signing path that injects the Ed25519 operation as an async callback, letting
  hosts that hold non-extractable keys (WebCrypto `crypto.subtle`, the
  `@aithos/sdk` `EnvelopeSigner`) sign without ever surfacing seed bytes — while
  sharing this module's canonicalization, so their envelopes are byte-identical
  to the seed-based path. Also exposes the building blocks `buildUnsignedEnvelope`
  and `attachProof`, and now **exports `envelopeSigningBytes`**. `signEnvelope` /
  `signEnvelopeWithMandate` are unchanged on the surface (re-wired internally onto
  the shared builder). Additive, non-breaking — conformance proven by
  `envelope-pluggable-signer.test.ts`.

### Changed

- **`package.json` now declares `sideEffects: false`,** letting bundlers
  tree-shake unused exports — this keeps the envelope-verification subset lean
  when imported by serverless hosts (e.g. the gateway-middleware lambdas, which
  pull only `canonical` / `envelope` / `mandate` via subpath exports).

## [0.6.2] — 2026-05-30

### Added

- **Append-only data scope `data.<collection>.append`.** A new *lateral*
  capability — deliberately outside the `read ⊂ write ⊂ admin` hierarchy
  (mirrors `gamma.write`) — that authorizes `insert_record` ONLY. Helpers
  `isDataAppendScope` / `hasDataAppendScope`. `createMandate` now requires
  `grantee.pubkey` for append mandates (the depositor signs each insert
  envelope), but NOT `kex_pubkey`: an append holder seals each DEK to the
  owner's public key (`@aithos/data-crypto` `encryptRecordForRecipient`) and
  gains no read capability — it cannot decrypt anything in the collection,
  not even its own deposit. Enables the "deposit without read" pattern
  (e.g. Délie: a patient drops a long-lived mandate into the practitioner's
  collection without being able to read other patients' deposits). The
  per-method enforcement (insert allowed, read/update/delete refused) lives
  in the data-backend; `append` is never treated as a write scope here.

## [0.6.1] — 2026-05-30

### Added

- **`validateScopesAgainstSphere` permits `data.*` scopes under the public
  sphere.** Data access scopes (`data.<collection>.<action>`, `spec/data`)
  are sphere-neutral — the access axis is the collection and the binding is
  the grantee key + CMK wrap, not the sphere. They are now accepted under
  every `actor_sphere`, including `public`, enabling combined mandates like
  `ethos.read.public` + `data.<col>.read`. Mint-side only — the verify path
  is unchanged. Mirrors `@aithos/protocol-client` — kept in lockstep.

## [0.6.0] — 2026-05-27

Adds the **sponsorship primitive** defined in
`spec/drafts/sponsorship-mandate-v0.1.md` (draft §13). Composes naturally
with the `compute.invoke` scope introduced in 0.5.1 (mandate envelope
v0.4.0): the per-mandate `constraints.compute` caps bound a delegate's
spend within a single user's wallet, while the new `SponsorshipMandate`
caps bound an app's spend across many users. Two complementary economic
dimensions, two signed primitives, fully composable.

The new surface is **experimental** until §13 is promoted to a normative
chapter; expect minor breaks on sponsorship-specific types before v1.0.
Existing APIs (envelope, mandate, ethos, gamma) unchanged.

### Added
- **Sponsorship mandates** (draft §13.3). New module
  `@aithos/protocol-core/sponsorship`:
  - `SponsorshipMandate` — signed by a sponsor declaring it will absorb
    the cost of operations performed by consumers within explicit budget
    and scope. Includes `audience` (open or list), `scopes` (e.g.
    `compute.invoke`), `allowed_methods`, optional `allowed_models`, a
    `budget` object (per-user, per-day, lifetime pool caps in an
    authority-defined `unit`), and an `accounting_authority` pointer
    (DID + endpoint).
  - `createSponsorshipMandate`, `verifySponsorshipMandate`,
    `sponsorshipMandateHash` (canonical SHA-256 used for envelope binding).
- **Consumption receipts** (draft §13.5). `ConsumptionReceipt` — signed
  by the accounting authority on every debit, binding `(sponsor,
  consumer, envelope, amount)` into one attestation. `createConsumptionReceipt`,
  `verifyConsumptionReceipt`. Carries `funded_by ∈ { "sponsored",
  "purchase", "grant" }`.
- **Sponsorship revocations** (draft §13.9). `createSponsorshipRevocation`
  reuses the existing `Revocation` shape with the new `mandate_kind`
  discriminator set to `"sponsorship-mandate"`.
- **Eligibility decision** (draft §13.7). `evaluateEligibility(input)` —
  pure routing function used by an authority to decide whether a
  candidate sponsorship covers a call. Returns `{ ok, reason }` where
  `reason` enumerates: `ok | expired | not_yet_valid | method_blocked |
  model_blocked | audience_excluded | per_user_cap_reached |
  per_user_window_cap_reached | per_day_cap_reached | pool_cap_reached |
  wallet_insufficient`.

### Changed (back-compatible, additive only)
- **`SignedEnvelope`** carries an optional `sponsorship?: { id, hash }`
  field. When present, the authority MUST verify the indicated
  sponsorship is eligible; when absent, the authority MAY auto-discover.
  The field is inside the signing bytes — an attacker cannot attach it
  after signing.
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
  introduce gamma-log anchoring (pending the
  `gamma-v0.3-per-entry-envelopes` draft landing and a
  `SponsorshipAcceptance` draft to grant the authority `gamma.write` on
  each party's log).

## [0.5.2] — 2026-05-10

### Fixed

- **`verifyMandate` now applies a clock-skew tolerance** (default 30s,
  per JWT/jose convention) on both `not_before` and `not_after` checks.
  Previously a mandate signed at time `T` and validated by a server
  whose clock ran 100ms behind was rejected as "Mandate not yet valid".
  Real-world clock drift between client and Lambda routinely produces
  sub-second skew; the strict comparison was generating spurious
  rejections that no caller had a reason to expect.

  New `MANDATE_CLOCK_SKEW_SECONDS_DEFAULT` constant exported.
  `verifyMandate(mandate, didDoc, now, options)` accepts an optional
  `options.clockSkewSeconds` to override (e.g. `0` for legacy strict
  behaviour, useful in tests). Symmetric: a 5-second-stale mandate is
  still accepted, also bounded at 30s — gives clients a small grace
  period after expiration where a delegate's in-flight request
  doesn't fall off a cliff.

  Tests added: `test/mandate-clock-skew.test.ts` covers acceptance
  within tolerance, rejection beyond it, opt-out via
  `clockSkewSeconds: 0`, and symmetric expiration behaviour.

## [0.5.1] — 2026-05-08

### Protocol — mandate envelope `0.4.0`
- **New scope `compute.invoke`** — opt-in, stand-alone capability that
  authorizes a delegate to spend the subject's compute credits via the
  Aithos compute proxy. NEVER implied by any `ethos.*` or `gamma.*`
  scope. A read-only mandate carries no token-spending authority,
  guaranteed at the protocol level.
- **New shape `constraints.compute`** — required when the scope is
  granted. Fields: `daily_cap_microcredits`, `total_cap_microcredits`,
  `max_credits_per_call`, `allowed_models`. At least one of the daily
  or total caps MUST be set — an unbounded compute mandate is
  rejected at mint AND at verify time. This is the "in conscience,
  voluntarily" invariant: a subject who authorizes spending is
  required to also bound it.
- **Mandate envelope bumped to `0.4.0`**. The verifier accepts
  `0.1.0`, `0.2.1`, `0.3.0`, and `0.4.0` for backward compatibility.
- **Compute mandates require `grantee.pubkey`**, like write mandates —
  bearer compute capabilities are forbidden by construction.

### Added
- `COMPUTE_INVOKE_SCOPE` constant (= `"compute.invoke"`).
- `ComputeConstraints` interface.
- `hasComputeInvokeScope(scopes)` predicate.
- `validateComputeAuthorization(scopes, constraints?)` — the
  protocol-level enforcement of the cap-required invariant. Called
  by `createMandate` and `verifyMandate`; also exported for hosts
  that build mandates outside the reference factory.

### Migration
- Existing 0.3.0 mandates without compute remain valid — the new
  invariant only fires when `compute.invoke` is present.
- Servers MUST refuse compute invocations under a mandate that does
  NOT carry `compute.invoke`. The compute-proxy patch lands separately.

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
