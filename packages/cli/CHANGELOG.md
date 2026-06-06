# Changelog

All notable changes to the Aithos reference CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] — 2026-06-06

### Changed
- **v0.3 (per-section) is now the default on-disk format.** `aithos init` /
  `aithos ethos init` create a v0.3 ethos, and the first owner `add/modify/
  delete-section` on an existing v0.2 keystore auto-migrates it in place to v0.3
  (the prior edition is archived under `history/`, and a one-line notice is
  printed to stderr). v0.2 installs stay readable. Set `AITHOS_FORMAT=v0.2` to
  keep a fresh install on the legacy format and suppress auto-migration.
- `aithos ethos pack`, `verify --handle`, and `list` now dispatch to the v0.3
  per-section path when the installed ethos is v0.3 (so they keep working on the
  new default); `init` reports the on-disk `Format:` line.
- **`aithos ethos migrate-to-v0.3 --in-place`** converts the live keystore ethos
  to v0.3 instead of writing a separate bundle.
- Requires `@aithos/protocol-core` `^0.8.0`.

## [0.7.0] — 2026-06-06

### Added
- **`aithos ethos migrate-to-v0.3`** — migrate a subject's v0.2 ethos into a
  v0.3 per-section bundle (decrypts with the owner's keys, splits each zone into
  per-section blobs, chains the migration edition back to the v0.2 predecessor).
  Writes a v0.3 bundle; the keystore ethos stays v0.2 until the format default
  flips.
- **`aithos ethos read`** — read a v0.3 bundle: `--index` prints the section
  index per zone (the encrypted `self` index is decrypted with `--handle`,
  otherwise titles show as `[hidden]`), `--section a,b,c` fetches one or several
  sections by id, `--zone` filters. This is the surface the hosting platform
  builds on.

### Fixed
- **`aithos mandate add`** now tracks `MANDATE_VERSION_CURRENT` from
  protocol-core instead of a hardcoded allowlist that had drifted to
  `0.1.0/0.2.1/0.3.0` — it rejected the current `0.4.0` mandates that `aithos
  grant` mints, breaking the grant→import flow.

### Changed
- Requires `@aithos/protocol-core` `^0.7.0` (per-section v0.3 bundle support).
- `--version` now reports the package version (was pinned to `0.4.0`).

## [0.6.0] — 2026-05-27

### Changed
- Bumped `@aithos/protocol-core` peer to `^0.6.0` to pick up the new
  sponsorship primitive (draft §13) alongside the existing
  `compute.invoke` scope and clock-skew tolerance from the
  protocol-core 0.5.2 line. The CLI itself does not yet expose
  sponsorship commands; this version bump exists so that users who
  reinstall the CLI resolve a protocol-core that contains the new types.
  Sponsorship commands (e.g. `aithos sponsorship create/revoke/show`)
  may be added in a later release once the draft stabilises.

### Notes
- No behaviour change in the existing command surface. All existing
  commands continue to work unchanged.

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

### Protocol
- Targets **`@aithos/protocol-core@^0.5.0`** (license-only bump in the library).

## [0.4.0] — 2026-04-28

### License
- Switched from **Apache-2.0** to **Business Source License 1.1** (**BUSL-1.1**).
  **Change Date:** 2030-12-31. **Change License:** Apache-2.0. See `LICENSE`.
  Artifacts previously published under Apache-2.0 remain under that license for
  anyone who obtained those versions.

### Changed
- `aithos --version` reports `0.4.0` (aligned with this package release).

### Protocol
- Targets **`@aithos/protocol-core@^0.4.0`** (license-only bump in the library).

## [0.3.0] — 2026-04-22

**Breaking release.** The gamma log switches from a single-file envelope
(one ciphertext sealed under the self sphere) to **per-entry asymmetric
envelopes**: each gamma entry carries its own `payload_ct` + a list of
`envelopes` (X25519-HKDF-SHA256-AEAD + XChaCha20-Poly1305), one per
recipient on `manifest.gamma.readers`. Bundles produced by `0.2.x` will
fail to verify against `0.3.0`; re-author under `0.3.0` or keep a pinned
`0.2.x` toolchain around for legacy bundles.

The whole point of the break is to **decouple zone writes from audit-log
reads**. In `0.2.x`, any `ethos.write.<zone>` mandate implicitly opened the
gamma log (the writer needed the log's symmetric key to append). In `0.3.0`
a mandate with `ethos.write.<zone>` alone can append new gamma entries
(signed by the delegate under `authorized_by: mandate_…`) but CANNOT read
any existing entry: every entry comes back with `_access_denied=true`.
Reading the log requires the new explicit `gamma.read` scope, which is the
only way to join `manifest.gamma.readers`.

This gives three clean capability profiles:

- `ethos.write.<zone>` — append-only writer. Can emit signed gamma
  entries but can't read the log or its own writes.
- `ethos.read.<zone>` — zone reader. Sees current zone content, the
  audit log stays opaque.
- `gamma.read` — auditor. Sees decrypted gamma entries (forward-only —
  envelopes are not retroactively resealed for readers added after the
  fact). Does not grant zone access by itself.

### Added
- **`aithos ethos show --mandate / --agent-key` extended to all CRUD ops
  and to `aithos gamma show/verify`.** Delegates can now walk the gamma
  log on a tracked install without owner seeds — the command resolves the
  delegate author, decrypts the envelopes it has a wrap for, and flags
  the rest with `_access_denied=true` rather than throwing.
- **New mandate scope `gamma.read`.** Adds the delegate to
  `manifest.gamma.readers` on `issueMandateWithRewrap`; every subsequent
  gamma entry seals an envelope for them.
- **Integrity-tier `gamma verify`.** The chain walk (per-entry hash +
  Ed25519 signature + manifest anchor) runs without any key material, so
  an external verifier can validate the log's integrity from a bundle
  without ever holding a sphere seed or a gamma DEK wrap.
- **`aithos mandate add` now accepts `aithos-mandate@0.3.0`** alongside
  `0.1.0` and `0.2.1`.

### Changed
- **`aithos grant` decouples zone rewrap from gamma readers.** The rewrap
  step (new edition, zone DEK sealed to the delegate) runs whenever the
  mandate includes `ethos.read.<zone>` / `ethos.write.<zone>`; the delegate
  is added to `manifest.gamma.readers` **only** when `gamma.read` is in the
  scope list. Prior behaviour — where any ethos-touching mandate opened
  the gamma log — is gone.
- **Gamma on-disk file format.** `gamma/gamma.jsonl.enc` is now a JSON
  envelope `{ "aithos-gamma-file": "0.3.0", entries: [ { payload_ct,
  envelopes, public_header, signature, hash, ... } ] }`. The old flat
  `{ ciphertext, nonce, ... }` shape is gone.
- **CLI version stamp bumped to `0.3.0`.**

### Protocol
- Targets **`@aithos/protocol-core@^0.3.0`**. Picks up: per-entry envelope
  format (spec §10.5.1′), the `gamma.read` scope (§4), the forward-only
  readers-list contract on `manifest.gamma.readers` (§10.5.4′), the
  integrity-only verification tier (§10.14.2′), `hasGammaReadScope()` in
  `issueMandateWithRewrap`, and the per-entry `_access_denied` marker
  surfaced by `readGammaLogForAuthor`.

### Tested
- New E2E scripts under `examples/` pin every scope profile:
  - `e2e-write-only-mandate.sh` — append-without-read (THE property).
  - `e2e-read-only-mandate.sh` — zone read, gamma opaque.
  - `e2e-gamma-read-only-mandate.sh` — auditor.
  - `e2e-crud-no-gamma-read.sh` — full zone CRUD with opaque audit log.
  - `e2e-multi-zone-mandate.sh` — `gamma.read` is zone-agnostic.
  - `e2e-public-read-mandate.sh` — degenerate case (no capability gain).
  - `e2e-revoke-regrant.sh` — revocation + fresh re-grant cycle.
- Existing `e2e-gamma-access-control.sh` updated for the v0.3 matrix
  (cases A–E) including the per-entry `payload_ct` tamper detection.

### Migration
- `0.2.x` bundles are **not** forward-compatible. An owner upgrading from
  `0.2.x` should re-author under `0.3.0`:

      aithos init --handle <h> --display-name "<…>"
      # re-add sections via ethos add-section …

- Existing `0.2.x` mandates remain valid as signed documents, but their
  DEK wraps target the old gamma format and will not decrypt a `0.3.0`
  log. Re-issue the mandate with `aithos grant …` under `0.3.0`.

## [0.2.1] — 2026-04-22

Point release. Closes the loop on **mandate-driven writes against a tracked
identity**: a delegate now produces a fully verifiable edition (signed manifest,
signed gamma entries, sealed zones) without ever holding the owner's sphere
seeds, and the owner can pull that edition back into their own keystore in one
command.

### Added
- **`aithos ethos install --force` on owned identities.** Lets an owner pull a
  delegate-produced edition back into their local keystore without touching the
  sealed sphere seeds (only `did.json`, `manifest.json`, the zone files, and the
  gamma log are overwritten).
- **`aithos mandate add` accepts both `aithos-mandate@0.1.0` and `0.2.1`
  mandates.** The version handshake is widened so a tracked installer can import
  v0.2.1 mandates carrying `grantee.pubkey` and the X25519 DEK wrap needed for
  delegate writes.
- **`aithos ethos show --mandate <id> --agent-key <path>` on tracked installs.**
  Closes the read-side asymmetry: delegate writes worked end-to-end in 0.2.1,
  but reading an encrypted zone on a tracked install still required owner
  seeds. A delegate carrying an `ethos.read.<zone>` scope can now decrypt
  the zone via its DEK wrap without ever touching sealed sphere material.
  Shares the same `resolveAuthor` validation pipeline as write commands
  (scope match, pubkey match, window, revocation).

### Changed
- **`aithos ethos install` now verifies delegate-signed bundles.** The install
  path threads a keystore-aware delegate-pubkey resolver into stateless bundle
  verification, so manifests/zones carrying `authorized_by: mandate_…` resolve
  the agent's signing key from the locally-installed mandate (verified, not
  revoked, matching grantee binding).
- **CLI version stamp bumped to `0.2.1`.**

### Protocol
- Targets **`@aithos/protocol-core@^0.2.1`**. Picks up: the `Author`
  abstraction (`OwnerAuthor | DelegateAuthor`), `authorized_by` on zone /
  manifest / gamma signatures, mandate v0.2.1 with `grantee.pubkey` + the
  RFC 7748 §4.1 Edwards→Montgomery key conversion, DEK rewrap on
  `issueMandateWithRewrap`, DEK repin on `repinAfterRevocation`, the
  `keystoreDelegateResolver` factored out for reuse, and the on-disk-bytes
  hash check for the public zone (previously rendered, which caused
  carry-forward editions to fail their own verification).

### Tested
- New end-to-end CLI scenario (`packages/cli/test/cli-delegate-e2e.test.ts`)
  driving the built `aithos` binary through: owner init → delegate-key →
  grant → pack → install on a fresh `AITHOS_HOME` → mandate add → delegate
  add-section → pack back → owner re-install (`--force`) → ethos verify →
  revoke → post-revocation pack → next delegate write fails closed
  (DEK no longer wrapped to the revoked grantee).

## [0.2.0] — 2026-04-21

**Breaking release.** Section mutation history is now recorded exclusively in
the **gamma log** — an append-only, hash-chained, Ed25519-signed JSONL stream
sealed under the self sphere. The per-section `revisions[]` hash chain that
shipped in `0.1.x` is gone. Old `.ethos` bundles produced by `0.1.x` will fail
stateless verification against `0.2.0`; migration is out of scope for this
release (re-author the ethos under `0.2.0`).

### Added
- `aithos ethos modify-section` — replace a section's title, body, tags, or
  clear its tags. Every mutation is recorded as a single signed entry in the
  gamma log; the live `<zone>.md` holds only the current state.
- `aithos ethos delete-section` — forget a section from the live document.
  The section is removed from the zone markdown, but the deletion itself is
  recorded as a signed gamma entry ("live forgets, gamma remembers").
- `aithos gamma show` — walk the signed mutation history in chronological
  order.
- `aithos gamma verify` — full chain walk: every entry's `prev` matches the
  previous `hash`, every signature verifies under the recorded key, and the
  final entry matches the manifest's `gamma.head` anchor.
- Section markdown headers carry a `gamma_ref` comment pointing to the latest
  gamma entry affecting the section.
- `.ethos` bundles now include `gamma.jsonl.enc` — the sealed gamma log —
  alongside `manifest.json`, `did.json`, and the three zone markdowns.
- Manifest gains a `gamma` anchor (`{head, count, url?}`) that commits to the
  gamma log's current tail. Stateless verification cross-checks the anchor.

### Removed — breaking
- `aithos ethos add-revision` — replaced by `modify-section`.
- Per-section `revisions[]` arrays in zone markdown.
- `signatures/` directory in `.ethos` bundles — gamma log supersedes it.
- `aithos ethos show --revisions` — section history now lives in the gamma
  log; use `aithos gamma show` to walk it.

### Changed
- `aithos ethos show` prints the section's current body only. History is
  obtained via `aithos gamma show`.
- `aithos ethos list` row shape: `ZONE | ID | GAMMA_REF | UPDATED | TITLE`.
- `aithos ethos verify` now cross-checks the manifest's gamma anchor against
  the log tail (when the sphere key is available) and warns rather than walks
  when verifying a packed bundle with a sealed log.
- Manifest `aithos` field stamped as `0.2.0`. Zone markdown frontmatter stamp
  follows.

### Protocol
- New normative chapter: **spec §10 — Gamma log**. Defines the entry schema,
  the chain + signature invariants, the manifest anchor, and the bundle
  layout. Supersedes the per-section hash chain from the `0.1.x` draft.

## [0.1.2] — 2026-04-20

Internal refactor. No functional changes, no wire-format changes, no keystore
changes. Same commands, same flags, same output. If you install `aithos@0.1.2`
and run it against a `0.1.0` or `0.1.1` keystore, everything keeps working.

### Changed
- Protocol primitives (DIDs, identities, ethos, mandates, bundles, canonical
  hashing) are now shipped as a separate library, **`@aithos/protocol-core`**,
  and consumed by the CLI as a normal dependency. The repository has moved to
  an npm workspace layout: `packages/protocol-core`, `packages/cli`,
  `packages/mcp`.
- The CLI itself (the `aithos` command) is unchanged on disk and on the
  network: every command, every flag, every exit code, every output format is
  identical to `0.1.1`. The `.ethos` bundle format, the `did:aithos` method,
  the mandate and revocation schemas, and the on-disk keystore layout are all
  byte-for-byte compatible.

### Why
So that any Aithos-speaking host — the reference CLI, the MCP server, the
forthcoming platform Lambdas, or a third-party implementation that wants to
reuse the reference primitives — can depend on exactly one source of truth
for the protocol. Any subtle difference in hashing, canonicalization, or
signature verification would break interoperability; `@aithos/protocol-core`
is now that single source.

## [0.1.1] — 2026-04-20

Point release. Closes the functional gap where a received `.ethos` bundle
could be unpacked but not consulted through the keystore commands.

### Added
- `aithos ethos verify --path <dir|.ethos>` — **stateless** bundle verification.
  Accepts either a directory in flat bundle layout or a `.ethos` zip. Does not
  touch the local keystore. Exit codes per spec §9.4: `0` valid, `1` invalid,
  `2` unparseable. Performs spec §3.8 checks 1, 2, 3, 4, 6, 8 unconditionally
  and checks 5, 7 fully for the `public` zone; content checks on encrypted
  zones are skipped (zone signatures are over plaintext, so no decryption key
  means no verification) and reported as warnings.
- `aithos ethos install <path>` — install a `.ethos` bundle into the local
  keystore as a **tracked identity** under `~/.aithos/identities/<handle>/`.
  Converts the bundle's flat layout into the nested native layout consumed by
  `ethos list` / `ethos show` / `ethos verify --handle`. Refuses to install an
  invalid bundle, to overwrite an owned identity (sealed seeds present), or to
  silently replace an existing tracked identity (requires `--force`). Flags:
  `--as <handle>` to override the manifest's `subject_handle`, `--set-default`
  to mark the identity as the keystore default.
- `aithos mandate add <path>` — import a mandate received out-of-band.
  Verifies the signature against the issuer's DID document, auto-discovered
  from the local keystore (owned or tracked) or supplied via `--did <path>`.
  Idempotent on a byte-identical mandate; refuses to silently overwrite a
  different mandate at the same id (requires `--force`); surfaces a warning
  when a revocation for the mandate is already on file. Optional
  `--allow-expired` for archival imports.

### Fixed
- Unpacking a bundle into `~/.aithos/identities/<handle>/` via `ethos unpack`
  used to leave the keystore in a state where `ethos list --handle <h>` and
  `ethos verify --handle <h>` reported `No ethos for "<h>"`. The supported path
  is now `ethos install <bundle>`, which produces the nested native layout
  those commands expect.

### Protocol
- New chapter: spec §9 — **Local store**. Defines owned vs tracked identities,
  the `ethos install` semantics, stateless `ethos verify --path` scope, and
  the `mandate add` intake flow. SPEC.md and the spec chapter map updated.

## [0.1.0] — 2026-04-19

First public release, published alongside the **birth** of the Aithos protocol.

### Added
- `aithos identity` — create, list, and inspect `did:aithos` identities (three sphere
  keys: public, circle, self; Ed25519 signing + X25519 key agreement).
- `aithos ethos` — author an ethos document as append-only revisions, pack it into
  a signed `.ethos` bundle (RFC 8785 canonical JSON + Ed25519 signatures over the
  three zones), and unpack / verify bundles produced by anyone.
- `aithos mandate` — grant a scope-limited, time-bounded mandate to a named
  agent, revoke it unilaterally, and verify its signature chain.
- `birth/` artifacts bundled in the package — the protocol's own signed birth
  record. Available at `node_modules/aithos/birth/` after installation:
  - `birth.json` — protocol-native birth record.
  - `birth-declaration.md` — human-readable declaration.
  - `aithos-birth.ethos` — signed ethos bundle, verifiable with `aithos ethos verify`.
  - `did.json` — DID document of the ceremonial founding identity
    `did:aithos:z6Mkeu1UTXwL4djF9JmH5idEAF5t7g3bHjvJTBGeWqX5qPpA`.

### Protocol
- Targets Aithos protocol **v0.1.0 (draft)**. The wire format may change on any
  minor-version bump until `1.0.0`.

### Known issues
- The ethos section-split regex (`src/ethos.ts` around line 336) treats a line
  starting with `# ` inside a revision body as a section boundary, which breaks
  the plaintext round-trip. Workaround: do not begin revision bodies with an H1
  heading; use `## ` or plain paragraphs. A fix is tracked for `0.1.1`.
