# Changelog

All notable changes to `@aithos/mcp` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-05-27

### Changed
- Bumped `@aithos/protocol-core` peer to `^0.6.0` to pick up the new
  sponsorship primitive (draft §13) alongside the existing
  `compute.invoke` scope and clock-skew tolerance from the
  protocol-core 0.5.2 line. The MCP server itself does not yet expose
  sponsorship-aware tools; this version bump exists so that consumers
  installing the MCP server resolve a protocol-core that contains the
  new types.

### Notes
- No behaviour change in the existing tool surface. Existing MCP
  clients continue to work unchanged.

## [0.6.1] — 2026-05-01

### Fixed
- `package.json` `homepage`, `repository.url`, and `bugs.url` now point at
  `github.com/aithos-protocol/aithos-protocol` (the canonical org-level repo).
  Previous releases lingered on `github.com/Math1987/aithos-protocol` from a
  transient state of the move into the `aithos-protocol` GitHub org. This is
  metadata-only — no code changes.

## [0.6.0] — 2026-04-30

### License
- Reverted from **BUSL-1.1** back to **Apache-2.0**. The reference packages
  are once again under a permissive OSI-approved license, immediately and
  irrevocably for the `0.x` line. Rationale: at zero traction, BUSL costs more
  in adoption friction (excluded from distros, OSI-only enterprise policies,
  community pushback) than it protects. For a protocol, adoption *is* value.
  See ADR-0007 in `ARCHITECTURE-DECISIONS.md`.
- Source-file SPDX headers, package.json `license` fields, and per-package
  `LICENSE` files are all aligned on `Apache-2.0`.
- Version 0.5.0 (published under BUSL-1.1) remains under BUSL-1.1 for anyone
  who already obtained it.

### Protocol
- Targets **`@aithos/protocol-core@^0.5.0`** (license-only bump in the library).

## [0.5.0] — 2026-04-28

### License
- Switched from **Apache-2.0** to **Business Source License 1.1** (**BUSL-1.1**).
  **Change Date:** 2030-12-31. **Change License:** Apache-2.0. See `LICENSE`.
  Artifacts previously published under Apache-2.0 remain under that license for
  anyone who obtained those versions.

### Changed
- MCP `initialize` server `version` stamp defaults to `0.5.0` (aligned with this
  package release).

### Protocol
- Targets **`@aithos/protocol-core@^0.4.0`** (license-only bump in the library).

## [0.4.0] — 2026-04-22

### Added
- `createServer()` now accepts an optional `storage: AithosStorage` option.
  When omitted, a new `FilesystemStorage()` is constructed — behaviour is
  identical to prior releases. Hosts embedding the MCP server (Aithos
  platform Lambdas, remote API bridges) can pass their own backend so every
  identity / ethos / mandate read and write flows through a pluggable
  interface instead of the local filesystem helpers.

### Changed
- Every tool and resource handler now goes through the injected
  `AithosStorage` (async). Private helpers `resolveHandle` and `readZone`
  take the storage as their first argument. Write handlers try to load the
  subject identity via `storage.loadIdentity(handle)`; a missing local
  identity is only tolerated if a mandate + agent keyfile was supplied
  (storage backend then decides whether delegate-only writes are
  acceptable — `FilesystemStorage` still rejects them with a clear error).
- `resolveMandate` / `resolveWriteAuth` in `auth.ts` now take an
  `AithosStorage` as their first argument and resolve id-form mandates via
  `storage.loadMandate(id)` instead of the direct filesystem helper.
- The diagnostic resource `aithos://ethos/{handle}/manifest-path` is only
  registered when the backend is a `FilesystemStorage` (the path is
  meaningless for remote backends).

## [0.3.0] — 2026-04-22

### Protocol
- Targets **`@aithos/protocol-core@^0.3.0`**. Picks up the v0.3 gamma log
  format break (per-entry asymmetric envelopes) and the `gamma.read`
  scope. MCP server version stamp bumped to `0.3.0` for alignment with
  the CLI release; server tool surface is unchanged.

## [0.2.1] — 2026-04-22

### Protocol
- Targets `@aithos/protocol-core@^0.2.1`. Picks up the `Author`
  abstraction and delegate-on-tracked support from the `0.2.1` release.
