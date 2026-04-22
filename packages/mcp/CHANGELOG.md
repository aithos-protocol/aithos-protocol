# Changelog

All notable changes to `@aithos/mcp` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-04-22

### Fixed
- Republish of the 0.4.0 release after the original `npm publish` was
  interrupted mid-upload and the `0.4.0` version slot became unusable on
  the registry. No functional changes vs. 0.4.0 — same `AithosStorage`
  injection surface, same auth flow, same tool and resource set. Only a
  cosmetic docstring touch in `src/server.ts` to produce a fresh tarball.

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
