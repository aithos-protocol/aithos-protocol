# Changelog

All notable changes to `@aithos/mcp` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] — 2026-06-10

### Fixed

- **The isomorphic core is now importable.** 0.9.0 shipped as a CLI-only
  package (`bin` entry, no `main`/`exports`, `declaration: false`), so
  library hosts could not `import { createServer } from "@aithos/mcp"` —
  which is the whole point of the P0 refactor. 0.9.1 adds the `exports`
  map (`.` and `./server` → `dist/server.js`, `./auth` → `dist/auth.js`),
  `main`/`types`, and ships `.d.ts` declarations. The CLI surface is
  unchanged. First consumer: the SDK in-process host (P1, `sdk.agent.run`).

## [0.9.0] — 2026-06-10

Phase P0 of PLAN-MCP-UNIFICATION-2026-06 (canonical catalogue + isomorphic
core + mandate-scoped exposure).

### Changed (breaking)

- **Canonical D1 tool names.** Tools renamed to the shared
  `@aithos/agent-tools` catalogue: `identity_list`, `identity_describe`,
  `ethos_list_sections`, `ethos_read_section` (was
  `aithos_ethos_show_section`), `ethos_read_sections`, `ethos_verify`,
  `ethos_add_section`, `ethos_update_section` (was
  `aithos_ethos_modify_section`), `ethos_delete_section`, `mandate_verify`.
  Arguments are snake_case (`section_id`, `section_ids`, `clear_tags`,
  `agent_key`). **Deprecation bridge:** the pre-0.9 `aithos_*` names (and
  camelCase args) keep resolving at `tools/call` — never listed — and are
  scheduled for removal in 1.0. Disable with `legacyAliases: false`.
- **`createServer` requires `storage`.** The isomorphic core ships no
  `FilesystemStorage` default any more; the `aithos-mcp` CLI (bin.ts) wires
  it, plus `home`, `manifestPath`, host `io`, and `renderZone`
  (protocol-core's `renderZoneMarkdown`). Library consumers that relied on
  the implicit filesystem default must pass it explicitly.

### Added

- **`@aithos/agent-tools` integration** — names, schemas, and normative
  descriptions come from the canonical catalogue; the h1 parity test (T10)
  fails on any drift.
- **Mandate-scoped exposure (P0.3).** `createServer({ mandate })` filters
  `tools/list` by the mandate's scopes (`toolsForScopes`); per-call zone
  enforcement in handlers is unchanged (defense in depth, tested by T5).
- **H1 in-memory harness** (`test/h1-inmemory.test.mjs`): InMemoryTransport
  linked pair + pure in-memory storage fake — locks T10 parity, T4
  exposure, T5 defense in depth, and the alias bridge, with no filesystem
  and no child process.
- **Isomorphism gate** — `npm run check:browser` bundles the server core
  with esbuild `--platform=browser`; node builtins in the core graph fail
  the build. protocol-core is consumed through its node-free granular
  entries (`/did`, `/mandate`) + type-only imports.

### Fixed

- README tool table updated (the stale `aithos_ethos_add_revision` entry is
  gone; it had been replaced by `modify_section` in 0.8.0).

## [0.8.0] — 2026-06-06

### Changed
- **Per-section reads (v0.3).** `aithos_ethos_list_sections` now reads the
  section INDEX (id + title + `gamma_ref`, no body decryption); the encrypted
  `self` index shows titles only with the owner key. `aithos_ethos_show_section`
  fetches ONLY the requested section's blob instead of decrypting the whole zone.
- The server is now v0.3-aware throughout (verify, the `aithos://ethos/{handle}/{zone}`
  resource), so it works on the new v0.3-default keystore.
- **Writes work on v0.3.** `aithos_ethos_add_section` / `aithos_ethos_modify_section`
  write per-section editions on a v0.3 keystore (owner or delegate). The signed
  gamma-log append is still deferred to gamma-v0.3, so `gamma_entry_id` falls
  back to the section's `gamma_ref` on v0.3.
- Requires `@aithos/protocol-core` `^0.8.0`.

### Added
- **`aithos_ethos_read_sections`** — fetch several sections by id in a single
  call, decrypting only those sections; ids are located across all zones (or a
  single `zone`), and each result reports `accessible` + a `reason` when not.
- **`aithos_ethos_delete_section`** — remove a section by id (owner or delegate);
  v0.2 emits a signed `section.delete` gamma entry, v0.3 drops the section blob
  and writes a new per-section edition.

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
