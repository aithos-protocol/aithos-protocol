# Changelog

All notable changes to `@aithos/mcp` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.5] — 2026-06-18

- `bin.ts` (node host) now forwards `LINKEDONE_API_BASE` env → `createServer({ linkedoneApiBase })`,
  so a locally-run MCP can target a local/dev Linkedone backend for the
  `linkedone_schedule_post` tool. Defaults to https://api.linkedone.fr.

## [0.13.4] — 2026-06-17

- NEW handler `linkedone_schedule_post` (PROVISIONAL third-party app broker, cf.
  linkedone PLAN-AITHOS-BROKER-MVP). Signs a delegate-path envelope with the
  session delegate key (protocol-core `signEnvelopeWithMandate`) and POSTs to
  Linkedone's `/v1/compose-and-schedule`. Pure orchestration in
  `linkedone-broker.ts` (5 unit tests). New `createServer` options:
  `linkedoneApiBase`, `fetchImpl`. Self-gates on `data.linkedone-posts.write`.
- (0.13.2 / 0.13.3 were version-only publishes; no code delta vs 0.13.1.)

## [0.13.1] — 2026-06-11

- `@aithos/protocol-core` range widened to `>=0.10.3 <0.12.0` (was
  `^0.10.3`): consumers on the v0.4 line (core 0.11.x) no longer carry a
  duplicate nested 0.10.3 — H1 30/30 + e2e validated against 0.11.3.
  No code change.

## 0.13.0 — 2026-06-11

P6 incarnation (plan §6.2/§6.3) — agent-tools ^0.5.0:

- NEW resource `aithos://ethos/{handle}/voice` (V10): the subject's
  presentation guidance — an authored PUBLIC section tagged `voice` (or
  `guidance`) served verbatim (JSON §12.3.2 or prose), else the spec
  §12.3.4 default with `{handle}` substituted.
- NEW tool `ethos_introduce` (V16): third-party introduction — public-only
  STRUCTURALLY (circle/self never read, whatever the mandate; forced calls
  refuse), anonymous, refusal template surfaced for out-of-ethos questions.
- NEW tool `agent_briefing` (V11): mandate description + voice profile +
  budgeted context pack in ONE call, composed from the same internal
  helpers (`describeSession` / `voiceProfile` / `buildContextPack`).
- `selfSigningWrites` storage capability marker formalized (P1 note): a
  storage signing with its own session keys declares it; an undefined
  subject identity on a non-delegated write now REFUSES honestly instead
  of proceeding silently. `SelfSigningStorage` type exported.
- H1: +6 tests (T9, T9b, T17, T7/narration, V11, 0.13 marker) → 30.

## [0.12.1] — 2026-06-10

### Fixed

- `./pack` subpath export — `parseMandatePack` / `hexToBytes` /
  `MandatePack` are now importable (`@aithos/mcp/pack`). First consumer:
  the `@aithos/mcp-remote` bin (P5, agent-at-the-client over the platform).

## [0.12.0] — 2026-06-10

Phase P4 of PLAN-MCP-UNIFICATION-2026-06: **the living mandate** (V12/V13)
and the **mandate pack** (spec §6.2.1 — "agent chez le client").

### Added

- **`--mandate-pack <path>`** — ONE file boots a delegated server: the
  signed mandate (scope-filtered `tools/list`), the delegate keypair (signs
  writes by default — no per-call `mandate`/`agent_key` args), host options
  (`auto_commit`, `expose_tools`). `createServer` accepts the same via
  `mandate.document` + `delegate`. Pack parsing is isomorphic
  (`parseMandatePack`, exported) and refuses tampered packs (key/grantee
  mismatch, bad hex, wrong version).
- **`mandate_describe`** — the session's authority as data: id, issuer,
  grantee, sphere, scopes, window, LIVE revocation status, and the EXACT
  served tool set (T15 holds by construction: the same registry that
  registers tools feeds the answer). Owner sessions report
  `session: "owner"`; `mandate` arg describes another mandate by id.
- **`ethos_preflight_write { zone }`** — `authorized` + reason without
  executing: scope + window + revocation. Ungated.
- **Liveness re-checks (T6)** — a mandated write checks validity window +
  revocation at STAGE time and AGAIN at commit; expired/revoked authority
  never writes (h1 + e2e locked). Self is mandatable for the subject's own
  agent (T7: preflight matrix == dispatch behaviour; delegate-authored
  self editions commit fine; out-of-sphere zones refuse).
- e2e: full pack lifecycle over the real binary — scoped exposure,
  pack-signed transactional commit with `authorized_by` on the manifest
  signature, self refusal.

### Dependencies

- `@aithos/agent-tools` ^0.4.0 (describe/preflight specs).

## [0.11.0] — 2026-06-10

Phase P3 of PLAN-MCP-UNIFICATION-2026-06: **contextualization primitives**
(V1/V2/V4/V5) — reading an ethos becomes cheap enough for recurring agents.

### Added

- **`ethos_search`** (V2/D2) — keyword search over readable titles/tags/
  bodies (no NLP): index first, then capped lazy body reads (≤50), scoring
  title ×3 / tags ×2 / body ×1, snippets + `est_tokens`. The searched zones
  are ALWAYS the intersection of the request with the mandate's read scopes
  — an explicit `zones` argument cannot escape them (T12).
- **`ethos_context_pack`** (V4) — `guidance`-tagged sections, then `pinned`,
  then task matches, deduplicated, bodies truncated to `budget_tokens`
  (~4 chars/token), zero inference. Budget AND mandate respected (T14).
- **`ethos_diff_since`** (V5) — added/modified/deleted since a height, by
  content address (`blob_sha` → `gamma_ref` fallback), zero body reads.
  Served only when the backend has the `readManifestAt` capability
  (filesystem `history/`; platform PDS lands with P5). T16.
- `ethos_list_sections` rows now carry `approx_size_bytes` + `est_tokens`
  when the backend can stat blobs (V1 read planning).

### Dependencies

- `@aithos/protocol-core` ^0.10.3 (`approx_size_bytes`, `readManifestAt`),
  `@aithos/agent-tools` ^0.3.0 (the P3 specs).

## [0.10.0] — 2026-06-10

Phase P2 of PLAN-MCP-UNIFICATION-2026-06: **transactional editing (D3).**

### Changed (breaking)

- **Writes STAGE by default.** `ethos_add/update/append/delete_section`
  no longer persist immediately: they validate (scope gate + fail-fast
  existence checks) and stage in the session; `ethos_commit { message? }`
  seals the whole batch as ONE edition through the storage backend's new
  `applyEdits` capability (one manifest re-sign, one gamma anchor advance).
  `ethos_discard` — or simply ending the session — drops the batch with
  ZERO writes. Staged state is invisible to reads (persisted-only semantics).
  One transaction = one handle + one write authority (mixing mandates or
  subjects in a batch refuses at stage time).
- **Opt-out:** `createServer({ autoCommit: true })` / `aithos-mcp
  --auto-commit` restores the pre-0.10 per-write behaviour; storages
  WITHOUT `applyEdits` fall back to it automatically (stderr notice);
  stateless HTTP forces it (a per-request server cannot stage).

### Added

- **`ethos_commit` / `ethos_discard`** — registered only on transactional
  hosts (T10 subset parity preserved).
- **`ethos_append_section`** — journal pattern, served in BOTH modes;
  appends compose in order over staged state.
- H1-tx suite (T13: 3 staged writes → one `applyEdits` batch, zero prior
  writes; T13b: discard = zero batches) and the H2 stdio e2e: full
  transactional lifecycle incl. a pre-0.9 alias staging through the same
  transaction, plus the `--auto-commit` fallback.

### Dependencies

- `@aithos/protocol-core` ^0.10.2 (`applyEdits` / `EthosEdit` types),
  `@aithos/agent-tools` ^0.2.0 (the transactional trio specs).

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
