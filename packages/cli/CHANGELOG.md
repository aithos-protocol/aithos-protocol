# Changelog

All notable changes to the Aithos reference CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
