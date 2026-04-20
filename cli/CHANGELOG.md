# Changelog

All notable changes to the Aithos reference CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
