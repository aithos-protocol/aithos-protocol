# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] — 2026-04-19

### Added
- Initial placeholder crate reserving the name `aithos` on crates.io.
- `PROTOCOL_VERSION: &str = "0.1.0"` — the Aithos protocol version this crate targets.
- `PACKAGE_VERSION: &str = "0.0.1"` — this crate's own version.
- `CEREMONIAL_DID: &str` — DID of the ceremonial founding identity that signed
  the protocol's first public artifacts.
- `Error::NotImplemented` and two stub functions (`verify_bundle`, `resolve_did`)
  that return it and point users to the TypeScript reference CLI.
- Bundled birth artifacts under `birth/` at the crate root (also shipped in the
  published `.crate` archive via the `include` field):
  - `birth.json` — protocol-native birth record.
  - `birth-declaration.md` — human-readable declaration.
  - `aithos-birth.ethos` — signed ethos bundle (spec §3), conformant and verifiable
    with `aithos ethos verify` from the TypeScript CLI.
  - `did.json` — DID document of the ceremonial founding identity.

### Notes
- This release is a **name reservation** and a **timestamped birth record**.
  Nothing in this crate is functional beyond exposing constants and reading the
  bundled artifacts.
- The protocol specification itself is at version `0.1.0` (draft). Breaking
  changes to the wire format are permitted on any minor-version bump until
  `1.0.0`.
