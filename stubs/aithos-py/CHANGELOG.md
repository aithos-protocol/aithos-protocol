# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] — 2026-04-19

### Added
- Initial placeholder package reserving the name `aithos` on PyPI.
- `PROTOCOL_VERSION = "0.1.0"` — the Aithos protocol version this package targets.
- `PACKAGE_VERSION = "0.0.1"` — this package's own version.
- `BIRTH_DIR` — path to the bundled birth artifacts.
- `verify_bundle()` and `resolve_did()` stubs that raise `NotImplementedError`
  and point users to the TypeScript reference CLI.
- Bundled birth artifacts under `aithos/birth/`:
  - `birth.json` — protocol-native birth record.
  - `birth-declaration.md` — human-readable declaration.
  - `aithos-birth.ethos` — signed ethos bundle (spec §3), conformant and verifiable
    with `aithos ethos verify` from the TypeScript CLI.
  - `did.json` — DID document of the ceremonial founding identity
    `did:aithos:z6Mkeu1UTXwL4djF9JmH5idEAF5t7g3bHjvJTBGeWqX5qPpA`.

### Notes
- This release is a **name reservation** and a **timestamped birth record**.
  Nothing in this package is functional beyond reading the bundled artifacts.
- The protocol specification itself is at version `0.1.0` (draft). Breaking
  changes to the wire format are permitted on any minor-version bump until
  `1.0.0`.
