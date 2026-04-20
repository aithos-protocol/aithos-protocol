# Aithos Protocol Specification

**Version:** 0.1.0 (draft)
**Status:** Under active development. Breaking changes expected until 1.0.0.
**Editors:** Mathieu Colla <mathieu.colla.pro@gmail.com>
**License:** Apache-2.0

---

This is the normative specification of the Aithos protocol. For the motivation and the argument, read the [white paper](./WHITEPAPER.md) first. For the implementation, see [`cli/`](./cli/).

## Document map

The spec is broken into self-contained chapters, roughly layered from the cryptographic floor up to the application ceiling. Chapters 0–7 are wire-format and protocol semantics; chapter 9 describes the local CLI store and the owned-vs-tracked distinction.

| # | Chapter | What it covers |
|---|---|---|
| 0 | [Introduction](./spec/00-introduction.md) | Terminology, conformance, versioning, RFC-2119 usage |
| 1 | [Identity](./spec/01-identity.md) | `did:aithos` method, root key, three sphere keys, DID document |
| 2 | [Ethos](./spec/02-ethos.md) | Ethos document model: zones, sections, editions, revisions, append-only history |
| 3 | [Bundle](./spec/03-bundle.md) | `.ethos` zip container, manifest, encrypted zones, per-edition hash chain |
| 4 | [Mandates](./spec/04-mandates.md) | Grant structure, scopes, TTL, revocation |
| 5 | [Signing](./spec/05-signing.md) | Canonicalization (RFC 8785), Ed25519 signatures, action artifacts |
| 6 | [Transport](./spec/06-transport.md) | MCP bridge (normative), HTTP API (normative) |
| 7 | [Threat model](./spec/07-threat-model.md) | Adversaries, tradeoffs, known leaks |
| 8 | [Glossary](./spec/08-glossary.md) | Every defined term in one place |
| 9 | [Local store](./spec/09-local-store.md) | Owned vs tracked identities, install, stateless verify, mandate intake, capability resolution |

## Conformance in one paragraph

A conformant **author implementation** produces bundles (§3) whose manifest, signatures, and DID document validate against this specification, with identity derived as in §1. A conformant **reader implementation** (an AI agent or an MCP server serving one) resolves the DID (§1), verifies the bundle (§3) and any mandate it holds (§4) before reading a non-public zone, and rejects any bundle or mandate whose signatures do not verify under the canonicalization rules in §5.

Implementations MUST declare the protocol version they target. The current version is `"aithos": "0.1.0"`.

## Requirement levels

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, **OPTIONAL** are used as defined in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when they appear in all capitals.

## Versioning policy

Until `1.0.0`, any minor-version bump (`0.1.x` → `0.2.x`) is permitted to break the wire format. Point releases (`0.1.0` → `0.1.1`) are clarifications that do not affect existing implementations.

After `1.0.0`, the protocol follows semantic versioning strictly. A new major version means a new identifier namespace (`did:aithos2:…`), not a new version of `did:aithos`.

## Open questions

The following are known open questions and are explicitly not yet normative. They are tracked at the end of the chapter where they belong and will be resolved in a future draft.

- **Sub-audiences in `circle`.** Multiple concentric circles (`circle.work`, `circle.family`) or a flat circle with per-recipient keying? See §4.
- **Section-title encryption.** The current manifest exposes section titles even for encrypted zones. Should v0.2 offer an opt-in to encrypt the section index? See §3.7.
- **Binding actions.** Which scope classes require a counter-signature from the mandated sphere key at action time, and which are fire-and-forget? See §5.4.
- **Root-key recovery.** The protocol currently has none. Whether to add a t-of-n social recovery layer is undecided. See §7.5.
- **Discovery.** How a counterparty resolves `@mathieu` to `did:aithos:z6Mkr…`. Most likely a companion `did:web` record; to be specified in v0.2. See §6.3.

## Errata

Errata for each published version will be maintained at [`spec/errata/`](./spec/) once there is anything to correct. Submit corrections as PRs against this repository.

---

Proceed to [chapter 0 — Introduction](./spec/00-introduction.md), or jump into the chapter you need from the map above.
