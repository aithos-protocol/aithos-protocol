# 0 · Introduction

## 0.1 Purpose

This specification defines the Aithos protocol: how a person publishes a portable, signed, versioned description of themselves; how they authorize AI agents to read it and act under it; and how the resulting actions are cryptographically attributable.

The protocol has three concentric layers:

1. **Identity.** A `did:aithos` DID and its three sphere keys. Chapter 1.
2. **Ethos.** The structured document and its zip container. Chapters 2–3.
3. **Authority.** Mandates and signed actions. Chapters 4–5.

A transport layer (MCP and HTTP) binds the three together for agents. Chapter 6.

## 0.2 Audience

This document is written for implementers — authors of editors, MCP servers, agent SDKs, and verifiers. It is normative. Readers looking for the motivation and the broader argument should start with the [white paper](../WHITEPAPER.md).

## 0.3 Terminology

The protocol defines the following terms. Full glossary in [chapter 8](./08-glossary.md).

- **Subject.** The person an ethos describes.
- **Root identity.** The Ed25519 key pair whose public half is embedded in the subject's `did:aithos` identifier. Used only to sign the DID document.
- **Sphere key.** One of three Ed25519 key pairs (`public`, `circle`, `self`) used to sign operations within a zone.
- **Ethos document.** The JSON object described in chapter 2.
- **Bundle.** A `.ethos` zip archive carrying the ethos document and its encrypted zones; chapter 3.
- **Mandate.** A signed capability token granting an agent authority to read zones and take actions; chapter 4.
- **Action artifact.** The signed object an agent emits when it acts under a mandate; chapter 5.
- **Agent.** Any software client fetching an ethos or acting under a mandate.
- **Verifier.** Any party validating a signature.

## 0.4 Conformance

### 0.4.1 Requirement levels

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals.

### 0.4.2 Roles

An implementation claims conformance against one or more of the following roles:

- **Author.** Produces bundles and mandates.
- **Reader.** Consumes bundles on behalf of an agent.
- **Actor.** Takes actions under a mandate and emits action artifacts.
- **Verifier.** Validates signatures on any of the above.
- **Server.** Hosts a bundle and enforces zone access over a transport.

Claimed roles MUST be listed in the implementation's documentation along with the targeted spec version.

### 0.4.3 Version declaration

Every ethos document, mandate, revocation, and action artifact MUST carry a top-level `aithos`, `aithos-mandate`, `aithos-revocation`, or `aithos-action` field respectively, whose value is the version string of the document schema (`"0.1.0"` in this draft). Implementations MUST refuse documents whose declared version they do not support.

## 0.5 Versioning

### 0.5.1 Protocol versioning

The protocol follows a single version number. The current version is `0.1.0`. Until `1.0.0`, minor-version bumps are permitted to introduce breaking changes. After `1.0.0`, the protocol follows semantic versioning strictly.

### 0.5.2 Document schemas

Individual document schemas (ethos, mandate, revocation, action) evolve in lockstep with the protocol version. There is no per-schema version separate from the protocol version.

### 0.5.3 Crypto agility

The protocol uses a fixed set of primitives at each version (§1.3, §3.4, §5.2). Adding a new primitive is a minor-version bump. Removing one is a major-version bump.

## 0.6 Notation

### 0.6.1 JSON examples

JSON examples in this document use the convention of leading commas only for clarity; actual conformant output is produced by an RFC 8785 canonicalizer (§5.1).

### 0.6.2 Binary encodings

Unless otherwise noted, binary data in JSON is encoded in **base64url without padding** (RFC 4648 §5). Multibase-encoded keys use the `z` prefix (base58btc) to match `did:key` convention.

### 0.6.3 Timestamps

All timestamps are **RFC 3339** strings in UTC (`Z` suffix), truncated to seconds: `2026-04-19T08:14:23Z`.

### 0.6.4 Identifiers

- **Mandate IDs** are `mandate_` followed by a 26-character Crockford-base32 ULID (§4.2.3).
- **DIDs** are as specified in chapter 1.
- **Bundle URNs** are `urn:aithos:<handle>:<edition>` where `<handle>` is the DNS-friendly subject handle and `<edition>` is the edition version string.

## 0.7 Relationship to other specifications

This protocol defers to and extends the following:

- **[W3C DID Core 1.0](https://www.w3.org/TR/did-core/)** — identifiers and DID documents.
- **[did:key](https://w3c-ccg.github.io/did-method-key/)** — encoding convention for public keys as DIDs; `did:aithos` uses the same multibase encoding for the root identifier.
- **[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)** — JSON canonicalization, used for all signing.
- **[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)** — Ed25519 signatures.
- **[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)** — ChaCha20-Poly1305; XChaCha20 per the libsodium construction.
- **[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)** — Argon2 password hashing.
- **[Model Context Protocol](https://modelcontextprotocol.io)** — the agent-side transport binding in chapter 6.

## 0.8 Non-goals

This protocol does **not**:

- Prescribe a storage backend or hosting model.
- Define a login or account system.
- Encode legal authority. A mandate is cryptographically verifiable but is not a power of attorney under any jurisdiction's law. See §7.6.
- Train, serve, or fine-tune a model.
- Provide a standard memory layer for an agent. An ethos is what an agent *reads*, not how it *remembers*.

## 0.9 License

Normative specification text in `spec/` (and [SPEC.md](../SPEC.md)) is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The reference TypeScript
implementation in this repository (`packages/*`) is under **BUSL-1.1** (see [LICENSE](../LICENSE));
other implementations may use any license.

---

Next: [chapter 1 — Identity](./01-identity.md).
