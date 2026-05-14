# Data sub-protocol — Overview

> **Status:** Draft v0.1. Source of truth for the data sub-protocol that
> complements the Ethos protocol (chapters 1–12 in `spec/`).
>
> **Scope.** This sub-protocol governs **operational data** owned by an
> Aithos subject and accessed by applications under signed mandates. It is
> orthogonal to the Ethos data model: the Ethos describes who the subject
> *is* (voice, preferences, refusals); the data sub-protocol stores what
> the subject *has* (prospects, messages, calendar events, …).
>
> Reading order: this `overview.md` first, then chapters 01–10 in numeric
> order. Each chapter is self-contained but assumes the cryptographic and
> identity primitives of chapters 1, 4, 5, and 11 of the Ethos spec.

## 0.1 Why a separate sub-protocol

The Ethos protocol (chapters 1–10) is designed for **narrative, slowly-
mutating descriptive content** about a subject: voice, tone, expertise,
pricing, refusals. Sections are free-form markdown. Mutations are coarse —
weeks or months apart in typical use. Immutability is enforced through a
hash-chained gamma log signed at each mutation.

Forcing **operational data** into this model breaks three properties:

1. **Cost per mutation.** Every Ethos mutation publishes a new edition: a
   signed manifest, an updated gamma head, full zone re-serialization (in
   v0.2; per-section in v0.3). Operational data mutates at a different
   tempo — a CRM record may change five times in an afternoon. Paying full
   edition cost on every change is prohibitive past a few records.

2. **Absence of schema.** Section bodies are markdown, intentionally
   free-form (Ethos §2.7). For descriptive content, this is a feature.
   For records that an application must read predictably (`contact.email`,
   `event.starts_at`), it forces every consumer to write a fragile parser.
   Schema discipline must move from convention to normative.

3. **No server-side query.** Ethos zones are encrypted blobs (v0.2) or
   per-section blobs (v0.3) with no index on payload contents. Filtering
   records by status, listing the 20 most recent contacts, or paginating a
   thousand-record collection requires fetching and decrypting everything.
   Tolerable for tens of sections, unworkable for hundreds or thousands of
   records.

The data sub-protocol introduces structures and primitives that resolve
these three frictions while preserving the core Aithos guarantees: the
subject owns the data, applications access only what the subject has
explicitly mandated, every access is auditable.

## 0.2 Relationship to the Ethos protocol

The two sub-protocols are **parallel**. They share:

- **Identity.** Records are owned by an Aithos `subject_did` (chapter 1 of
  the Ethos spec). The subject's DID document is the same; no new
  identity primitive is introduced.
- **Sphere keys.** The subject's sphere keys are reused as the root of
  the data sub-protocol's key hierarchy (chapter 02 here).
- **Mandates.** The mandate document (Ethos chapter 4) is reused
  unchanged, with new scope strings introduced for data access
  (chapter 04 here).
- **Signed envelopes.** The write-path envelope (Ethos chapter 11) is
  reused unchanged for authenticated writes to the data sub-protocol.
- **Gamma log.** The hash-chained mutation log (Ethos chapter 10) is
  extended with new operation types for data records (chapter 08 here).

The two sub-protocols differ on:

- **Unit of storage.** Ethos stores sections inside zones; the data
  sub-protocol stores records inside collections.
- **Encryption granularity.** Ethos zones are per-zone (v0.2) or
  per-section (v0.3) blobs. Data records are always per-record blobs
  with their own DEK, regardless of protocol version.
- **Schema discipline.** Ethos sections are markdown free-form. Data
  records conform to a versioned JSON schema (`aithos.<name>.v<n>`) with
  explicit declaration of which fields are server-indexable and which
  are encrypted (chapter 03 here).
- **Authorization granularity.** Ethos zones inherit zone-grain
  authorization. Data collections add a `Collection Master Key` (CMK)
  that allows a single wrap to authorize an application on the entire
  collection, regardless of its size (chapter 02 here).

A subject MAY publish only an Ethos and no data collections, only data
collections and no Ethos, or both. Applications speaking only one
sub-protocol MUST tolerate the absence of the other.

## 0.3 Guiding principles

The principles below frame every design decision in this sub-protocol.
They are normative when they appear as MUST/SHOULD in subsequent chapters
and informative when stated here as principles.

**P1 — The subject owns the data.** No application maintains a private
store of operational data belonging to an Aithos subject. All such data
lives in the subject's PDS (Personal Data Server) under the subject's
identity. An application reads or writes through a mandate the subject
issues and can revoke at any time.

**P2 — The server sees only what must leak for it to function.** Record
payloads are AEAD-encrypted client-side. Only metadata explicitly marked
`indexable` in the record's schema is stored in the clear server-side, to
enable indexed queries and native pagination. The threat model
(chapter 09) makes the leak surface explicit.

**P3 — Authorization is O(1) on collection size.** Authorizing or
revoking an application on a collection containing N records requires a
constant number of cryptographic operations, not N. The Collection
Master Key construction (chapter 02) is the mechanism that delivers
this property.

**P4 — The protocol is portable.** Any collection can be exported as a
signed `.data` artifact (chapter 07) and re-imported on any conformant
PDS. The subject is never captive: data flows out as easily as it flows
in. Schema standardization (P5) is what makes the export *useful* on
import.

**P5 — Schemas standardize interop.** A schema `aithos.<name>.v<n>` is
declared, versioned, and immutable once published. Applications that
conform to the same schema read and write the same fields. Without this
discipline, portability is cosmetic — the data moves but no other
application knows what to do with it.

**P6 — Developer experience is the product.** The SDK exposes an ergonomic
surface (`client.data('contacts').list({ filter, limit })`) that does
not require developers to learn the underlying cryptographic constructs.
Protocol concepts (DIDs, sphere keys, gamma, wraps) are accessible to
developers who need them, invisible by default to those who do not.

## 0.4 Document model summary

```
User Aithos (subject_did)
└── Collection "contacts" (schema: aithos.contacts.v1)
    ├── Collection Master Key (CMK)
    │   ├── wrap for owner's sphere key
    │   ├── wrap for switchia (mandate_01J…)
    │   └── wrap for email-app (mandate_01K…)
    │
    └── Records
        ├── record_01J… { metadata_clear, payload_ciphertext, DEK_wrapped_for_CMK }
        ├── record_01K… { … }
        └── …
```

Each record carries:

- **`metadata_clear`** — fields the schema declares `indexable`. Stored in
  the clear server-side. Enables `WHERE status = 'lead'`-style queries
  and pagination.
- **`payload_ciphertext`** — fields the schema declares `encrypted`. AEAD
  ciphertext under a per-record DEK.
- **`DEK_wrapped_for_CMK`** — the record's DEK, encrypted (wrapped) for
  the collection's CMK. Anyone holding a wrap of the CMK can unwrap the
  DEK and then decrypt the payload.

The CMK itself is wrapped for the subject's sphere key and for each
application the subject has authorized. Adding an application to the
collection's wrap list is the single operation needed to grant access
to all records — past and future. See chapter 02 for the full
construction and chapter 04 for the authorization flow.

## 0.5 Terminology

Throughout this sub-protocol:

| Term | Definition |
|---|---|
| **Subject** | The Aithos identity (`did:aithos:…`) that owns one or more collections. The data sub-protocol's principal. |
| **Collection** | A logical container scoped to a single schema, owned by a single subject. Identified by `(subject_did, collection_name)`. |
| **Record** | One instance of a schema, stored in a collection. Identified by a ULID. |
| **Schema** | A versioned JSON Schema declaring the shape and indexability of a record type. Named `aithos.<name>.v<n>`. |
| **CMK** | Collection Master Key. A 32-byte symmetric key, one per collection, that intermediates between the subject's sphere key and the records' DEKs. |
| **DEK** | Data Encryption Key. A 32-byte symmetric key, one per record, that AEAD-encrypts the record's payload. |
| **Wrap** | An encrypted copy of a key, addressed to a specific recipient (a public key). Plural: a key may have multiple wraps, one per authorized recipient. |
| **Grantee** | The recipient of a mandate. Typically an application identified by a stable Ed25519 + X25519 keypair. |
| **PDS** | Personal Data Server. The platform-side implementation of this sub-protocol — the storage layer + RPC server. The user can move their PDS between conformant implementations. |
| **Payload** | The encrypted portion of a record (schema fields marked `encrypted`). |
| **Metadata clear** | The non-encrypted portion of a record (schema fields marked `indexable`). |
| **Authorization** | The act of adding a mandate grantee to a collection's wrap list. |
| **Revocation** | The act of removing a grantee from a collection's wrap list and revoking the underlying mandate. |

## 0.6 What is normative in this sub-protocol

Every chapter labels its statements:

- **MUST / MUST NOT** — strict requirements; non-conformance is a bug.
- **SHOULD / SHOULD NOT** — strong recommendations; deviation is allowed
  with explicit justification.
- **MAY** — permitted variation; implementations are free to choose.

Implementations declaring conformance to `aithos.data.v0.1` MUST satisfy
every MUST clause in chapters 01 through 09. Chapter 10 (Open questions)
is informative.

## 0.7 Versioning

This document is the v0.1 draft. Subsequent versions follow semantic
versioning at the sub-protocol level:

- **Patch (v0.1.1, v0.1.2, …)** — editorial corrections, clarifications.
- **Minor (v0.2.0, v0.3.0, …)** — backward-compatible additions: new
  scope strings, new RPC methods, new optional fields.
- **Major (v1.0.0)** — first stable cut. Subsequent major bumps imply
  breaking changes and a documented migration path.

Schemas (`aithos.<name>.v<n>`) version independently of the sub-protocol
itself. See chapter 03 for schema versioning rules.

## 0.8 Reading the rest of this RFC

| Chapter | Subject |
|---|---|
| [01 — Data model](./01-data-model.md) | Records, Collections, identifiers, lifecycle |
| [02 — Key hierarchy](./02-key-hierarchy.md) | sphere → CMK → DEK, wraps, rotation |
| [03 — Schemas](./03-schemas.md) | JSON Schema + Aithos annotations, versioning, validation |
| [04 — Mandates](./04-mandates.md) | Scope vocabulary for data access, optional filters |
| [05 — API primitives](./05-api-primitives.md) | RPC tools on read/write paths |
| [06 — Pagination](./06-pagination.md) | Page<T>, cursors, behavior under concurrent mutation |
| [07 — Portability](./07-portability.md) | `.data` export format, import procedure |
| [08 — Audit](./08-audit.md) | Gamma log extension with `data.*` entries |
| [09 — Threat model](./09-threat-model.md) | Leak surface, attacker models, mitigations |
| [10 — Open questions](./10-open-questions.md) | Decisions deferred to future revisions |

Implementers should read 01, 02, and 04 first — those three chapters
contain the core constructions that every subsequent chapter relies on.
