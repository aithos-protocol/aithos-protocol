# Assets sub-protocol — Overview

> **Status:** Draft v0.1. Source of truth for the assets sub-protocol that
> complements the Ethos protocol (chapters 1–12 in `spec/`) and the data
> sub-protocol (chapters in `spec/data/`).
>
> **Scope.** This sub-protocol governs **heavy binary content** owned by
> an Aithos subject — images, documents, audio, video — referenced from
> an Ethos section or a data record, but hosted out-of-band of the
> bundle. It is orthogonal to both the Ethos data model (which carries
> narrative markdown) and the data sub-protocol (which carries
> JSON-schema-validated records).
>
> Reading order: this `00-overview.md` first, then chapters 01–10 in
> numeric order. Each chapter is self-contained but assumes the
> cryptographic and identity primitives of chapters 1, 4, 5, and 11 of
> the Ethos spec, plus the wrap-and-recipient pattern of `spec/data/02`.

## 0.1 Why a separate sub-protocol

The Ethos protocol (chapters 1–10) is designed for **narrative content**
about a subject: voice, tone, pricing, refusals. Sections are short
markdown bodies, typically a few hundred bytes to a few kilobytes each.
The bundle is a ZIP archive intended to travel end-to-end — by email
attachment, USB stick, CDN — and §3.9 of the bundle spec explicitly caps
the recommended size at 10 MB, with the guidance that "anything larger
suggests attached media belongs elsewhere."

Real-world subjects nonetheless carry heavy content alongside their
narrative identity:

- A profile avatar in usable resolution (200 KB to several MB).
- A résumé in PDF (a few hundred KB to a few MB).
- A portfolio of photographs, work samples, audio clips, video reels.
- Documents attached to a CRM record — a signed contract, a scan of an
  ID, an invoice PDF.

Forcing this content into the Ethos bundle or the data sub-protocol's
record payloads breaks three properties:

1. **Bundle portability.** A 50 MB bundle ceases to be an attachable
   artifact. CDN egress, mobile bandwidth, and storage costs all rise
   linearly with bundle weight, while the value of the bundle as a
   single-shot identity object decreases.

2. **Record payload weight.** Data records are AEAD-encrypted client-side
   and transported over JSON-RPC. Embedding a multi-megabyte PDF in the
   `payload_ciphertext` of a record inflates every list and read call,
   even for callers who do not need the attachment.

3. **Reference semantics.** The same asset may be referenced from
   multiple sections (an avatar shown in `Identity` and `Voice`),
   multiple editions (an avatar that survives 30 Ethos editions
   unchanged), or multiple subjects' contexts (a shared logo). Embedding
   the bytes in each container duplicates storage and tangles updates.

The assets sub-protocol introduces a primitive — the **Asset** — that
resolves these three frictions while preserving the core Aithos
guarantees: the subject owns the bytes, applications access only what
the subject has explicitly mandated, every access is auditable.

## 0.2 Relationship to the Ethos and data sub-protocols

The three sub-protocols are **parallel**. They share:

- **Identity.** Assets are owned by an Aithos `subject_did` (chapter 1
  of the Ethos spec). The subject's DID document is the same; no new
  identity primitive is introduced.
- **Sphere keys.** An asset's encryption keys are wrapped for the same
  sphere keys (`#public`, `#circle`, `#self`, `#data-kex`) used by the
  zone or collection from which the asset is referenced. The assets
  sub-protocol does NOT introduce a new sphere key (§2.2).
- **Mandates.** The mandate document (Ethos chapter 4) is reused
  unchanged, with new scope strings introduced for asset access
  (chapter 04 here).
- **Signed envelopes.** The write-path envelope (Ethos chapter 11) is
  reused unchanged for authenticated upload, fetch, and management
  calls.
- **Gamma log.** The hash-chained mutation log (Ethos chapter 10) is
  extended with new operation types for assets (chapter 08 here).

The three sub-protocols differ on:

- **Unit of storage.** Ethos stores sections inside zones; data stores
  records inside collections; assets stores byte blobs inside the
  subject's asset space (no further nesting — assets are flat).
- **Storage backend.** Ethos editions live in S3 + CloudFront as signed
  immutable objects. Data records live in DynamoDB as small encrypted
  payloads. Assets live in S3 (one object per asset), with their
  metadata in a small index table; large payloads never touch DynamoDB.
- **Encryption granularity.** Always per-asset. Each asset carries its
  own random Asset Master Key (AMK, §2). There is no "asset master
  key" intermediating across assets — assets are atomic.
- **Mutability.** Assets are **content-addressable**: the asset
  identifier binds to the plaintext SHA-256, and the bytes never
  change. An "update" is a new asset with a new identifier; the old
  asset is dereferenced and eventually purged. This is in contrast to
  data records (mutable) and Ethos sections (mutable through gamma).

A subject MAY publish only an Ethos and no assets, an Ethos with
assets, a data collection with assets attached, or any combination.
Applications speaking only one sub-protocol MUST tolerate the absence
of the others.

## 0.3 Guiding principles

The principles below frame every design decision in this sub-protocol.
They are normative when they appear as MUST/SHOULD in subsequent
chapters and informative when stated here as principles.

**P1 — The subject owns the bytes.** No application maintains a private
store of binary content belonging to an Aithos subject. All such bytes
live in the subject's asset space under the subject's identity. An
application reads or writes through a mandate the subject issues and can
revoke at any time.

**P2 — The server sees only what must leak for it to function.** Asset
payloads are AEAD-encrypted client-side when the asset is attached to a
private context (circle, self, private data collection). Only metadata
necessary for storage operation — size, content type, owner, recipient
set, integrity hash of the plaintext — is visible server-side. The
threat model (chapter 09) makes the leak surface explicit.

**P3 — Authorization is O(1) on asset size.** Authorizing or revoking
an application on an asset requires a constant number of cryptographic
operations, independent of the asset's byte size. The Asset Master Key
construction (chapter 02) is the mechanism that delivers this property.
Re-encrypting the asset bytes for forward secrecy is opt-in (§2.5.2).

**P4 — Assets are content-addressable.** An asset's identifier binds to
the SHA-256 of its plaintext bytes. Re-uploading the same content under
the same subject yields the same asset identifier (intra-subject
deduplication, §1.4). Cross-subject deduplication is deliberately NOT
performed (chapter 09 §9.4).

**P5 — Public and private asymmetry is explicit.** A public asset (e.g.
an avatar attached to the Ethos `public` zone) is stored unencrypted
and served via CDN with a stable URL. A private asset is stored
encrypted under an AMK whose wrap list mirrors the recipient set of the
referencing context. The two regimes are routed automatically by the
SDK based on the attaching zone or collection (chapter 03 §3.2).

**P6 — References are first-class.** Every section, record, or other
container that points to an asset emits an explicit reference recorded
in the asset's `referenced_by[]` index (§1.3) and audited via gamma
(chapter 08). An asset whose reference count drops to zero is
**orphaned**; the platform MAY purge orphans after a retention window
(§1.2.4). The subject's data is never silently lost.

**P7 — The protocol is portable.** Every asset can be exported as a
signed `.asset` artifact (chapter 07) and re-imported on any conformant
PDS. The subject is never captive: bytes flow out as easily as they
flow in.

**P8 — Developer experience is the product.** The SDK exposes an
ergonomic surface (`client.assets.upload({ bytes, mediaType, attachTo })`)
that does not require developers to learn the underlying cryptographic
constructs. Protocol concepts (DIDs, sphere keys, wraps, AMKs) are
accessible to developers who need them, invisible by default to those
who do not.

## 0.4 Document model summary

```
User Aithos (subject_did)
└── Asset space
    ├── Asset asset_01J… (avatar.png, public, attached to ethos.public.sec_identity)
    │   ├── S3 object: s3://aithos-assets/{did}/{asset_id}/raw.bin
    │   ├── metadata: { media_type, size, sha256, encrypted: false }
    │   └── referenced_by: [{ ethos_edition_urn, zone: "public", section_id: "sec_identity" }]
    │
    ├── Asset asset_01K… (cv.pdf, private, attached to data.contacts.record_01M…)
    │   ├── S3 object: s3://aithos-assets/{did}/{asset_id}/raw.bin (ciphertext)
    │   ├── metadata: { media_type, size, sha256, encrypted: true }
    │   ├── amk_envelope: { wraps: [
    │   │     { recipient: did:aithos:…#self-kex, ... },
    │   │     { recipient: did:key:…recruiter-X-kex, ... }
    │   │   ] }
    │   └── referenced_by: [
    │       { ethos_edition_urn, zone: "self", section_id: "sec_career_docs" },
    │       { data_record_urn: "urn:aithos:data-record:…", field: "attachment" }
    │     ]
    │
    └── …
```

Each asset carries:

- **`bytes`** — the actual content, stored in S3. Either plaintext (for
  public assets) or AEAD ciphertext under a per-asset AMK (for private
  assets).
- **`metadata`** — server-visible descriptor: media type, size,
  plaintext SHA-256, encryption flag, owner DID, creation timestamp.
- **`amk_envelope`** — for private assets only. The AMK wrapped for
  each authorized recipient.
- **`referenced_by[]`** — the list of contexts (Ethos editions, data
  records) that point to this asset. Updated transactionally on
  reference and unreference operations.

The AMK itself is wrapped for the subject's sphere key matching the
attaching zone, and for each application the subject has authorized.
Adding an application to an asset's wrap list is the single operation
needed to grant access to the asset, regardless of its byte size. See
chapter 02 for the full construction and chapter 04 for the
authorization flow.

## 0.5 Scope of v0.1

The v0.1 implementation target is intentionally narrow to ship a usable
asset layer quickly. Subsequent minor versions extend the surface.

**In scope for v0.1:**

- Owner-only upload, fetch, list, head, delete.
- Public and private asset regimes (both encrypted and unencrypted).
- Per-asset AMK wrapping for the subject's sphere keys.
- Intra-subject deduplication by SHA-256 of plaintext (§1.4).
- Reference tracking with `referenced_by[]` updated by the Ethos and
  data sub-protocols on section/record mutations.
- Gamma audit entries for every state change.
- CloudFront-served public assets via stable URL; S3 presigned URLs
  (short-lived) for private assets.

**Specified but not implemented in v0.1:**

- Mandate-based grantee authorization (chapter 04).
- AMK rotation and forward-secrecy strict mode.
- Asset portability export/import (chapter 07).
- Multipart streaming upload for very large assets.

**Open questions deferred to later versions:**

- Convergent encryption / cross-subject deduplication (rejected in
  v0.1; see §0.6 and chapter 10).
- Server-side image transcoding and thumbnail generation.
- Range requests on encrypted assets.
- Post-quantum algorithm migration.

## 0.6 Two design choices explicitly rejected

Two patterns that may seem attractive at first glance are rejected
explicitly to spare future reviewers the cycle.

**Convergent encryption** would set `AMK = HKDF(plaintext, fixed_salt)`,
so that two subjects uploading the same file produce the same
ciphertext and the same asset identifier — enabling cross-subject
deduplication. This pattern is rejected. Convergent encryption leaks
"these N subjects all possess the same file" to the storage layer and
exposes them to dictionary attacks (the server can confirm whether
subject X holds a known file by encrypting the known file under the
convergent scheme and comparing). For a system whose first principle is
that the server sees as little as possible (P2), this is unacceptable.

**Server-side re-encryption for grantee revocation** would have the
server re-encrypt every asset's bytes upon a recipient's revocation.
This pattern is rejected. The server holds no plaintext and no AMK; it
cannot re-encrypt without learning the AMK, which would defeat the
client-side encryption model. Forward secrecy on revocation is achieved
client-side via AMK rotation (§2.5.2) when explicitly requested by the
owner.

## 0.7 Terminology

Throughout this sub-protocol:

| Term | Definition |
|---|---|
| **Subject** | The Aithos identity (`did:aithos:…`) that owns one or more assets. The assets sub-protocol's principal. |
| **Asset** | One binary content blob, identified by a ULID. Atomic, content-addressable, immutable. |
| **AMK** | Asset Master Key. A 32-byte symmetric key, one per private asset, that AEAD-encrypts the asset's bytes. |
| **Wrap** | An encrypted copy of an AMK, addressed to a specific recipient (a public key). Plural: an AMK may have multiple wraps, one per authorized recipient. |
| **Grantee** | The recipient of a mandate. Typically an application identified by a stable Ed25519 + X25519 keypair. |
| **PDS / Asset PDS** | Personal Data Server, asset variant. The platform-side implementation of this sub-protocol — the S3 bucket + index table + RPC server. The user can move their asset PDS between conformant implementations. |
| **Referenced by** | The set of contexts (Ethos editions, data records) that currently point to a given asset. Updated transactionally by reference and unreference operations. |
| **Orphan** | An asset whose `referenced_by[]` is empty. Eligible for purge after a retention window. |
| **RecipientResolver** | A function that, given a target context (Ethos zone + section, or data collection), returns the set of DID URL recipients whose wraps an AMK must carry. The resolver is the abstraction that lets the SDK route automatically between Ethos v0.2 (zone-grain) and v0.3 (section-grain) recipient sets without applicative changes. |
| **Media type** | An IANA media type (RFC 6838) describing the asset's content. Used for client-side rendering and server-side content sniffing rejection. |

## 0.8 What is normative in this sub-protocol

Every chapter labels its statements:

- **MUST / MUST NOT** — strict requirements; non-conformance is a bug.
- **SHOULD / SHOULD NOT** — strong recommendations; deviation is allowed
  with explicit justification.
- **MAY** — permitted variation; implementations are free to choose.

Implementations declaring conformance to `aithos.assets.v0.1` MUST
satisfy every MUST clause in chapters 01 through 09. Chapter 10 (Open
questions) is informative.

## 0.9 Versioning

This document is the v0.1 draft. Subsequent versions follow semantic
versioning at the sub-protocol level:

- **Patch (v0.1.1, v0.1.2, …)** — editorial corrections, clarifications.
- **Minor (v0.2.0, v0.3.0, …)** — backward-compatible additions: new
  scope strings, new RPC methods, new optional fields. Most notably,
  the migration of recipient resolution from Ethos zone-grain to
  Ethos section-grain (when the bundle spec moves to v0.3) is a minor
  bump and does not break the wire format of existing assets.
- **Major (v1.0.0)** — first stable cut. Subsequent major bumps imply
  breaking changes and a documented migration path.

The wire format identifiers (`alg`, `wrap.alg`, AAD prefixes) include
explicit version markers (e.g. `"aithos-asset-v1\0"`) so multiple
protocol revisions can coexist on the same backend.

## 0.10 Reading the rest of this RFC

| Chapter | Subject |
|---|---|
| [01 — Data model](./01-data-model.md) | Asset object, identifiers, lifecycle, references |
| [02 — Key hierarchy](./02-key-hierarchy.md) | Sphere → AMK → bytes; wrap construction; rotation |
| [03 — Asset descriptors](./03-asset-descriptors.md) | How sections and records reference assets; media types; integrity |
| [04 — Mandates](./04-mandates.md) | Scope vocabulary for asset access, optional filters |
| [05 — API primitives](./05-api-primitives.md) | RPC tools on read/write paths, presigned URL flow |
| [06 — Pagination](./06-pagination.md) | Page<T>, cursors, ordering |
| [07 — Portability](./07-portability.md) | `.asset` export format, import procedure |
| [08 — Audit](./08-audit.md) | Gamma log extension with `assets.*` entries |
| [09 — Threat model](./09-threat-model.md) | Leak surface, attacker models, mitigations |
| [10 — Open questions](./10-open-questions.md) | Decisions deferred to future revisions |

Implementers should read 01, 02, and 03 first — those three chapters
contain the core constructions that every subsequent chapter relies on.

---

Next: [chapter 01 — Data model](./01-data-model.md).
