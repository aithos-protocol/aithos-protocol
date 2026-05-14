# 8 · Audit

## 8.1 Overview

Every mutation in the data sub-protocol emits a signed entry in a
hash-chained audit log — the **gamma log** — reusing the same construct
as the Ethos sub-protocol (Ethos chapter 10).

The gamma log delivers three properties:

- **Tamper evidence.** Each entry's `prev_hash` chains to the previous
  entry's `hash`. Modifying any past entry breaks every subsequent
  entry's chain, detectable on read.
- **Authorship attribution.** Each entry is signed either by a sphere
  key (the subject acting directly) or by a delegate key with
  `authorized_by` pointing to a mandate (the application acting on
  behalf of the subject).
- **Audit completeness.** A reader walking the chain from genesis to
  head reconstructs the full history of mutations to the subject's data
  state — including authorizations and revocations.

This chapter specifies the data-specific gamma entry types, their
payloads, and how they relate to the existing Ethos gamma chain.

## 8.2 Relationship to the Ethos gamma log

A subject has **one gamma log** that records mutations to both their
Ethos and their data collections. Entries are interleaved
chronologically. This is intentional:

- Cross-references between Ethos sections and data records (e.g. an
  Ethos section that mentions a collection) need to be auditable in
  the same chain.
- Sphere key rotation (an Ethos primitive) affects data collections
  (CMK wraps become unverifiable). Linking both chains in one log
  makes the dependency explicit.
- A subject who holds a `.gamma` file for backup has one file, not
  two.

A platform MAY shard the storage of gamma entries (e.g. Ethos entries
in `s3://…/ethos/{did}/gamma/`, data entries in
`s3://…/ethos/{did}/gamma-data/`) for operational reasons, as long as
the **logical chain** is unified. Each entry's `prev_hash` references
the chronologically previous entry, regardless of its op type.

## 8.3 Data-specific gamma entry types

The Ethos sub-protocol defines `op` values like `section.add`,
`section.modify`, `section.delete` (Ethos §10.5). The data sub-protocol
adds:

| `op` | Meaning |
|---|---|
| `data.collection.created` | A new collection was created. |
| `data.collection.tombstoned` | The collection was soft-deleted. |
| `data.collection.purged` | The collection was hard-deleted (after retention). |
| `data.collection.authorize_grantee` | A grantee was added to the CMK wrap list. |
| `data.collection.revoke_grantee` | A grantee was removed from the CMK wrap list. |
| `data.collection.rotate_cmk` | The CMK was rotated. |
| `data.collection.rotate_owner_wrap` | The owner's CMK wrap was renewed after sphere rotation. |
| `data.collection.imported` | The collection was imported from a `.data` bundle. |
| `data.record.created` | A record was inserted. |
| `data.record.modified` | A record was updated. |
| `data.record.deleted` | A record was soft-deleted. |
| `data.record.purged` | A record was hard-deleted (after retention). |

Each entry's `payload` carries information specific to the op type, as
detailed below.

## 8.4 Entry format

A gamma entry for a data operation has the standard shape (Ethos §10.4):

```json
{
  "id": "gamma_01K6X…",
  "at": "2026-05-14T12:34:56.789Z",
  "subject": "did:aithos:z6Mkr…",
  "prev_hash": "sha256:abc123…",
  "hash":       "sha256:def456…",
  "op":         "data.record.created",
  "payload": {
    "collection_urn": "urn:aithos:collection:did:aithos:z6Mkr…:contacts",
    "record_id": "record_01J9YB2X7Q1K3P4R5S6T7U8V9W",
    "schema": "aithos.contacts.v1",
    "metadata_hash": "sha256:0ab1…",
    "payload_hash": "sha256:5e7c…"
  },
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#data",
    "value": "z6V…",
    "authorized_by": "mandate_01JG4X…"
  }
}
```

`payload_hash` and `metadata_hash` are SHA-256 hashes of the
post-mutation record's `payload` and `metadata` fields respectively.
The gamma entry does not carry the record's content — only commitments
to it. This keeps gamma entries small while preserving the audit
guarantee that the chain commits to every byte of every record.

### 8.4.1 Why hashes, not full content

Including full record content in gamma would balloon the log:
1000 records × 10 KB × 5 revisions = 50 MB of gamma entries. Hashes
keep gamma at ~500 bytes per entry while preserving the verification
property — given a record's current bytes, a verifier can recompute the
hashes and confirm they match what the gamma chain claims.

The trade-off: a reader cannot reconstruct a deleted record's content
from gamma alone. They can confirm that **some** record existed with
**this exact hash** at **this exact time** — but the bytes themselves
are in the record store, which is subject to purge.

## 8.5 Per-op payload schemas

### 8.5.1 `data.collection.created`

```json
{
  "collection_urn": "...",
  "collection_name": "...",
  "schema": "aithos.<name>.v<n>",
  "forward_secrecy": "best_effort" | "strict",
  "cmk_wrap_count": 1
}
```

### 8.5.2 `data.collection.authorize_grantee`

```json
{
  "collection_urn": "...",
  "mandate_id": "mandate_01J…",
  "grantee_did_url": "did:key:z6Mk…",
  "scopes": ["data.contacts.read", "data.contacts.write"],
  "filter": null
}
```

### 8.5.3 `data.collection.revoke_grantee`

```json
{
  "collection_urn": "...",
  "mandate_id": "mandate_01J…",
  "revocation_id": "revocation_01J…",
  "rotated_cmk": false
}
```

### 8.5.4 `data.collection.rotate_cmk`

```json
{
  "collection_urn": "...",
  "reason": "manual" | "revoke" | "scheduled" | "sphere_rotation",
  "prior_cmk_hash": "sha256:…",
  "new_cmk_hash": "sha256:…",
  "records_rewrapped": 247,
  "ciphertexts_re_encrypted": 247
}
```

### 8.5.5 `data.record.created`

```json
{
  "collection_urn": "...",
  "record_id": "record_01J…",
  "schema": "aithos.<name>.v<n>",
  "metadata_hash": "sha256:…",
  "payload_hash": "sha256:…"
}
```

### 8.5.6 `data.record.modified`

```json
{
  "collection_urn": "...",
  "record_id": "record_01J…",
  "prev_metadata_hash": "sha256:…",
  "prev_payload_hash": "sha256:…",
  "metadata_hash": "sha256:…",
  "payload_hash": "sha256:…"
}
```

`prev_metadata_hash` and `prev_payload_hash` chain the record's
mutation history. A verifier given a record's current bytes and the
gamma chain can reconstruct the sequence of state transitions for
that record (hashes only — content is opaque).

### 8.5.7 `data.record.deleted`

```json
{
  "collection_urn": "...",
  "record_id": "record_01J…",
  "prev_metadata_hash": "sha256:…",
  "prev_payload_hash": "sha256:…"
}
```

### 8.5.8 `data.collection.imported`

```json
{
  "collection_urn": "...",
  "source_bundle_id": "urn:aithos-data:export:01J…",
  "source_subject_did": "did:aithos:z6Mkr…",
  "source_collection_urn": "urn:aithos:collection:…",
  "record_count": 247,
  "gamma_imported": true
}
```

## 8.6 Sphere-key vs delegate-key signatures

A gamma entry's `signature.key` indicates who emitted the entry:

- **Sphere key (`#data`, `#root`, `#circle`, `#self`)**: the subject
  acted directly. No `authorized_by` field.
- **Delegate key (a bare multibase pubkey)**: an application acted via
  a mandate. The mandate id is present in `signature.authorized_by`.

The platform MUST verify, at write time, that:

1. The signing key matches the envelope signing key.
2. For sphere keys: the key is listed in the subject's current DID
   document.
3. For delegate keys: the mandate referenced by `authorized_by` is
   present, valid, not revoked, and grants a scope covering the
   operation.

This binding makes the gamma chain a tamper-evident audit trail of
*who* performed *what* at *when*. A subject reviewing their log can
spot any operation that wasn't expected.

## 8.7 Reading the audit log

The data sub-protocol does NOT define new RPCs for reading the gamma
log — it reuses the Ethos sub-protocol's `aithos.list_gamma_entries`
(Ethos §10.5.x, Mode B) if the platform exposes a readable gamma log.
A platform operating in Mode A (write-only gamma, Ethos §10.11.1) does
not serve gamma reads; subjects who want their audit trail can extract
it via `.data` export with `include_history: true` (chapter 07).

Filtering gamma entries by op-type prefix (e.g. `data.*` to see only
data operations) is a SHOULD-implement convenience on the read primitive
where supported.

## 8.8 Audit semantics in practice

Three use cases illustrate the audit guarantee:

### 8.8.1 "Did Switchia delete that lead?"

The subject queries `aithos.list_gamma_entries(op="data.record.deleted",
collection="contacts")`. The platform returns the entries. Each entry
is signed; the `authorized_by` field reveals which mandate authorized
the delete. The subject correlates with their issued mandates to see
which application performed it, and at what time.

### 8.8.2 "Did the platform tamper with my data?"

The subject downloads a `.data` export with `include_history: true`,
then verifies the gamma chain end-to-end (each entry's prev_hash
matches the previous's hash, each signature verifies). Any tampered or
inserted entry breaks the chain. The subject can re-export periodically
and diff to detect changes.

### 8.8.3 "Show me everything that happened on a specific record."

The subject queries `aithos.list_gamma_entries` with a filter on the
record_id (in the payload). The platform returns every entry referencing
that record — creation, modifications, and deletion. The subject
reconstructs the record's full lifecycle.

## 8.9 Gamma in write-only mode

Per Ethos §10.11.1, a PDS MAY operate the gamma log in "write-only" mode:
entries are persisted but not exposed via read primitives. This mode is
acceptable for the data sub-protocol; the subject's own client can
retain a copy of every gamma entry it submits and reconstruct the
chain locally.

In write-only mode, the `.data` export with `include_history: true` is
the canonical way for the subject to retrieve their audit trail.

---

Next: [chapter 09 — Threat model](./09-threat-model.md).
