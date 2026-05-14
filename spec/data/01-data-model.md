# 1 · Data model

## 1.1 The three primitives

The data sub-protocol is built around three primitive types:

```
Collection ──contains──→ Record(s)
    │
    └──conforms-to──→ Schema
```

- A **Schema** declares the shape of a kind of data (e.g. "a contact").
  It is published, versioned, and immutable once issued.
- A **Collection** is a container scoped to one schema, owned by one
  subject. A subject may have many collections, including multiple
  collections under the same schema (e.g. `contacts.work` and
  `contacts.personal` both under `aithos.contacts.v1`).
- A **Record** is one instance of a schema, stored in a collection.
  Records are identified by ULIDs and ordered by creation time.

The rest of this chapter specifies the data model of Collections and
Records. Schemas are specified in [chapter 03](./03-schemas.md).

## 1.2 Collection

### 1.2.1 Identifier

A collection is identified by the tuple `(subject_did, collection_name)`.

- `subject_did` — the Aithos DID of the subject that owns the collection.
- `collection_name` — a string drawn from `[a-z][a-z0-9_-]{0,62}`,
  MUST NOT start with the reserved prefix `aithos_` (reserved for
  protocol-managed collections).

Examples of valid names: `contacts`, `messages`, `calendar`,
`contacts_work`, `prospects-2026`.

Collection names are unique within a subject. The full URN form for a
collection is:

```
urn:aithos:collection:<subject_did>:<collection_name>
```

This URN is used in mandates (chapter 04), in audit log entries
(chapter 08), and in export artifacts (chapter 07).

### 1.2.2 Required fields

A collection's metadata document, as exposed by `aithos.data.get_collection`
(chapter 05), has the following shape:

```json
{
  "aithos-data": "0.1.0",
  "urn": "urn:aithos:collection:did:aithos:z6Mkr…:contacts",
  "subject_did": "did:aithos:z6Mkr…",
  "name": "contacts",
  "schema": "aithos.contacts.v1",
  "created_at": "2026-05-14T08:14:23Z",
  "modified_at": "2026-06-02T11:42:09Z",
  "record_count": 247,
  "cmk": {
    "alg": "xchacha20poly1305-ietf",
    "wraps": [
      {
        "recipient": "did:aithos:z6Mkr…#data-kex",
        "alg": "x25519-hkdf-sha256-aead",
        "ephemeral_public": "z6LS…",
        "wrap_nonce": "bK3x…",
        "wrapped_key": "cP2r…"
      }
    ]
  },
  "gamma_ref": "gamma_01J…"
}
```

| Field | Type | Description |
|---|---|---|
| `aithos-data` | string | Sub-protocol version. MUST be `"0.1.0"` for this draft. |
| `urn` | string | Canonical URN for the collection (§1.2.1). |
| `subject_did` | string | Owner's DID. |
| `name` | string | Collection name within the subject's namespace. |
| `schema` | string | Schema identifier, of form `aithos.<name>.v<n>`. |
| `created_at` | string (RFC 3339) | First publication of this collection. Immutable once set. |
| `modified_at` | string (RFC 3339) | Last collection-level mutation (rotation, add/revoke recipient). |
| `record_count` | integer | Number of non-deleted records. Server-computed, advisory. |
| `cmk` | object | Collection Master Key envelope per [chapter 02](./02-key-hierarchy.md). |
| `gamma_ref` | string | Gamma entry id of the most recent collection-level mutation. |

### 1.2.3 Collection lifecycle

A collection passes through four states:

```
                 create_collection
       ┌────────────────────────────────┐
       │                                ↓
       │                            ┌─────────┐
       │                            │  ACTIVE │ ←─ rotate_cmk
       │                            └─────────┘    authorize_app
       │                                │          revoke_app
       │                                │
       │            tombstone_collection│
       │                                ↓
       │                          ┌──────────┐
       │                          │TOMBSTONED│ (read-only, indexed-out)
       │                          └──────────┘
       │                                │
       │       purge_collection         │
       │   (after retention window)     │
       │                                ↓
       │                           ┌─────────┐
       └─────────────────────────→ │  GONE   │
                                   └─────────┘
```

Transitions:

- **create_collection** → ACTIVE. Issued by the owner. Creates the CMK,
  produces the first wrap (for the owner's sphere key), writes the
  collection metadata document, emits a gamma entry `data.collection.created`.
- **authorize_app / revoke_app / rotate_cmk** → ACTIVE → ACTIVE. Mutate
  the CMK wrap list. Each emits a gamma entry.
- **tombstone_collection** → TOMBSTONED. Marks the collection as
  soft-deleted. Records remain readable to existing authorized recipients
  but the collection no longer accepts writes, no longer appears in the
  subject's collection listing, and is excluded from cross-collection
  queries. Issued by the owner.
- **purge_collection** → GONE. Hard delete after a retention window
  (default 30 days post-tombstone, configurable per platform). All
  ciphertexts and metadata are removed; gamma entries remain (they are
  append-only).

A platform MAY refuse to issue `purge_collection` for compliance reasons
(e.g. a regulated user under retention obligation). In that case the
collection stays TOMBSTONED indefinitely.

### 1.2.4 Single-schema invariant

A collection is bound to exactly one schema for its entire lifetime. To
change schema, the subject MUST create a new collection and migrate
records explicitly. This is a deliberate invariant: it makes the
"applications conforming to the same schema read the same data" property
(P5 in chapter 00) non-negotiable.

A schema's minor or patch version bump (e.g. `aithos.contacts.v1` →
`aithos.contacts.v1.1`) is **not** a schema change — the major version is
the contract. Backward-compatible schema evolution is specified in
[chapter 03](./03-schemas.md).

## 1.3 Record

### 1.3.1 Identifier

A record is identified by a [ULID](https://github.com/ulid/spec):

```
record_01J9YB2X7Q1K3P4R5S6T7U8V9W
```

The ULID encodes a 48-bit millisecond timestamp and 80 bits of randomness,
lexicographically sortable by creation time. Identifiers are scoped to a
collection — `(subject_did, collection_name, record_id)` is the global
addressing tuple.

A record's full URN form:

```
urn:aithos:record:<subject_did>:<collection_name>:<record_id>
```

### 1.3.2 Record document — server view

The "server view" is what the PDS stores and what readers receive over
the wire. It separates clear metadata from encrypted payload:

```json
{
  "aithos-data": "0.1.0",
  "urn": "urn:aithos:record:did:aithos:z6Mkr…:contacts:record_01J…",
  "collection_urn": "urn:aithos:collection:did:aithos:z6Mkr…:contacts",
  "record_id": "record_01J…",
  "schema": "aithos.contacts.v1",
  "metadata": {
    "name": "Jean Dupont",
    "email": "jean@example.com",
    "phone_hash": "blake3:7f3a…",
    "status": "lead",
    "tags": ["priority", "fr"],
    "created_at": "2026-05-14T09:12:43Z",
    "modified_at": "2026-05-14T15:33:01Z"
  },
  "payload": {
    "alg": "xchacha20poly1305-ietf",
    "nonce": "9c4f…",
    "ciphertext": "b2d8…",
    "dek_wrapped_for_cmk": "f7a1…"
  },
  "gamma_ref": "gamma_01K…",
  "deleted": false
}
```

| Field | Type | Description |
|---|---|---|
| `aithos-data` | string | Sub-protocol version. |
| `urn` | string | Canonical URN for the record. |
| `collection_urn` | string | URN of the containing collection. |
| `record_id` | string | ULID identifier within the collection. |
| `schema` | string | Schema id — MUST equal the containing collection's schema. |
| `metadata` | object | Fields declared `indexable` in the schema. Stored in clear. |
| `payload` | object | AEAD ciphertext of the encrypted fields. Schema in §1.3.4. |
| `gamma_ref` | string | Gamma entry id of the most recent mutation to this record. |
| `deleted` | boolean | `true` after a `delete_record` call (soft delete). |

### 1.3.3 Record document — client view

The "client view" is what the SDK presents after decryption, merging
metadata and payload into a single object that conforms to the schema:

```json
{
  "record_id": "record_01J…",
  "name": "Jean Dupont",
  "email": "jean@example.com",
  "phone": "+33612345678",
  "status": "lead",
  "tags": ["priority", "fr"],
  "notes": "Met at SaaStr 2026. Interested in our enterprise tier.",
  "conversation_log": [
    { "at": "2026-05-14T10:00:00Z", "from": "user", "text": "…" }
  ],
  "form_responses": { "company_size": "10-50", "budget_range": "€20k+" },
  "created_at": "2026-05-14T09:12:43Z",
  "modified_at": "2026-05-14T15:33:01Z"
}
```

`name`, `email`, `status`, `tags`, `created_at`, `modified_at` are the
indexable fields (server-visible). `phone`, `notes`, `conversation_log`,
`form_responses` are the encrypted fields (server-blind). The schema
(`aithos.contacts.v1`) is what dictates the split — see chapter 03.

### 1.3.4 Payload envelope

The `payload` field of a record carries an AEAD envelope:

```json
{
  "alg": "xchacha20poly1305-ietf",
  "nonce": "9c4f…",
  "ciphertext": "b2d8…",
  "dek_wrapped_for_cmk": "f7a1…"
}
```

| Field | Type | Description |
|---|---|---|
| `alg` | string | AEAD algorithm. MUST be `"xchacha20poly1305-ietf"` in v0.1. |
| `nonce` | string (base64) | 24-byte nonce. Fresh per encryption operation. |
| `ciphertext` | string (base64) | AEAD output: encrypted payload + 16-byte tag. |
| `dek_wrapped_for_cmk` | string (base64) | The 32-byte DEK, wrapped under the current CMK. |

The AAD (additional authenticated data) bound to each AEAD operation is:

```
"aithos-data-record-v1\0" ‖ utf8(subject_did) ‖ "\0" ‖
   utf8(collection_name) ‖ "\0" ‖ utf8(record_id)
```

This binding ensures a ciphertext cannot be replayed from one record into
another, or from one collection to another, or across subjects. See
[chapter 09 — Threat model](./09-threat-model.md) for the rationale.

### 1.3.5 Record lifecycle

```
                 insert_record
       ┌────────────────────────────────┐
       │                                ↓
       │                          ┌──────────┐
       │     update_record   ───→ │  ACTIVE  │
       │                          └──────────┘
       │                                │
       │           delete_record         │
       │                                ↓
       │                         ┌────────────┐
       │                         │SOFT-DELETED│
       │                         └────────────┘
       │                                │
       │     purge_record (admin)        │
       │                                ↓
       │                          ┌─────────┐
       └────────────────────────→ │  GONE   │
                                  └─────────┘
```

Transitions:

- **insert_record** → ACTIVE. Owner or app with `data.<collection>.write`
  scope. Generates DEK, encrypts payload, wraps DEK for CMK, writes
  metadata clear, emits gamma entry `data.record.created`.
- **update_record** → ACTIVE → ACTIVE. Re-encrypts payload with same
  DEK + fresh nonce, OR with fresh DEK depending on the rotation
  policy (see [chapter 02 §2.5](./02-key-hierarchy.md)). Updates
  modified_at, emits gamma entry `data.record.modified`.
- **delete_record** → SOFT-DELETED. Sets `deleted: true`, retains the
  metadata + ciphertext for the gamma chain integrity. Emits gamma
  entry `data.record.deleted`. The record no longer appears in
  `list_records` results unless `include_deleted: true` is explicitly
  passed.
- **purge_record** → GONE. Administrative operation; not exposed to apps.
  Used during PDS maintenance to permanently remove a soft-deleted record
  after a retention window. Emits gamma entry `data.record.purged` with
  only the record_id (no metadata or payload to preserve).

A record's `deleted` flag is part of the metadata clear; an app holding a
read mandate sees that a record was deleted even if it cannot read the
payload. This is intentional: the existence of the record is part of the
collection's structural state, distinct from the record's content.

## 1.4 Ordering and listing

Records within a collection are listed in **ULID descending order by
default** — newest first, matching most CRUD UI expectations. Callers
MAY request ascending order via `aithos.data.list_records` parameters.

Lexicographic comparison of ULIDs reproduces creation-time order, since
the first 48 bits of a ULID encode a millisecond timestamp. This makes
range queries `record_id > 'record_01J…' ` equivalent to time queries,
without requiring a separate timestamp index.

The pagination model for `list_records` is specified in
[chapter 06](./06-pagination.md).

## 1.5 Cross-collection references

Records may carry references to other records (e.g. a `messages` record
referencing a `contacts` record as its recipient). The protocol does not
enforce referential integrity — that is a schema-level concern. A schema
declaring a reference field follows this pattern:

```json
{
  "type": "object",
  "properties": {
    "to_contact": {
      "type": "string",
      "format": "urn",
      "aithos:ref": "aithos.contacts.v1"
    }
  }
}
```

The `aithos:ref` annotation declares that the field's value MUST be a
record URN of the named schema. Validators MAY check that the referenced
record exists at write time; readers MUST NOT assume the reference still
resolves (the target may have been deleted).

Cross-collection references are URNs in the metadata clear, so they are
indexable: an app can query "all messages whose `to_contact` is
`record_X`" using a server-side filter.

## 1.6 Owner sphere key binding

Every collection is owned by exactly one subject. Ownership is
established at `create_collection` time and is permanent — there is no
ownership transfer primitive in v0.1.

The owner relationship is enforced at three layers:

1. **Identification.** The collection's `subject_did` is set at creation
   and never modified.
2. **Authorization.** Every mutation (record CRUD, collection-level
   operations, mandate management) MUST be signed in an envelope whose
   `iss` is `subject_did`. For mandate-authorized writes by an
   application, `iss` is still the subject and the mandate appears as
   `_envelope.mandate`; for sphere-key writes by the owner directly,
   `iss` is the subject and the signing key is one of the subject's
   sphere keys.
3. **Encryption.** The CMK is wrapped at minimum for one of the owner's
   sphere keys. The platform refuses to write a collection whose CMK
   has no wrap matching a verification method in the subject's DID
   document. See [chapter 02 §2.4](./02-key-hierarchy.md).

A subject who loses control of all their sphere keys (without a recovery
file — see Ethos spec §1) loses access to their collections, with no
recovery mechanism at the protocol layer. This matches the Ethos
sub-protocol's behaviour and is intentional: a backdoor to recover from
total key loss would weaken the ownership guarantee.

## 1.7 What is NOT in the data model

The following are explicitly out of scope for v0.1:

- **Collaborative editing of a record by multiple writers in real-time.**
  Records are not CRDTs. Concurrent writes by different applications to
  the same record produce a last-write-wins result; conflicting writes
  are resolved by the platform's ordering of received writes. Schemas
  needing collaboration semantics should design their fields to be
  append-only (e.g. `conversation_log` as an array that grows, with each
  entry self-contained).
- **Bulk imports of millions of records in one call.** Bulk operations
  are deferred to a future minor version. v0.1 expects per-record writes.
- **Cross-subject collections.** A collection has one owner; data shared
  between subjects is modeled by each subject having their own
  collection and an explicit sync protocol (out of scope for this RFC).
- **Versioned records.** A record holds its current state only; history
  is reconstructable from the gamma log (chapter 08) but is not exposed
  as a versioned read primitive in v0.1.

Future revisions MAY relax these omissions.

---

Next: [chapter 02 — Key hierarchy](./02-key-hierarchy.md).
