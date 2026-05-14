# 3 · Schemas

## 3.1 Overview

A **schema** in this sub-protocol declares the shape of a record type:
its fields, their types, which are server-indexable and which are
client-encrypted, validation rules, references to other schemas.

Schemas are the contract that makes interop real. An application that
writes records under `aithos.contacts.v1` and another that reads them
under the same identifier are reading and writing the same fields with
the same semantics. Without schema discipline, portability is cosmetic
(see chapter 00 §0.3 P5).

This chapter specifies:

- The schema document format (JSON Schema + Aithos annotations).
- The split between indexable (clear) and encrypted fields.
- The naming and versioning rules.
- Validation, both at write time and at schema publication time.
- The process for proposing new core schemas.

## 3.2 Schema document format

A schema is a JSON document conforming to [JSON Schema 2020-12](https://json-schema.org/),
augmented with three Aithos-specific keyword annotations under the
`aithos:*` prefix.

### 3.2.1 Example

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.aithos.dev/aithos.contacts.v1.json",
  "aithos:schema": "aithos.contacts.v1",
  "aithos:version": "0.1.0",
  "aithos:created_at": "2026-05-14T08:00:00Z",
  "title": "Contact (prospect or customer)",
  "description": "A natural-person contact record for CRM-like use cases.",
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 200,
      "aithos:indexable": true
    },
    "email": {
      "type": "string",
      "format": "email",
      "maxLength": 200,
      "aithos:indexable": true
    },
    "phone": {
      "type": "string",
      "maxLength": 50,
      "aithos:encrypted": true
    },
    "phone_hash": {
      "type": "string",
      "pattern": "^blake3:[0-9a-f]{64}$",
      "aithos:indexable": true,
      "aithos:derived_from": "phone",
      "description": "Blake3 hash of normalized phone, for exact-match lookup without leaking the number itself."
    },
    "status": {
      "type": "string",
      "enum": ["lead", "contact", "opportunity", "won", "lost", "archived"],
      "aithos:indexable": true,
      "default": "lead"
    },
    "tags": {
      "type": "array",
      "items": { "type": "string", "maxLength": 64 },
      "maxItems": 32,
      "aithos:indexable": true
    },
    "notes": {
      "type": "string",
      "maxLength": 100000,
      "aithos:encrypted": true
    },
    "conversation_log": {
      "type": "array",
      "items": { "$ref": "#/$defs/conversationEntry" },
      "aithos:encrypted": true
    },
    "form_responses": {
      "type": "object",
      "additionalProperties": true,
      "aithos:encrypted": true
    },
    "created_at": {
      "type": "string",
      "format": "date-time",
      "aithos:indexable": true,
      "aithos:auto": "on_insert"
    },
    "modified_at": {
      "type": "string",
      "format": "date-time",
      "aithos:indexable": true,
      "aithos:auto": "on_modify"
    }
  },
  "$defs": {
    "conversationEntry": {
      "type": "object",
      "required": ["at", "from", "text"],
      "properties": {
        "at": { "type": "string", "format": "date-time" },
        "from": { "type": "string", "enum": ["user", "agent", "contact"] },
        "text": { "type": "string", "maxLength": 50000 }
      }
    }
  }
}
```

### 3.2.2 Top-level required fields

| Field | Type | Description |
|---|---|---|
| `$schema` | string | MUST be `"https://json-schema.org/draft/2020-12/schema"`. |
| `$id` | string | Canonical URL for the schema document (informative). |
| `aithos:schema` | string | Schema identifier (§3.3). REQUIRED, unique. |
| `aithos:version` | string | Schema document version, semver. REQUIRED. |
| `aithos:created_at` | string (RFC 3339) | First publication date. Immutable. |
| `title` | string | Human-readable name. REQUIRED. |
| `type` | string | MUST be `"object"`. |
| `properties` | object | Field definitions. REQUIRED. |

### 3.2.3 Per-field Aithos annotations

The following keywords extend JSON Schema with sub-protocol semantics:

| Keyword | Type | Description |
|---|---|---|
| `aithos:indexable` | boolean | If `true`, the field is stored in `metadata_clear` on the PDS, visible to the server, indexed for queries. Mutually exclusive with `aithos:encrypted`. |
| `aithos:encrypted` | boolean | If `true`, the field is in the AEAD-encrypted payload. Server-invisible. Mutually exclusive with `aithos:indexable`. |
| `aithos:derived_from` | string | Name of another field this one is derived from (typically a hash for index lookup). Informative. |
| `aithos:auto` | string | One of `"on_insert"`, `"on_modify"`. The platform sets this field automatically; client-supplied values are ignored. |
| `aithos:ref` | string | The field's value is a record URN of the named schema (§1.5). |
| `aithos:pii` | boolean | Marks the field as personally identifiable. Informative, used by audit and export to apply privacy rules. |

A field that is neither `aithos:indexable` nor `aithos:encrypted` is
considered **opaque metadata**: it is stored in `metadata_clear` but not
indexed by the server (no GSI projection). Apps can read it, the server
won't filter by it.

### 3.2.4 The clear/encrypted split

A schema MUST be designed such that:

- Every field used in mandate filters or in `list_records` queries is
  `aithos:indexable`.
- Every field carrying free-form, potentially sensitive, or unbounded
  content is `aithos:encrypted`.
- The two sets are disjoint — a field cannot be both indexable and
  encrypted.

Implementations MUST reject a record write that includes a field not
declared in the schema, OR that places a value of the wrong type in a
field. See §3.5 for the validation procedure.

## 3.3 Naming

A schema identifier (`aithos:schema`) has the form:

```
aithos.<name>.v<major>
```

where:

- `<name>` is a lowercase string matching `[a-z][a-z0-9_-]{0,62}`,
  optionally segmented with dots for organization namespaces
  (e.g. `aithos.contacts.v1`, `aithos.x.acme.invoices.v1`).
- `<major>` is a positive integer.

The `aithos.*` namespace (no other segments before `<name>`) is
reserved for **core schemas** maintained by the Aithos protocol
authority. Third parties publish under their own namespace:
`aithos.x.<vendor>.<name>.v<n>` or any other prefix not starting with
`aithos.<bareword>`.

Examples:

- `aithos.contacts.v1` — core schema for natural-person contacts.
- `aithos.messages.v1` — core schema for messages (mail, DM, SMS).
- `aithos.calendar.v1` — core schema for calendar events.
- `aithos.x.switchia.qualification_session.v1` — vendor-specific schema.

## 3.4 Versioning

### 3.4.1 Major version (`vN` in the identifier)

The major version is part of the schema identifier and represents the
**breaking-change boundary**. A collection bound to `aithos.contacts.v1`
will never see records conforming to `aithos.contacts.v2`. Migrations
between major versions are explicit and require creating a new
collection.

### 3.4.2 Minor and patch versions (`aithos:version` field)

Within a major version, the schema document's `aithos:version` (semver)
can evolve subject to strict backward-compatibility rules:

- **Patch** (`v1.0.0` → `v1.0.1`) — documentation, descriptions, minor
  type tightening that doesn't reject previously-valid records.
- **Minor** (`v1.0.0` → `v1.1.0`) — purely additive: new optional
  fields, new optional enum values. Existing records remain valid.
- **No backward-incompatible change** within a major version. Removing a
  field, narrowing a type, adding a required field, changing a field's
  `aithos:indexable`/`aithos:encrypted` annotation are all forbidden in
  minor/patch revisions.

A schema breaking these rules MUST bump its major version (publish a
`aithos.<name>.v(N+1)` document) and is treated as a distinct schema.

### 3.4.3 Resolution

Applications dereference schema identifiers as follows:

1. **Cached registry.** A platform maintains a registry of known
   schemas. Resolution starts here.
2. **`$id` URL.** If not in cache, the platform MAY fetch the schema
   document from the `$id` URL declared in the schema. Implementations
   SHOULD pin schemas they have validated to avoid runtime DNS
   dependency.
3. **Hardcoded.** Conformant implementations SHOULD bundle the core
   `aithos.*` schemas at build time, with no runtime fetch needed.

A schema document, once published with a given `aithos:schema` +
`aithos:version`, is immutable. Any change requires bumping the version.
A platform MUST refuse to accept a write referencing a schema it cannot
resolve.

## 3.5 Validation

### 3.5.1 At write time

When an application calls `aithos.data.insert_record` or
`update_record`, the platform validates the supplied record against the
schema as follows:

1. **Schema lookup.** Resolve `aithos:schema` of the containing
   collection. If unknown, reject with `AITHOS_DATA_SCHEMA_UNKNOWN`.
2. **Structural validation.** Run the record against the JSON Schema's
   structural rules: types, required fields, formats, patterns.
3. **Annotation enforcement.**
   - For each `aithos:indexable` field: validate the value, store in
     `metadata_clear`.
   - For each `aithos:encrypted` field: validate the value, place in
     the payload object to be encrypted (chapter 02 §2.4.4).
   - For each `aithos:auto` field: set value server-side, reject if
     client supplied a value.
   - For each `aithos:ref` field: validate the URN format. The platform
     MAY (but is not required to) check that the referenced record
     exists at write time.
4. **Size limits.** The platform MAY apply size limits per-field or
   per-record. Recommended defaults: 64 KB for any encrypted field
   stored as JSON, 400 KB total per record, beyond which the platform
   pushes the encrypted payload to S3 with the record metadata pointing
   to the object.

### 3.5.2 At schema publication

A new schema (or new version) is validated at publication:

1. **Identifier well-formedness** (§3.3).
2. **JSON Schema 2020-12 validity** — the document itself validates
   against the meta-schema.
3. **Aithos annotation consistency** — no field is both indexable and
   encrypted, every `aithos:ref` points to a known schema, etc.
4. **Backward compatibility** (for minor/patch bumps over an existing
   major version) — automated diff against the previous version
   confirms only additive changes.

Schema publication is not part of the PDS write path. Schemas are
published via the protocol registry process (§3.7), not via runtime
calls.

## 3.6 Indexing model — how the platform uses schemas

A conformant PDS uses the schema's `aithos:indexable` annotations to
provision:

- **A primary index** on `(subject_did, collection_name, record_id)`
  for direct fetch.
- **A secondary index** (in DynamoDB terms, a GSI) per indexable field
  that the schema marks as `aithos:queryable: true` (a sub-annotation
  for fields that the platform should provision a dedicated index for;
  by default, indexable fields are filterable but not separately
  indexed beyond a scan on the primary partition).

The platform SHOULD support filtering on any `aithos:indexable` field
via `list_records`. The platform MAY refuse complex predicates
(arbitrary `AND` / `OR` combinations of unrelated fields) for cost
reasons; the canonical predicate form is "equality on one indexed
field + optional range on a second indexed field," matching DynamoDB
GSI semantics.

## 3.7 Core schemas and registry

### 3.7.1 v0.1 core schemas

The following schemas SHOULD be published alongside the v0.1
sub-protocol release:

- **`aithos.contacts.v1`** — natural-person contact records (CRM, address
  book, prospect pipeline). Reference: [03a-schema-contacts-v1.md](./03a-schema-contacts-v1.md)
  (to be drafted alongside the reference implementation).

Subsequent schemas (`messages.v1`, `calendar.v1`, `documents.v1`) are
deferred to later minor versions of the sub-protocol. They follow the
same publication process when their first concrete use case appears.

### 3.7.2 Publication process

Until a formal RFC process is in place:

1. A schema proposal is opened as a markdown document in the protocol
   repo under `spec/data/schemas/draft-<name>.md`, with the proposed
   schema document, rationale, expected use cases, and any prior art.
2. The draft is open to comment for ≥14 days.
3. If accepted, the schema document is moved to
   `spec/data/schemas/aithos.<name>.v1.json` and the draft markdown
   becomes the normative documentation.
4. A platform implementing the schema MUST follow the document
   verbatim; deviations require a new major version.

### 3.7.3 Schema retraction

A core schema once published is, in principle, permanent. If a schema
must be retracted (e.g. discovered design flaw), the protocol authority
publishes:

- A `RETRACTED` notice in the schema's documentation.
- A successor schema (`v2`).
- Migration guidance for subjects holding collections under the
  retracted version.

The retracted schema continues to be served by conformant platforms
(existing collections must remain readable), but new collections MAY be
refused under the retracted identifier.

## 3.8 Implementation requirements

A conformant implementation MUST:

- Validate records against the declared collection schema before storage.
- Reject writes referencing unknown schemas.
- Enforce the `aithos:indexable` / `aithos:encrypted` split — clear
  fields go to `metadata`, encrypted fields go inside the payload
  ciphertext.
- Enforce `aithos:auto` — set fields server-side on insert/modify,
  reject client-supplied values.
- Preserve fields the schema declares but the record omits (treat as
  absent, default values applied per the schema).

A conformant implementation SHOULD:

- Bundle the v0.1 core schemas at build time.
- Provide schema validation as a callable primitive
  (`aithos.data.validate_record`) for application-side pre-check before
  RPC, to reduce error surface.
- Surface clear error messages indicating which field failed and why.

---

Next: [chapter 04 — Mandates](./04-mandates.md).
