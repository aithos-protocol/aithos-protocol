# 5 · API primitives

## 5.1 Overview

The data sub-protocol exposes its primitives over the same MCP transport
as the Ethos sub-protocol's platform endpoint (Ethos chapter 10):

```
POST {base}/mcp/primitives/read
POST {base}/mcp/primitives/write
```

with the JSON-RPC method names beginning with `aithos.data.*`. Reads are
anonymous from a transport standpoint; writes carry signed envelopes
per Ethos chapter 11.

The PDS implementation MAY expose the primitives on a dedicated endpoint
(e.g. `{base}/mcp/data/`) to ease deployment separation, as long as the
URI is discoverable via the platform's `initialize` response.

## 5.2 Authentication summary

| Method category | Authentication |
|---|---|
| Anonymous reads (limited) | None — only `aithos.data.list_public_collections` (see §5.3.1). |
| Owner reads/writes | Signed envelope with sphere key (`#data` or `#root`). |
| App reads/writes | Signed envelope + mandate (§4). |

A read for a private collection requires authentication even though
Ethos reads are anonymous. This reflects the fact that data records are
operational state, not public attestation.

## 5.3 Read primitives

### 5.3.1 `aithos.data.list_public_collections`

Anonymous endpoint listing collections a subject has marked as public.
Most data sub-protocol use cases involve private collections; this
primitive exists for cases like an artist publishing their catalogue.

Input:

```ts
interface ListPublicCollectionsInput {
  subject_did: string;
  limit?: number;     // default 20, max 100
  cursor?: string;
}
```

Output: `Page<CollectionBrief>`.

### 5.3.2 `aithos.data.get_collection`

Retrieve a collection's metadata document.

Input:

```ts
interface GetCollectionInput {
  subject_did: string;
  collection_name: string;
}
```

Output: `CollectionMetadata` per §1.2.2.

Authentication: required. Caller must hold either a sphere key matching
a wrap in the CMK or a mandate with at least `data.<col>.read` scope.

### 5.3.3 `aithos.data.list_collections`

List all collections a subject owns. Authentication: required; caller
must be the owner.

Input:

```ts
interface ListCollectionsInput {
  subject_did: string;     // MUST equal envelope iss for owner-only access
  limit?: number;
  cursor?: string;
}
```

Output: `Page<CollectionBrief>`:

```ts
interface CollectionBrief {
  name: string;
  urn: string;
  schema: string;
  record_count: number;
  created_at: string;
  modified_at: string;
}
```

### 5.3.4 `aithos.data.get_record`

Retrieve one record.

Input:

```ts
interface GetRecordInput {
  collection_urn: string;
  record_id: string;
}
```

Output: `RecordServerView` per §1.3.2.

Authentication: required. The caller must hold either an owner sphere
key or a mandate with `data.<col>.read` scope. Filter mandates are
enforced per §4.3.2.

Errors:
- `AITHOS_NOT_FOUND` — record doesn't exist OR is outside caller's
  filter scope.
- `AITHOS_INSUFFICIENT_SCOPE` — mandate lacks `read` on this collection.

### 5.3.5 `aithos.data.list_records`

Paginated list of records, with optional filtering.

Input:

```ts
interface ListRecordsInput {
  collection_urn: string;
  filter?: RecordFilter;    // optional, see §5.3.5.1
  order?: "newest" | "oldest";  // default "newest"
  limit?: number;            // default 20, max 100
  cursor?: string;
  include_deleted?: boolean; // default false
}

interface RecordFilter {
  // Equality on a single indexable field
  equals?: { field: string; value: string | number | boolean };
  // Substring search on a single string field (case-insensitive)
  contains?: { field: string; value: string };
  // Tag set membership: record's tags array contains any of these
  tags_any?: string[];
  // Tag set: record's tags array contains all of these
  tags_all?: string[];
  // Range on a single timestamp field
  range?: { field: string; gte?: string; lte?: string };
}
```

Filter semantics: a `RecordFilter` is a conjunction (AND) of its
non-null fields. The platform MAY refuse a filter combination it
cannot index efficiently with `AITHOS_DATA_FILTER_UNSUPPORTED`. The
minimum a conformant PDS MUST support: `equals` on any indexable field,
`tags_any`, `range` on `created_at` and `modified_at`.

Output: `Page<RecordServerView>` per §1.3.2.

### 5.3.6 `aithos.data.count_records`

Return the count of records matching a filter, without returning the
records themselves. Useful for UIs showing "247 prospects" without
fetching the records.

Input: same as `list_records` minus `limit`/`cursor`/`order`.

Output: `{ count: number, exact: boolean }`. `exact: false` indicates
the count is an estimate (the platform MAY return an estimate when an
exact count would be expensive).

## 5.4 Write primitives

All write primitives carry a signed envelope. The envelope is verified
per Ethos §11.4. Each method's `params` body is described below.

### 5.4.1 `aithos.data.create_collection`

Initialize a new collection.

Input:

```ts
interface CreateCollectionInput {
  subject_did: string;
  collection_name: string;
  schema: string;                  // e.g. "aithos.contacts.v1"
  cmk_envelope: CMKEnvelope;       // CMK wrapped for owner (chapter 02)
  forward_secrecy?: "best_effort" | "strict";  // default "best_effort"
}

interface CMKEnvelope {
  alg: "xchacha20poly1305-ietf";
  wraps: WrapEntry[];              // at minimum one for owner
}
```

Server-side: validates the schema exists, the collection name is
available, the CMK envelope contains at least one wrap matching a
sphere key in the subject's DID document. Records the
`forward_secrecy` flag (immutable for the collection's life).

Output: `CollectionMetadata` per §1.2.2.

Emits gamma entry: `data.collection.created`.

### 5.4.2 `aithos.data.insert_record`

Insert one record.

Input:

```ts
interface InsertRecordInput {
  collection_urn: string;
  record_id?: string;              // optional, server generates ULID if omitted
  metadata: Record<string, unknown>; // indexable fields per schema
  payload: PayloadEnvelope;        // encrypted payload per §1.3.4
}
```

The platform validates `metadata` against the schema's indexable
fields. It does NOT decrypt or validate the payload — that's the
client's responsibility against the schema's encrypted fields.

Output: `{ record_id: string, gamma_ref: string }`.

Emits gamma entry: `data.record.created`.

### 5.4.3 `aithos.data.update_record`

Mutate one record. The full new state is supplied; the platform
replaces the existing record.

Input:

```ts
interface UpdateRecordInput {
  collection_urn: string;
  record_id: string;
  metadata: Record<string, unknown>;
  payload: PayloadEnvelope;
  expected_modified_at?: string;   // optimistic concurrency control
}
```

If `expected_modified_at` is supplied and doesn't match the record's
current `modified_at`, the platform rejects with
`AITHOS_DATA_CONCURRENT_MODIFICATION`. This lets clients implement
optimistic locking without polling.

Emits gamma entry: `data.record.modified`.

### 5.4.4 `aithos.data.delete_record`

Soft-delete a record. Sets `deleted: true` and clears the payload
(server replaces with an empty ciphertext) so storage is reclaimed
even before the post-tombstone retention window expires.

Input:

```ts
interface DeleteRecordInput {
  collection_urn: string;
  record_id: string;
}
```

Output: `{ deleted_at: string, gamma_ref: string }`.

Emits gamma entry: `data.record.deleted`.

### 5.4.5 `aithos.data.authorize_app`

Add a recipient to the collection's CMK wrap list.

Input:

```ts
interface AuthorizeAppInput {
  collection_urn: string;
  mandate: SignedMandate;          // full mandate document
  wrap: WrapEntry;                 // CMK wrap for the grantee
  filter?: FilterClause;           // optional, mirrors mandate scope filter
}
```

Server-side: validates the mandate signature, scope coverage, grantee
identity match (`mandate.grantee.kex_pubkey` == `wrap.recipient`-key
material). Appends the wrap.

Output: `{ wrap_index: number, gamma_ref: string }`.

Emits gamma entry: `data.collection.authorize_grantee`.

### 5.4.6 `aithos.data.revoke_app`

Remove a recipient. May force CMK rotation per §4.6.

Input:

```ts
interface RevokeAppInput {
  collection_urn: string;
  mandate_id: string;
  revocation: SignedRevocation;
  rotate_cmk?: boolean;            // default reflects collection.forward_secrecy
  new_cmk_envelope?: CMKEnvelope;  // required if rotate_cmk: true
  re_encrypted_records?: {         // required if rotate_cmk: true and forward_secrecy: strict
    record_id: string;
    metadata: Record<string, unknown>;
    payload: PayloadEnvelope;      // re-encrypted under the new CMK's DEK chain
  }[];
}
```

If `rotate_cmk: true` and `forward_secrecy: "best_effort"`, only the
CMK and the per-record `dek_wrapped_for_cmk` are renewed; ciphertexts
are kept as-is. If `forward_secrecy: "strict"`, the caller MUST supply
re-encrypted ciphertexts for every record.

Output: `{ revoked_at: string, gamma_ref: string }`.

Emits gamma entry: `data.collection.revoke_grantee` (and possibly
`data.collection.rotate_cmk`).

### 5.4.7 `aithos.data.rotate_cmk`

Rotate the CMK on demand (independent of any revoke). The caller (the
owner) supplies the new CMK envelope and the new per-record DEK
wraps.

Input:

```ts
interface RotateCMKInput {
  collection_urn: string;
  new_cmk_envelope: CMKEnvelope;
  re_wrapped_deks: {
    record_id: string;
    dek_wrapped_for_cmk: string;   // new wrap of the existing DEK
  }[];
  re_encrypted_records?: {         // only if forward_secrecy: strict
    record_id: string;
    metadata: Record<string, unknown>;
    payload: PayloadEnvelope;
  }[];
}
```

The operation is atomic from the platform's perspective: the new CMK
and the new wraps are committed together; reads after the commit see
the new CMK.

Emits gamma entry: `data.collection.rotate_cmk`.

### 5.4.8 `aithos.data.rotate_owner_wrap`

After the subject rotates their `#data` sphere key, every collection
needs a new wrap of the CMK for the new sphere key. This primitive
performs that wrap.

Input:

```ts
interface RotateOwnerWrapInput {
  collection_urn: string;
  new_wrap: WrapEntry;             // CMK wrapped for the new #data-kex
}
```

The caller MUST sign the envelope with the new sphere key. The
platform's verification path looks up the subject's current DID
document (which by this time advertises the new key) and confirms
the new wrap's `recipient` matches the new `#data-kex` DID URL.

Emits gamma entry: `data.collection.rotate_owner_wrap`.

### 5.4.9 `aithos.data.tombstone_collection`

Soft-delete the entire collection.

Input:

```ts
interface TombstoneCollectionInput {
  collection_urn: string;
  reason?: string;
}
```

Effect: marks the collection as TOMBSTONED, freezes writes, excludes
from `list_collections` results unless `include_tombstoned: true`. The
records remain readable (so authorized grantees can extract data
before purge) for the platform's retention window.

Emits gamma entry: `data.collection.tombstoned`.

## 5.5 Schema-related primitives

### 5.5.1 `aithos.data.get_schema`

Fetch a schema document by identifier.

Input: `{ schema: string }` — e.g. `"aithos.contacts.v1"`.

Output: full JSON Schema document (§3.2.1).

Anonymous read. Schemas are public.

### 5.5.2 `aithos.data.list_schemas`

List schemas the platform knows.

Input:

```ts
interface ListSchemasInput {
  prefix?: string;       // e.g. "aithos.contacts" or "aithos.x.acme"
  limit?: number;
  cursor?: string;
}
```

Output: `Page<SchemaBrief>`:

```ts
interface SchemaBrief {
  schema: string;        // identifier
  version: string;       // aithos:version
  title: string;
  $id: string;           // canonical URL
}
```

### 5.5.3 `aithos.data.validate_record`

Run schema validation against a candidate record, without inserting it.
Useful for client-side pre-validation.

Input: `{ schema: string, record: Record<string, unknown> }`.

Output: `{ valid: boolean, errors?: ValidationError[] }`.

## 5.6 Portability primitives

### 5.6.1 `aithos.data.export_collection`

Begin a collection export. Returns a job identifier; the export is
streamed asynchronously (chapter 07).

Input:

```ts
interface ExportCollectionInput {
  collection_urn: string;
  include_history?: boolean;   // default false; include full gamma log if true
}
```

Output: `{ job_id: string }`. Job results are fetched via
`aithos.data.get_export_status`.

### 5.6.2 `aithos.data.get_export_status`

Poll the status of an export job.

Input: `{ job_id: string }`.

Output:

```ts
interface ExportStatus {
  job_id: string;
  state: "pending" | "running" | "ready" | "failed";
  artifact_url?: string;     // when state == "ready"
  expires_at?: string;       // signed-URL expiry
  bytes?: number;
  error?: string;
}
```

### 5.6.3 `aithos.data.import_collection`

Import a `.data` artifact into a fresh collection (chapter 07).

Input:

```ts
interface ImportCollectionInput {
  artifact_url: string;       // signed URL or data: URL of the .data file
  new_collection_name?: string; // defaults to the export's source name
}
```

Output: `CollectionMetadata` of the imported collection.

The import primitive validates the artifact's signature against the
exporting subject's DID document, refuses to import malformed or
unsigned artifacts.

## 5.7 Error codes

The data sub-protocol extends the Ethos error code table (Ethos §10.9)
with codes in the range `[-32099, -32070]`:

| Code    | Name                              | Meaning |
|---------|-----------------------------------|---------|
| -32070  | `AITHOS_DATA_SCHEMA_UNKNOWN`      | Schema id not resolvable. |
| -32071  | `AITHOS_DATA_SCHEMA_INVALID`      | Schema document fails validation. |
| -32072  | `AITHOS_DATA_RECORD_INVALID`      | Record fails schema validation. |
| -32073  | `AITHOS_DATA_COLLECTION_EXISTS`   | `create_collection` on an existing name. |
| -32074  | `AITHOS_DATA_COLLECTION_TOMBSTONED` | Operation on a tombstoned collection. |
| -32075  | `AITHOS_DATA_FILTER_VIOLATION`    | Record (post-write) would fall outside mandate filter. |
| -32076  | `AITHOS_DATA_FILTER_UNSUPPORTED`  | Query filter is well-formed but not supported by this platform. |
| -32077  | `AITHOS_DATA_CONCURRENT_MODIFICATION` | `expected_modified_at` mismatch. |
| -32078  | `AITHOS_DATA_CMK_INVALID`         | CMK envelope malformed or wraps missing required owner. |
| -32079  | `AITHOS_DATA_WRAP_RECIPIENT_MISMATCH` | Authorize_app wrap's recipient doesn't match the mandate's grantee key. |
| -32080  | `AITHOS_DATA_ROTATION_IN_PROGRESS` | Concurrent CMK rotation. |
| -32081  | `AITHOS_DATA_OWNER_WRAP_MISSING`  | After sphere rotation, the collection has no wrap for the current owner sphere. |

Reuse from Ethos: `AITHOS_NOT_FOUND` (-32020), `AITHOS_INSUFFICIENT_SCOPE`
(-32042), `AITHOS_BAD_ENVELOPE` (-32010), `AITHOS_BAD_SIGNATURE`
(-32011), `AITHOS_MANDATE_INVALID` (-32040), `AITHOS_MANDATE_REVOKED`
(-32041), `AITHOS_RATE_LIMITED` (-32050).

## 5.8 Rate limits

A conformant PDS SHOULD enforce at least:

- **Per-mandate writes.** 200/min sustained, burst 30. Per-mandate, not
  per-subject — the subject's own writes are not rate-limited beyond
  any platform-wide limits.
- **Per-mandate reads.** 600/min sustained.
- **Schema fetches.** 60/min anonymous (the schema cache should make
  this rare).
- **Authorize / revoke.** 10/min per subject. Higher rates suggest a
  bug or abuse.

Rate limits a mandate carries in `constraints.rate_limit` are
additionally enforced on top of platform limits. The stricter of the
two wins.

---

Next: [chapter 06 — Pagination](./06-pagination.md).
