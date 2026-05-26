# 5 · API primitives

## 5.1 Overview

The assets sub-protocol exposes its primitives over the same MCP
transport as the Ethos and data sub-protocols:

```
POST {base}/mcp/primitives/read
POST {base}/mcp/primitives/write
```

with JSON-RPC method names beginning with `aithos.assets.*`. Reads of
public assets are anonymous from a transport standpoint; reads of
private assets and all writes carry signed envelopes per Ethos
chapter 11.

The PDS implementation MAY expose the primitives on a dedicated
endpoint (e.g. `{base}/mcp/assets/`) to ease deployment separation, as
long as the URI is discoverable via the platform's `initialize`
response.

The asset bytes themselves do **not** travel over JSON-RPC. The RPC
returns a **presigned URL** (S3 signed PUT for upload, S3 signed GET
for private fetch, or a stable CloudFront URL for public fetch). The
caller transfers bytes directly to/from object storage out-of-band of
the JSON-RPC channel. This keeps the RPC tier cheap and the byte path
high-throughput.

## 5.2 Authentication summary

| Method category | Authentication |
|---|---|
| Anonymous reads of public assets | None — `aithos.assets.get_public_asset`, `aithos.assets.head_public_asset` (see §5.3.7–5.3.8). |
| Owner reads/writes | Signed envelope with sphere key (`#circle`, `#self`, `#public`, `#data` depending on attaching context). |
| App reads/writes | Signed envelope + mandate (§4). |

A read for a private asset requires authentication even if the asset's
public hash is otherwise known.

## 5.3 Read primitives

### 5.3.1 `aithos.assets.get_asset`

Retrieve an asset's full metadata document plus a presigned fetch URL.

Input:

```ts
interface GetAssetInput {
  urn: string;                    // urn:aithos:asset:<did>:<asset_id>
  url_ttl_seconds?: number;       // default 900 (15 min), max 3600
  range?: { start: number; end?: number };  // OPTIONAL byte-range for public assets only (private assets must decrypt the whole AEAD frame)
}
```

Output:

```ts
interface GetAssetOutput {
  asset: AssetMetadata;           // §1.2.2
  fetch_url: string;              // presigned URL or stable CloudFront URL
  fetch_url_expires_at?: string;  // RFC 3339 for presigned URLs; absent for stable URLs
  fetch_url_kind: "s3_presigned" | "cloudfront_stable";
}
```

Authentication: required for private assets (caller must hold an
owner sphere key or a mandate per §4.3). Anonymous for public assets;
the platform MAY route anonymous get_asset to the public variant
internally without surfacing the distinction.

The caller, upon receiving the response:

1. For a private asset: locates its wrap in `asset.amk_envelope.wraps`,
   unwraps the AMK (§2.3.5).
2. Fetches the bytes via `fetch_url`.
3. For a private asset: decrypts with the AMK and the asset's nonce
   (§2.3.6); verifies SHA-256 against `asset.sha256_of_plaintext`.
4. For a public asset: verifies SHA-256 against `asset.sha256_of_plaintext`.

Errors:
- `AITHOS_NOT_FOUND` — asset does not exist OR caller has insufficient
  scope (per §4.4, the platform conflates these to avoid leaking
  existence).
- `AITHOS_ASSETS_TOMBSTONED` — asset is in TOMBSTONED state; metadata
  is returned but `fetch_url` is omitted.

### 5.3.2 `aithos.assets.head_asset`

Fetch only the metadata, without allocating a presigned URL. Useful
for refresh-checks (has the asset's `modified_at` changed?), for
sizing batch downloads, or for verifying a remote hash before
fetching.

Input: `{ urn: string }`.
Output: `{ asset: AssetMetadata }`.

Authentication: same as `get_asset`.

### 5.3.3 `aithos.assets.list_assets`

Paginated list of assets, with optional filtering.

Input:

```ts
interface ListAssetsInput {
  subject_did: string;              // owner being queried
  filter?: AssetFilter;             // §5.3.3.1
  order?: "newest" | "oldest";      // default "newest"
  limit?: number;                   // default 20, max 100
  cursor?: string;
  include_orphaned?: boolean;       // default false
  include_tombstoned?: boolean;     // default false
}

interface AssetFilter {
  media_type_prefix?: string;       // e.g. "image/"
  attached_to?:
    | { kind: "ethos"; zone?: "public" | "circle" | "self"; section_id?: string }
    | { kind: "data"; collection_name?: string; record_id?: string };
  size_bytes?: { gte?: number; lte?: number };
  created_after?: string;           // RFC 3339
  created_before?: string;          // RFC 3339
  tags_any?: string[];              // matched via the referring context's tags
}
```

Output: `Page<AssetBrief>`:

```ts
interface AssetBrief {
  urn: string;
  asset_id: string;
  media_type: string;
  size_bytes: number;
  sha256_of_plaintext: string;
  encrypted: boolean;
  created_at: string;
  modified_at: string;
  reference_count: number;          // = referenced_by.length
  state: "ACTIVE" | "ORPHANED" | "TOMBSTONED";
}
```

A grantee with a context-scoped read mandate (§4.2.2) MUST receive
only the assets within their authorized scope; the platform filters
the result at query time.

Authentication: required (owner or grantee).

### 5.3.4 `aithos.assets.list_references`

Return the `referenced_by[]` array for one asset, filtered by the
caller's authorization (per §1.3.3).

Input: `{ urn: string, limit?: number, cursor?: string }`.
Output: `Page<AssetReference>` (entry shape per §1.3).

Useful for an owner to inspect why an asset is still pinned (e.g.
"why can't I delete this avatar?"), and for tools that need to walk
incoming references.

### 5.3.5 `aithos.assets.verify`

Verify integrity of a stored asset without fetching the bytes. The
platform reads the S3 object (or a sampled hash), recomputes
`sha256_of_plaintext` (or, for private assets, `sha256_of_ciphertext`
since the platform cannot decrypt), and compares to the metadata.

Input: `{ urn: string }`.
Output:

```ts
interface VerifyOutput {
  urn: string;
  storage_present: boolean;
  storage_size_bytes: number;
  storage_sha256: string;                  // SHA-256 of the on-disk bytes
  metadata_sha256_of_plaintext: string;    // as recorded in metadata
  metadata_sha256_of_ciphertext?: string;  // platform-computed at upload time, if recorded
  ok: boolean;                             // metadata and storage agree
  notes?: string;                          // diagnostic for ok=false
}
```

A client MAY use this to detect platform-side corruption (storage
SHA differs from what was recorded at upload), independently of any
fetch.

Authentication: required (owner or mandate with `read`).

### 5.3.6 `aithos.assets.list_recipients`

List the recipients currently authorized on an asset.

Input: `{ urn: string }`.
Output:

```ts
interface ListRecipientsOutput {
  urn: string;
  recipients: {
    recipient: string;          // DID URL
    kind: "owner_sphere" | "grantee";
    mandate_id?: string;        // for grantee recipients
    added_at: string;
  }[];
}
```

Authentication: owner only by default. A grantee MAY be granted
visibility via a special scope `assets.<urn>.list_recipients` (not in
the v0.1 default vocabulary).

### 5.3.7 `aithos.assets.get_public_asset` (anonymous)

Convenience variant for public assets. Returns the stable CloudFront
URL plus the integrity hash, without an authenticated envelope.

Input: `{ urn: string }`.
Output:

```ts
interface GetPublicAssetOutput {
  urn: string;
  media_type: string;
  size_bytes: number;
  sha256_of_plaintext: string;
  fetch_url: string;          // stable CloudFront URL
  // No metadata beyond integrity, no recipients.
}
```

Rejects with `AITHOS_NOT_PUBLIC` if the asset is private.

### 5.3.8 `aithos.assets.head_public_asset` (anonymous)

Same as `get_public_asset` but without the fetch URL — pure integrity
metadata. Useful for content-address verification before bothering
with a fetch.

## 5.4 Write primitives

All write primitives carry a signed envelope. The envelope is verified
per Ethos §11.4. Each method's `params` body is described below.

### 5.4.1 `aithos.assets.init_upload`

Begin a new upload. The platform allocates an `asset_id`, runs the
deduplication probe (§1.4.1), and either returns the existing
asset_id (hit) or returns a presigned PUT URL plus an upload session
token (miss).

Input:

```ts
interface InitUploadInput {
  subject_did: string;
  media_type: string;
  size_bytes: number;
  sha256_of_plaintext: string;
  attached_context?: AttachedContext;  // §1.5
  regime?: "auto" | "public" | "private";  // default "auto"
  forward_secrecy?: "best_effort" | "strict";  // default "best_effort"
  // For private regime: the AMK envelope (constructed client-side via the RecipientResolver)
  amk_envelope?: AMKEnvelope;
  // For private regime: the bytes encryption nonce (the AMK's nonce)
  encryption_nonce?: string;             // base64 of 24 bytes
}
```

Output (dedup hit):

```ts
interface InitUploadHit {
  result: "dedup_hit";
  urn: string;
  asset_id: string;
  asset: AssetMetadata;            // the existing asset's full metadata
}
```

Output (dedup miss — fresh upload):

```ts
interface InitUploadMiss {
  result: "upload";
  urn: string;
  asset_id: string;
  upload_session: string;           // opaque token, presented to complete_upload
  upload_url: string;               // presigned S3 PUT URL
  upload_url_expires_at: string;    // RFC 3339, default +15 min
  upload_constraints: {
    max_bytes: number;
    expected_sha256: string;        // server echoes this back so the client cannot drift
  };
}
```

The platform records an upload-pending entry in the metadata table
with a TTL equal to `upload_url_expires_at + 60s`. If the client
never calls `complete_upload`, the entry expires and the slot is
freed.

The platform writes nothing yet to S3; the client does the PUT
directly using `upload_url`. The S3 object content MUST be:

- For public regime: the plaintext bytes.
- For private regime: `nonce_24 ‖ ciphertext_N ‖ poly1305_tag_16`
  (§2.3.2).

Server-side validations on init:

- Caller's envelope verifies and the issuer is the `subject_did` (or
  a grantee with `assets.attach.<context>` scope).
- `media_type` is in the allow-list.
- `size_bytes` is within the platform's per-asset cap.
- `attached_context`, if present, refers to a context the caller is
  authorized for.
- The dedup probe runs after the above checks.

Emits gamma entry on miss: `assets.upload_initiated`. Dedup hits emit
no gamma entry (no state change).

### 5.4.2 `aithos.assets.complete_upload`

Finalize an upload after the S3 PUT has succeeded.

Input:

```ts
interface CompleteUploadInput {
  upload_session: string;
  // The client may resupply the canonical metadata for double-binding;
  // the platform validates against the values declared at init.
  observed_sha256_of_plaintext?: string;  // RECOMMENDED — defends against client bugs
}
```

Output:

```ts
interface CompleteUploadOutput {
  urn: string;
  asset: AssetMetadata;     // now in ACTIVE state
}
```

Server-side validations:

- The S3 object at the allocated key exists and its size matches
  `size_bytes` from init.
- The SHA-256 of the object bytes matches:
  - For public assets: `sha256_of_plaintext` from init.
  - For private assets: NOT verifiable server-side (ciphertext bytes
    are not `sha256_of_plaintext`). The platform records the
    SHA-256 of the ciphertext as `sha256_of_ciphertext` (used by
    `verify`) and trusts the client's claim of plaintext SHA.
- For public assets, an OPTIONAL magic-byte sniff (§3.4.2).

On success, the upload-pending entry transitions to ACTIVE, the
metadata document is materialized fully, and a `assets.created`
gamma entry is emitted.

Errors:
- `AITHOS_ASSETS_UPLOAD_NOT_FOUND` — session token unknown or
  expired.
- `AITHOS_ASSETS_HASH_MISMATCH` — public asset's SHA differs from
  declared.
- `AITHOS_ASSETS_SIZE_MISMATCH` — actual S3 object size differs
  from declared.

### 5.4.3 `aithos.assets.abort_upload`

Cancel a pending upload. The platform deletes any partial S3 object
and releases the asset_id slot.

Input: `{ upload_session: string }`.
Output: `{ aborted: boolean }`.

### 5.4.4 `aithos.assets.ref_asset`

Add a reference entry to an asset's `referenced_by[]`. Called by the
consuming sub-protocol's write path (Ethos publish, data record
insert/update) as part of its commit.

Input:

```ts
interface RefAssetInput {
  urn: string;
  reference:
    | {
        kind: "ethos.section";
        ethos_edition_urn: string;
        zone: "public" | "circle" | "self";
        section_id: string;
        since_height: number;
      }
    | {
        kind: "data.record";
        data_record_urn: string;
        field: string;
      };
}
```

Output: `{ urn: string, reference_count: number, gamma_ref: string }`.

The call is idempotent: if the same `(kind, ...id fields)` tuple already
exists in `referenced_by[]`, the platform returns success without
mutating the array.

If the asset was in ORPHANED state, this call moves it back to ACTIVE.

Authentication: owner OR mandate with `assets.attach.<context>` where
`<context>` matches the reference's kind/zone/collection.

Emits gamma entry: `assets.referenced`.

### 5.4.5 `aithos.assets.unref_asset`

Remove a reference from `referenced_by[]`. The platform decrements
the implicit count; if it reaches zero, the asset transitions to
ORPHANED.

Input: same shape as `ref_asset`.
Output: `{ urn: string, reference_count: number, gamma_ref: string }`.

Idempotent: removing a non-existent reference returns success.

Emits gamma entry: `assets.unreferenced`. If the count drops to zero,
additionally emits `assets.orphaned`.

### 5.4.6 `aithos.assets.delete_asset`

Force a transition to TOMBSTONED, bypassing the retention window.
Requires `referenced_by[]` to be empty; otherwise rejects with
`AITHOS_ASSETS_STILL_REFERENCED`.

Input: `{ urn: string }`.
Output: `{ urn: string, tombstoned_at: string, gamma_ref: string }`.

Authentication: owner OR `assets.<urn>.delete` OR `assets.*.delete`.

Effect: S3 object is deleted; metadata document is kept with a
`tombstoned_at` field and `referenced_by: []`. After
`tombstone_window` elapses (platform configuration), the metadata
document is also deleted (`assets.purged`).

Emits gamma entry: `assets.tombstoned`.

### 5.4.7 `aithos.assets.authorize_grantee`

Add a recipient wrap to an asset's `amk_envelope`. Used when issuing a
mandate that needs to confer read access on an asset.

Input:

```ts
interface AuthorizeGranteeInput {
  urn: string;
  mandate: SignedMandate;      // full mandate doc, validated server-side
  wrap: WrapEntry;             // AMK wrap for the grantee
}
```

Server-side: validates the mandate signature, scope coverage on the
asset, grantee identity match (`mandate.grantee.kex_pubkey` matches
the `wrap.recipient`'s X25519 key).

Output: `{ urn: string, recipient_count: number, gamma_ref: string }`.

Emits gamma entry: `assets.authorize_grantee`.

### 5.4.8 `aithos.assets.revoke_grantee`

Remove a recipient's wrap from an asset's `amk_envelope`.

Input:

```ts
interface RevokeGranteeInput {
  urn: string;
  mandate_id: string;
  revocation: SignedRevocation;
  rotate_amk?: boolean;        // default reflects asset.forward_secrecy
  new_amk_envelope?: AMKEnvelope;       // required if rotate_amk: true
  new_encryption_nonce?: string;         // required if rotate_amk: true
  // The client also re-uploads the re-encrypted bytes via init_upload+complete_upload
  // pattern; the new S3 key is the existing asset_id (forced replacement) — protocol
  // wrapper not yet specified for v0.1. See §5.4.10.
}
```

If `rotate_amk: true`, this call is paired with a follow-up
`rotate_amk` (§5.4.10). The platform commits the new wrap list only
after the new ciphertext is fully uploaded.

Output: `{ urn: string, revoked_at: string, gamma_ref: string }`.

Emits gamma entry: `assets.revoke_grantee` (and possibly
`assets.amk_rotated`).

### 5.4.9 `aithos.assets.rotate_amk`

Rotate the AMK and re-encrypt the asset bytes.

Input:

```ts
interface RotateAmkInput {
  urn: string;
  new_amk_envelope: AMKEnvelope;
  new_encryption_nonce: string;
  // The client uploads new ciphertext via a fresh init_upload session,
  // then references the new ciphertext here.
  new_upload_session: string;
}
```

The operation is atomic from a reader's perspective. The platform
updates the metadata's `amk_envelope`, `encryption_nonce`, and
`modified_at`, swaps the S3 object atomically (via versioning), and
emits the gamma entry — all in a single transaction equivalent.

Output: `{ urn: string, asset: AssetMetadata, gamma_ref: string }`.

Authentication: owner only by default. A scope `assets.<urn>.rotate`
exists for delegated rotation (rare).

Emits gamma entry: `assets.amk_rotated`.

### 5.4.10 `aithos.assets.rotate_owner_wrap`

Re-wrap the AMK for a new owner sphere key. Issued after a sphere
key rotation. Per-asset.

Input:

```ts
interface RotateOwnerWrapInput {
  urn: string;
  new_wrap: WrapEntry;       // AMK wrapped for the new sphere key
  // Old wrap is identified by the recipient DID URL it carries.
  old_wrap_recipient: string;
}
```

The caller MUST sign the envelope with the new sphere key. The
platform validates the new wrap's `recipient` matches the new sphere
key in the (now updated) DID document, removes the old wrap, appends
the new one.

Output: `{ urn: string, gamma_ref: string }`.

Emits gamma entry: `assets.rotate_owner_wrap`.

#### 5.4.10.1 Batch variant (informative)

For owners with many assets:

```ts
interface BulkRotateOwnerWrapInput {
  rotations: { urn: string; new_wrap: WrapEntry; old_wrap_recipient: string }[];
}
```

Output: `{ rotated: number, failed: { urn: string; error: AithosError }[] }`.

The platform processes the array sequentially or in parallel as it
chooses; the call is at-least-once-per-item idempotent at the per-asset
level.

## 5.5 Error codes

| Code | Symbol | Meaning |
|---|---|---|
| -32020 | `AITHOS_NOT_FOUND` | Asset does not exist or is outside the caller's filter scope. |
| -32021 | `AITHOS_INSUFFICIENT_SCOPE` | Caller's mandate does not cover the requested op. |
| -32030 | `AITHOS_ASSETS_HASH_MISMATCH` | The uploaded bytes' SHA does not match the declared hash. |
| -32031 | `AITHOS_ASSETS_SIZE_MISMATCH` | The uploaded bytes' size does not match the declared size. |
| -32032 | `AITHOS_ASSETS_UPLOAD_NOT_FOUND` | The upload session token is unknown or expired. |
| -32033 | `AITHOS_ASSETS_STILL_REFERENCED` | `delete_asset` was called on an asset with non-empty `referenced_by[]`. |
| -32034 | `AITHOS_ASSETS_TOMBSTONED` | Asset is in TOMBSTONED state; bytes are gone. |
| -32035 | `AITHOS_ASSETS_NOT_PUBLIC` | An anonymous variant was called on a private asset. |
| -32036 | `AITHOS_ASSETS_MEDIA_TYPE_REJECTED` | The declared media type is not in the platform's allow-list. |
| -32037 | `AITHOS_ASSETS_SIZE_CAP_EXCEEDED` | Declared `size_bytes` exceeds the platform's per-asset cap. |
| -32038 | `AITHOS_ASSETS_QUOTA_EXCEEDED` | The upload would breach the subject's per-subject byte quota. `data` carries `{ used_bytes, limit_bytes }`. See §10.13 for default values. |

## 5.6 Schema-related primitives

Unlike the data sub-protocol, assets are schema-less at the protocol
layer (the schema discipline lives in the consuming context — Ethos's
section model or data's record model). No primitives in this chapter
expose a schema endpoint.

---

Next: [chapter 06 — Pagination](./06-pagination.md).
