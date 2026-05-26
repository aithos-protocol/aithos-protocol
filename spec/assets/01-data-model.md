# 1 · Data model

## 1.1 The single primitive

The assets sub-protocol is built around a single primitive type: the
**Asset**. Assets are flat — there is no enclosing container analogous
to a data collection or an Ethos zone. Every asset is owned by a subject
DID, identified by a ULID, and reachable directly from that subject's
asset space.

```
Subject ──owns──→ Asset(s)
   │
   └──refers-to-from──→ Ethos sections / data records
```

The flatness is deliberate. Most consumers reach for an asset by URN —
which already carries the subject DID and the asset ID — and rarely
need to enumerate "all assets in folder X". Grouping is achieved
extrinsically through the `referenced_by[]` index (§1.3): the set of
assets attached to a given Ethos zone or data collection is a query
result, not a folder.

## 1.2 Asset

### 1.2.1 Identifier

An asset is identified by the tuple `(subject_did, asset_id)`.

- `subject_did` — the Aithos DID of the subject that owns the asset.
- `asset_id` — a Crockford-base32 ULID prefixed by `asset_`, e.g.
  `asset_01J9YB2X7Q1K3P4R5S6T7U8V9W`. The ULID's 48-bit timestamp
  prefix sorts assets chronologically by creation time. ULIDs are
  unique within the subject's asset space.

The full URN form for an asset is:

```
urn:aithos:asset:<subject_did>:<asset_id>
```

This URN is used in mandates (chapter 04), in audit log entries
(chapter 08), in export artifacts (chapter 07), and as the
authoritative reference handle from Ethos sections and data records.

### 1.2.2 Required fields

An asset's metadata document, as returned by `aithos.assets.get_asset`
(chapter 05), has the following shape:

```json
{
  "aithos-assets": "0.1.0",
  "urn": "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…",
  "subject_did": "did:aithos:z6Mkr…",
  "asset_id": "asset_01J9YB2X7Q1K3P4R5S6T7U8V9W",
  "media_type": "image/png",
  "size_bytes": 184320,
  "sha256_of_plaintext": "a8b2f1ef…",
  "encrypted": true,
  "amk_envelope": {
    "alg": "xchacha20poly1305-ietf",
    "nonce": "bK3x…",
    "wraps": [
      {
        "recipient": "did:aithos:z6Mkr…#self-kex",
        "alg": "x25519-hkdf-sha256-aead",
        "ephemeral_public": "z6LS…",
        "wrap_nonce": "cP2r…",
        "wrapped_key": "dQ8s…"
      }
    ]
  },
  "storage": {
    "backend": "s3",
    "key": "did:aithos:z6Mkr…/asset_01J…/raw.bin"
  },
  "attached_context": {
    "zone_hint": "self",
    "kind": "ethos"
  },
  "referenced_by": [
    {
      "kind": "ethos.section",
      "ethos_edition_urn": "urn:aithos:ethos:john-doe:2026.05.10-1",
      "zone": "self",
      "section_id": "sec_career_docs",
      "since_height": 14
    }
  ],
  "created_at": "2026-05-10T08:14:23Z",
  "modified_at": "2026-05-10T08:14:23Z",
  "last_referenced_at": "2026-05-12T11:42:09Z",
  "gamma_ref": "gamma_01J…"
}
```

| Field | Type | Description |
|---|---|---|
| `aithos-assets` | string | Sub-protocol version. MUST be `"0.1.0"` for this draft. |
| `urn` | string | Canonical URN for the asset (§1.2.1). |
| `subject_did` | string | Owner's DID. |
| `asset_id` | string | ULID identifier within the subject's asset space. |
| `media_type` | string | IANA media type (RFC 6838). REQUIRED. |
| `size_bytes` | integer | Size of the plaintext content. REQUIRED. The on-disk ciphertext size is `size_bytes + 16` (Poly1305 tag) for encrypted assets, plus negligible AEAD overhead. |
| `sha256_of_plaintext` | string (hex) | SHA-256 of the plaintext bytes, lower-case hex. The content address. REQUIRED. |
| `encrypted` | boolean | `true` if the asset bytes are AEAD-encrypted under an AMK; `false` if stored as plaintext. REQUIRED. |
| `amk_envelope` | object | AMK envelope per [chapter 02](./02-key-hierarchy.md). REQUIRED iff `encrypted: true`; MUST be absent iff `encrypted: false`. |
| `storage` | object | Storage backend metadata (§1.2.3). REQUIRED. |
| `attached_context` | object | An informative hint describing the originating attachment context, used by the RecipientResolver at upload time (§1.5). Not authoritative — `referenced_by[]` is. |
| `referenced_by` | array | List of contexts currently referencing this asset (§1.3). REQUIRED. MAY be `[]` (orphan). |
| `created_at` | string (RFC 3339) | First publication of this asset. Immutable once set. |
| `modified_at` | string (RFC 3339) | Last metadata-level mutation (AMK rotation, authorize/revoke recipient, reference change). |
| `last_referenced_at` | string (RFC 3339) | Most recent moment a reference was added or removed. Used by the purge scheduler (§1.2.4). |
| `gamma_ref` | string | Gamma entry id of the most recent asset-level mutation. |

The asset metadata document is **stored in the index table** (DynamoDB
in the reference implementation), not in S3. The S3 object holds only
the raw bytes (plaintext or ciphertext). This split lets the metadata
be small, indexable, and queryable without touching the byte storage.

### 1.2.3 Storage backend descriptor

The `storage` object describes where the asset bytes live:

```json
{
  "backend": "s3",
  "key": "did:aithos:z6Mkr…/asset_01J…/raw.bin"
}
```

- `backend` — implementation discriminator. v0.1 defines only `"s3"`.
  A future revision MAY add `"ipfs"`, `"r2"`, `"gcs"`, etc.
- `key` — the implementation-specific object key. For S3 in the
  reference implementation, the key form is
  `<subject_did>/<asset_id>/raw.bin`. The bucket name itself is not
  part of the descriptor; it is the deployment's configuration.

Clients SHOULD treat the `storage` field as opaque and SHOULD reach the
bytes via the `aithos.assets.get_asset` RPC (which yields a presigned
URL), not by composing a direct URL from `storage.key`. The descriptor
is exposed for portability (chapter 07) and audit, not for direct
fetching.

### 1.2.4 Asset lifecycle

An asset passes through four states:

```
                  init_upload + complete_upload
       ┌────────────────────────────────────────┐
       │                                         ↓
       │                                  ┌────────────┐
       │                                  │   ACTIVE   │ ←─ authorize_grantee
       │                                  └────────────┘    revoke_grantee
       │                                         │          rotate_amk
       │                                         │          ref / unref
       │                                         │
       │       reference_count drops to 0        │
       │   (last unref leaves referenced_by=[])  │
       │                                         ↓
       │                                  ┌────────────┐
       │                                  │  ORPHANED  │  (waits retention window)
       │                                  └────────────┘
       │                                         │
       │         retention_window elapsed        │
       │            OR explicit purge            │
       │                                         ↓
       │                                  ┌────────────┐
       │                                  │ TOMBSTONED │  (metadata kept, bytes purged)
       │                                  └────────────┘
       │                                         │
       │             tombstone_window elapsed    │
       │                                         ↓
       │                                  ┌────────────┐
       └────────────────────────────────→ │    GONE    │  (metadata also purged)
                                          └────────────┘
```

Transitions:

- `ACTIVE → ORPHANED` — Automatic. The platform observes
  `referenced_by[]` becoming empty (typically after the last `unref`
  call). The transition emits a `assets.orphaned` gamma entry.

- `ORPHANED → ACTIVE` — Reversible. If a new `ref` arrives during the
  retention window, the asset re-enters ACTIVE. Emits
  `assets.referenced` (no special "un-orphan" entry; the reference
  itself signals the return).

- `ORPHANED → TOMBSTONED` — Automatic, after `retention_window` (default
  90 days from `last_referenced_at`). The S3 object is deleted; the
  metadata document is kept with a `tombstoned_at` field. Emits
  `assets.tombstoned`.

- `TOMBSTONED → GONE` — Automatic, after `tombstone_window` (default
  90 additional days). The metadata document is also deleted. Emits
  `assets.purged`.

- Any state → ORPHANED (or TOMBSTONED directly) — Explicit. The owner
  MAY call `aithos.assets.delete_asset` to force immediate purge. The
  call moves the asset to TOMBSTONED if `referenced_by[]` is empty, or
  rejects with `AITHOS_ASSETS_STILL_REFERENCED` otherwise (the owner
  must first unreference, then delete).

The retention and tombstone windows are platform configuration, not
protocol-mandated. The defaults above are recommended; deployments MAY
configure shorter windows for size-constrained environments, but
shorter windows reduce the safety net for accidental dereference.

### 1.2.5 Immutability of bytes

The asset's plaintext bytes are immutable. Once `complete_upload` has
been validated against `sha256_of_plaintext`, the S3 object MUST NOT be
overwritten with different content. An "edit" semantics is achieved at
a layer above: the consumer (an Ethos editor, a data record handler)
creates a **new** asset with a new ULID, points the reference at the
new asset, and unreferences the old. The old asset becomes orphaned
and is eventually purged.

This is what makes asset URNs and `sha256_of_plaintext` content-
addressable: anyone receiving an URN can fetch the bytes and verify
they correspond to the expected SHA-256, with no risk of TOCTOU between
two reads.

Mutable metadata (the AMK envelope's wrap list, `referenced_by[]`) is
permitted to change; the byte payload is not.

## 1.3 The `referenced_by[]` index

Every asset metadata document carries a `referenced_by[]` array listing
the contexts that currently point to it. Each entry is one of:

```json
{
  "kind": "ethos.section",
  "ethos_edition_urn": "urn:aithos:ethos:<handle>:<version>",
  "zone": "public" | "circle" | "self",
  "section_id": "sec_…",
  "since_height": 14
}
```

```json
{
  "kind": "data.record",
  "data_record_urn": "urn:aithos:data-record:<subject>:<collection>:<record_id>",
  "field": "attachment",
  "since": "2026-05-12T11:42:09Z"
}
```

| Field | Description |
|---|---|
| `kind` | One of `"ethos.section"`, `"data.record"`, or future kinds. REQUIRED. |
| `ethos_edition_urn` / `data_record_urn` | URN of the referring context. REQUIRED for the corresponding kind. |
| `zone` / `section_id` / `field` | Sub-identifier within the referring context. REQUIRED for the corresponding kind. |
| `since_height` / `since` | When the reference was added. Used by the audit log (chapter 08). |

### 1.3.1 Updates

References are added and removed via the explicit RPCs
`aithos.assets.ref_asset` and `aithos.assets.unref_asset`
(chapter 05 §5.4.6 and §5.4.7), called by the consuming sub-protocol's
write path:

- An Ethos publish that introduces a new asset reference in a section
  calls `ref_asset` as part of the edition's commit. An edition that
  drops a reference (the section was modified to remove the URN, or the
  section was deleted) calls `unref_asset`.
- A data record write that includes an asset URN in an `attachment`
  field calls `ref_asset`. Updating the record to remove or replace
  the URN calls `unref_asset` and possibly a new `ref_asset` for the
  replacement.

The calls MUST be authenticated by the same envelope as the parent
operation (the Ethos edition write or the data record write). Each emits
a gamma entry: `assets.referenced` or `assets.unreferenced`.

### 1.3.2 Counter invariants

The platform MUST maintain `referenced_by[]` such that:

- An entry is appended exactly once when `ref_asset` is called with new
  `(kind, urn, sub-id)` tuple. Idempotent on duplicate calls (the
  platform detects the tuple already exists and returns success without
  growing the array).
- An entry is removed exactly once when `unref_asset` is called.
  Idempotent on duplicate calls (no entry to remove → success).
- `referenced_by[]` is updated **atomically** with the gamma entry. A
  failure between the index update and the gamma append leaves the
  asset in a recoverable state (the gamma append is the journal; the
  index is the materialized view, and a reconciliation pass can rebuild
  the index from gamma if needed).

### 1.3.3 Privacy of the index

`referenced_by[]` is visible to the platform and to the asset's owner.
It is NOT visible to a recipient who has been granted access to the
asset but not to the referring context. Specifically:

- An owner sees the full `referenced_by[]` list for every asset they
  own.
- A grantee authorized on the asset (chapter 04) sees only the
  references for which the grantee is also authorized on the referring
  context. The platform applies this filter at read time.
- The platform itself sees the full list to operate the purge
  scheduler and the ref-count invariants.

The size of `referenced_by[]` is itself a metadata leak (see chapter 09
§9.2.3); subjects with strong unlinkability requirements may want to
keep references few and aliased.

## 1.4 Intra-subject deduplication

A subject who uploads the same plaintext twice MUST produce only one
asset object in storage. The deduplication mechanism is the
content-address binding established by `sha256_of_plaintext`.

### 1.4.1 Pre-upload probe

The client computes `sha256_of_plaintext` locally and submits it to
`aithos.assets.init_upload` (chapter 05 §5.4.1). The platform queries an
internal index `(subject_did, sha256_of_plaintext) → asset_id`. Two
cases:

1. **Hit.** The platform returns the existing `asset_id` and skips the
   presigned-URL allocation. The client treats the response as a
   successful upload of an asset already in the subject's space. No new
   gamma entry is emitted; if the caller subsequently issues a `ref_asset`
   on this URN, that is the only state change.

2. **Miss.** The platform allocates a new `asset_id`, returns the
   presigned PUT URL, and waits for the client to upload the bytes and
   call `complete_upload`.

### 1.4.2 Hash collision handling

A SHA-256 collision is computationally infeasible. The platform
nonetheless validates `sha256(uploaded_bytes) == claimed_sha256` at
`complete_upload` and rejects with `AITHOS_ASSETS_HASH_MISMATCH`
if they diverge. This protects against (a) honest client bugs and (b) a
malicious client trying to associate one hash with mismatching bytes.

### 1.4.3 No cross-subject deduplication

The deduplication index is keyed by `(subject_did, sha256_of_plaintext)`,
not by `sha256_of_plaintext` alone. Two distinct subjects uploading the
same plaintext produce two distinct asset objects with two distinct
AMKs (or, for public assets, two distinct S3 objects under separate
prefixes). See chapter 09 §9.4 for the threat-model rationale.

## 1.5 Attached context and the RecipientResolver

When a client calls `aithos.assets.init_upload`, it MAY supply an
`attached_context` argument:

```ts
interface AttachedContext {
  kind: "ethos" | "data";
  // For ethos: which zone is the asset destined for?
  zone?: "public" | "circle" | "self";
  // For ethos in v0.3+: which specific section?
  section_id?: string;
  // For data: which collection?
  collection_urn?: string;
}
```

This argument is **informative** — it tells the SDK and the platform
which RecipientResolver to apply when constructing the asset's AMK wrap
list. The resolver is the abstraction that allows the same asset code
path to work across Ethos v0.2 (zone-grain), Ethos v0.3 (section-grain),
and data collections (CMK-grain).

### 1.5.1 Resolver outputs

Given an `AttachedContext`, the resolver returns:

- For `kind: "ethos"` + `zone: "public"`: empty recipient set. The
  asset is uploaded with `encrypted: false`; no AMK is generated.

- For `kind: "ethos"` + `zone: "circle" | "self"` under Ethos v0.2:
  the recipient set is the union of the subject's matching sphere
  key (`#circle-kex` or `#self-kex`) and any grantee currently
  authorized on the zone via a recipient-conferring mandate. The set
  is computed by inspecting the current bundle manifest's
  `zones.<zone>.cipher.wraps[]`.

- For `kind: "ethos"` + `zone: "circle" | "self"` + `section_id`
  under Ethos v0.3: the recipient set is the wrap list of the specific
  section, read from `manifest.zones.<zone>.sections[i].cipher.wraps[]`
  for the matching `section_id`.

- For `kind: "data"` + `collection_urn`: the recipient set is the
  union of the subject's `#data-kex` sphere key and any grantee
  currently in the collection's CMK envelope wrap list.

### 1.5.2 Resolver-time vs upload-time

The resolver runs **at upload time only**. The wrap list produced is
recorded in the asset's `amk_envelope` and persists until the owner
explicitly rotates the AMK or authorizes/revokes a recipient.
Subsequent changes to the referring context's recipient set (e.g. a new
grantee added to a circle zone) do NOT automatically propagate to
already-uploaded assets attached to that zone. The owner MUST issue
`aithos.assets.authorize_grantee` per-asset to bring the grantee into
the wrap list.

This decoupling is deliberate. An asset, once uploaded, is its own
authorization unit; binding it to the dynamic state of a zone would
mean re-encrypting assets every time a zone's recipient list changes,
which is exactly the O(zone size) cost that the per-asset AMK
construction was introduced to avoid.

The SDK MAY offer a convenience method `assets.sync_recipients(urn)`
that compares the asset's wrap list to the referring context's current
wrap list and adds/removes wraps to match. This is sugar around the
authorize/revoke RPCs and remains the owner's explicit choice.

## 1.6 Constraints on byte content

The protocol places normative bounds on what an asset may carry:

- **Maximum size.** v0.1 imposes a soft cap of **100 MB per asset** for
  the simple single-PUT upload path. Larger assets are reserved for a
  multipart streaming path specified in a future revision (currently
  in §10.5). The platform MAY enforce a hard limit (e.g. 500 MB) via
  the presigned URL's `Content-Length` constraint.

- **Media type.** The `media_type` MUST be a valid IANA registered or
  vendor-tree media type per RFC 6838. The platform MAY reject media
  types not in its allow-list (typically: images, PDFs, common
  document formats, common audio/video). The allow-list is platform
  configuration, not protocol-mandated.

- **Active content.** The platform MUST refuse to serve assets whose
  media type would cause active code execution in a typical browser
  context (e.g. `text/html`, `application/javascript`,
  `application/x-shockwave-flash`). This is enforced at upload time
  by the media type allow-list and at fetch time by appropriate
  `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`
  headers on the presigned URL response.

- **No symbolic content.** The asset payload is opaque bytes. No
  recursive parsing, no embedded scripts, no executable. The platform
  treats the bytes as inert; the only validation performed is
  size, hash, and (optionally) magic-byte sniffing against the
  declared media type.

## 1.7 Public versus private regime

The `encrypted` flag bisects the asset universe into two regimes whose
operational semantics differ:

| Property | Public (`encrypted: false`) | Private (`encrypted: true`) |
|---|---|---|
| AMK | None | One per asset |
| S3 object content | Plaintext bytes | AEAD ciphertext |
| Fetch URL | Stable CloudFront URL (long-lived) | S3 presigned URL (short TTL, default 15 min) |
| Recipient gating | None — anyone with the URL can fetch | AMK wrap required; URL alone is insufficient |
| Suitable for | Avatars, branding, public catalog images, logos | Personal documents, IDs, signed contracts, private photos |
| Server visibility | Bytes are public anyway | Bytes are opaque to server |
| Cost-per-byte | Lower (cached by CDN, single object) | Higher (per-fetch presign, no CDN cache for private) |

The two regimes are not interchangeable. An asset uploaded as public
cannot be later "encrypted" by the platform — its plaintext bytes are
already in S3 and may have been cached by CDN. The owner can instead
upload a new private asset, switch the reference, and dereference the
public one. Similarly, a private asset cannot be unilaterally
"published"; the owner uploads a public copy and re-references.

The SDK chooses the regime automatically based on the `AttachedContext`
(public zones → public regime; everything else → private regime). The
owner MAY override this in advanced flows by passing an explicit
`regime` argument to `init_upload`.

---

Next: [chapter 02 — Key hierarchy](./02-key-hierarchy.md).
