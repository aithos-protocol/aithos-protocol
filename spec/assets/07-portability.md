# 7 · Portability

## 7.1 Overview

A core principle (P7, §0.3) is that the subject is never captive: every
asset can be exported and re-imported on any conformant PDS. This
chapter specifies the export artifact format (`.asset` for single
assets, `.assets` for batches), the export procedure, and the import
procedure.

Portability is **specified but not implemented in v0.1**. The reference
implementation MAY expose stub endpoints that return
`AITHOS_NOT_IMPLEMENTED` until a future revision lands the full flow.

## 7.2 The `.asset` artifact (single asset)

A single-asset export is a ZIP archive with the `.asset` extension and
the following internal layout:

```
example_asset_01J….asset
├── manifest.json                 (UTF-8 JSON, §7.2.1)
├── raw.bin                       (the asset bytes — plaintext or ciphertext)
├── did.json                      (the subject's DID document at export time)
└── signature.json                (Ed25519 signature over canonical manifest, §7.2.2)
```

### 7.2.1 The manifest

```json
{
  "aithos-assets": "0.1.0",
  "kind": "asset.export",
  "exported_at": "2026-05-21T09:14:23Z",
  "exported_by": "did:aithos:z6Mkr…",
  "asset": {
    "urn": "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…",
    "asset_id": "asset_01J…",
    "media_type": "image/png",
    "size_bytes": 184320,
    "sha256_of_plaintext": "a8b2f1ef…",
    "sha256_of_ciphertext": "9b12af…",       // present iff encrypted
    "encrypted": true,
    "amk_envelope": { /* full envelope per §1.2.2 */ },
    "encryption_nonce": "bK3x…",
    "created_at": "2026-05-10T08:14:23Z",
    "gamma_ref": "gamma_01J…"
  },
  "referenced_by_at_export": [ /* snapshot of referenced_by[] at export time */ ],
  "history": [ /* OPTIONAL — included if --include-history was set */
    {
      "gamma_entry_id": "gamma_01J…",
      "op": "assets.created",
      "at": "…"
    },
    /* … */
  ]
}
```

### 7.2.2 Signature

`signature.json` carries an Ed25519 signature over the JCS-canonical
form of `manifest.json`, signed by the subject's `#public` sphere key.
This binds the export to the subject's identity at the time of export.

```json
{
  "alg": "ed25519",
  "key": "did:aithos:z6Mkr…#public",
  "value": "z9V…",
  "signed_at": "2026-05-21T09:14:23Z"
}
```

A verifier:

1. Recomputes the JCS canonical form of `manifest.json`.
2. Verifies the signature against the key declared in `signature.json`.
3. Resolves the key against `did.json` to confirm the key was valid for
   the subject at the time recorded in `signed_at`.

### 7.2.3 The bytes

`raw.bin` carries the exact same bytes that were stored at the PDS
S3 backend: plaintext for public assets, AEAD ciphertext (with prefixed
nonce, per §2.3.2) for private assets. No re-encryption happens at
export.

The export consumer can therefore verify integrity by computing
SHA-256 of `raw.bin`:

- For public assets: `sha256(raw.bin) == manifest.asset.sha256_of_plaintext`.
- For private assets: `sha256(raw.bin) == manifest.asset.sha256_of_ciphertext`.
  Decryption (and the subsequent verification of `sha256_of_plaintext`)
  requires unwrapping the AMK using one of the wraps in the envelope.

A consumer importing the asset into a fresh PDS preserves the same
ciphertext bytes byte-for-byte. The new PDS's S3 object's content
hash is identical to the original's, even though the storage key may
differ.

## 7.3 The `.assets` batch artifact

A batch export packages multiple assets into a single archive:

```
my-assets-2026-05-21.assets
├── manifest.json                 (top-level batch manifest, §7.3.1)
├── did.json
├── signature.json
└── assets/
    ├── asset_01J…/
    │   ├── manifest.json         (per-asset manifest, same shape as §7.2.1)
    │   └── raw.bin
    ├── asset_01K…/
    │   ├── manifest.json
    │   └── raw.bin
    └── …
```

### 7.3.1 Top-level batch manifest

```json
{
  "aithos-assets": "0.1.0",
  "kind": "assets.batch.export",
  "exported_at": "2026-05-21T09:14:23Z",
  "exported_by": "did:aithos:z6Mkr…",
  "asset_count": 47,
  "total_bytes": 234567890,
  "filter_applied": {
    "attached_to": { "kind": "ethos", "zone": "self" }
  },
  "assets": [
    { "urn": "urn:aithos:asset:…:asset_01J…", "path": "assets/asset_01J…/" },
    { "urn": "urn:aithos:asset:…:asset_01K…", "path": "assets/asset_01K…/" },
    /* … */
  ]
}
```

The top-level signature covers the batch manifest only. Each per-asset
manifest carries its own integrity hashes (the bytes' SHA-256); the
top-level batch is a deterministic, signed table of contents.

## 7.4 Export procedure

### 7.4.1 `aithos.assets.export_asset`

Begin a single-asset export.

Input:

```ts
interface ExportAssetInput {
  urn: string;
  include_history?: boolean;     // default false
}
```

Output:

```ts
interface ExportAssetOutput {
  job_id: string;
}
```

The export runs asynchronously. Single-asset exports are typically
fast; the async API exists for symmetry with batch exports.

### 7.4.2 `aithos.assets.export_collection`

Begin a batch export over a filter.

Input:

```ts
interface ExportCollectionInput {
  filter?: AssetFilter;          // §5.3.3
  include_history?: boolean;     // default false
}
```

Output: `{ job_id: string }`.

### 7.4.3 `aithos.assets.get_export_status`

Poll the status of an export job.

Input: `{ job_id: string }`.

Output:

```ts
interface ExportStatus {
  job_id: string;
  state: "pending" | "running" | "ready" | "failed";
  artifact_url?: string;         // signed URL when state == "ready"
  artifact_size_bytes?: number;
  asset_count?: number;
  expires_at?: string;           // RFC 3339, signed URL TTL (default 1 hour)
  error?: string;
}
```

The `artifact_url` returned for a `.assets` export points to a single
ZIP file on the platform's export storage. The TTL is short; the
caller is expected to fetch promptly and re-export if delayed.

## 7.5 Import procedure

### 7.5.1 `aithos.assets.import_asset`

Import a `.asset` artifact.

Input:

```ts
interface ImportAssetInput {
  artifact_url: string;          // URL or data: URI of the .asset file
  preserve_urn?: boolean;        // default false (the import re-allocates a fresh asset_id under the importing subject)
  retain_recipients?: boolean;   // default false (only the importing owner's wrap is preserved; other wraps are dropped)
}
```

Output:

```ts
interface ImportAssetOutput {
  imported_urn: string;
  original_urn: string;
  reissued: boolean;             // true if a fresh asset_id was allocated
  asset: AssetMetadata;
}
```

The import procedure:

1. Fetch the artifact.
2. Verify the signature against the embedded `did.json`.
3. Validate manifest schema and integrity (`raw.bin`'s SHA matches the
   declared ciphertext hash for private assets, or plaintext hash for
   public).
4. Compute the new subject's `subject_did` from the importing
   envelope's issuer.
5. If `preserve_urn` is true AND the importing subject matches the
   manifest's `exported_by`, reuse the original `asset_id`; otherwise
   allocate a fresh ULID.
6. Upload `raw.bin` to the new PDS's S3.
7. Materialize the metadata document, preserving `media_type`,
   `size_bytes`, `sha256_of_plaintext`, and (for private assets) the
   wrap matching the importing subject's sphere key. If
   `retain_recipients: false`, other wraps are dropped (the importing
   subject must re-issue mandates and re-wrap as needed).
8. Emit `assets.created` with an `imported_from` field pointing to
   the original URN.

The deduplication probe (§1.4.1) runs as part of step 5; if the
importing subject already holds an asset with the same plaintext
SHA-256, the existing asset is returned and the import becomes a
no-op.

### 7.5.2 `aithos.assets.import_collection`

Import a `.assets` batch artifact.

Input:

```ts
interface ImportCollectionInput {
  artifact_url: string;
  preserve_urns?: boolean;
  retain_recipients?: boolean;
}
```

Output: `{ job_id: string }` (asynchronous, like exports).

The job iterates the batch manifest's `assets[]` array, calling the
single-asset import procedure for each. Failures on individual assets
do not abort the batch; the final job status returns counts.

## 7.6 Inter-PDS migration

A subject migrating from PDS A to PDS B follows the sequence:

1. On PDS A: `export_collection` with no filter (full asset space) →
   download artifact.
2. On PDS B: `import_collection` against the artifact.
3. On PDS B: for each asset, issue any mandates required by the new
   recipient set (e.g. re-authorizing grantees that PDS A had).
4. On PDS A: tombstone the old assets (or wait for the natural purge
   cycle).
5. Update the subject's Ethos editions to point asset references at
   the new PDS endpoint via standard DID resolver mechanics.

Steps 3 and 5 are out of scope for the assets sub-protocol itself —
they live in the mandate and resolver layers.

## 7.7 Verification of imported assets

A consumer of an imported asset has end-to-end integrity guarantees
that survive the migration:

- The asset's plaintext SHA-256 is unchanged (the byte payload is
  byte-identical across PDSes).
- The original signing key (`exported_by`) is recorded in the import's
  metadata; the importing subject's own signature covers the new
  metadata document.
- The Ethos manifest's `x-assets[i].sha256_of_plaintext` field remains
  the same — meaning Ethos editions that reference the asset continue
  to verify against the imported asset's bytes without modification.

The URN, however, MAY change (different PDS or different `asset_id`
allocation). Ethos editions on the new PDS that newly reference the
asset use the new URN; old editions that reference the old URN are
historical artifacts (PDS A's resolution still works as long as PDS A
holds the metadata, even if the bytes have been tombstoned).

---

Next: [chapter 08 — Audit](./08-audit.md).
