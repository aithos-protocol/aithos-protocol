# 7 · Portability

## 7.1 Overview

A core promise of the data sub-protocol is that a subject can leave any
PDS and take their data with them, intact. This chapter specifies:

- The `.data` artifact format — a signed ZIP carrying a full collection
  snapshot.
- The export procedure, including the gamma log inclusion option.
- The import procedure, including validation and integrity checks.
- The semantics of partial exports and incremental imports.

The portability artifact is to the data sub-protocol what the `.ethos`
bundle is to the Ethos sub-protocol (Ethos chapter 3): a self-contained
file that a third party can verify without contacting the originating
platform.

## 7.2 `.data` bundle layout

A `.data` artifact is a ZIP archive with the `.data` extension:

```
collection-contacts-2026-05-14.data
├── manifest.json                       (UTF-8 JSON, §7.3)
├── did.json                            (signed DID document of the subject)
├── schema.json                         (the collection's schema)
├── collection.json                     (the collection metadata, §1.2.2)
├── records/
│   ├── record_01J….json                (one file per record, server view)
│   ├── record_01K….json
│   └── …
├── payloads/                            (encrypted payload bodies, separate
│   ├── record_01J….bin                  for records exceeding inline-size)
│   └── …
├── gamma/                               (OPTIONAL, only when include_history)
│   ├── gamma_01J….json
│   └── …
└── integrity.json                      (signatures and hashes)
```

### 7.2.1 Required entries

- `manifest.json` — §7.3 below.
- `did.json` — the subject's DID document at the time of export.
  Required so a recipient can verify all signatures in the bundle.
- `schema.json` — the schema the collection was bound to. Including
  it makes the bundle self-contained; the recipient doesn't need
  network access to interpret the records.
- `collection.json` — the collection metadata, including the CMK
  envelope. The CMK is still wrapped for the subject's sphere key
  and any active grantees — the recipient who imports the bundle on
  their PDS needs to hold one of those keys (or to re-wrap on import
  if they're the subject themselves).
- `records/<record_id>.json` — one file per record, server view shape
  per §1.3.2. Records inline payloads up to ~256 KB; larger records
  reference `payloads/<record_id>.bin`.
- `integrity.json` — see §7.4.

### 7.2.2 Optional entries

- `payloads/<record_id>.bin` — the raw AEAD ciphertext for records
  whose inline payload would exceed the size threshold.
- `gamma/<gamma_id>.json` — the gamma log entries for the collection,
  included when `include_history: true` was set on export.

### 7.2.3 Forbidden entries

A conformant `.data` bundle MUST NOT contain:

- Symbolic links, executable code, or other non-regular ZIP entries.
- Files outside the layout described above.
- Schema files for schemas other than the collection's bound one
  (cross-collection imports require multiple bundles).

## 7.3 `manifest.json`

```json
{
  "aithos-data-bundle": "0.1.0",
  "bundle_id": "urn:aithos-data:export:01JG5X…",
  "subject_did": "did:aithos:z6Mkr…",
  "collection_urn": "urn:aithos:collection:did:aithos:z6Mkr…:contacts",
  "collection_name": "contacts",
  "schema": "aithos.contacts.v1",
  "exported_at": "2026-05-14T12:00:00Z",
  "record_count": 247,
  "gamma": {
    "included": true,
    "head": "gamma_01K…",
    "count": 1182
  },
  "size_bytes": 4823901,
  "files": [
    { "path": "did.json", "sha256": "…" },
    { "path": "schema.json", "sha256": "…" },
    { "path": "collection.json", "sha256": "…" },
    { "path": "records/record_01J….json", "sha256": "…" },
    …
  ]
}
```

The `files` array enumerates every file in the bundle (except
`manifest.json` and `integrity.json` themselves), with the SHA-256 hash
of its bytes. This anchors the bundle's content to the manifest.

## 7.4 `integrity.json`

```json
{
  "aithos-data-bundle": "0.1.0",
  "bundle_id": "urn:aithos-data:export:01JG5X…",
  "manifest_sha256": "<sha256 of manifest.json>",
  "did_json_sha256": "<sha256 of did.json>",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#data",
    "value": "<base64 ed25519 signature>",
    "created": "2026-05-14T12:00:01Z"
  }
}
```

The signature is over the JCS-canonicalized form of `integrity.json`
with `signature.value = ""`. Verifiers reproduce this canonicalization
and verify against the public key recovered from `did.json`.

The signing key is normally `#data`. If the subject has tombstoned
their `#data` sphere or it has been rotated, the signature uses the
current `#data` key as advertised in the bundled `did.json`.

## 7.5 Export procedure

The platform-side export procedure:

```
1. Validate caller authorization: only the collection owner OR a
   mandate with `data.<col>.admin` scope may export.

2. Acquire a consistent snapshot of the collection. Implementations
   MAY use:
   - A point-in-time read replica.
   - A logical lock on the collection (refusing writes during export).
   - Best-effort iteration (some concurrent writes may or may not be
     included; the export is timestamped).
   Implementations MUST document their snapshot semantics.

3. Stream each record to records/<record_id>.json. For records whose
   payload exceeds 256 KB, write the payload bytes to
   payloads/<record_id>.bin and reference it from the record file.

4. Stream the schema, the DID document, the collection metadata.

5. If include_history: stream each gamma entry to gamma/<gamma_id>.json.

6. Build manifest.json with every file's SHA-256.

7. Sign integrity.json with the subject's #data sphere key. The signing
   happens client-side if the subject is exporting their own data
   directly (the platform doesn't hold the sphere private key); for
   platform-initiated exports (e.g. compliance), the platform requests
   the subject's client to co-sign.

8. ZIP everything, present as a downloadable artifact via signed URL.
```

The signing step (step 7) is the one that makes `.data` a true sovereign
artifact. The platform cannot produce a valid `.data` bundle without the
subject's collaboration — there is no "platform-signed" mode in v0.1.

## 7.6 Import procedure

A receiving platform imports a `.data` bundle as follows:

```
1. Validate ZIP integrity (no malformed entries).

2. Parse manifest.json. Verify every listed file's SHA-256 matches the
   actual bytes.

3. Parse did.json. Verify its root signature per Ethos §1.6.2.

4. Parse integrity.json. Verify the signature against the public key
   from did.json. If the signature fails, ABORT.

5. Parse schema.json. Verify it has not been retracted (§3.7.3).
   Register it if not already known.

6. Parse collection.json. The CMK envelope may or may not have a wrap
   addressed to the importing principal:
   - If the importer is the subject themselves and they hold the
     #data sphere key, they can unwrap the CMK directly.
   - If the importer is a third party who held a mandate at export time,
     they may have a wrap addressed to their grantee key.
   - If neither: the importer can still verify integrity but cannot
     decrypt payloads.

7. For each record:
   - Verify record_id matches the file name.
   - Verify the metadata clear conforms to the schema's indexable fields.
   - Store the record as-is on the new PDS.

8. If gamma entries are present: verify their chain (each entry's
   prev_hash matches the previous), then store.

9. Produce a fresh collection on the importing PDS, with a fresh
   collection_name (default: the source's name, unless the input
   specifies otherwise). The collection's gamma_ref initially points
   at the imported head; subsequent mutations chain on.

10. Emit gamma entry data.collection.imported with the bundle_id of the
    source.
```

The imported collection is a **fork** from the source's perspective:
the two collections share history up to the export point but diverge
thereafter. There is no continuous-replication protocol in v0.1.

## 7.7 Cross-platform interoperability

Because the bundle is platform-agnostic — only the protocol primitives
appear in its structure — a bundle exported from platform A can be
imported on platform B without coordination, provided both platforms
implement the same sub-protocol version.

Version compatibility:

- A `v0.1.x` bundle imports on any `v0.1.y` platform.
- A `v0.2.x` bundle imports on a `v0.2.y` platform. v0.1 platforms
  MAY refuse v0.2 bundles or may attempt best-effort import (drop
  unknown fields, warn).
- Major version bumps MUST document an export-side and import-side
  migration path.

## 7.8 Incremental export (deferred)

A common request is incremental export: "give me everything that
changed since timestamp T". v0.1 does not provide this primitive
directly; the closest equivalent is to include the gamma log
(`include_history: true`) and let the recipient filter by timestamp.

A future version MAY add `aithos.data.export_collection_since(t)` that
produces a bundle containing only records modified after `t`, plus the
gamma entries linking back to the previous export.

## 7.9 Threat model considerations

The portability format inherits the encryption model: payloads are
AEAD-encrypted, the CMK is wrapped only for legitimate recipients.
Implications:

- **A `.data` bundle in transit (e.g. on email) leaks all metadata
  clear** — names, emails, statuses, tags, timestamps. The encryption
  layer protects bodies, not metadata. Subjects exporting to share
  with a third party SHOULD be aware that the third party sees what
  the PDS server sees, which is the metadata clear.
- **A `.data` bundle leaked to an unauthorized party who doesn't hold
  a CMK wrap cannot decrypt payloads** — the AEAD ciphertext is safe
  in transit.
- **A `.data` bundle imported on a hostile platform** can be replayed,
  but cannot be silently altered without the integrity signature
  failing.

## 7.10 Test matrix

Conformant implementations MUST satisfy:

| Test | Assertion |
|---|---|
| P1 — Export → import roundtrip | A collection exported and imported on a fresh platform reads identical to the original (for the holding subject). |
| P2 — Tampered manifest | Modifying any byte of any bundled file invalidates `manifest.json`'s SHA-256 check; import MUST fail. |
| P3 — Tampered signature | Modifying the integrity signature invalidates the import; import MUST fail. |
| P4 — Schema-mismatch import | Importing a bundle whose schema is unknown to the platform MUST succeed if the schema is well-formed (the platform registers it); MUST fail if the schema is retracted. |
| P5 — Import without CMK access | A third party with no CMK wrap can verify the bundle's integrity and read metadata clear, but cannot decrypt payloads. |
| P6 — Forked import | A collection exported, imported on a second platform, then mutated on both: each platform diverges. The bundle's `bundle_id` is the common ancestor. |
| P7 — History-included export | An export with `include_history: true` produces a bundle whose gamma chain verifies end-to-end. |

---

Next: [chapter 08 — Audit](./08-audit.md).
