# 4 · Mandates

## 4.1 Overview

The assets sub-protocol reuses the Ethos mandate document (Ethos
spec §4) unchanged. Only the **scope vocabulary** is extended to cover
asset-level access. A mandate that authorizes an application to act on
behalf of a subject MAY include one or more `assets.*` scopes drawn
from §4.2 below.

This chapter is **specified but not implemented in v0.1**. The
reference v0.1 implementation supports only owner-signed envelopes
(envelope `iss == subject_did` and a sphere key from the subject's DID
document). Delegate access via mandate is a v0.2 implementation
target. The scope vocabulary is specified now so that mandate documents
issued today can already declare future asset scopes without breaking
forward compatibility.

## 4.2 Scope vocabulary

Asset scopes follow the dot-separated lattice used throughout Aithos
(Ethos §4.4). Each scope is a string of the form `assets.<target>.<op>`
where `<target>` may identify a single asset, an attaching context, or
the entire asset space.

### 4.2.1 Per-asset scopes (URN-targeted)

The narrowest grain. The scope names a single asset URN.

| Scope | Effect |
|---|---|
| `assets.urn:aithos:asset:<did>:<asset_id>.read` | Permits `get_asset`, `head_asset`, and AMK unwrap for one specific asset. |
| `assets.urn:aithos:asset:<did>:<asset_id>.delete` | Permits `delete_asset` for one specific asset. |
| `assets.urn:aithos:asset:<did>:<asset_id>.rotate` | Permits `rotate_amk` (the grantee can refresh the AMK; useful for service accounts that auto-rotate). |

A mandate carrying a per-asset scope MUST be accompanied by a
corresponding wrap of the asset's AMK for the grantee's X25519 key, added
via `aithos.assets.authorize_grantee` (chapter 05 §5.4.8) at the time
the mandate is issued. Without the wrap, the grantee can call the RPC
but cannot decrypt the bytes.

### 4.2.2 Context-targeted scopes

A scope that targets the attaching context — an Ethos zone or a data
collection — implicitly applies to every asset attached to that
context.

| Scope | Effect |
|---|---|
| `assets.ethos.<zone>.read` | Permits read of every asset attached to the named Ethos zone (`public`, `circle`, `self`) of the subject. |
| `assets.ethos.<zone>.section.<section_id>.read` | (v0.3 only) Permits read of every asset attached to the named section. |
| `assets.data.<collection_name>.read` | Permits read of every asset attached to records in the named data collection. |
| `assets.data.<collection_name>.record.<record_id>.read` | Permits read of every asset attached to the specific record. |

Context-targeted scopes are convenient but carry a tradeoff: the wrap
list of each asset attached to the context must include the grantee.
For an existing asset in a context the grantee is being added to, the
owner MUST call `authorize_grantee` per asset (no implicit propagation
in v0.1). The SDK's `assets.sync_recipients(context)` convenience
walks the context and authorizes the grantee on every attached asset
in one batch from the owner's perspective.

### 4.2.3 Subject-wide scopes

The coarsest grain. The scope grants the same operation on every asset
the subject owns.

| Scope | Effect |
|---|---|
| `assets.*.read` | Permits read of every asset owned by the subject. |
| `assets.*.write` | Permits `init_upload` / `complete_upload` on the subject's behalf. |
| `assets.*.delete` | Permits `delete_asset` on any of the subject's assets. |

Subject-wide scopes are appropriate only for very high-trust
applications (e.g. a recovery agent, a personal-archive backup tool).
The SDK MAY warn the user before issuing a mandate carrying a
`assets.*.*` scope.

### 4.2.4 Write-side scopes

Write scopes are deliberately rare in v0.1: most asset writes are
performed by the owner directly, with applications instead acting as
read-only consumers under section/collection mandates.

| Scope | Effect |
|---|---|
| `assets.attach.ethos.<zone>` | (v0.3) Permits the grantee to upload a new asset on the owner's behalf AND attach it to the named zone (i.e. emit the `ref_asset` for the resulting URN as part of an Ethos write the grantee is also authorized for via `ethos.write.<zone>`). |
| `assets.attach.data.<collection_name>` | Permits the grantee to upload + attach an asset as part of a data record write. |
| `assets.authorize` | Permits the grantee to add new recipient wraps on existing assets (typical only for very-high-trust automation; SHOULD NOT be granted to third parties). |

These scopes do NOT permit the grantee to mutate existing asset bytes
— assets are immutable (§1.2.5). They permit creation of new assets
and the corresponding reference operation, atomically with the parent
operation that motivates the upload.

## 4.3 Scope-to-method mapping

The platform's write router enforces a table mapping required scopes
to RPC methods:

| Method | Required scope on `assets.*` | Notes |
|---|---|---|
| `aithos.assets.init_upload` | owner OR `assets.attach.<context>` | The `<context>` MUST match the `attached_context` argument. |
| `aithos.assets.complete_upload` | owner OR matches the `init_upload` caller | The caller MUST be the same identity as the `init_upload` caller; opaque session token enforces this. |
| `aithos.assets.get_asset` | owner OR `assets.<urn>.read` OR matching context-scope | Anonymous for public assets (no scope check at all). |
| `aithos.assets.head_asset` | as get_asset | Anonymous for public assets. |
| `aithos.assets.list_assets` | owner OR matching context-scope | A grantee with `assets.ethos.circle.read` may list circle-attached assets; SHOULD NOT see assets attached to other zones. |
| `aithos.assets.delete_asset` | owner OR `assets.<urn>.delete` OR `assets.*.delete` | |
| `aithos.assets.ref_asset` | owner OR `assets.attach.<context>` | The context MUST match the reference's kind/zone/collection. |
| `aithos.assets.unref_asset` | owner OR `assets.attach.<context>` | |
| `aithos.assets.authorize_grantee` | owner OR `assets.authorize` | |
| `aithos.assets.revoke_grantee` | owner OR `assets.authorize` | |
| `aithos.assets.rotate_amk` | owner OR `assets.<urn>.rotate` | |
| `aithos.assets.rotate_owner_wrap` | owner only | The new owner sphere key signs the envelope — see chapter 02 §2.5.3. |
| `aithos.assets.tombstone_collection` / `purge` | owner only | Administrative ops; no delegation. |

The "owner" classification means envelope `iss == asset.subject_did`
and the signing key is a sphere key currently listed in the subject's
DID document.

## 4.4 Filter clauses

A scope MAY carry a filter clause that narrows it further. Filters are
the same shape used by data sub-protocol mandates (data §4.3.2):

```json
{
  "scope": "assets.ethos.self.read",
  "filter": {
    "tags_any": ["career", "professional"],
    "media_type_prefix": "application/pdf"
  }
}
```

| Filter key | Description |
|---|---|
| `tags_any` | The asset (via its referring section/record) carries any of the listed tags. |
| `media_type_prefix` | The asset's `media_type` starts with the given prefix (e.g. `image/`). |
| `size_bytes` | `{ lte: number, gte: number }` — narrow by size. |
| `created_after`, `created_before` | RFC 3339 timestamps. |

The platform MUST enforce filters at every read primitive — a
`get_asset` call for an asset outside the filter MUST return
`AITHOS_NOT_FOUND` (NOT `AITHOS_INSUFFICIENT_SCOPE`, which would leak
the asset's existence to a caller not allowed to see it).

A platform MAY refuse a filter combination it cannot enforce
efficiently with `AITHOS_FILTER_UNSUPPORTED`. The minimum a conformant
PDS MUST support: `media_type_prefix`, `size_bytes`, `created_after`.

## 4.5 Recipient-conferring versus operational scopes

The Ethos mandate spec (§4.5) distinguishes two classes of mandate:

- **Operational scopes** confer the right to invoke methods. The
  grantee acts under the subject's authority but holds no
  long-lived key material associated with the data itself.
- **Recipient-conferring scopes** make the grantee a recipient — the
  grantee's X25519 public key is added to the data's wrap list, and
  decryption is performed client-side by the grantee.

Asset scopes are **always recipient-conferring** in v0.1. There is no
"the platform decrypts and re-encrypts for you" path. A grantee
authorized on an asset MUST have a wrap of the AMK; the platform's
role is limited to verifying the mandate, returning the asset metadata
(including the grantee's wrap), and issuing a presigned URL for the
ciphertext. Decryption happens on the grantee's machine.

This has two consequences:

1. **Mandate issuance is more than just signing the document.**
   Issuing an asset mandate requires the owner to (a) sign the mandate,
   (b) wrap the AMK for the grantee, (c) call
   `aithos.assets.authorize_grantee` with the wrap. Skipping (b)
   produces a mandate the grantee can present but not use.

2. **Revocation requires more than just publishing a revocation.**
   Revoking removes the grantee from the wrap list (operational
   blocking), but the grantee may have cached the AMK from prior reads
   (the AMK itself is 32 bytes — easy to retain). To deny access to
   past versions of the ciphertext, the owner must rotate the AMK and
   re-encrypt the bytes (§2.5.2). This is the same forward-secrecy
   tradeoff documented in chapter 02.

The SDK SHOULD bundle (a)+(b)+(c) into a single `assets.authorize()`
ergonomic call and (revoke)+(rotate) into a single `assets.revoke()`
call, with a flag to control whether rotation is performed.

## 4.6 Interaction with Ethos and data mandates

An application typically holds compound mandates that cover multiple
sub-protocols. A recruitment assistant agent operating on the
gocandidate use case might carry:

```json
{
  "scopes": [
    "ethos.self.read",
    "assets.ethos.self.read",
    "data.candidates.read"
  ]
}
```

The three scopes interact:

- `ethos.self.read` gives the agent access to the self-zone markdown
  bodies (with the agent's wrap on the zone's `wraps[]`).
- `assets.ethos.self.read` gives the agent access to the assets
  attached to the self zone — including the CV PDFs.
- `data.candidates.read` gives access to the candidate records.

The mandate document declares all three; the issuance flow adds the
agent's wrap to each relevant wrap list (zone wraps for the Ethos
zone, AMK wraps for each attached asset, CMK wraps for the data
collection).

A mandate that grants `ethos.self.read` but NOT `assets.ethos.self.read`
permits the agent to read the markdown but receive opaque
`aithos-asset:` references it cannot resolve. The agent SHOULD
gracefully degrade — render the alt text, surface that an asset is
present but inaccessible — rather than failing.

## 4.7 Mandate revocation propagation

When a mandate is revoked (per Ethos §4.6), the platform MUST:

1. Reject any future envelope signed by the revoked grantee key,
   regardless of scope.
2. Update every asset wrap list that contains the grantee's recipient
   DID URL to remove that wrap. This is a fan-out operation: the
   reference implementation maintains a secondary index
   `(grantee_did_url) → asset_id[]` to perform it efficiently.
3. Emit one `assets.revoke_grantee` gamma entry per affected asset.
4. NOT automatically rotate the AMK. Forward secrecy on revocation
   remains explicit (chapter 02 §2.3.8).

Until step 2 completes, a race may exist where the grantee can still
fetch ciphertexts (using a leaked presigned URL or a cached one). The
platform SHOULD invalidate outstanding presigned URLs on revocation —
the reference implementation uses short TTLs (15 min default) to bound
the race window.

---

Next: [chapter 05 — API primitives](./05-api-primitives.md).
