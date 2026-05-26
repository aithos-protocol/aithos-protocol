# 10 · Open questions

> **Status:** Informative. This chapter records (a) decisions taken
> during the v0.1 design review of 2026-05-21, noted inline below with
> **Decision (locked 2026-05-21)** tags, and (b) genuinely open
> questions still deferred to future revisions. None of the items below
> is itself normative for v0.1 conformance — the normative outcomes of
> the locked decisions are reflected in the relevant chapters 01–09.

## 0 · Decisions log — 2026-05-21

The v0.1 design review concluded with the following decisions. Each
locked decision is restated in the relevant section below.

| § | Topic | Outcome |
|---|---|---|
| 10.1 | Gamma chain | Keep multi-table storage, merge at read |
| 10.2 | Cross-subject dedup | Remain rejected (confirms §1.4.3, §9.4) |
| 10.3 | Server-side transcoding | Deferred to v0.2 for public assets only |
| 10.4 | Chunked encryption | Deferred to v0.2, opt-in via `encryption.mode` discriminator |
| 10.5 | Multipart upload | Deferred to v0.2, ships with 10.4 |
| 10.6 | Post-quantum crypto | Track NIST/IETF, plan v0.2/v0.3 minor when standards stabilize |
| 10.7 | Auto-sync recipients from context | Deferred to v0.2; v0.1 requires explicit `authorize_grantee` |
| 10.8 | Padding for size obfuscation | Opt-in at the client layer; no protocol change |
| 10.9 | Signed sidecar for public integrity | Deferred to v0.2 as optional capability |
| 10.10 | Cross-subject reference counting | Out of scope; `referenced_by[]` remains a hint |
| 10.11 | Compression | Non-normative; clients compress as they wish |
| 10.12 | Explicit asset versioning | Not added; gamma + supersedes pattern suffices |
| 10.13 | Quotas | **Default 5 GB per subject** in v0.1, configurable; `get_quota` RPC deferred to v0.2; error `AITHOS_ASSETS_QUOTA_EXCEEDED` (-32038) is normative in v0.1 |
| 10.14 | Asset refs from data records | `aithos-asset-ref/v1` schema fragment in v0.2 data; the field MUST be encrypted by default; the SDK MUST trigger `ref_asset`/`unref_asset` transparently on insert/update/delete |

The wire format of v0.1 is therefore **frozen** as currently specified
in chapters 01–09. None of the deferred items requires a breaking
change when adopted: each carries a discriminator (`encryption.mode`,
`alg`, optional fields) that allows the v0.2+ behaviour to coexist
with v0.1-emitted assets.

## 10.1 Unified gamma chain across sub-protocols

Per §8.2, v0.1 keeps the Ethos chain and the data+asset chain in
separate tables, requiring readers to merge at query time.

**Question.** Should v0.2 introduce a unified gamma service hosting
all sub-protocols' entries in a single table, or keep the multi-table
storage with a unified read abstraction?

**Considerations:**

- A single physical table simplifies cross-sub-protocol invariant
  checks (e.g. "no `assets.referenced` for a section that does not
  exist in the Ethos manifest").
- A single table couples the lifecycles of three backends that
  currently scale independently.
- The current merge logic in the SDK is small (~30 lines); the cost
  of keeping it is not high.

**Decision (locked 2026-05-21).** Stay with multi-table storage. Promote the
merge logic to a stable SDK helper and document it as the canonical
read pattern.

## 10.2 Cross-subject deduplication and convergent encryption

Per §1.4.3 and §9.4, v0.1 deliberately excludes cross-subject
deduplication because convergent encryption opens a metadata channel
that contradicts the protocol's confidentiality goals.

**Question.** Is there a construction that allows cross-subject dedup
without exposing existence of a shared file to the platform?

**Considerations:**

- Information-theoretic answer: no. Cross-subject dedup requires the
  platform to recognize "these two subjects' bytes are identical,"
  which is by definition a leak of that fact.
- Limited-utility constructions (e.g. private set intersection with
  the platform as the helper) exist but are computationally heavy
  and add operational complexity.
- The benefit of cross-subject dedup is small in practice: most
  user-uploaded content (selfies, scanned documents, personal
  recordings) is unique per subject.

**Decision (locked 2026-05-21).** Leave excluded. Revisit only if a strong
operational case appears.

## 10.3 Server-side image transcoding and thumbnails

A common UI need is to display a small thumbnail of a large asset
without fetching the full bytes. The current protocol requires the
client to either fetch the full asset and downscale locally, or to
upload a separate thumbnail asset and reference it explicitly via the
`"thumbnail"` role (§3.2.3).

**Question.** Should the platform offer server-side transcoding
(resize, transcode, watermark) for public assets, exposed via a
parameter on `aithos.assets.get_public_asset`?

**Considerations:**

- For private assets, the platform cannot transcode (it does not hold
  the plaintext). This is a hard limit.
- For public assets, server-side transcoding is feasible and useful:
  a `?w=256` query parameter on the CloudFront URL could trigger
  on-the-fly resize via Lambda@Edge or CloudFront Functions.
- Caching: transcoded variants would need their own cache keys.
  Integrity: transcoded variants would not have a signed
  `sha256_of_plaintext` in the manifest (the manifest signs the
  original, not the derivative).
- Cost: transcoding is cheap; storage of variants is the bigger cost.

**Decision (locked 2026-05-21).** Add as v0.2 optional capability for public
assets only, with a fixed set of standard sizes (32, 64, 128, 256,
512, 1024 longest edge). Make explicit that derivative variants are
NOT signed and carry their own integrity contract (the transcoder is
the trust root for those specific bytes).

## 10.4 Range requests on encrypted assets

XChaCha20-Poly1305 is a frame-AEAD, not a streaming cipher with
random access. To read byte N of a private asset, the client must
decrypt the entire frame.

For very large assets (multi-GB video), this is impractical.

**Question.** Should v0.2 introduce chunked encryption (e.g. one
AEAD frame per 1 MB chunk, each with its own nonce derived from the
chunk index) to allow range requests?

**Considerations:**

- Chunked encryption complicates the AAD construction (chunks must
  bind to chunk index to prevent rearrangement).
- The HTTP range-request semantic on the presigned URL still works
  for ciphertext range; the question is purely about what plaintext
  ranges become available.
- Most asset types in v0.1's scope (PDFs, images) are small enough
  that the question doesn't arise.

**Decision (locked 2026-05-21).** Specify a chunked-AEAD mode as
`encryption: { mode: "frame" | "chunked", chunk_size: 1048576 }` for
v0.2, with `frame` as the default. Only assets explicitly opted into
`chunked` would support range requests.

## 10.5 Multipart streaming upload for very large assets

The single-PUT presigned URL flow (§5.4.1) is appropriate for assets
up to a few hundred MB. Larger assets need S3 multipart upload.

**Question.** Should v0.2 expose a streaming upload flow that
issues multiple presigned URLs (one per part) and a finalize call?

**Considerations:**

- S3 multipart upload is well-understood. The protocol shape is:
  `init_multipart_upload` → N × `get_part_url` → `complete_multipart_upload`.
- For private assets, each part is its own AEAD frame (in conjunction
  with §10.4's chunked encryption).
- Resumable uploads (a client that lost connection on part 3 of 10
  resuming from part 3) is the operational win.

**Decision (locked 2026-05-21).** Spec'd in v0.2 alongside chunked
encryption.

## 10.6 Post-quantum cryptography

X25519 wraps are conjecturally vulnerable to "store-now-decrypt-later"
attacks by an adversary with a future quantum computer. Bytes
encrypted today under an X25519-wrapped AMK could be retroactively
read once a quantum computer of sufficient capacity exists.

**Question.** When should the protocol introduce a post-quantum
algorithm?

**Considerations:**

- The protocol's `alg` field on every cryptographic operation allows
  per-asset migration: an old asset stays under X25519+XChaCha20, a
  new asset uses a PQ KEM + XChaCha20 (or AES-GCM, whichever the PQ
  ecosystem standardizes on).
- The NIST PQ standardization process is ongoing; ML-KEM
  (formerly Kyber) is the leading candidate.
- Migrating ahead of consensus has ecosystem-compatibility costs.

**Decision (locked 2026-05-21).** Track NIST + IETF activity. Plan a v0.2 or
v0.3 minor that adds `alg: "ml-kem-768"` as an optional wrap
algorithm once the standards stabilize.

## 10.7 Auto-sync of recipients from referring context

§1.5.2 explicitly does not auto-sync an asset's wrap list with the
referring context's wrap list when the context's recipient set
changes. The owner must explicitly call `authorize_grantee` or
`revoke_grantee`.

**Question.** Should v0.2 introduce an `inherit_recipients_from:
"context"` flag that makes the asset's wraps follow the context's
wraps automatically?

**Considerations:**

- Auto-sync requires the platform to maintain dynamic dependencies
  between asset wraps and zone/collection wraps, with cascade
  semantics on context updates.
- Cost: when a zone gains a grantee, every attached asset must be
  re-wrapped (one wrap op per asset, no re-encryption needed).
- Failure modes: a sync that partially succeeds leaves some assets
  in the new state and some in the old.
- The current design (explicit owner action) is simpler and less
  surprising; the cost is the owner's friction.

**Decision (locked 2026-05-21).** Defer to v0.2 with feedback from real
usage. If users routinely hit "I added a grantee to my circle but
they cannot see the attached PDFs," auto-sync becomes a priority.

## 10.8 Padding to obscure asset sizes

Per §9.2.3, the platform sees an asset's `size_bytes`. For some
threat models, the asset's size is itself information ("a 4 KB
private text is probably a credit card number, a 30 MB private file
is probably a PDF").

**Question.** Should v0.2 support optional padding to a small set of
fixed sizes (e.g. powers of two)?

**Considerations:**

- Padding bytes inside the AEAD frame are easy: the client pads the
  plaintext before encryption.
- The `size_bytes` declared in the metadata then reflects the padded
  size, not the original. The `sha256_of_plaintext` covers the
  padded plaintext.
- The client must remember the padding scheme to decode on read.
- Storage cost: padding bumps every asset's bytes to the next bucket
  size (potentially ~2× storage in the worst case).

**Decision (locked 2026-05-21).** Specify as opt-in client behaviour (no
protocol change required); the spec MAY document a recommended
padding scheme as informative guidance.

## 10.9 Signed sidecar for public asset integrity

§2.6 mentions an optional "integrity sidecar" — a small signed JSON
document carrying the SHA-256, hosted alongside the public asset on
S3/CloudFront. This would let environments that can fetch a CloudFront
URL but cannot reach the RPC tier verify integrity end-to-end.

**Question.** Make the sidecar normative for public assets?

**Considerations:**

- The Ethos manifest already signs `sha256_of_plaintext` for assets
  it references. Reachable-via-Ethos consumers don't need the
  sidecar.
- For consumers reaching an asset via a non-Ethos channel (e.g. a
  bare CloudFront URL embedded in an email), a sidecar would close
  the gap.
- Cost: one additional small S3 object per public asset; one
  additional fetch on the verification path.

**Decision (locked 2026-05-21).** Make available as optional in v0.2;
recommend it for assets shared via non-Ethos channels.

## 10.10 Reference counting under federated consumers

The `referenced_by[]` model assumes the asset PDS receives `ref_asset`
and `unref_asset` calls from authoritative sources (the subject's own
Ethos write path, the subject's data record writes). If a third-party
service that the subject has not authorized starts referencing the
asset (e.g. another subject's Ethos pulls one of our assets as a
quote), the reference count is not updated.

**Question.** Should v0.2 support cross-subject referencing with
push-notification by the consumer to the asset PDS?

**Considerations:**

- "Asset attached to a section of another subject" is a real use
  case (avatars used as identification in conversation summaries,
  for instance).
- The asset PDS cannot enforce that the cross-subject reference is
  valid (it does not see the other subject's bundle).
- The simplest model is: cross-subject references are out of scope
  of `referenced_by[]`. The owner SHOULD treat their assets as
  potentially referenced anywhere on the network; deletion is at
  their own risk.

**Decision (locked 2026-05-21).** Leave out of scope. The
`referenced_by[]` index is a hint, not a guarantee of completeness.

## 10.11 Compression

The protocol does not specify compression. Bytes go into S3 as
provided by the client. PNG, PDF, JPEG, MP4 are already compressed;
plaintext (markdown, JSON) is not but is rarely large enough to
matter.

**Question.** Should compression be specified?

**Decision (locked 2026-05-21).** No. Clients are free to compress before
upload (the protocol sees the compressed bytes as the plaintext);
the protocol layer does not need to know.

## 10.12 Asset versioning vs. asset replacement

§1.2.5 specifies that asset bytes are immutable. An "edit" creates a
new asset; the old is dereferenced and eventually purged.

**Question.** Should v0.2 introduce explicit versioning, where an
asset has multiple immutable versions chained together?

**Considerations:**

- Versioning is useful for tracking the history of an avatar across
  Ethos editions, or the evolution of a CV.
- The current approach (each version is a distinct asset with its
  own URN) achieves the same outcome via the consuming context's
  history (the Ethos gamma log shows the section's old `aithos-asset:`
  reference and the new one).
- Adding explicit versioning at the asset layer would duplicate
  what gamma already captures.

**Decision (locked 2026-05-21).** Don't add. The lineage of an asset across
its conceptual "versions" is already reconstructable from the
consuming context's audit log; making it first-class at the asset
layer would add complexity without new functionality.

## 10.13 Quotas and pricing

§1.6 mentions a 100 MB soft cap per asset. The protocol does not
specify per-subject quotas (total bytes, total asset count, rate
limits).

**Question.** Are quotas a protocol concern or a deployment concern?

**Considerations:**

- The protocol is silent on payment / commercial terms.
- The reference implementation (`aithos.be` managed PDS) will impose
  its own quotas.
- A self-hosted PDS may impose none.
- Standardizing a way for the platform to communicate quotas back to
  the client (e.g. via headers or a dedicated RPC) would help SDK
  authors handle "out of quota" cleanly.

**Decision (locked 2026-05-21).** Three sub-decisions:

- **v0.1 default quota: 5 GB per subject.** Configurable per deployment.
  The reference managed PDS (`aithos.be`) implements this default.
  Self-hosted deployments MAY choose any value, including unlimited.
- **`AITHOS_ASSETS_QUOTA_EXCEEDED` (-32038)** is a normative error in
  v0.1, returned by `init_upload` when the upload would breach the
  subject's quota. The error payload's `data` field carries
  `{ used_bytes, limit_bytes }` so SDKs can render meaningful messages.
- **`aithos.assets.get_quota` RPC deferred to v0.2.** v0.1 SDKs surface
  the quota only on the error path. v0.2 adds an explicit read RPC
  returning `{ used_bytes, limit_bytes, asset_count, asset_count_limit,
  plan }`. A future minor revision MAY additionally surface usage via
  passive HTTP response headers (`X-Aithos-Quota-Used`,
  `X-Aithos-Quota-Limit`) on every RPC response.

## 10.14 Direct asset references from the data sub-protocol

§1.3 specifies that data records can reference assets via a
`kind: "data.record"` reference entry. The data sub-protocol's
record schema does not yet define how an asset URN is embedded in a
record's metadata or payload.

**Question.** Define a canonical `aithos-asset` JSON Schema fragment
that data record schemas can use.

**Decision (locked 2026-05-21).** Three sub-decisions:

- **Schema fragment.** v0.2 of the data sub-protocol introduces a field
  type `{ "$ref": "aithos://schemas/asset-ref/v1" }` validated as an
  asset URN string.
- **Default placement: encrypted, not indexable.** A field carrying an
  asset URN MUST be declared `x-aithos-encrypted: true` in the data
  schema. The server therefore does not see the topology of
  asset-to-record attachment. The trade-off — losing the ability to
  query "which records reference this asset" via a server-side filter —
  is acceptable because the asset's own `referenced_by[]` already
  carries the inverse index. Schemas that explicitly need the URN
  indexable (e.g. for cross-record join queries) MAY opt out by
  declaring `x-aithos-indexable: true`, but the v0.1 default is
  encrypted.
- **Transparent reference lifecycle.** The SDK MUST detect fields typed
  as `aithos-asset-ref/v1` in a data record write and automatically
  trigger:
  - `aithos.assets.ref_asset` on insert that introduces a new asset URN.
  - `aithos.assets.unref_asset` + `ref_asset` on update that changes
    the URN.
  - `aithos.assets.unref_asset` on delete or on update that clears the
    field.
  The developer writes `record.cv_pdf = "urn:aithos:asset:…"` and the
  SDK handles the reference plumbing without explicit calls.

Data record handlers MAY also expose helper APIs to resolve a URN into
a fetched, decrypted blob — but the helper layer is non-normative.

---

End of v0.1 draft. Implementation begins in
`packages/assets-backend/`, `packages/assets-crypto/`, and
`packages/assets-client/`; SDK surface in `@aithos/sdk` under
`sdk.assets`. Cross-references back into the bundle spec (§3.2.1
above) will be promoted into the bundle's normative §3.X once Ethos
v0.3 lands.
