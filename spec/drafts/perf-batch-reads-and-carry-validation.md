# Draft — Performance addenda: batch section reads, carry-forward validation, immutable blob caching

**Status:** draft (perf audit 2026-06-09). Additive only — no breaking change to
v0.3 bundles, mandates, or existing primitives.

**Motivation.** The v0.3 per-section model made the *crypto* cost of an edit
O(section). The remaining costs are *transport-shaped*: one RPC per section
read, one server-side existence probe per carried section, and zero CDN
cacheability because every read is a POST. None of these are protocol
properties today — this draft makes the fast behaviours normative so providers
and clients can rely on them. Target: an Ethos holding an entire digital life
(10³–10⁵ sections) with interactive read/publish latency.

---

## 1. `aithos.get_ethos_sections` — batch read primitive (§10.5 addendum)

One round-trip, M sections, ONE envelope verification.

```jsonc
// request params
{
  "did": "did:aithos:z6Mk…",        // or "handle"
  "section_ids": ["sec_a", "sec_b"], // 1..64 ids
  "edition": 41,                     // optional, default latest
  "_envelope": { … }                 // optional §11.4 (required for circle/self)
}
// result
{
  "objects": { "sec_a": { "bytes_base64": "…" }, "sec_b": { "bytes_base64": "…" } },
  "missing": []                      // ids not present in the edition
}
```

Rules:

1. The envelope (when present) is verified ONCE per request; per-section
   authorization then follows exactly `aithos.get_ethos_section` semantics
   (owner: all; delegate: scope-check per section, revocation-checked; anonymous:
   public only). A section the caller may not read goes to `missing` — the
   response MUST NOT distinguish "absent" from "forbidden" (no oracle).
2. `section_ids` is capped at **64**; providers MAY advertise a lower cap via
   error `-32602` data `{max_batch}`. Responses are bounded by the provider's
   payload limit — clients MUST be prepared to paginate.
3. Ordering: `objects` is keyed by id; clients must not rely on map order.

Client guidance: `loadEthosV03` / eager zone reads SHOULD use the batch
primitive with bounded fan-out, falling back to per-section
`aithos.get_ethos_section` when the provider doesn't expose it (probe once,
remember per provider).

## 2. Carry-forward validation — predecessor-set rule (§10.6 addendum)

Current informal behaviour: on `publish_ethos_edition` (v0.3), a descriptor
whose `blob_sha` blob is omitted from the upload is accepted only after the
provider asserts the object exists in its blob store — in practice one
existence probe per carried section, O(N) per publish.

Normative replacement:

> A provider MUST accept an omitted blob when its `blob_sha` appears in the
> **immediately preceding edition's** descriptor set (any zone). For a
> `blob_sha` NOT present in the predecessor, the provider MUST verify
> existence in its store (or require the bytes) before accepting the edition.
> Providers MUST NOT delete a blob while any edition ≤ latest references it
> (append-only blob store; garbage collection, if ever introduced, must
> preserve the latest edition's closure).

Soundness: an accepted edition's blobs were all validated when it was
accepted (uploaded-and-hashed, or recursively covered by ITS predecessor); by
induction every `blob_sha` in edition N−1 exists. The rule turns publish-time
server I/O from O(N sections) to O(K changed + new-sha carries), unblocking
digital-life-scale editions. No client change required.

## 3. Content-addressed blobs are immutable — cache accordingly

`blob_sha` IS the content hash of the stored bytes (§3.3.2′). Therefore:

1. Providers SHOULD expose **public-zone** blobs on a cacheable GET endpoint,
   e.g. `GET {cdn}/e/{did}/blobs/{blob_sha}`, with
   `Cache-Control: public, max-age=31536000, immutable`.
2. Encrypted-zone blobs MUST NOT be exposed unauthenticated by default — not
   for confidentiality (they are E2E ciphertext) but because (a) the
   read-envelope gate is the revocation cut-off for FUTURE reads and (b) blob
   sizes/access patterns are metadata. Providers MAY serve them via
   short-lived signed URLs minted by an authorized read RPC (one
   authorization covering a batch of URLs).
3. Manifests are mutable pointers (per edition) and stay on the RPC surface.

## 4. Non-goals (kept as is, deliberately)

- Per-request revocation freshness on delegate reads — the kill-switch
  property is worth one fast index lookup per request.
- Manifest re-signing per edition (JCS) — the manifest is small; signing is
  O(metadata), not a transport cost.
- Gamma whole-file re-encryption — already addressed separately by §10.9
  rolling chunks (orthogonal to this draft).

## 5. Cross-references

- Provider-side audit + ready patches: `aithos-provider` branch
  `docs/perf-write-read-path` → `PERF-AUDIT-2026-06-09.md`.
- Client-side: `protocol-client@perf/lazy-parallel-reads` (bounded-parallel
  section fan-out, concurrent pre-publish lookups, opt-in identity/grants
  caches, `extraGrantMandates`), `aithos-sdk@perf/publish-fastpath`
  (post-publish cache seeding, `reseal({includeMandates})`).
