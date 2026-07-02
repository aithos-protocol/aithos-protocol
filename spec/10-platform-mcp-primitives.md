# 10 · Platform MCP — primitives

> **Revision note (v0.2.0).** This chapter was first written against the
> v0.1.x wire format. It is realigned here to match the gamma-authoritative
> section model of chapter 10 (the deep-memory log) and the delegate-on-
> tracked flow shipped in v0.2.1. The bumps tracked below are not
> backward-compatible with the v0.1.x draft of this chapter:
>
> - `experimental.aithos.spec` on this endpoint is `"0.2.0"`.
> - `aithos.publish_ethos_edition` now takes a `new_gamma_entries` array
>   (§10.6.3).
> - Signed objects surface an optional `authorized_by` mandate id whenever
>   the underlying signature was produced by a delegate key (§10.4.3).
> - A new §10.11 describes the **write-only gamma** hosting mode a platform
>   may adopt.

> **Format status (bundle v0.4 — NORMATIVE).** The platform MUST serve the v0.4
> bundle format (manifest marker `aithos: "0.4.0"`, spec §3A) alongside v0.3
> (dual-read). The v0.4 behavior of the primitives is normative and specified in
> the body below:
>
> - `aithos.get_ethos_manifest` (§10.5.3) returns the manifest **as stored** —
>   either a v0.3 (`0.3.0`) or a v0.4 (`0.4.0`) manifest. A v0.4 manifest is the
>   small incremental document that references zone objects by sha (§3A.5).
> - The read route **`aithos.get_ethos_objects`** (§10.5.4a) is the normative
>   v0.4 object-fetch route: `{ did, shas: [≤64] }` → `{ objects: [{sha, b64}],
>   missing: [sha] }`, with per-object-type ACL (§10.5.4a, §3A.7).
> - `aithos.publish_ethos_edition` (§10.6.3a) accepts the v0.4 envelope
>   `{ manifest, objects, blobs }` (§3A.6). Dual-write: a subject already
>   migrated to v0.4 that attempts a v0.3 publish MUST be rejected with
>   **`-32045 ethos_spec_version_regression`** (`aithos` never regresses).
> - The whole-zone routes `aithos.get_ethos_zone` (§10.5.4) and
>   `aithos.get_ethos_edition` (§10.5.5) are functional for a v0.4 subject but
>   are **not** the canonical v0.4 access path; on a legacy v0.3 per-section
>   subject they fail with `-32020` (§10.5.4). The canonical v0.4 path is
>   `get_ethos_manifest` + `get_ethos_objects` + `get_ethos_section(s)`.
> - New object/integrity errors: `-32043 ethos_object_missing`,
>   `-32044 ethos_object_hash_mismatch`, `-32045 ethos_spec_version_regression`,
>   `-32046 ethos_keyring_forbidden` (§10.9, §3A.12).

## 10.1 Overview

Chapter 6 specifies a **per-subject local MCP server** that exposes one
subject's ethos to a co-located agent host (Claude Desktop, Cursor, …). This
chapter specifies a **platform MCP server** that sits on the network and
exposes the primitives of a multi-subject Aithos host: identity resolution,
ethos fetching, cross-subject search, mandate publication, signed writes.

The platform MCP is the stable, documented, machine-first surface that any
Aithos-speaking agent or backend is expected to depend on. A conformant
hosting platform SHOULD expose this surface; a strict minimum subset (§10.8)
is normative, the rest is RECOMMENDED.

Scope boundary: this chapter specifies the **`primitives` endpoint** — sharp,
technical tools with minimal descriptions. The **`converse` endpoint** — same
underlying data, presented to narrate a subject conversationally — is the
subject of chapter 12.

## 10.2 Transport

### 10.2.1 Endpoint

A conformant platform MUST serve the primitives MCP at a single URL, split
into two transport paths so that anonymous reads and signed writes can be
rate-limited, authorized, and audited independently:

```
POST {base}/mcp/primitives/read
POST {base}/mcp/primitives/write
```

Both paths speak JSON-RPC 2.0 per the MCP
[Streamable HTTP](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports)
transport. Servers MUST support `POST` and MAY upgrade to SSE for server-to-client
notifications; clients MUST accept both.

### 10.2.2 Capabilities

The server's `initialize` response MUST declare:

```json
{
  "serverInfo": { "name": "aithos-platform", "version": "0.2.0" },
  "capabilities": {
    "tools": {},
    "experimental": { "aithos": { "spec": "0.2.0", "role": "primitives" } }
  }
}
```

Clients MUST verify `experimental.aithos.role === "primitives"` and that
`experimental.aithos.spec` starts with `"0.2."` before calling the tools
specified here — a server still advertising `"0.1.x"` is running the
pre-gamma wire format and its `publish_ethos_edition` surface is incompatible
with this revision.

### 10.2.3 Authentication

- **Read path.** Anonymous. No authentication header, no envelope. The
  server MAY apply rate limits by client IP (§10.7).
- **Write path.** Every call MUST carry a signed envelope per chapter 11 as
  a `params._envelope` field (§10.6.1). The server MUST reject any write
  whose envelope fails verification, with JSON-RPC error code `-32010`
  (§10.9).

### 10.2.4 Versioning

The server MUST expose its semantic version in `serverInfo.version` and the
protocol version in `experimental.aithos.spec`. Breaking changes to a tool's
input schema, output schema, or semantics MUST either be gated behind a new
tool name (e.g. `aithos.get_ethos_manifest` → `aithos.get_ethos_manifest_v2`)
or require a bump to `experimental.aithos.spec`.

## 10.3 Data model recap

Tools in this chapter operate against the on-platform state defined in
PLATFORM-DESIGN.md:

- **Storage (source of truth).** Immutable editions under
  `s3://<bucket>/ethos/{did}/editions/{height}/`. Mandates and revocations
  under `s3://<bucket>/mandates/` and `.../revocations/`.
- **Index (derivable).** DynamoDB tables `ethos-index`, `mandates-index`,
  `revocations-index`. The server MUST NOT return data that exists only in
  the index and was not validated against the underlying signed object in
  storage.

All tools that return subject data MUST include the surrounding signatures
(either inline or as a reference) so a caller can re-verify independently.

## 10.4 Common types

### 10.4.1 `DidRef`

An identity is addressed by its full DID. A short prefix MAY additionally be
accepted on tools where the caller is a human (the `aithos.resolve_handle`
result disambiguates).

```ts
type DidRef = string; // "did:aithos:z6Mk…" — full DID only
```

### 10.4.2 `EditionRef`

```ts
type EditionRef =
  | { kind: "height"; height: number }
  | { kind: "bundle_id"; bundle_id: string } // "urn:aithos:<handle>:<version>"
  | { kind: "latest" };                       // default
```

### 10.4.3 `SignedObject<T>`

Every object returned by a read tool is wrapped:

```ts
interface SignedObject<T> {
  object: T;                    // the payload (manifest, DID doc, mandate, …)
  signature: {                  // detached proof, per spec §5
    proofValue: string;         // base64url(Ed25519)
    verificationMethod: string; // did:aithos:…#<sphere> OR delegate multibase key
    created: string;            // RFC 3339
    authorized_by?: string;     // mandate id, when verificationMethod is a
                                //   delegate key (spec §4.5.4). Absent when
                                //   the signer is the subject's sphere key.
  };
  fetched_at: string;           // RFC 3339; server's observation time, not signed
}
```

When `authorized_by` is present, the caller resolves the mandate (via
`aithos.get_mandate`) to verify that the delegate was within scope and window
at the `created` timestamp. Verification remains stateless on the platform
side — the server MUST return the raw signature object as stored; it is not
allowed to strip, rewrite, or annotate the proof.

For compound objects (an edition = manifest + zone docs + per-zone
signatures), the wrapper SHOULD carry the signature of the manifest and an
array of zone signatures; see `aithos.get_ethos_edition`. Any of those
inner signatures MAY independently carry `authorized_by` — a single edition
can mix subject-signed zones with delegate-signed zones.

### 10.4.4 `Pagination`

Cursor-based, opaque to the client:

```ts
interface Page<T> {
  items: T[];
  next_cursor?: string;   // absent when no more pages
  total_estimate?: number; // best-effort, MAY be absent
}
```

## 10.5 Read tools

All tools in §10.5 are exposed on `POST {base}/mcp/primitives/read` and
require no authentication.

### 10.5.1 `aithos.resolve_handle`

Look up identities by handle (non-unique) and/or DID prefix.

Input:

```json
{
  "handle": "alice",           // optional
  "did_prefix": "z6MkEU",      // optional; 6+ chars
  "limit": 20,                  // default 20, max 100
  "cursor": null
}
```

At least one of `handle` or `did_prefix` MUST be present. If both are
provided, results are intersected.

Output: `Page<IdentityBrief>` where:

```ts
interface IdentityBrief {
  did: string;
  handle: string;
  display_name?: string;
  did_prefix: string;           // first 10 chars of multibase body
  created_at: string;           // first publication of this identity
  latest_height: number;
  status: "live" | "tombstoned";
}
```

### 10.5.2 `aithos.get_identity`

Input: `{ "did": DidRef }`.

Output: `SignedObject<DidDocument>` per spec §1.2.3.

Errors: `AITHOS_NOT_FOUND` (§10.9).

### 10.5.3 `aithos.get_ethos_manifest`

Input: `{ "did": DidRef, "edition"?: EditionRef }`. Default `edition = latest`.

Output: `SignedObject<Manifest>` per spec §2.6. The server MUST return the
manifest **as stored**, discriminated by the `aithos` marker: a v0.3 (`0.3.0`)
manifest or a v0.4 (`0.4.0`) incremental manifest (spec §3A.5). A v0.4 manifest
references the zone objects by sha and is read via `aithos.get_ethos_objects`
(§10.5.4a).

The returned `Manifest` carries `gamma.head` and `gamma.count` (spec §10.7 of
the gamma chapter) whenever the subject has ever authored a section. Callers
that want to verify history independently walk the gamma log starting from
`gamma.head`; see §10.11 for how a platform may choose to serve (or not
serve) those gamma entries.

### 10.5.4a `aithos.get_ethos_objects` (v0.4, NORMATIVE)

Batch-fetch content-addressed zone objects (`zone_shard`, `keyring`,
`extra_wraps`; spec §3A.1) referenced by a v0.4 manifest. This is the normative
object-fetch route of the canonical v0.4 read path.

Input: `{ "did": DidRef, "shas": string[] }` — at most **64** shas per call. A
call carrying more than 64 shas MUST be rejected.

Output:

```ts
interface EthosObjectsResult {
  objects: { sha: string; b64: string }[]; // JCS bytes of each object, base64
  missing: string[];                        // requested shas not returned
}
```

Each returned `b64` MUST be the exact JCS bytes whose `sha256` equals `sha`, so
the caller re-verifies integrity locally (§3A.1). The server MUST NOT re-sign,
re-canonicalize, or otherwise rewrite an object.

ACL is applied **per object type** (spec §3A.7): `zone_shard` follows the
manifest ACL (an anonymous reader is admitted — a shard exposes no recipient
label); `keyring` and `extra_wraps` require read-auth (owner or an active
delegate of the subject, exactly as `circle`/`self` bodies). An object that is
absent *or* forbidden MUST be reported in `missing` — the two cases are
indistinguishable, so the route is **not an authorization oracle**. See §10.9 /
§3A.12 for the object integrity errors returned by the write path.

> **Canonical v0.4 read path (normative for clients).** A v0.4 client reads an
> ethos as: `get_ethos_manifest` → `get_ethos_objects` (the zone's shards, plus
> `keyring` / `extra_wraps` on the authenticated channel) → unwrap the zone key
> → `enc_dek` → DEK, then fetch the section bodies with `get_ethos_section` /
> `get_ethos_sections` (spec §3A.8). The whole-zone routes §10.5.4 / §10.5.5
> below are **not** the canonical v0.4 access path.

### 10.5.4 `aithos.get_ethos_zone`

Input: `{ "did": DidRef, "zone": "public" | "circle" | "self", "edition"?: EditionRef }`.

Output:

```ts
type ZoneFetchResult =
  | { kind: "plaintext"; markdown: string; signature: Signature }
  | { kind: "ciphertext"; wire: CipherEnvelope; signature: Signature };
```

The server MUST return ciphertext for `circle` / `self` zones without
inspecting them. Plaintext for `public` only. Decryption is always
client-side.

> **Behavior across formats (normative).** This route (and §10.5.5) was
> designed for the v0.2 whole-zone blob model. Normative behavior:
> - **v0.4 subject** — the route MUST return the zone's sections; clients SHOULD
>   nonetheless prefer the canonical `get_ethos_manifest` + `get_ethos_objects`
>   + `get_ethos_section(s)` path (§10.5.4a, §3A.8), which this route is not.
> - **Legacy v0.3 per-section subject** — the route MUST fail with **`-32020`**:
>   its legacy branch expects a single whole-zone file (`zm.file`) that
>   per-section manifests do not carry. Per-section v0.3 subjects are read
>   section by section.

### 10.5.5 `aithos.get_ethos_edition`

Convenience: returns manifest + all zones in one call. Input:
`{ "did": DidRef, "edition"?: EditionRef, "zones"?: ("public" | "circle" | "self")[] }`.

Output:

```ts
interface EthosEdition {
  manifest: SignedObject<Manifest>;
  zones: {
    public?: SignedObject<ZoneFetchResult>;
    circle?: SignedObject<ZoneFetchResult>;
    self?:   SignedObject<ZoneFetchResult>;
  };
  bundle_id: string;
}
```

> **Behavior across formats (normative).** Same as §10.5.4: functional for a
> v0.4 subject, but MUST fail with **`-32020`** on a legacy v0.3 per-section
> subject (the whole-zone `zm.file` is absent from per-section manifests). The
> canonical v0.4 path is `get_ethos_manifest` + `get_ethos_objects` +
> `get_ethos_section(s)` (§10.5.4a, §3A.8).

### 10.5.6 `aithos.list_editions`

Input: `{ "did": DidRef, "limit"?: number, "cursor"?: string }`.

Output: `Page<EditionBrief>` where:

```ts
interface EditionBrief {
  height: number;
  bundle_id: string;
  created_at: string;
  prev_hash?: string;
}
```

Ordered by descending height.

### 10.5.7 `aithos.get_feed`

Chronological feed of latest editions across all live identities. No ranking.

Input: `{ "limit"?: number, "cursor"?: string }`. Default limit 20, max 100.

Output: `Page<FeedEntry>`:

```ts
interface FeedEntry {
  did: string;
  handle: string;
  display_name?: string;
  latest_height: number;
  latest_bundle_id: string;
  published_at: string;
}
```

### 10.5.8 `aithos.search`

Simple substring search across `(handle, did_prefix, display_name)`. No
full-text on zone contents at this spec level.

Input: `{ "query": string, "limit"?: number, "cursor"?: string }`.

Output: `Page<IdentityBrief>`.

### 10.5.9 `aithos.get_mandate`

Input: `{ "mandate_id": string }`.

Output: `SignedObject<Mandate>` per spec §4.2.

Access: the server MUST serve any mandate whose existence has been published
to the platform. The mandate object itself is not secret — its contents bind
to the issuer's DID and are verifiable by anyone.

### 10.5.10 `aithos.list_mandates`

Input:

```json
{
  "issuer_did": "did:aithos:…",   // optional
  "actor_did":  "did:aithos:…",   // optional
  "subject_did":"did:aithos:…",   // optional; where the mandate applies
  "include_revoked": false,        // default false
  "limit": 20,
  "cursor": null
}
```

At least one of `issuer_did`, `actor_did`, `subject_did` MUST be present.

Output: `Page<MandateBrief>`:

```ts
interface MandateBrief {
  mandate_id: string;
  issuer_did: string;
  actor_did: string;
  subject_did: string;
  scopes: string[];
  not_before: string;
  not_after: string;
  status: "active" | "expired" | "revoked";
}
```

### 10.5.11 `aithos.get_revocation`

Input: `{ "mandate_id": string }`.

Output: `SignedObject<Revocation>` or `null` if no revocation exists.

### 10.5.12 `aithos.verify_bundle`

Stateless verification of a bundle reference — the platform fetches by
bundle_id and runs spec §3.8 checks 1-6, 8. Intended for sanity-checking
links received out-of-band.

Input: `{ "bundle_id": string }` or `{ "bundle_url": string }`.

Output:

```ts
interface VerifyResult {
  valid: boolean;
  checks: { id: number; label: string; status: "pass" | "fail" | "skipped" }[];
  errors?: string[];
  warnings?: string[];
}
```

## 10.6 Write tools

All tools in §10.6 are exposed on `POST {base}/mcp/primitives/write` and
require a signed envelope per chapter 11.

### 10.6.1 Envelope placement

Every write tool's `params` object MUST carry an `_envelope` field whose
value is a full §11.2 envelope. The server MUST:

1. Verify the envelope per §11.4.
2. Extract `_envelope.nonce`, `_envelope.iat`, `_envelope.exp`,
   `_envelope.iss`, `_envelope.method`, `_envelope.params_hash`.
3. Re-compute `params_hash` over the remainder of `params`
   (`params` minus `_envelope`, canonicalized per RFC 8785) and confirm it
   equals the claimed hash.
4. Confirm `_envelope.method` equals the JSON-RPC `method` being invoked.
5. Check the nonce against the server's nonce cache (§11.5).
6. Only then invoke the tool's business logic.

A caller SHOULD populate `_envelope` via the client-side helpers provided by
`@aithos/protocol-core` (`signEnvelope`, `signEnvelopeWithMandate`). The
envelope is the sole authentication mechanism on the write path.

### 10.6.2 `aithos.publish_identity`

Register a new identity on the platform. The first call for a given DID
creates its S3 tree and index entries; subsequent calls under the same DID
with an unchanged DID document are idempotent no-ops, with a changed DID
document must go through `aithos.rotate_sphere_key` instead.

Input (inside `params`):

```ts
interface PublishIdentityInput {
  did_document: DidDocument;      // signed by the subject's root key
  handle: string;                  // display label, non-unique
  display_name?: string;
}
```

The envelope MUST be signed by the subject's **root** sphere key
(`verificationMethod = <did>#public` is NOT sufficient here; a dedicated
`#root` or the signature on the DID document itself applies — see §1.2.3).

Output:

```ts
interface PublishIdentityResult {
  did: string;
  canonical_url: string;          // "https://aithos.xyz/@{handle}#{did_prefix}"
  created_at: string;
}
```

Errors: `AITHOS_DID_CONFLICT` (DID already published with a different DID
document), `AITHOS_BAD_SIGNATURE`, `AITHOS_HANDLE_RESERVED` (servers MAY
reserve handles; not normative).

### 10.6.3 `aithos.publish_ethos_edition`

Publish a new edition at height `latest_height + 1` (or height 1 for a
first edition), together with the **new gamma entries** that produced the
edition's section state.

Input:

```ts
interface PublishEthosEditionInput {
  did: DidRef;
  manifest: Manifest;                            // signed; carries gamma.head
  zones: {
    public:  ZonePayload;
    circle?: ZonePayload;
    self?:   ZonePayload;
  };
  new_gamma_entries: SignedGammaEntry[];         // chronological, chained
}

interface ZonePayload {
  content:   { kind: "plaintext"; markdown: string }
           | { kind: "ciphertext"; wire: CipherEnvelope };
  signature: ZoneSignature;                       // per §2.4;
                                                   //   MAY carry authorized_by
}

type SignedGammaEntry = GammaEntry;               // per the gamma chapter §10.4:
                                                   //   id, at, prev_hash, hash,
                                                   //   op, signature{ key, sig,
                                                   //   authorized_by? }
```

`new_gamma_entries` MUST contain every gamma entry produced since the
previous edition's `manifest.gamma.head`. Empty array is valid only when
the edition produces no section-level change (rare; typically a metadata-
only republish).

**Signer of the envelope.** The write-path envelope (§11) MUST be signed
either:

- by one of the subject's sphere keys whose sphere covers every zone
  touched by this edition (in practice `#root` when multiple zones change,
  or the matching `#public`/`#circle`/`#self` when only one does), OR
- by a delegate key whose mandate (inside the envelope per §11.6) grants
  `ethos.write.<zone>` for every zone touched. In this case every gamma
  entry in `new_gamma_entries` that mutates such a zone MUST carry
  `signature.authorized_by == envelope.mandate.id`, and at least one zone
  signature in `zones` MUST likewise carry `authorized_by == envelope.mandate.id`.

Server MUST, in order, before any write lands:

1. Resolve `ethos-index` for `did`; read `latest_height`, `latest_gamma_head`,
   `latest_gamma_count`.
2. Verify `manifest.edition.height == latest_height + 1` (or `1` when
   `latest_height` is absent).
3. Verify `manifest.edition.prev_hash == sha256(canonical(prev_manifest))`
   (or `null` for the first edition).
4. Walk `new_gamma_entries` in order; for each entry verify:
   - Its `prev_hash` equals the hash of the previous entry in the list, or
     equals `latest_gamma_head` for the first entry (or `null` for the very
     first edition).
   - Its `hash` is `sha256(canonical(entry without hash + signature))`
     per gamma §10.4.
   - Its `signature` verifies (sphere-key path or delegate+mandate path).
   - When `authorized_by` is set, the mandate exists, is not revoked, and
     is within its time window at the entry's `at`.
5. Verify that the last new entry's `hash` equals `manifest.gamma.head`, and
   that `manifest.gamma.count == latest_gamma_count + new_gamma_entries.length`.
6. Verify every zone signature per §5 (sphere-key or delegate+mandate),
   and that each section's `gamma_ref` in the zone doc resolves to either
   an entry in `new_gamma_entries` or an earlier entry already anchored by
   the previous `gamma.head`.
7. Store, atomically:
   - `s3://…/ethos/{did}/editions/{height}/manifest.json` + zones under the
     same prefix (spec §3 layout);
   - each `new_gamma_entries[i]` at
     `s3://…/ethos/{did}/gamma/{entry.id}.json` (write-once; see §10.11).
8. Update the `ethos-index` entry's `latest_height`, `latest_gamma_head`,
   `latest_gamma_count` atomically.

Output:

```ts
interface PublishEthosEditionResult {
  bundle_id: string;
  height: number;
  canonical_url: string;
  gamma_head: string;            // sha256:<hex>, identical to manifest.gamma.head
  gamma_count: number;
  authorized_by?: string;         // mandate id, when the edition was delegate-signed
}
```

Errors: `AITHOS_EDITION_HEIGHT_CONFLICT`, `AITHOS_PREV_HASH_MISMATCH`,
`AITHOS_GAMMA_CHAIN_BROKEN` (new; §10.9), `AITHOS_GAMMA_HEAD_MISMATCH` (new;
§10.9), `AITHOS_BAD_SIGNATURE`, `AITHOS_MANDATE_INVALID`,
`AITHOS_MANDATE_REVOKED`, `AITHOS_INSUFFICIENT_SCOPE`,
`AITHOS_IDENTITY_TOMBSTONED`.

### 10.6.3a `aithos.publish_ethos_edition` — v0.4 envelope (NORMATIVE)

For a subject on the v0.4 format (manifest marker `aithos: "0.4.0"`),
`aithos.publish_ethos_edition` takes the content-addressed envelope of spec
§3A.6 instead of the v0.3 `zones` + `new_gamma_entries` payload of §10.6.3:

```ts
interface PublishEthosEditionV04Input {
  manifest: Manifest;                       // v0.4 manifest (§3A.5), signed
  objects: { [sha: string]: string };       // sha → base64(JCS object bytes)
  blobs:   { [sha: string]: string };       // sha → base64(section body bytes)
}
```

`objects` carries the ZoneShard / KeyRing / ExtraWraps objects that are **new**
to this edition; `blobs` carries the section bodies that are new. Objects and
blobs unchanged since the previous edition are NOT re-uploaded — they are
carried by sha.

The server MUST, in this order, before any write lands:

1. **Envelope + chain (unchanged from §10.6.3 / §3.8).** Verify the §11
   envelope, the `manifest_signature` (owner `#public` or delegate +
   `authorized_by`, §3.8 form), the linear `height` / `prev_hash` chain
   (`-32030` on a height conflict, `-32031` on a `prev_hash` mismatch), and
   `sha256_of_did_json`.
2. **Object integrity.** Every key of `objects` and `blobs` MUST equal the real
   `sha256` of its decoded content, else `-32044 ethos_object_hash_mismatch`.
   Every sha the manifest references (each `shard_shas[]`, `keyring_sha`,
   `extrawraps_sha`) MUST be present in the uploaded `objects` **or** in the set
   of objects referenced by the previous edition (carry by induction — the exact
   analogue of `carriedShaSet`), else `-32043 ethos_object_missing`.
3. **Body carry.** For each shard object that is **absent from the previous
   edition** (a new sha), each of its `entries[].blob_sha` MUST be present in
   the uploaded `blobs` **or** in `carriedShaSet(prev)`, else `-32043`. Shards
   carried identically are not re-read.
4. **Delegated authorization** (when the envelope carries a mandate). Verify the
   mandate (FRESH `did.json`, epoch, ConsistentRead revocation — unchanged),
   then diff only the **changed shards**: per zone, `entries(prev changed
   shards)` vs `entries(new changed shards)` → `create` / `edit` / `delete` ops
   keyed by `section_id` (create = new id; edit = `blob_sha` / `sha256_of_plaintext`
   / `title*` / `enc_dek` changed; delete = id gone), mapped onto the §4.8.2′
   verbs + selectors (draft `bundle-v0.3-section-verb-scopes.md`). Structural
   rules, enforced with
   `-32046 ethos_keyring_forbidden`: `keyring_sha` MUST change ONLY in an owner
   publish; an ExtraWraps entry MUST change only if the corresponding op on that
   `section_id` is authorized; `shard_count` MUST be stable outside an owner
   publish unless a re-shard is made necessary by an authorized `create`.
5. **Version regression.** A v0.3 publish on a subject already at v0.4 MUST be
   refused with `-32045 ethos_spec_version_regression` — `aithos` never
   regresses (dual-write does not permit a downgrade).
6. **Persistence.** Objects and blobs are written in parallel; the DDB index row
   is written LAST (atomicity unchanged from §10.6.3 step 7–8).

The output shape is that of §10.6.3 (`PublishEthosEditionResult`); `gamma_head`
/ `gamma_count` continue to reflect the edition's gamma anchor.

Migration (§3A.10) is an ordinary owner publish under this envelope: the objects
+ manifest are uploaded, **zero blob** (all bodies carried), `height + 1`.

### 10.6.4 `aithos.publish_mandate`

Input: `{ mandate: Mandate }` — full §4.2 object, signed by the issuer.

Server stores under `s3://…/mandates/{mandate_id}.json` and indexes.
Idempotent on byte-identical re-publication.

Envelope MUST be signed by the issuer's sphere key whose scope covers the
mandate's zone (e.g. publishing a `circle.read` mandate requires a signature
from the issuer's `#circle` key).

Output: `{ mandate_id: string; stored_at: string }`.

### 10.6.5 `aithos.publish_revocation`

Input: `{ revocation: Revocation }` — full §4.6 object, signed by the
issuer of the referenced mandate.

Envelope MUST be signed by the same sphere key that signed the original
mandate (or a subsequent rotation chain).

Output: `{ mandate_id: string; revoked_at: string }`.

### 10.6.6 `aithos.publish_tombstone`

Soft-delete a subject. The edition tree remains in place (third parties
may already hold bundle copies; their cryptographic validity is unaffected),
but the platform stops serving new reads, flips the index status to
`tombstoned`, and excludes the identity from feed and search.

Input:

```ts
interface Tombstone {
  aithos: "0.1.0";
  subject: string;                  // DID
  at: string;                        // RFC 3339
  reason?: "user_request" | "compromise" | "policy_change" | "other";
  reason_details?: string;
  proof: Signature;                  // signed by the subject's root key
}
```

Output: `{ did: string; tombstoned_at: string }`.

After a tombstone is published, `aithos.get_ethos_*` tools MUST return
`AITHOS_IDENTITY_TOMBSTONED` with `tombstoned_at` and `reason` in the error
data. `aithos.get_identity` continues to return the DID document — the key
material stays verifiable, which matters for downstream tools verifying
historical signatures.

### 10.6.7 `aithos.rotate_sphere_key`

Rotate a sphere key and re-publish the DID document. All mandates signed by
the retired key become unverifiable (their signatures no longer match the
current DID document) — see spec §5.4 for the rotation chain semantics.

Input:

```ts
interface RotateSphereKeyInput {
  did: DidRef;
  sphere: "public" | "circle" | "self";
  new_did_document: DidDocument;     // carries the new sphere pubkey
}
```

Envelope MUST be signed by the subject's **root** key — a compromised sphere
key cannot rotate itself; rotations always escalate to root.

Output: `{ did: string; sphere: "public"|"circle"|"self"; new_fingerprint: string; rotated_at: string }`.

## 10.7 Rate limits (normative minimum)

A conformant platform SHOULD enforce at least:

- **Read path, anonymous.** 60 req/min per source IP, 600 req/hour.
- **Read path, per DID** (when a caller identifies itself via a signed read
  envelope; optional). 600 req/min.
- **Write path, per DID.** 30 req/min sustained, burst 10. Write-heavy
  operations (`publish_ethos_edition`) count double.

On exceeding any limit, the server MUST respond with JSON-RPC error
`AITHOS_RATE_LIMITED` and MAY include a `Retry-After` transport header.

Limits a mandate embeds in its `constraints.rate` (§4.2.5) are **additional**
— they are applied in conjunction with the platform's own limits, not in
place of them.

## 10.8 Conformance

A conformant platform MUST implement:

- §10.5.1, §10.5.2, §10.5.3, §10.5.4, §10.5.4a, §10.5.5, §10.5.6, §10.5.9,
  §10.5.10, §10.5.11 (all core read tools, including the v0.4 object-fetch route
  §10.5.4a);
- §10.6.2, §10.6.3, §10.6.3a, §10.6.4, §10.6.5, §10.6.6 (all core write tools,
  including the v0.4 publish envelope §10.6.3a);
- dual-read of both the v0.3 (`0.3.0`) and v0.4 (`0.4.0`) bundle formats
  (spec §3A), with the version-regression refusal of §10.6.3a step 5;
- §10.7 with at least the rate limits listed.

A conformant platform SHOULD implement §10.5.7 (feed), §10.5.8 (search),
§10.5.12 (verify_bundle), §10.6.7 (rotate_sphere_key).

A platform MAY expose additional tools, prefixed `aithos.x_` to signal
non-standard extension.

## 10.9 Errors

JSON-RPC errors use the standard envelope. Aithos-specific codes live in
`[-32099, -32010]`:

| Code    | Name                              | Meaning |
|---------|-----------------------------------|---------|
| -32010  | `AITHOS_BAD_ENVELOPE`             | Signed envelope missing, malformed, or failed signature check. |
| -32011  | `AITHOS_BAD_SIGNATURE`            | Payload signature failed to verify against the DID document. |
| -32012  | `AITHOS_REPLAY_DETECTED`          | Envelope nonce was already seen. |
| -32013  | `AITHOS_STALE_ENVELOPE`           | Envelope `exp` is in the past, or `iat` too far in the future. |
| -32020  | `AITHOS_NOT_FOUND`                | DID, edition, mandate, or revocation does not exist. |
| -32021  | `AITHOS_IDENTITY_TOMBSTONED`      | Identity exists but was soft-deleted. |
| -32022  | `AITHOS_DID_CONFLICT`             | DID already published with a different DID document. |
| -32023  | `AITHOS_HANDLE_RESERVED`          | Handle is on the server's reserved list. |
| -32030  | `AITHOS_EDITION_HEIGHT_CONFLICT`  | Submitted height is not `latest_height + 1`. |
| -32031  | `AITHOS_PREV_HASH_MISMATCH`       | `manifest.edition.prev_hash` does not match previous edition. |
| -32032  | `AITHOS_BUNDLE_INVALID`           | Bundle failed a §3.8 check. |
| -32033  | `AITHOS_GAMMA_CHAIN_BROKEN`       | A `new_gamma_entries` item's `prev_hash` does not match its predecessor (or the stored `latest_gamma_head`). |
| -32034  | `AITHOS_GAMMA_HEAD_MISMATCH`      | The last new gamma entry's hash does not equal `manifest.gamma.head`, or `manifest.gamma.count` disagrees with the stored count plus the new entries. |
| -32040  | `AITHOS_MANDATE_INVALID`          | Mandate structure, signature, or time window invalid. |
| -32041  | `AITHOS_MANDATE_REVOKED`          | Mandate presented is revoked. |
| -32042  | `AITHOS_INSUFFICIENT_SCOPE`       | Presented mandate does not cover the requested operation. |
| -32043  | `ethos_object_missing`            | A sha referenced by a v0.4 manifest is neither uploaded nor carried (§10.6.3a, §3A.6). |
| -32044  | `ethos_object_hash_mismatch`      | An uploaded v0.4 object/blob's content does not match its announced sha (§10.6.3a). |
| -32045  | `ethos_spec_version_regression`   | A v0.3 publish on a subject already migrated to v0.4 (§10.6.3a). |
| -32046  | `ethos_keyring_forbidden`         | `keyring_sha` or `shard_count` changed outside an owner publish (§10.6.3a). |
| -32050  | `AITHOS_RATE_LIMITED`             | Caller exceeded the platform rate limit. |
| -32051  | `AITHOS_BUDGET_TRIPPED`           | Platform-wide kill switch active; writes are paused. |

Error `data` fields SHOULD carry structured context (`{ did, height,
mandate_id, retry_after_seconds, … }`) so clients can act without parsing
human-readable messages.

## 10.10 Versioning discipline

The tool names in this chapter are reserved under `aithos.*`. The platform
MUST NOT change a tool's input schema, output schema, or error codes
without either:

- adding a new tool under a versioned name (`aithos.get_feed_v2`), or
- bumping `experimental.aithos.spec` to a new minor and documenting the
  diff in a new chapter or amendment.

Between `experimental.aithos.spec` `0.1.x` and `1.0.0`, breaking changes are
permitted on minor bumps; after `1.0.0` they require a major.

## 10.11 Hosting modes for the gamma log

The gamma log (the gamma chapter, §10.3) is authoritative for section
mutation history. A bundle anchors to it via `manifest.gamma.head`, but the
log content itself lives *outside* the bundle. A platform that accepts
`aithos.publish_ethos_edition` with `new_gamma_entries` therefore has a
choice about what to do with those entries after verification.

### 10.11.1 Mode A — append-only, not re-served (write-only)

The platform stores each accepted gamma entry at
`s3://…/ethos/{did}/gamma/{entry.id}.json` (or equivalent write-once object
store), but does **not** expose any read tool for them. Readers who need
history obtain the log from the subject out-of-band (e.g. the `.gamma`
companion artifact the subject keeps locally, or a `gamma.url` the subject
publishes in the manifest pointing to their own host).

This mode is explicitly permitted. A platform operating in Mode A:

- MAY omit `aithos.get_gamma_entry` / `aithos.list_gamma_entries` entirely.
- MUST still accept and validate `new_gamma_entries` on writes (the chain
  integrity checks in §10.6.3 step 4 are non-negotiable — they protect
  against a later rug-pull where the subject claims a different history).
- SHOULD persist the entries even though it never serves them back. A
  platform that accepts but discards gamma entries loses the audit trail
  that justifies the write-path rigor and SHOULD NOT be advertised as
  conformant.
- SHOULD document its mode in the `initialize` response under
  `experimental.aithos.gamma_mode: "write-only"` (see §10.11.3).

**Rationale.** A light consumer (gamma chapter §10.2) only needs the bundle
and its `gamma.head` anchor — it does not need to walk the log to use the
ethos. Write-only gamma matches that reality and reduces the platform's
surface area. Full-consumer audit remains possible via the subject's own
copy of the log.

### 10.11.2 Mode B — readable gamma (full history)

The platform additionally exposes:

- `aithos.get_gamma_entry` — `{ did: DidRef, entry_id: string }` →
  `SignedObject<GammaEntry>` (§10.4 of the gamma chapter).
- `aithos.list_gamma_entries` — `{ did: DidRef, from_id?: string, limit?: number,
  cursor?: string }` → `Page<GammaEntry>`, oldest-first by default, with
  an option to walk backwards from a given entry.

These tools are **RECOMMENDED but not REQUIRED**. A platform implementing
them MUST:

- Serve the raw stored entry bytes — no re-signing, no re-canonicalization.
- Refuse to serve an entry for a tombstoned subject unless the caller
  carries a signed read envelope whose subject is the tombstoned identity
  (out-of-band audit path).

In Mode B, the platform SHOULD declare `experimental.aithos.gamma_mode:
"readable"` in the `initialize` response.

### 10.11.3 Mode discovery

The `initialize` response's `capabilities.experimental.aithos` object
SHOULD carry a `gamma_mode` field:

```json
{
  "aithos": {
    "spec": "0.2.0",
    "role": "primitives",
    "gamma_mode": "write-only" | "readable"
  }
}
```

Absent `gamma_mode` is equivalent to `"write-only"`. Clients that require
readable gamma for their flow MUST check this field and refuse servers
that cannot serve history.

### 10.11.4 Relationship to the subject's own host

Nothing in this chapter constrains where else a subject may publish their
gamma log. A subject running their own `gamma.url` endpoint, or sharing a
`.gamma.enc` file peer-to-peer, is compatible with either Mode A or Mode B
on the platform — the bundle's `gamma.head` anchor is the single source of
truth, and any number of readable copies may exist downstream.
