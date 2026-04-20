# 10 · Platform MCP — primitives

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
  "serverInfo": { "name": "aithos-platform", "version": "0.1.0" },
  "capabilities": {
    "tools": {},
    "experimental": { "aithos": { "spec": "0.1.0", "role": "primitives" } }
  }
}
```

Clients MUST verify `experimental.aithos.role === "primitives"` before calling
the tools specified here.

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
    verificationMethod: string; // did:aithos:…#<sphere>
    created: string;            // RFC 3339
  };
  fetched_at: string;           // RFC 3339; server's observation time, not signed
}
```

For compound objects (an edition = manifest + zone docs + per-zone
signatures), the wrapper SHOULD carry the signature of the manifest and an
array of zone signatures; see `aithos.get_ethos_edition`.

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

Output: `SignedObject<Manifest>` per spec §2.6.

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
first edition).

Input:

```ts
interface PublishEthosEditionInput {
  did: DidRef;
  manifest: Manifest;                            // signed
  zones: {
    public:  ZonePayload;
    circle?: ZonePayload;
    self?:   ZonePayload;
  };
}

interface ZonePayload {
  content:   { kind: "plaintext"; markdown: string }
           | { kind: "ciphertext"; wire: CipherEnvelope };
  signature: Signature;                           // over the zone doc per §2.4
}
```

The envelope MUST be signed either:
- by the sphere key matching each zone being written — i.e. a single
  envelope signed by the root key authorizing the edition, OR
- by a delegate key holding a write mandate whose scopes cover every zone
  in `zones` (§4.4).

Server MUST:
1. Verify `manifest.edition.height == latest_height + 1` (or 1 for first).
2. Verify `manifest.edition.prev_hash` matches `sha256(prev_manifest_canonical)`.
3. Verify all signatures per spec §5.
4. Store under `s3://…/ethos/{did}/editions/{height}/`.
5. Update the `ethos-index` entry's `latest_height` atomically.

Output: `{ bundle_id: string; height: number; canonical_url: string }`.

Errors: `AITHOS_EDITION_HEIGHT_CONFLICT`, `AITHOS_PREV_HASH_MISMATCH`,
`AITHOS_BAD_SIGNATURE`, `AITHOS_IDENTITY_TOMBSTONED`.

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

- §10.5.1, §10.5.2, §10.5.3, §10.5.4, §10.5.5, §10.5.6, §10.5.9, §10.5.10,
  §10.5.11 (all core read tools);
- §10.6.2, §10.6.3, §10.6.4, §10.6.5, §10.6.6 (all core write tools);
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
| -32040  | `AITHOS_MANDATE_INVALID`          | Mandate structure, signature, or time window invalid. |
| -32041  | `AITHOS_MANDATE_REVOKED`          | Mandate presented is revoked. |
| -32042  | `AITHOS_INSUFFICIENT_SCOPE`       | Presented mandate does not cover the requested operation. |
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
