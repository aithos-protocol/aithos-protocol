# 11 · Signed requests

## 11.1 Overview

Every write to a platform endpoint (§10.6, §12 where applicable) is signed
by the caller. There is no session, no cookie, no JWT, no bearer token. The
only way to authorize a write is to send it inside a **signed envelope** —
a compact, self-contained, time-bounded attestation that (a) proves the
caller possesses a specific private key and (b) is unique enough that the
server can safely refuse a replay.

This chapter specifies the envelope, the canonicalization of the payload it
covers, the server's verification steps, and the replay-protection cache.

## 11.2 Envelope shape

An envelope is a JSON object with exactly these fields, in this order when
canonicalized:

```json
{
  "aithos-envelope": "0.1.0",
  "iss":           "did:aithos:z6Mk…",
  "aud":           "https://mcp.aithos.xyz/primitives/write",
  "method":        "aithos.publish_ethos_edition",
  "iat":           1714000000,
  "exp":           1714000300,
  "nonce":         "01HV8F1T2Z6Q0M0N0K0J0C0B0A",
  "params_hash":   "sha256-<hex>",
  "mandate":       { … } | null,
  "proof": {
    "type":              "Ed25519Signature2020",
    "verificationMethod":"did:aithos:z6Mk…#circle" | "<multibase-delegate-key>",
    "created":           "2026-04-20T16:00:00Z",
    "proofValue":        "<base64url>"
  }
}
```

Field-by-field:

| Field             | Type    | Required | Description |
|-------------------|---------|----------|-------------|
| `aithos-envelope` | string  | yes | Envelope format version. Only `"0.1.0"` is valid at this spec revision. |
| `iss`             | string  | yes | DID of the **authoring subject** — the identity whose state is being mutated, never the delegate's DID. |
| `aud`             | string  | yes | Absolute URL of the endpoint the envelope is addressed to. Includes scheme, host, path; no query string, no fragment. |
| `method`          | string  | yes | The fully-qualified tool name being invoked (e.g. `"aithos.publish_ethos_edition"`). MUST match the JSON-RPC `method`. |
| `iat`             | integer | yes | Issued-at, UNIX seconds. |
| `exp`             | integer | yes | Expiry, UNIX seconds. MUST satisfy §11.3. |
| `nonce`           | string  | yes | Per-request unique identifier. [ULID](https://github.com/ulid/spec) recommended; any 16–64 char printable-ASCII token is accepted. MUST be unique per `(iss, iat)` pair within the TTL window. |
| `params_hash`     | string  | yes | `"sha256-"` prefix + lowercase hex SHA-256 of the RFC-8785 canonicalization of the JSON-RPC `params` object with `_envelope` removed. |
| `mandate`         | object  | cond. | Required when `proof.verificationMethod` points to a **delegate key** rather than a sphere key (§11.6). Contains the full §4.2 mandate object authorizing the delegate. Omitted (or `null`) when `iss` directly signs with one of its own sphere keys. |
| `proof`           | object  | yes | Detached signature per spec §5. |

The envelope is carried as `params._envelope` in every write-path JSON-RPC
call; no HTTP header is used. This keeps the envelope end-to-end visible to
any intermediary (proxy, log, audit trail) without depending on header
forwarding semantics.

## 11.3 TTL constraints

At the moment of server-side verification (server clock `now`, UNIX seconds):

- `iat` MUST be within `[now - 30, now + 30]`. A 30-second clock skew
  tolerance is normative; servers MAY narrow it but MUST NOT widen it
  beyond 60 seconds.
- `exp > now` MUST hold.
- `exp - iat` MUST be in `[1, 300]`. The envelope is short-lived by
  construction: no five-minute-plus authorizations. If a caller needs a
  longer authority, they use a mandate (chapter 4), not a long-lived
  envelope.

Any violation is `AITHOS_STALE_ENVELOPE` (§10.9 `-32013`).

## 11.4 Server verification

The server MUST perform these steps, in order, before invoking the business
logic of any write tool:

1. **Schema check.** Reject any envelope missing a required field or with a
   type mismatch. Error: `AITHOS_BAD_ENVELOPE` (`-32010`).
2. **Audience check.** `aud` MUST equal the server's canonical URL for the
   path that received the request (comparing after normalizing trailing
   slashes, lowercasing host). Mismatch: `AITHOS_BAD_ENVELOPE`.
3. **Method check.** `method` MUST equal the JSON-RPC `method` being
   invoked. Mismatch: `AITHOS_BAD_ENVELOPE`.
4. **TTL check.** Apply §11.3. Violation: `AITHOS_STALE_ENVELOPE`
   (`-32013`).
5. **Params-hash check.** Recompute
   `"sha256-" + sha256_hex(rfc8785_canonicalize(params_without_envelope))`
   and compare to `params_hash`. Mismatch: `AITHOS_BAD_ENVELOPE`.
6. **Signer resolution.**
   - If `mandate` is absent: resolve `proof.verificationMethod` against
     the current DID document of `iss` (fetched per §1). The verification
     method MUST appear in the DID document and MUST have an assertion
     purpose compatible with the called tool (`#public`, `#circle`,
     `#self`, or `#root`; see §11.7). Failure: `AITHOS_BAD_SIGNATURE`
     (`-32011`).
   - If `mandate` is present: resolve the mandate per §4.7 against `iss`'s
     current DID document. `proof.verificationMethod` MUST equal
     `mandate.grantee.pubkey`. The mandate MUST be within its time window
     and not revoked. Its scopes MUST cover `method` per §11.6. Failure:
     `AITHOS_MANDATE_INVALID` (`-32040`), `AITHOS_MANDATE_REVOKED`
     (`-32041`), or `AITHOS_INSUFFICIENT_SCOPE` (`-32042`).
7. **Signature verification.** Reconstruct the canonical envelope (the
   envelope JSON minus `proof.proofValue`, RFC-8785 canonicalized), verify
   the Ed25519 signature against the resolved signer public key. Failure:
   `AITHOS_BAD_SIGNATURE`.
8. **Replay check.** Apply §11.5. Failure: `AITHOS_REPLAY_DETECTED`
   (`-32012`).
9. **Commit nonce.** Write the nonce to the replay cache with TTL
   `exp + 30s` before invoking the business logic, so a concurrent
   identical request loses the replay-check race.

Only after all eight checks pass MAY the server execute the tool. A tool
failure after the nonce is committed does NOT release the nonce — the
envelope has been consumed.

## 11.5 Replay cache

### 11.5.1 Key

```
replay_key = "aithos.envelope.v1:" + iss + ":" + nonce
```

`iss` namespacing is load-bearing: two different identities MAY legitimately
choose the same nonce, and isolating them avoids unnecessary collisions.

### 11.5.2 Storage (reference implementation)

The reference AWS implementation uses a DynamoDB table `aithos-nonces`:

```
PK:   replay_key   (string)
TTL:  expires_at   (number, UNIX seconds)
```

- Conditional `PutItem` with `attribute_not_exists(PK)`:
  - Success → nonce unseen, proceed.
  - `ConditionalCheckFailedException` → replay, reject.
- `expires_at = envelope.exp + 30` (`+30s` matches the §11.3 skew tolerance).
- DynamoDB TTL auto-expires rows ~10 minutes after `expires_at`; the server
  MUST NOT rely on immediate deletion and MUST always write with the
  conditional check.

### 11.5.3 Non-AWS implementations

Any backing store that provides **atomic conditional insert with TTL** is
acceptable. A Redis `SET key 1 NX EX <ttl>` pattern, a SQL unique constraint
on `(iss, nonce)` with a background sweeper, etc. In all cases:

- The conditional check MUST be atomic (no read-then-write race).
- Cache lifetime MUST be ≥ `exp - now` at the moment the nonce is written,
  plus §11.3 skew. A cache that expires nonces early before envelope `exp`
  creates a replay window.

### 11.5.4 Cross-region / cross-partition

A platform that shards its write path across regions or partitions MUST
ensure that a nonce committed in one shard is visible to every shard within
the envelope TTL window. Global DynamoDB tables, a single-region replay
cache, or a distributed lock service are all acceptable. Per-shard caches
that never replicate are NOT acceptable.

## 11.6 Mandate-authorized writes

A subject can authorize a delegate to sign envelopes on their behalf by
issuing a write mandate (§4.2) whose `grantee.pubkey` matches the delegate's
Ed25519 public key.

In that case the envelope looks like:

```json
{
  "aithos-envelope": "0.1.0",
  "iss":   "did:aithos:<subject>",
  "aud":   "https://mcp.aithos.xyz/primitives/write",
  "method":"aithos.publish_ethos_edition",
  …,
  "mandate": {
    "aithos-mandate": "0.1.0",
    "id":         "urn:aithos:mandate:01HV…",
    "issuer":     "did:aithos:<subject>",
    "grantee":    { "pubkey": "z6Mk<delegate-pub>" },
    "scopes":     ["ethos.write.public"],
    "not_before": "2026-04-20T00:00:00Z",
    "not_after":  "2026-05-20T00:00:00Z",
    "proof":      { … mandate signed by subject's #public key … }
  },
  "proof": {
    "verificationMethod":"z6Mk<delegate-pub>",  // delegate key, not a DID URL
    …,
    "proofValue":"<base64url>"                  // signed by delegate's private key
  }
}
```

Scope-to-method mapping (normative):

| Method                              | Required scope(s) |
|-------------------------------------|-------------------|
| `aithos.publish_ethos_edition`      | `ethos.write.<zone>` for every zone present in the edition's payload |
| `aithos.publish_mandate`            | `mandate.issue.<sphere>` where `<sphere>` is the mandate's zone |
| `aithos.publish_revocation`         | `mandate.revoke` |
| `aithos.publish_tombstone`          | `identity.tombstone` (rare; subject usually signs with root) |
| `aithos.publish_identity`           | never delegable — root signature required |
| `aithos.rotate_sphere_key`          | never delegable — root signature required |

The server MUST reject an envelope whose mandate does not cover the method,
with `AITHOS_INSUFFICIENT_SCOPE` (`-32042`).

## 11.7 Signing purposes

When the envelope is signed directly by the subject (no mandate), the
required sphere key depends on the method:

| Method                              | Required sphere key |
|-------------------------------------|---------------------|
| `aithos.publish_ethos_edition`      | Any sphere key whose zone appears in the edition payload; when the edition writes multiple zones, the envelope MUST be signed by `#root`. |
| `aithos.publish_mandate`            | The sphere key matching `mandate.sphere` (`#public`, `#circle`, `#self`, or `#root` for unrestricted mandates). |
| `aithos.publish_revocation`         | Same sphere that issued the mandate (or `#root`). |
| `aithos.publish_tombstone`          | `#root`. |
| `aithos.publish_identity`           | `#root` (the DID-document-signing key). |
| `aithos.rotate_sphere_key`          | `#root`. |

`#root` is the identity's DID-document-signing key; it MUST NOT be delegated
and SHOULD be held in a higher-assurance storage tier (offline, hardware,
sealed) than sphere keys.

## 11.8 Canonicalization

Every hash and every signature in this chapter is taken over the
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization
Scheme of the relevant object, interpreted as UTF-8 bytes. The reference
implementation lives in `@aithos/protocol-core/canonical`.

## 11.9 Client helpers (non-normative)

`@aithos/protocol-core` exposes two high-level helpers for callers:

```ts
import {
  signEnvelope,
  signEnvelopeWithMandate,
} from "@aithos/protocol-core";

// Subject signing directly
const envelope = signEnvelope({
  iss,                        // subject DID
  aud: "https://mcp.aithos.xyz/primitives/write",
  method: "aithos.publish_ethos_edition",
  params,                     // the tool params, without _envelope
  sphereKey: identity.spheres.public, // Ed25519 seed + pubkey
  ttlSeconds: 60,
});

// Delegate signing with a mandate
const envelope = signEnvelopeWithMandate({
  iss,
  aud,
  method,
  params,
  delegateKey,                // Ed25519 seed + pubkey
  mandate,                    // full mandate object
  ttlSeconds: 60,
});
```

Both helpers produce an envelope that passes §11.4 verification against a
compliant server. They set `nonce` to a freshly minted ULID, `iat` to `now`,
`exp` to `now + ttlSeconds`, and `params_hash` over the RFC-8785 canonical
form of `params`.

Implementations on other platforms (browser WebCrypto, mobile, non-Node
runtimes) are expected to follow the same contract.

## 11.10 Security notes

- **Clock drift.** The 30s skew tolerance is there to handle NTP drift, not
  to authorize misconfigured clients. A client whose clock is off by more
  than 30s SHOULD fail its own pre-flight and refuse to send.
- **TTL lower bound.** A 1-second TTL is valid and useful for interactive
  per-action signing (user clicks "publish", UI signs, sends, window closes
  before a passive adversary could capture and replay). Clients SHOULD
  prefer short TTLs where the UX permits.
- **Nonce entropy.** A ULID provides 80 bits of randomness. Implementations
  using non-ULID nonces MUST ensure at least 64 bits of unpredictable
  randomness; predictable nonces (counter, timestamp-only) are NOT
  acceptable.
- **Replay cache outages.** If the replay cache is unreachable, the server
  MUST fail closed — reject the write with an internal error rather than
  allow it through. Writes that flow without replay protection defeat the
  purpose of the envelope.
- **Logging.** Servers SHOULD log the full envelope (minus `proofValue`)
  for audit. The envelope is not secret; its signature provides
  non-repudiation that can be replayed through logs without loss of
  fidelity.
