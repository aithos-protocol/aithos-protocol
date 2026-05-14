# 4 · Mandates for data

## 4.1 Overview

The data sub-protocol reuses the **mandate** document defined in the
Ethos sub-protocol (chapter 4 of `spec/`) unchanged. What this chapter
adds:

- The **scope vocabulary** for data access (`data.<collection>.<action>`).
- **Filter constraints** that scope a mandate to a subset of records.
- The **authorization flow** that connects a mandate to a CMK wrap.
- The **revocation flow** and its effect on the CMK and on outstanding
  ciphertext copies.

A reader unfamiliar with the mandate document format should review
Ethos §4.2 before proceeding.

## 4.2 Scope vocabulary

Mandate scopes for data access follow this grammar:

```
data.<collection_name>.<action>
data.<collection_name>.<action>.<filter_key>
data.*.<action>                    // wildcard across all collections
```

### 4.2.1 Per-collection scopes

| Scope | Action permitted |
|---|---|
| `data.<col>.read` | Call `aithos.data.get_record`, `list_records` on collection `<col>`. |
| `data.<col>.write` | Call `insert_record`, `update_record`, `delete_record`. Implies `read`. |
| `data.<col>.admin` | Same as `write` plus `authorize_app`, `revoke_app` (sub-delegation), `rotate_cmk`. Reserved for trusted apps — typically not granted to third-party apps in v0.1. |

### 4.2.2 Wildcards

| Scope | Meaning |
|---|---|
| `data.*.read` | Read access across every collection the subject owns. |
| `data.*.write` | Write access to every collection. |

Wildcards are conservative. A subject SHOULD grant per-collection
scopes whenever the granularity is known. Wildcards exist for cases
where the application's scope is intrinsically cross-collection (an
agent that browses every data collection to assemble cross-domain
answers), and SHOULD be accompanied by a tight `not_after` window.

### 4.2.3 Sub-collection filters

A scope MAY carry a filter suffix narrowing the records it covers:

```
data.contacts.read.status:lead
data.messages.read.thread:thread_01J…
```

The filter syntax is `<field>:<value>`, where `<field>` MUST be an
`aithos:indexable` field of the collection's schema and `<value>` is
an exact-match equality predicate.

> **Decision (revisable):** v0.1 supports only single-field equality
> filters in mandate scopes. Multi-field filters and value ranges are
> deferred.
>
> **Rationale.** Mandate filters must be evaluable server-side without
> ambiguity. A simple equality grammar is unambiguous, fits naturally
> on DynamoDB GSI lookups, and covers the bulk of useful cases
> ("agent X may read leads only," "agent Y may read messages of this
> thread only"). Generic predicate languages introduce parser
> complexity and security surface (predicate injection, evaluation
> cost) for marginal benefit.
>
> **Pending review.** The decision to defer range filters and OR
> predicates is open.

A scope without a filter (`data.contacts.read`) covers the entire
collection.

## 4.3 Filter enforcement

A mandate carrying a filter scope (`data.contacts.read.status:lead`) is
enforced at three levels:

### 4.3.1 At authorization time

When the subject calls `aithos.data.authorize_app` with a filtered
mandate:

1. The platform records the filter in the wrap metadata (the wrap
   entry in the collection's CMK wraps array gains a `filter` field).
2. The wrap itself is NOT filter-restricted cryptographically — the
   grantee receives a wrap of the full CMK. The filter is enforced by
   the platform on every request, not by the encryption layer.
3. Rationale: cryptographically restricting access to a subset of
   records would require sub-collection keys, which would defeat the
   O(1) authorization property. The PDS becomes a trusted enforcement
   point for filter mandates.

> **Decision (revisable):** v0.1 filter mandates are **platform-enforced**,
> not cryptographically enforced. Cryptographic enforcement of filters
> requires sub-collection key derivation and is deferred to a future
> minor version.
>
> **Threat consequence.** A platform operator who bypasses the filter
> check could expose records outside the filter scope to the grantee.
> Subjects who require cryptographic enforcement against a hostile
> platform MUST NOT grant filter mandates and SHOULD use full-collection
> mandates with single-tenant deployments instead.

### 4.3.2 On reads

On `list_records` and `get_record`:

- The platform extracts the mandate's filter from the envelope.
- For `list_records`, the filter is implicitly ANDed with the caller's
  query filter. Returned items satisfy both.
- For `get_record`, the platform fetches the record, evaluates the
  mandate filter against the record's metadata clear, returns the
  record only if the filter matches. Otherwise `AITHOS_NOT_FOUND` is
  returned (not `AITHOS_INSUFFICIENT_SCOPE`, to avoid leaking the
  existence of records outside the filter).

### 4.3.3 On writes

On `insert_record` / `update_record`:

- The platform evaluates the mandate filter against the proposed
  metadata clear of the post-write record.
- A write that would produce a record OUTSIDE the filter scope is
  rejected with `AITHOS_DATA_FILTER_VIOLATION`.
- This prevents a `data.contacts.write.status:lead` mandate from
  inserting a record with `status: won`, which would otherwise leak
  the writer's filtered visibility.

A write that **updates** a record FROM inside the filter scope TO
outside is also rejected — the writer cannot move a record out of
their own scope. The owner (or a wider-scoped agent) must perform such
transitions.

## 4.4 Mandate document — data-specific fields

The mandate document (Ethos §4.2) is reused unchanged. Data mandates use
the following conventions:

- `actor_sphere` — set to `"data"`. Existing Aithos spheres are
  `public`, `circle`, `self`; v0.1 of the data sub-protocol adds
  `data` to that list. (The `actor_sphere` field is informative for
  data scopes; the cryptographic binding is via the grantee pubkey
  and the CMK wrap, not via a sphere.)
- `scopes` — array of data scope strings (§4.2).
- `constraints` — same constraint vocabulary as Ethos §4.2.5 applies.
  Notably:
  - `rate_limit` — keys like `reads_per_hour`, `writes_per_hour`,
    `inserts_per_day`.
  - `require_counter_sign` — actions requiring live owner co-sign
    (typically `delete_record`, `rotate_cmk`, `revoke_app`).

### 4.4.1 Example mandate for switchia

```json
{
  "aithos-mandate": "0.1.0",
  "id": "mandate_01JG4X7RABCDXYZ123",
  "issuer": "did:aithos:z6Mkr…",
  "issued_by_key": "did:aithos:z6Mkr…#data",
  "grantee": {
    "id": "urn:aithos:app:switchia@instance-eu-west-1",
    "label": "Switchia — prospect qualification agent",
    "pubkey": "z6MkSwitchiaEd25519PublicKey…",
    "kex_pubkey": "z6LSSwitchiaX25519PublicKey…"
  },
  "actor_sphere": "data",
  "scopes": [
    "data.contacts.write",
    "data.messages.write"
  ],
  "constraints": {
    "rate_limit": { "writes_per_hour": 200, "reads_per_hour": 600 },
    "require_counter_sign": ["delete_record", "rotate_cmk"]
  },
  "not_before": "2026-05-14T00:00:00Z",
  "not_after":  "2027-05-14T00:00:00Z",
  "issued_at":  "2026-05-13T19:00:00Z",
  "nonce":      "rNlx4L9k3qBp",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#data",
    "value": "mF7p2x9kLQ…"
  }
}
```

### 4.4.2 Grantee key pair

Unlike pure-action mandates that may use only an Ed25519 grantee key,
data mandates that authorize **reads** REQUIRE the grantee to advertise
an X25519 public key (`kex_pubkey`). The X25519 key is the recipient of
the CMK wrap. Without it, the grantee cannot decrypt anything.

A mandate granting only write scope MAY omit `kex_pubkey` (the grantee
would be writing blind, with the owner managing read access separately).
This is unusual but valid.

## 4.5 Authorization flow

The end-to-end flow when an application is granted access to a
collection:

```
1. Application generates Ed25519 + X25519 keypairs locally.
   Publishes Ed25519 pubkey + X25519 pubkey in its identification.

2. Application requests a mandate from the user (via deep link,
   QR code, browser extension popup, etc.).

3. User reviews the requested scopes in their Aithos client UI.
   Signs the mandate with their #data sphere key.

4. User's Aithos client calls:
     aithos.data.authorize_app({
       collection_name,
       mandate,             // the signed document
       grantee_kex_pubkey   // duplicated from mandate.grantee.kex_pubkey
                            // for explicit CMK wrap target
     })

5. Platform verifies:
   - mandate signature against subject's DID document
   - mandate.issuer == subject_did
   - scopes contain the appropriate data.<collection>.<action> entries
   - not_before <= now <= not_after
   - the user's client also produced a fresh CMK wrap for the grantee
     (the wrap is included in the call's params)

6. Platform appends the wrap to the collection's wrap list (chapter 02
   §2.3.5), emits a gamma entry, returns success.

7. Application caches the mandate. On subsequent calls, it includes the
   mandate in its envelope (params._envelope.mandate per Ethos §11.6).
```

Step 5 is critical: the **client** computes the wrap, not the platform.
The platform never sees the CMK in clear. The new wrap is computed
during step 4's call preparation, alongside the mandate, by the user's
client unwrapping its own CMK (it holds a wrap addressed to its own
sphere key) and re-wrapping for the grantee.

## 4.6 Revocation

Revocation of a mandate follows Ethos §4.6 (revocation document), with
a data-specific consequence: the revoked grantee MUST be removed from
the collection's wrap list.

```
1. User signs a revocation document for the mandate.
2. User's client calls:
     aithos.data.revoke_app({
       collection_name,
       mandate_id,
       revocation,           // the signed revocation doc
       rotate_cmk: boolean   // optional, default false
     })

3. Platform:
   - verifies the revocation signature
   - removes the grantee's wrap from the collection's wrap list
   - publishes the revocation document (so other readers verifying
     the grantee's signatures detect the revocation)
   - if rotate_cmk: true, performs a CMK rotation per chapter 02 §2.5.2
   - emits a gamma entry data.collection.revoke_grantee
```

After revocation, the platform refuses to honor any envelope signed
under the revoked mandate. The grantee can no longer call any RPC for
the collection.

If `rotate_cmk: true`, the revoked grantee, even with cached copies of
the old CMK, cannot decrypt the records' new ciphertexts (each record's
DEK is re-wrapped under the new CMK, and each ciphertext is re-encrypted
with the freshly-wrapped DEK). The old CMK still decrypts the **prior**
ciphertexts the grantee may have cached during the mandate's validity.
This is the unavoidable forward-only nature of symmetric AEAD.

If `rotate_cmk: false`, revocation only enforces access at the platform
boundary. A cooperative platform refuses to serve the grantee; an
adversarial grantee with a back channel to the encrypted bytes (e.g.
via a backup of past responses) retains decryption capability for those
specific bytes.

> **Decision (revisable):** The default behavior of `revoke_app` is
> `rotate_cmk: false` for cost reasons (O(N) re-encrypt). Subjects
> handling regulated data declare `forward_secrecy: "strict"` at
> collection creation, in which case revocation forces rotation
> automatically. See chapter 02 §2.3.6 and §2.5.2.

## 4.7 Mandate verification by the platform

On every authenticated call (`_envelope` with `mandate`), the platform
verifies in this order:

1. **Envelope signature** against the grantee's Ed25519 pubkey
   advertised in the mandate (`mandate.grantee.pubkey`).
2. **Envelope freshness** — `_envelope.iat` and `_envelope.exp` are
   within tolerance; `_envelope.nonce` not in the replay cache.
3. **Mandate signature** against the subject's DID document.
4. **Mandate time window** — `not_before <= now <= not_after`.
5. **Mandate revocation** — no revocation document published for
   `mandate.id`.
6. **Mandate scope** — at least one scope in `mandate.scopes` covers
   the called method + collection.
7. **Filter enforcement** (§4.3) — for filtered scopes, the operation's
   target record (for reads) or proposed state (for writes) is within
   the filter.
8. **Rate limit** — enforced per `mandate.constraints.rate_limit`.

A failure at any step short-circuits to a JSON-RPC error per
Ethos §10.9 / §11.7. Specifically, scope failures return
`AITHOS_INSUFFICIENT_SCOPE` and filter failures return
`AITHOS_DATA_FILTER_VIOLATION`.

## 4.8 Inter-app delegation (deferred)

A common pattern in OAuth is for an application to receive a token and
re-delegate a narrower token to a sub-component. In Aithos, this would
correspond to a grantee holding a mandate and issuing a downstream
mandate to another grantee.

v0.1 of this sub-protocol does NOT support inter-app delegation. Only
the subject (the owner) can issue mandates. An application that needs
to grant access to a downstream system must request the subject to
issue the downstream mandate directly.

A future version MAY add a `data.<col>.delegate` scope that allows the
holder to issue downstream mandates within their own scope envelope.

---

Next: [chapter 05 — API primitives](./05-api-primitives.md).
