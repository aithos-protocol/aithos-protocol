# Draft · Sponsorship Mandate v0.1 — commercial sponsorship between Ethos

> **Status:** Draft. Source of truth for the v0.1 sponsorship mechanism. Not yet normative. Promotion target: a new chapter `spec/13-sponsorship.md` on release, with cross-references added to §4 (mandates), §10 (platform primitives), §11 (signed envelopes), and §10-gamma (anchoring V2).
>
> **Scope.** This draft adds a new commercial primitive to the protocol: a signed, persistent declaration by one subject (the **sponsor**) that it will absorb the cost of platform operations invoked by other subjects (the **consumers**), within explicit budget and scope constraints. Verification, accounting, and dispute resolution rely on a designated **accounting authority** — itself a subject — that signs per-debit **consumption receipts**.
>
> **Non-goals.** This draft does NOT introduce a currency, a settlement mechanism, a token, or any consensus layer. The `unit` field of a sponsorship is uninterpreted by the protocol; authorities choose which units they support. There is no peer-to-peer payment primitive in v0.1.

## Motivation

The protocol up to v0.3 is purely identity-and-authorization: subjects, ethos, mandates, signed envelopes. Cost is a side-channel implementation detail outside the spec. This is intentional and the current draft preserves that posture for *peer* interactions.

However, a class of real-world interaction — a developer offering free or partially-free access to a service powered by platform compute, before the consumer commits to paying — cannot be expressed without a structural concept of **who absorbs the cost of an operation**. Today, implementations bolt on bespoke BFFs (a Lambda per app, hardcoded caps, no portability, no audit trail visible to the consumer). The protocol gains nothing from this; consumers gain no portable proof; auditors gain no signed trail.

The v0.1 sponsorship mandate formalizes the act of *one subject promising to fund another subject's operations* as a first-class signed artifact. It does not introduce any new cryptographic primitive: it composes existing signatures, mandates, and envelopes.

Three properties motivate doing this at the protocol layer rather than as infrastructure:

- **Portability.** Any conformant authority can honor a sponsorship signed by any sponsor, regardless of which Aithos host hosts either party. The sponsorship is not bound to a particular vendor.
- **Auditability.** Each debit produces a signed receipt that survives outside the authority's database. A consumer can later prove what they consumed; a sponsor can later prove what they paid for; an auditor can verify both without trusting the authority's recall.
- **Composition.** A sponsorship is just another signed object alongside ethos editions, mandates, and gamma entries. It can be referenced, revoked, and anchored to gamma logs using the existing primitives.

## Reference use case

A developer (call her **Dev**) publishes an Aithos application identified by `did:aithos:dev-app-X`. The application calls platform compute (e.g. `aithos.compute_invoke`) to deliver value to end users. Dev wants to let new users try the application *for free* before they decide to top up their own wallet.

Without a sponsorship primitive, Dev's only options today are:

1. Run a custom BFF that re-signs calls under her own identity, accepting whatever spoofing risk and hard-coded caps that entails, and re-implementing the verification logic that the platform already performs (current state — `builder-bedrock-proxy`).
2. Manually top up each new user's wallet via ops, which doesn't scale and gives Dev no control over how the credit is spent.

With v0.1 sponsorship, Dev publishes a `SponsorshipMandate` declaring "I will absorb up to 2000 mc per consumer, up to 50000 mc per day, total pool 100000 mc, only for the model `claude-haiku-4-5`, only for the method `aithos.compute_invoke`, only for envelopes invoking `did:aithos:dev-app-X`." She tops up her wallet on the chosen authority (V1: `compute.aithos.be`). When any consumer invokes her app, the authority routes the debit to Dev's pool transparently, signs a consumption receipt, and the consumer is never aware they consumed sponsored credit.

When Dev's pool is empty, or a per-user cap is reached, the authority falls back to debiting the consumer's own wallet. If the consumer has no wallet balance either, the call returns the standard `insufficient_balance` error already specified in §10.

## 13.1 Vocabulary

- **Sponsor** — A subject (`did:aithos:…`) that has signed and published one or more `SponsorshipMandate`s. The sponsor commits its own wallet balance to fund operations performed by other subjects within the bounds of those mandates.
- **Consumer** — A subject whose signed envelope triggers an operation. In a sponsored call, the consumer is the `iss` of the envelope; the sponsor is *not* the `iss`. The consumer remains the cryptographic author of the operation.
- **Accounting authority** — A subject (also `did:aithos:…`) that holds the canonical mutable state for one or more sponsorships: the sponsor's wallet balance, the per-consumer consumption ledger, and the per-day pool counter. The authority signs every debit as a `ConsumptionReceipt`. An authority MAY serve many sponsorships from many sponsors.
- **Sponsorship pool** — The sponsor's wallet balance, scoped to a single sponsorship if the sponsor wishes (one wallet per sponsorship) or shared across multiple of their own sponsorships. V1 specifies the shared model: one sponsor wallet per `(sponsor_did, authority_did)` pair.
- **Sponsored call** — A signed envelope from a consumer that the authority elects to fund from a sponsor's pool, having verified the sponsor's `SponsorshipMandate` is active, scoped to the requested method, and not exhausted for that consumer.
- **Fallback** — When a sponsorship cannot cover a call (mandate not found, depleted, cap reached, scope mismatch, etc.), the authority MUST attempt to debit the consumer's own wallet. If neither is available, the standard insufficient-balance error is returned.

## 13.2 Three-party trust model

A sponsored call involves three signed parties:

```
       SponsorshipMandate (signed by sponsor)
   ┌───────────────────────────────────────────┐
   │ sponsor_did → audience, budget, authority │
   └───────────────────────────────────────────┘
           │
           │ resolved by authority on each call
           ▼
   ┌──────────────────────────────┐    Envelope (signed by consumer)
   │   Accounting Authority       │ ◀──────────────────────────────────
   │   (subject did:aithos:…)     │   { iss: consumer, method, aud }
   │                              │
   │   - Holds sponsor wallet     │
   │   - Holds consumption ledger │
   │   - Signs ConsumptionReceipt │ ──────────────────────────────────▶
   └──────────────────────────────┘   ConsumptionReceipt (signed by authority)
                                      → archived; later anchorable
                                        in sponsor's and consumer's
                                        gamma logs (V2)
```

Three cryptographic acts compose a sponsored call:

1. The sponsor's signature on the `SponsorshipMandate`, fixing the rules.
2. The consumer's signature on the `Envelope`, fixing the operation and its author.
3. The authority's signature on the `ConsumptionReceipt`, fixing the debit and binding the two above.

No party can unilaterally rewrite history. The sponsor cannot deny having authorized the rules (signed mandate). The consumer cannot deny having triggered the operation (signed envelope). The authority cannot inflate the debit or invent debits without producing a forgery on its own key.

A failure mode the v0.1 design accepts: the authority is trusted to *correctly meter* the operation (i.e. estimate `amount` truthfully). The receipt commits the authority to a number, but the protocol does not yet provide a way for the sponsor or consumer to independently audit the underlying cost. V0.2 may add a `cost_attestation` carrying the authority's own pricing model and the input metrics; v0.1 leaves this to operational trust.

## 13.3 The SponsorshipMandate object

The sponsorship mandate is a JSON object signed by the sponsor's sphere key (conventionally `#public`, since the mandate is publicly resolvable). It is canonicalized per RFC-8785 (JCS) before hashing.

### 13.3.1 Grammar

```jsonc
{
  "aithos-sponsorship-mandate": "0.1.0",
  "id": "spons_01J7…",
  "issuer": "did:aithos:dev-app-X",
  "issued_by_key": "did:aithos:dev-app-X#public",
  "audience": {
    "app_did": "did:aithos:dev-app-X",
    "audience_set": "open"
  },
  "scopes": ["compute.invoke"],
  "allowed_methods": ["aithos.compute_invoke"],
  "allowed_models": ["claude-haiku-4-5"],
  "budget": {
    "unit": "aithos.mc",
    "per_user_cap": 2000,
    "per_user_window_seconds": null,
    "per_day_total_cap": 50000,
    "pool_cap_total": 100000
  },
  "accounting_authority": {
    "did": "did:aithos:compute-authority-v1",
    "endpoint": "https://compute.aithos.be"
  },
  "not_before": "2026-05-27T00:00:00Z",
  "not_after": "2027-05-27T00:00:00Z",
  "issued_at": "2026-05-27T00:00:00Z",
  "nonce": "k9eFhX2vQ0r5ZsP8t1u7yA",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:dev-app-X#public",
    "value": "base64url(…)"
  }
}
```

### 13.3.2 Required fields

| Field | Type | Constraints |
|---|---|---|
| `aithos-sponsorship-mandate` | string | Exactly `"0.1.0"` for this draft. |
| `id` | string | Stable identifier, format `spons_<ULID>`. Unique per issuer. |
| `issuer` | string | DID of the sponsor (the subject whose wallet will be debited). |
| `issued_by_key` | string | DID URL of the sphere key that signed. MUST be a sphere of `issuer`. Convention is `#public` since the mandate is publicly resolvable. |
| `audience` | object | See §13.3.3. |
| `scopes` | array of strings | Subset of the platform scope vocabulary (§4.3). At least one entry. |
| `allowed_methods` | array of strings | RPC method names the sponsorship covers. At least one entry. The mandate authorizes the debit only when the envelope's `method` is in this list. |
| `budget` | object | See §13.3.4. |
| `accounting_authority` | object | See §13.3.5. |
| `not_before`, `not_after` | string | RFC-3339, with `not_after > not_before`. Outside this window, the mandate is inactive. |
| `issued_at` | string | RFC-3339. |
| `nonce` | string | At least 48 bits of entropy, base64url. |
| `signature` | object | Ed25519 signature over the JCS canonical bytes of the mandate with `signature.value` cleared. Same envelope as §11 signatures. |

### 13.3.3 The `audience` object

Defines which envelopes the sponsorship may cover.

| Field | Type | Semantics |
|---|---|---|
| `app_did` | string (DID) | The application DID that envelopes must target. The authority matches this against the envelope's `app_did` field (or the equivalent app-scoping mechanism in §10). |
| `audience_set` | string | One of `"open"`, `"list"`. With `"open"`, any consumer's envelope targeting `app_did` is eligible (subject to caps). With `"list"`, only consumers whose DID is in the explicit `consumers` list below. |
| `consumers` | array of strings (DIDs) | REQUIRED iff `audience_set == "list"`. Each entry is a consumer DID eligible for the sponsorship. |

Future versions may add `audience_set: "credential"` (eligible to subjects holding a specific verifiable credential, e.g. employees of a company) — out of scope for v0.1.

### 13.3.4 The `budget` object

Defines the spending limits the authority MUST enforce.

| Field | Type | Semantics |
|---|---|---|
| `unit` | string | Authority-interpreted unit of account. The reserved value `"aithos.mc"` denotes the platform microcredit (1 mc ≡ €0.001 of pass-through cost, per the Aithos pricing model). Other values are permitted; authorities MAY reject mandates with units they do not interpret. |
| `per_user_cap` | integer | Lifetime cumulative cap, in `unit`, applied per consumer. Hard ceiling — once a consumer's `consumed_lifetime` exceeds this value, the authority MUST fall back. |
| `per_user_window_seconds` | integer or null | If non-null, the `per_user_cap` is enforced over a sliding window of this duration. If null, the cap is lifetime. |
| `per_day_total_cap` | integer | UTC-day cap on total sponsored consumption across all consumers. The authority MUST reset this counter at 00:00 UTC. |
| `pool_cap_total` | integer or null | Lifetime cap across all consumers, all days. Once reached, the sponsorship transitions to status `"depleted"` and stays that way until the sponsor publishes a new mandate or tops up against an unbounded pool. May be null (no lifetime cap; only the wallet balance limits). |

The authority enforces ALL caps that apply. The first cap to be exceeded triggers the fallback.

### 13.3.5 The `accounting_authority` object

Identifies the subject that will hold the mutable state for this sponsorship and sign consumption receipts.

| Field | Type | Semantics |
|---|---|---|
| `did` | string (DID) | The authority's stable DID. The authority's signing key is resolved from its DID document, exactly like any other subject (§1). |
| `endpoint` | string (URL) | The authority's HTTP endpoint that accepts envelopes covered by this mandate. Informational; the protocol does not mandate that this be the only endpoint the authority operates. |

A sponsor MAY designate the same authority across multiple sponsorships (typical), or different authorities (rare; useful for region-scoped or fallback configurations).

The authority MUST be a subject in good standing. The relationship between sponsor and authority is one of *delegation of accounting* — the sponsor trusts the authority to debit its wallet truthfully, to keep the ledger atomically, and to sign each debit. The sponsor does NOT delegate any signing capability *on its own DID* to the authority. The authority signs receipts on its own DID; the sponsor's signature appears only on the mandate.

### 13.3.6 Where the mandate is published

The sponsor publishes its sponsorship mandates at well-known URLs under its canonical ethos host:

```
https://<ethos-host>/ethos/<sponsor-did>/sponsorships/<sponsorship-id>.json
https://<ethos-host>/ethos/<sponsor-did>/sponsorships/index.json
https://<ethos-host>/ethos/<sponsor-did>/sponsorships/revocations.json
```

- `<id>.json` returns the signed sponsorship mandate exactly as defined in §13.3.1.
- `index.json` returns a signed list of active sponsorship IDs (format mirrors §4.6.4 for revocations).
- `revocations.json` is the standard §4.6 revocation list, scoped to sponsorship mandates.

An authority MUST be able to fetch and verify mandates from these endpoints. An authority MAY cache mandates aggressively; sponsors SHOULD include short HTTP cache headers and SHOULD honor `If-None-Match` if updating.

### 13.3.7 Hash and signature computation

Identical mechanism to §4.7:

1. Set `signature.value = ""`.
2. Canonicalize per RFC-8785 (JCS).
3. Sign the canonical bytes with the Ed25519 private half of `issued_by_key`.
4. Set `signature.value` to the resulting base64url signature.

A verifier computes `mandate.hash = "sha256:" + hex(sha256(jcs(mandate_with_signature_blank)))` if it needs to commit to a specific mandate in another object (e.g. an envelope referencing it, §13.6).

## 13.4 The accounting authority as a subject

An accounting authority is a regular Aithos subject. It has:

- A root DID and identifier (e.g. `did:aithos:compute-authority-v1`).
- Three sphere keys (`#public`, `#circle`, `#self`) declared in its DID document.
- A canonical ethos host where its DID document and authority declarations are published.

This is intentional: the authority's signatures are verifiable by every existing Aithos client using the existing DID resolution and §11 envelope verification logic. No new cryptographic mechanism is introduced.

### 13.4.1 Two-level declaration

A sponsor's commitment to a given authority is expressed at two levels of strength:

**Level 1 — Implicit, per-mandate.** Every `SponsorshipMandate` carries `accounting_authority.did`. By signing the mandate, the sponsor implicitly commits to this authority for the scope of that mandate. This is REQUIRED.

**Level 2 — Explicit, in the sponsor's ethos.** The sponsor MAY publish, in the public zone of its ethos bundle, a section declaring the authorities it considers legitimate:

```yaml
# In the public zone of the sponsor's ethos
authorities:
  accounting:
    - did: did:aithos:compute-authority-v1
      endpoint: https://compute.aithos.be
      scopes: ["compute.invoke", "compute.url_fetch"]
      since: "2026-05-27"
```

Level 2 is OPTIONAL for v0.1, but RECOMMENDED for sponsorships exceeding some implementation-defined threshold (e.g. mandates with `pool_cap_total > 100000`). It provides defense-in-depth: a tampered or coerced mandate can be cross-checked against the sponsor's public attestation.

A verifier checking a sponsored call MAY consult Level 2. The protocol does not REQUIRE this check; authorities MAY consult it as an anti-fraud heuristic.

### 13.4.2 Authority obligations

An authority that accepts a sponsorship mandate (i.e. routes a debit to its pool) MUST:

1. Maintain the sponsor's wallet balance atomically (no double-spend, no debit beyond zero).
2. Maintain the per-consumer consumption ledger atomically (writes never lost, never duplicated across concurrent debits for the same consumer).
3. Maintain the per-day pool counter, resetting at 00:00 UTC.
4. Sign a `ConsumptionReceipt` (§13.5) for every successful debit.
5. Make receipts queryable to the sponsor (for accounting) and the consumer (for audit). The protocol does not mandate a specific query API; §13.5.4 sketches the V1 endpoint.
6. Honor revocations: once a mandate's ID appears in the sponsor's `revocations.json`, the authority MUST stop debiting from that pool for any subsequent envelope. In-flight envelopes already accepted MAY complete.
7. Honor the `not_before` / `not_after` window.

An authority MAY:

- Refuse to honor a mandate whose `unit` it does not interpret (returning a clear error to the consumer, which then triggers fallback).
- Refuse to host new mandates from a particular sponsor (operational policy).
- Charge the sponsor a hosting fee at top-up time (outside the protocol; the wallet balance is denominated in `unit` after the authority's fee is deducted).

### 13.4.3 Authority identity persistence

An authority SHOULD use a stable DID for its lifetime. Migration to a new DID (e.g. for cryptographic agility) SHOULD be coordinated with all sponsors that have designated it; sponsors MUST publish new mandates with the new authority DID for continued sponsorship. The protocol does not specify a migration ceremony; this is V0.2+ work.

## 13.5 The ConsumptionReceipt object

The receipt is a JSON object signed by the authority on every successful debit (sponsored or fallback).

### 13.5.1 Grammar

```jsonc
{
  "aithos-consumption-receipt": "0.1.0",
  "id": "rcpt_01J7…",
  "sponsorship_id": "spons_01J7…",
  "sponsorship_hash": "sha256:b2c4…",
  "sponsor_did": "did:aithos:dev-app-X",
  "consumer_did": "did:aithos:user-Y",
  "app_did": "did:aithos:dev-app-X",
  "method": "aithos.compute_invoke",
  "envelope_nonce": "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
  "envelope_hash": "sha256:e5a1…",
  "funded_by": "sponsored",
  "amount": 47,
  "unit": "aithos.mc",
  "ledger_after": {
    "user_consumed_lifetime": 1234,
    "user_consumed_window": null,
    "user_cap_remaining": 766,
    "pool_consumed_lifetime": 12500,
    "pool_consumed_today": 4823
  },
  "timestamp": "2026-05-27T14:32:11.123Z",
  "issued_by": "did:aithos:compute-authority-v1",
  "issued_by_key": "did:aithos:compute-authority-v1#public",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:compute-authority-v1#public",
    "value": "base64url(…)"
  }
}
```

### 13.5.2 Field semantics

| Field | Type | Semantics |
|---|---|---|
| `aithos-consumption-receipt` | string | Exactly `"0.1.0"`. |
| `id` | string | Stable identifier, format `rcpt_<ULID>`. Unique within an authority. |
| `sponsorship_id` | string or null | The sponsorship mandate's `id` if `funded_by == "sponsored"`. NULL for fallback debits. |
| `sponsorship_hash` | string or null | SHA-256 of the sponsorship mandate that authorized this debit. Binds the receipt to a specific mandate version, defeating retroactive mandate edits. NULL when `sponsorship_id` is null. |
| `sponsor_did` | string or null | The sponsor of this debit, if sponsored. NULL for fallback. |
| `consumer_did` | string | The DID of the envelope's `iss`. Authoritative — the consumer cannot deny having triggered the operation. |
| `app_did` | string | The application DID the envelope targeted. |
| `method` | string | The RPC method invoked (e.g. `aithos.compute_invoke`). |
| `envelope_nonce` | string | The nonce of the triggering envelope. Pairs the receipt to a specific call. |
| `envelope_hash` | string | SHA-256 of the canonical envelope bytes. Stronger pairing — survives any cache where nonces could be reused (they MUST NOT, per §11, but the hash is a belt-and-braces commitment). |
| `funded_by` | string | One of `"sponsored"`, `"purchase"`, `"grant"`. See §13.8. |
| `amount` | integer | Debit amount in `unit`. Strictly positive. |
| `unit` | string | Same as the sponsorship's `budget.unit` for sponsored debits; the authority's chosen unit for fallback debits. |
| `ledger_after` | object | Optional but RECOMMENDED. Snapshot of relevant counters after the debit. |
| `timestamp` | string | RFC-3339 with millisecond precision. Authority's wall clock at debit. |
| `issued_by` | string (DID) | The authority's DID. |
| `issued_by_key` | string (DID URL) | The authority's sphere key DID URL used for signing. |
| `signature` | object | Ed25519 over the JCS canonical bytes of the receipt with `signature.value` cleared. |

### 13.5.3 When the receipt is emitted

The authority emits a receipt **after** a successful platform operation has been observed (e.g. Bedrock returned a non-error response). If the operation fails after the wallet has been debited, the authority MUST refund and either:

- Emit a corrective receipt with negative `amount` and `id` referencing the original (V0.2), OR
- Not emit the receipt at all (V0.1 — refund silently; consumer sees only the final outcome).

V0.1 specifies the "do not emit" path for simplicity. The authority MUST guarantee no orphan debit exists: if a receipt is emitted, the corresponding amount stayed debited.

### 13.5.4 Storage and retrieval

V0.1 storage: the authority archives every receipt in its own store, queryable via a simple HTTP API at the authority's endpoint:

```
GET /v1/receipts?sponsor=<did>&consumer=<did>&since=<rfc3339>&limit=<n>
  → 200 { "receipts": [<ConsumptionReceipt>, …], "next": "<cursor>" }
```

Authenticated by an envelope from either the sponsor or the consumer querying their own slice. A receipt is NEVER queryable by an unrelated subject in V0.1.

V0.2 anchoring (planned, see §13.10): the authority, granted `gamma.write` mandates by the sponsor and the consumer respectively, publishes each receipt as a gamma entry in *both* parties' gamma logs. The receipt becomes inviolable and portable without dependency on the authority's storage. Until v0.2 lands, the authority's archive is the source of truth.

## 13.6 Envelope changes

A signed envelope (§11) MAY carry an optional `sponsorship` field that hints at which sponsorship the consumer expects to be applied.

### 13.6.1 New optional field

```jsonc
{
  "aithos-envelope": "0.1.0",
  "iss": "did:aithos:user-Y",
  "aud": "https://compute.aithos.be/v1/invoke",
  "method": "aithos.compute_invoke",
  "iat": 1748359200,
  "exp": 1748359500,
  "nonce": "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
  "params_hash": "sha256-…",
  "mandate": null,
  "sponsorship": {
    "id": "spons_01J7…",
    "hash": "sha256:b2c4…"
  },
  "proof": { … }
}
```

The `sponsorship` field is OPTIONAL. When absent, the authority MAY autodiscover a matching sponsorship (e.g. by looking up sponsorships published by `app_did`'s sponsor for the requested method). When present, the authority MUST use the indicated sponsorship if eligible, otherwise fall back.

### 13.6.2 Effect on verification

The §11 envelope verification flow is unchanged. After verifying signature, scope, mandate (if any), and freshness, the authority performs the additional sponsorship resolution step described in §13.7.

### 13.6.3 Anti-spoof

The consumer cannot forge the sponsor's signature on the mandate, so the consumer cannot fabricate a sponsorship that does not exist. The consumer cannot rewrite the mandate's caps either: the `sponsorship.hash` in the envelope (when present) pins to a specific signed version; the authority recomputes the hash and rejects on mismatch.

## 13.7 Server-side verification flow

Pseudocode for the authority's processing of an incoming envelope:

```text
1. Verify envelope per §11 (signature, freshness, mandate if delegated, scope).
2. Determine candidate sponsorship:
   a. If envelope carries `sponsorship.id`, fetch that mandate (cached or via §13.3.6 URLs).
   b. Else, query the authority's sponsorship index for active mandates where
      `audience.app_did == envelope.app_did` AND `envelope.iss` is eligible per
      audience_set rules AND `method` ∈ allowed_methods AND `not_before ≤ now ≤ not_after`.
   c. If multiple candidates, the authority picks per its own deterministic policy
      (V0.1: most-recently-issued).
3. If a candidate sponsorship exists, run eligibility checks in order:
   a. mandate is not revoked.
   b. envelope.method ∈ sponsorship.allowed_methods.
   c. resolved model (from params, if applicable) ∈ sponsorship.allowed_models.
   d. envelope.iss ∈ sponsorship.audience.consumers, if audience_set == "list".
   e. ledger[sponsorship.id, envelope.iss].consumed_lifetime + estimate ≤ per_user_cap.
   f. (if per_user_window_seconds) ledger[…].consumed_window + estimate ≤ per_user_cap
      within the current sliding window.
   g. day_counter[sponsorship.id, today_utc].consumed + estimate ≤ per_day_total_cap.
   h. pool_counter[sponsorship.id].consumed_lifetime + estimate ≤ pool_cap_total
      (if pool_cap_total is non-null).
   i. wallet[sponsor.did].balance ≥ estimate.
4. If all checks pass: payer = sponsor.did, funded_by = "sponsored".
   Else: payer = consumer.did (envelope.iss), funded_by = "purchase" (or "grant", per §13.8).
5. Reserve `estimate` from wallet[payer]. (Atomic decrement.)
6. Execute the underlying operation (e.g. Bedrock invocation).
7. On success:
   a. Reconcile: refund (estimate - actual_cost) to wallet[payer] if estimate > actual.
   b. Update ledger and counters atomically.
   c. Sign and archive a ConsumptionReceipt (§13.5).
   d. Append the receipt to the audit log (§10 platform audit, with funded_by).
   e. Return the response with the receipt id and funded_by in the SDK metadata.
8. On failure:
   a. Refund the full estimate to wallet[payer].
   b. Do not emit a receipt (V0.1) or emit a negative-amount receipt (V0.2+).
   c. Return the operation error to the caller.
9. If step 5 fails (insufficient_balance on the chosen payer):
   a. If payer == sponsor.did, retry from step 4 with payer = consumer.did.
   b. If payer == consumer.did, return insufficient_balance (-32071) to the caller.
```

The atomicity in steps 5 and 7 is per-payer-wallet: the implementation MUST guarantee that no two concurrent envelopes targeting the same payer can both reserve more than the available balance. The implementation primitive is DDB ConditionExpression or equivalent in V0.1.

## 13.8 Routing decision and `funded_by`

The receipt's `funded_by` field communicates which wallet was actually debited, regardless of whether the sponsorship was attempted first.

| Value | Meaning |
|---|---|
| `"sponsored"` | The sponsor's wallet was debited, against an eligible sponsorship. `sponsor_did` and `sponsorship_id` are populated. |
| `"purchase"` | The consumer's own wallet was debited. `sponsor_did` and `sponsorship_id` are NULL. |
| `"grant"` | The consumer's *grant* bucket was debited (a credit Aithos previously gave the consumer, e.g. a free-trial top-up). `sponsor_did` and `sponsorship_id` are NULL. |

The grant bucket is the consumer's `balance_grant` from the Phase B wallet model. It is debited *before* the purchase bucket (V0.1 keeps the existing rule). The relevant decision tree, end-to-end:

```
1. Try sponsor wallet via SponsorshipMandate.   → funded_by = "sponsored"
2. Else try consumer's grant bucket.             → funded_by = "grant"
3. Else try consumer's purchase bucket.          → funded_by = "purchase"
4. Else return insufficient_balance (-32071).
```

Importantly, this is the **only** behavior in v0.1. There is no opt-in to block on sponsorship depletion. If the sponsor declines to subsidize the call (depleted, capped, scope mismatch), the consumer is offered the chance to pay before being refused. This was an explicit design decision: a consumer that is willing and able to pay must not be artificially blocked by the sponsor's pool exhaustion.

A future v0.2 may introduce a `block_on_depletion` flag, but only with a strong use case justifying the additional complexity.

## 13.9 Revocation

The §4.6 revocation mechanism applies unchanged. A sponsor revoking a sponsorship publishes:

```jsonc
{
  "aithos-revocation": "0.1.0",
  "mandate_id": "spons_01J7…",
  "mandate_kind": "sponsorship-mandate",
  "revoked_at": "2026-06-15T12:00:00Z",
  "reason": "superseded",
  "signature": { … }
}
```

The `mandate_kind` field is a new addition recommended for v0.1 (existing revocations target action mandates implicitly; this field disambiguates). Authorities MUST consult the sponsor's `revocations.json` before authorizing a sponsored debit and MUST reject debits citing a revoked sponsorship.

Revocation is forward-only: receipts issued before `revoked_at` remain valid and the sponsor's debit is final. A sponsor cannot retroactively reverse charges via revocation.

## 13.10 Interaction with existing protocol layers

### 13.10.1 With action mandates (§4)

Sponsorship mandates are orthogonal to action mandates. A consumer's envelope MAY be signed by a delegate operating under an action mandate (§11.6); the sponsorship mandate then funds the call regardless of whether the consumer signed directly or via delegation. The protocol does NOT require the action mandate's `grantee` to match anything in the sponsorship's `audience`.

A consumer's action mandate is about *what the delegate may do on the consumer's behalf*. A sponsorship is about *who pays for what the consumer does*. They compose freely.

### 13.10.2 With platform primitives (§10)

The platform compute primitives (`aithos.compute_invoke` and siblings) are the V0.1 reference target. The mechanism is generic, however: any platform method whose scope appears in a sponsorship's `scopes` can be sponsored. A v0.2 may extend to `aithos.compute_url_fetch`, `aithos.data_*`, or future methods, without spec changes — the sponsorship grammar already allows arbitrary method names in `allowed_methods`.

### 13.10.3 With signed envelopes (§11)

§11 verifies authorship. §13 adds funding routing. The two are sequential: envelope verification first (authorship is settled), then sponsorship resolution (funding is settled). A failure in §11 short-circuits §13.

### 13.10.4 With gamma anchoring (§10-gamma)

V0.1 stores receipts only at the authority. V0.2 plans to anchor receipts in both parties' gamma logs:

1. At sponsorship creation, the sponsor optionally signs a `gamma.write` mandate to the authority's DID, scoped narrowly (e.g. `gamma.write.public` with a content tag `aithos.consumption-receipt`).
2. Similarly, the consumer signs a `gamma.write` mandate to the authority on first consent (V0.2 introduces a `SponsorshipAcceptance` for this purpose).
3. On each debit, the authority appends a gamma entry containing the receipt to *each* party's log (using §10-gamma per-entry envelopes from the v0.3 draft, sealing the entry key to the relevant subject's `#public` X25519 key).
4. Result: both parties hold cryptographic, append-only proof of each debit, independent of the authority's archive.

This requires:
- The `gamma.read` and `gamma.write` scopes from the v0.3 gamma draft.
- A new `SponsorshipAcceptance` object (V0.2) that the consumer signs at first sponsored call. The acceptance grants `gamma.write` to the authority for receipt anchoring and serves as opt-in evidence (useful for ToS compliance).

V0.2 is out of scope for this draft beyond noting that the v0.1 schema is forward-compatible: a future `acceptance_id` or `anchor_targets` field can be added without breaking v0.1 verifiers.

## 13.11 Threat model

Attack surface against the v0.1 design, with mitigations.

| Threat | Mitigation |
|---|---|
| A consumer tampers with a local copy of a sponsorship to widen its caps. | The envelope's `sponsorship.hash` pins the mandate version. The authority recomputes the hash from its own canonical copy and rejects on mismatch. |
| A consumer modifies their local consumption counter to bypass the per-user cap. | The counter lives at the authority, never on the consumer's device. The consumer's local view is informational, not authoritative. |
| A consumer replays an old envelope to consume twice. | Envelope nonces are unique per `(iss, iat)` per §11. Replay attempts fail. |
| A consumer impersonates another consumer to consume their quota. | The envelope's `iss` is derived from the signing key; Ed25519 prevents impersonation. |
| A consumer fabricates a sponsorship mandate granting themselves a huge quota. | The mandate must be signed by the sponsor's sphere key; forgery is computationally infeasible. |
| A consumer fetches a sponsorship that the sponsor has since revoked. | The authority consults `revocations.json` before authorizing a debit; revoked mandates are rejected. |
| A consumer routes the same envelope to two authorities to double-spend the sponsorship. | The `accounting_authority.did` in the mandate designates a SINGLE authority as the ledger of record. Other authorities receiving the envelope MUST refuse (cite mandate's chosen authority) or, in V0.2, forward to the chosen authority. V0.1 mandates that only the chosen authority debit. |
| A malicious authority debits the sponsor without producing a corresponding operation. | Each debit produces a signed receipt referencing `envelope_hash`; a debit without a matching envelope is a forgery on the authority's key and is detectable by the sponsor. The sponsor MAY periodically query its receipts and verify each one against a known envelope. |
| A malicious authority inflates `amount` beyond actual cost. | V0.1 trusts the authority to meter correctly. Mitigation deferred to V0.2 (`cost_attestation` field carrying authority's pricing model and input metrics). Sponsors choose authorities they trust; reputational/contractual recourse outside the protocol. |
| A consumer creates a new DID to reset their per-user cap. | OUT OF SCOPE — Sybil resistance is an identity-layer problem, not a sponsorship-layer problem. Mentioned for completeness. The protocol cannot prevent this; sponsors who care MUST gate their `audience_set` on credentials (V0.2 feature). |
| A sponsor publishes a malicious mandate designating an authority the sponsor does not actually trust. | The Level-2 declaration in the sponsor's ethos (§13.4.1) acts as cross-evidence. A high-stakes verifier MAY require Level 2; the protocol does not. |
| An authority's signing key is compromised. | All receipts signed during the compromise window are repudiable using the standard §4.6 key-rotation ceremony. The authority publishes a new DID document, sponsors revoke and re-issue mandates pointing to the new key. Affected receipts may need manual reconciliation; in-scope of operational policy, not protocol. |

## 13.12 Test matrix (spec-bound)

Every conformant v0.1 implementation MUST satisfy:

| Test | Assertion |
|---|---|
| T1 — Sponsored happy path | Sponsor publishes mandate; consumer invokes `app_did`; authority debits sponsor; receipt signed and queryable; consumer's wallet untouched; `funded_by = "sponsored"`. |
| T2 — Fallback on depleted pool | Sponsor's wallet is at 0 mc; consumer invokes; authority falls back to consumer wallet; receipt has `funded_by = "purchase"`; `sponsor_did = null`. |
| T3 — Fallback on per-user cap reached | Consumer has already consumed exactly `per_user_cap` of sponsorship; new call falls back; receipt `funded_by = "purchase"`. |
| T4 — Fallback on per-day cap reached | Pool has consumed `per_day_total_cap` today; new call falls back; T+1 day same call is again sponsored. |
| T5 — Fallback on scope mismatch | Consumer invokes a method not in `allowed_methods`; falls back to consumer wallet (since sponsorship doesn't apply at all). |
| T6 — Fallback on model mismatch | Consumer invokes with a model not in `allowed_models`; falls back. |
| T7 — Insufficient balance on both | Sponsor depleted AND consumer has no wallet balance; call returns `insufficient_balance` (-32071). |
| T8 — Revocation honored | Sponsor publishes revocation; subsequent call falls back (sponsorship is treated as absent). |
| T9 — Expiry honored | After `not_after`, sponsorship is treated as absent; fallback. |
| T10 — Hash mismatch rejected | Envelope carries `sponsorship.hash` that does not match authority's canonical copy; authority refuses to apply that sponsorship and falls back. |
| T11 — Audience list enforced | Mandate has `audience_set = "list"` with explicit consumers; non-listed consumer's call falls back. |
| T12 — Receipt signature verifiable | Any receipt's signature, when verified against the authority's DID document, MUST be valid; tampering with any byte of the receipt MUST invalidate. |
| T13 — Receipt query authentication | A query against `/v1/receipts` signed by an unrelated DID returns empty results (no leakage of receipts the caller is not party to). |
| T14 — Concurrent debits atomic | N concurrent envelopes from one consumer against an `allow_methods` operation: total debited never exceeds `per_user_cap`; no double-debit; no lost debit. |
| T15 — Mandate fetch fallback | If the authority cannot fetch the mandate from `<ethos-host>/ethos/<sponsor>/sponsorships/<id>.json` (404, timeout), it falls back to the consumer's wallet (does NOT block the call). |

Implementations SHOULD publish test vectors for T1–T15 alongside their release. Test data for T12 specifically MUST include a known-valid receipt and a known-tampered receipt, allowing third-party verification of the implementation's signature logic.

## 13.13 Open questions

- **Currency-unit registry.** v0.1 reserves `"aithos.mc"`. Should the protocol maintain a registry of well-known units (e.g. `"openai.input-tokens"`, `"fal.compute-seconds"`) or leave the namespace fully open? A registry adds central coordination; full openness risks ambiguity. Lean: full openness, with a recommended naming convention (`<provider>.<unit>`).
- **Acceptance signature by consumer.** v0.1 has no `SponsorshipAcceptance`; the consumer's signed envelope is the only consent signal. v0.2 may introduce an Acceptance for explicit ToS attestation. Open: is this necessary at all, or does the envelope's `sponsorship.id` reference (when present) suffice?
- **Multi-authority sponsorships.** A sponsor MAY want to designate a primary and a fallback authority. v0.1 supports one. Adding a `failover_authority` field is forward-compatible.
- **Cost attestation.** v0.1 trusts the authority's metering. v0.2 may add a `cost_attestation` field with the authority's pricing function and input metrics for a third party to verify `amount` is consistent with the authority's published pricing.
- **Sponsorship discovery.** When an envelope carries no `sponsorship` field, how does the authority discover candidate sponsorships? v0.1 assumes the authority maintains an internal index of sponsorships keyed on `(app_did, method)`. The protocol does not specify the discovery API; this is an authority implementation choice. Open: should there be a standard `GET /v1/sponsorships?app_did=…` discovery endpoint?
- **Receipt anchoring V2 mandate shape.** The exact scope and policy for the `gamma.write` mandate granting the authority anchor rights is left to the sponsorship-acceptance draft. Open: does the consumer grant `gamma.write.public` (visible to all) or `gamma.write.self` (private)? Public is auditor-friendly but exposes consumption patterns; self is private but harder to verify externally.
- **Top-up flow standardization.** The sponsor's wallet top-up is currently a side-channel (Stripe checkout). Should the protocol specify a `WalletTopUp` object for portable top-up evidence, or is this purely a hosting-provider concern? Lean: out of scope; let providers handle.
- **Sponsor-to-sponsor sponsorship.** Could a sponsor B sponsor a sponsor A's pool ("white-label sponsorship")? Conceptually yes — sponsor A is just another consumer from B's point of view. The grammar already supports this. Open: do we need to test for it, or is it implicitly covered?

---

## Sequencing of implementation

In `packages/protocol-core` (and consumers):

1. Introduce `SponsorshipMandate` TypeScript type and JSON validation in a new file `packages/protocol-core/src/sponsorship.ts`. Field-by-field per §13.3.
2. Add `ConsumptionReceipt` type, validator, hash helper, and signature verification in the same file.
3. Add an optional `sponsorship?: { id, hash }` field to the `SignedEnvelope` TypeScript type in `envelope.ts` (back-compat: absent on existing envelopes).
4. Add a `mandate_kind: "action" | "sponsorship-mandate"` field to revocation documents (default `"action"` if absent, for back-compat with existing v0.3 revocations).
5. Export the new types from `protocol-core` index.

In the platform / compute-proxy implementation:

6. Create DynamoDB tables (or equivalent backing stores) for sponsorship metadata, consumption ledger, day counters, and receipt archive. Schemas per §13.4.
7. Implement the authority-side eligibility flow per §13.7 between envelope verification and wallet debit.
8. Extend the existing `debitWallet(deps, userDid, amount)` to `debitWallet(deps, payerDid, amount)` so the same primitive serves both routing branches.
9. Extend the audit log (§10 audit) with `funded_by`, `sponsorship_id`, `sponsor_did`, and `receipt_id`.
10. Implement `/v1/receipts` query endpoint at the authority, with envelope-based authentication.
11. Adapt the existing `builder-bedrock-proxy` to be a no-op (or deprecated) once the eligibility path covers its capabilities — the BFF becomes redundant.

In the Aithos SDK:

12. Add a `AppsNamespace` to the SDK exposing `createSponsorship`, `updateSponsorship`, `pauseSponsorship`, `revokeSponsorship`, `getSponsorshipStatus`, `getSponsorshipStatusForUser`, `createAppTopupSession`.
13. Extend `InvokeBedrockResult` (back-compat) with `funded_by`, `receipt_id`, and `sponsored_remaining_for_user` informational fields.
14. Publish a minor-version bump of `@aithos/sdk` (e.g. `0.2.0`).

Conformance test vectors (per §13.12) ship in `spec/data/sponsorship-v0.1/` alongside the existing envelope and mandate vectors.

---

## Changelog

- 2026-05-27 — Initial draft (Mathieu + Claude, after discussion on app-sponsored compute originally drafted as infra plan `aithos-sdk/PLAN-APP-SPONSORED-COMPUTE.md`). Promotes the design from infrastructure layer to protocol layer.
