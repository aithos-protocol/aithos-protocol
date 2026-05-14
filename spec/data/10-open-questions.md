# 10 · Open questions

This chapter aggregates the decisions left unresolved in v0.1, the
alternatives considered, and the criteria that would drive resolution
in a future revision. It is **informative**, not normative.

## 10.1 Decisions marked revisable in this RFC

### 10.1.1 Dedicated `#data` sphere key vs reuse of `#circle`

**Chapter:** 02 §2.2.

**Choice in v0.1:** Introduce a new `#data` sphere key per DID document.

**Alternative:** Reuse `#circle` for backwards compatibility with
existing Aithos identities, avoiding a DID document modification.

**Criterion for revision:** Whether the operational benefit of
independent rotation outweighs the migration cost on existing
identities. Decide after observing rotation patterns in the wild.

### 10.1.2 DEK rotation on update

**Chapter:** 02 §2.5.1.

**Choice in v0.1:** DEK reuse with fresh nonce on every update. DEK
rotation is RECOMMENDED on schema migration only.

**Alternative:** Mandatory DEK rotation on every update for
defense-in-depth.

**Criterion for revision:** Discovery of a real-world attack that
benefits from DEK rotation more than the cost it adds. Unlikely.

### 10.1.3 CMK rotation on revoke

**Chapter:** 02 §2.3.6 / 04 §4.6.

**Choice in v0.1:** CMK rotation on revoke is OPTIONAL by default,
controlled by per-collection `forward_secrecy: "best_effort" | "strict"`
flag set at collection creation time.

**Alternative:** Always rotate on revoke (the costs become the default;
opt-out for users who prefer cheaper revocations).

**Criterion for revision:** Survey of how subjects actually use
revocation — if most revocations are precautionary (no real breach
suspected), keeping rotation optional is right. If most are reactive
(actual compromise), rotation should be the default.

### 10.1.4 Mandate filter expressiveness

**Chapter:** 04 §4.2.3 / 4.3.

**Choice in v0.1:** Single-field equality only
(`data.contacts.read.status:lead`).

**Alternatives:**
- Multi-field conjunctions (`status:lead AND geo:fr`).
- Range filters (`created_at >= 2026-01-01`).
- Set-membership (`status IN (lead, contact)`).

**Criterion for revision:** Concrete use cases where single-field
equality is insufficient. The most common one likely to drive change is
"agent X may only access records modified after timestamp T" — range
on `modified_at`.

### 10.1.5 Cryptographic filter enforcement

**Chapter:** 04 §4.3.1 / 09 §9.7.

**Choice in v0.1:** Filter mandates are platform-enforced, not
cryptographically. A hostile platform can bypass the filter.

**Alternatives:**
- Sub-collection key derivation: derive a sub-CMK per filter value
  (e.g. one CMK for `status:lead` records, another for `status:won`).
  Adds complexity, fragments storage, but offers cryptographic
  enforcement.
- ABE (Attribute-Based Encryption): records encrypted under policies,
  not keys. Strong cryptographic enforcement, but ABE is academic and
  deployment-immature.

**Criterion for revision:** Demand from subjects who genuinely do not
trust the platform's filter enforcement. Currently this profile is
covered by "use full-collection mandates with single-tenant deployments
on a platform you control."

### 10.1.6 Cursor format

**Chapter:** 06 §6.3.

**Choice in v0.1:** Opaque cursor encoded by the platform, encoding the
filter and position. Platform-MACed optionally.

**Alternative:** Stable cursor based on `record_id` alone, exposing the
ULID as the cursor.

**Criterion for revision:** Whether opaque cursors create migration
problems when changing storage backends. Stable record-id cursors would
be more portable but constrain backend design.

## 10.2 Decisions deferred (explicitly out of scope for v0.1)

### 10.2.1 Inter-app mandate delegation

A grantee holding a mandate cannot issue downstream mandates to other
grantees. v0.1 keeps mandate issuance centralized at the subject.

**When to revisit:** When a credible use case appears for chained
delegation (e.g. "an agent platform that orchestrates sub-agents under
my mandate"). The scope `data.<col>.delegate` is reserved.

### 10.2.2 Cross-subject collections

A collection has exactly one owner. Shared collections between subjects
(e.g. "team contacts" with multiple owner-equivalent identities) are not
modeled in v0.1.

**When to revisit:** When team/organization use cases emerge. Likely
solution: a multi-issuer mandate model where two or more sphere keys
hold equivalent admin rights to a collection.

### 10.2.3 Versioned reads of a record

A record exposes its current state only. Historical states are
reconstructable from gamma + S3 archival, but not as a primitive.

**When to revisit:** When a compliance use case demands point-in-time
reads (e.g. "show the record as it was on 2026-03-01").

### 10.2.4 Bulk import / streaming write

`insert_record` is per-record. Bulk loads of N records require N RPC
calls.

**When to revisit:** When the first heavy migration scenario emerges
(import of 10k+ records from a legacy system). Likely solution: a
batched `insert_records` primitive with chunked AEAD streaming.

### 10.2.5 Real-time collaborative editing

Records are not CRDTs. Concurrent writes by different applications
produce last-write-wins.

**When to revisit:** When a collaborative-document schema is proposed
(e.g. `aithos.documents.v1` with multi-user editing). Likely solution:
schema-level append-only field design rather than full CRDT semantics.

### 10.2.6 Trusted compute on encrypted data

The platform never sees payloads in clear. Features like server-side
AI inference, full-text indexing, aggregations across records are
therefore unavailable at the protocol layer.

**When to revisit:** When a credible trusted-compute primitive
(Nitro Enclaves, Intel SGX, AMD SEV-SNP) reaches deployment maturity
and a use case demands it. Likely solution: an optional `compute_in_enclave`
flag on a collection that authorizes the platform to decrypt records
inside an attested enclave.

### 10.2.7 Anonymity of authorized grantees

The wrap list exposes which grantees are authorized on a collection
(by their DID URLs). A privacy-aware variant would obfuscate this with
per-recipient anonymous credentials.

**When to revisit:** When a subject has a credible privacy concern
about "who can see that they have authorized this app." Unlikely for
business use cases; relevant for political-dissent or whistleblower
profiles. Out of scope for v0.1's TPE/PME target.

### 10.2.8 Quantum resistance

The protocol uses classical X25519 + Ed25519 + XChaCha20-Poly1305.

**When to revisit:** When NIST PQC standards are deployed in browser
WebCrypto (likely 2027-2028). Migration is via algorithm-identifier
extension and a versioned wrap format.

## 10.3 Governance of schemas

**Current state:** Schema publication follows the loose process
described in chapter 03 §3.7.2 — markdown proposal, 14-day comment,
move to normative directory. The protocol authority (currently
@Math1987 personal repository → Aithos organization once formed) is the
arbiter.

**Open question:** How does this evolve when third parties start
proposing schemas, and when conflicts arise (two proposals for
`aithos.messages.v1` with different splits)?

**Likely path:** Once 5+ external schemas exist, establish an RFC
process with stewardship roles, mailing list, and a public review
period analogous to IETF or W3C lightweight processes.

## 10.4 Multi-CMK sharding for large collections

**Chapter:** Not yet covered, raised in PLAN §6.

A collection with 100k+ records, holding one CMK, places significant
risk concentration on that one key. Sharding the collection into
multiple sub-CMKs (e.g. by record_id prefix) would:

- Reduce blast radius on CMK compromise.
- Allow incremental rotation (rotate only one shard at a time).

**Cost:** Adds complexity to the authorize/revoke flow (multiple wraps
per app, one per shard) and to read paths (which shard does this
record live in?).

**Criterion for adoption:** When collections > 10k records become
common. Until then, single-CMK is simpler and good enough.

## 10.5 Per-record TTL / retention rules

Records currently live until explicitly deleted. Some use cases want
TTL — "delete this record automatically after 30 days."

**Open question:** Schema-declared TTL (`aithos:ttl: "P30D"`) vs
mandate-declared TTL vs operator-set retention. Each has different
semantics:

- Schema-level: applies to all records of that type, uniform retention.
- Mandate-level: per-grant retention. The mandate could declare "anything I
  insert auto-deletes after X."
- Operator-level: bulk policy ("this PDS deletes everything older than
  3 years").

**Likely path:** Combine schema-level (default) and per-record (override
via metadata field `aithos:expires_at`). Operator policies layered on
top via the gamma chain.

## 10.6 Notifications and webhooks

Server-side notifications are precluded by the encryption model — the
platform doesn't know "this record was modified and you should care."
But client-driven polling is wasteful for many use cases.

**Open question:** A "notification primitive" that the platform can
emit when ANY mutation happens on a collection (without revealing
which record), letting subscribed clients then refetch.

**Likely path:** A SSE channel from the platform pushing
`data.<collection>.dirty` events, gated by mandates. The event carries
only the collection URN and a monotonic counter; the client refetches.

## 10.7 Interaction with the Ethos v0.3 transition

When the Ethos sub-protocol transitions from v0.2 (zone-monolithic) to
v0.3 (per-section), the data sub-protocol's relation to it does NOT
change at the API level — they remain orthogonal. But two practical
points:

1. **Code reuse.** v0.3 Ethos and data v0.1 both use per-unit AEAD with
   the same algorithm choices. The reference implementation SHOULD
   factor a common `encryptUnit` / `decryptUnit` helper used by both.
2. **Sphere key registry.** Both sub-protocols share `did.json`. The
   addition of `#data` (data sub-protocol) and the existence of
   `#circle`, `#self`, `#public` (Ethos) must coexist cleanly.

These are implementation concerns, not protocol concerns. Tracked in
the implementation issues list.

---

End of RFC v0.1 draft. Total: 11 chapters (00–10), normative through 09,
informative open questions in 10.

Implementation begins in `packages/data-crypto/` (Jalon 2).
