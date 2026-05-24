# PLAN A2b — Schema self-registration for vendor namespaces

**Status** : planned, not yet implemented.
**Created** : 2026-05-24
**Owner** : Mathieu Colla
**Depends on** : A2a shipped (cf. commit modifying `collections.ts` to
accept `aithos.x.*` schemas at face value).

## 1. Context

Per spec §3.3, the schema namespace is partitioned:

| Namespace                                | Authority                           |
| ---------------------------------------- | ----------------------------------- |
| `aithos.<name>.v<N>`                     | Aithos protocol (core schemas)      |
| `aithos.x.<vendor>.<name>.v<N>`          | Third-party vendors                 |
| Anything else (e.g. `did:web:...`)       | Any organization, no Aithos opinion |

Until 2026-05-24, the PDS rejected any `aithos.*` schema not present in
the server-bundled `REGISTRY`. After A2a, the PDS accepts `aithos.x.*`
at face value (no server-side metadata validation). This unblocked apps
like Linkedone but leaves a gap: **a buggy or malicious client can store
arbitrary fields in record metadata for vendor schemas**, bypassing the
`additionalProperties: false` enforcement that core schemas enjoy.

A2b closes that gap by letting each owner publish their own schemas to
their own PDS, where the platform stores and enforces them.

## 2. Design

### 2.1 Storage

New DDB table `aithos-data-schemas`:

| Attr        | Type   | Notes                                          |
| ----------- | ------ | ---------------------------------------------- |
| `pk`        | String | `owner_did` (partition)                        |
| `sk`        | String | `schema_id` (sort), e.g. `aithos.x.linkedone.post.v1` |
| `schema_doc`| Map    | Full JSON Schema 2020-12 document              |
| `doc_hash`  | String | sha256 of canonical schema_doc, for idempotency|
| `created_at`| String | ISO 8601                                       |

Single-region (eu-west-3), on-demand billing, point-in-time recovery on.

### 2.2 New MCP endpoint

```
aithos.data.register_schema
  params: {
    subject_did: string,         // owner_did (must match caller, owner-only)
    schema_doc:  object,         // full JSON Schema doc
  }
  returns: {
    schema_id: string,           // echoed from schema_doc["aithos:schema"]
    doc_hash:  string,           // sha256 of canonical doc
    created:   boolean,          // true if newly registered, false if idempotent
  }
```

**Authentication** : signed envelope by the owner. Delegates cannot
register schemas (it's a configuration action, not a data action).

**Validation rules** :

1. `schema_doc["aithos:schema"]` MUST match `^aithos\.x\.[a-z][a-z0-9_-]{0,30}\.[a-z][a-z0-9_-]{0,62}\.v[1-9][0-9]*$`.
   No core (`aithos.<bareword>`) schemas — those go through PR review.
   No non-aithos namespaces — those don't need server-side registration
   (no validation needed, they're owner-only conventions).

2. `schema_doc["aithos:version"]` MUST be set, semver-formatted.

3. Maximum schema_doc size: **10 KB serialized**.

4. Maximum schemas per owner: **50**.

5. The doc MUST parse as valid JSON Schema 2020-12 (subset the platform
   supports — same subset as `validateMetadata` in `registry.ts`).

### 2.3 Immutability and idempotency

Per spec §3.5 :
> *A schema document, once published with a given `aithos:schema` +
> `aithos:version`, is immutable. Any change requires bumping the version.*

Implementation :

- On `register_schema`, compute `doc_hash = sha256(canonicalize(schema_doc))`.
- If `(pk=owner_did, sk=schema_id)` already exists :
  - Same `doc_hash` → idempotent OK, return `{ created: false }`.
  - Different `doc_hash` → reject with `AITHOS_DATA_SCHEMA_IMMUTABLE`.
- If absent → insert, return `{ created: true }`.

This means an app can safely re-call `register_schema` on every boot
(e.g. inside the SDK provider) and it will be a no-op after the first
successful call.

### 2.4 Lookup ordering at write time

Modify `getSchema()` in `registry.ts` to accept an optional `owner_did`:

```ts
export async function getSchema(id: string, ownerDid?: string): Promise<AithosSchema | null> {
  // 1. Bundled REGISTRY first (core schemas, no DDB read).
  const core = REGISTRY[id] ?? null;
  if (core) return core;
  // 2. Per-owner registered schemas in DDB.
  if (ownerDid && id.startsWith("aithos.x.")) {
    return await fetchOwnerSchema(ownerDid, id);
  }
  return null;
}
```

`createCollectionHandler` already has `subject_did` in scope and passes
it. Same for `insertRecordHandler` / `updateRecordHandler` (they have
the collection's `subject_did` via the collection lookup).

### 2.5 Schema evolution

The model is **immutable schemas, explicit versioning** :

- v1 of a schema, once registered, never changes.
- To evolve, register a new version (`aithos.x.linkedone.post.v2`).
- Existing collections keep their `schema` attribute pointing at v1 →
  validation continues against v1.
- New collections can be created with `schema: "aithos.x.linkedone.post.v2"`.
- Two collections (one per version) can coexist indefinitely.
- An app can read both in parallel during a transition.
- Migration is an app-level concern : a script reads each v1 record,
  transforms it, inserts in a v2 collection, optionally deletes the v1
  row. The protocol doesn't provide a built-in migration primitive
  (intentional — every migration is bespoke and the protocol shouldn't
  guess).

### 2.6 IAM and quotas

- `linkedone-deployer-mfa` and equivalent app deploy roles need
  `dynamodb:GetItem,PutItem,Query` on `aithos-data-schemas`. Scoped by
  `LeadingKeys` condition to their owner_did range.
- Per-owner quotas (50 schemas × 10 KB = 500 KB max DDB footprint per
  owner) are enforced at write time by an explicit count check
  (Query LIMIT 50 + size sum) before the Put.

### 2.7 SDK surface

Add to `@aithos/sdk` :

```ts
interface DataClient {
  // ... existing methods ...

  /**
   * Idempotently register a vendor schema with the PDS. Safe to call
   * on every app boot — if the same schema doc was already registered,
   * the call resolves to `{ created: false }`.
   *
   * Throws AITHOS_DATA_SCHEMA_IMMUTABLE if the same schema_id was
   * previously registered with a different document — the caller MUST
   * bump the version in `aithos:schema` and retry.
   */
  registerSchema(schemaDoc: object): Promise<{
    schemaId: string;
    docHash: string;
    created: boolean;
  }>;
}
```

The SDK also keeps the per-client local schemas Map populated in A2a
(via `createDataClient({ schemas: [...] })`) so the SDK split logic
keeps working even before the first successful `registerSchema()`.

## 3. Migration from A2a to A2b

When A2b ships :

1. Existing collections with `aithos.x.*` schemas continue to work.
   `getSchema()` returns null for them in the bundled REGISTRY, the
   validation skip in `records.ts` (`if (getSchema(schemaId))`) still
   applies — so writes don't suddenly start failing.

2. Apps SHOULD call `registerSchema()` at boot to opt into server-side
   validation. Until they do, A2a behavior persists (no enforcement).

3. Once an app's schema is registered, subsequent writes ARE validated
   server-side. This is a strict regime change for that schema — if the
   app was silently writing additional fields beyond what the schema
   declares, those writes will start failing. App owners should test
   with `registerSchema()` enabled in staging before flipping prod.

4. No data backfill needed. No deprecation of A2a behavior planned —
   the "accept at face value" path stays as a fallback for apps that
   never call `registerSchema()`.

## 4. Estimated effort

| Component                                          | Estimate |
| -------------------------------------------------- | -------- |
| DDB table + CDK                                    | 0.5 day  |
| `register_schema` endpoint + handler + tests       | 1 day    |
| `getSchema()` async + DDB read + cache             | 0.5 day  |
| Wiring in collections/records handlers + tests     | 0.5 day  |
| SDK `registerSchema` + idempotency tests           | 0.5 day  |
| IAM policies update (per-app deploy roles)         | 0.25 day |
| Migration test (existing A2a collection still OK)  | 0.25 day |
| Docs (spec §3.6 new section, README)               | 0.5 day  |
| **Total**                                          | ~4 days  |

## 5. Open questions

- **Caching**. DDB read on every `createCollection` / first insert per
  collection adds 5-15 ms latency. Cache in Lambda memory keyed by
  `(owner_did, schema_id)` with 5 min TTL? Acceptable since schemas are
  immutable.
- **Schema discovery by other parties**. If Alice's app delegates write
  access to Bob's agent, does Bob need to know Alice's schema doc?
  Probably yes — add a `aithos.data.get_schema(owner_did, schema_id)`
  read primitive. Public (no auth required) since the doc itself isn't
  sensitive.
- **Cross-owner sharing**. Can two owners agree to use the same vendor
  schema without each registering it? Currently no — each owner's PDS
  is independent. If we want a "vendor publishes once, all users see
  it", we need a global vendor registry, but that's a separate
  governance question (who can write to `aithos-vendor-schemas`?).
- **Cost**. Negligible at MVP scale. At 10k tenants × 5 schemas avg ×
  10 KB = 500 MB DDB footprint, ~$0.15/mo. Reads bounded by collection
  creates + insert metadata path.

## 6. Decision log

- **2026-05-24** : A2a shipped (this commit). PDS accepts `aithos.x.*`
  at face value. A2b deferred for now to unblock Linkedone MVP.
- **TBD** : A2b kick-off — depends on a second app needing vendor
  schemas with server-side validation (probably Switchia v2 or the next
  app after Linkedone).
