# @aithos/data-backend

AWS reference implementation of the Aithos **data sub-protocol** PDS
(Personal Data Server). See [spec/data/](../../spec/data/00-overview.md).

> **Status:** Sub-jalon 3.2a — authentication is now real. Every call
> to `/mcp/primitives/{read,write}` requires a valid signed envelope
> per spec chapter 11. Anyone holding only a DID **cannot** access
> any data.

## What's here

- **CDK stack** (`cdk/data-pds-stack.ts`) — DynamoDB single-table + HTTP
  API Gateway + Lambda router. Deploys in eu-west-3 by default.
- **Lambda router** (`lambda/router.ts`) — JSON-RPC 2.0 dispatcher.
- **Handlers** (`lambda/handlers/`) — collection and record primitives.

## What's implemented (Sub-jalon 3.2a)

| Method | Handler | Spec |
|---|---|---|
| `aithos.data.create_collection` | `collections.ts` | §5.4.1 |
| `aithos.data.get_collection` | `collections.ts` | §5.3.2 |
| `aithos.data.list_collections` | `collections.ts` | §5.3.3 |
| `aithos.data.insert_record` | `records.ts` | §5.4.2 |
| `aithos.data.get_record` | `records.ts` | §5.3.4 |
| `aithos.data.list_records` | `records.ts` | §5.3.5 |
| `aithos.data.update_record` | `records.ts` | §5.4.3 |
| `aithos.data.delete_record` | `records.ts` | §5.4.4 |

Plus a `/healthz` GET endpoint for liveness probes (no envelope required).

**Every other endpoint requires** a JSON-RPC envelope signed per
spec chapter 11, verified by the full 9-step path in
`@aithos/protocol-core`. Failure at any step rejects the request:

| Spec error code | Meaning | HTTP |
|---|---|---|
| `-32010 AITHOS_BAD_ENVELOPE` | malformed / aud / method / params_hash mismatch | 401 |
| `-32011 AITHOS_BAD_SIGNATURE` | signature did not verify against the DID document | 401 |
| `-32012 AITHOS_REPLAY_DETECTED` | nonce already consumed | 401 |
| `-32013 AITHOS_STALE_ENVELOPE` | iat/exp out of clock-skew window | 401 |
| `-32020 AITHOS_NOT_FOUND` | record / collection does not exist | 404 |
| `-32040 AITHOS_MANDATE_INVALID` | mandate signature / window / binding | 403 |
| `-32041 AITHOS_MANDATE_REVOKED` | mandate revoked | 403 |
| `-32042 AITHOS_INSUFFICIENT_SCOPE` | scope or subject_did mismatch | 403 |
| `-32603` (internal) | replay cache outage → fail closed | 500 |

## What's NOT yet implemented

- `authorize_app`, `revoke_app`, `rotate_cmk` (Sub-jalon 3.2b)
- `did:aithos:…` resolution (currently `did:key:…` only) — 3.2b
- Mandate revocation lookup — 3.2b
- Schema validation against the registry — 3.2c
- Gamma log persistence — 3.2c
- Portability — export/import `.data` — later jalon

## Architecture

```
HTTP API Gateway (eu-west-3)
  POST /mcp/primitives/read   ─┐
  POST /mcp/primitives/write  ─┴─→  Lambda router  ─┐
  GET  /healthz               ─→  (200 OK)         │
                                                   ↓
                                          handlers/{collections,records}.ts
                                                   │
                                                   ↓
                                       DynamoDB (single-table)
                                       aithos-data-pds-dev
                                         ├── PK = subject_did
                                         ├── SK = col#<name>[#rec#<id>]
                                         └── GSI1: by collection × mtime
```

Single-table key scheme:

```
("subj#<did>", "col#<name>")                  → collection metadata
("subj#<did>", "col#<name>#rec#<record_id>")  → record document
```

GSI1 supports paginated `list_records` sorted by `modified_at` per
collection.

## Deploying

Requires:
- An AWS account with admin credentials in the environment
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optionally
  `AWS_SESSION_TOKEN`).
- Bootstrap of the CDK toolkit stack in the target account/region
  (`cdk bootstrap aws://<acct>/eu-west-3`).
- Node 20+, npm.

```bash
# From the data-backend package directory:
npm install
npm run cdk:synth       # generate CloudFormation template
npm run cdk:diff        # diff vs deployed
npm run cdk:deploy      # deploy
npm run cdk:destroy     # tear down
```

The stack is named `AithosDataPdsDev` and exports:
- `DataPdsApiUrl` — the base URL of the HTTP API
- `DataTableName` — `aithos-data-pds-dev`
- `RouterFnArn` — Lambda ARN

## Trying it

Once deployed:

```bash
API_URL=$(aws cloudformation describe-stacks --stack-name AithosDataPdsDev \
  --query "Stacks[0].Outputs[?OutputKey=='DataPdsApiUrl'].OutputValue" --output text)

# Health
curl "$API_URL/healthz"

# Create collection
curl -X POST "$API_URL/mcp/primitives/write" \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "aithos.data.create_collection",
    "params": {
      "subject_did": "did:aithos:z6Mk…",
      "collection_name": "contacts",
      "schema": "aithos.contacts.v1",
      "cmk_envelope": { ... }
    }
  }'

# Insert
curl -X POST "$API_URL/mcp/primitives/write" \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "aithos.data.insert_record",
    "params": {
      "collection_urn": "urn:aithos:collection:did:aithos:z6Mk…:contacts",
      "metadata": { "name": "Jean", "email": "j@example.com", "status": "lead" },
      "payload": { "alg": "xchacha20poly1305-ietf", "nonce": "…", "ciphertext": "…", "dek_wrapped_for_cmk": "…" }
    }
  }'
```

## End-to-end test (Sub-jalon 3.2a acceptance)

Run `node test-e2e/auth-flow.mjs` against a deployed stack. It
generates a `did:key:…` locally, signs envelopes with
`@aithos/protocol-core`, and validates 14 assertions across the happy
path and the negative-auth surface:

**Happy path:**
1. `create_collection` (owner-signed) → 200
2. `insert_record` (owner-signed) → 200
3. `list_records` returns the inserted record
4. `get_record` returns the inserted record
5. `update_record` persists changes (status: lead → won)
6. `delete_record` (soft) → 200
7. `get_record` after delete → 404 `AITHOS_NOT_FOUND`

**Negative auth:**
8. No envelope → 401 `AITHOS_BAD_ENVELOPE`
9. Tampered signature → 401 `AITHOS_BAD_SIGNATURE`
10. Method mismatch (envelope.method ≠ RPC method) → 401 `AITHOS_BAD_ENVELOPE`
11. Replayed nonce → 401 `AITHOS_REPLAY_DETECTED`
12. `envelope.iss` ≠ `subject_did` → 403 `AITHOS_INSUFFICIENT_SCOPE`

## Security model (current state)

Every authenticated endpoint enforces the spec §11.4 9-step
verification before executing any business logic:

1. **Schema** — envelope shape validation.
2. **Audience** — `envelope.aud` must match the exact request URL.
3. **Method** — `envelope.method` must match the JSON-RPC method called.
4. **TTL** — `iat ∈ [now-30, now+30]`, `exp > now`, `exp - iat ≤ 300s`.
5. **`params_hash`** — recomputed JCS canonical hash of params (sans
   `_envelope`); must match.
6. **Signer resolution** — DID document resolved (currently `did:key:…`
   only); `verificationMethod` exists in it. For mandate-bearing
   envelopes, the mandate's signature, time window, and grantee binding
   are also checked.
7. **Signature** — Ed25519 verification against the signing-bytes form
   (substitute-value canonicalization).
8. **Replay** — atomic `PutItem(condition: attribute_not_exists)` on
   the `aithos-data-pds-nonces-dev` table.
9. **Commit** — nonce stored with TTL on `expires_at_epoch`.

Replay cache outages **fail closed** per spec §11.10: if DynamoDB is
unreachable, the request is rejected with `-32603`, never allowed
through.

Handlers also enforce:

- **`requireSubjectMatch`** — `envelope.iss` must equal the target
  `subject_did` argument. A caller signing for subject A cannot
  operate on subject B's data.
- **`requireScope`** — for delegate-mode callers, the mandate's
  `scopes` must cover the requested operation (`data.<col>.<action>`,
  with wildcards and admin-implies-write etc.). Owner mode bypasses
  scope check (the owner has full access).

## Cost note

The dev stack costs essentially zero at idle. DynamoDB on-demand has
no minimum charge, Lambda is pay-per-invocation, HTTP API Gateway is
$1/M requests. CDK bootstrap stack costs <$0.10/mo (S3 bucket for
assets).

## License

Apache-2.0 © Mathieu Colla
