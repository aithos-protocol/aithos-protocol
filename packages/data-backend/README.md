# @aithos/data-backend

AWS reference implementation of the Aithos **data sub-protocol** PDS
(Personal Data Server). See [spec/data/](../../spec/data/00-overview.md).

> **Status:** Sub-jalon 3.1 — MVP infrastructure deployed and validated
> end-to-end. Auth (envelope + mandate verification) is intentionally
> stubbed; wire in Sub-jalon 3.2.

## What's here

- **CDK stack** (`cdk/data-pds-stack.ts`) — DynamoDB single-table + HTTP
  API Gateway + Lambda router. Deploys in eu-west-3 by default.
- **Lambda router** (`lambda/router.ts`) — JSON-RPC 2.0 dispatcher.
- **Handlers** (`lambda/handlers/`) — collection and record primitives.

## What's implemented (Sub-jalon 3.1)

| Method | Handler | Spec |
|---|---|---|
| `aithos.data.create_collection` | `collections.ts` | §5.4.1 |
| `aithos.data.get_collection` | `collections.ts` | §5.3.2 |
| `aithos.data.list_collections` | `collections.ts` | §5.3.3 |
| `aithos.data.insert_record` | `records.ts` | §5.4.2 |
| `aithos.data.get_record` | `records.ts` | §5.3.4 |
| `aithos.data.list_records` | `records.ts` | §5.3.5 |

Plus a `/healthz` GET endpoint for liveness probes.

## What's NOT yet implemented

- `update_record`, `delete_record` (Sub-jalon 3.2)
- `authorize_app`, `revoke_app`, `rotate_cmk` (Sub-jalon 3.2)
- Envelope + mandate signature verification (Sub-jalon 3.2)
- Schema validation against the registry (Sub-jalon 3.2)
- Gamma log persistence (Sub-jalon 3.2+)
- Portability — export/import `.data` (later jalon)

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

## End-to-end test (Sub-jalon 3.1 acceptance)

The MVP deployment was validated against this scenario, all paths
returning expected results:

1. `POST /healthz` → 200 `{ ok: true, protocol: "aithos.data", version: "0.1.0" }`
2. `create_collection` with stub CMK envelope → 200, collection persisted
3. `insert_record` × 3 → 200, ULIDs generated, record_count incremented
4. `list_records` → returns 3 items, newest first
5. `get_collection` → reports `record_count: 3`, `modified_at` updated
6. `list_collections` → returns 1 collection
7. `get_record` (existing) → returns the record with metadata + payload
8. `get_record` (missing) → JSON-RPC error code -32020 `AITHOS_NOT_FOUND`
9. `create_collection` (duplicate) → JSON-RPC error code -32073 `AITHOS_DATA_COLLECTION_EXISTS`
10. Unknown method → JSON-RPC error code -32601

## Security note for v0.1 dev

The current handlers **do not verify** the JSON-RPC envelope's
signature or the mandate. They accept the caller-supplied `subject_did`
at face value. This is intentional for the MVP iteration — the goal of
Sub-jalon 3.1 is to validate the infrastructure shape and the data
model, not the security surface.

**Do not expose this API publicly in its current state.** The current
URL is fine for development against the dev account, but any production
deployment MUST wait for Sub-jalon 3.2 (envelope verification + mandate
binding via `@aithos/protocol-core`).

## Cost note

The dev stack costs essentially zero at idle. DynamoDB on-demand has
no minimum charge, Lambda is pay-per-invocation, HTTP API Gateway is
$1/M requests. CDK bootstrap stack costs <$0.10/mo (S3 bucket for
assets).

## License

Apache-2.0 © Mathieu Colla
