# @aithos/data-backend — Changelog

## 0.1.0-alpha.1 — 2026-05-14

Initial deployment of the data sub-protocol PDS reference backend.

### Added

- CDK stack `AithosDataPdsDev` (eu-west-3) provisioning:
  - DynamoDB table `aithos-data-pds-dev` (single-table design, on-demand,
    PITR enabled, ARM-architecture friendly).
  - GSI1 (`gsi1_by_collection_mtime`) for paginated record listing.
  - HTTP API Gateway with CORS-enabled `POST /mcp/primitives/{read,write}`
    and `GET /healthz`.
  - Lambda router (Node 20 ARM64, ESM bundled via esbuild) with handlers
    for: `create_collection`, `get_collection`, `list_collections`,
    `insert_record`, `get_record`, `list_records`.
- JSON-RPC 2.0 envelope handling with error codes aligned to
  `spec/data/05-api-primitives.md` §5.7.
- Tags: `Project=aithos`, `Component=data-pds`, `Environment=dev`,
  `ManagedBy=cdk`.

### Status

- **Deployed and validated end-to-end** against the acceptance scenario
  documented in README §"End-to-end test".
- **Auth is stubbed** — handlers accept caller-supplied `subject_did`
  without verifying envelope or mandate. To be addressed in
  Sub-jalon 3.2 by wiring `@aithos/protocol-core`'s envelope verifier
  and the mandate signature path.

### Known limitations (deferred to Sub-jalon 3.2+)

- No envelope / mandate verification.
- No schema validation against the registry.
- No gamma log persistence.
- Missing primitives: `update_record`, `delete_record`, `authorize_app`,
  `revoke_app`, `rotate_cmk`.
- Bookkeeping update of `collection.record_count` is best-effort, not
  transactional with the record insert. Will move to `TransactWriteItems`.
- No retry/idempotency token on writes.
- No portability (`export_collection` / `import_collection`).

### Bootstrap

- CDK bootstrap stack `CDKToolkit` was created in eu-west-3 (qualifier
  `hnb659fds`) as part of this work. It persists as a baseline for
  any subsequent CDK deployments in this region.
