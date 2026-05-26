# @aithos/assets-backend

AWS infrastructure (S3 + DynamoDB + Lambda + API Gateway + CloudFront)
implementing the [Aithos assets sub-protocol](https://github.com/aithos-protocol/aithos-protocol/tree/main/spec/assets)
PDS.

> **Status:** Alpha. Mirrors the data-backend pattern. Owner-only auth
> in v0.1; mandate-based grantee auth lands in v0.2.

## Architecture

```
                       ┌─────────────────────┐
                       │   HTTP API Gateway  │
                       │  /mcp/primitives/*  │
                       │  /healthz           │
                       └──────────┬──────────┘
                                  │
                       ┌──────────▼──────────┐
                       │  Router Lambda      │
                       │  (Node 20 ARM64)    │
                       │  JSON-RPC dispatch  │
                       └──┬─────────────┬────┘
                          │             │
       ┌──────────────────┴──┐       ┌──┴─────────────────────┐
       │   DynamoDB tables   │       │   S3 bucket            │
       │   - assets-index    │       │   aithos-assets-pds-*  │
       │   - nonces (TTL)    │       │   versioned, KMS,      │
       │   - gamma           │       │   block-public-access  │
       │   - uploads (TTL)   │       └──────────┬─────────────┘
       └─────────────────────┘                  │
                                                │ OAC
                                     ┌──────────▼─────────┐
                                     │   CloudFront CDN   │
                                     │  (public assets    │
                                     │   only)            │
                                     └────────────────────┘
```

### Tables

| Table | Purpose | Key shape |
|---|---|---|
| `aithos-assets-pds-dev` | Asset metadata index | PK=subject_did, SK=asset_id |
| `aithos-assets-pds-nonces-dev` | Envelope replay protection | PK=<iss>#<nonce>, TTL=expires_at_epoch |
| `aithos-assets-pds-gamma-dev` | Audit log | PK=subject_did, SK=entry_id (ULID) |
| `aithos-assets-pds-uploads-dev` | Pending upload sessions | PK=upload_session, TTL=expires_at_epoch |

The metadata table has two GSIs:
- `gsi1_by_subject_sha` — for the intra-subject dedup probe.
- `gsi2_purge_by_age` — reserved for the v0.2 purge scheduler.

### S3 bucket layout

```
s3://aithos-assets-pds-dev-<account>/
  └── <subject_did>/
      └── <asset_id>/
          └── raw.bin
```

For encrypted assets, `raw.bin` is the nonce-prefix XChaCha20-Poly1305
blob produced by `@aithos/assets-crypto`. For public assets, it is the
plaintext bytes served directly via CloudFront.

## Build & deploy

```sh
# From the assets-backend directory
npm run check-types
npm run cdk:synth     # render CloudFormation
npm run cdk:diff      # diff vs deployed
npm run cdk:deploy    # deploy
npm run cdk:destroy   # tear down
```

The default region is `eu-west-3` (Paris). Override via
`AWS_REGION` environment variable.

Stack outputs:
- `AithosAssetsPdsApiUrl` — base URL for the PDS API
- `AssetsBucketName` — S3 bucket name
- `AssetsTableName` — DynamoDB metadata table name
- `PublicAssetsCDNDomain` — CloudFront distribution domain for public assets
- `RouterFnArn` — Lambda function ARN

## Sandbox notes

`cdk synth` runs `esbuild` natively to bundle the router Lambda code.
This requires:
- The `esbuild` binary in `node_modules/.bin/` to match the host
  architecture (e.g. ARM64 native binary on Apple Silicon, x64 on
  most Linux CI runners).
- Write access on the temporary bundling directory (default
  `cdk.out/bundling-temp-*`).

If you see `Exec format error` on `esbuild` it's because the installed
binary doesn't match your host CPU. Run `npm rebuild esbuild` to fix.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See
[../../LICENSE](../../LICENSE).
