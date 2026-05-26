# Changelog

All notable changes to `@aithos/assets-backend` will be documented in
this file.

## [Unreleased]

## [0.1.0-alpha.1] — 2026-05-21

Initial alpha release.

### Added

- CDK stack `AithosAssetsPdsStack` defining the full PDS infrastructure:
  S3 bucket (versioned, KMS, block-public-access), 4 DynamoDB tables
  (assets-index with 2 GSIs, nonces with TTL, gamma, uploads with TTL),
  Node 20 ARM64 Lambda router, HTTP API Gateway with CORS, CloudFront
  distribution with Origin Access Control for public assets.
- Stub Lambda router (`lambda/router.ts`) reserving the entry point
  for the full JSON-RPC dispatch landing in Phase 3.
- Stack outputs for downstream wiring (API URL, bucket name, table
  names, CDN domain, Lambda ARN).
- Configurable per-subject quota (default 5 GB) and per-asset cap
  (default 100 MB), per `spec/assets/10-open-questions.md` §10.13.

[Unreleased]: https://github.com/aithos-protocol/aithos-protocol/compare/assets-backend-0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/aithos-protocol/aithos-protocol/releases/tag/assets-backend-0.1.0-alpha.1
