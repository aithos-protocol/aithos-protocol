# `@aithos/protocol-core`

Reference implementation of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol)
primitives — DIDs, identities, ethos documents, mandates, signed bundles, and
canonical hashing.

This is the library the [`aithos`](https://www.npmjs.com/package/aithos) CLI
and any other Aithos-speaking host (MCP server, platform Lambdas, third-party
implementations) are built on. It is the single source of truth for the wire
format: any subtle difference in hashing, canonicalization, or signature
verification would break interoperability between hosts, so every host is
expected to depend on exactly this package.

## Install

```sh
npm install @aithos/protocol-core
```

## Usage

```ts
import {
  createIdentity,
  rootDid,
  ensureEthosLayout,
  addSection,
  createMandate,
  verifyMandate,
  verifyBundleAtPath,
} from "@aithos/protocol-core";
```

See the [protocol specification](https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md)
for semantics and the on-disk layout.

## Scope

`@aithos/protocol-core` is **pure TypeScript**. It does not read
`$AITHOS_HOME`-independent config, it does not perform network I/O, and it
does not ship any CLI. Everything that touches a filesystem path takes that
path as an argument. Hosts that want a default keystore layout (the
`~/.aithos/` convention) are expected to compose it on top of this package —
`aithos` does, and so does `@aithos/mcp`.

## Status

**Draft**, package v0.2.1, targeting Aithos protocol v0.2.x (manifests stamp
`aithos: "0.2.0"`, mandates stamp `aithos-mandate: "0.2.1"`). The wire format
may change on any minor-version bump until 1.0.0. v0.2.0 was a breaking release
over v0.1.x: section mutation history lives in the signed gamma log only (see
spec §10). v0.2.1 closes the loop on delegate writes against a tracked
identity: mandates carry the grantee's Ed25519 pubkey, zone/manifest/gamma
signatures carry an optional `authorized_by`, and the keystore-aware delegate
resolver lets stateless verifiers accept delegate-signed bundles.

## License

Business Source License 1.1 (**BUSL-1.1**), **Change Date** 2030-12-31, **Change License**
Apache-2.0. See [LICENSE](./LICENSE) and the [repository overview](../../LICENSE).
