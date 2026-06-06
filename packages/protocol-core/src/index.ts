// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * @aithos/protocol-core — library barrel export.
 *
 * Pure TypeScript implementation of the Aithos protocol primitives:
 * DIDs, identities, ethos, mandates, bundles, canonical hashing.
 *
 * Both the `aithos` CLI and the platform Lambdas import from here so that
 * there is exactly one implementation of the protocol across all consumers.
 * Any subtle difference in hashing, canonicalization, or signature verification
 * would break interoperability — this barrel is the single source of truth.
 */

export * from "./did.js";
export * from "./storage.js";
export * from "./identity.js";
export * from "./mandate.js";
export * from "./mandate-store.js";
export * from "./ethos.js";
export * from "./bundle.js";
export * from "./bundle-v03.js";
export * from "./bundle-migrate.js";
export * from "./bundle-edit.js";
export * from "./keystore-v3.js";
export * from "./canonical.js";
export * from "./gamma.js";
export * from "./author.js";
export * from "./envelope.js";
export * from "./backend.js";
export * from "./filesystem-storage.js";
export * from "./sponsorship.js";
