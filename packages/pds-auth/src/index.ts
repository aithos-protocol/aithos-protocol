// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Shared PDS auth surface — consumed (and bundled from source) by the data and
// assets PDS backends. Single source of truth for the DID resolver, the
// revocation-epoch cache invalidation, the owner sphere lock, and RpcError.
export { RpcError } from "./errors.js";
export { resolveIssuerDoc, invalidateDidCache } from "./did-resolver.js";
export { assertOwnerDataSphere } from "./sphere-lock.js";
