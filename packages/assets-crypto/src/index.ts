// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Public entry point of @aithos/assets-crypto.
 *
 * Re-exports the full surface across types / aad / amk / asset
 * modules. Most callers should be able to import from the package
 * root rather than from the individual sub-paths.
 *
 * Spec ref: `spec/assets/02-key-hierarchy.md`.
 */

export * from "./types.js";
export * from "./aad.js";
export * from "./amk.js";
export * from "./asset.js";
