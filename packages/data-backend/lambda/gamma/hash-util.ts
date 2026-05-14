// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Small helper for hashing JSON content used as commitments in gamma
 * entry payloads (e.g. `payload_hash` of a record).
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalize } from "@aithos/protocol-core/canonical";

/**
 * Return `sha256:<hex>` of the JCS-canonicalized form of `value`.
 */
export function hashJson(value: unknown): string {
  const bytes = new TextEncoder().encode(canonicalize(value));
  const digest = sha256(bytes);
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}
