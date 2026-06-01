// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Byte/string encoding primitives shared across the protocol.
 *
 * These live in their own module (rather than identity.ts) on purpose: the
 * envelope/mandate verification path needs `base64url` + `sha256Hex` but must
 * NOT drag in the filesystem keystore (node:fs/path) that identity.ts carries.
 * Keeping the pure encoders here lets browser bundlers (Vite/Rollup) build the
 * verify path without externalizing node built-ins. No `node:` imports here.
 */

import { sha256 } from "@noble/hashes/sha256";

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function base64urlDecode(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return "sha256:" + Buffer.from(sha256(bytes)).toString("hex");
}
