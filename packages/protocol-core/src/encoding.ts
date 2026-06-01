// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Byte/string encoding primitives shared across the protocol.
 *
 * These live in their own module (rather than identity.ts) on purpose: the
 * envelope/mandate verification path needs `base64url` + `sha256Hex` but must
 * NOT drag in the filesystem keystore (node:fs/path) that identity.ts carries.
 *
 * Implementations are deliberately **Buffer-free** so the verify/sign path runs
 * unchanged in the browser (where `Buffer` is not a global). They use the
 * cross-platform `btoa`/`atob` (present in Node ≥16 and all modern browsers)
 * and produce byte-identical output to the previous `Buffer`-based versions —
 * the conformance + byte-snapshot suite guards that equivalence.
 */

import { sha256 } from "@noble/hashes/sha256";

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  // Standard base64, then translate to the URL-safe, unpadded alphabet.
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Restore padding that base64url drops.
  const remainder = b64.length % 4;
  if (remainder === 2) b64 += "==";
  else if (remainder === 3) b64 += "=";
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = sha256(bytes);
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    hex += digest[i]!.toString(16).padStart(2, "0");
  }
  return "sha256:" + hex;
}
