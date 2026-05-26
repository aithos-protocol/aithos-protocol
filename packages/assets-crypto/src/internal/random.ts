// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Cross-platform CSPRNG helper.
 *
 * Replaces `node:crypto.randomBytes(n)` which is Node-only and breaks
 * browser bundlers (Vite, esbuild, webpack with no node polyfill).
 *
 * Uses the Web Crypto API's `crypto.getRandomValues()` which is
 * available identically in:
 *   - all browsers (since IE11)
 *   - Node 16+ (exposed as `globalThis.crypto`, no import needed)
 *   - Deno, Bun, and most modern JS runtimes
 *
 * Throws if no CSPRNG is available (e.g. very old environment) — but
 * any environment that can run this package will have it.
 */
export function randomBytes(n: number): Uint8Array {
  if (n < 0 || !Number.isInteger(n)) {
    throw new Error(`randomBytes: size must be a non-negative integer, got ${n}`);
  }
  const g = globalThis as { crypto?: { getRandomValues<T extends ArrayBufferView | null>(array: T): T } };
  if (!g.crypto || typeof g.crypto.getRandomValues !== "function") {
    throw new Error(
      "randomBytes: globalThis.crypto.getRandomValues is not available in this environment",
    );
  }
  const out = new Uint8Array(n);
  g.crypto.getRandomValues(out);
  return out;
}
