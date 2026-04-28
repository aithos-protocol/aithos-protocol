// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * did:aithos helpers. The root portion reuses the did:key encoding so that any
 * did:key resolver can parse it.
 *
 *   did:aithos:<multibase(z)>  ->  decoded bytes are [0xed, 0x01, ...32-byte Ed25519 pk]
 *
 * Sphere keys are referenced as DID URL fragments: #public, #circle, #self.
 */

import { base58 } from "@scure/base";

export const SPHERE_FRAGMENTS = ["public", "circle", "self"] as const;
export type Sphere = (typeof SPHERE_FRAGMENTS)[number];

const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);
const X25519_MULTICODEC = new Uint8Array([0xec, 0x01]);

export function ed25519PublicKeyToMultibase(pk: Uint8Array): string {
  if (pk.byteLength !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes; got ${pk.byteLength}`);
  }
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + pk.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(pk, ED25519_MULTICODEC.length);
  return "z" + base58.encode(prefixed);
}

export function x25519PublicKeyToMultibase(pk: Uint8Array): string {
  if (pk.byteLength !== 32) {
    throw new Error(`X25519 public key must be 32 bytes; got ${pk.byteLength}`);
  }
  const prefixed = new Uint8Array(X25519_MULTICODEC.length + pk.length);
  prefixed.set(X25519_MULTICODEC, 0);
  prefixed.set(pk, X25519_MULTICODEC.length);
  return "z" + base58.encode(prefixed);
}

export function multibaseToEd25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) {
    throw new Error("Expected multibase base58btc encoding (prefix 'z')");
  }
  const decoded = base58.decode(mb.slice(1));
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Multibase data does not carry the Ed25519 multicodec prefix 0xed01");
  }
  return decoded.slice(2);
}

export function didAithosForRootKey(rootPk: Uint8Array): string {
  return "did:aithos:" + ed25519PublicKeyToMultibase(rootPk);
}

export function didUrlForSphere(rootDid: string, sphere: Sphere): string {
  return `${rootDid}#${sphere}`;
}

export function didUrlForKex(rootDid: string, sphere: Sphere): string {
  return `${rootDid}#${sphere}-kex`;
}

export function parseDidAithos(did: string): { rootMultibase: string; fragment: string | null } {
  const m = did.match(/^did:aithos:([^#]+)(#.*)?$/);
  if (!m) throw new Error(`Not a did:aithos identifier: ${did}`);
  return { rootMultibase: m[1], fragment: m[2] ? m[2].slice(1) : null };
}
