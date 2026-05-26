// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Shared types for the Aithos assets sub-protocol crypto primitives.
 *
 * Mirrors the wire format described in `spec/assets/01-data-model.md`
 * and `spec/assets/02-key-hierarchy.md`. Binary values are kept as
 * `Uint8Array` in memory; serialization to JSON uses base64 encoding
 * via the helpers in this module.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { base64 } from "@scure/base";

/* -------------------------------------------------------------------------- */
/*  Wraps                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * A wrap of the Asset Master Key (AMK) addressed to one recipient.
 *
 * Spec ref: `spec/assets/02-key-hierarchy.md` §2.3.3.
 */
export interface WrapEntry {
  /** DID URL of the recipient's X25519 verification method. */
  readonly recipient: string;
  /** Algorithm identifier. v0.1: "x25519-hkdf-sha256-aead". */
  readonly alg: "x25519-hkdf-sha256-aead";
  /** Ephemeral X25519 public key generated for this wrap (base64). */
  readonly ephemeral_public: string;
  /** 24-byte XChaCha20-Poly1305 nonce (base64). */
  readonly wrap_nonce: string;
  /** AEAD ciphertext of the wrapped AMK (base64). */
  readonly wrapped_key: string;
}

/**
 * The Asset Master Key envelope — what the asset metadata document
 * stores. Carries the bytes-encryption nonce alongside the wrap list.
 *
 * Spec ref: `spec/assets/02-key-hierarchy.md` §2.3.4.
 */
export interface AMKEnvelope {
  /** Algorithm identifier for the bytes encryption. v0.1: "xchacha20poly1305-ietf". */
  readonly alg: "xchacha20poly1305-ietf";
  /**
   * 24-byte XChaCha20-Poly1305 nonce used to encrypt the asset bytes
   * (base64). This is the same nonce prepended to the on-disk
   * ciphertext blob (§2.3.2 nonce-prefix layout).
   */
  readonly nonce: string;
  /** One wrap per authorized recipient (owner + grantees). */
  readonly wraps: readonly WrapEntry[];
}

/* -------------------------------------------------------------------------- */
/*  Asset metadata                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Hint describing the originating attachment context. Informative —
 * the platform's `referenced_by[]` is authoritative.
 *
 * Spec ref: `spec/assets/01-data-model.md` §1.5.
 */
export type AttachedContext =
  | { readonly kind: "ethos"; readonly zone?: "public" | "circle" | "self"; readonly section_id?: string }
  | { readonly kind: "data"; readonly collection_urn?: string; readonly record_id?: string };

/**
 * Storage backend descriptor pointing to where the asset bytes live.
 *
 * Spec ref: `spec/assets/01-data-model.md` §1.2.3.
 */
export interface StorageDescriptor {
  /** Storage backend discriminator. v0.1: "s3". */
  readonly backend: "s3";
  /** Implementation-specific object key (e.g. "<did>/<asset_id>/raw.bin"). */
  readonly key: string;
}

/**
 * An entry in an asset's `referenced_by[]` index.
 *
 * Spec ref: `spec/assets/01-data-model.md` §1.3.
 */
export type AssetReference =
  | {
      readonly kind: "ethos.section";
      readonly ethos_edition_urn: string;
      readonly zone: "public" | "circle" | "self";
      readonly section_id: string;
      readonly since_height: number;
    }
  | {
      readonly kind: "data.record";
      readonly data_record_urn: string;
      readonly field: string;
      readonly since: string;
    };

/**
 * Asset lifecycle state.
 *
 * Spec ref: `spec/assets/01-data-model.md` §1.2.4.
 */
export type AssetState = "ACTIVE" | "ORPHANED" | "TOMBSTONED" | "GONE";

/**
 * Asset metadata document as returned by `aithos.assets.get_asset`.
 *
 * Spec ref: `spec/assets/01-data-model.md` §1.2.2.
 */
export interface AssetMetadata {
  readonly "aithos-assets": "0.1.0";
  readonly urn: string;
  readonly subject_did: string;
  readonly asset_id: string;
  readonly media_type: string;
  readonly size_bytes: number;
  readonly sha256_of_plaintext: string;
  readonly encrypted: boolean;
  /** Present iff `encrypted: true`. */
  readonly amk_envelope?: AMKEnvelope;
  readonly storage: StorageDescriptor;
  readonly attached_context?: AttachedContext;
  readonly referenced_by: readonly AssetReference[];
  readonly created_at: string;
  readonly modified_at: string;
  readonly last_referenced_at?: string;
  readonly state?: AssetState;
  readonly gamma_ref?: string;
}

/* -------------------------------------------------------------------------- */
/*  Key material helpers                                                      */
/* -------------------------------------------------------------------------- */

export interface X25519Keypair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/**
 * Generate a fresh X25519 keypair using @noble/curves.
 *
 * Used by tests and POCs to materialize identity / app keys. Production
 * code derives X25519 keys from sphere seeds via the existing
 * protocol-core identity module; this helper exists only for standalone
 * test scenarios.
 */
export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/* -------------------------------------------------------------------------- */
/*  Hex helpers                                                               */
/* -------------------------------------------------------------------------- */

export function encodeHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}

export function decodeHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error("hex string length must be even");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  Base64 helpers                                                            */
/* -------------------------------------------------------------------------- */

export function encodeBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

export function decodeBase64(s: string): Uint8Array {
  return base64.decode(s);
}

/* -------------------------------------------------------------------------- */
/*  Errors                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Thrown for any cryptographic operation failure. The `code` field
 * maps to the error codes documented in
 * `spec/assets/05-api-primitives.md` §5.5 where applicable.
 */
export class AssetsCryptoError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AssetsCryptoError";
    this.code = code;
  }
}
