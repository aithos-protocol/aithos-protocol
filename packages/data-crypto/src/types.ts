// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Shared types for the Aithos data sub-protocol crypto primitives.
 *
 * Mirrors the wire format described in `spec/data/02-key-hierarchy.md`.
 * Binary values are kept as `Uint8Array` in memory; serialization to JSON
 * uses base64 encoding via the helpers in this module.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { base64 } from "@scure/base";

/* -------------------------------------------------------------------------- */
/*  Wraps                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * A wrap of a symmetric key (CMK or DEK) addressed to one recipient.
 *
 * Spec ref: `spec/data/02-key-hierarchy.md` §2.3.2.
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
  /** AEAD ciphertext of the wrapped key (base64). */
  readonly wrapped_key: string;
}

/**
 * The Collection Master Key envelope — what the manifest stores.
 *
 * Spec ref: `spec/data/02-key-hierarchy.md` §2.3.3.
 */
export interface CMKEnvelope {
  /** Algorithm identifier. v0.1: "xchacha20poly1305-ietf". */
  readonly alg: "xchacha20poly1305-ietf";
  /** One wrap per authorized recipient (owner + grantees). */
  readonly wraps: readonly WrapEntry[];
}

/* -------------------------------------------------------------------------- */
/*  Records                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The payload envelope of a record.
 *
 * Spec ref: `spec/data/01-data-model.md` §1.3.4.
 */
export interface RecordPayload {
  readonly alg: "xchacha20poly1305-ietf";
  /** 24-byte AEAD nonce (base64). */
  readonly nonce: string;
  /** AEAD ciphertext of the payload (base64). */
  readonly ciphertext: string;
  /** DEK wrapped for the collection's CMK (nonce ‖ ciphertext, base64). */
  readonly dek_wrapped_for_cmk: string;
}

/* -------------------------------------------------------------------------- */
/*  Collection (in-memory representation for the POC)                         */
/* -------------------------------------------------------------------------- */

/**
 * Collection metadata as held in memory by the POC. The backend (Jalon 3)
 * will persist a richer document; here we keep only what the crypto
 * primitives need to operate.
 */
export interface CollectionDoc {
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly schema: string;
  readonly createdAt: string;
  readonly cmkEnvelope: CMKEnvelope;
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
 * Thrown for any cryptographic operation failure. The `code` field maps
 * to the error codes documented in `spec/data/05-api-primitives.md` §5.7
 * where applicable.
 */
export class DataCryptoError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DataCryptoError";
    this.code = code;
  }
}
