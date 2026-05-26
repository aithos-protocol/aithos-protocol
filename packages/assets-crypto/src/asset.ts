// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Asset bytes encryption and decryption.
 *
 * Implements `spec/assets/02-key-hierarchy.md` §2.3.2 and §2.3.6.
 *
 * Encryption (private regime):
 *
 *   nonce      = random(24 bytes)
 *   aad        = "aithos-asset-v1\0" ‖ utf8(asset_urn)
 *   ciphertext = XChaCha20-Poly1305.encrypt(amk, nonce, aad, plaintext)
 *
 * On-disk layout in S3 (the "nonce-prefix" layout, §2.3.2):
 *
 *   [ nonce: 24 bytes | ciphertext: N bytes | poly1305 tag: 16 bytes ]
 *
 * The encoder returns this concatenated blob ready to PUT to S3 as-is.
 * The decoder accepts the same blob layout and the AMK to recover the
 * plaintext.
 *
 * Public regime: the bytes are stored as plaintext directly (no AMK,
 * no nonce, no AAD). Integrity is verified solely by SHA-256 of the
 * plaintext (§2.6). This module exposes `verifyPlaintextHash` for that
 * purpose; it does not perform any "encryption" on public bytes.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { randomBytes } from "./internal/random.js";
import { aadForAssetBytes } from "./aad.js";
import {
  AssetsCryptoError,
  decodeBase64,
  encodeBase64,
  encodeHex,
} from "./types.js";

const NONCE_LENGTH = 24;
const POLY_TAG_LENGTH = 16;

/* -------------------------------------------------------------------------- */
/*  Encrypt                                                                   */
/* -------------------------------------------------------------------------- */

export interface EncryptAssetInput {
  /** The 32-byte AMK. */
  readonly amk: Uint8Array;
  /** Asset URN — bound into the AEAD AAD. */
  readonly assetUrn: string;
  /** The plaintext bytes to encrypt. */
  readonly plaintext: Uint8Array;
  /**
   * OPTIONAL — caller-supplied nonce. If omitted, a fresh 24-byte
   * nonce is drawn from the CSPRNG. Supplying a nonce is reserved for
   * deterministic test vectors and AMK rotation flows; never reuse a
   * (AMK, nonce) pair in production.
   */
  readonly nonce?: Uint8Array;
}

export interface EncryptAssetOutput {
  /**
   * The S3 blob to upload: 24-byte nonce ‖ ciphertext+tag. This is the
   * exact byte sequence written to `s3://.../<asset_id>/raw.bin`.
   */
  readonly blob: Uint8Array;
  /** The nonce used (base64), to record in the AMK envelope. */
  readonly nonce_b64: string;
  /** SHA-256 of the plaintext (hex), to record in the asset metadata. */
  readonly sha256_of_plaintext_hex: string;
  /** Size of the plaintext in bytes, to record in the asset metadata. */
  readonly size_bytes: number;
}

/**
 * Encrypt asset bytes under the given AMK, returning the on-disk blob
 * (nonce-prefix layout) plus the metadata fields needed to record the
 * asset.
 */
export function encryptAssetBytes(input: EncryptAssetInput): EncryptAssetOutput {
  if (input.amk.length !== 32) {
    throw new AssetsCryptoError(
      "ASSETS_AMK_INVALID_LENGTH",
      `AMK must be 32 bytes, got ${input.amk.length}`,
    );
  }
  if (input.nonce && input.nonce.length !== NONCE_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_NONCE_INVALID_LENGTH",
      `nonce must be ${NONCE_LENGTH} bytes, got ${input.nonce.length}`,
    );
  }

  const nonce = input.nonce ?? new Uint8Array(randomBytes(NONCE_LENGTH));
  const aad = aadForAssetBytes(input.assetUrn);

  const aead = new XChaCha20Poly1305(input.amk);
  const ciphertext = aead.seal(nonce, input.plaintext, aad);

  // Compose the nonce-prefix blob.
  const blob = new Uint8Array(NONCE_LENGTH + ciphertext.length);
  blob.set(nonce, 0);
  blob.set(ciphertext, NONCE_LENGTH);

  // Compute SHA-256 of plaintext (content address).
  const sha = sha256(input.plaintext);

  return {
    blob,
    nonce_b64: encodeBase64(nonce),
    sha256_of_plaintext_hex: encodeHex(sha),
    size_bytes: input.plaintext.length,
  };
}

/* -------------------------------------------------------------------------- */
/*  Decrypt                                                                   */
/* -------------------------------------------------------------------------- */

export interface DecryptAssetInput {
  /** The 32-byte AMK (typically unwrapped from a WrapEntry). */
  readonly amk: Uint8Array;
  /** Asset URN — must match what was bound at encrypt time. */
  readonly assetUrn: string;
  /**
   * The on-disk blob in nonce-prefix layout: 24-byte nonce ‖ ciphertext+tag.
   * This is what `encryptAssetBytes` produces and what S3 stores.
   */
  readonly blob: Uint8Array;
  /**
   * OPTIONAL — the expected SHA-256 of the plaintext (hex). If
   * provided, the decoder verifies the match and throws on
   * mismatch. RECOMMENDED for the spec §3.4.3 integrity check 2.
   */
  readonly expectedSha256Hex?: string;
}

/**
 * Decrypt asset bytes and verify integrity.
 *
 * Returns the plaintext as a fresh Uint8Array. Throws on AEAD failure
 * (tampering, AAD mismatch) or hash mismatch (if `expectedSha256Hex`
 * was supplied).
 */
export function decryptAssetBytes(input: DecryptAssetInput): Uint8Array {
  if (input.amk.length !== 32) {
    throw new AssetsCryptoError(
      "ASSETS_AMK_INVALID_LENGTH",
      `AMK must be 32 bytes, got ${input.amk.length}`,
    );
  }
  if (input.blob.length < NONCE_LENGTH + POLY_TAG_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_BLOB_TOO_SHORT",
      `blob length ${input.blob.length} is too short to contain a nonce-prefixed ciphertext`,
    );
  }

  const nonce = input.blob.subarray(0, NONCE_LENGTH);
  const ciphertext = input.blob.subarray(NONCE_LENGTH);
  const aad = aadForAssetBytes(input.assetUrn);

  const aead = new XChaCha20Poly1305(input.amk);
  const plaintext = aead.open(nonce, ciphertext, aad);

  if (plaintext === null) {
    throw new AssetsCryptoError(
      "ASSETS_DECRYPT_FAILED",
      "asset bytes decrypt failed — wrong AMK, tampered ciphertext, or AAD mismatch",
    );
  }

  if (input.expectedSha256Hex !== undefined) {
    const actualHex = encodeHex(sha256(plaintext));
    if (actualHex !== input.expectedSha256Hex.toLowerCase()) {
      throw new AssetsCryptoError(
        "ASSETS_HASH_MISMATCH",
        `decrypted plaintext SHA-256 ${actualHex} does not match expected ${input.expectedSha256Hex}`,
      );
    }
  }

  return new Uint8Array(plaintext);
}

/* -------------------------------------------------------------------------- */
/*  Plaintext hash (public regime)                                            */
/* -------------------------------------------------------------------------- */

/**
 * Compute the SHA-256 of the plaintext bytes, returned as lower-case
 * hex. Used by:
 *  - the upload-init flow to declare `sha256_of_plaintext` before
 *    uploading,
 *  - the public-asset fetch flow to verify integrity against the
 *    metadata's declared hash (§3.4.3 check 2).
 */
export function plaintextSha256Hex(plaintext: Uint8Array): string {
  return encodeHex(sha256(plaintext));
}

/**
 * Verify that the supplied plaintext bytes hash to the expected
 * lower-case hex SHA-256. Throws on mismatch. Used for public-asset
 * integrity checks (§2.6).
 */
export function verifyPlaintextHash(
  plaintext: Uint8Array,
  expectedSha256Hex: string,
): void {
  const actualHex = plaintextSha256Hex(plaintext);
  if (actualHex !== expectedSha256Hex.toLowerCase()) {
    throw new AssetsCryptoError(
      "ASSETS_HASH_MISMATCH",
      `plaintext SHA-256 ${actualHex} does not match expected ${expectedSha256Hex}`,
    );
  }
}

/* -------------------------------------------------------------------------- */
/*  Blob inspection helpers                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Extract the 24-byte nonce from an on-disk blob (the leading bytes).
 * Useful when the caller wants to record the nonce in metadata without
 * decrypting.
 */
export function extractBlobNonce(blob: Uint8Array): Uint8Array {
  if (blob.length < NONCE_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_BLOB_TOO_SHORT",
      `blob length ${blob.length} is smaller than the nonce length ${NONCE_LENGTH}`,
    );
  }
  return blob.subarray(0, NONCE_LENGTH);
}

/**
 * Compose a blob given a nonce and a ciphertext-with-tag. Useful for
 * recomposing a blob from base64-encoded fields without re-encrypting.
 */
export function composeBlob(
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array {
  if (nonce.length !== NONCE_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_NONCE_INVALID_LENGTH",
      `nonce length must be ${NONCE_LENGTH}, got ${nonce.length}`,
    );
  }
  const out = new Uint8Array(NONCE_LENGTH + ciphertextWithTag.length);
  out.set(nonce, 0);
  out.set(ciphertextWithTag, NONCE_LENGTH);
  return out;
}

/** Re-export base64 decode for callers that round-trip a nonce. */
export { decodeBase64 };
