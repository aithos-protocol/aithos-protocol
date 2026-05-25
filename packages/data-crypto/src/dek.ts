// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Data Encryption Key (DEK) generation, wrap under a CMK, unwrap.
 *
 * Implements `spec/data/02-key-hierarchy.md` §2.4.
 *
 * Construction:
 *
 *   wrap_nonce  = random(24 bytes)
 *   aad         = "aithos-data-dek-v1\0" ‖ subject_did ‖ "\0" ‖
 *                 collection_name ‖ "\0" ‖ record_id
 *   dek_wrapped = XChaCha20Poly1305.encrypt(cmk, wrap_nonce, aad, dek)
 *
 * Serialization: nonce ‖ ciphertext, base64-encoded.
 *
 * The AAD binding to (subject_did, collection_name, record_id) prevents
 * replay of a wrapped DEK from one record into another.
 */

import { randomBytes } from "./internal/random.js";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import {
  DataCryptoError,
  decodeBase64,
  encodeBase64,
} from "./types.js";

const AAD_PREFIX = utf8("aithos-data-dek-v1\0");
const NONCE_LENGTH = 24;
const DEK_LENGTH = 32;

/* -------------------------------------------------------------------------- */
/*  DEK generation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Generate a fresh 32-byte DEK using the OS CSPRNG.
 */
export function generateDEK(): Uint8Array {
  return new Uint8Array(randomBytes(DEK_LENGTH));
}

/* -------------------------------------------------------------------------- */
/*  Wrap                                                                      */
/* -------------------------------------------------------------------------- */

export interface WrapDEKInput {
  /** The 32-byte DEK to wrap. */
  readonly dek: Uint8Array;
  /** The CMK as a 32-byte symmetric key. */
  readonly cmk: Uint8Array;
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
}

/**
 * Wrap the DEK under the CMK using XChaCha20-Poly1305 with AAD bound
 * to (subject_did, collection_name, record_id).
 *
 * Returns a base64 string of `nonce ‖ ciphertext`. The serialization
 * format keeps the wrap in a single field of the record's payload
 * envelope (`dek_wrapped_for_cmk`).
 */
export function wrapDEKForCMK(input: WrapDEKInput): string {
  if (input.dek.length !== DEK_LENGTH) {
    throw new DataCryptoError(
      "DATA_DEK_INVALID_LENGTH",
      `DEK must be ${DEK_LENGTH} bytes`,
    );
  }
  if (input.cmk.length !== 32) {
    throw new DataCryptoError(
      "DATA_CMK_INVALID_LENGTH",
      `CMK must be 32 bytes`,
    );
  }

  const wrapNonce = new Uint8Array(randomBytes(NONCE_LENGTH));
  const aad = aadForDEKWrap(
    input.subjectDid,
    input.collectionName,
    input.recordId,
  );
  const aead = new XChaCha20Poly1305(input.cmk);
  const ciphertext = aead.seal(wrapNonce, input.dek, aad);

  // Serialize as nonce ‖ ciphertext
  const out = new Uint8Array(wrapNonce.length + ciphertext.length);
  out.set(wrapNonce, 0);
  out.set(ciphertext, wrapNonce.length);
  return encodeBase64(out);
}

/* -------------------------------------------------------------------------- */
/*  Unwrap                                                                    */
/* -------------------------------------------------------------------------- */

export interface UnwrapDEKInput {
  /** Serialized wrap (base64 of nonce ‖ ciphertext). */
  readonly wrappedDek: string;
  /** The CMK. */
  readonly cmk: Uint8Array;
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
}

/**
 * Recover the DEK from its wrap.
 *
 * Returns the 32-byte DEK. Callers SHOULD zero it after use.
 *
 * Throws DataCryptoError on any failure.
 */
export function unwrapDEKFromCMK(input: UnwrapDEKInput): Uint8Array {
  if (input.cmk.length !== 32) {
    throw new DataCryptoError(
      "DATA_CMK_INVALID_LENGTH",
      `CMK must be 32 bytes`,
    );
  }

  const buffer = decodeBase64(input.wrappedDek);
  if (buffer.length < NONCE_LENGTH + 16) {
    throw new DataCryptoError(
      "DATA_DEK_WRAP_MALFORMED",
      `wrapped DEK too short: ${buffer.length} bytes (need >= ${NONCE_LENGTH + 16})`,
    );
  }
  const wrapNonce = buffer.slice(0, NONCE_LENGTH);
  const ciphertext = buffer.slice(NONCE_LENGTH);

  const aad = aadForDEKWrap(
    input.subjectDid,
    input.collectionName,
    input.recordId,
  );
  const aead = new XChaCha20Poly1305(input.cmk);
  const dek = aead.open(wrapNonce, ciphertext, aad);

  if (dek === null) {
    throw new DataCryptoError(
      "DATA_DEK_DECRYPT_FAILED",
      "DEK unwrap failed — wrong CMK, tampered wrap, or AAD mismatch (collection/record)",
    );
  }
  if (dek.length !== DEK_LENGTH) {
    throw new DataCryptoError(
      "DATA_DEK_INVALID_LENGTH",
      `unwrapped DEK has wrong length ${dek.length}`,
    );
  }

  return dek;
}

/* -------------------------------------------------------------------------- */
/*  AAD construction                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Compose the AEAD additional-data bytes for a DEK wrap:
 *
 *   "aithos-data-dek-v1\0" ‖ utf8(subject_did) ‖ "\0" ‖
 *      utf8(collection_name) ‖ "\0" ‖ utf8(record_id)
 *
 * Spec ref: §2.4.2.
 */
function aadForDEKWrap(
  subjectDid: string,
  collectionName: string,
  recordId: string,
): Uint8Array {
  const s = utf8(subjectDid);
  const c = utf8(collectionName);
  const r = utf8(recordId);
  const sep = new Uint8Array([0]);
  const total = AAD_PREFIX.length + s.length + sep.length + c.length + sep.length + r.length;
  const out = new Uint8Array(total);
  let off = 0;
  out.set(AAD_PREFIX, off);
  off += AAD_PREFIX.length;
  out.set(s, off);
  off += s.length;
  out.set(sep, off);
  off += sep.length;
  out.set(c, off);
  off += c.length;
  out.set(sep, off);
  off += sep.length;
  out.set(r, off);
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
