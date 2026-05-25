// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Record-level encryption and decryption.
 *
 * Implements `spec/data/02-key-hierarchy.md` §2.4.4 (payload encryption)
 * and the matching decrypt path.
 *
 * Construction:
 *
 *   plaintext   = JCS-canonicalize(payload_object)   // for content addressability
 *   dek         = random(32 bytes)                   // fresh DEK per record
 *   nonce       = random(24 bytes)
 *   aad         = "aithos-data-record-v1\0" ‖ subject_did ‖ "\0" ‖
 *                 collection_name ‖ "\0" ‖ record_id
 *   ciphertext  = XChaCha20Poly1305.encrypt(dek, nonce, aad, plaintext)
 *
 *   dek_wrapped = wrapDEKForCMK(dek, cmk, subject_did, collection_name, record_id)
 *
 * The output bundles the ciphertext, nonce, and wrapped DEK into a
 * RecordPayload envelope.
 */

import { randomBytes } from "./internal/random.js";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { generateDEK, unwrapDEKFromCMK, wrapDEKForCMK } from "./dek.js";
import {
  DataCryptoError,
  decodeBase64,
  encodeBase64,
  type RecordPayload,
} from "./types.js";

const AAD_PREFIX = utf8("aithos-data-record-v1\0");
const NONCE_LENGTH = 24;

/* -------------------------------------------------------------------------- */
/*  Encrypt                                                                   */
/* -------------------------------------------------------------------------- */

export interface EncryptRecordInput {
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
  /**
   * The payload to encrypt. Will be JCS-canonicalized then UTF-8 encoded.
   * Must be JSON-serializable.
   */
  readonly payload: unknown;
  /**
   * The current CMK (32 bytes). The encrypt step generates a fresh DEK,
   * wraps it under the CMK, and includes the wrap in the output.
   */
  readonly cmk: Uint8Array;
}

/**
 * Encrypt a record's payload.
 *
 * Generates a fresh DEK, wraps it under the supplied CMK, encrypts the
 * canonicalized payload under the DEK. Returns the full RecordPayload
 * envelope. The DEK is zeroed before return.
 */
export function encryptRecord(input: EncryptRecordInput): RecordPayload {
  const plaintext = utf8(canonicalize(input.payload));
  const dek = generateDEK();
  try {
    const nonce = new Uint8Array(randomBytes(NONCE_LENGTH));
    const aad = aadForRecord(
      input.subjectDid,
      input.collectionName,
      input.recordId,
    );
    const aead = new XChaCha20Poly1305(dek);
    const ciphertext = aead.seal(nonce, plaintext, aad);

    const wrappedDek = wrapDEKForCMK({
      dek,
      cmk: input.cmk,
      subjectDid: input.subjectDid,
      collectionName: input.collectionName,
      recordId: input.recordId,
    });

    return {
      alg: "xchacha20poly1305-ietf",
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(ciphertext),
      dek_wrapped_for_cmk: wrappedDek,
    };
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Decrypt                                                                   */
/* -------------------------------------------------------------------------- */

export interface DecryptRecordInput {
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
  readonly encrypted: RecordPayload;
  readonly cmk: Uint8Array;
}

/**
 * Decrypt a record's payload.
 *
 * Unwraps the DEK with the supplied CMK, then AEAD-decrypts the
 * ciphertext. Returns the JSON-parsed payload.
 *
 * Throws DataCryptoError on any failure (wrong CMK, tampered ciphertext,
 * AAD mismatch).
 */
export function decryptRecord<T = unknown>(input: DecryptRecordInput): T {
  if (input.encrypted.alg !== "xchacha20poly1305-ietf") {
    throw new DataCryptoError(
      "DATA_RECORD_ALG_UNKNOWN",
      `unknown record AEAD alg "${input.encrypted.alg}"`,
    );
  }

  const dek = unwrapDEKFromCMK({
    wrappedDek: input.encrypted.dek_wrapped_for_cmk,
    cmk: input.cmk,
    subjectDid: input.subjectDid,
    collectionName: input.collectionName,
    recordId: input.recordId,
  });

  try {
    const nonce = decodeBase64(input.encrypted.nonce);
    const ciphertext = decodeBase64(input.encrypted.ciphertext);

    const aad = aadForRecord(
      input.subjectDid,
      input.collectionName,
      input.recordId,
    );
    const aead = new XChaCha20Poly1305(dek);
    const plaintext = aead.open(nonce, ciphertext, aad);

    if (plaintext === null) {
      throw new DataCryptoError(
        "DATA_RECORD_DECRYPT_FAILED",
        "record payload AEAD decryption failed",
      );
    }

    const text = new TextDecoder().decode(plaintext);
    return JSON.parse(text) as T;
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Re-wrap DEK under a new CMK (CMK rotation support)                        */
/* -------------------------------------------------------------------------- */

export interface RewrapRecordDEKInput {
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
  readonly encrypted: RecordPayload;
  readonly oldCmk: Uint8Array;
  readonly newCmk: Uint8Array;
}

/**
 * Re-wrap the DEK from `oldCmk` to `newCmk` without touching the
 * ciphertext.
 *
 * Used during CMK rotation (spec §2.5.2). Mutation cost = 1 AEAD
 * decrypt + 1 AEAD encrypt per record. The payload ciphertext is
 * byte-identical before and after.
 */
export function rewrapRecordDEK(input: RewrapRecordDEKInput): RecordPayload {
  const dek = unwrapDEKFromCMK({
    wrappedDek: input.encrypted.dek_wrapped_for_cmk,
    cmk: input.oldCmk,
    subjectDid: input.subjectDid,
    collectionName: input.collectionName,
    recordId: input.recordId,
  });
  try {
    const newWrappedDek = wrapDEKForCMK({
      dek,
      cmk: input.newCmk,
      subjectDid: input.subjectDid,
      collectionName: input.collectionName,
      recordId: input.recordId,
    });
    return {
      ...input.encrypted,
      dek_wrapped_for_cmk: newWrappedDek,
    };
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Minimal JCS-style canonicalization for record payloads. Sufficient
 * for the value types we encrypt: objects with strings, numbers,
 * booleans, null, arrays. For full RFC 8785 we'd defer to
 * protocol-core's `canonicalize` once data-crypto is folded in; for
 * the POC this inline version is enough.
 */
function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) throw new Error("Cannot canonicalize undefined");
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return value.toString();
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`Cannot canonicalize ${typeof value}`);
}

function aadForRecord(
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
