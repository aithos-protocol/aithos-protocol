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
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import {
  DataCryptoError,
  decodeBase64,
  encodeBase64,
  type WrapEntry,
} from "./types.js";

const AAD_PREFIX = utf8("aithos-data-dek-v1\0");
const NONCE_LENGTH = 24;
const DEK_LENGTH = 32;

/* -- Deposit (append-only) DEK-to-owner wrap constants -- */

/**
 * HKDF salt for the append-only deposit DEK wrap. Distinct from the CMK
 * wrap salt (`aithos-data-cmk-wrap-v1`) so the two key-derivation domains
 * can never collide even though both seal 32-byte keys via X25519-HKDF.
 */
const DEPOSIT_WRAP_SALT = utf8("aithos-data-dek-deposit-wrap-v1");
/**
 * AEAD AAD prefix for the deposit DEK wrap. Bound to
 * (subject_did, collection_name, record_id, recipient_did_url) so a sealed
 * DEK cannot be replayed into another record, collection, or recipient.
 */
const DEPOSIT_AAD_PREFIX = utf8("aithos-data-dek-deposit-v1\0");

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
/*  Deposit wrap — DEK sealed to the owner's X25519 public key (append-only)  */
/* -------------------------------------------------------------------------- */

export interface WrapDEKForRecipientInput {
  /** The 32-byte DEK to seal. */
  readonly dek: Uint8Array;
  /** Recipient's (owner's) X25519 public key (32 bytes). */
  readonly recipientPublicKey: Uint8Array;
  /** DID URL of the recipient key (e.g. "did:aithos:z6Mkr…#data-kex"). */
  readonly recipientDidUrl: string;
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
}

/**
 * Seal a DEK to a recipient's X25519 public key — the append-only deposit
 * primitive.
 *
 * Unlike {@link wrapDEKForCMK} (symmetric, requires the CMK), this is a
 * public-key seal: a depositor who holds ONLY the owner's public key can
 * produce a wrap the owner alone can open. The depositor needs no CMK and
 * therefore gains no read capability. Mirrors `wrapCMKForRecipient` but
 * targets a DEK and binds the AAD to the full record context.
 */
export function wrapDEKForRecipient(input: WrapDEKForRecipientInput): WrapEntry {
  if (input.dek.length !== DEK_LENGTH) {
    throw new DataCryptoError(
      "DATA_DEK_INVALID_LENGTH",
      `DEK must be ${DEK_LENGTH} bytes`,
    );
  }
  if (input.recipientPublicKey.length !== 32) {
    throw new DataCryptoError(
      "DATA_RECIPIENT_PUBKEY_INVALID",
      `recipient X25519 public key must be 32 bytes, got ${input.recipientPublicKey.length}`,
    );
  }

  const ephemeralSk = x25519.utils.randomSecretKey();
  const ephemeralPk = x25519.getPublicKey(ephemeralSk);
  const sharedSecret = x25519.getSharedSecret(
    ephemeralSk,
    input.recipientPublicKey,
  );
  const wrapKey = hkdf(
    sha256,
    sharedSecret,
    DEPOSIT_WRAP_SALT,
    utf8(input.recipientDidUrl),
    32,
  );
  const wrapNonce = new Uint8Array(randomBytes(NONCE_LENGTH));
  const aad = aadForDepositWrap(
    input.subjectDid,
    input.collectionName,
    input.recordId,
    input.recipientDidUrl,
  );
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrappedKey = aead.seal(wrapNonce, input.dek, aad);

  wrapKey.fill(0);
  sharedSecret.fill(0);

  return {
    recipient: input.recipientDidUrl,
    alg: "x25519-hkdf-sha256-aead",
    ephemeral_public: encodeBase64(ephemeralPk),
    wrap_nonce: encodeBase64(wrapNonce),
    wrapped_key: encodeBase64(wrappedKey),
  };
}

export interface UnwrapDEKForRecipientInput {
  /** The deposit wrap entry from the record payload. */
  readonly wrap: WrapEntry;
  /** The recipient's (owner's) X25519 private key (32 bytes). */
  readonly recipientPrivateKey: Uint8Array;
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly recordId: string;
}

/**
 * Recover a DEK from a deposit wrap, given the owner's X25519 private key.
 * Reverse of {@link wrapDEKForRecipient}. Callers SHOULD zero the result.
 */
export function unwrapDEKForRecipient(
  input: UnwrapDEKForRecipientInput,
): Uint8Array {
  if (input.recipientPrivateKey.length !== 32) {
    throw new DataCryptoError(
      "DATA_RECIPIENT_PRIVKEY_INVALID",
      `recipient X25519 private key must be 32 bytes`,
    );
  }
  if (input.wrap.alg !== "x25519-hkdf-sha256-aead") {
    throw new DataCryptoError(
      "DATA_WRAP_ALG_UNKNOWN",
      `unknown wrap algorithm "${input.wrap.alg}"`,
    );
  }

  const ephemeralPk = decodeBase64(input.wrap.ephemeral_public);
  if (ephemeralPk.length !== 32) {
    throw new DataCryptoError(
      "DATA_WRAP_INVALID",
      "ephemeral public key length != 32",
    );
  }
  const wrapNonce = decodeBase64(input.wrap.wrap_nonce);
  if (wrapNonce.length !== NONCE_LENGTH) {
    throw new DataCryptoError(
      "DATA_WRAP_INVALID",
      `wrap nonce length != ${NONCE_LENGTH}`,
    );
  }
  const wrappedKey = decodeBase64(input.wrap.wrapped_key);

  const sharedSecret = x25519.getSharedSecret(
    input.recipientPrivateKey,
    ephemeralPk,
  );
  const wrapKey = hkdf(
    sha256,
    sharedSecret,
    DEPOSIT_WRAP_SALT,
    utf8(input.wrap.recipient),
    32,
  );
  const aad = aadForDepositWrap(
    input.subjectDid,
    input.collectionName,
    input.recordId,
    input.wrap.recipient,
  );
  const aead = new XChaCha20Poly1305(wrapKey);
  const dek = aead.open(wrapNonce, wrappedKey, aad);

  wrapKey.fill(0);
  sharedSecret.fill(0);

  if (dek === null) {
    throw new DataCryptoError(
      "DATA_DEK_DECRYPT_FAILED",
      "deposit DEK unwrap failed — wrong key, tampered wrap, or AAD mismatch",
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
 * AAD for the append-only deposit DEK wrap:
 *
 *   "aithos-data-dek-deposit-v1\0" ‖ subject_did ‖ "\0" ‖ collection_name
 *      ‖ "\0" ‖ record_id ‖ "\0" ‖ recipient_did_url
 */
function aadForDepositWrap(
  subjectDid: string,
  collectionName: string,
  recordId: string,
  recipientDidUrl: string,
): Uint8Array {
  const parts = [subjectDid, collectionName, recordId, recipientDidUrl].map(
    utf8,
  );
  const sep = new Uint8Array([0]);
  let total = DEPOSIT_AAD_PREFIX.length;
  for (let i = 0; i < parts.length; i++) {
    total += parts[i].length + (i < parts.length - 1 ? sep.length : 0);
  }
  const out = new Uint8Array(total);
  let off = 0;
  out.set(DEPOSIT_AAD_PREFIX, off);
  off += DEPOSIT_AAD_PREFIX.length;
  for (let i = 0; i < parts.length; i++) {
    out.set(parts[i], off);
    off += parts[i].length;
    if (i < parts.length - 1) {
      out.set(sep, off);
      off += sep.length;
    }
  }
  return out;
}

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
