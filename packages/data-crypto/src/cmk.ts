// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Collection Master Key (CMK) generation, wrap, unwrap.
 *
 * Implements `spec/data/02-key-hierarchy.md` §2.3:
 *
 *   - `generateCMK` — fresh 32-byte symmetric key from the CSPRNG.
 *   - `wrapCMKForRecipient` — X25519-HKDF-SHA256-AEAD wrap addressed
 *     to one recipient's X25519 public key.
 *   - `unwrapCMK` — reverse, given the recipient's X25519 private key
 *     and the matching wrap entry.
 *
 * The wrap construction:
 *
 *   shared_secret = X25519(ephemeral_sk, recipient_pk)
 *   wrap_key      = HKDF-SHA256(shared_secret, salt, info, 32)
 *   wrap_nonce    = random(24 bytes)
 *   aad           = "aithos-data-cmk-v1\0" ‖ collection_urn ‖ "\0" ‖ recipient_did_url
 *   wrapped_key   = XChaCha20Poly1305.encrypt(wrap_key, wrap_nonce, aad, cmk)
 *
 *   salt = "aithos-data-cmk-wrap-v1"
 *   info = recipient_did_url
 *
 * AAD binding to collection_urn and recipient_did_url prevents replay
 * across collections and across recipients within the same collection.
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

const WRAP_SALT = utf8("aithos-data-cmk-wrap-v1");
const AAD_PREFIX = utf8("aithos-data-cmk-v1\0");
const NONCE_LENGTH = 24;
const CMK_LENGTH = 32;

/* -------------------------------------------------------------------------- */
/*  CMK generation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Generate a fresh 32-byte CMK using the OS CSPRNG.
 *
 * The returned buffer is sensitive — callers SHOULD zero it after wrapping
 * (`cmk.fill(0)`) and SHOULD NOT serialize it in any form except inside
 * a wrap.
 */
export function generateCMK(): Uint8Array {
  return new Uint8Array(randomBytes(CMK_LENGTH));
}

/* -------------------------------------------------------------------------- */
/*  Wrap                                                                      */
/* -------------------------------------------------------------------------- */

export interface WrapCMKInput {
  /** The 32-byte CMK to wrap. */
  readonly cmk: Uint8Array;
  /** Recipient's X25519 public key (32 bytes). */
  readonly recipientPublicKey: Uint8Array;
  /** DID URL of the recipient (e.g. "did:aithos:z6Mkr…#data-kex"). */
  readonly recipientDidUrl: string;
  /** Collection URN — bound into the AEAD AAD. */
  readonly collectionUrn: string;
}

/**
 * Produce a wrap of the CMK addressed to one recipient.
 *
 * The construction generates a fresh ephemeral X25519 keypair per wrap,
 * so two calls with identical inputs produce different wraps. This is
 * intentional: the ephemeral key avoids replay properties tied to
 * deterministic wraps.
 */
export function wrapCMKForRecipient(input: WrapCMKInput): WrapEntry {
  if (input.cmk.length !== CMK_LENGTH) {
    throw new DataCryptoError(
      "DATA_CMK_INVALID_LENGTH",
      `CMK must be ${CMK_LENGTH} bytes, got ${input.cmk.length}`,
    );
  }
  if (input.recipientPublicKey.length !== 32) {
    throw new DataCryptoError(
      "DATA_RECIPIENT_PUBKEY_INVALID",
      `recipient X25519 public key must be 32 bytes, got ${input.recipientPublicKey.length}`,
    );
  }

  // Generate ephemeral X25519 keypair for this wrap.
  const ephemeralSk = x25519.utils.randomSecretKey();
  const ephemeralPk = x25519.getPublicKey(ephemeralSk);

  // ECDH
  const sharedSecret = x25519.getSharedSecret(
    ephemeralSk,
    input.recipientPublicKey,
  );

  // HKDF to derive the wrap key
  const wrapKey = hkdf(
    sha256,
    sharedSecret,
    WRAP_SALT,
    utf8(input.recipientDidUrl),
    32,
  );

  // Fresh nonce
  const wrapNonce = new Uint8Array(randomBytes(NONCE_LENGTH));

  // AAD binding the wrap to (collection_urn, recipient_did_url)
  const aad = aadForCMKWrap(input.collectionUrn, input.recipientDidUrl);

  // XChaCha20-Poly1305 encrypt of the CMK
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrappedKey = aead.seal(wrapNonce, input.cmk, aad);

  // Zero the wrap key (sensitive) - the local Uint8Array goes out of scope
  // but we explicitly fill to be safe.
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

/* -------------------------------------------------------------------------- */
/*  Unwrap                                                                    */
/* -------------------------------------------------------------------------- */

export interface UnwrapCMKInput {
  /** The wrap entry addressed to this recipient. */
  readonly wrap: WrapEntry;
  /** The recipient's X25519 private key. */
  readonly recipientPrivateKey: Uint8Array;
  /** Collection URN — must match what was bound at wrap time. */
  readonly collectionUrn: string;
}

/**
 * Recover the 32-byte CMK from a wrap, given the recipient's X25519
 * private key.
 *
 * Returns the CMK as a fresh Uint8Array. Callers SHOULD zero it after
 * use.
 *
 * Throws DataCryptoError on any decryption failure (tampering, wrong
 * key, AAD mismatch, malformed wrap).
 */
export function unwrapCMK(input: UnwrapCMKInput): Uint8Array {
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

  // ECDH from recipient side
  const sharedSecret = x25519.getSharedSecret(
    input.recipientPrivateKey,
    ephemeralPk,
  );

  const wrapKey = hkdf(
    sha256,
    sharedSecret,
    WRAP_SALT,
    utf8(input.wrap.recipient),
    32,
  );

  const aad = aadForCMKWrap(input.collectionUrn, input.wrap.recipient);

  const aead = new XChaCha20Poly1305(wrapKey);
  const cmk = aead.open(wrapNonce, wrappedKey, aad);

  // Zero sensitive intermediates
  wrapKey.fill(0);
  sharedSecret.fill(0);

  if (cmk === null) {
    throw new DataCryptoError(
      "DATA_WRAP_DECRYPT_FAILED",
      "CMK unwrap failed — wrong key, tampered wrap, or AAD mismatch",
    );
  }
  if (cmk.length !== CMK_LENGTH) {
    throw new DataCryptoError(
      "DATA_CMK_INVALID_LENGTH",
      `unwrapped CMK has wrong length ${cmk.length}`,
    );
  }

  return cmk;
}

/* -------------------------------------------------------------------------- */
/*  AAD construction                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Compose the AEAD additional-data bytes for a CMK wrap:
 *
 *   "aithos-data-cmk-v1\0" ‖ utf8(collection_urn) ‖ "\0" ‖ utf8(recipient_did_url)
 *
 * Spec ref: §2.3.2.
 */
function aadForCMKWrap(collectionUrn: string, recipientDidUrl: string): Uint8Array {
  const c = utf8(collectionUrn);
  const r = utf8(recipientDidUrl);
  const sep = new Uint8Array([0]);
  const total = AAD_PREFIX.length + c.length + sep.length + r.length;
  const out = new Uint8Array(total);
  let off = 0;
  out.set(AAD_PREFIX, off);
  off += AAD_PREFIX.length;
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
