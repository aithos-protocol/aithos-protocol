// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Asset Master Key (AMK) generation, wrap, unwrap.
 *
 * Implements `spec/assets/02-key-hierarchy.md` §2.3:
 *
 *   - `generateAMK` — fresh 32-byte symmetric key from the CSPRNG.
 *   - `wrapAMKForRecipient` — X25519-HKDF-SHA256-AEAD wrap addressed
 *     to one recipient's X25519 public key.
 *   - `unwrapAMK` — reverse, given the recipient's X25519 private key
 *     and the matching wrap entry.
 *
 * The wrap construction:
 *
 *   shared_secret = X25519(ephemeral_sk, recipient_pk)
 *   wrap_key      = HKDF-SHA256(shared_secret, salt, info, 32)
 *   wrap_nonce    = random(24 bytes)
 *   aad           = "aithos-assets-amk-v1\0" ‖ asset_urn ‖ "\0" ‖ recipient_did_url
 *   wrapped_key   = XChaCha20Poly1305.encrypt(wrap_key, wrap_nonce, aad, amk)
 *
 *   salt = "aithos-assets-amk-wrap-v1"
 *   info = recipient_did_url
 *
 * AAD binding to asset_urn and recipient_did_url prevents replay
 * across assets and across recipients within the same asset.
 */

import { randomBytes } from "./internal/random.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { aadForAMKWrap, HKDF_WRAP_SALT } from "./aad.js";
import {
  AssetsCryptoError,
  decodeBase64,
  encodeBase64,
  type WrapEntry,
} from "./types.js";

const NONCE_LENGTH = 24;
const AMK_LENGTH = 32;

/* -------------------------------------------------------------------------- */
/*  AMK generation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Generate a fresh 32-byte AMK using the OS CSPRNG.
 *
 * The returned buffer is sensitive — callers SHOULD zero it after
 * wrapping (`amk.fill(0)`) and SHOULD NOT serialize it in any form
 * except inside a wrap.
 */
export function generateAMK(): Uint8Array {
  return new Uint8Array(randomBytes(AMK_LENGTH));
}

/* -------------------------------------------------------------------------- */
/*  Wrap                                                                      */
/* -------------------------------------------------------------------------- */

export interface WrapAMKInput {
  /** The 32-byte AMK to wrap. */
  readonly amk: Uint8Array;
  /** Recipient's X25519 public key (32 bytes). */
  readonly recipientPublicKey: Uint8Array;
  /** DID URL of the recipient (e.g. "did:aithos:z6Mkr…#circle-kex"). */
  readonly recipientDidUrl: string;
  /** Asset URN — bound into the AEAD AAD. */
  readonly assetUrn: string;
}

/**
 * Produce a wrap of the AMK addressed to one recipient.
 *
 * The construction generates a fresh ephemeral X25519 keypair per wrap,
 * so two calls with identical inputs produce different wraps. This is
 * intentional: the ephemeral key avoids replay properties tied to
 * deterministic wraps.
 */
export function wrapAMKForRecipient(input: WrapAMKInput): WrapEntry {
  if (input.amk.length !== AMK_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_AMK_INVALID_LENGTH",
      `AMK must be ${AMK_LENGTH} bytes, got ${input.amk.length}`,
    );
  }
  if (input.recipientPublicKey.length !== 32) {
    throw new AssetsCryptoError(
      "ASSETS_RECIPIENT_PUBKEY_INVALID",
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
    HKDF_WRAP_SALT,
    utf8(input.recipientDidUrl),
    32,
  );

  // Fresh nonce
  const wrapNonce = new Uint8Array(randomBytes(NONCE_LENGTH));

  // AAD binding the wrap to (asset_urn, recipient_did_url)
  const aad = aadForAMKWrap(input.assetUrn, input.recipientDidUrl);

  // XChaCha20-Poly1305 encrypt of the AMK
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrappedKey = aead.seal(wrapNonce, input.amk, aad);

  // Zero sensitive intermediates
  wrapKey.fill(0);
  sharedSecret.fill(0);
  ephemeralSk.fill(0);

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

export interface UnwrapAMKInput {
  /** The wrap entry addressed to this recipient. */
  readonly wrap: WrapEntry;
  /** The recipient's X25519 private key. */
  readonly recipientPrivateKey: Uint8Array;
  /** Asset URN — must match what was bound at wrap time. */
  readonly assetUrn: string;
}

/**
 * Recover the 32-byte AMK from a wrap, given the recipient's X25519
 * private key.
 *
 * Returns the AMK as a fresh Uint8Array. Callers SHOULD zero it after
 * use.
 *
 * Throws AssetsCryptoError on any decryption failure (tampering, wrong
 * key, AAD mismatch, malformed wrap).
 */
export function unwrapAMK(input: UnwrapAMKInput): Uint8Array {
  if (input.recipientPrivateKey.length !== 32) {
    throw new AssetsCryptoError(
      "ASSETS_RECIPIENT_PRIVKEY_INVALID",
      `recipient X25519 private key must be 32 bytes`,
    );
  }
  if (input.wrap.alg !== "x25519-hkdf-sha256-aead") {
    throw new AssetsCryptoError(
      "ASSETS_WRAP_ALG_UNKNOWN",
      `unknown wrap algorithm "${input.wrap.alg}"`,
    );
  }

  const ephemeralPk = decodeBase64(input.wrap.ephemeral_public);
  if (ephemeralPk.length !== 32) {
    throw new AssetsCryptoError(
      "ASSETS_WRAP_INVALID",
      "ephemeral public key length != 32",
    );
  }
  const wrapNonce = decodeBase64(input.wrap.wrap_nonce);
  if (wrapNonce.length !== NONCE_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_WRAP_INVALID",
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
    HKDF_WRAP_SALT,
    utf8(input.wrap.recipient),
    32,
  );

  const aad = aadForAMKWrap(input.assetUrn, input.wrap.recipient);

  const aead = new XChaCha20Poly1305(wrapKey);
  const amk = aead.open(wrapNonce, wrappedKey, aad);

  // Zero sensitive intermediates
  wrapKey.fill(0);
  sharedSecret.fill(0);

  if (amk === null) {
    throw new AssetsCryptoError(
      "ASSETS_WRAP_DECRYPT_FAILED",
      "AMK unwrap failed — wrong key, tampered wrap, or AAD mismatch",
    );
  }
  if (amk.length !== AMK_LENGTH) {
    throw new AssetsCryptoError(
      "ASSETS_AMK_INVALID_LENGTH",
      `unwrapped AMK has wrong length ${amk.length}`,
    );
  }

  return amk;
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
