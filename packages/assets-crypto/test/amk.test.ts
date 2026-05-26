// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Test vectors for AMK generation, wrap, and unwrap.
 *
 * Covers spec/assets/02-key-hierarchy.md §2.8 scenarios:
 *   - AMK generation + wrap + unwrap roundtrip
 *   - Wrap AAD binding to (asset_urn, recipient_did_url)
 *   - Recipient binding: a wrap to A is not openable by B
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import {
  generateAMK,
  wrapAMKForRecipient,
  unwrapAMK,
  generateX25519Keypair,
  AssetsCryptoError,
} from "../src/index.js";

const ASSET_URN_A = "urn:aithos:asset:did:aithos:z6MkrAAA:asset_01J9YB2X7Q";
const ASSET_URN_B = "urn:aithos:asset:did:aithos:z6MkrAAA:asset_01J9YB2X7R";
const RECIPIENT_A = "did:aithos:z6MkrAAA#circle-kex";
const RECIPIENT_B = "did:key:z6MkBBB#switchia-kex";

describe("AMK roundtrip", () => {
  it("wrap then unwrap recovers the original AMK byte-for-byte", () => {
    const amk = generateAMK();
    const { privateKey, publicKey } = generateX25519Keypair();

    const wrap = wrapAMKForRecipient({
      amk,
      recipientPublicKey: publicKey,
      recipientDidUrl: RECIPIENT_A,
      assetUrn: ASSET_URN_A,
    });

    const recovered = unwrapAMK({
      wrap,
      recipientPrivateKey: privateKey,
      assetUrn: ASSET_URN_A,
    });

    assert.equal(recovered.length, 32);
    assert.deepEqual(Array.from(recovered), Array.from(amk));
  });

  it("two wraps of the same AMK to the same recipient produce different ciphertexts (ephemeral key randomization)", () => {
    const amk = generateAMK();
    const { publicKey } = generateX25519Keypair();

    const wrap1 = wrapAMKForRecipient({
      amk,
      recipientPublicKey: publicKey,
      recipientDidUrl: RECIPIENT_A,
      assetUrn: ASSET_URN_A,
    });
    const wrap2 = wrapAMKForRecipient({
      amk,
      recipientPublicKey: publicKey,
      recipientDidUrl: RECIPIENT_A,
      assetUrn: ASSET_URN_A,
    });

    assert.notEqual(wrap1.ephemeral_public, wrap2.ephemeral_public);
    assert.notEqual(wrap1.wrap_nonce, wrap2.wrap_nonce);
    assert.notEqual(wrap1.wrapped_key, wrap2.wrapped_key);
  });
});

describe("AMK wrap AAD binding", () => {
  it("a wrap bound to asset_urn A cannot be unwrapped with asset_urn B", () => {
    const amk = generateAMK();
    const { privateKey, publicKey } = generateX25519Keypair();

    const wrap = wrapAMKForRecipient({
      amk,
      recipientPublicKey: publicKey,
      recipientDidUrl: RECIPIENT_A,
      assetUrn: ASSET_URN_A,
    });

    assert.throws(
      () =>
        unwrapAMK({
          wrap,
          recipientPrivateKey: privateKey,
          assetUrn: ASSET_URN_B, // wrong URN
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError &&
        err.code === "ASSETS_WRAP_DECRYPT_FAILED",
    );
  });

  it("a wrap bound to recipient A cannot be unwrapped with recipient B's key (even if recipient field matches A)", () => {
    const amk = generateAMK();
    const aKeys = generateX25519Keypair();
    const bKeys = generateX25519Keypair();

    const wrap = wrapAMKForRecipient({
      amk,
      recipientPublicKey: aKeys.publicKey,
      recipientDidUrl: RECIPIENT_A,
      assetUrn: ASSET_URN_A,
    });

    // Use B's private key, but keep the wrap's recipient field saying A
    // (the AAD will compute with A, but ECDH will use B's key against
    // the ephemeral, yielding a wrong shared secret).
    assert.throws(
      () =>
        unwrapAMK({
          wrap,
          recipientPrivateKey: bKeys.privateKey,
          assetUrn: ASSET_URN_A,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError &&
        err.code === "ASSETS_WRAP_DECRYPT_FAILED",
    );
  });
});

describe("AMK independence", () => {
  it("compromising one asset's AMK does not affect another asset's AMK", () => {
    const amkA = generateAMK();
    const amkB = generateAMK();
    // Two distinct random AMKs MUST differ (probability of collision is negligible)
    assert.notDeepEqual(Array.from(amkA), Array.from(amkB));
  });
});

describe("AMK input validation", () => {
  it("rejects an AMK of wrong length on wrap", () => {
    const { publicKey } = generateX25519Keypair();
    const badAmk = new Uint8Array(31); // wrong length
    assert.throws(
      () =>
        wrapAMKForRecipient({
          amk: badAmk,
          recipientPublicKey: publicKey,
          recipientDidUrl: RECIPIENT_A,
          assetUrn: ASSET_URN_A,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError &&
        err.code === "ASSETS_AMK_INVALID_LENGTH",
    );
  });

  it("rejects a public key of wrong length on wrap", () => {
    const amk = generateAMK();
    const badPk = new Uint8Array(31);
    assert.throws(
      () =>
        wrapAMKForRecipient({
          amk,
          recipientPublicKey: badPk,
          recipientDidUrl: RECIPIENT_A,
          assetUrn: ASSET_URN_A,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError &&
        err.code === "ASSETS_RECIPIENT_PUBKEY_INVALID",
    );
  });
});
