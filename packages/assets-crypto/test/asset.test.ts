// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Test vectors for asset bytes encryption and decryption.
 *
 * Covers spec/assets/02-key-hierarchy.md §2.8 scenarios:
 *   - Plaintext encrypt + decrypt roundtrip with hash verification
 *   - AAD binding to asset_urn
 *   - Public-regime SHA-256 verification
 *   - AMK rotation flow (re-encrypt under new AMK)
 *   - Tampered ciphertext detection
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import {
  generateAMK,
  encryptAssetBytes,
  decryptAssetBytes,
  plaintextSha256Hex,
  verifyPlaintextHash,
  AssetsCryptoError,
} from "../src/index.js";

const ASSET_URN_A = "urn:aithos:asset:did:aithos:z6MkrAAA:asset_01J9YB2X7Q";
const ASSET_URN_B = "urn:aithos:asset:did:aithos:z6MkrAAA:asset_01J9YB2X7R";

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("Asset bytes encrypt/decrypt roundtrip", () => {
  it("encrypts then decrypts a small plaintext correctly", () => {
    const amk = generateAMK();
    const plaintext = bytes("Hello, Aithos — this is a private file.");

    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });

    // The blob layout: 24-byte nonce + ciphertext+16-byte tag
    assert.equal(enc.blob.length, 24 + plaintext.length + 16);
    assert.equal(enc.size_bytes, plaintext.length);
    assert.equal(enc.sha256_of_plaintext_hex.length, 64); // hex of 32 bytes

    const dec = decryptAssetBytes({
      amk,
      assetUrn: ASSET_URN_A,
      blob: enc.blob,
      expectedSha256Hex: enc.sha256_of_plaintext_hex,
    });

    assert.deepEqual(Array.from(dec), Array.from(plaintext));
  });

  it("handles binary plaintext (PNG header for example)", () => {
    const amk = generateAMK();
    // Fake "PNG-ish" header + random body
    const plaintext = new Uint8Array(1024);
    plaintext[0] = 0x89;
    plaintext[1] = 0x50;
    plaintext[2] = 0x4e;
    plaintext[3] = 0x47;
    for (let i = 4; i < plaintext.length; i++) plaintext[i] = i & 0xff;

    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });
    const dec = decryptAssetBytes({
      amk,
      assetUrn: ASSET_URN_A,
      blob: enc.blob,
    });

    assert.deepEqual(Array.from(dec), Array.from(plaintext));
  });

  it("handles empty plaintext (edge case)", () => {
    const amk = generateAMK();
    const plaintext = new Uint8Array(0);
    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });
    assert.equal(enc.blob.length, 24 + 16); // nonce + tag only
    const dec = decryptAssetBytes({
      amk,
      assetUrn: ASSET_URN_A,
      blob: enc.blob,
    });
    assert.equal(dec.length, 0);
  });
});

describe("Asset bytes AAD binding", () => {
  it("a ciphertext under asset_urn A cannot be decrypted as asset_urn B", () => {
    const amk = generateAMK();
    const plaintext = bytes("secret content");
    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });

    assert.throws(
      () =>
        decryptAssetBytes({
          amk,
          assetUrn: ASSET_URN_B, // wrong URN — AAD mismatch
          blob: enc.blob,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_DECRYPT_FAILED",
    );
  });

  it("a ciphertext under AMK_a cannot be decrypted with AMK_b", () => {
    const amkA = generateAMK();
    const amkB = generateAMK();
    const plaintext = bytes("secret content");
    const enc = encryptAssetBytes({ amk: amkA, assetUrn: ASSET_URN_A, plaintext });

    assert.throws(
      () =>
        decryptAssetBytes({
          amk: amkB,
          assetUrn: ASSET_URN_A,
          blob: enc.blob,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_DECRYPT_FAILED",
    );
  });

  it("tampered ciphertext (single byte flip) is rejected", () => {
    const amk = generateAMK();
    const plaintext = bytes("integrity matters");
    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });

    // Flip one byte in the ciphertext region (not in the nonce prefix)
    const tampered = new Uint8Array(enc.blob);
    tampered[30] = (tampered[30] as number) ^ 0x01;

    assert.throws(
      () =>
        decryptAssetBytes({
          amk,
          assetUrn: ASSET_URN_A,
          blob: tampered,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_DECRYPT_FAILED",
    );
  });
});

describe("Asset bytes hash verification", () => {
  it("decrypt + expected hash mismatch raises ASSETS_HASH_MISMATCH", () => {
    const amk = generateAMK();
    const plaintext = bytes("hello world");
    const enc = encryptAssetBytes({ amk, assetUrn: ASSET_URN_A, plaintext });

    const wrongHash = "0".repeat(64);
    assert.throws(
      () =>
        decryptAssetBytes({
          amk,
          assetUrn: ASSET_URN_A,
          blob: enc.blob,
          expectedSha256Hex: wrongHash,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_HASH_MISMATCH",
    );
  });

  it("public regime: verifyPlaintextHash passes on match and throws on mismatch", () => {
    const plaintext = bytes("public bytes — no encryption");
    const expectedHex = plaintextSha256Hex(plaintext);

    // pass
    verifyPlaintextHash(plaintext, expectedHex);

    // throws
    assert.throws(
      () => verifyPlaintextHash(plaintext, "0".repeat(64)),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_HASH_MISMATCH",
    );
  });
});

describe("Deterministic encryption with explicit nonce (test vector path)", () => {
  it("supplying the same nonce + same AMK + same plaintext yields the same ciphertext", () => {
    const amk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) amk[i] = i; // deterministic AMK
    const nonce = new Uint8Array(24);
    for (let i = 0; i < 24; i++) nonce[i] = 0xa0 + (i & 0x0f);
    const plaintext = bytes("deterministic test vector");

    const enc1 = encryptAssetBytes({
      amk,
      assetUrn: ASSET_URN_A,
      plaintext,
      nonce,
    });
    const enc2 = encryptAssetBytes({
      amk,
      assetUrn: ASSET_URN_A,
      plaintext,
      nonce,
    });

    assert.deepEqual(Array.from(enc1.blob), Array.from(enc2.blob));
    assert.equal(enc1.sha256_of_plaintext_hex, enc2.sha256_of_plaintext_hex);
  });
});

describe("AMK rotation roundtrip", () => {
  it("rotating the AMK re-encrypts the plaintext but preserves sha256_of_plaintext", () => {
    const amkOld = generateAMK();
    const amkNew = generateAMK();
    const plaintext = bytes("content that survives rotation");

    const encOld = encryptAssetBytes({
      amk: amkOld,
      assetUrn: ASSET_URN_A,
      plaintext,
    });
    const decOld = decryptAssetBytes({
      amk: amkOld,
      assetUrn: ASSET_URN_A,
      blob: encOld.blob,
    });

    // Rotation: re-encrypt the recovered plaintext under the new AMK
    const encNew = encryptAssetBytes({
      amk: amkNew,
      assetUrn: ASSET_URN_A,
      plaintext: decOld,
    });

    // The new ciphertext blob differs from the old
    assert.notDeepEqual(Array.from(encOld.blob), Array.from(encNew.blob));

    // But the plaintext hash is unchanged — same content
    assert.equal(encOld.sha256_of_plaintext_hex, encNew.sha256_of_plaintext_hex);

    // The old AMK CANNOT decrypt the new blob
    assert.throws(
      () =>
        decryptAssetBytes({
          amk: amkOld,
          assetUrn: ASSET_URN_A,
          blob: encNew.blob,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_DECRYPT_FAILED",
    );

    // The new AMK CAN
    const decNew = decryptAssetBytes({
      amk: amkNew,
      assetUrn: ASSET_URN_A,
      blob: encNew.blob,
    });
    assert.deepEqual(Array.from(decNew), Array.from(plaintext));
  });
});

describe("Input validation", () => {
  it("rejects an AMK of wrong length on encrypt", () => {
    const badAmk = new Uint8Array(16);
    assert.throws(
      () =>
        encryptAssetBytes({
          amk: badAmk,
          assetUrn: ASSET_URN_A,
          plaintext: bytes("x"),
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_AMK_INVALID_LENGTH",
    );
  });

  it("rejects a blob shorter than nonce+tag length on decrypt", () => {
    const amk = generateAMK();
    const shortBlob = new Uint8Array(10);
    assert.throws(
      () =>
        decryptAssetBytes({
          amk,
          assetUrn: ASSET_URN_A,
          blob: shortBlob,
        }),
      (err: unknown) =>
        err instanceof AssetsCryptoError && err.code === "ASSETS_BLOB_TOO_SHORT",
    );
  });
});
