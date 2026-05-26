// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * E2E test — full private-asset upload + fetch roundtrip.
 *
 * 1. Client generates AMK, wraps it for own X25519 sphere key.
 * 2. Client encrypts a known plaintext with AMK + nonce-prefix layout.
 * 3. init_upload (declare media_type, size, sha256, amk_envelope, regime=private).
 * 4. PUT the ciphertext bytes to the presigned URL.
 * 5. complete_upload — receives the asset metadata.
 * 6. get_asset — receives a presigned GET URL.
 * 7. Fetch via the presigned GET, decrypt, verify SHA-256.
 *
 * Spec ref: spec/assets/05-api-primitives.md §5.4.1–5.4.2, §5.3.1.
 *           spec/assets/02-key-hierarchy.md §2.3.2.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import {
  generateAMK,
  wrapAMKForRecipient,
  unwrapAMK,
  encryptAssetBytes,
  decryptAssetBytes,
  generateX25519Keypair,
} from "@aithos/assets-crypto";

import { call, testIdentity } from "./_helpers/client.js";

describe("E2E — private upload roundtrip", () => {
  it("uploads, fetches, and decrypts a private asset end-to-end", async () => {
    const identity = await testIdentity();
    const recipientKex = generateX25519Keypair();
    const recipientDidUrl = `${identity.did}#kex`;

    // 1+2: Crypto
    const amk = generateAMK();
    const plaintext = new TextEncoder().encode("E2E roundtrip private bytes");
    const assetUrn = "PLACEHOLDER"; // filled in after init_upload

    // 3: init_upload
    const initResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.init_upload",
      identity,
      params: {
        subject_did: identity.did,
        media_type: "application/pdf",
        size_bytes: plaintext.length,
        sha256_of_plaintext: hashHex(plaintext),
        regime: "private",
        amk_envelope: {
          alg: "xchacha20poly1305-ietf",
          // Nonce will be re-filled at encrypt time; the manifest's
          // nonce is the bytes-encryption nonce.
          nonce: "",
          wraps: [],
        },
      },
    })) as InitUploadResp;

    assert.equal(initResp.result, "upload");
    assert.ok(initResp.upload_url);

    const finalUrn = initResp.urn;
    const wrap = wrapAMKForRecipient({
      amk,
      recipientPublicKey: recipientKex.publicKey,
      recipientDidUrl,
      assetUrn: finalUrn,
    });

    const encrypted = encryptAssetBytes({
      amk,
      assetUrn: finalUrn,
      plaintext,
    });

    // 4: PUT the bytes
    const putResp = await fetch(initResp.upload_url, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: encrypted.blob,
    });
    assert.equal(putResp.status, 200, "PUT to S3 must succeed");

    // 5: complete_upload
    const completeResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.complete_upload",
      identity,
      params: {
        upload_session: initResp.upload_session,
        observed_sha256_of_plaintext: encrypted.sha256_of_plaintext_hex,
      },
    })) as CompleteUploadResp;
    assert.equal(completeResp.urn, finalUrn);

    // 6: get_asset
    const getResp = (await call({
      path: "/mcp/primitives/read",
      method: "aithos.assets.get_asset",
      identity,
      params: { urn: finalUrn },
    })) as GetAssetResp;
    assert.ok(getResp.fetch_url);
    assert.equal(getResp.fetch_url_kind, "s3_presigned");

    // 7: Fetch + decrypt
    const ctR = await fetch(getResp.fetch_url);
    const ctBlob = new Uint8Array(await ctR.arrayBuffer());

    const recoveredAmk = unwrapAMK({
      wrap,
      recipientPrivateKey: recipientKex.privateKey,
      assetUrn: finalUrn,
    });
    const recovered = decryptAssetBytes({
      amk: recoveredAmk,
      assetUrn: finalUrn,
      blob: ctBlob,
      expectedSha256Hex: encrypted.sha256_of_plaintext_hex,
    });
    assert.deepEqual(Array.from(recovered), Array.from(plaintext));
  });
});

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface InitUploadResp {
  result: "upload" | "dedup_hit";
  urn: string;
  asset_id: string;
  upload_session: string;
  upload_url: string;
  upload_url_expires_at: string;
}

interface CompleteUploadResp {
  urn: string;
  asset: { sha256_of_plaintext: string };
}

interface GetAssetResp {
  asset: Record<string, unknown>;
  fetch_url: string;
  fetch_url_kind: "s3_presigned" | "cloudfront_stable";
}

function hashHex(bytes: Uint8Array): string {
  // Recompute here to avoid coupling — but in practice tests use
  // encryptAssetBytes.sha256_of_plaintext_hex.
  // For init_upload we declare the SAME plaintext SHA the client will
  // verify against on read.
  const cryptoSubtle = (
    globalThis as { crypto?: { subtle?: SubtleCrypto } }
  ).crypto?.subtle;
  if (!cryptoSubtle) {
    throw new Error("crypto.subtle not available in this runtime");
  }
  // Fallback: deterministic call to @noble/hashes
  // (sha256 in the helper file is asynchronous in WebCrypto;
  // we use the sync noble import here to keep it simple.)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { sha256 } = require("@noble/hashes/sha2.js") as {
    sha256: (b: Uint8Array) => Uint8Array;
  };
  const digest = sha256(bytes);
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    hex += (digest[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}
