// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * E2E test — full public-asset upload + anonymous fetch roundtrip.
 *
 * 1. init_upload with regime=public, attached_context.zone="public".
 * 2. PUT the plaintext bytes to the presigned URL.
 * 3. complete_upload.
 * 4. get_public_asset (anonymous) — receives a stable CloudFront URL.
 * 5. Fetch via CloudFront, verify SHA-256.
 *
 * Spec ref: spec/assets/01-data-model.md §1.7 (public regime).
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import { sha256 } from "@noble/hashes/sha2.js";

import { anonCall, call, testIdentity } from "./_helpers/client.js";

describe("E2E — public upload roundtrip", () => {
  it("uploads a public asset and fetches it anonymously via CDN", async () => {
    const identity = await testIdentity();
    const plaintext = new TextEncoder().encode("public bytes — readable by anyone");
    const sha = bytesToHex(sha256(plaintext));

    // init_upload
    const initResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.init_upload",
      identity,
      params: {
        subject_did: identity.did,
        media_type: "text/plain",
        size_bytes: plaintext.length,
        sha256_of_plaintext: sha,
        regime: "public",
        attached_context: { kind: "ethos", zone: "public" },
      },
    })) as { result: string; urn: string; upload_session: string; upload_url: string };

    assert.equal(initResp.result, "upload");

    // PUT plaintext directly
    const putResp = await fetch(initResp.upload_url, {
      method: "PUT",
      headers: { "content-type": "text/plain" },
      body: plaintext,
    });
    assert.equal(putResp.status, 200, "PUT to S3 must succeed");

    // complete_upload
    await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.complete_upload",
      identity,
      params: { upload_session: initResp.upload_session },
    });

    // get_public_asset (anonymous, no envelope)
    const getResp = (await anonCall("/mcp/primitives/read", "aithos.assets.get_public_asset", {
      urn: initResp.urn,
    })) as { urn: string; fetch_url: string; sha256_of_plaintext: string };

    assert.equal(getResp.urn, initResp.urn);
    assert.equal(getResp.sha256_of_plaintext, sha);

    // CloudFront propagation may take a few seconds; retry briefly.
    const fetched = await fetchWithRetry(getResp.fetch_url, 5, 2000);
    const observed = new Uint8Array(await fetched.arrayBuffer());
    const observedSha = bytesToHex(sha256(observed));
    assert.equal(observedSha, sha);
  });
});

async function fetchWithRetry(
  url: string,
  attempts: number,
  delayMs: number,
): Promise<Response> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
      lastErr = new Error(`status ${r.status}`);
    } catch (e) {
      lastErr = e;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw lastErr;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}
