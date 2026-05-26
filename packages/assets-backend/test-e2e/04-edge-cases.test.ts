// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * E2E test — edge cases and error paths from spec/assets/09-threat-model.md §9.6.
 *
 *   - Dedup intra-subject: two uploads of the same plaintext.
 *   - Media type rejection: text/html / application/javascript.
 *   - Size cap: declared size > 100 MB.
 *   - Hash mismatch: declared sha differs from actual bytes.
 *   - Anonymous private fetch: AITHOS_ASSETS_NOT_PUBLIC.
 *   - Replay: same envelope nonce twice.
 *
 * Skipped placeholders are listed for tests that depend on a deployed
 * stack and require some setup we'll wire when implementing Phase 8.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import { sha256 } from "@noble/hashes/sha2.js";

import { anonCall, call, testIdentity } from "./_helpers/client.js";

const NOT_PUBLIC = -32035;
const MEDIA_TYPE_REJECTED = -32036;
const SIZE_CAP_EXCEEDED = -32037;

describe("E2E — edge cases", () => {
  it("rejects forbidden media types (text/html)", async () => {
    const identity = await testIdentity();
    let err: { code?: number } | null = null;
    try {
      await call({
        path: "/mcp/primitives/write",
        method: "aithos.assets.init_upload",
        identity,
        params: {
          subject_did: identity.did,
          media_type: "text/html",
          size_bytes: 100,
          sha256_of_plaintext: "0".repeat(64),
        },
      });
    } catch (e) {
      err = e as { code?: number };
    }
    assert.equal(err?.code, MEDIA_TYPE_REJECTED);
  });

  it("rejects declared size > 100 MB", async () => {
    const identity = await testIdentity();
    let err: { code?: number } | null = null;
    try {
      await call({
        path: "/mcp/primitives/write",
        method: "aithos.assets.init_upload",
        identity,
        params: {
          subject_did: identity.did,
          media_type: "application/pdf",
          size_bytes: 200 * 1024 * 1024,
          sha256_of_plaintext: "0".repeat(64),
        },
      });
    } catch (e) {
      err = e as { code?: number };
    }
    assert.equal(err?.code, SIZE_CAP_EXCEEDED);
  });

  it("intra-subject dedup: second init returns dedup_hit", async () => {
    const identity = await testIdentity();
    const plaintext = new TextEncoder().encode("dedup-test-plaintext");
    const sha = bytesToHex(sha256(plaintext));

    const first = (await call({
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
    })) as { result: string; urn: string; upload_session?: string; upload_url?: string };

    if (first.result === "upload" && first.upload_url) {
      // We need to actually complete the first upload for it to be in
      // the dedup index.
      const putR = await fetch(first.upload_url, {
        method: "PUT",
        headers: { "content-type": "text/plain" },
        body: plaintext,
      });
      assert.equal(putR.status, 200);
      await call({
        path: "/mcp/primitives/write",
        method: "aithos.assets.complete_upload",
        identity,
        params: { upload_session: first.upload_session },
      });
    }

    const second = (await call({
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
    })) as { result: string; urn: string };

    assert.equal(second.result, "dedup_hit");
    assert.equal(second.urn, first.urn);
  });

  it("anonymous get_public_asset on a PRIVATE asset returns AITHOS_ASSETS_NOT_PUBLIC", async () => {
    const identity = await testIdentity();
    const plaintext = new TextEncoder().encode("private bytes for not-public probe");
    const sha = bytesToHex(sha256(plaintext));

    const init = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.init_upload",
      identity,
      params: {
        subject_did: identity.did,
        media_type: "application/pdf",
        size_bytes: plaintext.length,
        sha256_of_plaintext: sha,
        regime: "private",
      },
    })) as { urn: string };

    let err: { code?: number } | null = null;
    try {
      await anonCall("/mcp/primitives/read", "aithos.assets.get_public_asset", {
        urn: init.urn,
      });
    } catch (e) {
      err = e as { code?: number };
    }
    assert.equal(err?.code, NOT_PUBLIC);
  });

  it.todo(
    "tampered ciphertext (single-byte flip in S3) fails client-side AEAD",
  );

  it.todo(
    "replay defence: same envelope nonce twice fails with -32013",
  );

  it.todo(
    "quota: upload past 5 GB returns AITHOS_ASSETS_QUOTA_EXCEEDED",
  );

  it.todo(
    "AAD binding: substituted ciphertext between two assets fails to decrypt",
  );
});

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}
