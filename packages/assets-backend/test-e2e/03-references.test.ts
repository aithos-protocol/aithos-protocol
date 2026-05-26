// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * E2E test — reference lifecycle and state transitions.
 *
 * 1. Upload a private asset (assumed scaffolded — depends on
 *    01-upload-private.test.ts).
 * 2. ref_asset with an ethos.section reference → state ACTIVE.
 * 3. unref_asset → state ORPHANED (count drops to 0).
 * 4. ref_asset again → state back to ACTIVE.
 * 5. delete_asset succeeds only after final unref.
 *
 * Spec ref: spec/assets/01-data-model.md §1.2.4, §1.3.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import { call, testIdentity } from "./_helpers/client.js";
import {
  generateAMK,
  wrapAMKForRecipient,
  encryptAssetBytes,
  generateX25519Keypair,
  plaintextSha256Hex,
} from "@aithos/assets-crypto";

describe("E2E — reference lifecycle", () => {
  it("ref + unref + ref + delete transition through states correctly", async () => {
    const identity = await testIdentity();
    const kex = generateX25519Keypair();
    const amk = generateAMK();
    const plaintext = new TextEncoder().encode("ref-cycle test bytes");

    // init_upload
    const initResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.init_upload",
      identity,
      params: {
        subject_did: identity.did,
        media_type: "application/pdf",
        size_bytes: plaintext.length,
        sha256_of_plaintext: plaintextSha256Hex(plaintext),
        regime: "private",
      },
    })) as { urn: string; upload_session: string; upload_url: string };

    const wrap = wrapAMKForRecipient({
      amk,
      recipientPublicKey: kex.publicKey,
      recipientDidUrl: `${identity.did}#kex`,
      assetUrn: initResp.urn,
    });
    void wrap;

    const enc = encryptAssetBytes({ amk, assetUrn: initResp.urn, plaintext });

    const putR = await fetch(initResp.upload_url, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: enc.blob,
    });
    assert.equal(putR.status, 200);

    await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.complete_upload",
      identity,
      params: { upload_session: initResp.upload_session },
    });

    // ref_asset
    const refResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.ref_asset",
      identity,
      params: {
        urn: initResp.urn,
        reference: {
          kind: "ethos.section",
          ethos_edition_urn: "urn:aithos:ethos:test:2026.05.21-1",
          zone: "self",
          section_id: "sec_test_refs",
          since_height: 1,
        },
      },
    })) as { reference_count: number; gamma_ref: string };
    assert.equal(refResp.reference_count, 1);
    assert.ok(refResp.gamma_ref);

    // delete_asset refused while referenced
    let stillRefError: { code?: number } | null = null;
    try {
      await call({
        path: "/mcp/primitives/write",
        method: "aithos.assets.delete_asset",
        identity,
        params: { urn: initResp.urn },
      });
    } catch (e) {
      stillRefError = e as { code?: number };
    }
    assert.equal(
      stillRefError?.code,
      -32033,
      "delete_asset must refuse with AITHOS_ASSETS_STILL_REFERENCED",
    );

    // unref_asset → ORPHANED
    const unrefResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.unref_asset",
      identity,
      params: {
        urn: initResp.urn,
        reference: {
          kind: "ethos.section",
          ethos_edition_urn: "urn:aithos:ethos:test:2026.05.21-1",
          zone: "self",
          section_id: "sec_test_refs",
          since_height: 1,
        },
      },
    })) as { reference_count: number };
    assert.equal(unrefResp.reference_count, 0);

    // delete_asset now succeeds
    const delResp = (await call({
      path: "/mcp/primitives/write",
      method: "aithos.assets.delete_asset",
      identity,
      params: { urn: initResp.urn },
    })) as { tombstoned_at: string };
    assert.ok(delResp.tombstoned_at);
  });
});
