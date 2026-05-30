// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Append-only data scope (`data.<collection>.append`) at the mandate layer.
 *
 * Verifies that:
 *  - the scope is recognized by isDataAppendScope / hasDataAppendScope;
 *  - append is NOT treated as a write scope (lateral capability);
 *  - createMandate requires grantee.pubkey for an append mandate;
 *  - an append mandate mints and verifies; it needs no kex_pubkey;
 *  - append is permitted under every actor_sphere (data scopes are
 *    sphere-neutral).
 *
 * Follows the AITHOS_HOME harness: set a throwaway keystore BEFORE importing
 * any protocol-core module (env is read at import time), then dynamic import.
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

let tmp: string;
async function loadCore() {
  return await import("../src/index.js");
}

describe("data.<collection>.append scope (protocol-core)", () => {
  before(() => {
    tmp = freshKeystore();
  });
  after(() => {
    // Cleanup is best-effort: when TMPDIR points at the host-mounted volume
    // (needed for disk space in the sandbox), rmdir can EPERM. The throwaway
    // keystore is harmless to leave behind.
    try {
      cleanupKeystore(tmp);
    } catch {
      /* ignore */
    }
  });

  const PUBKEY = "z6MkfakeDelegateEd25519PublicKeyForTest000000000000";

  test("isDataAppendScope recognizes only well-formed append scopes", async () => {
    const core = await loadCore();
    assert.equal(core.isDataAppendScope("data.mandats_patients.append"), true);
    assert.equal(core.isDataAppendScope("data.contacts.append"), true);
    assert.equal(core.isDataAppendScope("data.contacts.read"), false);
    assert.equal(core.isDataAppendScope("data.contacts.write"), false);
    assert.equal(core.isDataAppendScope("data.a.b.append"), false); // "." in collection
    assert.equal(core.isDataAppendScope("ethos.write.self"), false);
  });

  test("append is a lateral capability — not a write scope", async () => {
    const core = await loadCore();
    assert.equal(core.hasWriteScope(["data.x.append"]), false);
    assert.equal(core.hasDataAppendScope(["data.x.append"]), true);
    assert.equal(core.hasDataAppendScope(["data.x.read"]), false);
  });

  test("createMandate requires grantee.pubkey for an append mandate", async () => {
    const core = await loadCore();
    const owner = core.createIdentity("alice", "Alice");
    assert.throws(
      () =>
        core.createMandate({
          issuer: owner,
          actorSphere: "self",
          grantee: { id: "urn:aithos:patient:bob" }, // no pubkey
          scopes: ["data.mandats_patients.append"],
          ttlSeconds: 600,
        }),
      /grantee\.pubkey/,
    );
  });

  test("append mandate mints and verifies (no kex_pubkey needed)", async () => {
    const core = await loadCore();
    const owner = core.createIdentity("bob", "Bob");
    core.writeIdentityToDisk(owner); // persist so we can load the DID document
    const m = core.createMandate({
      issuer: owner,
      actorSphere: "self",
      grantee: { id: "urn:aithos:patient:carol", pubkey: PUBKEY },
      scopes: ["data.mandats_patients.append"],
      ttlSeconds: 600,
    });
    assert.equal(m.scopes[0], "data.mandats_patients.append");
    const doc = core.loadIdentityMetadata("bob").didDocument;
    const res = core.verifyMandate(m, doc);
    assert.ok(res.ok, `verify errors: ${res.errors.join("; ")}`);
  });

  test("append is permitted under the public sphere too", async () => {
    const core = await loadCore();
    const owner = core.createIdentity("dave", "Dave");
    assert.doesNotThrow(() =>
      core.createMandate({
        issuer: owner,
        actorSphere: "public",
        grantee: { id: "urn:aithos:patient:erin", pubkey: PUBKEY },
        scopes: ["data.mandats_patients.append"],
        ttlSeconds: 600,
      }),
    );
  });
});
