// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Tests for the optional dedicated `#data` sphere
 * (spec/data/02-key-hierarchy.md §2.2).
 *
 * Invariants under test:
 *   - `createIdentity` is eager: new identities carry a `#data` keypair.
 *   - The signed DID document gains a `#data` verificationMethod + a
 *     `#data-kex` keyAgreement entry, while keeping the three Ethos spheres,
 *     and still verifies under the root proof.
 *   - The keystore round-trips the `#data` seed.
 *   - Legacy identities WITHOUT a `#data` key still build a valid 3-sphere DID
 *     document that verifies (backward compatibility).
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

function readDidDoc(dir: string): any {
  return JSON.parse(readFileSync(join(dir, "did.json"), "utf8"));
}

test("createIdentity is eager — new identities carry a #data sphere", async () => {
  const ks = freshKeystore();
  try {
    const core = await import("../src/index.js");
    const id = core.createIdentity("alice", "Alice");
    assert.ok(id.data, "identity.data should be present");
    assert.equal(id.data.seed.length, 32);
    assert.equal(id.data.publicKey.length, 32);
    // #data is a distinct key, not a copy of root.
    assert.notDeepEqual(id.data.seed, id.root.seed);
  } finally {
    cleanupKeystore(ks);
  }
});

test("DID document exposes #data + #data-kex and still verifies", async () => {
  const ks = freshKeystore();
  try {
    const core = await import("../src/index.js");
    const id = core.createIdentity("bob", "Bob");
    const { dir } = core.writeIdentityToDisk(id);
    const doc = readDidDoc(dir);

    const vmIds = doc.verificationMethod.map((vm: any) => vm.id);
    const kexIds = doc.keyAgreement.map((vm: any) => vm.id);

    // Three Ethos spheres preserved …
    for (const s of ["public", "circle", "self"]) {
      assert.ok(vmIds.includes(`${doc.id}#${s}`), `missing #${s} VM`);
    }
    // … plus the new #data signing key and its kex counterpart.
    assert.ok(vmIds.includes(`${doc.id}#data`), "missing #data VM");
    assert.ok(kexIds.includes(`${doc.id}#data-kex`), "missing #data-kex");

    // The #data pubkey in the doc matches the identity's data key.
    const dataVm = doc.verificationMethod.find(
      (vm: any) => vm.id === `${doc.id}#data`,
    );
    assert.equal(
      dataVm.publicKeyMultibase,
      core.ed25519PublicKeyToMultibase(id.data!.publicKey),
    );

    // Root proof still covers the (now larger) document.
    assert.equal(core.verifyDidDocument(doc), true);
  } finally {
    cleanupKeystore(ks);
  }
});

test("keystore round-trips the #data seed", async () => {
  const ks = freshKeystore();
  try {
    const core = await import("../src/index.js");
    const id = core.createIdentity("carol", "Carol");
    core.writeIdentityToDisk(id);
    const reloaded = core.loadIdentity("carol");
    assert.ok(reloaded.data, "reloaded identity should carry #data");
    assert.deepEqual(reloaded.data.seed, id.data!.seed);
  } finally {
    cleanupKeystore(ks);
  }
});

test("legacy identity without #data builds a valid 3-sphere DID doc", async () => {
  const ks = freshKeystore();
  try {
    const core = await import("../src/index.js");
    const id = core.createIdentity("dave", "Dave");
    // Simulate a pre-#data identity.
    delete (id as { data?: unknown }).data;
    const { dir } = core.writeIdentityToDisk(id);
    const doc = readDidDoc(dir);

    const vmIds = doc.verificationMethod.map((vm: any) => vm.id);
    assert.ok(!vmIds.includes(`${doc.id}#data`), "#data must be absent");
    assert.equal(doc.verificationMethod.length, 3);
    assert.equal(core.verifyDidDocument(doc), true);

    const reloaded = core.loadIdentity("dave");
    assert.equal(reloaded.data, undefined);
  } finally {
    cleanupKeystore(ks);
  }
});
