// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Smoke tests for FilesystemStorage.
 *
 * The default backend wraps existing filesystem helpers one-to-one. These
 * tests confirm that each method returns the same result as the direct
 * helper and that write operations flow through the core orchestration
 * unchanged.
 *
 * Test isolation: every module in protocol-core reads `process.env.AITHOS_HOME`
 * at import time, which is frozen by the first test's `freshKeystore`. Tests
 * running later in the same file see the first test's dir (already cleaned
 * up after the first test). To avoid cross-test pollution of ethos zones
 * (which are encrypted with per-test identity keys), every test uses a
 * unique handle — see `uniqueHandle()`.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function loadCore() {
  return await import("../src/index.js");
}

/**
 * Return a handle unique to this test run. Protects against ethos-zone
 * ciphertext pollution across tests that share the (frozen) AITHOS_HOME.
 */
function uniqueHandle(): string {
  return "alice-" + Buffer.from(randomBytes(6)).toString("hex");
}

describe("FilesystemStorage — identity reads", () => {
  test("listHandles / loadIdentityMetadata / loadIdentity / loadDidDocument / isTrackedIdentity", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);

      const fs = new core.FilesystemStorage();

      const handles = await fs.listHandles();
      assert.ok(handles.includes(handle), `handles=${handles.join(",")}`);

      const meta = await fs.loadIdentityMetadata(handle);
      assert.equal(meta.handle, handle);
      assert.equal(meta.tracked, false);
      assert.equal(meta.displayName, "Alice");
      assert.ok(meta.sphereKeys.public);
      assert.ok(meta.sphereKeys.circle);
      assert.ok(meta.sphereKeys.self);

      const identity = await fs.loadIdentity(handle);
      assert.equal(identity.handle, handle);
      assert.equal(identity.root.seed.length, 32);
      assert.equal(identity.public.seed.length, 32);

      const didDoc = await fs.loadDidDocument(handle);
      assert.equal(didDoc.id, meta.did);
      assert.ok(didDoc.verificationMethod.length >= 3);

      assert.equal(await fs.isTrackedIdentity(handle), false);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

describe("FilesystemStorage — ethos writes + reads", () => {
  test("addSection goes through core orchestration and persists", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);
      core.ensureEthosLayout(handle);

      const fs = new core.FilesystemStorage();
      const { section, manifest, gammaEntry } = await fs.addSection(
        {
          handle,
          zone: "circle",
          title: "Test plan",
          body: "Prove the backend abstraction works.",
          tags: ["test"],
        },
        { identity: alice },
      );

      assert.equal(section.title, "Test plan");
      assert.deepEqual([...section.tags], ["test"]);
      assert.equal(gammaEntry.op, "section.add");
      assert.equal(manifest.edition.height, 1);

      const zone = await fs.readZoneDoc(handle, "circle", { identity: alice });
      assert.equal(zone.sections.length, 1);
      assert.equal(zone.sections[0].body, "Prove the backend abstraction works.");

      const bytes = await fs.readZoneBytes(handle, "circle");
      assert.ok(bytes instanceof Uint8Array);
      assert.ok(bytes.length > 0);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("modifySection emits a section.modify gamma entry", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);
      core.ensureEthosLayout(handle);

      const fs = new core.FilesystemStorage();
      const first = await fs.addSection(
        { handle, zone: "circle", title: "v1", body: "body v1" },
        { identity: alice },
      );

      const second = await fs.modifySection(
        {
          handle,
          zone: "circle",
          sectionId: first.section.id,
          body: "body v2",
        },
        { identity: alice },
      );

      assert.equal(second.gammaEntry.op, "section.modify");
      assert.equal(second.section.id, first.section.id);
      assert.notEqual(second.section.gamma_ref, first.section.gamma_ref);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("addSection without auth.identity throws", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const fs = new core.FilesystemStorage();
      await assert.rejects(
        fs.addSection(
          { handle: uniqueHandle(), zone: "circle", title: "x", body: "y" },
          {} as { identity?: unknown; delegate?: unknown },
        ),
        /auth\.identity is required/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});

describe("FilesystemStorage — verification", () => {
  test("verifyEthos returns ok for a fresh ethos", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);
      core.ensureEthosLayout(handle);

      const fs = new core.FilesystemStorage();
      await fs.addSection(
        { handle, zone: "circle", title: "t", body: "b" },
        { identity: alice },
      );

      const didDoc = await fs.loadDidDocument(handle);
      const result = await fs.verifyEthos(handle, alice, didDoc);
      assert.equal(result.ok, true, `errors: ${result.errors.join("; ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

describe("FilesystemStorage — v0.3 per-section reads", () => {
  test("readSectionIndex (entitlement) + readSections (by id, multi) + write guard", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);

      // A v0.3 (per-section) keystore with one circle + two self sections.
      core.initKeystoreV03({ handle, identity: alice });
      core.keystoreEditSection({ handle, author: alice, zone: "circle", sectionId: "sec_rate", change: { title: "Rate", body: "1200" } });
      core.keystoreEditSection({ handle, author: alice, zone: "self", sectionId: "sec_routine", change: { title: "Routine", body: "6h", tags: ["am"] } });
      core.keystoreEditSection({ handle, author: alice, zone: "self", sectionId: "sec_goals", change: { title: "Goals", body: "ship v0.3" } });

      const fs = new core.FilesystemStorage();

      // --- index: owner sees self titles; host (no key) sees them hidden ------
      const selfOwner = await fs.readSectionIndex(handle, "self", { identity: alice });
      assert.deepEqual(selfOwner.map((r) => r.title).sort(), ["Goals", "Routine"]);
      assert.ok(selfOwner.every((r) => !r.title_hidden && r.gamma_ref.startsWith("gamma_")));

      const selfHost = await fs.readSectionIndex(handle, "self");
      assert.ok(selfHost.every((r) => r.title_hidden && r.title === undefined), "self titles hidden without key");

      // circle index is clear: titles visible even without a key.
      const circleHost = await fs.readSectionIndex(handle, "circle");
      assert.deepEqual(circleHost.map((r) => r.title), ["Rate"]);
      assert.ok(!circleHost[0].title_hidden);

      // --- readSections: multi-id, zone-agnostic locate ----------------------
      const got = await fs.readSections(handle, ["sec_goals", "sec_rate", "sec_routine"], { identity: alice });
      assert.equal(got.length, 3);
      assert.ok(got.every((r) => r.accessible));
      const byId = new Map(got.map((r) => [r.section_id, r]));
      assert.equal(byId.get("sec_goals")!.zone, "self");
      assert.equal(byId.get("sec_rate")!.zone, "circle");
      assert.equal(byId.get("sec_routine")!.section!.body, "6h");
      assert.deepEqual([...(byId.get("sec_routine")!.section!.tags ?? [])], ["am"]);

      // unknown id → not accessible; self id without a key → not accessible.
      const miss = await fs.readSections(handle, ["sec_nope"], { identity: alice });
      assert.equal(miss[0].accessible, false);
      const noKey = await fs.readSections(handle, ["sec_routine"]);
      assert.equal(noKey[0].accessible, false);

      // --- readZoneDoc + verify still work on v0.3 ---------------------------
      const doc = await fs.readZoneDoc(handle, "self", { identity: alice });
      assert.equal(doc.sections.length, 2);
      const didDoc = await fs.loadDidDocument(handle);
      const v = await fs.verifyEthos(handle, alice, didDoc);
      assert.equal(v.ok, true, `errors: ${v.errors.join("; ")}`);

    } finally {
      cleanupKeystore(dir);
    }
  });

  test("v0.3 write round-trip through the storage surface: add → modify → delete", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const handle = uniqueHandle();
      const alice = core.createIdentity(handle, "Alice");
      core.writeIdentityToDisk(alice);
      core.initKeystoreV03({ handle, identity: alice });

      const fs = new core.FilesystemStorage();

      // add (owner)
      const added = await fs.addSection(
        { handle, zone: "self", title: "Routine", body: "Up at six.", tags: ["am"] },
        { identity: alice },
      );
      assert.ok(added.section.id.startsWith("sec_"));
      assert.equal(added.section.title, "Routine");
      assert.deepEqual([...added.section.tags], ["am"]);
      assert.equal(added.gammaEntry, undefined, "v0.3 writes omit the gamma entry for now");
      const id = added.section.id;

      // read back the body via the per-section read
      const [r1] = await fs.readSections(handle, [id], { identity: alice });
      assert.equal(r1.section!.body, "Up at six.");

      // modify (body only) — title carries forward in the result
      const modified = await fs.modifySection(
        { handle, zone: "self", sectionId: id, body: "Up at five." },
        { identity: alice },
      );
      assert.equal(modified.section.title, "Routine", "unchanged title read back accurately");
      const [r2] = await fs.readSections(handle, [id], { identity: alice });
      assert.equal(r2.section!.body, "Up at five.");

      // a second section, so the index has two
      await fs.addSection({ handle, zone: "self", title: "Goals", body: "ship v0.3" }, { identity: alice });
      let idx = await fs.readSectionIndex(handle, "self", { identity: alice });
      assert.deepEqual(idx.map((e) => e.title).sort(), ["Goals", "Routine"]);

      // delete the first; it disappears from the live index, blob removed
      const del = await fs.deleteSection({ handle, zone: "self", sectionId: id }, { identity: alice });
      assert.equal(del.sectionId, id);
      idx = await fs.readSectionIndex(handle, "self", { identity: alice });
      assert.deepEqual(idx.map((e) => e.title), ["Goals"]);
      const [gone] = await fs.readSections(handle, [id], { identity: alice });
      assert.equal(gone.accessible, false);

      // the ethos still verifies after the write round-trip
      const didDoc = await fs.loadDidDocument(handle);
      const v = await fs.verifyEthos(handle, alice, didDoc);
      assert.equal(v.ok, true, `errors: ${v.errors.join("; ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

describe("FilesystemStorage — mandate reads", () => {
  test("findRevocation returns null when none exists", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const fs = new core.FilesystemStorage();
      const rev = await fs.findRevocation("mandate_NONEXISTENT");
      assert.equal(rev, null);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

describe("FilesystemStorage — instance state", () => {
  test("defaultHandle mirrors saveConfig", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const fs = new core.FilesystemStorage();

      // Set a known default, read it back. (We can't reliably assert `null`
      // first because earlier tests in the file may have set a default.)
      const handle = uniqueHandle();
      core.saveConfig({
        version: "0.1.0",
        default_handle: handle,
        created_at: new Date().toISOString(),
      });
      assert.equal(await fs.defaultHandle(), handle);

      core.saveConfig({
        version: "0.1.0",
        default_handle: null,
        created_at: new Date().toISOString(),
      });
      assert.equal(await fs.defaultHandle(), null);
    } finally {
      cleanupKeystore(dir);
    }
  });
});
