// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Keystore-native v0.3 (opt-in) — lot 4b-2.
 *
 * Build a v0.2 keystore ethos, migrate it IN PLACE to v0.3, then add/modify/
 * delete sections directly in the keystore via the v0.3 helpers.
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

let core!: typeof import("../src/index.js");
let KEYSTORE!: string;

before(async () => {
  KEYSTORE = freshKeystore();
  core = await import("../src/index.js");
});
after(() => cleanupKeystore(KEYSTORE));

function seedV02(handle: string) {
  const owner = core.createIdentity(handle, handle);
  core.writeIdentityToDisk(owner);
  core.ensureEthosLayout(handle);
  core.addSection({ handle, identity: owner, zone: "public", title: "Bio", body: "hello" });
  core.addSection({ handle, identity: owner, zone: "circle", title: "Rate", body: "1200" });
  core.addSection({ handle, identity: owner, zone: "self", title: "Routine", body: "6h" });
  return owner;
}

describe("keystore-native v0.3 (lot 4b-2)", () => {
  test("migrate in place, then add/modify/delete sections in the keystore", () => {
    const owner = seedV02("ks_alice");
    const ed = core.ethosDir("ks_alice");

    // Starts as v0.2 monolithic.
    assert.equal(core.keystoreEthosVersion("ks_alice"), "0.2.0");
    assert.ok(!core.isV03Keystore("ks_alice"));
    assert.ok(existsSync(join(ed, "circle", "circle.md.enc")), "v0.2 monolithic file present");

    // Migrate IN PLACE → v0.3.
    const mig = core.migrateKeystoreInPlace({ handle: "ks_alice", identity: owner });
    assert.equal(mig.aithos, "0.3.0");
    assert.ok(core.isV03Keystore("ks_alice"));
    assert.ok(!existsSync(join(ed, "circle", "circle.md.enc")), "monolithic file removed");
    assert.ok(readdirSync(join(ed, "circle")).some((f) => f.endsWith(".enc")), "per-section blob present");
    assert.ok(!existsSync(join(ed, "gamma")), "old gamma/ dir removed");
    assert.ok(existsSync(join(ed, "gamma.jsonl.enc")), "gamma log at root (carried forward)");

    // Read it back.
    const back = core.keystoreReadSectionsV03("ks_alice", owner);
    assert.equal(back.circle.find((s) => s.title === "Rate")!.body, "1200");
    assert.equal(back.self.find((s) => s.title === "Routine")!.body, "6h");

    // Modify the circle section by id (only that blob changes; old manifest archived).
    const circleId = mig.zones.circle.sections[0].section_id;
    const m2 = core.keystoreEditSection({
      handle: "ks_alice",
      author: owner,
      zone: "circle",
      sectionId: circleId,
      change: { body: "1500" },
    });
    assert.equal(m2.edition.height, mig.edition.height + 1);
    assert.ok(existsSync(join(ed, "history", `${mig.edition.version}.manifest.json`)), "prior manifest archived");
    assert.equal(core.keystoreReadSectionsV03("ks_alice", owner).circle[0].body, "1500");

    // Add a new self section.
    core.keystoreEditSection({
      handle: "ks_alice",
      author: owner,
      zone: "self",
      sectionId: "sec_goals1",
      change: { title: "Goals", body: "ship v0.3", tags: ["plan"] },
    });
    const back3 = core.keystoreReadSectionsV03("ks_alice", owner);
    assert.ok(back3.self.some((s) => s.title === "Goals"), "new self section present");

    // Delete the original self section.
    const routineId = back3.self.find((s) => s.title === "Routine")!.id;
    core.keystoreEditSection({ handle: "ks_alice", author: owner, zone: "self", sectionId: routineId, delete: true });
    const back4 = core.keystoreReadSectionsV03("ks_alice", owner);
    assert.ok(!back4.self.some((s) => s.title === "Routine"), "deleted from the live ethos");
    assert.ok(!existsSync(join(ed, "self", `${routineId}.enc`)), "deleted blob removed from the keystore");

    // The keystore still verifies as a v0.3 bundle.
    const r = core.subjectRecipientFor(owner, "self");
    const v = core.verifyBundleV03AtPath(ed, { readers: [{ didUrl: r.did, x25519Secret: r.x25519Secret }] });
    assert.ok(v.ok, `keystore verify failed: ${v.errors.join(", ")}`);

    // Migrating again is rejected.
    assert.throws(() => core.migrateKeystoreInPlace({ handle: "ks_alice", identity: owner }), /already v0\.3/i);
  });
});

describe("write-format default + init/auto-migrate (lot 4b-3)", () => {
  function withFormat<T>(value: string | undefined, fn: () => T): T {
    const prev = process.env.AITHOS_FORMAT;
    if (value === undefined) delete process.env.AITHOS_FORMAT;
    else process.env.AITHOS_FORMAT = value;
    try {
      return fn();
    } finally {
      if (prev === undefined) delete process.env.AITHOS_FORMAT;
      else process.env.AITHOS_FORMAT = prev;
    }
  }

  test("defaultWriteFormat: v0.3 unless AITHOS_FORMAT opts out", () => {
    assert.equal(withFormat(undefined, () => core.defaultWriteFormat()), "v0.3");
    assert.equal(withFormat("v0.2", () => core.defaultWriteFormat()), "v0.2");
    assert.equal(withFormat("0.2.0", () => core.defaultWriteFormat()), "v0.2");
    assert.equal(withFormat("v0.3", () => core.defaultWriteFormat()), "v0.3");
    assert.equal(withFormat("garbage", () => core.defaultWriteFormat()), "v0.3");
  });

  test("initKeystoreV03 creates an empty v0.3 ethos at height 1", () => {
    const owner = core.createIdentity("ks_init", "ks_init");
    core.writeIdentityToDisk(owner);
    const m = core.initKeystoreV03({ handle: "ks_init", identity: owner });
    assert.equal(m.aithos, "0.3.0");
    assert.equal(m.edition.height, 1);
    assert.equal(m.edition.supersedes, null);
    assert.ok(core.isV03Keystore("ks_init"));
    for (const z of ["public", "circle", "self"] as const) {
      assert.equal(m.zones[z].sections.length, 0, `${z} starts empty`);
    }
    // An owner add-section lands in the per-section layout.
    core.keystoreEditSection({ handle: "ks_init", author: owner, zone: "self", sectionId: "sec_x1", change: { title: "T", body: "B" } });
    assert.ok(core.keystoreReadSectionsV03("ks_init", owner).self.some((s) => s.title === "T"));
  });

  test("autoMigrateKeystoreIfDefault: migrates v0.2 under the v0.3 default, no-op otherwise", () => {
    // Seed a v0.2 keystore.
    const owner = core.createIdentity("ks_auto", "ks_auto");
    core.writeIdentityToDisk(owner);
    core.ensureEthosLayout("ks_auto");
    core.addSection({ handle: "ks_auto", identity: owner, zone: "self", title: "Old", body: "v2" });
    assert.equal(core.keystoreEthosVersion("ks_auto"), "0.2.0");

    // Opt-out → no migration.
    assert.equal(withFormat("v0.2", () => core.autoMigrateKeystoreIfDefault({ handle: "ks_auto", identity: owner })), false);
    assert.equal(core.keystoreEthosVersion("ks_auto"), "0.2.0");

    // Default → migrates in place.
    assert.equal(withFormat(undefined, () => core.autoMigrateKeystoreIfDefault({ handle: "ks_auto", identity: owner })), true);
    assert.ok(core.isV03Keystore("ks_auto"));
    assert.ok(core.keystoreReadSectionsV03("ks_auto", owner).self.some((s) => s.title === "Old"));

    // Already v0.3 → no-op.
    assert.equal(withFormat(undefined, () => core.autoMigrateKeystoreIfDefault({ handle: "ks_auto", identity: owner })), false);
  });
});
