// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Targeted edit/delete of a v0.3 bundle section (lot 4a):
 * editSectionV03 / deleteSectionV03, owner + whole-zone delegate.
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

let core!: typeof import("../src/index.js");
let KEYSTORE!: string;
const outDirs: string[] = [];

before(async () => {
  KEYSTORE = freshKeystore();
  core = await import("../src/index.js");
});
after(() => {
  cleanupKeystore(KEYSTORE);
  for (const d of outDirs) rmSync(d, { recursive: true, force: true });
});

function outDir(): string {
  const d = mkdtempSync(join(tmpdir(), "aithos-edit-"));
  outDirs.push(d);
  return d;
}
function sec(id: string, title: string, body: string, n: number, tags?: string[]) {
  return { id, title, body, gamma_ref: "gamma_" + String(n).padStart(24, "0"), ...(tags ? { tags } : {}) };
}
function makeIdentity(handle: string) {
  const id = core.createIdentity(handle, handle);
  core.writeIdentityToDisk(id);
  return id;
}
function reader(id: ReturnType<typeof core.createIdentity>, zone: "circle" | "self") {
  const r = core.subjectRecipientFor(id, zone);
  return { didUrl: r.did, x25519Secret: r.x25519Secret };
}
const bytes = (p: string) => readFileSync(p);

describe("editSectionV03 / deleteSectionV03 (lot 4a)", () => {
  test("owner edits one self section body by id — only that blob changes", () => {
    const owner = makeIdentity("ed_alice");
    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: {
        public: [],
        circle: [sec("sec_c1", "Rate", "1200", 1)],
        self: [sec("sec_s1", "Routine", "Up at six.", 2), sec("sec_s2", "Goals", "Ship.", 3)],
      },
    });

    const dir2 = outDir();
    const m2 = core.editSectionV03({
      author: owner,
      bundleDir: dir1,
      outDir: dir2,
      zone: "self",
      sectionId: "sec_s1",
      change: { body: "Up at five." },
    });

    assert.equal(m2.edition.height, 2);
    assert.equal(m2.edition.supersedes, m1.bundle_id);

    // Only sec_s1 re-encrypted; sec_s2 + circle byte-identical.
    assert.notEqual(Buffer.compare(bytes(join(dir1, "self", "sec_s1.enc")), bytes(join(dir2, "self", "sec_s1.enc"))), 0);
    assert.equal(Buffer.compare(bytes(join(dir1, "self", "sec_s2.enc")), bytes(join(dir2, "self", "sec_s2.enc"))), 0);
    assert.equal(Buffer.compare(bytes(join(dir1, "circle", "sec_c1.enc")), bytes(join(dir2, "circle", "sec_c1.enc"))), 0);

    // New body, title preserved; index still lists both titles.
    const rd = reader(owner, "self");
    const did = core.rootDid(owner);
    const back = core.readSection(dir2, m2.zones.self, m2.zones.self.sections.find((s) => s.section_id === "sec_s1")!, did, rd);
    assert.equal(back.section!.body, "Up at five.");
    assert.equal(back.section!.title, "Routine");
    const idx = core.readZoneIndex("self", m2.zones.self, did, rd);
    assert.deepEqual(idx.map((r) => r.title).sort(), ["Goals", "Routine"]);

    assert.ok(core.verifyBundleV03AtPath(dir2, { readers: [rd], predecessorManifest: m1 }).ok);
  });

  test("owner edits a self title — the encrypted index is rebuilt", () => {
    const owner = makeIdentity("ed_title");
    const dir1 = outDir();
    core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [], circle: [], self: [sec("sec_s1", "Old", "b", 1)] },
    });
    const dir2 = outDir();
    const m2 = core.editSectionV03({
      author: owner,
      bundleDir: dir1,
      outDir: dir2,
      zone: "self",
      sectionId: "sec_s1",
      change: { title: "New" },
    });
    const rd = reader(owner, "self");
    const idx = core.readZoneIndex("self", m2.zones.self, core.rootDid(owner), rd);
    assert.equal(idx[0].title, "New");
  });

  test("owner deletes a section — gone from the new edition, kept in the old", () => {
    const owner = makeIdentity("ed_del");
    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [], circle: [], self: [sec("sec_s1", "A", "a", 1), sec("sec_s2", "B", "b", 2)] },
    });
    const dir2 = outDir();
    const m2 = core.deleteSectionV03({
      author: owner,
      bundleDir: dir1,
      outDir: dir2,
      zone: "self",
      sectionId: "sec_s2",
    });
    assert.deepEqual(m2.zones.self.sections.map((s) => s.section_id), ["sec_s1"]);
    assert.ok(existsSync(join(dir1, "self", "sec_s2.enc")), "old edition keeps the deleted blob");
    assert.ok(!existsSync(join(dir2, "self", "sec_s2.enc")), "new edition drops it");
    assert.ok(core.verifyBundleV03AtPath(dir2, { readers: [reader(owner, "self")], predecessorManifest: m1 }).ok);
  });

  test("a whole-zone delegate edits a circle section; self carried forward", () => {
    const owner = makeIdentity("ed_bob");
    const kp = core.generateKeyPair();
    const mb = core.ed25519PublicKeyToMultibase(kp.publicKey);
    const mandate = core.createMandate({
      issuer: owner,
      actorSphere: "circle",
      grantee: { id: "agent:c", pubkey: mb },
      scopes: ["ethos.read.circle", "ethos.write.circle"],
      ttlSeconds: 3600,
    });
    core.writeMandate(mandate);

    const dir1 = outDir();
    core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [], circle: [sec("sec_c1", "Rate", "1200", 1)], self: [sec("sec_s1", "Routine", "x", 2)] },
    });

    const da = core.delegateAuthor({
      subject: core.loadIdentityMetadata("ed_bob"),
      seed: kp.seed,
      pubkeyMultibase: mb,
      mandate,
    });
    const dir2 = outDir();
    const m2 = core.editSectionV03({
      author: da,
      bundleDir: dir1,
      outDir: dir2,
      zone: "circle",
      sectionId: "sec_c1",
      change: { body: "1500" },
    });

    assert.equal(m2.integrity.manifest_signature.authorized_by, mandate.id);
    // self carried forward byte-identical (the delegate never touched it).
    assert.equal(Buffer.compare(bytes(join(dir1, "self", "sec_s1.enc")), bytes(join(dir2, "self", "sec_s1.enc"))), 0);
    // owner reads the delegate's new circle body.
    const back = core.readSection(dir2, m2.zones.circle, m2.zones.circle.sections[0], core.rootDid(owner), reader(owner, "circle"));
    assert.equal(back.section!.body, "1500");
  });
});
