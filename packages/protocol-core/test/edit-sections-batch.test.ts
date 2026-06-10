// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Transactional batch edits (P2, D3) — core-level T13/T13b semantics:
 *
 *   - `editSectionsV03`: N section changes → ONE edition (one height bump,
 *     one manifest signature), in-batch composition (modify-after-add,
 *     delete-after-add cancels), untouched siblings carried forward
 *     byte-identical, delegate batches bounded to the actor sphere with
 *     `authorized_by` stamped on the manifest signature.
 *   - `FilesystemStorage.applyEdits`: the AithosStorage capability over an
 *     installed v0.3 keystore (and the v0.2 refusal).
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, readFileSync, readdirSync } from "node:fs";
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
  const d = mkdtempSync(join(tmpdir(), "aithos-batch-"));
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

describe("editSectionsV03 — N changes, one edition (T13 core)", () => {
  test("add + modify + delete across zones in ONE edition; sibling blobs carry forward", () => {
    const owner = makeIdentity("batch_alice");
    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: {
        public: [sec("sec_p1", "Bio", "I build Aithos.", 1)],
        circle: [sec("sec_c1", "Rate", "1200", 2)],
        self: [sec("sec_s1", "Routine", "Up at six.", 3), sec("sec_s2", "Goals", "Ship.", 4)],
      },
    });

    const dir2 = outDir();
    const m2 = core.editSectionsV03({
      author: owner,
      bundleDir: dir1,
      outDir: dir2,
      edits: [
        { op: "upsert", zone: "public", sectionId: "sec_p2", change: { title: "Projets", body: "PACKD, Aithos." } },
        { op: "upsert", zone: "circle", sectionId: "sec_c1", change: { body: "1500" } },
        { op: "delete", zone: "self", sectionId: "sec_s2" },
      ],
    });

    // ONE edition for the whole batch.
    assert.equal(m2.edition.height, m1.edition.height + 1);
    assert.equal(m2.edition.supersedes, m1.bundle_id);

    // Net state.
    assert.equal(m2.zones.public.sections.length, 2);
    assert.equal(m2.zones.circle.sections.length, 1);
    assert.equal(m2.zones.self.sections.length, 1);
    const back = core.readSection(
      dir2,
      m2.zones.circle,
      m2.zones.circle.sections.find((s) => s.section_id === "sec_c1")!,
      core.rootDid(owner),
      reader(owner, "circle"),
    );
    assert.equal(back.section!.body, "1500");

    // Untouched self sibling carried forward byte-identical.
    assert.equal(
      Buffer.compare(bytes(join(dir1, "self", "sec_s1.enc")), bytes(join(dir2, "self", "sec_s1.enc"))),
      0,
    );
  });

  test("in-batch composition: modify-after-add composes; delete-after-add cancels", () => {
    const owner = makeIdentity("batch_compose");
    const dir1 = outDir();
    core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [sec("sec_p1", "Bio", "x", 1)], circle: [], self: [] },
    });

    const dir2 = outDir();
    const m2 = core.editSectionsV03({
      author: owner,
      bundleDir: dir1,
      outDir: dir2,
      edits: [
        { op: "upsert", zone: "public", sectionId: "sec_new", change: { title: "Draft", body: "v1" } },
        { op: "upsert", zone: "public", sectionId: "sec_new", change: { body: "v2" } },
        { op: "upsert", zone: "public", sectionId: "sec_tmp", change: { title: "Tmp", body: "t" } },
        { op: "delete", zone: "public", sectionId: "sec_tmp" },
      ],
    });

    const ids = m2.zones.public.sections.map((s) => s.section_id).sort();
    assert.deepEqual(ids, ["sec_new", "sec_p1"]);
    const back = core.readSection(
      dir2,
      m2.zones.public,
      m2.zones.public.sections.find((s) => s.section_id === "sec_new")!,
      m2.subject_did,
    );
    assert.equal(back.section!.title, "Draft", "title from the first upsert survives");
    assert.equal(back.section!.body, "v2", "body composed by the second upsert");
  });

  test("empty and net-zero batches throw (no empty editions)", () => {
    const owner = makeIdentity("batch_zero");
    const dir1 = outDir();
    core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [sec("sec_p1", "Bio", "x", 1)], circle: [], self: [] },
    });

    assert.throws(
      () => core.editSectionsV03({ author: owner, bundleDir: dir1, outDir: outDir(), edits: [] }),
      /empty batch/,
    );
    assert.throws(
      () =>
        core.editSectionsV03({
          author: owner,
          bundleDir: dir1,
          outDir: outDir(),
          edits: [
            { op: "upsert", zone: "public", sectionId: "sec_x", change: { title: "X", body: "x" } },
            { op: "delete", zone: "public", sectionId: "sec_x" },
          ],
        }),
      /nets out to no changes/,
    );
  });

  test("delegate batch: bounded to the actor sphere, authorized_by stamped (T13)", () => {
    const owner = makeIdentity("batch_bob");
    const kp = core.generateKeyPair();
    const mb = core.ed25519PublicKeyToMultibase(kp.publicKey);
    const mandate = core.createMandate({
      issuer: owner,
      actorSphere: "circle",
      grantee: { id: "agent:batch", pubkey: mb },
      scopes: ["ethos.read.circle", "ethos.write.circle"],
      ttlSeconds: 3600,
    });
    core.writeMandate(mandate);

    const dir1 = outDir();
    core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: {
        public: [],
        circle: [sec("sec_c1", "Rate", "1200", 1)],
        self: [sec("sec_s1", "Routine", "x", 2)],
      },
    });
    const da = core.delegateAuthor({
      subject: core.loadIdentityMetadata("batch_bob"),
      seed: kp.seed,
      pubkeyMultibase: mb,
      mandate,
    });

    // Two circle edits in one batch → one delegate-authored edition.
    const dir2 = outDir();
    const m2 = core.editSectionsV03({
      author: da,
      bundleDir: dir1,
      outDir: dir2,
      edits: [
        { op: "upsert", zone: "circle", sectionId: "sec_c1", change: { body: "1500" } },
        { op: "upsert", zone: "circle", sectionId: "sec_c2", change: { title: "Dispo", body: "Sept." } },
      ],
    });
    assert.equal(m2.integrity.manifest_signature.authorized_by, mandate.id);
    assert.equal(m2.zones.circle.sections.length, 2);
    // self carried forward byte-identical.
    assert.equal(
      Buffer.compare(bytes(join(dir1, "self", "sec_s1.enc")), bytes(join(dir2, "self", "sec_s1.enc"))),
      0,
    );

    // A batch touching a zone outside the mandate is rejected wholesale.
    assert.throws(
      () =>
        core.editSectionsV03({
          author: da,
          bundleDir: dir2,
          outDir: outDir(),
          edits: [
            { op: "upsert", zone: "circle", sectionId: "sec_c1", change: { body: "1600" } },
            { op: "upsert", zone: "public", sectionId: "sec_p1", change: { title: "X", body: "x" } },
          ],
        }),
      /may not write zone public/,
    );
  });
});

describe("FilesystemStorage.applyEdits — the AithosStorage capability (T13)", () => {
  test("batch over an installed v0.3 keystore: one edition, per-edit results, one archive", async () => {
    const owner = makeIdentity("batch_store");
    core.ensureEthosLayout("batch_store");
    core.addSection({ handle: "batch_store", identity: owner, zone: "public", title: "Bio", body: "hello" });
    core.migrateKeystoreInPlace({ handle: "batch_store", identity: owner });
    const m0 = core.keystoreEthosVersion("batch_store");
    assert.equal(m0, "0.3.0");

    const storage = new core.FilesystemStorage();
    const before = (await storage.readManifest("batch_store")) as unknown as {
      edition: { height: number };
    };
    const historyBefore = readdirSync(join(core.ethosDir("batch_store"), "history")).length;

    const bioId = (await storage.readSectionIndex("batch_store", "public"))[0]!.section_id;
    const res = await storage.applyEdits!(
      "batch_store",
      [
        { op: "add", zone: "public", title: "Projets", body: "PACKD, Aithos." },
        { op: "modify", zone: "public", sectionId: bioId, body: "hello, world" },
        { op: "add", zone: "circle", title: "Rate", body: "1500" },
      ],
      { identity: owner },
    );

    // ONE edition for three edits (T13).
    const after = res.manifest as unknown as { edition: { height: number } };
    assert.equal(after.edition.height, before.edition.height + 1);
    const historyAfter = readdirSync(join(core.ethosDir("batch_store"), "history")).length;
    assert.equal(historyAfter, historyBefore + 1, "exactly one archived predecessor");

    // Per-edit results, input order.
    assert.equal(res.results.length, 3);
    const [r1, r2, r3] = res.results;
    assert.equal(r1!.op, "add");
    assert.match((r1 as { section: { id: string } }).section.id, /^sec_/);
    assert.equal((r1 as { section: { title: string } }).section.title, "Projets");
    assert.equal(r2!.op, "modify");
    assert.equal((r2 as { section: { id: string } }).section.id, bioId);
    assert.equal(r3!.op, "add");
    assert.equal((r3 as { zone: string }).zone, "circle");

    // Read-back through the storage interface.
    const fetched = await storage.readSections(
      "batch_store",
      [bioId],
      { zone: "public", identity: owner },
    );
    assert.equal(fetched[0]!.section!.body, "hello, world");
  });

  test("v0.2 keystore: applyEdits refuses (migrate first) — T13 precondition", async () => {
    const owner = makeIdentity("batch_v02");
    core.ensureEthosLayout("batch_v02");
    core.addSection({ handle: "batch_v02", identity: owner, zone: "public", title: "Bio", body: "x" });
    assert.equal(core.keystoreEthosVersion("batch_v02"), "0.2.0");

    const storage = new core.FilesystemStorage();
    await assert.rejects(
      () =>
        storage.applyEdits!(
          "batch_v02",
          [{ op: "add", zone: "public", title: "T", body: "b" }],
          { identity: owner },
        ),
      /transactional edits require a v0\.3 ethos/,
    );
  });
});

describe("P3 — index size hints + readManifestAt (diff foundation)", () => {
  test("readSectionIndex carries approx_size_bytes; readManifestAt resolves archived heights", async () => {
    const owner = makeIdentity("p3_store");
    core.ensureEthosLayout("p3_store");
    core.addSection({ handle: "p3_store", identity: owner, zone: "public", title: "Bio", body: "hello world" });
    core.migrateKeystoreInPlace({ handle: "p3_store", identity: owner });

    const storage = new core.FilesystemStorage();
    const idx = await storage.readSectionIndex("p3_store", "public");
    assert.equal(idx.length, 1);
    assert.ok(
      typeof idx[0]!.approx_size_bytes === "number" && idx[0]!.approx_size_bytes >= "hello world".length,
      `approx_size_bytes present and plausible (got ${idx[0]!.approx_size_bytes})`,
    );

    // One batch on top → a new edition; the prior manifest is archived.
    const h1 = (await storage.readManifest("p3_store")).edition.height;
    await storage.applyEdits!(
      "p3_store",
      [{ op: "add", zone: "public", title: "Projets", body: "PACKD." }],
      { identity: owner },
    );
    const h2 = (await storage.readManifest("p3_store")).edition.height;
    assert.equal(h2, h1 + 1);

    const atH1 = await storage.readManifestAt!("p3_store", h1);
    assert.ok(atH1, "archived manifest resolved");
    assert.equal(atH1.edition.height, h1);
    const atH2 = await storage.readManifestAt!("p3_store", h2);
    assert.equal(atH2.edition.height, h2, "current manifest answers its own height");
    assert.equal(await storage.readManifestAt!("p3_store", 999), null);
  });
});
