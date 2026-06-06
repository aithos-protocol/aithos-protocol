// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Section-level mandates (lot 3 / companion draft
 * `bundle-v0.3-section-level-mandates.md`, §3.12.1′ M-tests).
 *
 * A delegate granted a `section_scope` decrypts ONLY the matching sections of a
 * zone, and cannot read the self index (no titles of the non-granted sections).
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
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
  const d = mkdtempSync(join(tmpdir(), "aithos-ss-"));
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
function ownerReader(id: ReturnType<typeof core.createIdentity>, zone: "circle" | "self") {
  const r = core.subjectRecipientFor(id, zone);
  return { didUrl: r.did, x25519Secret: r.x25519Secret };
}
function mintDelegate(
  owner: ReturnType<typeof core.createIdentity>,
  id: string,
  sectionScope?: { ids?: string[]; tags?: string[] },
) {
  const kp = core.generateKeyPair();
  const delegateMb = core.ed25519PublicKeyToMultibase(kp.publicKey);
  const mandate = core.createMandate({
    issuer: owner,
    actorSphere: "self",
    grantee: { id, pubkey: delegateMb },
    scopes: ["ethos.read.self"],
    ttlSeconds: 3600,
    ...(sectionScope ? { sectionScope } : {}),
  });
  core.writeMandate(mandate);
  return {
    mandate,
    reader: {
      didUrl: core.delegateWrapDid(id, delegateMb),
      x25519Secret: core.edSeedToX25519Secret(kp.seed),
    },
  };
}

describe("section-level mandates (lot 3)", () => {
  test("M1/M2/M3 — section-scoped delegate reads only matching sections, not the index", () => {
    const owner = makeIdentity("ss_alice");
    const del = mintDelegate(owner, "agent:gmail", { tags: ["gmail"] });
    const subjectDid = core.rootDid(owner);

    const dir = outDir();
    const m = core.authorBundleV03({
      identity: owner,
      outDir: dir,
      zones: {
        public: [],
        circle: [],
        self: [
          sec("sec_gm1", "Inbox summary", "3 unread.", 1, ["gmail"]),
          sec("sec_priv", "Journal", "secret thoughts", 2, ["private"]),
        ],
      },
    });

    // Recipient sets: gmail section → subject + delegate; private → subject only.
    const wraps = new Map(
      m.zones.self.sections.map((s) => [s.section_id, s.cipher!.wraps.map((w) => w.recipient)]),
    );
    assert.equal(wraps.get("sec_gm1")!.length, 2, "gmail section sealed to subject + delegate");
    assert.equal(wraps.get("sec_priv")!.length, 1, "private section sealed to subject only");

    // The delegate decrypts the gmail section...
    const okGm = core.readSection(dir, m.zones.self, m.zones.self.sections[0], subjectDid, del.reader);
    assert.ok(okGm.accessible && okGm.section!.title === "Inbox summary");
    // ...but NOT the private one (no wrap).
    const noPriv = core.readSection(dir, m.zones.self, m.zones.self.sections[1], subjectDid, del.reader);
    assert.ok(!noPriv.accessible, "private section opaque to the section-scoped delegate");

    // M3 — the delegate cannot decrypt the self index (not an index recipient).
    const delIdx = core.readZoneIndex("self", m.zones.self, subjectDid, del.reader);
    assert.deepEqual(delIdx.map((r) => r.title_hidden), [true, true], "delegate sees no self titles");

    // The subject still reads everything + the index.
    const subIdx = core.readZoneIndex("self", m.zones.self, subjectDid, ownerReader(owner, "self"));
    assert.deepEqual(subIdx.map((r) => r.title), ["Inbox summary", "Journal"]);

    // M1 by id behaves identically (sanity: an ids-scope on sec_gm1 only).
    const owner2 = makeIdentity("ss_byid");
    const del2 = mintDelegate(owner2, "agent:x", { ids: ["sec_gm1"] });
    const dir2 = outDir();
    const m2 = core.authorBundleV03({
      identity: owner2,
      outDir: dir2,
      zones: { public: [], circle: [], self: [sec("sec_gm1", "A", "a", 1), sec("sec_other", "B", "b", 2)] },
    });
    assert.equal(m2.zones.self.sections.find((s) => s.section_id === "sec_gm1")!.cipher!.wraps.length, 2);
    assert.equal(m2.zones.self.sections.find((s) => s.section_id === "sec_other")!.cipher!.wraps.length, 1);
    void del2;
  });

  test("M4 — a whole-zone delegate (no section_scope) reads every section + the index", () => {
    const owner = makeIdentity("ss_whole");
    const del = mintDelegate(owner, "agent:full"); // no section_scope
    const subjectDid = core.rootDid(owner);
    const dir = outDir();
    const m = core.authorBundleV03({
      identity: owner,
      outDir: dir,
      zones: { public: [], circle: [], self: [sec("sec_a", "A", "a", 1), sec("sec_b", "B", "b", 2)] },
    });
    // Both sections sealed to subject + delegate.
    for (const s of m.zones.self.sections) assert.equal(s.cipher!.wraps.length, 2);
    // Delegate reads both + the index.
    assert.ok(core.readSection(dir, m.zones.self, m.zones.self.sections[0], subjectDid, del.reader).accessible);
    const idx = core.readZoneIndex("self", m.zones.self, subjectDid, del.reader);
    assert.deepEqual(idx.map((r) => r.title), ["A", "B"], "whole-zone delegate decrypts the index");
  });

  test("M5 — granting re-encrypts only matching sections; the rest carry forward", () => {
    const owner = makeIdentity("ss_m5");
    const sections = [sec("sec_gm1", "A", "a", 1, ["gmail"]), sec("sec_priv", "B", "b", 2)];

    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [], circle: [], self: sections },
    });

    // Grant a section-scoped delegate on the gmail tag, then re-author.
    mintDelegate(owner, "agent:g", { tags: ["gmail"] });
    const dir2 = outDir();
    const m2 = core.authorBundleV03({
      identity: owner,
      outDir: dir2,
      zones: { public: [], circle: [], self: sections },
      prev: { manifest: m1, dir: dir1 },
    });

    // gmail section re-encrypted (recipient set grew); private section byte-identical.
    const gm1 = readFileSync(join(dir1, "self", "sec_gm1.enc"));
    const gm2 = readFileSync(join(dir2, "self", "sec_gm1.enc"));
    assert.notEqual(Buffer.compare(gm1, gm2), 0, "gmail section re-encrypted");
    const pv1 = readFileSync(join(dir1, "self", "sec_priv.enc"));
    const pv2 = readFileSync(join(dir2, "self", "sec_priv.enc"));
    assert.equal(Buffer.compare(pv1, pv2), 0, "private section carried forward byte-identical");

    assert.equal(m2.zones.self.sections.find((s) => s.section_id === "sec_gm1")!.cipher!.wraps.length, 2);
    assert.equal(m2.zones.self.sections.find((s) => s.section_id === "sec_priv")!.cipher!.wraps.length, 1);
  });

  test("createMandate validates section_scope", () => {
    const owner = makeIdentity("ss_val");
    const kp = core.generateKeyPair();
    const mb = core.ed25519PublicKeyToMultibase(kp.publicKey);
    // Empty selector is rejected.
    assert.throws(
      () =>
        core.createMandate({
          issuer: owner,
          actorSphere: "self",
          grantee: { id: "a", pubkey: mb },
          scopes: ["ethos.read.self"],
          sectionScope: {},
          ttlSeconds: 3600,
        }),
      /at least one section id or tag/i,
    );
    // A valid section_scope mandate carries the field (signed).
    const m = core.createMandate({
      issuer: owner,
      actorSphere: "self",
      grantee: { id: "a", pubkey: mb },
      scopes: ["ethos.read.self"],
      sectionScope: { tags: ["gmail"] },
      ttlSeconds: 3600,
    });
    assert.deepEqual(m.section_scope, { tags: ["gmail"] });
    // ...and verifies (the field is covered by the signature).
    const didDoc = core.loadIdentityMetadata("ss_val").didDocument;
    assert.ok(core.verifyMandate(m, didDoc).ok);
  });
});
