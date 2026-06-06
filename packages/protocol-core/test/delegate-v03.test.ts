// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Delegate authoring of a v0.3 per-section bundle (lot 2).
 *
 * Story: Alice authors a v0.3 ethos (circle + self) and installs a write+read
 * mandate for an agent on `circle` (which rewraps circle to the delegate). The
 * delegate authors a NEW v0.3 edition adding a circle section — `self` is
 * carried forward byte-identical (the delegate never reads it), and the
 * manifest is signed with the delegate key + `authorized_by`. Alice reads back
 * both zones; the bundle verifies with a delegate resolver.
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
  const d = mkdtempSync(join(tmpdir(), "aithos-del-v03-"));
  outDirs.push(d);
  return d;
}
function sec(id: string, title: string, body: string, n: number) {
  return { id, title, body, gamma_ref: "gamma_" + String(n).padStart(24, "0") };
}
function reader(id: ReturnType<typeof core.createIdentity>, zone: "circle" | "self") {
  const r = core.subjectRecipientFor(id, zone);
  return { didUrl: r.did, x25519Secret: r.x25519Secret };
}

describe("delegate authoring of a v0.3 bundle (lot 2)", () => {
  test("delegate writes circle, self carried forward, manifest authorized_by", () => {
    const owner = core.createIdentity("del_alice", "Alice");
    core.writeIdentityToDisk(owner);

    // Mint a delegate key + a write+read mandate on circle, and install it so
    // the owner's re-render rewraps circle to the delegate (activeDelegates).
    const kp = core.generateKeyPair();
    const delegateMb = core.ed25519PublicKeyToMultibase(kp.publicKey);
    const mandate = core.createMandate({
      issuer: owner,
      actorSphere: "circle",
      grantee: { id: "agent:bob", pubkey: delegateMb },
      scopes: ["ethos.write.circle", "ethos.read.circle"],
      ttlSeconds: 3600,
    });
    core.writeMandate(mandate);

    // Edition 1 — owner authors circle + self. circle is sealed to owner + delegate.
    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: {
        public: [],
        circle: [sec("sec_c1", "Day rate", "1200/day.", 1)],
        self: [sec("sec_s1", "Routine", "Up at six.", 2)],
      },
    });
    // circle wrapped to BOTH the subject and the delegate.
    const circleRecips = new Set(m1.zones.circle.sections[0].cipher!.wraps.map((w) => w.recipient));
    assert.equal(circleRecips.size, 2, "circle sealed to subject + delegate");
    // self wrapped to the subject only.
    assert.equal(m1.zones.self.sections[0].cipher!.wraps.length, 1, "self sealed to subject only");

    // The delegate can decrypt circle (proves the rewrap), using its own key.
    const delegateReader = {
      didUrl: core.delegateWrapDid("agent:bob", delegateMb),
      x25519Secret: core.edSeedToX25519Secret(kp.seed),
    };
    const dRead = core.readSection(dir1, m1.zones.circle, m1.zones.circle.sections[0], core.rootDid(owner), delegateReader);
    assert.ok(dRead.accessible && dRead.section!.body === "1200/day.", "delegate reads circle");

    // Edition 2 — the DELEGATE authors, adding a circle section.
    const subjectMeta = core.loadIdentityMetadata("del_alice");
    const da = core.delegateAuthor({
      subject: subjectMeta,
      seed: kp.seed,
      pubkeyMultibase: delegateMb,
      mandate,
    });
    const dir2 = outDir();
    const m2 = core.authorBundleV03({
      author: da,
      outDir: dir2,
      zones: {
        circle: [sec("sec_c1", "Day rate", "1200/day.", 1), sec("sec_c2", "Projects", "X, Y.", 3)],
      },
      prev: { manifest: m1, dir: dir1 },
    });

    // Manifest is delegate-signed.
    assert.equal(m2.integrity.manifest_signature.authorized_by, mandate.id);
    assert.equal(m2.integrity.manifest_signature.key, delegateMb);
    assert.equal(m2.edition.height, 2);
    assert.equal(m2.edition.supersedes, m1.bundle_id);
    assert.equal(m2.zones.circle.sections.length, 2);

    // self carried forward WHOLESALE: byte-identical blob, identical descriptor.
    const a = readFileSync(join(dir1, m1.zones.self.sections[0].file));
    const b = readFileSync(join(dir2, m2.zones.self.sections[0].file));
    assert.equal(Buffer.compare(a, b), 0, "self section byte-identical across the delegate edition");
    assert.deepEqual(m2.zones.self, m1.zones.self, "self zone entry reused verbatim (incl. index_cipher)");

    // The owner reads back BOTH zones from the delegate's edition.
    const ownerDid = core.rootDid(owner);
    const cBack = m2.zones.circle.sections.map((d) =>
      core.readSection(dir2, m2.zones.circle, d, ownerDid, reader(owner, "circle")),
    );
    assert.deepEqual(cBack.map((r) => r.section!.title).sort(), ["Day rate", "Projects"]);
    const sBack = core.readSection(dir2, m2.zones.self, m2.zones.self.sections[0], ownerDid, reader(owner, "self"));
    assert.ok(sBack.accessible && sBack.section!.body === "Up at six.", "owner still reads self");

    // Verify with a delegate resolver + predecessor: OK.
    const resolver = (keyId: string, mandateId: string) => {
      if (mandateId !== mandate.id) throw new Error(`unknown mandate ${mandateId}`);
      return core.multibaseToEd25519PublicKey(keyId);
    };
    const v = core.verifyBundleV03AtPath(dir2, {
      readers: [reader(owner, "circle"), reader(owner, "self")],
      resolveDelegatePubkey: resolver,
      predecessorManifest: m1,
    });
    assert.ok(v.ok, `verify failed: ${v.errors.join(", ")}`);

    // Without a resolver, the delegate-signed manifest is rejected.
    const vNo = core.verifyBundleV03AtPath(dir2, { readers: [reader(owner, "circle")] });
    assert.ok(!vNo.ok);
    assert.ok(vNo.errors.some((e) => /delegate-signed|resolveDelegatePubkey/i.test(e)));
  });

  test("a delegate cannot author a zone outside its mandate's actor_sphere", () => {
    const owner = core.createIdentity("del_bob", "Bob");
    core.writeIdentityToDisk(owner);
    const kp = core.generateKeyPair();
    const delegateMb = core.ed25519PublicKeyToMultibase(kp.publicKey);
    const mandate = core.createMandate({
      issuer: owner,
      actorSphere: "circle",
      grantee: { id: "agent:carol", pubkey: delegateMb },
      scopes: ["ethos.write.circle"],
      ttlSeconds: 3600,
    });
    core.writeMandate(mandate);

    const dir1 = outDir();
    const m1 = core.authorBundleV03({
      identity: owner,
      outDir: dir1,
      zones: { public: [], circle: [sec("sec_c1", "T", "B", 1)], self: [sec("sec_s1", "S", "Sb", 2)] },
    });

    const da = core.delegateAuthor({
      subject: core.loadIdentityMetadata("del_bob"),
      seed: kp.seed,
      pubkeyMultibase: delegateMb,
      mandate,
    });
    // The delegate supplies a self edit it has no authority for — self is simply
    // carried forward from prev, never authored from the supplied sections.
    const dir2 = outDir();
    const m2 = core.authorBundleV03({
      author: da,
      outDir: dir2,
      zones: { circle: [sec("sec_c1", "T", "B", 1)], self: [sec("sec_evil", "leak", "x", 9)] },
      prev: { manifest: m1, dir: dir1 },
    });
    // self is unchanged (the supplied sec_evil was ignored).
    assert.deepEqual(m2.zones.self, m1.zones.self);
    assert.ok(existsSync(join(dir2, m1.zones.self.sections[0].file)));
  });
});
