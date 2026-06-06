// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Conformance tests for the v0.2 ↔ v0.3 boundary (§3.12′ B9–B10):
 * the compat read path (§3.10.2′) and the one-shot migration (§3.10.3′).
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
  const d = mkdtempSync(join(tmpdir(), "aithos-mig-"));
  outDirs.push(d);
  return d;
}

/** Author a v0.2 bundle with one section in each of the three zones. */
function makeV02Bundle(handle: string) {
  const owner = core.createIdentity(handle, handle);
  core.writeIdentityToDisk(owner);
  core.ensureEthosLayout(handle);
  core.addSection({ handle, identity: owner, zone: "public", title: "Bio", body: "Public bio." });
  core.addSection({ handle, identity: owner, zone: "circle", title: "Day rate", body: "1200/day." });
  core.addSection({ handle, identity: owner, zone: "self", title: "Routine", body: "Up at six." });
  const dir = outDir();
  core.packEthosToDir({ handle, identity: owner, outDir: dir });
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  return { owner, dir, manifest };
}

function subjectReaders(owner: ReturnType<typeof core.createIdentity>) {
  return (["circle", "self"] as const).map((z) => {
    const r = core.subjectRecipientFor(owner, z);
    return { didUrl: r.did, x25519Secret: r.x25519Secret };
  });
}

describe("v0.2 ↔ v0.3 boundary (§3.12′)", () => {
  /* ------------------------------------------------------------------------ */
  /*  B9 — v0.2 compat read                                                   */
  /* ------------------------------------------------------------------------ */

  test("B9 — a v0.2 bundle is read by the v0.3 runtime, all zones decrypt", () => {
    const { owner, dir, manifest } = makeV02Bundle("b9_alice");
    assert.ok(core.isV02Aithos(manifest.aithos), `expected v0.2 marker, got ${manifest.aithos}`);

    const decoded = core.decodeBundleV02(dir, owner);
    const pair = (zone: "public" | "circle" | "self") =>
      decoded.zones[zone].map((s) => [s.title, s.body]);
    assert.deepEqual(pair("public"), [["Bio", "Public bio."]]);
    assert.deepEqual(pair("circle"), [["Day rate", "1200/day."]]);
    assert.deepEqual(pair("self"), [["Routine", "Up at six."]]);

    // The unified reader (dispatching on the version marker) returns the same.
    const uni = core.readBundleSections(dir, owner);
    assert.equal(uni.circle[0].body, "1200/day.");
    assert.equal(uni.self[0].body, "Up at six.");

    // The shared verify entrypoint still routes v0.2 to the v0.2 verifier.
    const v = core.verifyBundleAtPath(dir);
    assert.ok(v.ok, `v0.2 verify failed: ${v.errors.join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B10 — migration round trip                                              */
  /* ------------------------------------------------------------------------ */

  test("B10 — v0.2 → v0.3 migration cross-validates and accepts a subsequent write", () => {
    const { owner, dir: v02Dir, manifest: v02 } = makeV02Bundle("b10_alice");

    const v03Dir = outDir();
    const mig = core.migrateBundleV02ToV03({ identity: owner, v02Dir, outDir: v03Dir });

    // Migration edition is a well-formed v0.3 bundle.
    assert.equal(mig.aithos, "0.3.0");
    for (const z of ["public", "circle", "self"] as const) {
      assert.equal(mig.zones[z].format_version, "v2");
    }
    assert.equal(mig.zones.public.encrypted, false);
    assert.equal(mig.zones.circle.encrypted, true);
    assert.equal(mig.zones.self.encrypted, true);

    // Edition chain cross-validates across the v0.2 → v0.3 boundary (§3.10.3′).
    assert.equal(mig.edition.supersedes, v02.bundle_id);
    assert.equal(mig.edition.height, v02.edition.height + 1);
    assert.equal(mig.edition.prev_hash, "sha256:" + core.canonicalManifestHashHex(v02));

    // Content is preserved through the split (same titles/bodies, same section ids).
    const back = core.readBundleSections(v03Dir, owner);
    assert.equal(back.public[0].body, "Public bio.");
    assert.equal(back.circle[0].body, "1200/day.");
    assert.equal(back.self[0].body, "Up at six.");
    assert.equal(back.self[0].id, mig.zones.self.sections[0].section_id);

    // The migrated bundle verifies (boundary predecessor not cross-hashed here).
    const readers = subjectReaders(owner);
    const vMig = core.verifyBundleV03AtPath(v03Dir, { readers });
    assert.ok(vMig.ok, `migration verify failed: ${vMig.errors.join(", ")}`);

    // A subsequent v0.3 write on top of the migration edition succeeds + chains,
    // carrying forward the unchanged sections and re-encrypting only the edit.
    const nextDir = outDir();
    const m2 = core.authorBundleV03({
      identity: owner,
      outDir: nextDir,
      zones: {
        public: back.public,
        circle: back.circle,
        self: back.self.map((s, i) =>
          i === 0 ? { ...s, body: "Up at five.", gamma_ref: "gamma_" + "5".repeat(24) } : s,
        ),
      },
      prev: { manifest: mig, dir: v03Dir },
    });
    assert.equal(m2.edition.height, mig.edition.height + 1);
    assert.equal(m2.edition.supersedes, mig.bundle_id);

    const v2 = core.verifyBundleV03AtPath(nextDir, { readers, predecessorManifest: mig });
    assert.ok(v2.ok, `subsequent v0.3 write verify failed: ${v2.errors.join(", ")}`);

    // The carried-forward circle section is byte-identical across the two v0.3 editions.
    const a = readFileSync(join(v03Dir, mig.zones.circle.sections[0].file));
    const b = readFileSync(join(nextDir, m2.zones.circle.sections[0].file));
    assert.equal(Buffer.compare(a, b), 0, "unchanged circle section carried forward byte-identical");
  });

  test("B10b — migration carries the gamma log + signed anchor forward (§3.10.4′)", () => {
    const { owner, dir: v02Dir, manifest: v02 } = makeV02Bundle("b10b_alice");
    // The v0.2 ethos was built with section.add edits → it has a gamma log + anchor.
    assert.ok(existsSync(join(v02Dir, "gamma.jsonl.enc")), "v0.2 source has a gamma log");
    assert.ok(v02.gamma && v02.gamma.count > 0, "v0.2 source has a gamma anchor");

    const v03Dir = outDir();
    const mig = core.migrateBundleV02ToV03({ identity: owner, v02Dir, outDir: v03Dir });

    // The log file travelled (byte-identical) and the anchor is recorded in the signed v0.3 manifest.
    assert.ok(existsSync(join(v03Dir, "gamma.jsonl.enc")), "v0.3 bundle carries the gamma log");
    assert.equal(
      Buffer.compare(readFileSync(join(v02Dir, "gamma.jsonl.enc")), readFileSync(join(v03Dir, "gamma.jsonl.enc"))),
      0,
      "gamma log byte-identical (history is not re-encrypted)",
    );
    assert.deepEqual(mig.gamma, v02.gamma, "v0.3 manifest carries the v0.2 gamma anchor verbatim");

    // A subsequent v0.3 edit keeps the gamma log + anchor.
    const back = core.readBundleSections(v03Dir, owner);
    const nextDir = outDir();
    const m2 = core.editSectionV03({
      author: owner,
      bundleDir: v03Dir,
      outDir: nextDir,
      zone: "self",
      sectionId: mig.zones.self.sections[0].section_id,
      change: { body: "edited" },
    });
    void back;
    assert.ok(existsSync(join(nextDir, "gamma.jsonl.enc")), "edit keeps the gamma log");
    assert.deepEqual(m2.gamma, v02.gamma, "edit carries the gamma anchor forward");
  });
});
