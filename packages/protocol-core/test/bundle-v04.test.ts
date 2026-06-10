// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Conformance tests for bundle v0.4 — incremental manifest + zone master keys
 * (spec/drafts/bundle-v0.4-incremental-manifest-and-zone-keys.md, Partie II).
 *
 * Pure-core coverage (no provider, no network):
 *   V1  sharding determinism (shardCountForN bounds, index range, partition)
 *   V2  object canonicalization — property order never changes the sha
 *   V3  zone key seal/open roundtrip + wrong-secret rejection
 *   V4  enc_dek roundtrip + AAD binding (section/zone/kid) + wrong key
 *   V5  title v2 roundtrip + cross-section AAD rejection
 *   V6  manifest v0.4 sign/verify (owner) + tamper detection + hash stability
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

function makeIdentity(handle: string) {
  const id = core.createIdentity(handle, handle);
  core.writeIdentityToDisk(id);
  return id;
}

function outDir(): string {
  const d = mkdtempSync(join(tmpdir(), "aithos-v04-out-"));
  outDirs.push(d);
  return d;
}

/** Materialize did.json for an identity (v0.3 author writes it alongside). */
function didDocFor(id: ReturnType<typeof makeIdentity>) {
  const dir = outDir();
  core.authorBundleV03({ identity: id, outDir: dir, zones: { public: [], circle: [], self: [] } });
  return JSON.parse(readFileSync(join(dir, "did.json"), "utf8"));
}

function entry(id: string, n: number): import("../src/index.js").ShardEntryV04 {
  return {
    section_id: id,
    title: `T ${id}`,
    blob_sha: "b".repeat(63) + String(n % 10),
    sha256_of_plaintext: "p".repeat(63) + String(n % 10),
    gamma_ref: "gamma_" + String(n).padStart(24, "0"),
  };
}

describe("bundle v0.4 (Partie II)", () => {
  test("V1 — sharding determinism", () => {
    // shardCountForN bounds
    for (const [n, want] of [
      [0, 1], [1, 1], [128, 1], [129, 2], [256, 2], [257, 4],
      [1000, 8], [8192, 64], [100000, 64],
    ] as const) {
      assert.equal(core.shardCountForN(n), want, `shardCountForN(${n})`);
    }
    // index in range + deterministic
    for (const count of [1, 2, 8, 64]) {
      for (let i = 0; i < 50; i++) {
        const idx = core.shardIndexForSection(`sec_${i}`, count);
        assert.ok(idx >= 0 && idx < count);
        assert.equal(idx, core.shardIndexForSection(`sec_${i}`, count), "stable");
      }
    }
    // partition: every entry in exactly the shard its id maps to; entries sorted
    const entries = Array.from({ length: 300 }, (_, i) => entry(`sec_${i}`, i));
    const shards = core.shardEntriesV04("circle", entries, 4);
    assert.equal(shards.length, 4);
    let total = 0;
    shards.forEach((sh, si) => {
      total += sh.entries.length;
      const sorted = [...sh.entries].sort((a, b) => (a.section_id < b.section_id ? -1 : 1));
      assert.deepEqual(sh.entries.map((e) => e.section_id), sorted.map((e) => e.section_id));
      for (const e of sh.entries) assert.equal(core.shardIndexForSection(e.section_id, 4), si);
    });
    assert.equal(total, 300, "no entry lost or duplicated");
  });

  test("V2 — object sha ignores property order (JCS)", () => {
    const a = { object: "zone_shard", v: 1, zone: "circle", entries: [entry("sec_1", 1)] } as const;
    const b = { entries: [entry("sec_1", 1)], zone: "circle", v: 1, object: "zone_shard" } as const;
    assert.equal(
      core.objectShaHexV04(a as never),
      core.objectShaHexV04(b as never),
      "JCS canonicalization makes shas order-independent",
    );
    // any content change moves the sha
    const c = { ...a, entries: [entry("sec_2", 2)] };
    assert.notEqual(core.objectShaHexV04(a as never), core.objectShaHexV04(c as never));
  });

  test("V3 — zone key seal/open + wrong secret", () => {
    const alice = makeIdentity("v04_zk_alice");
    const bob = makeIdentity("v04_zk_bob");
    const zk = core.generateZoneKeyV04();
    assert.match(zk.kid, /^zk[0-9a-f]{16}$/);

    const aliceKex = core.subjectRecipientFor(alice, "circle");
    const wrapEntry = core.sealZoneKeyV04(zk, aliceKex.did, aliceKex.x25519PublicKey);
    assert.equal(wrapEntry.recipient, aliceKex.did);

    const opened = core.openZoneKeyV04(wrapEntry, aliceKex.x25519Secret);
    assert.equal(opened.kid, zk.kid);
    assert.deepEqual(Buffer.from(opened.key), Buffer.from(zk.key));

    const bobKex = core.subjectRecipientFor(bob, "circle");
    assert.throws(() => core.openZoneKeyV04(wrapEntry, bobKex.x25519Secret), /unwrap|failed|open/i);
  });

  test("V4 — enc_dek roundtrip + AAD binding", () => {
    const zk = core.generateZoneKeyV04();
    const dek = new Uint8Array(32).fill(7);
    const did = "did:aithos:zV04Subject";
    const enc = core.encryptDekV04(zk, dek, did, "circle", "sec_x");
    assert.equal(enc.kid, zk.kid);

    const back = core.decryptDekV04(zk.key, enc, did, "circle", "sec_x");
    assert.deepEqual(Buffer.from(back), Buffer.from(dek));

    // wrong section / wrong zone / wrong kid / wrong key all fail closed
    assert.throws(() => core.decryptDekV04(zk.key, enc, did, "circle", "sec_y"));
    assert.throws(() => core.decryptDekV04(zk.key, enc, did, "self", "sec_x"));
    assert.throws(() => core.decryptDekV04(zk.key, { ...enc, kid: "zk" + "0".repeat(16) }, did, "circle", "sec_x"));
    const other = core.generateZoneKeyV04();
    assert.throws(() => core.decryptDekV04(other.key, enc, did, "circle", "sec_x"));
  });

  test("V5 — title v2 roundtrip + cross-section rejection", () => {
    const dek = new Uint8Array(32).fill(9);
    const did = "did:aithos:zV04Subject";
    const tc = core.encryptTitleV2(dek, did, "sec_t", { title: "Hidden", tags: ["a", "b"] });
    const back = core.decryptTitleV2(dek, did, "sec_t", tc);
    assert.deepEqual(back, { title: "Hidden", tags: ["a", "b"] });
    assert.throws(() => core.decryptTitleV2(dek, did, "sec_other", tc));
  });

  test("V6 — manifest v0.4 sign/verify + tamper + hash stability", () => {
    const alice = makeIdentity("v04_m_alice");
    const didDoc = didDocFor(alice);
    const did = core.rootDid ? (core as { rootDid?: (i: unknown) => string }).rootDid!(alice) : didDoc.id;

    const zones = {
      public: { n: 1, shard_count: 1, shard_shas: ["a".repeat(64)] },
      circle: { n: 2, shard_count: 1, shard_shas: ["c".repeat(64)], keyring_sha: "d".repeat(64) },
      self: { n: 0, shard_count: 1, shard_shas: ["e".repeat(64)], keyring_sha: "f".repeat(64) },
    };
    const unsigned = core.buildManifestV04({
      subjectDid: didDoc.id ?? did,
      handle: "v04_m_alice",
      displayName: "v04_m_alice",
      bundleId: "bundle_v04_test",
      editionVersion: "1.0",
      createdAt: new Date().toISOString(),
      supersedes: null,
      prevHash: null,
      height: 1,
      zones,
      sha256OfDidJson: "0".repeat(64),
    });
    assert.equal(unsigned.aithos, "0.4.0");

    const signed = core.signManifestV04(alice, unsigned);
    assert.ok(signed.integrity.manifest_signature.value.length > 0);
    assert.ok(core.verifyManifestSignatureV04(signed, didDoc).ok, "owner signature verifies");

    // hash is stable across re-serialization and signature-value blanking
    const h1 = core.canonicalManifestHashHexV04(signed);
    const h2 = core.canonicalManifestHashHexV04(JSON.parse(JSON.stringify(signed)));
    assert.equal(h1, h2);

    // tampering with a zone ref breaks the signature (zones are signed)
    const tampered = JSON.parse(JSON.stringify(signed)) as typeof signed;
    tampered.zones.circle.shard_shas = ["9".repeat(64)];
    assert.equal(core.verifyManifestSignatureV04(tampered, didDoc).ok, false, "tamper detected");
    assert.notEqual(core.canonicalManifestHashHexV04(tampered), h1, "hash moves with zones");
  });
});
