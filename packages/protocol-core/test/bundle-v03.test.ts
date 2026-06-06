// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Conformance tests for the v0.3 per-section bundle format
 * (spec/drafts/bundle-v0.3-per-section-encryption.md, §3.12′ test matrix).
 *
 * This pass covers bricks 1–5 (write/read core + v0.3 verifier): B1–B8 and
 * B11–B15. B9 (v0.2 compat read) and B10 (migration) depend on bricks 6–7 and
 * are deferred to the next focused pass.
 *
 * AAD note: per the design decision recorded in the spec, the per-section AEAD
 * binds `subject_did ‖ section_id` (not the draft's per-edition bundle_id), so
 * carried-forward sections stay byte-identical across editions (B3). B5 is
 * therefore the CROSS-SUBJECT replay test: copying a ciphertext into a
 * different subject's bundle must fail; copying into another edition of the
 * same subject is legitimate carry-forward.
 */

import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

/* -------------------------------------------------------------------------- */
/*  Fixture plumbing                                                          */
/* -------------------------------------------------------------------------- */

let core!: typeof import("../src/index.js");
let KEYSTORE!: string;
const outDirs: string[] = [];

before(async () => {
  // AITHOS_HOME must be frozen before the first import of the library.
  KEYSTORE = freshKeystore();
  core = await import("../src/index.js");
});

after(() => {
  cleanupKeystore(KEYSTORE);
  for (const d of outDirs) rmSync(d, { recursive: true, force: true });
});

/** A fresh, on-disk identity (writes did.json + sealed seeds into the keystore). */
function makeIdentity(handle: string) {
  const id = core.createIdentity(handle, handle);
  core.writeIdentityToDisk(id);
  return id;
}

/** A throwaway output directory for a bundle edition. */
function outDir(): string {
  const d = mkdtempSync(join(tmpdir(), "aithos-v03-out-"));
  outDirs.push(d);
  return d;
}

/** Build a Section with a deterministic, valid-looking gamma_ref. */
function sec(id: string, title: string, body: string, gammaN: number, tags?: string[]) {
  return {
    id,
    title,
    body,
    gamma_ref: "gamma_" + String(gammaN).padStart(24, "0"),
    ...(tags ? { tags } : {}),
  };
}

const pad3 = (i: number) => String(i).padStart(3, "0");

/** Subject reader credential for an encrypted zone. */
function reader(id: ReturnType<typeof makeIdentity>, zone: "circle" | "self") {
  const r = core.subjectRecipientFor(id, zone);
  return { didUrl: r.did, x25519Secret: r.x25519Secret };
}

/* -------------------------------------------------------------------------- */
/*  B1 — v0.3 round trip, single section                                      */
/* -------------------------------------------------------------------------- */

describe("v0.3 per-section bundle (§3.12′)", () => {
  test("B1 — round trip, single self section", () => {
    const alice = makeIdentity("b1_alice");
    const dir = outDir();
    const manifest = core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [], circle: [], self: [sec("sec_aa1", "Morning routine", "Up at six.", 1)] },
    });

    const desc = manifest.zones.self.sections[0];
    // Per-section DEK fresh; ciphertext at self/<id>.enc.
    assert.equal(desc.file, "self/sec_aa1.enc");
    assert.ok(existsSync(join(dir, "self", "sec_aa1.enc")));
    assert.ok(desc.cipher && desc.cipher.nonce.length > 0, "section carries a cipher + nonce");
    assert.equal(manifest.zones.self.format_version, "v2");
    assert.equal(manifest.zones.self.encrypted, true);

    // Manifest signature verifies.
    const didDoc = JSON.parse(readFileSync(join(dir, "did.json"), "utf8"));
    assert.ok(core.verifyManifestSignatureV03(manifest, didDoc).ok, "manifest signature verifies");

    // Reader decrypts + the full bundle verifies.
    const rd = reader(alice, "self");
    const res = core.verifyBundleV03AtPath(dir, { readers: [rd] });
    assert.ok(res.ok, `verify failed: ${res.errors.join(", ")}`);

    // readSection round-trips the body.
    const back = core.readSection(dir, manifest.zones.self, desc, core.rootDid(alice), rd);
    assert.ok(back.accessible);
    assert.equal(back.section!.title, "Morning routine");
    assert.equal(back.section!.body, "Up at six.");
  });

  /* ------------------------------------------------------------------------ */
  /*  B2 — many sections                                                      */
  /* ------------------------------------------------------------------------ */

  test("B2 — 100 sections, independent DEK/nonce, distinct AADs", () => {
    const alice = makeIdentity("b2_alice");
    const dir = outDir();
    const sections = Array.from({ length: 100 }, (_, i) =>
      sec(`sec_${pad3(i)}`, `Title ${i}`, `body ${i}`, i + 1),
    );
    const m = core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [], circle: [], self: sections },
    });

    assert.equal(m.zones.self.sections.length, 100);

    // Each section has its own nonce (independent DEK ⇒ fresh nonce per seal).
    const nonces = new Set(m.zones.self.sections.map((s) => s.cipher?.nonce));
    assert.equal(nonces.size, 100, "all 100 nonces distinct");

    // Per-section AADs are distinct (section_id is part of the AAD).
    const did = core.rootDid(alice);
    const aadA = Buffer.from(core.sectionAad(did, "sec_000")).toString("hex");
    const aadB = Buffer.from(core.sectionAad(did, "sec_001")).toString("hex");
    assert.notEqual(aadA, aadB);

    // Reader decrypts all of them.
    const rd = reader(alice, "self");
    const res = core.verifyBundleV03AtPath(dir, { readers: [rd] });
    assert.ok(res.ok, `verify failed: ${res.errors.slice(0, 5).join(", ")}`);

    const spot = core.readSection(dir, m.zones.self, m.zones.self.sections[42], did, rd);
    assert.equal(spot.section!.body, "body 42");
  });

  /* ------------------------------------------------------------------------ */
  /*  B3 — single-section edit cost (byte-identical carry-forward)            */
  /* ------------------------------------------------------------------------ */

  test("B3 — editing section 5 of 100 rewrites only that blob", () => {
    const alice = makeIdentity("b3_alice");
    const dir1 = outDir();
    const secs1 = Array.from({ length: 100 }, (_, i) =>
      sec(`sec_${pad3(i)}`, `Title ${i}`, `body ${i}`, i + 1),
    );
    const m1 = core.authorBundleV03({
      identity: alice,
      outDir: dir1,
      zones: { public: [], circle: [], self: secs1 },
    });

    // Edition 2: section 5 gets a new body + new gamma_ref; everything else identical.
    const dir2 = outDir();
    const secs2 = secs1.map((s, i) =>
      i === 5 ? { ...s, body: "body 5 EDITED", gamma_ref: "gamma_" + "9".repeat(24) } : s,
    );
    const m2 = core.authorBundleV03({
      identity: alice,
      outDir: dir2,
      zones: { public: [], circle: [], self: secs2 },
      prev: { manifest: m1, dir: dir1 },
    });

    // Only self/sec_005.enc differs on disk; the other 99 are byte-identical.
    for (let i = 0; i < 100; i++) {
      const a = readFileSync(join(dir1, "self", `sec_${pad3(i)}.enc`));
      const b = readFileSync(join(dir2, "self", `sec_${pad3(i)}.enc`));
      if (i === 5) assert.notEqual(Buffer.compare(a, b), 0, "edited section ciphertext changed");
      else assert.equal(Buffer.compare(a, b), 0, `sec_${pad3(i)} must be byte-identical`);
    }

    // Manifest: only section[5]'s sha/nonce/gamma_ref moved.
    for (let i = 0; i < 100; i++) {
      const s1 = m1.zones.self.sections[i];
      const s2 = m2.zones.self.sections[i];
      if (i === 5) {
        assert.notEqual(s1.sha256_of_plaintext, s2.sha256_of_plaintext);
        assert.notEqual(s1.cipher!.nonce, s2.cipher!.nonce);
        assert.notEqual(s1.gamma_ref, s2.gamma_ref);
      } else {
        assert.equal(s1.sha256_of_plaintext, s2.sha256_of_plaintext);
        assert.equal(s1.cipher!.nonce, s2.cipher!.nonce);
        assert.equal(s1.gamma_ref, s2.gamma_ref);
      }
    }

    // Edition chain + full verify against the predecessor (§3.8′ #8).
    assert.equal(m2.edition.height, 2);
    assert.equal(m2.edition.supersedes, m1.bundle_id);
    const res = core.verifyBundleV03AtPath(dir2, {
      readers: [reader(alice, "self")],
      predecessorManifest: m1,
    });
    assert.ok(res.ok, `verify failed: ${res.errors.slice(0, 5).join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B4 — cross-section AAD binding                                          */
  /* ------------------------------------------------------------------------ */

  test("B4 — swapping two section ciphertexts makes both fail", () => {
    const alice = makeIdentity("b4_alice");
    const dir = outDir();
    const m = core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: {
        public: [],
        circle: [],
        self: [sec("sec_aaa", "A", "alpha", 1), sec("sec_bbb", "B", "bravo", 2)],
      },
    });
    assert.ok(m.zones.self.sections.length === 2);

    // Swap the two ciphertext files on disk.
    const pA = join(dir, "self", "sec_aaa.enc");
    const pB = join(dir, "self", "sec_bbb.enc");
    const bytesA = readFileSync(pA);
    const bytesB = readFileSync(pB);
    writeFileSync(pA, bytesB);
    writeFileSync(pB, bytesA);

    const res = core.verifyBundleV03AtPath(dir, { readers: [reader(alice, "self")] });
    assert.ok(!res.ok, "verify must fail after the swap");
    const decryptFailures = res.errors.filter((e) => /decrypt failed/i.test(e));
    assert.ok(decryptFailures.length >= 2, `both sections fail AAD: ${res.errors.join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B5 — cross-SUBJECT AAD binding                                          */
  /* ------------------------------------------------------------------------ */

  test("B5 — a ciphertext does not decrypt under a different subject_did", () => {
    const alice = makeIdentity("b5_alice");
    const r = core.subjectRecipientFor(alice, "self");
    const recipients = [{ did: r.did, x25519PublicKey: r.x25519PublicKey }];
    const aliceDid = core.rootDid(alice);

    const enc = core.encryptSection("# S\n\nsecret\n", aliceDid, "sec_sss", recipients);

    // Under Alice's own subject_did it opens fine (sanity).
    const ok = core.decryptSection(
      enc.ciphertext,
      enc.cipher,
      aliceDid,
      "sec_sss",
      r.did,
      r.x25519Secret,
    );
    assert.equal(core.parseSectionMarkdown(ok).body, "secret");

    // Re-homed into a different subject's bundle: the wrap still resolves (same
    // recipient key) but the AAD's subject_did differs ⇒ AEAD tag fails.
    const bobDid = "did:aithos:z6MkBobDifferentSubjectXXXXXXXXXXXXXXXXXXXXXXXX";
    assert.throws(
      () =>
        core.decryptSection(enc.ciphertext, enc.cipher, bobDid, "sec_sss", r.did, r.x25519Secret),
      /authentication failed/i,
    );
  });

  /* ------------------------------------------------------------------------ */
  /*  B6 — manifest tampering                                                 */
  /* ------------------------------------------------------------------------ */

  test("B6 — any byte change to manifest.json invalidates the signature", () => {
    const alice = makeIdentity("b6_alice");
    const dir = outDir();
    core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [], circle: [], self: [sec("sec_x1", "T", "B", 1)] },
    });
    const rd = reader(alice, "self");
    assert.ok(core.verifyBundleV03AtPath(dir, { readers: [rd] }).ok, "baseline verifies");

    const mpath = join(dir, "manifest.json");
    const tampered = JSON.parse(readFileSync(mpath, "utf8"));
    tampered.display_name = tampered.display_name + "!"; // one-character change
    writeFileSync(mpath, JSON.stringify(tampered, null, 2) + "\n");

    const res = core.verifyBundleV03AtPath(dir, { readers: [rd] });
    assert.ok(!res.ok, "verify must fail");
    assert.ok(res.errors.some((e) => /signature/i.test(e)), `expected a signature error: ${res.errors.join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B7 — orphan ciphertext                                                  */
  /* ------------------------------------------------------------------------ */

  test("B7 — an unlisted ciphertext file fails verification", () => {
    const alice = makeIdentity("b7_alice");
    const dir = outDir();
    core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [], circle: [], self: [sec("sec_x1", "T", "B", 1)] },
    });
    writeFileSync(join(dir, "self", "sec_orphan.enc"), Buffer.from("not in the manifest"));

    const res = core.verifyBundleV03AtPath(dir, { readers: [reader(alice, "self")] });
    assert.ok(!res.ok);
    assert.ok(res.errors.some((e) => /orphan/i.test(e)), `expected an orphan error: ${res.errors.join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B8 — missing ciphertext                                                 */
  /* ------------------------------------------------------------------------ */

  test("B8 — a manifest entry with no file fails verification", () => {
    const alice = makeIdentity("b8_alice");
    const dir = outDir();
    core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: {
        public: [],
        circle: [],
        self: [sec("sec_x1", "T", "B", 1), sec("sec_x2", "T2", "B2", 2)],
      },
    });
    rmSync(join(dir, "self", "sec_x2.enc"));

    const res = core.verifyBundleV03AtPath(dir, { readers: [reader(alice, "self")] });
    assert.ok(!res.ok);
    assert.ok(
      res.errors.some((e) => /missing from bundle/i.test(e)),
      `expected a missing-file error: ${res.errors.join(", ")}`,
    );
  });

  /* ------------------------------------------------------------------------ */
  /*  B11 — section-grain partial read                                        */
  /* ------------------------------------------------------------------------ */

  test("B11 — reader decrypts the section it is wrapped to, skips the other", () => {
    const alice = makeIdentity("b11_alice");
    const stranger = core.createIdentity("b11_stranger", "Stranger"); // keys only; no keystore needed
    const aliceR = core.subjectRecipientFor(alice, "self");
    const strangerR = core.subjectRecipientFor(stranger, "self");
    const subjectDid = core.rootDid(alice);
    const dir = outDir();

    // Section X wrapped to Alice; section Y wrapped to the stranger.
    const descX = core.writeSection(
      {
        bundleDir: dir,
        zone: "self",
        encrypted: true,
        subjectDid,
        recipients: [{ did: aliceR.did, x25519PublicKey: aliceR.x25519PublicKey }],
      },
      sec("sec_xxx", "X", "for alice", 1),
    );
    const descY = core.writeSection(
      {
        bundleDir: dir,
        zone: "self",
        encrypted: true,
        subjectDid,
        recipients: [{ did: strangerR.did, x25519PublicKey: strangerR.x25519PublicKey }],
      },
      sec("sec_yyy", "Y", "for stranger", 2),
    );

    const zone = { format_version: "v2" as const, encrypted: true, sections: [descX, descY] };
    const rd = { didUrl: aliceR.did, x25519Secret: aliceR.x25519Secret };

    const rx = core.readSection(dir, zone, descX, subjectDid, rd);
    const ry = core.readSection(dir, zone, descY, subjectDid, rd);

    assert.ok(rx.accessible, "X is readable");
    assert.equal(rx.section!.body, "for alice");
    assert.ok(!ry.accessible, "Y is reported inaccessible, not thrown");
    assert.ok(/no wrap/i.test(ry.reason ?? ""), `Y reason: ${ry.reason}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B12 — independence of section DEKs                                      */
  /* ------------------------------------------------------------------------ */

  test("B12 — a leaked section DEK does not open another section", () => {
    const alice = makeIdentity("b12_alice");
    const r = core.subjectRecipientFor(alice, "self");
    const recipients = [{ did: r.did, x25519PublicKey: r.x25519PublicKey }];
    const did = core.rootDid(alice);

    const X = core.encryptSection("# X\n\nbodyX\n", did, "sec_x", recipients);
    const Y = core.encryptSection("# Y\n\nbodyY\n", did, "sec_y", recipients);

    // "Leak" section X's DEK by unwrapping it with Alice's secret.
    const dekX = core.unwrapDek(X.cipher.wraps[0], r.x25519Secret);

    // The leaked DEK opens X (sanity)...
    const openedX = new XChaCha20Poly1305(dekX).open(
      core.base64urlDecode(X.cipher.nonce),
      X.ciphertext,
      core.sectionAad(did, "sec_x"),
    );
    assert.ok(openedX, "leaked DEK opens its own section");

    // ...but NOT section Y (different independent DEK; also different AAD).
    const openedY = new XChaCha20Poly1305(dekX).open(
      core.base64urlDecode(Y.cipher.nonce),
      Y.ciphertext,
      core.sectionAad(did, "sec_y"),
    );
    assert.equal(openedY, null, "leaked DEK_X cannot open section Y");
  });

  /* ------------------------------------------------------------------------ */
  /*  B13 — public zone v2 round trip                                         */
  /* ------------------------------------------------------------------------ */

  test("B13 — 5 public sections, no cipher, fetch one + verify hash", () => {
    const alice = makeIdentity("b13_alice");
    const dir = outDir();
    const pubs = Array.from({ length: 5 }, (_, i) =>
      sec(`sec_p${i}`, `Public ${i}`, `public body ${i}`, i + 1),
    );
    const m = core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: pubs, circle: [], self: [] },
    });

    assert.equal(m.zones.public.format_version, "v2");
    assert.equal(m.zones.public.encrypted, false);
    for (const d of m.zones.public.sections) {
      assert.ok(!d.cipher, "public section carries no cipher");
      assert.ok(d.file.endsWith(".md"));
      assert.ok(existsSync(join(dir, d.file)));
    }

    // Fetch one section file directly (no reader key needed) + verify its hash.
    const d2 = m.zones.public.sections[2];
    const res = core.readSection(dir, m.zones.public, d2, core.rootDid(alice));
    assert.ok(res.accessible);
    assert.equal(res.section!.body, "public body 2");

    const v = core.verifyBundleV03AtPath(dir, {});
    assert.ok(v.ok, `verify failed: ${v.errors.join(", ")}`);
  });

  /* ------------------------------------------------------------------------ */
  /*  B14 — public single-section edit                                        */
  /* ------------------------------------------------------------------------ */

  test("B14 — editing one public section rewrites only that file", () => {
    const alice = makeIdentity("b14_alice");
    const dir1 = outDir();
    const pubs1 = Array.from({ length: 5 }, (_, i) =>
      sec(`sec_p${i}`, `Public ${i}`, `public ${i}`, i + 1),
    );
    const m1 = core.authorBundleV03({
      identity: alice,
      outDir: dir1,
      zones: { public: pubs1, circle: [], self: [] },
    });

    const dir2 = outDir();
    const pubs2 = pubs1.map((s, i) =>
      i === 2 ? { ...s, body: "public 2 EDITED", gamma_ref: "gamma_" + "7".repeat(24) } : s,
    );
    const m2 = core.authorBundleV03({
      identity: alice,
      outDir: dir2,
      zones: { public: pubs2, circle: [], self: [] },
      prev: { manifest: m1, dir: dir1 },
    });

    for (let i = 0; i < 5; i++) {
      const a = readFileSync(join(dir1, "public", `sec_p${i}.md`));
      const b = readFileSync(join(dir2, "public", `sec_p${i}.md`));
      if (i === 2) assert.notEqual(Buffer.compare(a, b), 0, "edited public section changed");
      else assert.equal(Buffer.compare(a, b), 0, `sec_p${i}.md must be byte-identical`);
    }

    const v = core.verifyBundleV03AtPath(dir2, { predecessorManifest: m1 });
    assert.ok(v.ok, `verify failed: ${v.errors.join(", ")}`);
    assert.equal(m2.edition.height, 2);
  });

  /* ------------------------------------------------------------------------ */
  /*  B15 — forbidden cipher on public                                        */
  /* ------------------------------------------------------------------------ */

  test("B15 — a cipher on a public section fails schema validation", () => {
    const alice = makeIdentity("b15_alice");
    const dir = outDir();
    core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [sec("sec_p0", "Public", "body", 1)], circle: [], self: [] },
    });

    // Inject a cipher onto the public section, then RE-SIGN so the failure is
    // isolated to the schema check (not the manifest signature).
    const mpath = join(dir, "manifest.json");
    const tampered = JSON.parse(readFileSync(mpath, "utf8"));
    tampered.zones.public.sections[0].cipher = {
      alg: "xchacha20poly1305-ietf",
      nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      wraps: [],
    };
    const resigned = core.signManifestV03(alice, tampered);
    writeFileSync(mpath, JSON.stringify(resigned, null, 2) + "\n");

    const v = core.verifyBundleV03AtPath(dir, {});
    assert.ok(!v.ok, "verify must fail");
    assert.ok(
      v.errors.some((e) => /forbidden cipher on public/i.test(e)),
      `expected forbidden-cipher error: ${v.errors.join(", ")}`,
    );

    // The encrypted:true variant on the public zone is likewise rejected.
    const tampered2 = JSON.parse(readFileSync(mpath, "utf8"));
    tampered2.zones.public.sections[0].cipher = undefined;
    delete tampered2.zones.public.sections[0].cipher;
    tampered2.zones.public.encrypted = true;
    const resigned2 = core.signManifestV03(alice, tampered2);
    writeFileSync(mpath, JSON.stringify(resigned2, null, 2) + "\n");
    const v2 = core.verifyBundleV03AtPath(dir, {});
    assert.ok(!v2.ok);
    assert.ok(
      v2.errors.some((e) => /encrypted must be false/i.test(e)),
      `expected encrypted-flag error: ${v2.errors.join(", ")}`,
    );
  });

  /* ------------------------------------------------------------------------ */
  /*  B16 — encrypted self index (circle clear / self private)                */
  /* ------------------------------------------------------------------------ */

  test("B16 — self index is encrypted: host sees no titles, subject decrypts", () => {
    const alice = makeIdentity("idx_alice");
    const dir = outDir();
    const m = core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: {
        public: [],
        circle: [sec("sec_c1", "Day rate", "1200/day.", 1)],
        self: [sec("sec_s1", "Routine", "Up at six.", 2), sec("sec_s2", "Goals", "Ship v0.3.", 3)],
      },
    });
    const subjectDid = core.rootDid(alice);

    // circle: clear index — title visible, no index_cipher.
    assert.ok(!m.zones.circle.index_encrypted);
    assert.equal(m.zones.circle.index_cipher, undefined);
    assert.equal(m.zones.circle.sections[0].title, "Day rate");

    // self: encrypted index — no clear titles, index_cipher present, structural fields intact.
    assert.equal(m.zones.self.index_encrypted, true);
    assert.ok(m.zones.self.index_cipher && m.zones.self.index_cipher.ct.length > 0);
    for (const s of m.zones.self.sections) {
      assert.equal(s.title, undefined, "self section carries no clear title");
      assert.ok(s.section_id && s.file && s.cipher && s.sha256_of_plaintext, "structural fields stay clear");
    }

    // Host (no key): self titles hidden; circle titles visible.
    const hostSelf = core.readZoneIndex("self", m.zones.self, subjectDid);
    assert.deepEqual(hostSelf.map((r) => r.title_hidden), [true, true]);
    assert.deepEqual(hostSelf.map((r) => r.title), [undefined, undefined]);
    const hostCircle = core.readZoneIndex("circle", m.zones.circle, subjectDid);
    assert.equal(hostCircle[0].title, "Day rate");

    // Subject (with key): decrypts the self index → titles.
    const rd = reader(alice, "self");
    const ownerSelf = core.readZoneIndex("self", m.zones.self, subjectDid, rd);
    assert.deepEqual(ownerSelf.map((r) => r.title), ["Routine", "Goals"]);
    assert.deepEqual(ownerSelf.map((r) => r.title_hidden), [false, false]);

    // Read one section by id (title recovered from the decrypted body).
    const one = core.readSection(dir, m.zones.self, m.zones.self.sections[0], subjectDid, rd);
    assert.ok(one.accessible);
    assert.equal(one.section!.title, "Routine");
    assert.equal(one.section!.body, "Up at six.");

    // Verifies both ways: host (opaque-but-attested) and subject (index cross-check).
    assert.ok(core.verifyBundleV03AtPath(dir, {}).ok, "host verify");
    assert.ok(core.verifyBundleV03AtPath(dir, { readers: [rd] }).ok, "subject verify");
  });

  test("B16b — a clear title leaked onto a self section fails verification", () => {
    const alice = makeIdentity("idx_neg");
    const dir = outDir();
    core.authorBundleV03({
      identity: alice,
      outDir: dir,
      zones: { public: [], circle: [], self: [sec("sec_s1", "Secret", "body", 1)] },
    });
    const mpath = join(dir, "manifest.json");
    const t = JSON.parse(readFileSync(mpath, "utf8"));
    t.zones.self.sections[0].title = "Secret"; // leak a clear title onto self
    const resigned = core.signManifestV03(alice, t); // re-sign so it's a schema failure, not a sig failure
    writeFileSync(mpath, JSON.stringify(resigned, null, 2) + "\n");

    const v = core.verifyBundleV03AtPath(dir, {});
    assert.ok(!v.ok);
    assert.ok(
      v.errors.some((e) => /clear title forbidden/i.test(e)),
      `expected clear-title-forbidden error: ${v.errors.join(", ")}`,
    );
  });
});
