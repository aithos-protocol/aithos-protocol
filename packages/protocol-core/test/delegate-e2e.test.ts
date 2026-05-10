// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: distant-delegate scenario (v0.2.1 acceptance spec).
 *
 * The story these tests tell — each `test(...)` step is one movement:
 *
 *   1. Alice creates her Aithos identity and writes an ethos with a circle
 *      section. She's the owner; she holds all four sealed seeds.
 *   2. Alice mints a delegate Ed25519 keypair for her AI agent, and issues a
 *      write-mandate on the circle sphere. The mandate also grants the agent
 *      read access to the circle zone.
 *   3. Issuing the mandate rewraps Alice's circle zone DEK (and her gamma
 *      log's DEK) to include the agent's X25519 pubkey — so a bundle packed
 *      AFTER mandate-issue is decryptable by the agent.
 *   4. Alice packs her ethos + mandate + did.json into a bundle. On a fresh
 *      machine (fresh AITHOS_HOME), Bob-the-agent installs it: tracked
 *      identity, no sealed seeds for Alice, but agent keyfile + mandate on
 *      disk.
 *   5. Bob appends a circle section via the mandate. The gamma entry is
 *      signed by the delegate key and carries `authorized_by` = mandate id.
 *      The zone signature and manifest signature follow the same pattern.
 *      This is the step that fails on v0.2.0: `loadIdentity` refuses tracked
 *      installs, and `signZone`/`signManifest` hardcode owner-sphere keys.
 *   6. Bob re-packs the updated ethos; Alice installs it back on her side
 *      (with --force semantics in CLI, but in tests we just move files).
 *      Alice can decrypt the circle zone (her sphere key is still a
 *      recipient) and verify the delegate's entries via the mandate.
 *   7. Alice revokes the mandate. She re-pins the circle zone and gamma log
 *      to a recipient set that no longer includes the agent. Bob's cached
 *      wrap for the new edition does not exist → he cannot decrypt the new
 *      state. Verifiers walking the gamma log reject any delegate-signed
 *      entries whose `at` is >= revocation.revoked_at.
 *
 * These tests are written AGAINST the target v0.2.1 API, not the current
 * v0.2.0 API. Several of them will fail before the refactor lands — that's
 * the whole point. The failures are the TDD checklist for the refactor.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/* -------------------------------------------------------------------------- */
/*  Test fixtures                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Load a freshly-isolated copy of @aithos/protocol-core. Every scenario below
 * starts from a clean AITHOS_HOME — import order matters (see helpers.ts),
 * so each test calls this AFTER freshKeystore().
 */
async function loadCore() {
  return await import("../src/index.js");
}

function encodeMultibaseEd25519(pk: Uint8Array): string {
  // Mirror of did.ts encoder — kept local to avoid importing before
  // AITHOS_HOME is set. base58btc + 0xed01 multicodec prefix.
  const prefixed = new Uint8Array(2 + pk.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pk, 2);
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let zeros = 0;
  while (zeros < prefixed.length && prefixed[zeros] === 0) zeros++;
  const input = Array.from(prefixed);
  const b58: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let carry = input[i];
    for (let j = 0; j < b58.length; j++) {
      carry += b58[j] << 8;
      b58[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      b58.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < zeros; i++) out += "1";
  for (let i = b58.length - 1; i >= 0; i--) out += ALPHA[b58[i]];
  return "z" + out;
}

/* -------------------------------------------------------------------------- */
/*  Baseline — owner-only happy path (should pass on v0.2.0 today)           */
/* -------------------------------------------------------------------------- */

describe("owner-only baseline (should already pass)", () => {
  test("owner creates identity, adds a circle section, reads it back, verifies", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);
      core.ensureEthosLayout("alice");

      const { section, gammaEntry, manifest } = core.addSection({
        handle: "alice",
        identity: owner,
        zone: "circle",
        title: "Project plan",
        body: "Ship v0.2.1 this week.",
      });

      assert.equal(section.title, "Project plan");
      assert.equal(gammaEntry.op, "section.add");
      assert.equal(manifest.edition.height, 1);

      const back = core.loadZoneDoc("alice", "circle", owner);
      assert.equal(back.sections.length, 1);
      assert.equal(back.sections[0].body, "Ship v0.2.1 this week.");

      const didDoc = core.loadIdentityMetadata("alice").didDocument;
      const verify = core.verifyEthos("alice", owner, didDoc);
      assert.ok(verify.ok, `verifyEthos failed: ${verify.errors.join(", ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  ed25519 -> x25519 pubkey conversion (NEW primitive)                       */
/* -------------------------------------------------------------------------- */

describe("ed25519PubToX25519Pub (public-key Edwards→Montgomery)", () => {
  test("round-trips against the seed-based derivation", async () => {
    freshKeystore();
    const core = await loadCore();

    // @ts-expect-error — helper is added in the v0.2.1 refactor
    const ed2x: (edPub: Uint8Array) => Uint8Array = core.ed25519PubToX25519Pub;
    assert.equal(typeof ed2x, "function", "ed25519PubToX25519Pub must be exported");

    // For any seed s, we have:
    //   edSeedToX25519Secret(s) -> sk
    //   x25519PublicFromSecret(sk) -> xpub_from_secret
    //   ed.getPublicKey(s) -> edpub
    //   ed25519PubToX25519Pub(edpub) -> xpub_from_pub
    // The invariant: xpub_from_secret == xpub_from_pub.
    for (let trial = 0; trial < 5; trial++) {
      const seed = new Uint8Array(randomBytes(32));
      const edPub = ed.getPublicKey(seed);
      const xSecret = core.edSeedToX25519Secret(seed);
      const xPubFromSecret = core.x25519PublicFromSecret(xSecret);
      const xPubFromEdPub = ed2x(edPub);
      assert.deepEqual(
        Array.from(xPubFromEdPub),
        Array.from(xPubFromSecret),
        "ed25519 pub -> x25519 pub must match x25519 pub derived from secret",
      );
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Mandate v0.2.1 — forbidden scopes + read scopes                           */
/* -------------------------------------------------------------------------- */

describe("mandate format v0.4.0", () => {
  test("bumps the mandate envelope to 0.4.0", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const seed = new Uint8Array(randomBytes(32));
      const pub = ed.getPublicKey(seed);

      const m = core.createMandate({
        issuer: owner,
        actorSphere: "circle",
        grantee: { id: "agent:bob", pubkey: encodeMultibaseEd25519(pub) },
        scopes: ["ethos.write.circle", "ethos.read.circle"],
        ttlSeconds: 3600,
      });
      assert.equal(m["aithos-mandate"], "0.4.0", "mandate version must be 0.4.0");
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("accepts the new read scopes: ethos.read.{public,circle,self}", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // Read-only mandate on circle sphere — no write, so no pubkey required.
      const m = core.createMandate({
        issuer: owner,
        actorSphere: "circle",
        grantee: { id: "viewer:bob" },
        scopes: ["ethos.read.circle"],
        ttlSeconds: 3600,
      });
      assert.ok(m.scopes.includes("ethos.read.circle"));
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("rejects forbidden scopes (mandate.issue, mandate.revoke, identity.rotate-keys, identity.destroy)", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      for (const forbidden of [
        "mandate.issue",
        "mandate.revoke",
        "identity.rotate-keys",
        "identity.destroy",
      ]) {
        assert.throws(
          () =>
            core.createMandate({
              issuer: owner,
              actorSphere: "self",
              grantee: { id: "agent:evil" },
              scopes: [forbidden],
              ttlSeconds: 3600,
            }),
          new RegExp(`forbidden|not permitted|${forbidden}`, "i"),
          `scope ${forbidden} must be rejected`,
        );
      }
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("rejects ethos.read.self when signed on a circle sphere", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(() =>
        core.createMandate({
          issuer: owner,
          actorSphere: "circle",
          grantee: { id: "agent:bob" },
          scopes: ["ethos.read.self"],
          ttlSeconds: 3600,
        }),
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Author abstraction (NEW) — OwnerAuthor vs DelegateAuthor                  */
/* -------------------------------------------------------------------------- */

describe("Author abstraction", () => {
  test("ownerAuthor + delegateAuthor constructors exist and are distinguishable", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();

      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // @ts-expect-error — API added in v0.2.1
      const oa = core.ownerAuthor(owner);
      assert.equal(oa.kind, "owner");

      const delegateSeed = new Uint8Array(randomBytes(32));
      const delegatePub = ed.getPublicKey(delegateSeed);
      const delegateMb = encodeMultibaseEd25519(delegatePub);
      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "circle",
        grantee: { id: "agent:bob", pubkey: delegateMb },
        scopes: ["ethos.write.circle", "ethos.read.circle"],
        ttlSeconds: 3600,
      });
      const subjectMeta = core.loadIdentityMetadata("alice");

      // @ts-expect-error — API added in v0.2.1
      const da = core.delegateAuthor({
        subject: subjectMeta,
        seed: delegateSeed,
        pubkeyMultibase: delegateMb,
        mandate,
      });
      assert.equal(da.kind, "delegate");
      assert.equal(da.mandate.id, mandate.id);
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Full delegate-on-tracked E2E                                              */
/* -------------------------------------------------------------------------- */

describe("delegate-on-tracked writes → owner reads back → revoke", () => {
  test("full scenario", async () => {
    // --- Owner side ---------------------------------------------------------
    const ownerHome = freshKeystore();
    try {
      const core = await loadCore();

      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);
      core.ensureEthosLayout("alice");

      // Seed the ethos with a circle section signed by the owner.
      core.addSection({
        handle: "alice",
        identity: owner,
        zone: "circle",
        title: "Friends",
        body: "Close friends only.",
      });

      // Mint the delegate key + issue the mandate.
      const delegateSeed = new Uint8Array(randomBytes(32));
      const delegatePub = ed.getPublicKey(delegateSeed);
      const delegateMb = encodeMultibaseEd25519(delegatePub);

      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "circle",
        grantee: { id: "agent:bob", pubkey: delegateMb },
        scopes: ["ethos.write.circle", "ethos.read.circle"],
        ttlSeconds: 86400,
      });
      core.writeMandate(mandate);

      // Rewrap zone + gamma DEKs to include the delegate. This is the
      // primitive the refactor adds: issuing a mandate that carries
      // read/write scopes on a zone MUST extend that zone's DEK wrap list
      // (and the gamma log's) to the delegate's X25519 key, so the delegate
      // can decrypt when operating from a tracked install.
      assert.equal(
        typeof (core as Record<string, unknown>).issueMandateWithRewrap,
        "function",
        "issueMandateWithRewrap must be exported (rewraps zone+gamma DEKs to include the delegate)",
      );
      // @ts-expect-error — API added in v0.2.1
      core.issueMandateWithRewrap({
        handle: "alice",
        identity: owner,
        mandate,
      });

      // Pack the bundle: all wraps must now include the delegate.
      const bundleDir = join(ownerHome, "outbox");
      mkdirSync(bundleDir, { recursive: true });
      // @ts-expect-error — API added in v0.2.1
      core.packEthosToDir({ handle: "alice", identity: owner, outDir: bundleDir });

      // --- Delegate side (fresh machine) -----------------------------------
      const delegateHome = freshKeystore();
      try {
        const coreDel = await loadCore();

        // Install the bundle (mimic `aithos ethos install`).
        const trackedHandle = "alice-tracked";
        // @ts-expect-error — API added in v0.2.1
        coreDel.installBundleFromDir({
          bundleDir,
          as: trackedHandle,
        });
        assert.ok(coreDel.isTrackedIdentity(trackedHandle));

        // Copy the mandate onto the delegate machine.
        coreDel.writeMandate(mandate);

        // Build a DelegateAuthor and append a section.
        const subjectMeta = coreDel.loadIdentityMetadata(trackedHandle);
        // @ts-expect-error — API added in v0.2.1
        const delegate = coreDel.delegateAuthor({
          subject: subjectMeta,
          seed: delegateSeed,
          pubkeyMultibase: delegateMb,
          mandate,
        });

        // @ts-expect-error — API added in v0.2.1 (addSection now takes Author)
        const { section: delSection, gammaEntry: delEntry, manifest: delManifest } =
          coreDel.addSection({
            handle: trackedHandle,
            author: delegate,
            zone: "circle",
            title: "Logged by delegate",
            body: "Action note added by agent:bob.",
          });

        // Gamma entry carries authorized_by.
        assert.equal(delEntry.authorized_by, mandate.id);
        assert.equal(delEntry.signature.key, delegateMb);

        // Zone signature carries authorized_by too.
        assert.equal(
          delManifest.zones.circle.signature.authorized_by,
          mandate.id,
          "zone signature must carry authorized_by when signed by delegate",
        );
        // Manifest signature carries authorized_by too.
        assert.equal(
          delManifest.integrity.manifest_signature.authorized_by,
          mandate.id,
          "manifest signature must carry authorized_by when signed by delegate",
        );

        // Re-pack the updated bundle and carry it back to the owner.
        const returnDir = join(delegateHome, "returnbox");
        mkdirSync(returnDir, { recursive: true });
        // @ts-expect-error — API added in v0.2.1
        coreDel.packEthosToDir({ handle: trackedHandle, author: delegate, outDir: returnDir });

        // --- Owner reads back -------------------------------------------
        // Switch AITHOS_HOME back to owner's machine and re-install.
        process.env.AITHOS_HOME = ownerHome;
        const coreBack = await loadCore();
        // @ts-expect-error — API added in v0.2.1
        coreBack.installBundleFromDir({
          bundleDir: returnDir,
          as: "alice",
          force: true,
        });

        const back = coreBack.loadZoneDoc("alice", "circle", owner);
        assert.ok(
          back.sections.find((s) => s.title === "Logged by delegate"),
          "owner must see delegate's section after re-install",
        );

        // Owner-side verifyEthos must accept the delegate signatures by
        // resolving `authorized_by` through the local mandate.
        const didDoc = coreBack.loadIdentityMetadata("alice").didDocument;
        const verify = coreBack.verifyEthos("alice", owner, didDoc);
        assert.ok(
          verify.ok,
          `verifyEthos must accept delegate-signed entries: ${verify.errors.join(", ")}`,
        );

        // --- Revocation ------------------------------------------------
        const revocation = coreBack.createRevocation({
          issuer: owner,
          mandate,
          reason: "test-end",
        });
        coreBack.writeRevocation(revocation);

        // Re-pin without the delegate: this rotates the zone DEKs so the
        // next edition's ciphertext is unreadable by the delegate.
        assert.equal(
          typeof (coreBack as Record<string, unknown>).repinAfterRevocation,
          "function",
          "repinAfterRevocation must be exported (removes delegate from DEK wraps on the current edition)",
        );
        // @ts-expect-error — API added in v0.2.1
        coreBack.repinAfterRevocation({
          handle: "alice",
          identity: owner,
          revocation,
        });

        // Pack a POST-revocation bundle and hand it to the (still-subverted)
        // delegate: they must not be able to decrypt the new circle zone.
        const postRevDir = join(ownerHome, "post-rev");
        mkdirSync(postRevDir, { recursive: true });
        // @ts-expect-error — API added in v0.2.1
        coreBack.packEthosToDir({ handle: "alice", identity: owner, outDir: postRevDir });

        // Delegate tries to decrypt the new circle zone — must fail.
        process.env.AITHOS_HOME = delegateHome;
        const coreDel2 = await loadCore();
        // @ts-expect-error — API added in v0.2.1
        coreDel2.installBundleFromDir({
          bundleDir: postRevDir,
          as: trackedHandle,
          force: true,
        });

        const postMeta = coreDel2.loadIdentityMetadata(trackedHandle);
        // @ts-expect-error — API added in v0.2.1
        const postDelegate = coreDel2.delegateAuthor({
          subject: postMeta,
          seed: delegateSeed,
          pubkeyMultibase: delegateMb,
          mandate,
        });

        assert.throws(
          () => {
            // @ts-expect-error — API added in v0.2.1
            coreDel2.addSection({
              handle: trackedHandle,
              author: postDelegate,
              zone: "circle",
              title: "Should fail",
              body: "Revocation should stop me.",
            });
          },
          /wrap|unwrap|decrypt|recipient|revoked/i,
          "delegate must not be able to decrypt or append to circle after revocation",
        );
      } finally {
        cleanupKeystore(delegateHome);
        process.env.AITHOS_HOME = ownerHome;
      }
    } finally {
      cleanupKeystore(ownerHome);
    }
  });
});
