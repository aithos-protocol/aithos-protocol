// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Tests for clock-skew tolerance in verifyMandate.
//
// Without tolerance, a mandate signed at time T was rejected by the
// server at time T-100ms (clock drift) with "Mandate not yet valid".
// The fix: accept mandates whose not_before is within
// MANDATE_CLOCK_SKEW_SECONDS_DEFAULT (30s) ahead of "now". Same for
// not_after on the expiration end.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function loadCore() {
  return await import("../src/index.ts");
}

function freshDelegatePubkey(): string {
  // Same trick as mandate-compute.test.ts — generate a random ed25519
  // pubkey and encode multibase. Actual signing isn't tested here.
  const seed = randomBytes(32);
  const pub = ed.getPublicKey(seed);
  // base58btc-multibase encoding: leading "z" + base58 of 0xed01 + pubkey
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);
  // Use core.ed25519PublicKeyToMultibase via dynamic import in tests; we
  // build it inline here to keep the test self-contained.
  // Cheat: import lazily inside the test where freshKeystore was called.
  return ""; // unused — replaced inside each test
}

describe("verifyMandate — clock-skew tolerance", () => {
  test("default tolerance is 30 seconds", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const m = await import("../src/mandate.ts");
      assert.equal(m.MANDATE_CLOCK_SKEW_SECONDS_DEFAULT, 30);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("accepts mandate signed within tolerance ahead of now", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // Sign a mandate whose not_before is FUTURE by 10 seconds —
      // simulates a client whose clock is 10s ahead of the server.
      const future = new Date(Date.now() + 10_000);
      const seed = randomBytes(32);
      const pub = await ed.getPublicKeyAsync(seed);
      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 600,
        grantee: {
          id: "urn:aithos:agent:test",
          pubkey: core.ed25519PublicKeyToMultibase(pub),
        },
        notBefore: future,
      });

      const didDoc = core.loadIdentityMetadata("alice").didDocument;
      const verdict = core.verifyMandate(mandate, didDoc);
      assert.equal(verdict.ok, true,
        `expected ok, got errors: ${(verdict as any).errors?.join(" / ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("rejects mandate signed FURTHER than tolerance ahead", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // 5 minutes ahead — well beyond the 30s tolerance window
      const farFuture = new Date(Date.now() + 5 * 60_000);
      const seed = randomBytes(32);
      const pub = await ed.getPublicKeyAsync(seed);
      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 3600,
        grantee: {
          id: "urn:aithos:agent:test",
          pubkey: core.ed25519PublicKeyToMultibase(pub),
        },
        notBefore: farFuture,
      });

      const didDoc = core.loadIdentityMetadata("alice").didDocument;
      const verdict = core.verifyMandate(mandate, didDoc);
      assert.equal(verdict.ok, false);
      assert.ok(
        (verdict as any).errors.some((e: string) => e.includes("not yet valid")),
        "expected 'not yet valid' error",
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("clockSkewSeconds: 0 reproduces the legacy strict behaviour", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const future = new Date(Date.now() + 5_000); // 5s ahead
      const seed = randomBytes(32);
      const pub = await ed.getPublicKeyAsync(seed);
      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 600,
        grantee: {
          id: "urn:aithos:agent:test",
          pubkey: core.ed25519PublicKeyToMultibase(pub),
        },
        notBefore: future,
      });

      const didDoc = core.loadIdentityMetadata("alice").didDocument;

      // With tolerance: 5s ahead is within the 30s default window → accepted
      const lenient = core.verifyMandate(mandate, didDoc);
      assert.equal(lenient.ok, true);

      // With clockSkewSeconds: 0 (legacy strict): same mandate is rejected
      const strict = core.verifyMandate(mandate, didDoc, new Date(), {
        clockSkewSeconds: 0,
      });
      assert.equal(strict.ok, false);
      assert.ok(
        (strict as any).errors.some((e: string) => e.includes("not yet valid")),
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("tolerance applies symmetrically to expiration", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // Mandate that EXPIRED 10 seconds ago — within the 30s skew window
      const past = new Date(Date.now() - 600_000); // not_before 10 min ago
      const ttl = 600 - 10; // expired 10s ago
      const seed = randomBytes(32);
      const pub = await ed.getPublicKeyAsync(seed);
      const mandate = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: ttl,
        grantee: {
          id: "urn:aithos:agent:test",
          pubkey: core.ed25519PublicKeyToMultibase(pub),
        },
        notBefore: past,
      });

      const didDoc = core.loadIdentityMetadata("alice").didDocument;

      // Just-expired mandate — accepted by default (within 30s skew)
      const lenient = core.verifyMandate(mandate, didDoc);
      assert.equal(lenient.ok, true);

      // Strict: rejected
      const strict = core.verifyMandate(mandate, didDoc, new Date(), {
        clockSkewSeconds: 0,
      });
      assert.equal(strict.ok, false);
      assert.ok(
        (strict as any).errors.some((e: string) => e.includes("expired")),
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});
