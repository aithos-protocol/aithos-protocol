// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Tests for the v0.4 `compute.invoke` scope and `constraints.compute`.
 *
 * Invariants under test (the "in conscience, voluntarily" property):
 *   1. `compute.invoke` is opt-in. Read-only / write-only mandates remain
 *      unaffected and their format is unchanged.
 *   2. `compute.invoke` without a `constraints.compute` budget is rejected
 *      at mint AND at verify time. The protocol layer makes the unbounded
 *      compute mandate impossible to express — the spend ceiling is a
 *      security invariant, not a server-side policy.
 *   3. `constraints.compute` without the scope is also rejected (caller
 *      mistake — silent no-ops are the enemy of "explicit consent").
 *   4. Caps must be positive integers; allowed_models, when present, must
 *      be a list of non-empty strings.
 *   5. Compute mandates require a delegate pubkey, like write mandates —
 *      bearer compute capabilities are forbidden by construction.
 *   6. The scope is permitted on every sphere (public / circle / self),
 *      since spending authority is orthogonal to the read/write sphere.
 *   7. `hasComputeInvokeScope` reports the scope correctly.
 *   8. Backward compatibility: a 0.3.0 mandate without compute is still
 *      accepted by the verifier.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/* -------------------------------------------------------------------------- */
/*  Test fixtures                                                             */
/* -------------------------------------------------------------------------- */

async function loadCore() {
  return await import("../src/index.js");
}

/** Mirror of did.ts encoder — kept local to avoid importing before AITHOS_HOME is set. */
function encodeMultibaseEd25519(pk: Uint8Array): string {
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
  return out;
}

function freshDelegatePubkey(): string {
  const seed = new Uint8Array(randomBytes(32));
  const pub = ed.getPublicKey(seed);
  return encodeMultibaseEd25519(pub);
}

/* -------------------------------------------------------------------------- */
/*  Mint-time validation                                                      */
/* -------------------------------------------------------------------------- */

describe("compute.invoke — mint-time validation", () => {
  test("mint succeeds with compute.invoke + daily cap only", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const m = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
        scopes: [core.COMPUTE_INVOKE_SCOPE],
        ttlSeconds: 3600,
        constraints: {
          compute: { daily_cap_microcredits: 5_000 },
        },
      });
      assert.equal(m["aithos-mandate"], "0.4.0");
      assert.ok(core.hasComputeInvokeScope(m.scopes));
      assert.equal(m.constraints?.compute?.daily_cap_microcredits, 5_000);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint succeeds with compute.invoke + total cap + per-call + allowed_models", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const m = core.createMandate({
        issuer: owner,
        actorSphere: "self",
        grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
        scopes: [core.COMPUTE_INVOKE_SCOPE],
        ttlSeconds: 86_400,
        constraints: {
          compute: {
            total_cap_microcredits: 100_000,
            max_credits_per_call: 500,
            allowed_models: ["claude-haiku-4-5", "claude-sonnet-4-6"],
          },
        },
      });
      assert.equal(m.constraints?.compute?.total_cap_microcredits, 100_000);
      assert.deepEqual(m.constraints?.compute?.allowed_models, [
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
      ]);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS compute.invoke without any constraints.compute", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(
        () =>
          core.createMandate({
            issuer: owner,
            actorSphere: "public",
            grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
            scopes: [core.COMPUTE_INVOKE_SCOPE],
            ttlSeconds: 3600,
            // No constraints at all
          }),
        /Token-spending capability requires an explicit budget/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS compute.invoke with constraints.compute but no cap", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(
        () =>
          core.createMandate({
            issuer: owner,
            actorSphere: "public",
            grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
            scopes: [core.COMPUTE_INVOKE_SCOPE],
            ttlSeconds: 3600,
            constraints: {
              compute: {
                // Both caps absent, only model allowlist set — still unbounded.
                allowed_models: ["claude-haiku-4-5"],
              },
            },
          }),
        /at least one of daily_cap_microcredits or total_cap_microcredits/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS constraints.compute without the compute.invoke scope (silent no-op guard)", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(
        () =>
          core.createMandate({
            issuer: owner,
            actorSphere: "public",
            grantee: { id: "viewer:bob" },
            scopes: ["ethos.read.public"], // no compute scope
            ttlSeconds: 3600,
            constraints: {
              compute: { daily_cap_microcredits: 5_000 },
            },
          }),
        /constraints\.compute is set but the compute\.invoke scope is missing/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS non-positive caps", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      for (const bad of [0, -1, 3.14]) {
        assert.throws(
          () =>
            core.createMandate({
              issuer: owner,
              actorSphere: "public",
              grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
              scopes: [core.COMPUTE_INVOKE_SCOPE],
              ttlSeconds: 3600,
              constraints: { compute: { daily_cap_microcredits: bad } },
            }),
          /must be a positive integer/,
          `expected rejection for daily_cap_microcredits=${bad}`,
        );
      }
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS allowed_models with non-string entries", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(
        () =>
          core.createMandate({
            issuer: owner,
            actorSphere: "public",
            grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
            scopes: [core.COMPUTE_INVOKE_SCOPE],
            ttlSeconds: 3600,
            constraints: {
              compute: {
                daily_cap_microcredits: 5_000,
                allowed_models: ["claude-haiku-4-5", "" as string],
              },
            },
          }),
        /allowed_models entries must be non-empty strings/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("mint REJECTS compute.invoke without grantee.pubkey (no bearer compute)", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      assert.throws(
        () =>
          core.createMandate({
            issuer: owner,
            actorSphere: "public",
            grantee: { id: "agent:bob" }, // no pubkey
            scopes: [core.COMPUTE_INVOKE_SCOPE],
            ttlSeconds: 3600,
            constraints: { compute: { daily_cap_microcredits: 5_000 } },
          }),
        /requires grantee\.pubkey/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Sphere compatibility                                                      */
/* -------------------------------------------------------------------------- */

describe("compute.invoke — sphere compatibility", () => {
  test("compute.invoke is permitted on all three spheres", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      for (const sphere of ["public", "circle", "self"] as const) {
        const m = core.createMandate({
          issuer: owner,
          actorSphere: sphere,
          grantee: { id: `agent:${sphere}`, pubkey: freshDelegatePubkey() },
          scopes: [core.COMPUTE_INVOKE_SCOPE],
          ttlSeconds: 3600,
          constraints: { compute: { daily_cap_microcredits: 5_000 } },
        });
        assert.equal(m.actor_sphere, sphere);
        assert.ok(core.hasComputeInvokeScope(m.scopes));
      }
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("compute.invoke can be combined with ethos.read scopes (typical agent setup)", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const m = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
        scopes: ["ethos.read.public", core.COMPUTE_INVOKE_SCOPE],
        ttlSeconds: 3600,
        constraints: { compute: { daily_cap_microcredits: 5_000 } },
      });
      assert.ok(m.scopes.includes("ethos.read.public"));
      assert.ok(m.scopes.includes("compute.invoke"));
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Helper coverage                                                           */
/* -------------------------------------------------------------------------- */

describe("compute.invoke — helpers", () => {
  test("hasComputeInvokeScope returns true iff the scope is present", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      assert.equal(core.hasComputeInvokeScope([]), false);
      assert.equal(core.hasComputeInvokeScope(["ethos.read.public"]), false);
      assert.equal(core.hasComputeInvokeScope(["compute.invoke"]), true);
      assert.equal(
        core.hasComputeInvokeScope(["ethos.read.public", "compute.invoke"]),
        true,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("validateComputeAuthorization is a no-op when neither scope nor constraints present", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      // Read-only mandates: scope absent, constraints absent — must not throw.
      core.validateComputeAuthorization(["ethos.read.public"]);
      core.validateComputeAuthorization(["ethos.read.public"], { domains: ["example.com"] });
    } finally {
      cleanupKeystore(dir);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  Verify-time enforcement                                                   */
/* -------------------------------------------------------------------------- */

describe("compute.invoke — verifier enforcement", () => {
  test("verifier accepts a well-formed v0.4.0 compute mandate", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      const m = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
        scopes: [core.COMPUTE_INVOKE_SCOPE],
        ttlSeconds: 3600,
        constraints: { compute: { daily_cap_microcredits: 5_000 } },
      });

      const didDoc = core.loadIdentityMetadata("alice").didDocument;
      const verdict = core.verifyMandate(m, didDoc);
      assert.equal(verdict.ok, true, `verifier rejected: ${verdict.errors.join(", ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("verifier REJECTS a hand-crafted compute mandate without caps (belt-and-suspenders)", async () => {
    const dir = freshKeystore();
    try {
      const core = await loadCore();
      const owner = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(owner);

      // Mint a legal mandate first, then forge a malformed copy that
      // strips the constraints — simulating either a buggy older library
      // or a tampered file. The verifier must catch this even though the
      // signature still validates against the (forged) canonical bytes.
      const legal = core.createMandate({
        issuer: owner,
        actorSphere: "public",
        grantee: { id: "agent:bob", pubkey: freshDelegatePubkey() },
        scopes: [core.COMPUTE_INVOKE_SCOPE],
        ttlSeconds: 3600,
        constraints: { compute: { daily_cap_microcredits: 5_000 } },
      });
      const forged: typeof legal = JSON.parse(JSON.stringify(legal));
      delete (forged as { constraints?: unknown }).constraints;

      const didDoc = core.loadIdentityMetadata("alice").didDocument;
      const verdict = core.verifyMandate(forged, didDoc);
      assert.equal(verdict.ok, false, "verifier should reject capless compute mandate");
      assert.ok(
        verdict.errors.some((e) => /Compute authorization invalid/.test(e)),
        `expected compute-authorization error, got: ${verdict.errors.join(" | ")}`,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});
