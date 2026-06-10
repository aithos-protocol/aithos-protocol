// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Revocation EPOCH (`did.json aithos.mandates_void_before`): one root-signed
// write voids every mandate issued before it — verifyMandate MUST reject those
// and keep accepting mandates issued at/after the epoch. Absent epoch =
// legacy behaviour (nothing rejected). This is what makes "revoke all" one
// write and per-mandate revocation GC safe (the epoch subsumes them).

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

async function fixture() {
  const core = await loadCore();
  const owner = core.createIdentity("epoch-alice", "Epoch Alice");
  core.writeIdentityToDisk(owner);
  const pub = await ed.getPublicKeyAsync(randomBytes(32));
  const mandate = core.createMandate({
    issuer: owner,
    actorSphere: "public",
    scopes: ["ethos.read.public"],
    ttlSeconds: 3600,
    grantee: { id: "urn:aithos:agent:test", pubkey: core.ed25519PublicKeyToMultibase(pub) },
  });
  const didDoc = core.loadIdentityMetadata("epoch-alice").didDocument;
  return { core, mandate, didDoc };
}

describe("verifyMandate — revocation epoch", () => {
  test("no epoch on the did.json → mandate verifies (legacy)", async () => {
    const dir = freshKeystore();
    try {
      const { core, mandate, didDoc } = await fixture();
      assert.equal(didDoc.aithos.mandates_void_before, undefined);
      const v = core.verifyMandate(mandate, didDoc);
      assert.equal(v.ok, true, `expected ok: ${(v as { errors?: string[] }).errors?.join(" / ")}`);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("epoch AFTER issued_at → mandate is void", async () => {
    const dir = freshKeystore();
    try {
      const { core, mandate, didDoc } = await fixture();
      const epoch = new Date(Date.parse(mandate.issued_at) + 1000).toISOString();
      const doc = { ...didDoc, aithos: { ...didDoc.aithos, mandates_void_before: epoch } };
      const v = core.verifyMandate(mandate, doc);
      assert.equal(v.ok, false, "pre-epoch mandate must be rejected");
      assert.ok(
        (v as { errors: string[] }).errors.some((e) => e.includes("revocation epoch")),
        "error names the epoch",
      );
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("epoch AT or BEFORE issued_at → mandate still verifies", async () => {
    const dir = freshKeystore();
    try {
      const { core, mandate, didDoc } = await fixture();
      // exactly at issued_at (strictly-before semantics) …
      const at = { ...didDoc, aithos: { ...didDoc.aithos, mandates_void_before: mandate.issued_at } };
      assert.equal(core.verifyMandate(mandate, at).ok, true, "issued_at == epoch is NOT void");
      // … and an epoch in the past.
      const past = new Date(Date.parse(mandate.issued_at) - 60_000).toISOString();
      const before = { ...didDoc, aithos: { ...didDoc.aithos, mandates_void_before: past } };
      assert.equal(core.verifyMandate(mandate, before).ok, true);
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("malformed epoch is ignored (fail-open on the field, not on the mandate)", async () => {
    const dir = freshKeystore();
    try {
      const { core, mandate, didDoc } = await fixture();
      const doc = { ...didDoc, aithos: { ...didDoc.aithos, mandates_void_before: "not-a-date" } };
      assert.equal(core.verifyMandate(mandate, doc).ok, true);
    } finally {
      cleanupKeystore(dir);
    }
  });
});
