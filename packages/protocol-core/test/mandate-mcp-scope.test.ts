// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// `mcp.<server>.<…>` connector scopes are sphere-neutral, like `data.*`: the
// access axis is the connector (gated at the gateway), not an ethos zone, so
// createMandate accepts them under ANY sphere — including public. This lets a
// consent bundle carry a connector grant in its single #public mandate.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function mint(scopes: string[]) {
  const core = await import("../src/index.ts");
  const owner = core.createIdentity("mcp-scope-alice", "MCP Scope Alice");
  core.writeIdentityToDisk(owner);
  const pub = await ed.getPublicKeyAsync(randomBytes(32));
  return core.createMandate({
    issuer: owner,
    actorSphere: "public",
    scopes,
    ttlSeconds: 3600,
    grantee: { id: "urn:aithos:agent:test", pubkey: core.ed25519PublicKeyToMultibase(pub) },
  });
}

describe("createMandate — mcp.* scopes under the public sphere", () => {
  test("mcp.<server> is accepted under public and carried in the mandate", async () => {
    const dir = freshKeystore();
    try {
      const m = await mint(["ethos.read.public", "mcp.github", "data.notes.read"]);
      assert.equal(m.actor_sphere, "public");
      assert.ok(m.scopes.includes("mcp.github"), "carries mcp.github");
      assert.ok(m.scopes.includes("data.notes.read"), "still carries data scopes");
    } finally {
      cleanupKeystore(dir);
    }
  });

  test("a non-allowed scope under public still throws (allow-list stays strict)", async () => {
    const dir = freshKeystore();
    try {
      await assert.rejects(
        () => mint(["ethos.read.self"]),
        /not permitted for the public sphere/,
      );
    } finally {
      cleanupKeystore(dir);
    }
  });
});
