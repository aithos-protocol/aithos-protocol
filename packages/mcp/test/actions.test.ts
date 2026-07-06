// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mandated Intent Envelope — gateway core (SPEC-mandated-intent-envelope 0.1.0).
 *
 * The load-bearing guarantees:
 *   - an action is parsed from signed content, not invented by the agent;
 *   - agent parameters are validated against the SIGNED schema, strictly
 *     (unknown props + out-of-constraint values rejected) — the security crux;
 *   - only in-scope actions are exposed;
 *   - the signed envelope round-trips through the real §5 verifier, and any
 *     tamper (params, method) is rejected.
 */
import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// $AITHOS_HOME must be set BEFORE protocol-core is imported (it freezes the
// home at import time); actions.ts imports it too, so both go through await.
process.env.AITHOS_HOME = mkdtempSync(join(tmpdir(), "aithos-actions-"));

const {
  parseActionSection,
  validateParams,
  actionScope,
  actionsInScope,
  actionToolName,
  actionIdFromToolName,
  signActionEnvelope,
} = await import("../src/actions.ts");
type ActionDefinition = import("../src/actions.ts").ActionDefinition;

const core = await import("@aithos/protocol-core");
const { createIdentity, createMandate, ed25519PublicKeyToMultibase, verifyEnvelope } = core;
type VerifyEnvelopeContext = import("@aithos/protocol-core").VerifyEnvelopeContext;

/* -------------------------------------------------------------------------- */
/* parseActionSection                                                         */
/* -------------------------------------------------------------------------- */

describe("parseActionSection", () => {
  test("parses id + goal + params_schema from the section body", () => {
    const a = parseActionSection({
      id: "demo_search",
      title: "Search",
      body: JSON.stringify({
        goal: "Search the site for a query",
        params_schema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
      }),
    });
    assert.equal(a.id, "demo_search");
    assert.equal(a.goal, "Search the site for a query");
    assert.equal(a.params_schema.required?.[0], "query");
  });

  test("goal falls back to the section title, then the id", () => {
    assert.equal(parseActionSection({ id: "x", title: "T", body: "{}" }).goal, "T");
    assert.equal(parseActionSection({ id: "x", body: "{}" }).goal, "x");
  });

  test("rejects a non-JSON or non-object body", () => {
    assert.throws(() => parseActionSection({ id: "x", body: "not json" }), /not valid JSON/);
    assert.throws(() => parseActionSection({ id: "x", body: "[1,2]" }), /must be a JSON object/);
  });

  test("rejects a malformed params_schema", () => {
    assert.throws(
      () => parseActionSection({ id: "x", body: JSON.stringify({ params_schema: 42 }) }),
      /params_schema must be an object/,
    );
  });
});

/* -------------------------------------------------------------------------- */
/* validateParams — the security crux                                         */
/* -------------------------------------------------------------------------- */

describe("validateParams (strict signed-schema enforcement)", () => {
  const schema = {
    type: "object",
    properties: {
      query: { type: "string", minLength: 1, maxLength: 100 },
      count: { type: "integer", minimum: 1, maximum: 10 },
      mode: { type: "string", enum: ["fast", "slow"] },
    },
    required: ["query"],
  };

  test("accepts a value that satisfies every declared constraint", () => {
    assert.deepEqual(validateParams(schema, { query: "hello", count: 3, mode: "fast" }), { ok: true });
    assert.deepEqual(validateParams(schema, { query: "hi" }), { ok: true });
  });

  test("REJECTS an undeclared property (deny by default)", () => {
    const r = validateParams(schema, { query: "hi", evil: "rm -rf" });
    assert.equal(r.ok, false);
    assert.match((r as { error: string }).error, /evil.*not an allowed parameter/);
  });

  test("rejects a missing required field", () => {
    assert.equal(validateParams(schema, { count: 2 }).ok, false);
  });

  test("rejects the wrong type", () => {
    assert.equal(validateParams(schema, { query: 123 }).ok, false);
    assert.equal(validateParams(schema, { query: "x", count: "3" }).ok, false);
  });

  test("rejects out-of-range numbers and non-integers", () => {
    assert.equal(validateParams(schema, { query: "x", count: 0 }).ok, false);
    assert.equal(validateParams(schema, { query: "x", count: 11 }).ok, false);
    assert.equal(validateParams(schema, { query: "x", count: 2.5 }).ok, false);
  });

  test("rejects an enum violation", () => {
    assert.equal(validateParams(schema, { query: "x", mode: "turbo" }).ok, false);
  });

  test("enforces string length + pattern", () => {
    const s = { type: "object", properties: { u: { type: "string", pattern: "^https://" } } };
    assert.equal(validateParams(s, { u: "https://ok" }).ok, true);
    assert.equal(validateParams(s, { u: "http://no" }).ok, false);
    assert.equal(validateParams(schema, { query: "" }).ok, false); // minLength 1
  });

  test("validates array items", () => {
    const s = { type: "object", properties: { tags: { type: "array", items: { type: "string" }, maxItems: 2 } } };
    assert.equal(validateParams(s, { tags: ["a", "b"] }).ok, true);
    assert.equal(validateParams(s, { tags: ["a", 2] }).ok, false);
    assert.equal(validateParams(s, { tags: ["a", "b", "c"] }).ok, false);
  });
});

/* -------------------------------------------------------------------------- */
/* scope filtering + tool naming                                              */
/* -------------------------------------------------------------------------- */

describe("scope + tool naming", () => {
  const actions: ActionDefinition[] = [
    { id: "demo_search", goal: "s", params_schema: {} },
    { id: "demo_post", goal: "p", params_schema: {} },
  ];

  test("actionsInScope keeps only granted actions (deny by default)", () => {
    const got = actionsInScope(actions, ["browser.action:demo_search"]).map((a) => a.id);
    assert.deepEqual(got, ["demo_search"]);
    assert.deepEqual(actionsInScope(actions, []).length, 0);
    assert.deepEqual(actionsInScope(actions, ["browser.observe"]).length, 0);
  });

  test("scope + tool-name helpers round-trip", () => {
    assert.equal(actionScope("demo_search"), "browser.action:demo_search");
    assert.equal(actionIdFromToolName(actionToolName("demo_search")), "demo_search");
    assert.equal(actionIdFromToolName("ethos_read_section"), null);
  });
});

/* -------------------------------------------------------------------------- */
/* sign → verify round-trip (the real §5 verifier)                            */
/* -------------------------------------------------------------------------- */

function makeReplay() {
  const seen = new Set<string>();
  return {
    async putIfAbsent(key: string, _expiresAt: number) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

function delegate() {
  const seed = new Uint8Array(randomBytes(32));
  return { seed, pubkeyMultibase: ed25519PublicKeyToMultibase(ed.getPublicKey(seed)) };
}

describe("Mandated Intent Envelope round-trip", () => {
  const AUD = "urn:aithos:downstream:browser-agent";

  let counter = 0;
  function setup(scope = "browser.action:demo_search") {
    const handle = `owner${counter++}`;
    const identity = createIdentity(handle, "Owner");
    core.writeIdentityToDisk(identity);
    core.initKeystoreV03({ handle, identity }); // lays out the ethos dir snapshotDidJson needs
    const del = delegate();
    // self sphere: browser.action:* rides like a connector scope. (Making it
    // sphere-neutral on `public` like mcp.* is a protocol-core follow-up.)
    const mandate = createMandate({
      issuer: identity,
      actorSphere: "self",
      grantee: { id: "urn:aithos:agent:demo", pubkey: del.pubkeyMultibase },
      scopes: [scope],
      ttlSeconds: 3600,
    });
    // snapshotDidJson returns { path, hashHex, content } where content is the
    // DID document as a JSON string.
    const snap = core.snapshotDidJson(handle) as unknown as { content: string };
    const didDoc = JSON.parse(snap.content) as { id: string };
    const ownerDid = didDoc.id;
    return { identity, del, mandate, ownerDid, didDoc };
  }

  function ctx(didDoc: unknown, method: string, params: unknown): VerifyEnvelopeContext {
    return {
      expectedAud: AUD,
      expectedMethod: method,
      params,
      nowSeconds: Math.floor(Date.now() / 1000),
      resolveIssuerDoc: async (iss: string) =>
        iss === (didDoc as { id: string }).id ? (didDoc as never) : null,
      replay: makeReplay(),
    } as VerifyEnvelopeContext;
  }

  test("gateway-signed action envelope verifies, resolves the mandate", async () => {
    const { del, mandate, ownerDid, didDoc } = setup();
    const params = { query: "dormant contacts" };
    const env = signActionEnvelope({
      ownerDid,
      aud: AUD,
      action: { id: "demo_search" },
      params,
      mandate,
      delegateKey: del,
    });
    assert.equal(env.method, "demo_search");
    const res = await verifyEnvelope(env, ctx(didDoc, "demo_search", params));
    assert.equal(res.ok, true, res.ok ? "" : JSON.stringify((res as { error: unknown }).error));
    if (res.ok) assert.equal(res.mandateId, mandate.id);
  });

  test("tampering the params after signing is rejected (params_hash)", async () => {
    const { del, mandate, ownerDid, didDoc } = setup();
    const env = signActionEnvelope({
      ownerDid, aud: AUD, action: { id: "demo_search" },
      params: { query: "safe" }, mandate, delegateKey: del,
    });
    // The downstream is handed DIFFERENT params than were signed.
    const res = await verifyEnvelope(env, ctx(didDoc, "demo_search", { query: "evil" }));
    assert.equal(res.ok, false, "mismatched params must be rejected");
  });

  test("an envelope for a different method is rejected", async () => {
    const { del, mandate, ownerDid, didDoc } = setup();
    const params = { query: "x" };
    const env = signActionEnvelope({
      ownerDid, aud: AUD, action: { id: "demo_search" }, params, mandate, delegateKey: del,
    });
    const res = await verifyEnvelope(env, ctx(didDoc, "demo_post", params));
    assert.equal(res.ok, false, "method mismatch must be rejected");
  });
});
