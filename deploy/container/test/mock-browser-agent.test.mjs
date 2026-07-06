// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * The "hand" verifies the Mandated Intent Envelope before executing — the
 * downstream half of the pattern. It runs an action ONLY on a valid envelope,
 * and refuses anything tampered, mis-addressed, or replayed.
 */
import { test, describe, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

process.env.AITHOS_HOME = mkdtempSync(join(tmpdir(), "aithos-mock-hand-"));

const core = await import("@aithos/protocol-core");
const { signActionEnvelope } = await import("@aithos/mcp/actions");
const { createMockBrowserAgent } = await import("../dev/mock-browser-agent.mjs");

const AUD = "urn:aithos:downstream:browser-agent";

let ownerDidDoc;
let del;
let mandate;
let ownerDid;

before(() => {
  const identity = core.createIdentity("owner", "Owner");
  core.writeIdentityToDisk(identity);
  core.initKeystoreV03({ handle: "owner", identity });
  const seed = new Uint8Array(randomBytes(32));
  del = { seed, pubkeyMultibase: core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed)) };
  mandate = core.createMandate({
    issuer: identity,
    actorSphere: "self",
    grantee: { id: "urn:aithos:agent:demo", pubkey: del.pubkeyMultibase },
    scopes: ["browser.action:demo_search"],
    ttlSeconds: 3600,
  });
  const snap = core.snapshotDidJson("owner");
  ownerDidDoc = JSON.parse(snap.content);
  ownerDid = ownerDidDoc.id;
});

after(() => rmSync(process.env.AITHOS_HOME, { recursive: true, force: true }));

function envelopeFor(actionId, params) {
  return signActionEnvelope({
    ownerDid,
    aud: AUD,
    action: { id: actionId },
    params,
    mandate,
    delegateKey: del,
  });
}

describe("mock hand — runAction verification", () => {
  test("a valid action envelope is verified and executed (run_report)", async () => {
    const { runAction } = createMockBrowserAgent({ ownerDidDoc, aud: AUD });
    const params = { query: "dormant" };
    const rep = await runAction({ envelope: envelopeFor("demo_search", params), action: { id: "demo_search" }, params });
    assert.equal(rep.type, "run_report");
    assert.equal(rep.ok, true);
    assert.equal(rep.mandate_id, mandate.id);
    assert.deepEqual(rep.observed, params);
  });

  test("tampered params (params_hash) → run_stopped", async () => {
    const { runAction } = createMockBrowserAgent({ ownerDidDoc, aud: AUD });
    const env = envelopeFor("demo_search", { query: "safe" });
    const rep = await runAction({ envelope: env, action: { id: "demo_search" }, params: { query: "evil" } });
    assert.equal(rep.type, "run_stopped");
    assert.equal(rep.ok, false);
  });

  test("envelope for a different action than claimed → run_stopped", async () => {
    const { runAction } = createMockBrowserAgent({ ownerDidDoc, aud: AUD });
    const env = envelopeFor("demo_search", { query: "x" });
    const rep = await runAction({ envelope: env, action: { id: "demo_post" }, params: { query: "x" } });
    assert.equal(rep.ok, false, "method/action mismatch must be refused");
  });

  test("wrong audience (a hand it was not addressed to) → run_stopped", async () => {
    const other = createMockBrowserAgent({ ownerDidDoc, aud: "urn:aithos:downstream:someone-else" });
    const env = envelopeFor("demo_search", { query: "x" });
    const rep = await other.runAction({ envelope: env, action: { id: "demo_search" }, params: { query: "x" } });
    assert.equal(rep.ok, false, "audience mismatch must be refused");
  });

  test("replay of the same envelope is refused the second time", async () => {
    const { runAction } = createMockBrowserAgent({ ownerDidDoc, aud: AUD });
    const params = { query: "once" };
    const env = envelopeFor("demo_search", params);
    const first = await runAction({ envelope: env, action: { id: "demo_search" }, params });
    assert.equal(first.ok, true);
    const second = await runAction({ envelope: env, action: { id: "demo_search" }, params });
    assert.equal(second.ok, false, "a replayed envelope must be refused");
  });

  test("an unknown owner DID cannot be resolved → run_stopped", async () => {
    const { runAction } = createMockBrowserAgent({ ownerDidDoc: null, aud: AUD });
    const env = envelopeFor("demo_search", { query: "x" });
    const rep = await runAction({ envelope: env, action: { id: "demo_search" }, params: { query: "x" } });
    assert.equal(rep.ok, false);
  });
});

describe("mock hand — HTTP surface", () => {
  test("POST /run_action returns the report; /healthz answers", async () => {
    const { server } = createMockBrowserAgent({ ownerDidDoc, aud: AUD });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const port = server.address().port;
    try {
      const health = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(health.status, 200);

      const params = { query: "http" };
      const body = { envelope: envelopeFor("demo_search", params), action: { id: "demo_search" }, params };
      const res = await fetch(`http://127.0.0.1:${port}/run_action`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 200);
      const rep = await res.json();
      assert.equal(rep.type, "run_report");
      assert.equal(rep.ok, true);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
});
