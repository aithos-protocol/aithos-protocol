// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Gateway action federation (A4) — the notary duties on every action tool call:
 * only in-scope actions are exposed; agent params are validated against the
 * SIGNED schema before anything is signed; a Mandated Intent Envelope is signed
 * and dispatched; the downstream (here an in-process verifier) accepts it. A
 * bad param or a dead mandate never reaches the downstream.
 */
import { test, describe, before } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

process.env.AITHOS_HOME = mkdtempSync(join(tmpdir(), "aithos-actfed-"));

const core = await import("@aithos/protocol-core");
const { federateActions } = await import("../src/action-federation.ts");

const AUD = "urn:aithos:downstream:browser-agent";

/* --- a fake Aithos server: records registered tools + dispatches them ------ */
function fakeServer() {
  const tools = new Map();
  return {
    registerTool(name, config, cb) {
      tools.set(name, { config, cb });
    },
    list() {
      return [...tools.keys()];
    },
    async call(name, args) {
      const t = tools.get(name);
      if (!t) throw new Error(`no such tool ${name}`);
      return t.cb(args ?? {});
    },
  };
}

/* --- an in-process "hand": verifies the envelope with the REAL §5 verifier -- */
function verifyingDispatch(ownerDidDoc) {
  const seen = new Set();
  const replay = { async putIfAbsent(k) { if (seen.has(k)) return false; seen.add(k); return true; } };
  const calls = [];
  const dispatch = async ({ envelope, action, params }) => {
    calls.push({ action: action.id, params });
    const res = await core.verifyEnvelope(envelope, {
      expectedAud: AUD,
      expectedMethod: action.id,
      params,
      nowSeconds: Math.floor(Date.now() / 1000),
      resolveIssuerDoc: async (iss) => (iss === ownerDidDoc.id ? ownerDidDoc : null),
      replay,
    });
    return res.ok
      ? { ok: true, type: "run_report", result: `ran ${action.id}`, mandate_id: res.mandateId }
      : { ok: false, type: "run_stopped", error: res.error?.message };
  };
  return { dispatch, calls };
}

const SEARCH = {
  id: "demo_search",
  goal: "Search the site",
  params_schema: { type: "object", properties: { query: { type: "string", minLength: 1 } }, required: ["query"] },
};
const POST = { id: "demo_post", goal: "Post", params_schema: { type: "object", properties: { text: { type: "string" } } } };

let del;
let mandate;
let ownerDid;
let ownerDidDoc;

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
    scopes: ["browser.action:demo_search"], // only search granted
    ttlSeconds: 3600,
  });
  ownerDidDoc = JSON.parse(core.snapshotDidJson("owner").content);
  ownerDid = ownerDidDoc.id;
});

function wire(overrides = {}) {
  const server = fakeServer();
  const { dispatch, calls } = verifyingDispatch(ownerDidDoc);
  const audit = [];
  const handle = federateActions({
    server,
    actions: [SEARCH, POST],
    scopes: ["browser.action:demo_search"],
    mandate,
    ownerDid,
    aud: AUD,
    delegateKey: del,
    dispatch,
    auditSink: (e) => audit.push(e),
    log: () => {},
    ...overrides,
  });
  return { server, calls, audit, handle };
}

describe("federateActions", () => {
  test("exposes only in-scope actions (deny by default)", () => {
    const { server, handle } = wire();
    assert.equal(handle.exposed, 1);
    assert.deepEqual(server.list(), ["browser_action__demo_search"]);
    assert.ok(!server.list().includes("browser_action__demo_post"));
  });

  test("a valid call signs an envelope the downstream verifies + runs", async () => {
    const { server, calls } = wire();
    const r = await server.call("browser_action__demo_search", { query: "dormant" });
    assert.ok(!r.isError, r.isError ? r.content[0].text : "");
    const report = JSON.parse(r.content[0].text);
    assert.equal(report.ok, true);
    assert.equal(report.mandate_id, mandate.id);
    assert.equal(calls.length, 1, "the downstream was reached exactly once");
  });

  test("invalid params are refused BEFORE signing — the downstream is never reached", async () => {
    const { server, calls } = wire();
    // unknown property (deny by default)
    const r1 = await server.call("browser_action__demo_search", { query: "x", evil: 1 });
    assert.equal(r1.isError, true);
    assert.match(r1.content[0].text, /invalid parameters/);
    // missing required
    const r2 = await server.call("browser_action__demo_search", {});
    assert.equal(r2.isError, true);
    assert.equal(calls.length, 0, "nothing dispatched on invalid params");
  });

  test("liveness failure (revocation) refuses before signing", async () => {
    let revoked = false;
    const { server, calls } = wire({
      liveness: async () => {
        if (revoked) throw new Error("mandate revoked");
      },
    });
    const ok = await server.call("browser_action__demo_search", { query: "x" });
    assert.ok(!ok.isError);
    revoked = true;
    const denied = await server.call("browser_action__demo_search", { query: "x" });
    assert.equal(denied.isError, true);
    assert.match(denied.content[0].text, /revoked/);
    assert.equal(calls.length, 1, "the revoked call never dispatched");
  });

  test("audit records ok + denied, attributed to the mandate", async () => {
    const { server, audit } = wire();
    await server.call("browser_action__demo_search", { query: "x" });
    await server.call("browser_action__demo_search", { bad: 1 });
    const statuses = audit.map((e) => e.status);
    assert.ok(statuses.includes("ok"));
    assert.ok(statuses.includes("denied"));
    assert.ok(audit.every((e) => e.mandateId === mandate.id));
  });
});
