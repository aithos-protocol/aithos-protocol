// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mandated Intent Envelope — acceptance, WITHOUT Docker. Boots the REAL gateway
 * process (packages/mcp/dist/bin.js) with --actions + --actions-downstream
 * pointed at the mock "hand", connects an MCP client (the caged agent), and
 * drives an action end to end:
 *
 *   - only the granted action is exposed as a tool (out-of-scope hidden);
 *   - a valid call signs an envelope the hand verifies + runs (run_report);
 *   - bad params are refused at the gateway — the hand is never reached;
 *   - revoke mid-session → the next call fails closed.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");
const MCP_BIN = join(REPO, "packages/mcp/dist/bin.js");
const AUD = "urn:aithos:downstream:browser-agent";
const TOKEN = "actenv-" + randomBytes(6).toString("hex");

let HOME;
let core;
let identity;
let mandate;
let gateway;
let gatewayPort;
let mock;
let mockPort;

async function startMock(ownerDidDoc) {
  const { createMockBrowserAgent } = await import("../dev/mock-browser-agent.mjs");
  const { server } = createMockBrowserAgent({ ownerDidDoc, aud: AUD, log: () => {} });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}

before(async () => {
  HOME = mkdtempSync(join(tmpdir(), "aithos-actenv-"));
  process.env.AITHOS_HOME = HOME;
  core = await import("@aithos/protocol-core");

  identity = core.createIdentity("owner", "Owner");
  core.writeIdentityToDisk(identity);
  core.initKeystoreV03({ handle: "owner", identity });

  const seed = new Uint8Array(randomBytes(32));
  const agentKey = {
    seed_hex: Buffer.from(seed).toString("hex"),
    pubkey_multibase: core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed)),
  };
  mandate = core.createMandate({
    issuer: identity,
    actorSphere: "self",
    grantee: { id: "urn:aithos:agent:demo", pubkey: agentKey.pubkey_multibase },
    scopes: ["browser.action:demo_search"], // demo_post is NOT granted
    ttlSeconds: 3600,
  });
  core.writeMandate(mandate);

  writeFileSync(
    join(HOME, "pack.json"),
    JSON.stringify({ "aithos-mandate-pack": "1", mandate, agent_key: agentKey, options: { auto_commit: true } }),
  );
  writeFileSync(
    join(HOME, "actions.json"),
    JSON.stringify({
      aud: AUD,
      actions: [
        { id: "demo_search", goal: "Search the site", params_schema: { type: "object", properties: { query: { type: "string", minLength: 1 } }, required: ["query"] } },
        { id: "demo_post", goal: "Post a message", params_schema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } },
      ],
    }),
  );

  const ownerDidDoc = JSON.parse(core.snapshotDidJson("owner").content);
  assert.equal(mandate.issuer, ownerDidDoc.id, "mandate issuer must be the owner DID");

  mock = await startMock(ownerDidDoc);
  mockPort = mock.port;

  gateway = spawn(
    process.execPath,
    [
      MCP_BIN, "--transport", "http", "--host", "127.0.0.1", "--port", "0",
      "--mandate-pack", join(HOME, "pack.json"),
      "--actions", join(HOME, "actions.json"),
      "--actions-downstream", `http://127.0.0.1:${mockPort}`,
    ],
    { env: { ...process.env, AITHOS_MCP_TOKEN: TOKEN, AITHOS_HOME: HOME }, stdio: ["ignore", "pipe", "pipe"] },
  );
  gatewayPort = await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error("gateway did not start")), 15000);
    let buf = "";
    gateway.stdout.on("data", (d) => {
      buf += d.toString();
      const m = buf.match(/127\.0\.0\.1:(\d+)\/mcp/);
      if (m) { clearTimeout(to); res(Number(m[1])); }
    });
    gateway.stderr.on("data", () => {});
  });
});

after(async () => {
  if (gateway) gateway.kill("SIGKILL");
  if (mock) await new Promise((r) => mock.server.close(r));
  if (HOME) rmSync(HOME, { recursive: true, force: true });
});

async function connect() {
  const t = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gatewayPort}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  });
  const c = new Client({ name: "cage-agent", version: "0" }, { capabilities: {} });
  await c.connect(t);
  return c;
}

test("only the granted action is exposed as a tool", async () => {
  const c = await connect();
  try {
    const names = (await c.listTools()).tools.map((t) => t.name);
    assert.ok(names.includes("browser_action__demo_search"), "granted action exposed");
    assert.ok(!names.includes("browser_action__demo_post"), "ungranted action hidden");
  } finally {
    await c.close();
  }
});

test("a valid action call signs an envelope the hand verifies + runs", async () => {
  const c = await connect();
  try {
    const r = await c.callTool({ name: "browser_action__demo_search", arguments: { query: "dormant" } });
    assert.ok(!r.isError, r.isError ? r.content?.[0]?.text : "");
    const report = JSON.parse(r.content[0].text);
    assert.equal(report.ok, true);
    assert.equal(report.type, "run_report");
    assert.equal(report.mandate_id, mandate.id);
    assert.deepEqual(report.observed, { query: "dormant" });
  } finally {
    await c.close();
  }
});

test("params are bounded by the SIGNED schema, at the gateway", async () => {
  const c = await connect();
  try {
    // A signed constraint the MCP SDK's lossy zod does NOT enforce (minLength):
    // the empty query reaches the gateway and MY validator (against the signed
    // schema) refuses it — before any signing. The hand is never reached.
    const empty = await c.callTool({ name: "browser_action__demo_search", arguments: { query: "" } });
    assert.equal(empty.isError, true);
    assert.match(empty.content[0].text, /invalid parameters/);

    // A missing required param is refused too.
    const missing = await c.callTool({ name: "browser_action__demo_search", arguments: {} });
    assert.equal(missing.isError, true);

    // An UNDECLARED param cannot reach the signed envelope: the schema strips
    // it, so it never appears in what the hand executed (no injection).
    const extra = await c.callTool({ name: "browser_action__demo_search", arguments: { query: "ok", evil: "rm -rf" } });
    assert.ok(!extra.isError);
    const report = JSON.parse(extra.content[0].text);
    assert.deepEqual(report.observed, { query: "ok" }, "undeclared param stripped, never signed");
  } finally {
    await c.close();
  }
});

test("revoke mid-session → the next action call fails closed", async () => {
  const c = await connect();
  try {
    const ok = await c.callTool({ name: "browser_action__demo_search", arguments: { query: "before" } });
    assert.ok(!ok.isError, "call succeeds before revocation");

    const rev = core.createRevocation({ issuer: identity, mandate, reason: "user_request" });
    core.writeRevocation(rev);

    const denied = await c.callTool({ name: "browser_action__demo_search", arguments: { query: "after" } });
    assert.equal(denied.isError, true, "action refused after revocation");
    assert.match(denied.content[0].text, /revoked/i);
  } finally {
    await c.close();
  }
});
