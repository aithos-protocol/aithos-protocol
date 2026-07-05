// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Per-session downstream federation over the HTTP transport — the container
 * gateway's core contract (SPEC-container-runtime §13.6 G1/G2, PLAN P0.1):
 *
 *   - each HTTP session federates the registry against the PACK's scopes;
 *   - out-of-scope tools are ABSENT from tools/list (not merely refused);
 *   - two sessions get independent federations (fresh downstream clients);
 *   - closing a session tears its downstream clients down;
 *   - an expired mandate window exposes NO federated tools (fail closed);
 *   - gateway close() disposes whatever sessions remain.
 *
 * The downstream client is injected (no subprocess, no network): what is
 * exercised for real is the HTTP transport + session lifecycle + scope gate.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const HOME = mkdtempSync(join(tmpdir(), "aithos-mcp-httpfed-"));
process.env.AITHOS_HOME = HOME;

const core = await import("@aithos/protocol-core");
const { startHttpGateway } = await import("../dist/http.js");
const { sessionFederation } = await import("../dist/gateway.js");

const alice = core.createIdentity("alice", "Alice");
core.writeIdentityToDisk(alice);
core.initKeystoreV03({ handle: "alice", identity: alice });

const TOKEN = "fed-test-token-0123456789abcd";

const HOUR = 3600_000;
function packWith(scopes, { expired = false } = {}) {
  const now = Date.now();
  return {
    "aithos-mandate-pack": "1",
    mandate: {
      id: "mandate_01FEDTEST",
      scopes,
      not_before: new Date(now - 2 * HOUR).toISOString(),
      not_after: new Date(expired ? now - HOUR : now + HOUR).toISOString(),
      grantee: { pubkey: "zFEDTEST" },
    },
    agent_key: { seed_hex: "00ff", pubkey_multibase: "zFEDTEST" },
  };
}

const REGISTRY = {
  servers: [
    {
      id: "demo",
      transport: "stdio",
      command: "unused-injected",
      tool_scopes: {
        list_contacts: "mcp.demo.read",
        add_contact: "mcp.demo.write",
      },
    },
  ],
};

function fakeDownstreamFactory() {
  const spawned = [];
  const connect = async () => {
    const client = {
      closed: false,
      async listTools() {
        return {
          tools: [
            { name: "list_contacts", description: "list", inputSchema: {} },
            { name: "add_contact", description: "add", inputSchema: {} },
          ],
        };
      },
      async callTool({ name }) {
        return { content: [{ type: "text", text: `downstream:${name}` }] };
      },
      async close() {
        client.closed = true;
      },
    };
    spawned.push(client);
    return client;
  };
  return { spawned, connect };
}

function serverOptions() {
  return {
    storage: new core.FilesystemStorage(),
    home: HOME,
    manifestPath: core.ethosManifestPath,
    renderZone: core.renderZoneMarkdown,
    autoCommit: true,
  };
}

async function bootFederated({ pack, audit = [], connect }) {
  return startHttpGateway({
    host: "127.0.0.1",
    port: 0,
    token: TOKEN,
    serverOptions,
    log: () => {},
    onSessionServer: sessionFederation({
      pack,
      registry: REGISTRY,
      auditSink: (e) => audit.push(e),
      log: () => {},
      connect,
    }),
  });
}

async function connectClient(port) {
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } } },
  );
  const client = new Client(
    { name: "http-fed-test", version: "0.0.0" },
    { capabilities: {} },
  );
  await client.connect(transport);
  client.terminateSession = () => transport.terminateSession();
  return client;
}

async function eventually(fn, what, tries = 50) {
  for (let i = 0; i < tries; i++) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.fail(`timed out waiting for: ${what}`);
}

/* -------------------------------------------------------------------------- */

test("session under a read-scoped pack sees exactly the read tool, namespaced", async () => {
  const { spawned, connect } = fakeDownstreamFactory();
  const gw = await bootFederated({ pack: packWith(["mcp.demo.read"]), connect });
  try {
    const client = await connectClient(gw.port);
    const tools = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(tools.includes("demo__list_contacts"), "read tool exposed");
    assert.ok(!tools.includes("demo__add_contact"), "write tool ABSENT from the list");
    assert.ok(tools.includes("ethos_read_section"), "core tools still there");

    const res = await client.callTool({
      name: "demo__list_contacts",
      arguments: {},
    });
    assert.ok(!res.isError, "granted call succeeds");
    assert.equal(res.content[0].text, "downstream:list_contacts");
    assert.equal(spawned.length, 1);
    await client.close();
  } finally {
    await gw.close();
  }
});

test("two sessions federate independently (one downstream client each)", async () => {
  const { spawned, connect } = fakeDownstreamFactory();
  const gw = await bootFederated({ pack: packWith(["mcp.demo.read"]), connect });
  try {
    const a = await connectClient(gw.port);
    const b = await connectClient(gw.port);
    assert.equal(spawned.length, 2, "one federation per session");
    await a.close();
    await b.close();
  } finally {
    await gw.close();
  }
});

test("closing a session tears its downstream client down", async () => {
  const { spawned, connect } = fakeDownstreamFactory();
  const gw = await bootFederated({ pack: packWith(["mcp.demo.read"]), connect });
  try {
    const client = await connectClient(gw.port);
    assert.equal(spawned.length, 1);
    // Explicit session termination (HTTP DELETE) → server transport onclose.
    await client.terminateSession();
    await client.close();
    await eventually(() => spawned[0].closed, "downstream client closed");
  } finally {
    await gw.close();
  }
});

test("expired mandate window: no federated tools at all (fail closed)", async () => {
  const { spawned, connect } = fakeDownstreamFactory();
  const gw = await bootFederated({
    pack: packWith(["mcp.demo.read"], { expired: true }),
    connect,
  });
  try {
    const client = await connectClient(gw.port);
    const tools = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(
      tools.every((t) => !t.startsWith("demo__")),
      "no demo__* tool under an expired mandate",
    );
    assert.equal(spawned.length, 0, "downstream never contacted");
    await client.close();
  } finally {
    await gw.close();
  }
});

test("audit entries carry the mandate id", async () => {
  const { connect } = fakeDownstreamFactory();
  const audit = [];
  const gw = await bootFederated({ pack: packWith(["mcp.demo.read"]), audit, connect });
  try {
    const client = await connectClient(gw.port);
    await client.callTool({ name: "demo__list_contacts", arguments: {} });
    assert.ok(audit.length >= 1);
    assert.equal(audit[0].mandateId, "mandate_01FEDTEST");
    assert.equal(audit[0].server, "demo");
    assert.equal(audit[0].status, "ok");
    await client.close();
  } finally {
    await gw.close();
  }
});

test("revocation mid-session: next federated call over HTTP is refused (G1)", async () => {
  const { connect } = fakeDownstreamFactory();
  let revoked = false;
  const gw = await startHttpGateway({
    host: "127.0.0.1",
    port: 0,
    token: TOKEN,
    serverOptions,
    log: () => {},
    onSessionServer: sessionFederation({
      pack: packWith(["mcp.demo.read"]),
      registry: REGISTRY,
      auditSink: () => {},
      log: () => {},
      connect,
      liveness: async () => {
        if (revoked) throw new Error("mandate mandate_01FEDTEST was revoked at T");
      },
    }),
  });
  try {
    const client = await connectClient(gw.port);
    const ok = await client.callTool({ name: "demo__list_contacts", arguments: {} });
    assert.ok(!ok.isError, "pre-revocation call passes");

    revoked = true; // ~ aithos revoke while the mission runs
    const denied = await client.callTool({
      name: "demo__list_contacts",
      arguments: {},
    });
    assert.equal(denied.isError, true, "post-revocation call refused");
    assert.match(denied.content[0].text, /revoked/);
    await client.close();
  } finally {
    await gw.close();
  }
});

test("gateway close() disposes live sessions' downstreams", async () => {
  const { spawned, connect } = fakeDownstreamFactory();
  const gw = await bootFederated({ pack: packWith(["mcp.demo.read"]), connect });
  const client = await connectClient(gw.port);
  assert.equal(spawned.length, 1);
  await gw.close();
  await eventually(() => spawned[0].closed, "downstream closed by gateway close()");
  try {
    await client.close();
  } catch {
    /* server already gone — fine */
  }
});

test.after(() => {
  rmSync(HOME, { recursive: true, force: true });
});
