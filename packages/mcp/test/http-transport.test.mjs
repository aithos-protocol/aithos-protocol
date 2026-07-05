// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * HTTP transport tests against the extracted gateway factory (src/http.ts).
 *
 * Covers, over a REAL http server on an ephemeral port:
 *   - /healthz liveness without auth
 *   - bearer gate: missing / malformed / wrong-length / wrong token → 401,
 *     correct token → MCP handshake succeeds (S2 regression, behavioural)
 *   - S3 (audit 2026-07-02) e2e: an AUTHENTICATED client passing path-form
 *     `mandate` / `agent_key` tool arguments ("/etc/passwd", "../../x") gets an
 *     explicit refusal and the server never reads the file (LFI, CWE-22)
 *   - stateful session reuse + stateless mode handshake
 *   - clean close()
 *
 * The bearer comparison itself is constant-time BY CONSTRUCTION
 * (crypto.timingSafeEqual behind a length gate — see bearerAuthorizer); these
 * tests pin the observable contract, not wall-clock timing (which is flaky in
 * CI by nature).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

// $AITHOS_HOME must be set BEFORE protocol-core is imported (frozen at import
// time), exactly like e2e-write.test.mjs.
const HOME = mkdtempSync(join(tmpdir(), "aithos-mcp-http-"));
process.env.AITHOS_HOME = HOME;

const core = await import("@aithos/protocol-core");
const { startHttpGateway, bearerAuthorizer } = await import("../dist/http.js");

// Seed a fresh keystore for "alice" so ethos tools have something to serve.
const alice = core.createIdentity("alice", "Alice");
core.writeIdentityToDisk(alice);
core.initKeystoreV03({ handle: "alice", identity: alice });

const TOKEN = "test-token-0123456789abcdef";

function serverOptions() {
  return {
    storage: new core.FilesystemStorage(),
    home: HOME,
    manifestPath: core.ethosManifestPath,
    renderZone: core.renderZoneMarkdown,
    autoCommit: true,
  };
}

async function boot(extra = {}) {
  return startHttpGateway({
    host: "127.0.0.1",
    port: 0, // ephemeral
    token: TOKEN,
    serverOptions,
    log: () => {},
    ...extra,
  });
}

async function connectClient(port, token = TOKEN) {
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
  );
  const client = new Client(
    { name: "http-transport-test", version: "0.0.0" },
    { capabilities: {} },
  );
  await client.connect(transport);
  return client;
}

function payload(res) {
  return JSON.parse(res.content[0].text);
}

/* -------------------------------------------------------------------------- */
/* bearerAuthorizer — unit                                                    */
/* -------------------------------------------------------------------------- */

test("bearerAuthorizer: exact token passes; anything else fails closed", () => {
  const authorize = bearerAuthorizer(TOKEN);
  const req = (auth) => ({ headers: auth === undefined ? {} : { authorization: auth } });

  assert.equal(authorize(req(`Bearer ${TOKEN}`)), true, "exact token");
  assert.equal(authorize(req(`bearer ${TOKEN}`)), true, "scheme is case-insensitive");
  assert.equal(authorize(req(undefined)), false, "missing header");
  assert.equal(authorize(req("")), false, "empty header");
  assert.equal(authorize(req(TOKEN)), false, "raw token without scheme");
  assert.equal(authorize(req(`Basic ${TOKEN}`)), false, "wrong scheme");
  assert.equal(authorize(req("Bearer short")), false, "wrong length");
  assert.equal(
    authorize(req(`Bearer ${TOKEN.slice(0, -1)}X`)),
    false,
    "same length, wrong content",
  );
});

/* -------------------------------------------------------------------------- */
/* liveness + auth gate over real HTTP                                        */
/* -------------------------------------------------------------------------- */

test("healthz answers without auth; /mcp is bearer-gated", async () => {
  const gw = await boot();
  try {
    const health = await fetch(`http://127.0.0.1:${gw.port}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true, name: "aithos-mcp" });

    // No bearer → 401 + WWW-Authenticate.
    const noAuth = await fetch(`http://127.0.0.1:${gw.port}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(noAuth.status, 401);
    assert.match(noAuth.headers.get("www-authenticate") ?? "", /Bearer/);

    // Wrong token (same length) → 401.
    const badAuth = await fetch(`http://127.0.0.1:${gw.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN.slice(0, -1)}X`,
      },
      body: "{}",
    });
    assert.equal(badAuth.status, 401);

    // Unknown path → 404.
    const nope = await fetch(`http://127.0.0.1:${gw.port}/nope`);
    assert.equal(nope.status, 404);
  } finally {
    await gw.close();
  }
});

/* -------------------------------------------------------------------------- */
/* MCP handshake + LFI regression (S3, e2e over HTTP)                          */
/* -------------------------------------------------------------------------- */

test("stateful: handshake works and sessions serve tools/list twice", async () => {
  const gw = await boot();
  try {
    const client = await connectClient(gw.port);
    const tools = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(tools.includes("ethos_read_section"), "canonical tools listed");
    // Second round-trip on the SAME session (session id reuse).
    const again = (await client.listTools()).tools.map((t) => t.name);
    assert.deepEqual(again, tools);
    await client.close();
  } finally {
    await gw.close();
  }
});

test("S3 e2e: path-form agent_key/mandate over authenticated HTTP is refused explicitly", async () => {
  const gw = await boot();
  try {
    const client = await connectClient(gw.port);

    for (const evil of ["/etc/passwd", "../../x"]) {
      const res = await client.callTool({
        name: "ethos_add_section",
        arguments: {
          handle: "alice",
          zone: "public",
          title: "probe",
          body: "probe",
          mandate: evil,
          agent_key: evil,
        },
      });
      assert.equal(res.isError, true, `path-form ${evil} must be refused`);
      const text = res.content?.[0]?.text ?? "";
      assert.match(
        text,
        /host file access|by id only|cannot read/i,
        `refusal for ${evil} is explicit (got: ${text.slice(0, 120)})`,
      );
      assert.doesNotMatch(text, /root:/, "no file content leaks back");
    }
    await client.close();
  } finally {
    await gw.close();
  }
});

test("id-form mandate still resolves through storage over HTTP (fail-closed, not fail-all)", async () => {
  const gw = await boot();
  try {
    const client = await connectClient(gw.port);
    // Unknown id → storage-backed miss, NOT an io/path error.
    const res = await client.callTool({
      name: "ethos_add_section",
      arguments: {
        handle: "alice",
        zone: "public",
        title: "probe",
        body: "probe",
        mandate: "mandate_01UNKNOWN",
        agent_key: "mandate_01UNKNOWN",
      },
    });
    assert.equal(res.isError, true);
    const text = res.content?.[0]?.text ?? "";
    // The agent key is still path-resolved (needs io) — but the mandate id
    // itself must not trip the path guard.
    assert.doesNotMatch(text, /mandates need host file access/i);
    await client.close();
  } finally {
    await gw.close();
  }
});

/* -------------------------------------------------------------------------- */
/* stateless mode + lifecycle                                                 */
/* -------------------------------------------------------------------------- */

test("stateless: handshake + tools/list work per-request", async () => {
  const gw = await boot({ stateless: true });
  try {
    const client = await connectClient(gw.port);
    const tools = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(tools.length > 0, "tools listed in stateless mode");
    await client.close();
  } finally {
    await gw.close();
  }
});

test("close() shuts the listener down", async () => {
  const gw = await boot();
  await gw.close();
  await assert.rejects(
    () => fetch(`http://127.0.0.1:${gw.port}/healthz`),
    /fetch failed/i,
  );
});

test.after(() => {
  rmSync(HOME, { recursive: true, force: true });
});
