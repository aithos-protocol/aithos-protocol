// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Self-wired gateway unit tests (PLAN-PROTO-SELFWIRED.md, T1–T7) — no network,
 * no subprocess: the downstream client is injected.
 *
 * Covers: registry parsing (T1), per-server scope gate (T3), namespacing +
 * exposure (T2/T3), routing + error mapping (T4), audit JSONL (T5), teardown
 * (T6), graceful degradation on connect failure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  parseRegistry,
  inputSchemaToShape,
  federate,
} from "../dist/gateway.js";

/* --- a fake Aithos server that records registered tools + dispatches them --- */
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

/* --- a fake downstream MCP client --- */
function fakeClient(tools, { onCall, failConnect } = {}) {
  let closed = false;
  return {
    closed: () => closed,
    async listTools() {
      return { tools };
    },
    async callTool({ name, arguments: args }) {
      if (onCall) return onCall(name, args);
      return { content: [{ type: "text", text: `ran ${name}` }] };
    },
    async close() {
      closed = true;
    },
    _failConnect: failConnect === true,
  };
}

const GH_TOOLS = [
  {
    name: "get_me",
    description: "Get the authenticated user",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "create_issue",
    description: "Create an issue",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string", description: "owner/repo" },
        title: { type: "string" },
        labels: { type: "array", items: { type: "string" } },
      },
      required: ["repo", "title"],
    },
  },
];

test("T1 — parseRegistry accepts a valid registry", () => {
  const reg = parseRegistry(
    JSON.stringify({
      servers: [{ id: "github", transport: "stdio", command: "npx", args: ["-y", "x"] }],
    }),
  );
  assert.equal(reg.servers.length, 1);
  assert.equal(reg.servers[0].id, "github");
});

test("T1 — parseRegistry rejects malformed input", () => {
  assert.throws(() => parseRegistry("not json"), /not valid JSON/);
  assert.throws(() => parseRegistry(JSON.stringify({})), /servers.*array/);
  assert.throws(
    () => parseRegistry(JSON.stringify({ servers: [{ id: "a", transport: "http", command: "x" }] })),
    /transport must be "stdio"/,
  );
  assert.throws(
    () =>
      parseRegistry(
        JSON.stringify({
          servers: [
            { id: "dup", transport: "stdio", command: "x" },
            { id: "dup", transport: "stdio", command: "y" },
          ],
        }),
      ),
    /duplicated/,
  );
});

test("inputSchemaToShape — produces a shape with the schema keys", () => {
  const shape = inputSchemaToShape(GH_TOOLS[1].inputSchema);
  assert.deepEqual(Object.keys(shape).sort(), ["labels", "repo", "title"]);
});

test("T3 — only servers whose scope mcp.<id> is present get federated", async () => {
  const server = fakeServer();
  const client = fakeClient(GH_TOOLS);
  const handle = await federate({
    server,
    scopes: ["mcp.github"], // slack absent
    mandateId: "mnd_1",
    registry: {
      servers: [
        { id: "github", transport: "stdio", command: "x" },
        { id: "slack", transport: "stdio", command: "y" },
      ],
    },
    connect: async () => client,
    log: () => {},
  });
  assert.equal(handle.connected, 1);
  // T2/T3 — namespaced exposure, github only.
  assert.deepEqual(server.list().sort(), ["github__create_issue", "github__get_me"]);
  await handle.teardown();
  assert.equal(client.closed(), true); // T6
});

test("T4/T5 — calling a federated tool routes downstream + writes an audit line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aithos-gw-"));
  const auditPath = join(dir, "audit.jsonl");
  try {
    const server = fakeServer();
    const calls = [];
    const client = fakeClient(GH_TOOLS, {
      onCall: (name, args) => {
        calls.push([name, args]);
        return { content: [{ type: "text", text: `issue#7 in ${args.repo}` }] };
      },
    });
    await federate({
      server,
      scopes: ["mcp.github"],
      mandateId: "mnd_42",
      registry: { servers: [{ id: "github", transport: "stdio", command: "x" }] },
      connect: async () => client,
      auditLogPath: auditPath,
      log: () => {},
    });

    const res = await server.call("github__create_issue", { repo: "me/proj", title: "hi" });
    // routed to the downstream tool (un-namespaced) with the args
    assert.deepEqual(calls, [["create_issue", { repo: "me/proj", title: "hi" }]]);
    assert.equal(res.isError, false); // not an error
    assert.match(res.content[0].text, /issue#7 in me\/proj/);

    const audit = readFileSync(auditPath, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(audit.length, 1);
    assert.equal(audit[0].mandateId, "mnd_42");
    assert.equal(audit[0].server, "github");
    assert.equal(audit[0].tool, "create_issue");
    assert.equal(audit[0].status, "ok");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("T4 — downstream isError is mapped through", async () => {
  const server = fakeServer();
  const client = fakeClient(GH_TOOLS, {
    onCall: () => ({ content: [{ type: "text", text: "boom" }], isError: true }),
  });
  await federate({
    server,
    scopes: ["mcp.github"],
    mandateId: "m",
    registry: { servers: [{ id: "github", transport: "stdio", command: "x" }] },
    connect: async () => client,
    auditLogPath: join(mkdtempSync(join(tmpdir(), "aithos-gw-")), "a.jsonl"),
    log: () => {},
  });
  const res = await server.call("github__get_me", {});
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /boom/);
});

test("T2 — a server that fails to connect is skipped, session survives", async () => {
  const server = fakeServer();
  const ok = fakeClient(GH_TOOLS);
  const handle = await federate({
    server,
    scopes: ["mcp.github", "mcp.broken"],
    mandateId: "m",
    registry: {
      servers: [
        { id: "broken", transport: "stdio", command: "nope" },
        { id: "github", transport: "stdio", command: "x" },
      ],
    },
    connect: async (entry) => {
      if (entry.id === "broken") throw new Error("spawn failed");
      return ok;
    },
    log: () => {},
  });
  assert.equal(handle.connected, 1);
  assert.deepEqual(server.list().sort(), ["github__create_issue", "github__get_me"]);
});
