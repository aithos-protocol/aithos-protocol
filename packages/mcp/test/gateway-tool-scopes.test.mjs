// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Per-tool scope granularity in the registry (SPEC-container-runtime §13.6 G2,
 * DESIGN-topologie D2): a registry entry may map individual downstream tools
 * to their own scopes (`tool_scopes`), so a mandate can grant `mcp.demo.read`
 * without `mcp.demo.write`.
 *
 * Contract pinned here:
 *   - whole-server scope `mcp.<id>` still grants every tool (back-compat);
 *   - with `tool_scopes`, a tool is exposed iff the mandate carries ITS scope;
 *   - tools NOT named in `tool_scopes` require the whole-server scope
 *     (deny by default — an unmapped tool is invisible, not implicitly open);
 *   - a server is not even CONNECTED unless at least one of its tools is
 *     grantable (no subprocess for nothing);
 *   - dispatch re-checks the scope (defense in depth) and audits denials.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseRegistry, federate } from "../dist/gateway.js";

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

function fakeDownstream(toolNames) {
  return {
    closed: false,
    async listTools() {
      return {
        tools: toolNames.map((name) => ({
          name,
          description: `${name} tool`,
          inputSchema: { type: "object", properties: {} },
        })),
      };
    },
    async callTool({ name }) {
      return { content: [{ type: "text", text: `ran:${name}` }] };
    },
    async close() {
      this.closed = true;
    },
  };
}

const DEMO_ENTRY = {
  id: "demo",
  transport: "stdio",
  command: "unused",
  tool_scopes: {
    list_contacts: "mcp.demo.read",
    get_contact: "mcp.demo.read",
    add_contact: "mcp.demo.write",
  },
};

function registryWith(entry = DEMO_ENTRY) {
  return { servers: [entry] };
}

async function fed(scopes, { entry = DEMO_ENTRY, audit = [] } = {}) {
  const server = fakeServer();
  const downstream = fakeDownstream([
    "list_contacts",
    "get_contact",
    "add_contact",
    "unmapped_tool",
  ]);
  let connects = 0;
  const handle = await federate({
    server,
    scopes,
    mandateId: "mandate_01TEST",
    registry: registryWith(entry),
    auditSink: (e) => audit.push(e),
    log: () => {},
    connect: async () => {
      connects += 1;
      return downstream;
    },
  });
  return { server, downstream, handle, audit, connects: () => connects };
}

/* -------------------------------------------------------------------------- */
/* parseRegistry                                                              */
/* -------------------------------------------------------------------------- */

test("parseRegistry accepts tool_scopes and validates its shape", () => {
  const ok = parseRegistry(
    JSON.stringify({
      servers: [
        {
          id: "demo",
          transport: "stdio",
          command: "node",
          tool_scopes: { list_contacts: "mcp.demo.read" },
        },
      ],
    }),
  );
  assert.equal(ok.servers[0].tool_scopes.list_contacts, "mcp.demo.read");

  assert.throws(
    () =>
      parseRegistry(
        JSON.stringify({
          servers: [
            {
              id: "demo",
              transport: "stdio",
              command: "node",
              tool_scopes: { list_contacts: 42 },
            },
          ],
        }),
      ),
    /tool_scopes/,
  );

  assert.throws(
    () =>
      parseRegistry(
        JSON.stringify({
          servers: [
            { id: "demo", transport: "stdio", command: "node", tool_scopes: "nope" },
          ],
        }),
      ),
    /tool_scopes/,
  );
});

/* -------------------------------------------------------------------------- */
/* exposure matrix                                                            */
/* -------------------------------------------------------------------------- */

test("whole-server scope mcp.<id> exposes every tool (back-compat)", async () => {
  const { server, handle } = await fed(["mcp.demo"]);
  assert.deepEqual(
    server.list().sort(),
    [
      "demo__add_contact",
      "demo__get_contact",
      "demo__list_contacts",
      "demo__unmapped_tool",
    ],
  );
  await handle.teardown();
});

test("read-only scope exposes exactly the read tools; write + unmapped stay invisible", async () => {
  const { server, handle } = await fed(["mcp.demo.read"]);
  assert.deepEqual(server.list().sort(), ["demo__get_contact", "demo__list_contacts"]);
  await handle.teardown();
});

test("write-only scope exposes exactly the write tool", async () => {
  const { server, handle } = await fed(["mcp.demo.write"]);
  assert.deepEqual(server.list(), ["demo__add_contact"]);
  await handle.teardown();
});

test("no relevant scope: server is never connected (no subprocess for nothing)", async () => {
  const { server, connects, handle } = await fed(["mcp.other", "ethos.read.public"]);
  assert.equal(connects(), 0, "connect must not be called");
  assert.deepEqual(server.list(), []);
  await handle.teardown();
});

test("entry without tool_scopes keeps the historical all-or-nothing behaviour", async () => {
  const entry = { id: "demo", transport: "stdio", command: "unused" };
  const granted = await fed(["mcp.demo"], { entry });
  assert.equal(granted.server.list().length, 4);
  await granted.handle.teardown();

  const denied = await fed(["mcp.demo.read"], { entry });
  // Without tool_scopes, mcp.demo.read is NOT a grant for server "demo".
  assert.equal(denied.connects(), 0);
  assert.deepEqual(denied.server.list(), []);
  await denied.handle.teardown();
});

/* -------------------------------------------------------------------------- */
/* dispatch re-check (defense in depth) + audit                               */
/* -------------------------------------------------------------------------- */

test("dispatch re-checks the per-tool scope and audits the denial", async () => {
  const scopes = ["mcp.demo.read"];
  const audit = [];
  const { server, handle } = await fed(scopes, { audit });

  const ok = await server.call("demo__list_contacts", {});
  assert.ok(!ok.isError, "granted call succeeds");
  assert.equal(ok.content[0].text, "ran:list_contacts");

  // Scope evaporates after registration (revocation-like) → dispatch denies.
  scopes.length = 0;
  const denied = await server.call("demo__list_contacts", {});
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /denied: mandate lacks scope mcp\.demo\.read/);

  const statuses = audit.map((e) => e.status);
  assert.ok(statuses.includes("ok"), "successful call audited");
  assert.ok(statuses.includes("denied"), "denial audited");
  assert.ok(
    audit.every((e) => e.mandateId === "mandate_01TEST"),
    "every entry attributed to the mandate",
  );
  await handle.teardown();
});

test("teardown closes the downstream client", async () => {
  const { downstream, handle } = await fed(["mcp.demo.read"]);
  await handle.teardown();
  assert.equal(downstream.closed, true);
});

/* -------------------------------------------------------------------------- */
/* per-call liveness (G1 — revocation is checked on EVERY dispatch)           */
/* -------------------------------------------------------------------------- */

test("a liveness failure (revocation) denies the NEXT dispatch, fail closed, audited", async () => {
  let revoked = false;
  const audit = [];
  const server = fakeServer();
  const downstream = fakeDownstream(["list_contacts"]);
  const handle = await federate({
    server,
    scopes: ["mcp.demo.read"],
    mandateId: "mandate_01TEST",
    registry: registryWith(),
    auditSink: (e) => audit.push(e),
    log: () => {},
    connect: async () => downstream,
    liveness: async () => {
      if (revoked) throw new Error("mandate mandate_01TEST was revoked at T");
    },
  });

  const ok = await server.call("demo__list_contacts", {});
  assert.ok(!ok.isError, "live mandate dispatches");

  revoked = true; // aithos revoke happens mid-mission…
  const denied = await server.call("demo__list_contacts", {});
  assert.equal(denied.isError, true, "…and the very next call is refused");
  assert.match(denied.content[0].text, /revoked/);

  const last = audit[audit.length - 1];
  assert.equal(last.status, "denied");
  assert.match(last.error ?? "", /revoked/);
  await handle.teardown();
});

test("a liveness check that itself crashes still fails closed", async () => {
  const server = fakeServer();
  const downstream = fakeDownstream(["list_contacts"]);
  const handle = await federate({
    server,
    scopes: ["mcp.demo.read"],
    mandateId: "mandate_01TEST",
    registry: registryWith(),
    auditSink: () => {},
    log: () => {},
    connect: async () => downstream,
    liveness: async () => {
      throw new Error("revocation authority unreachable");
    },
  });
  const denied = await server.call("demo__list_contacts", {});
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /unreachable/);
  await handle.teardown();
});
