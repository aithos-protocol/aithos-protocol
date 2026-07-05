#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Demo downstream MCP server (PLAN-CONTAINER P0.4): a tiny in-memory contacts
 * service exposed over stdio, standing in for a real first-party connector.
 *
 * Three tools, two scopes:
 *   list_contacts  → mcp.demo.read
 *   get_contact    → mcp.demo.read
 *   add_contact    → mcp.demo.write
 *
 * The gateway federates this server per the registry (registry.example.json)
 * and gates each tool by the mandate's scopes. This process holds NO Aithos
 * authority — it is just a service the gateway is allowed to reach.
 *
 * Deliberately dependency-light: it speaks the MCP stdio framing directly
 * (newline-delimited JSON-RPC is NOT the wire format — MCP stdio uses
 * Content-Length framing), via the official SDK when present, else a minimal
 * built-in loop so the image needs nothing but Node.
 */
import { createInterface } from "node:readline";

const SEED = [
  { id: "c1", name: "Ada Lovelace", email: "ada@example.com", status: "dormant" },
  { id: "c2", name: "Alan Turing", email: "alan@example.com", status: "active" },
  { id: "c3", name: "Grace Hopper", email: "grace@example.com", status: "dormant" },
];
const contacts = new Map(SEED.map((c) => [c.id, { ...c }]));

const TOOLS = [
  {
    name: "list_contacts",
    description: "List contacts, optionally filtered by status (active|dormant).",
    inputSchema: {
      type: "object",
      properties: { status: { type: "string", enum: ["active", "dormant"] } },
    },
  },
  {
    name: "get_contact",
    description: "Fetch a single contact by id.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "add_contact",
    description: "Add a contact. Returns the created record.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        email: { type: "string" },
        status: { type: "string", enum: ["active", "dormant"] },
      },
      required: ["name", "email"],
    },
  },
];

function runTool(name, args = {}) {
  switch (name) {
    case "list_contacts": {
      const all = [...contacts.values()];
      const filtered = args.status
        ? all.filter((c) => c.status === args.status)
        : all;
      return { contacts: filtered, count: filtered.length };
    }
    case "get_contact": {
      const c = contacts.get(args.id);
      if (!c) throw new Error(`no contact ${args.id}`);
      return c;
    }
    case "add_contact": {
      const id = `c${contacts.size + 1}`;
      const rec = {
        id,
        name: String(args.name),
        email: String(args.email),
        status: args.status === "active" ? "active" : "dormant",
      };
      contacts.set(id, rec);
      return rec;
    }
    default:
      throw new Error(`unknown tool ${name}`);
  }
}

/* ---- Prefer the official SDK; fall back to a minimal stdio JSON-RPC loop --- */

async function main() {
  let McpServer, StdioServerTransport, z;
  try {
    ({ McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js"));
    ({ StdioServerTransport } = await import(
      "@modelcontextprotocol/sdk/server/stdio.js"
    ));
    ({ z } = await import("zod"));
  } catch {
    return minimalLoop();
  }

  const server = new McpServer({ name: "aithos-demo-contacts", version: "0.1.0" });
  const shape = {
    list_contacts: { status: z.enum(["active", "dormant"]).optional() },
    get_contact: { id: z.string() },
    add_contact: {
      name: z.string(),
      email: z.string(),
      status: z.enum(["active", "dormant"]).optional(),
    },
  };
  for (const t of TOOLS) {
    server.registerTool(
      t.name,
      { description: t.description, inputSchema: shape[t.name] },
      async (args) => {
        try {
          return {
            content: [{ type: "text", text: JSON.stringify(runTool(t.name, args)) }],
          };
        } catch (e) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: e.message }) }],
            isError: true,
          };
        }
      },
    );
  }
  await server.connect(new StdioServerTransport());
}

/**
 * SDK-free fallback: newline-delimited JSON-RPC. Good enough for smoke use and
 * environments without the SDK; the compose image installs the SDK so the
 * real path above is what runs in the demo.
 */
function minimalLoop() {
  const rl = createInterface({ input: process.stdin });
  const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (msg.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "aithos-demo-contacts", version: "0.1.0" },
        },
      });
    } else if (msg.method === "tools/list") {
      send({ jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } });
    } else if (msg.method === "tools/call") {
      try {
        const out = runTool(msg.params?.name, msg.params?.arguments ?? {});
        send({
          jsonrpc: "2.0",
          id: msg.id,
          result: { content: [{ type: "text", text: JSON.stringify(out) }] },
        });
      } catch (e) {
        send({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            content: [{ type: "text", text: JSON.stringify({ error: e.message }) }],
            isError: true,
          },
        });
      }
    } else if (msg.id !== undefined) {
      send({ jsonrpc: "2.0", id: msg.id, result: {} });
    }
  });
}

main().catch((e) => {
  console.error(`contacts-server: ${e.message}`);
  process.exit(1);
});
