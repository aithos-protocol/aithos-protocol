#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// Host-side MCP client: call a browser action through the RUNNING gateway
// container (the caged agent's tool call, made by hand). The gateway signs +
// validates + dispatches run_action to browser-agent over the WebSocket.
//
// Run from the aithos-protocol repo root, after `up gateway`:
//   AITHOS_MCP_TOKEN=<same as the container> \
//     node deploy/container/scripts/call-action.mjs "Sophie Martin" [action] [param]
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const VALUE = process.argv[2] ?? "Sophie Martin";
const ACTION = process.argv[3] ?? "inscription-sandbox";
const PARAM = process.argv[4] ?? "nom";
const TOKEN = process.env.AITHOS_MCP_TOKEN;
const GATEWAY = process.env.AITHOS_GATEWAY_URL ?? "http://127.0.0.1:8787/mcp";
if (!TOKEN) {
  console.error("Set AITHOS_MCP_TOKEN to the same value the gateway container uses.");
  process.exit(2);
}

const transport = new StreamableHTTPClientTransport(new URL(GATEWAY), {
  requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
});
const client = new Client({ name: "call-action", version: "0" }, { capabilities: {} });
await client.connect(transport);

const tools = (await client.listTools()).tools.map((t) => t.name).filter((n) => n.startsWith("browser_action__"));
console.log(`tools the agent sees: ${JSON.stringify(tools)}`);
console.log(`calling browser_action__${ACTION} { ${PARAM}: ${JSON.stringify(VALUE)} } — watch Chrome…`);
const r = await client.callTool({ name: `browser_action__${ACTION}`, arguments: { [PARAM]: VALUE } });
const report = JSON.parse(r.content[0].text);
console.log(JSON.stringify(report, null, 2));
await client.close();
console.log(report.ok ? "✅ the container drove the action under the mandate." : "❌ the hand stopped — see the report.");
process.exit(report.ok ? 0 : 1);
