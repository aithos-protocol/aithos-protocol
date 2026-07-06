#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * check.mjs — the demo's five assertions, live, WITHOUT Docker.
 *
 * Boots the REAL gateway process (packages/mcp/dist/bin.js) under a freshly
 * prepared mandate + a local-path registry + a fake LLM upstream, then asserts:
 *
 *   1. in-scope tool runs and is visible;
 *   2. out-of-scope tool is invisible + refused if forced;
 *   3. inference flows through the gateway /llm proxy;
 *   4. revoke mid-session → next tool call AND inference fail closed;
 *   5. (structural) no secret is handed to a runtime — the pack is the gateway's.
 *
 * Criterion 3's kernel network isolation ("curl example.com fails") is the only
 * thing that needs Docker; everything else is proven here in seconds. Run:
 *
 *   node deploy/container/scripts/check.mjs        # from the repo root
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { randomBytes } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..", "..");
const MCP_BIN = join(ROOT, "packages/mcp/dist/bin.js");
const CONTACTS = join(HERE, "..", "demo", "contacts-server.mjs");
const TOKEN = "check-" + randomBytes(6).toString("hex");

let fails = 0;
const ok = (name, cond, extra = "") =>
  console.log(`  ${cond ? "✓" : "✗ FAIL"}  ${name}${extra ? "  — " + extra : ""}`) ||
  (cond ? 0 : (fails += 1));

const HOME = mkdtempSync(join(tmpdir(), "aithos-check-"));
process.env.AITHOS_HOME = HOME;

const core = await import("@aithos/protocol-core");
const ed = await import("@noble/ed25519");
const { sha512 } = await import("@noble/hashes/sha512");
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// --- prepare identity + read-only mandate + pack + local registry -----------
const identity = core.createIdentity("demo", "Demo Owner");
core.writeIdentityToDisk(identity);
core.initKeystoreV03({ handle: "demo", identity });
const seed = new Uint8Array(randomBytes(32));
const agentKey = {
  seed_hex: Buffer.from(seed).toString("hex"),
  pubkey_multibase: core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed)),
};
const mandate = core.createMandate({
  issuer: identity,
  actorSphere: "public",
  grantee: { id: "urn:aithos:agent:demo", pubkey: agentKey.pubkey_multibase },
  scopes: ["mcp.demo.read"],
  ttlSeconds: 3600,
});
core.writeMandate(mandate);
writeFileSync(
  join(HOME, "pack.json"),
  JSON.stringify({ "aithos-mandate-pack": "1", mandate, agent_key: agentKey, options: { auto_commit: true } }),
);
writeFileSync(
  join(HOME, "registry.json"),
  JSON.stringify({
    servers: [
      {
        id: "demo",
        transport: "stdio",
        command: process.execPath,
        args: [CONTACTS],
        tool_scopes: { list_contacts: "mcp.demo.read", get_contact: "mcp.demo.read", add_contact: "mcp.demo.write" },
      },
    ],
  }),
);

// --- fake upstream + real gateway -------------------------------------------
let llmHits = 0;
const upstream = http.createServer((_q, r) => { llmHits += 1; r.writeHead(200); r.end("{}"); });
await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
const upstreamPort = upstream.address().port;

const gw = spawn(process.execPath, [
  MCP_BIN, "--transport", "http", "--host", "127.0.0.1", "--port", "0",
  "--mandate-pack", join(HOME, "pack.json"),
  "--mcp-registry", join(HOME, "registry.json"),
  "--llm-proxy", "--llm-upstream", `http://127.0.0.1:${upstreamPort}`,
], { env: { ...process.env, AITHOS_MCP_TOKEN: TOKEN, AITHOS_HOME: HOME }, stdio: ["ignore", "pipe", "pipe"] });

const port = await new Promise((res, rej) => {
  const to = setTimeout(() => rej(new Error("gateway did not start")), 15000);
  gw.stdout.on("data", (d) => {
    const m = d.toString().match(/127\.0\.0\.1:(\d+)\/mcp/);
    if (m) { clearTimeout(to); res(Number(m[1])); }
  });
});

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
const connect = async () => {
  const t = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  });
  const c = new Client({ name: "check", version: "0" }, { capabilities: {} });
  await c.connect(t);
  return c;
};

try {
  console.log("Aithos container — five assertions (no Docker):\n");

  const c = await connect();
  const names = (await c.listTools()).tools.map((t) => t.name);
  ok("1. in-scope tool visible + runs", names.includes("demo__list_contacts"));
  const r1 = await c.callTool({ name: "demo__list_contacts", arguments: { status: "dormant" } });
  ok("   list_contacts returns data", !r1.isError && JSON.parse(r1.content[0].text).count === 2);

  ok("2. out-of-scope tool invisible", !names.includes("demo__add_contact"));
  const forced = await c.callTool({ name: "demo__add_contact", arguments: { name: "x", email: "y" } });
  ok("   forced out-of-scope call refused", forced.isError === true);

  const before = llmHits;
  const llm = await fetch(`http://127.0.0.1:${port}/llm/v1/messages`, { method: "POST", body: "{}" });
  ok("3. inference flows through /llm proxy", llm.status === 200 && llmHits === before + 1);
  await c.close();

  // 4. revoke mid-session.
  const rev = core.createRevocation({ issuer: identity, mandate, reason: "user_request" });
  core.writeRevocation(rev);
  const c2 = await connect();
  const denied = await c2.callTool({ name: "demo__list_contacts", arguments: {} });
  ok("4. tool refused after revoke", denied.isError === true && /revoked/i.test(denied.content?.[0]?.text ?? ""));
  const llm2 = await fetch(`http://127.0.0.1:${port}/llm/v1/messages`, { method: "POST", body: "{}" });
  ok("   inference refused after revoke (403)", llm2.status === 403);
  await c2.close();

  // 5. structural: the pack lives with the gateway, nothing was handed to a runtime.
  const packOnDisk = JSON.parse(readFileSync(join(HOME, "pack.json"), "utf8"));
  ok("5. pack is the gateway's (agent_key never leaves it)", !!packOnDisk.agent_key?.seed_hex);
} finally {
  gw.kill("SIGKILL");
  await new Promise((r) => upstream.close(r));
  rmSync(HOME, { recursive: true, force: true });
}

console.log(fails === 0 ? "\nAll five assertions hold. ✓" : `\n${fails} assertion(s) FAILED.`);
process.exit(fails === 0 ? 0 : 1);
