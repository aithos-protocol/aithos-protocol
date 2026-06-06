// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: the full section lifecycle through the BUILT MCP server over a
 * real stdio transport, against a v0.3 (per-section) keystore.
 *
 *   add (×2) → read several by id → modify → read → delete → list
 *
 * This exercises the actual server process (dist/bin.js), the MCP client SDK
 * handshake, and the v0.3 write/read storage path wired in this lot. The
 * keystore is seeded with protocol-core directly; the server child inherits the
 * same throwaway $AITHOS_HOME.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// $AITHOS_HOME must be set BEFORE protocol-core is imported (it freezes the
// home at import time), and is inherited by the spawned server.
const HOME = mkdtempSync(join(tmpdir(), "aithos-mcp-e2e-"));
process.env.AITHOS_HOME = HOME;

const core = await import("@aithos/protocol-core");

// Seed a fresh v0.3 keystore for "alice".
const alice = core.createIdentity("alice", "Alice");
core.writeIdentityToDisk(alice);
core.initKeystoreV03({ handle: "alice", identity: alice });

function payload(res) {
  return JSON.parse(res.content[0].text);
}

async function withClient(fn) {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/bin.js", "--transport", "stdio"],
    env: { ...process.env },
  });
  const client = new Client({ name: "aithos-e2e", version: "0.0.0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

test("MCP v0.3 section lifecycle over stdio (add/read-many/modify/delete)", async () => {
  try {
    await withClient(async (client) => {
      const call = (name, args) =>
        client.callTool({ name, arguments: args }).then(payload);

      // --- the delete tool is now part of the surface ---------------------
      const tools = (await client.listTools()).tools.map((t) => t.name);
      assert.ok(tools.includes("aithos_ethos_delete_section"), "delete tool registered");
      assert.ok(tools.includes("aithos_ethos_read_sections"), "multi-read tool registered");

      // --- add two self sections -----------------------------------------
      const a = await call("aithos_ethos_add_section", {
        handle: "alice", zone: "self", title: "Routine", body: "Up at six.", tags: ["am"],
      });
      const b = await call("aithos_ethos_add_section", {
        handle: "alice", zone: "self", title: "Goals", body: "Ship v0.3.",
      });
      const idA = a.section.id;
      const idB = b.section.id;
      assert.ok(idA.startsWith("sec_") && idB.startsWith("sec_"));
      assert.equal(a.section.title, "Routine");

      // --- read BOTH at once by id ---------------------------------------
      const read = await call("aithos_ethos_read_sections", {
        handle: "alice", sectionIds: [idA, idB],
      });
      assert.equal(read.sections.length, 2);
      assert.ok(read.sections.every((s) => s.accessible));
      const bodies = Object.fromEntries(read.sections.map((s) => [s.id, s.body]));
      assert.equal(bodies[idA], "Up at six.");
      assert.equal(bodies[idB], "Ship v0.3.");

      // --- modify one, confirm via re-read --------------------------------
      await call("aithos_ethos_modify_section", {
        handle: "alice", zone: "self", sectionId: idA, body: "Up at five.",
      });
      const reread = await call("aithos_ethos_read_sections", { handle: "alice", sectionIds: [idA] });
      assert.equal(reread.sections[0].body, "Up at five.");

      // --- list shows both via the index ---------------------------------
      let list = await call("aithos_ethos_list_sections", { handle: "alice", zone: "self" });
      assert.deepEqual(list.sections.map((s) => s.title).sort(), ["Goals", "Routine"]);

      // --- delete one, confirm it's gone ---------------------------------
      const del = await call("aithos_ethos_delete_section", {
        handle: "alice", zone: "self", sectionId: idA,
      });
      assert.equal(del.deleted_section_id, idA);
      list = await call("aithos_ethos_list_sections", { handle: "alice", zone: "self" });
      assert.deepEqual(list.sections.map((s) => s.title), ["Goals"]);
      const goneRead = await call("aithos_ethos_read_sections", { handle: "alice", sectionIds: [idA] });
      assert.equal(goneRead.sections[0].accessible, false);

      // --- the ethos still verifies after the write round-trip -----------
      const verify = await call("aithos_ethos_verify", { handle: "alice" });
      assert.equal(verify.ok, true, JSON.stringify(verify.errors ?? []));
    });
  } finally {
    rmSync(HOME, { recursive: true, force: true });
  }
});
