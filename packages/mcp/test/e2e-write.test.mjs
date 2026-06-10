// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: the full section lifecycle through the BUILT MCP server over a
 * real stdio transport, against a v0.3 (per-section) keystore.
 *
 *   add (×2) → read several by id → modify (via LEGACY alias) → read →
 *   delete → list → verify
 *
 * This exercises the actual server process (dist/bin.js), the MCP client SDK
 * handshake, the v0.3 write/read storage path, the canonical D1 tool names,
 * and the pre-0.9 `aithos_*` alias bridge (accepted at tools/call, never
 * listed). The keystore is seeded with protocol-core directly; the server
 * child inherits the same throwaway $AITHOS_HOME.
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

test("MCP v0.3 section lifecycle over stdio (add/read-many/update/delete)", async () => {
  try {
    await withClient(async (client) => {
      const call = (name, args) =>
        client.callTool({ name, arguments: args }).then(payload);

      // --- tools/list exposes ONLY the canonical D1 names ------------------
      const tools = (await client.listTools()).tools.map((t) => t.name);
      assert.ok(tools.includes("ethos_delete_section"), "delete tool registered");
      assert.ok(tools.includes("ethos_read_sections"), "multi-read tool registered");
      assert.ok(
        tools.every((t) => !t.startsWith("aithos_")),
        `legacy aithos_* names must not be listed (got: ${tools.join(", ")})`,
      );

      // --- add two self sections (canonical names) -------------------------
      const a = await call("ethos_add_section", {
        handle: "alice", zone: "self", title: "Routine", body: "Up at six.", tags: ["am"],
      });
      const b = await call("ethos_add_section", {
        handle: "alice", zone: "self", title: "Goals", body: "Ship v0.3.",
      });
      const idA = a.section.id;
      const idB = b.section.id;
      assert.ok(idA.startsWith("sec_") && idB.startsWith("sec_"));
      assert.equal(a.section.title, "Routine");

      // --- read BOTH at once by id (snake_case args) -----------------------
      const read = await call("ethos_read_sections", {
        handle: "alice", section_ids: [idA, idB],
      });
      assert.equal(read.sections.length, 2);
      assert.ok(read.sections.every((s) => s.accessible));
      const bodies = Object.fromEntries(read.sections.map((s) => [s.id, s.body]));
      assert.equal(bodies[idA], "Up at six.");
      assert.equal(bodies[idB], "Ship v0.3.");

      // --- modify via the LEGACY alias + legacy camelCase args -------------
      // (pre-0.9 clients keep working for one minor; the bridge renames
      // aithos_ethos_modify_section → ethos_update_section, sectionId →
      // section_id. Removal scheduled for 1.0.)
      await call("aithos_ethos_modify_section", {
        handle: "alice", zone: "self", sectionId: idA, body: "Up at five.",
      });
      const reread = await call("ethos_read_sections", { handle: "alice", section_ids: [idA] });
      assert.equal(reread.sections[0].body, "Up at five.");

      // --- single-section canonical read ------------------------------------
      const single = await call("ethos_read_section", {
        handle: "alice", zone: "self", section_id: idB,
      });
      assert.equal(single.body, "Ship v0.3.");

      // --- list shows both via the index ---------------------------------
      let list = await call("ethos_list_sections", { handle: "alice", zone: "self" });
      assert.deepEqual(list.sections.map((s) => s.title).sort(), ["Goals", "Routine"]);

      // --- delete one, confirm it's gone ---------------------------------
      const del = await call("ethos_delete_section", {
        handle: "alice", zone: "self", section_id: idA,
      });
      assert.equal(del.deleted_section_id, idA);
      list = await call("ethos_list_sections", { handle: "alice", zone: "self" });
      assert.deepEqual(list.sections.map((s) => s.title), ["Goals"]);
      const goneRead = await call("ethos_read_sections", { handle: "alice", section_ids: [idA] });
      assert.equal(goneRead.sections[0].accessible, false);

      // --- the ethos still verifies after the write round-trip -----------
      const verify = await call("ethos_verify", { handle: "alice" });
      assert.equal(verify.ok, true, JSON.stringify(verify.errors ?? []));
    });
  } finally {
    rmSync(HOME, { recursive: true, force: true });
  }
});
