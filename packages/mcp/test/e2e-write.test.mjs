// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * H2 — end-to-end TRANSACTIONAL lifecycle through the BUILT MCP server over a
 * real stdio transport, against a v0.3 (per-section) keystore:
 *
 *   stage (add ×2, append, LEGACY-alias modify) → reads see persisted state
 *   only → ethos_commit = ONE edition (T13) → stage delete → ethos_discard =
 *   zero writes (T13b) → delete + commit → verify. Plus the `--auto-commit`
 *   fallback: pre-0.10 per-write behaviour, commit/discard not listed.
 *
 * Exercises the actual server process (dist/bin.js), the MCP client SDK
 * handshake, the v0.3 batch write path (`applyEdits` → one manifest re-sign),
 * the canonical D1 names, and the pre-0.9 `aithos_*` alias bridge staging
 * through the SAME transaction. The keystore is seeded with protocol-core
 * directly; the server child inherits the same throwaway $AITHOS_HOME.
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

const storage = new core.FilesystemStorage();
const height = async () =>
  (await storage.readManifest("alice")).edition.height;

function payload(res) {
  return JSON.parse(res.content[0].text);
}

async function withClient(fn, extraArgs = []) {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/bin.js", "--transport", "stdio", ...extraArgs],
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

test("H2 — MCP v0.3 transactional lifecycle over stdio (stage/commit/discard)", async () => {
  await withClient(async (client) => {
    const call = (name, args) =>
      client.callTool({ name, arguments: args }).then(payload);

    // --- tools/list: canonical names + the transactional trio -------------
    const tools = (await client.listTools()).tools.map((t) => t.name);
    for (const t of [
      "ethos_commit",
      "ethos_discard",
      "ethos_append_section",
      "ethos_delete_section",
      "ethos_read_sections",
    ]) {
      assert.ok(tools.includes(t), `${t} registered`);
    }
    assert.ok(
      tools.every((t) => !t.startsWith("aithos_")),
      `legacy aithos_* names must not be listed (got: ${tools.join(", ")})`,
    );

    const h0 = await height();

    // --- stage two adds (canonical names) ---------------------------------
    const a = await call("ethos_add_section", {
      handle: "alice", zone: "self", title: "Routine", body: "Up at six.", tags: ["am"],
    });
    assert.equal(a.staged, true);
    assert.equal(a.pending, 1);
    const idA = a.section_id;
    assert.ok(idA.startsWith("sec_"), "host-minted id at stage time");

    const b = await call("ethos_add_section", {
      handle: "alice", zone: "self", title: "Goals", body: "Ship v0.3.",
    });
    assert.equal(b.pending, 2);
    const idB = b.section_id;

    // --- staged ≠ persisted: reads and the manifest see NOTHING yet -------
    assert.equal(await height(), h0, "no edition while staging (T13b guarantee)");
    const peek = await call("ethos_read_sections", {
      handle: "alice", section_ids: [idA, idB],
    });
    assert.ok(peek.sections.every((s) => s.accessible === false),
      "reads reflect persisted state only");

    // --- append composes onto the STAGED add ------------------------------
    const ap = await call("ethos_append_section", {
      handle: "alice", zone: "self", section_id: idA, content: "Coffee first.",
    });
    assert.equal(ap.staged, true);
    assert.equal(ap.op, "append");
    assert.equal(ap.pending, 3);

    // --- LEGACY alias stages through the SAME transaction ------------------
    // (pre-0.9 clients keep working: aithos_ethos_modify_section →
    // ethos_update_section, sectionId → section_id; removal in 1.0.)
    const mod = await call("aithos_ethos_modify_section", {
      handle: "alice", zone: "self", sectionId: idB, body: "Ship v0.3 NOW.",
    });
    assert.equal(mod.staged, true);
    assert.equal(mod.pending, 4);

    // --- T13: ONE commit = ONE edition for the four staged writes ---------
    const commit = await call("ethos_commit", { message: "morning batch" });
    assert.equal(commit.committed, true);
    assert.equal(commit.edits, 4);
    assert.equal(commit.message, "morning batch");
    assert.equal(commit.manifest_height, h0 + 1, "exactly one height bump");
    assert.equal(await height(), h0 + 1);

    // Committed state: append composed, alias modify applied.
    const read = await call("ethos_read_sections", {
      handle: "alice", section_ids: [idA, idB],
    });
    const bodies = Object.fromEntries(read.sections.map((s) => [s.id, s.body]));
    assert.equal(bodies[idA], "Up at six.\nCoffee first.");
    assert.equal(bodies[idB], "Ship v0.3 NOW.");

    // --- T13b: stage a delete, then DISCARD — zero writes ------------------
    const del = await call("ethos_delete_section", {
      handle: "alice", zone: "self", section_id: idA,
    });
    assert.equal(del.staged, true);
    const disc = await call("ethos_discard", {});
    assert.equal(disc.discarded, 1);
    assert.equal(await height(), h0 + 1, "discard wrote nothing");
    const still = await call("ethos_read_section", {
      handle: "alice", zone: "self", section_id: idA,
    });
    assert.equal(still.body, "Up at six.\nCoffee first.", "section survived the discard");

    // --- empty commit refuses ---------------------------------------------
    const empty = await client.callTool({ name: "ethos_commit", arguments: {} });
    assert.equal(empty.isError, true, "commit with nothing staged is an error");

    // --- real delete: stage + commit ---------------------------------------
    await call("ethos_delete_section", { handle: "alice", zone: "self", section_id: idA });
    const commit2 = await call("ethos_commit", {});
    assert.equal(commit2.edits, 1);
    assert.equal(await height(), h0 + 2);
    const list = await call("ethos_list_sections", { handle: "alice", zone: "self" });
    assert.deepEqual(list.sections.map((s) => s.title), ["Goals"]);

    // --- the ethos still verifies after the transactional round-trip ------
    const verify = await call("ethos_verify", { handle: "alice" });
    assert.equal(verify.ok, true, JSON.stringify(verify.errors ?? []));
  });
});

test("H2 — --auto-commit fallback: per-write editions, no commit/discard tools", async () => {
  try {
    await withClient(async (client) => {
      const call = (name, args) =>
        client.callTool({ name, arguments: args }).then(payload);

      const tools = (await client.listTools()).tools.map((t) => t.name);
      assert.ok(!tools.includes("ethos_commit"), "commit not served in auto-commit mode");
      assert.ok(!tools.includes("ethos_discard"), "discard not served in auto-commit mode");
      assert.ok(tools.includes("ethos_append_section"), "append works in both modes");

      const h0 = await height();
      const add = await call("ethos_add_section", {
        handle: "alice", zone: "public", title: "Bio", body: "I build Aithos.",
      });
      assert.equal(add.staged, undefined, "pre-0.10 immediate ack shape");
      assert.equal(add.manifest_height, h0 + 1, "one edition per write");

      const ap = await call("ethos_append_section", {
        handle: "alice", zone: "public", section_id: add.section.id, content: "Brussels.",
      });
      assert.equal(ap.appended_chars, "Brussels.".length);
      assert.equal(ap.manifest_height, h0 + 2);
      const read = await call("ethos_read_section", {
        handle: "alice", zone: "public", section_id: add.section.id,
      });
      assert.equal(read.body, "I build Aithos.\nBrussels.");
    }, ["--auto-commit"]);
  } finally {
    rmSync(HOME, { recursive: true, force: true });
  }
});
