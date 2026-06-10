// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * H1 harness — the isomorphic server core over an InMemoryTransport linked
 * pair, against a pure in-memory AithosStorage fake. No filesystem, no
 * child process, no crypto: the suite locks the *contract*:
 *
 *   T10 — parity: every listed tool is structurally identical to its
 *         @aithos/agent-tools canonical spec (name, description, schema).
 *   T4  — mandate exposure: tools/list is filtered by the mandate scopes;
 *         legacy names are never listed.
 *   T5  — defense in depth: a forced call to a hidden write tool fails
 *         without writing; an exposed write tool still refuses an
 *         out-of-scope zone at dispatch time without writing.
 *   Aliases — pre-0.9 `aithos_*` names resolve at tools/call (with arg
 *         renames) but can be disabled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer } from "../dist/server.js";
import { AGENT_TOOL_CATALOG, getToolSpec } from "@aithos/agent-tools";

// ---------------------------------------------------------------- fixtures

const DID = "did:aithos:z6MkFakeAliceAliceAliceAliceAlice";

function makeSection(id, title, body) {
  return { id, title, body, gamma_ref: `gamma_${id}`, tags: ["t"] };
}

/** Pure in-memory AithosStorage fake (public zone only; counts writes). */
function memoryStorage() {
  const sections = new Map([
    ["sec_bio", makeSection("sec_bio", "Bio", "I build Aithos.")],
    ["sec_work", makeSection("sec_work", "Work", "Consulting + protocol.")],
  ]);
  const writes = { add: 0, modify: 0, delete: 0 };
  const mandates = new Map();

  const manifest = () => ({
    subject_did: DID,
    edition: { version: "1.0.0", height: 3, created_at: "2026-06-10T00:00:00Z" },
    gamma: { head: "sha256:deadbeef", count: 7 },
  });

  return {
    writes,
    mandates,
    // identity domain
    listHandles: async () => ["alice"],
    loadIdentityMetadata: async (h) => {
      if (h !== "alice") throw new Error(`unknown handle ${h}`);
      return {
        handle: "alice",
        displayName: "Alice",
        did: DID,
        tracked: false,
        sphereDids: { public: `${DID}#public` },
        sphereKeys: { public: "zPubKeyFake" },
        didDocument: { id: DID },
      };
    },
    loadIdentity: async () => {
      // No secret material in the fake — reads degrade gracefully, and
      // delegated writes proceed identity-less (remote-storage shape).
      throw new Error("no local identity in memory fake");
    },
    loadDidDocument: async () => ({ id: DID }),
    isTrackedIdentity: async () => false,
    // ethos reads
    readManifest: async () => manifest(),
    readZoneDoc: async () => {
      throw new Error("not supported by fake");
    },
    readZoneBytes: async () => new TextEncoder().encode("# public\n"),
    readSectionIndex: async (_h, zone) => {
      if (zone !== "public") throw new Error(`no key for ${zone}`);
      return [...sections.values()].map((s) => ({
        section_id: s.id,
        title: s.title,
        title_hidden: false,
        gamma_ref: s.gamma_ref,
        tags: s.tags,
      }));
    },
    readSections: async (_h, ids, opts = {}) => {
      const zone = opts.zone ?? "public";
      return ids.map((id) => {
        const s = zone === "public" ? sections.get(id) : undefined;
        return s
          ? { zone, section_id: id, accessible: true, section: s }
          : { zone, section_id: id, accessible: false, reason: "not found" };
      });
    },
    // ethos writes (counted; minimal result shapes)
    addSection: async (args) => {
      writes.add++;
      const s = makeSection("sec_new", args.title, args.body);
      sections.set(s.id, s);
      return { section: s, manifest: manifest(), gammaEntry: { id: "g_new" } };
    },
    modifySection: async (args) => {
      writes.modify++;
      const s = sections.get(args.sectionId);
      return { section: s, manifest: manifest(), gammaEntry: { id: "g_mod" } };
    },
    deleteSection: async (args) => {
      writes.delete++;
      sections.delete(args.sectionId);
      return {
        sectionId: args.sectionId,
        deletedTitle: "x",
        manifest: manifest(),
        gammaEntry: { id: "g_del" },
      };
    },
    verifyEthos: async () => ({ ok: true, errors: [] }),
    // mandates
    loadMandate: async (id) => {
      const m = mandates.get(id);
      if (!m) throw new Error(`unknown mandate ${id}`);
      return m;
    },
    findRevocation: async () => null,
    defaultHandle: async () => "alice",
  };
}

async function connect(opts) {
  const server = createServer(opts);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "h1", version: "0.0.0" }, { capabilities: {} });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return { client, server };
}

const text = (res) => JSON.parse(res.content[0].text);

// ---------------------------------------------------------------- T10

test("T10 — every listed tool matches its canonical @aithos/agent-tools spec", async () => {
  const storage = memoryStorage();
  const { client } = await connect({ storage });
  const listed = (await client.listTools()).tools;

  // The server registers a subset of the catalogue (data_query has no
  // backend here yet) — and never anything outside it.
  const catalogNames = new Set(AGENT_TOOL_CATALOG.map((t) => t.name));
  for (const t of listed) {
    assert.ok(catalogNames.has(t.name), `${t.name} not in canonical catalogue`);
    const spec = getToolSpec(t.name);
    assert.equal(t.description, spec.description, `${t.name}: description drift`);
    const gotProps = Object.keys(t.inputSchema?.properties ?? {}).sort();
    const wantProps = Object.keys(spec.input_schema.properties ?? {}).sort();
    assert.deepEqual(gotProps, wantProps, `${t.name}: schema property drift`);
    const gotReq = [...(t.inputSchema?.required ?? [])].sort();
    const wantReq = [...(spec.input_schema.required ?? [])].sort();
    assert.deepEqual(gotReq, wantReq, `${t.name}: required drift`);
  }

  // Owner session over a storage WITHOUT applyEdits: auto-commit fallback —
  // the transactional trio is not served (commit/discard have nothing to
  // operate on); data_query still has no backend here.
  const names = listed.map((t) => t.name).sort();
  const hidden = new Set(["data_query", "ethos_commit", "ethos_discard"]);
  assert.deepEqual(
    names,
    [...catalogNames].filter((n) => !hidden.has(n)).sort(),
  );
});

// ---------------------------------------------------------------- T4

test("T4 — tools/list is filtered by the mandate scopes; no legacy names", async () => {
  const storage = memoryStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: ["ethos.read.public"] },
  });
  const names = (await client.listTools()).tools.map((t) => t.name);

  for (const expected of [
    "identity_list",
    "identity_describe",
    "ethos_list_sections",
    "ethos_read_section",
    "ethos_read_sections",
    "ethos_verify",
    "mandate_verify",
  ]) {
    assert.ok(names.includes(expected), `missing ${expected}`);
  }
  for (const hidden of [
    "ethos_add_section",
    "ethos_update_section",
    "ethos_append_section",
    "ethos_delete_section",
    "ethos_commit",
    "ethos_discard",
    "data_query",
  ]) {
    assert.ok(!names.includes(hidden), `${hidden} must be hidden`);
  }
  assert.ok(names.every((n) => !n.startsWith("aithos_")), "no legacy names listed");

  // The exposed read path actually works.
  const idx = text(
    await client.callTool({
      name: "ethos_list_sections",
      arguments: { zone: "public" },
    }),
  );
  assert.deepEqual(idx.sections.map((s) => s.id).sort(), ["sec_bio", "sec_work"]);
});

// ---------------------------------------------------------------- T5

test("T5a — calling a hidden write tool fails and never writes", async () => {
  const storage = memoryStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: ["ethos.read.public"] },
  });
  // The SDK surfaces the protocol error as an isError result (1.29 behavior).
  const res = await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "X", body: "Y" },
  });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /not found/i);
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });
});

test("T5b — exposed write tool still refuses an out-of-scope zone at dispatch", async () => {
  const storage = memoryStorage();
  storage.mandates.set("mandate_pub", {
    id: "mandate_pub",
    issuer: DID,
    scopes: ["ethos.write.public"],
    grantee: { pubkey: "zDelegateKey" },
  });
  const io = {
    // fake keyfile matching the mandate's grantee pubkey
    readTextFile: async () =>
      JSON.stringify({ seed_hex: "ab".repeat(32), pubkey_multibase: "zDelegateKey" }),
  };
  const { client } = await connect({
    storage,
    io,
    mandate: { scopes: ["ethos.read.public", "ethos.write.public"] },
  });

  // (1) zone NOT covered by the write mandate → is_error result, zero writes.
  const refused = await client.callTool({
    name: "ethos_add_section",
    arguments: {
      zone: "circle",
      title: "X",
      body: "Y",
      mandate: "mandate_pub",
      agent_key: "/keys/delegate.json",
    },
  });
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /does not include scope ethos\.write\.circle/);
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });

  // (2) covered zone → the delegated write proceeds (identity-less fake).
  const okRes = await client.callTool({
    name: "ethos_add_section",
    arguments: {
      zone: "public",
      title: "From agent",
      body: "Written under mandate.",
      mandate: "mandate_pub",
      agent_key: "/keys/delegate.json",
    },
  });
  assert.ok(!okRes.isError);
  assert.equal(storage.writes.add, 1);
});

// ---------------------------------------------------------------- aliases

test("aliases — legacy aithos_* names resolve at tools/call with arg renames", async () => {
  const storage = memoryStorage();
  const { client } = await connect({ storage });
  const res = text(
    await client.callTool({
      name: "aithos_ethos_show_section",
      arguments: { zone: "public", sectionId: "sec_bio" },
    }),
  );
  assert.equal(res.id, "sec_bio");
  assert.equal(res.body, "I build Aithos.");
});

test("aliases — disabled with legacyAliases:false", async () => {
  const storage = memoryStorage();
  const { client } = await connect({ storage, legacyAliases: false });
  const res = await client.callTool({
    name: "aithos_ethos_show_section",
    arguments: { zone: "public", sectionId: "sec_bio" },
  });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /not found/i);
});

// ---------------------------------------------------------------- guards

test("createServer requires an explicit storage (isomorphic core)", () => {
  assert.throws(() => createServer({}), /storage is required/);
});

// ------------------------------------------------------- T13/T13b (H1-tx)
//
// Transactional staging over an in-memory storage WITH the applyEdits
// capability: zero storage writes until commit, ONE applyEdits batch per
// commit, discard drops everything, append composes over staged adds.

function transactionalStorage() {
  const base = memoryStorage();
  // Self-signing host contract (the SdkStorage shape): the backend signs with
  // its own session keys; loadIdentity resolves undefined instead of throwing.
  base.loadIdentity = async () => undefined;
  const batches = [];
  let height = 3;
  base.applyEdits = async (handle, edits, _auth) => {
    batches.push({ handle, edits });
    height += 1;
    const results = edits.map((e) => {
      if (e.op === "delete") {
        return { op: "delete", zone: e.zone, sectionId: e.sectionId };
      }
      return {
        op: e.op,
        zone: e.zone,
        section: {
          id: e.sectionId ?? "sec_minted",
          title: e.title ?? "(kept)",
          gamma_ref: `g_batch_${height}`,
          tags: e.tags ?? [],
        },
      };
    });
    return {
      manifest: {
        subject_did: DID,
        edition: { version: `1.0.${height}`, height, created_at: "2026-06-10T00:00:00Z" },
        gamma: { head: "sha256:batched", count: 7 + batches.length },
      },
      results,
    };
  };
  return { ...base, batches };
}

test("T13 — three staged writes commit as ONE applyEdits batch; zero writes before", async () => {
  const storage = transactionalStorage();
  const { client } = await connect({ storage });

  // The trio is served on a transactional host.
  const names = (await client.listTools()).tools.map((t) => t.name);
  for (const t of ["ethos_commit", "ethos_discard", "ethos_append_section"]) {
    assert.ok(names.includes(t), `${t} listed`);
  }

  const s1 = text(await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "Projets", body: "PACKD." },
  }));
  assert.equal(s1.staged, true);
  assert.equal(s1.pending, 1);
  const s2 = text(await client.callTool({
    name: "ethos_update_section",
    arguments: { zone: "public", section_id: "sec_bio", body: "I build Aithos, full-time." },
  }));
  assert.equal(s2.pending, 2);
  const s3 = text(await client.callTool({
    name: "ethos_delete_section",
    arguments: { zone: "public", section_id: "sec_work" },
  }));
  assert.equal(s3.pending, 3);

  // ZERO storage writes while staging (T13b guarantee half).
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });
  assert.equal(storage.batches.length, 0);

  const c = text(await client.callTool({ name: "ethos_commit", arguments: { message: "batch" } }));
  assert.equal(c.committed, true);
  assert.equal(c.edits, 3);
  assert.equal(c.message, "batch");
  assert.equal(c.manifest_height, 4);

  // ONE batch, in staging order, legacy per-write paths never touched.
  assert.equal(storage.batches.length, 1);
  assert.deepEqual(storage.batches[0].edits.map((e) => e.op), ["add", "modify", "delete"]);
  assert.equal(storage.batches[0].handle, "alice");
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });

  // Committed: a second commit with nothing staged refuses.
  const again = await client.callTool({ name: "ethos_commit", arguments: {} });
  assert.equal(again.isError, true);
});

test("T13b — discard drops the staged batch: zero writes, zero batches", async () => {
  const storage = transactionalStorage();
  const { client } = await connect({ storage });

  await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "Tmp", body: "x" },
  });
  await client.callTool({
    name: "ethos_delete_section",
    arguments: { zone: "public", section_id: "sec_bio" },
  });
  const d = text(await client.callTool({ name: "ethos_discard", arguments: {} }));
  assert.equal(d.discarded, 2);

  assert.equal(storage.batches.length, 0, "no applyEdits call");
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });

  // Discard with nothing staged is a polite no-op.
  const d2 = text(await client.callTool({ name: "ethos_discard", arguments: {} }));
  assert.equal(d2.discarded, 0);
});

test("H1-tx — append composes over a staged add; fail-fast on unknown targets", async () => {
  const storage = transactionalStorage();
  const { client } = await connect({ storage });

  const add = text(await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "Journal", body: "Day 1." },
  }));
  const id = add.section_id;

  const ap = text(await client.callTool({
    name: "ethos_append_section",
    arguments: { zone: "public", section_id: id, content: "Day 2." },
  }));
  assert.equal(ap.staged, true);
  assert.equal(ap.op, "append");

  // Appending to a section that exists NOWHERE fails fast, stages nothing.
  const bad = await client.callTool({
    name: "ethos_append_section",
    arguments: { zone: "public", section_id: "sec_ghost", content: "x" },
  });
  assert.equal(bad.isError, true);

  const c = text(await client.callTool({ name: "ethos_commit", arguments: {} }));
  assert.equal(c.edits, 2);
  const [e1, e2] = storage.batches[0].edits;
  assert.equal(e1.op, "add");
  assert.equal(e2.op, "modify");
  assert.equal(e2.sectionId, id);
  assert.equal(e2.body, "Day 1.\nDay 2.", "append composed over the staged body");

  // Modify of a persisted section also fail-fasts when unknown.
  const badMod = await client.callTool({
    name: "ethos_update_section",
    arguments: { zone: "public", section_id: "sec_nope", body: "x" },
  });
  assert.equal(badMod.isError, true);
  assert.equal(storage.batches.length, 1, "nothing extra staged or flushed");
});

test("H1-tx — autoCommit: true forces the pre-0.10 behaviour on a capable storage", async () => {
  const storage = transactionalStorage();
  const { client } = await connect({ storage, autoCommit: true });

  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.ok(!names.includes("ethos_commit"), "commit hidden under autoCommit");
  assert.ok(!names.includes("ethos_discard"), "discard hidden under autoCommit");

  const add = text(await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "Now", body: "persist me" },
  }));
  assert.equal(add.staged, undefined);
  assert.equal(storage.writes.add, 1, "immediate per-write persistence");
  assert.equal(storage.batches.length, 0);
});
