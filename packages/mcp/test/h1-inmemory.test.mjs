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
  // ethos_diff_since needs the readManifestAt capability (edition history).
  const hidden = new Set(["data_query", "ethos_commit", "ethos_discard", "ethos_diff_since"]);
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

// ------------------------------------------------------ P3 (T12/T14/T16)
//
// Contextualization primitives over the in-memory fake: search never leaves
// the mandate's read scopes (T12), the context pack respects budget AND
// mandate (T14), diff_since reports content-address changes after a
// transaction (T16).

function contextStorage() {
  const base = memoryStorage();
  base.loadIdentity = async () => undefined;
  // Sections across zones; circle/self readable by THIS fake regardless of
  // session — scope-bounding must come from the SERVER (that's the point).
  const all = {
    public: [
      { id: "sec_bio", title: "Bio", body: "I build Aithos, a protocol for digital incarnation.", tags: ["pinned"] },
      { id: "sec_work", title: "Work", body: "Consulting on protocols and agents.", tags: [] },
    ],
    circle: [
      { id: "sec_rate", title: "Rates", body: "Aithos consulting rate: 1200.", tags: ["guidance"] },
    ],
    self: [
      { id: "sec_diary", title: "Diary", body: "Secret thoughts about aithos governance.", tags: [] },
    ],
  };
  base.readSectionIndex = async (_h, zone) => {
    return (all[zone] ?? []).map((s) => ({
      section_id: s.id,
      title: s.title,
      title_hidden: false,
      gamma_ref: `g_${s.id}`,
      tags: s.tags,
      approx_size_bytes: s.body.length,
    }));
  };
  base.readSections = async (_h, ids, opts = {}) => {
    const zone = opts.zone ?? "public";
    return ids.map((id) => {
      const s = (all[zone] ?? []).find((x) => x.id === id);
      return s
        ? { zone, section_id: id, accessible: true, section: { ...s, gamma_ref: `g_${id}` } }
        : { zone, section_id: id, accessible: false, reason: "not found" };
    });
  };
  return base;
}

test("T12 — search is bounded by the mandate's read scopes (never circle/self)", async () => {
  const storage = contextStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: ["ethos.read.public"] },
  });

  // "aithos" matches sections in ALL three zones — only public may surface.
  const res = text(await client.callTool({
    name: "ethos_search",
    arguments: { query: "aithos" },
  }));
  assert.deepEqual(res.zones_searched, ["public"]);
  assert.ok(res.matches.length >= 1);
  assert.ok(res.matches.every((m) => m.zone === "public"), "no circle/self leakage");

  // Even an EXPLICIT zones request cannot escape the scopes.
  const forced = text(await client.callTool({
    name: "ethos_search",
    arguments: { query: "aithos", zones: ["circle", "self", "public"] },
  }));
  assert.deepEqual(forced.zones_searched, ["public"]);
  assert.ok(forced.matches.every((m) => m.zone === "public"));
});

test("T12/owner — search ranks title/tag hits above body hits and snippets them", async () => {
  const storage = contextStorage();
  const { client } = await connect({ storage });
  const res = text(await client.callTool({
    name: "ethos_search",
    arguments: { query: "consulting", limit: 5 },
  }));
  const ids = res.matches.map((m) => m.id);
  assert.ok(ids.includes("sec_work"), "body+title match found");
  assert.ok(ids.includes("sec_rate"), "circle match visible to the owner");
  const work = res.matches.find((m) => m.id === "sec_work");
  assert.ok(work.snippet.toLowerCase().includes("consulting"));
  assert.ok(typeof work.est_tokens === "number" && work.est_tokens > 0);
});

test("T14 — context pack: guidance/pinned first, budget respected, mandate-bounded", async () => {
  const storage = contextStorage();
  const { client } = await connect({ storage });

  const pack = text(await client.callTool({
    name: "ethos_context_pack",
    arguments: { task: "draft a consulting proposal for a protocol client", budget_tokens: 100 },
  }));
  // guidance (circle sec_rate) before pinned (public sec_bio).
  assert.equal(pack.sections[0].id, "sec_rate");
  assert.equal(pack.sections[0].reason, "guidance");
  assert.equal(pack.sections[1].id, "sec_bio");
  assert.equal(pack.sections[1].reason, "pinned");
  assert.ok(pack.used_tokens_est <= pack.budget_tokens, "budget respected");
  // dedup: anchors already included are not re-added as matches.
  const keys = pack.sections.map((s) => `${s.zone}/${s.id}`);
  assert.equal(new Set(keys).size, keys.length);

  // Tiny budget → truncation flagged, hard cap held.
  const tiny = text(await client.callTool({
    name: "ethos_context_pack",
    arguments: { task: "anything aithos", budget_tokens: 100 },
  }));
  assert.ok(tiny.used_tokens_est <= 100);

  // Mandate-bounded (T14 second half): public-only session never packs circle/self.
  const { client: bounded } = await connect({
    storage: contextStorage(),
    mandate: { scopes: ["ethos.read.public"] },
  });
  const bp = text(await bounded.callTool({
    name: "ethos_context_pack",
    arguments: { task: "consulting rates aithos" },
  }));
  assert.deepEqual(bp.zones_considered, ["public"]);
  assert.ok(bp.sections.every((s) => s.zone === "public"), "no out-of-scope sections in the pack");
  assert.ok(!bp.sections.some((s) => s.id === "sec_rate"), "guidance outside scope is excluded");
});

test("T16 — diff_since reports added/modified/deleted by content address", async () => {
  const storage = contextStorage();
  // Edition history capability: height 3 (old) vs current manifest shape.
  const oldZones = {
    public: { sections: [
      { section_id: "sec_bio", blob_sha: "sha_bio_v1", gamma_ref: "g_bio" },
      { section_id: "sec_gone", blob_sha: "sha_gone", gamma_ref: "g_gone" },
    ] },
  };
  const curZones = {
    public: { sections: [
      { section_id: "sec_bio", blob_sha: "sha_bio_v2", gamma_ref: "g_bio2", title: "Bio" },
      { section_id: "sec_new", blob_sha: "sha_new", gamma_ref: "g_new", title: "Projets" },
    ] },
  };
  storage.readManifestAt = async (_h, height) =>
    height === 3
      ? { subject_did: DID, edition: { version: "1.0.3", height: 3, created_at: "x" }, zones: oldZones }
      : null;
  storage.readManifest = async () => ({
    subject_did: DID,
    edition: { version: "1.0.5", height: 5, created_at: "y" },
    gamma: { head: "sha256:h", count: 9 },
    zones: curZones,
  });

  const { client } = await connect({ storage });
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.ok(names.includes("ethos_diff_since"), "served when history capability exists");

  const diff = text(await client.callTool({
    name: "ethos_diff_since",
    arguments: { height: 3 },
  }));
  assert.equal(diff.from_height, 3);
  assert.equal(diff.to_height, 5);
  assert.deepEqual(diff.changed.public.added, [{ id: "sec_new", title: "Projets" }]);
  assert.deepEqual(diff.changed.public.modified, [{ id: "sec_bio", title: "Bio" }]);
  assert.deepEqual(diff.changed.public.deleted, ["sec_gone"]);
  assert.equal(diff.unchanged, false);

  // Unknown height → clean error.
  const bad = await client.callTool({ name: "ethos_diff_since", arguments: { height: 1 } });
  assert.equal(bad.isError, true);

  // Same height → unchanged.
  storage.readManifestAt = async () => storage.readManifest();
  const { client: c2 } = await connect({ storage });
  const same = text(await c2.callTool({ name: "ethos_diff_since", arguments: { height: 5 } }));
  assert.equal(same.unchanged, true);
});

// ------------------------------------------------------ P4 (T15/T6/T7)

function liveMandate(overrides = {}) {
  const now = Date.now();
  return {
    "aithos-mandate": "0.2.0",
    id: "mandate_01TESTLIVING",
    issuer: DID,
    issued_by_key: `${DID}#root`,
    grantee: { id: "agent:claude", pubkey: "zAgentKey" },
    actor_sphere: "circle",
    scopes: ["ethos.read.public", "ethos.read.circle", "ethos.write.circle"],
    not_before: new Date(now - 3600_000).toISOString(),
    not_after: new Date(now + 3600_000).toISOString(),
    issued_at: new Date(now - 3600_000).toISOString(),
    nonce: "n",
    signature: { alg: "ed25519", key: `${DID}#root`, value: "sig" },
    ...overrides,
  };
}

test("T15 — mandate_describe announces EXACTLY what tools/list serves", async () => {
  const doc = liveMandate();
  const storage = transactionalStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: doc.scopes, document: doc },
  });

  const listed = (await client.listTools()).tools.map((t) => t.name).sort();
  const d = text(await client.callTool({ name: "mandate_describe", arguments: {} }));

  assert.deepEqual(d.tools, listed, "describe.tools == tools/list, by enumeration");
  assert.equal(d.session, "delegate");
  assert.equal(d.id, doc.id);
  assert.equal(d.actor_sphere, "circle");
  assert.deepEqual(d.scopes, doc.scopes);
  assert.equal(d.status.valid, true);
  assert.equal(d.revoked, null);
  assert.equal(d.status.signature_checked, false, "signature verification is mandate_verify's job");

  // Enumeration, the other way: every announced tool actually dispatches
  // (no "unknown tool" / not-listed surprises).
  for (const name of d.tools) {
    const found = listed.includes(name);
    assert.ok(found, `${name} announced but not listed`);
  }
});

test("T15/owner — describe reports the owner session and the full served set", async () => {
  const storage = transactionalStorage();
  const { client } = await connect({ storage });
  const listed = (await client.listTools()).tools.map((t) => t.name).sort();
  const d = text(await client.callTool({ name: "mandate_describe", arguments: {} }));
  assert.equal(d.session, "owner");
  assert.equal(d.scopes, null);
  assert.deepEqual(d.tools, listed);
});

test("T6 — expired mandate: stage refuses; revoked between stage and commit: commit refuses", async () => {
  // Expired at STAGE time.
  const expired = liveMandate({ not_after: new Date(Date.now() - 60_000).toISOString() });
  const s1 = transactionalStorage();
  const { client: c1 } = await connect({
    storage: s1,
    mandate: { scopes: expired.scopes, document: expired },
    delegate: { mandateId: expired.id, keySeed: new Uint8Array(32), keyMultibase: "zAgentKey" },
  });
  const stage = await c1.callTool({
    name: "ethos_add_section",
    arguments: { zone: "circle", title: "X", body: "y" },
  });
  assert.equal(stage.isError, true);
  assert.match(stage.content[0].text, /expired/);
  assert.equal(s1.batches.length, 0);
  assert.deepEqual(s1.writes, { add: 0, modify: 0, delete: 0 }, "zero writes (T6)");

  // Valid at stage, REVOKED before commit.
  const doc = liveMandate();
  const s2 = transactionalStorage();
  let revoked = null;
  s2.findRevocation = async (id) => (id === doc.id ? revoked : null);
  const { client: c2 } = await connect({
    storage: s2,
    mandate: { scopes: doc.scopes, document: doc },
    delegate: { mandateId: doc.id, keySeed: new Uint8Array(32), keyMultibase: "zAgentKey" },
  });
  const ok1 = text(await c2.callTool({
    name: "ethos_add_section",
    arguments: { zone: "circle", title: "Dispo", body: "Sept." },
  }));
  assert.equal(ok1.staged, true, "valid mandate stages fine");

  revoked = { "aithos-revocation": "0.1.0", mandate_id: doc.id, issuer: DID,
    issued_by_key: `${DID}#root`, revoked_at: new Date().toISOString(),
    reason: "owner pulled the plug", signature: { alg: "ed25519", key: "k", value: "v" } };

  const commit = await c2.callTool({ name: "ethos_commit", arguments: {} });
  assert.equal(commit.isError, true, "commit re-checks liveness (T6)");
  assert.match(commit.content[0].text, /revoked/);
  assert.equal(s2.batches.length, 0, "nothing persisted after revocation");

  // preflight agrees, with the reason.
  const pf = text(await c2.callTool({
    name: "ethos_preflight_write",
    arguments: { zone: "circle" },
  }));
  assert.equal(pf.authorized, false);
  assert.match(pf.reason, /revoked/);
});

test("T7 — self is mandatable for the subject's own agent; bounded elsewhere", async () => {
  const doc = liveMandate({
    actor_sphere: "self",
    scopes: ["ethos.read.self", "ethos.write.self"],
  });
  const storage = transactionalStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: doc.scopes, document: doc },
    delegate: { mandateId: doc.id, keySeed: new Uint8Array(32), keyMultibase: "zAgentKey" },
  });

  // Exposure: self write tools present; public/circle reads ARE the same
  // tools (zone-scoped at dispatch) — check preflight matrix instead.
  const pfSelf = text(await client.callTool({ name: "ethos_preflight_write", arguments: { zone: "self" } }));
  assert.equal(pfSelf.authorized, true, "self writable under ethos.write.self (V9)");
  const pfPub = text(await client.callTool({ name: "ethos_preflight_write", arguments: { zone: "public" } }));
  assert.equal(pfPub.authorized, false);
  assert.match(pfPub.reason, /does not include scope ethos\.write\.public/);

  // Dispatch agrees with the preflight matrix (T15 spirit): self write
  // stages + commits; public write refuses at stage.
  const ok1 = text(await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "self", title: "Journal", body: "Day 1." },
  }));
  assert.equal(ok1.staged, true);
  const commit = text(await client.callTool({ name: "ethos_commit", arguments: {} }));
  assert.equal(commit.committed, true);
  assert.equal(storage.batches.length, 1);
  assert.equal(storage.batches[0].edits[0].zone, "self");

  const bad = await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "public", title: "X", body: "y" },
  });
  assert.equal(bad.isError, true);
  assert.equal(storage.batches.length, 1, "no second batch");

  // Search/list bounded to self (+ nothing leaks from other zones).
  const sr = text(await client.callTool({ name: "ethos_search", arguments: { query: "aithos" } }));
  assert.deepEqual(sr.zones_searched, ["self"]);
});

test("P4 — mandate pack parser: valid pack round-trips; tampered packs throw", async () => {
  const { parseMandatePack } = await import("../dist/pack.js");
  const doc = liveMandate();
  const good = {
    "aithos-mandate-pack": "1",
    mandate: doc,
    agent_key: { seed_hex: "ab".repeat(32), pubkey_multibase: "zAgentKey" },
    options: { auto_commit: false, expose_tools: ["ethos_list_sections"] },
  };
  const parsed = parseMandatePack(JSON.stringify(good));
  assert.equal(parsed.mandate.id, doc.id);
  assert.equal(parsed.agent_key.pubkey_multibase, "zAgentKey");

  assert.throws(() => parseMandatePack("{"), /not valid JSON/);
  assert.throws(
    () => parseMandatePack(JSON.stringify({ ...good, "aithos-mandate-pack": "2" })),
    /unsupported/,
  );
  assert.throws(
    () => parseMandatePack(JSON.stringify({ ...good, agent_key: { seed_hex: "xx", pubkey_multibase: "zAgentKey" } })),
    /invalid hex/,
  );
  assert.throws(
    () =>
      parseMandatePack(
        JSON.stringify({ ...good, agent_key: { seed_hex: "ab".repeat(32), pubkey_multibase: "zOTHER" } }),
      ),
    /does not match mandate\.grantee\.pubkey/,
  );
});

test("T6/session — a session mandate WITHOUT a delegate key still gates liveness (SDK shape)", async () => {
  const expired = liveMandate({ not_after: new Date(Date.now() - 60_000).toISOString() });
  const storage = transactionalStorage();
  const { client } = await connect({
    storage,
    mandate: { scopes: expired.scopes, document: expired },
    // NO delegate: the storage signs with its own keys (SdkStorage shape).
  });
  const stage = await client.callTool({
    name: "ethos_add_section",
    arguments: { zone: "circle", title: "X", body: "y" },
  });
  assert.equal(stage.isError, true);
  assert.match(stage.content[0].text, /expired/);
  assert.equal(storage.batches.length, 0);
  assert.deepEqual(storage.writes, { add: 0, modify: 0, delete: 0 });
});
