// E2E test of gamma log persistence + chain integrity.
//
// Scenario:
//   1. Owner creates a collection → 1 gamma entry (data.collection.created)
//   2. Insert 3 records → 3 entries (data.record.created x3)
//   3. Update 1 record → 1 entry (data.record.modified)
//   4. Delete 1 record → 1 entry (data.record.deleted)
//   5. List gamma entries with verify:true → 6 entries, chain ok
//   6. Each entry's prev_hash matches the previous entry's hash
//   7. The first entry's prev_hash is the genesis sentinel
//   8. List with op_prefix filter works

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { randomBytes } from "node:crypto";

import {
  signEnvelope,
  delegateMultibaseFromSeed,
} from "@aithos/protocol-core/envelope";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

const API_URL = process.env.PDS_API_URL;
if (!API_URL) throw new Error("Set PDS_API_URL to a dev PDS endpoint");

function assert(cond, msg) {
  if (!cond) {
    console.error("✗", msg);
    process.exitCode = 1;
  } else {
    console.log("✓", msg);
  }
}

const seed = new Uint8Array(randomBytes(32));
const mb = delegateMultibaseFromSeed(seed);
const did = `did:key:${mb}`;
const vm = `${did}#${mb}`;

async function call(path, method, params) {
  const aud = `${API_URL}${path}`;
  const envelope = signEnvelope({
    iss: did,
    aud,
    method,
    params,
    sphereKey: { seed, verificationMethod: vm },
  });
  const r = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: `req-${Math.random()}`,
      method,
      params: { ...params, _envelope: envelope },
    }),
  });
  return { status: r.status, body: await r.json() };
}

console.log(`Subject: ${did}\n`);

const collectionName = `gamma_e2e_${Date.now()}`;
const collectionUrn = `urn:aithos:collection:${did}:${collectionName}`;

// ─── 1. Create collection ────────────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.create_collection", {
    subject_did: did,
    collection_name: collectionName,
    schema: "aithos.contacts.v1",
    cmk_envelope: {
      alg: "xchacha20poly1305-ietf",
      wraps: [
        {
          recipient: `${did}#data-kex`,
          alg: "x25519-hkdf-sha256-aead",
          ephemeral_public: "z6stub",
          wrap_nonce: "AAA",
          wrapped_key: "BBB",
        },
      ],
    },
  });
  assert(r.status === 200, "create_collection ok");
  assert(r.body.result?.urn === collectionUrn, "  urn matches");
}

// ─── 2. Insert 3 records ─────────────────────────────────────────────────────

const stubPayload = (i) => ({
  alg: "xchacha20poly1305-ietf",
  nonce: "AAA" + i,
  ciphertext: `CT${i}`,
  dek_wrapped_for_cmk: `DEK${i}`,
});

const recordIds = [];
for (let i = 1; i <= 3; i++) {
  const r = await call("/mcp/primitives/write", "aithos.data.insert_record", {
    collection_urn: collectionUrn,
    metadata: { name: `Prospect ${i}`, status: "lead" },
    payload: stubPayload(i),
  });
  assert(r.status === 200 && r.body.result?.record_id, `insert_record #${i} ok`);
  recordIds.push(r.body.result?.record_id);
}

// ─── 3. Update + 4. Delete ───────────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.update_record", {
    collection_urn: collectionUrn,
    record_id: recordIds[0],
    metadata: { name: "Updated Prospect 1", status: "won" },
    payload: stubPayload(99),
  });
  assert(r.status === 200, "update_record ok");
}

{
  const r = await call("/mcp/primitives/write", "aithos.data.delete_record", {
    collection_urn: collectionUrn,
    record_id: recordIds[1],
  });
  assert(r.status === 200, "delete_record ok");
}

// ─── 5. List + verify chain ──────────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/read", "aithos.data.list_gamma_entries", {
    subject_did: did,
    verify: true,
  });
  assert(r.status === 200, "list_gamma_entries ok");
  const items = r.body.result?.items ?? [];
  const verification = r.body.result?.verification ?? {};

  assert(items.length === 6, `expected 6 gamma entries, got ${items.length}`);
  assert(
    items.filter((e) => e.op === "data.collection.created").length === 1,
    "  1× data.collection.created",
  );
  assert(
    items.filter((e) => e.op === "data.record.created").length === 3,
    "  3× data.record.created",
  );
  assert(
    items.filter((e) => e.op === "data.record.modified").length === 1,
    "  1× data.record.modified",
  );
  assert(
    items.filter((e) => e.op === "data.record.deleted").length === 1,
    "  1× data.record.deleted",
  );
  assert(verification.ok === true, `chain verification ok (errors: ${JSON.stringify(verification.errors)})`);
  assert(verification.entryCount === 6, "verification.entryCount == 6");

  // First entry's prev_hash is genesis
  const genesisPrev = "sha256:" + "0".repeat(64);
  assert(items[0].prev_hash === genesisPrev, "first entry's prev_hash is genesis sentinel");

  // Each subsequent entry chains to the previous
  let chainOk = true;
  for (let i = 1; i < items.length; i++) {
    if (items[i].prev_hash !== items[i - 1].hash) {
      chainOk = false;
      console.error(`  chain broken at entry ${i}: prev_hash=${items[i].prev_hash} vs prior.hash=${items[i - 1].hash}`);
    }
  }
  assert(chainOk, "every entry's prev_hash matches previous entry's hash");

  // Each entry has audit metadata
  assert(
    items.every((e) => e.authored_by_envelope_nonce && e.authored_by_pubkey),
    "every entry has authored_by_envelope_nonce + authored_by_pubkey",
  );

  // Each entry's hash is well-formed
  assert(
    items.every((e) => /^sha256:[0-9a-f]{64}$/.test(e.hash)),
    "every entry's hash is well-formed sha256",
  );
}

// ─── 6. Filter by op_prefix ──────────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/read", "aithos.data.list_gamma_entries", {
    subject_did: did,
    op_prefix: "data.record",
  });
  const items = r.body.result?.items ?? [];
  assert(
    items.length === 5 && items.every((e) => e.op.startsWith("data.record")),
    "op_prefix=data.record filter returns only 5 record-level entries",
  );
}

// ─── 7. Owner-only access ────────────────────────────────────────────────────

{
  // Try to list gamma for a different subject — should fail
  const otherSeed = new Uint8Array(randomBytes(32));
  const otherDid = `did:key:${delegateMultibaseFromSeed(otherSeed)}`;
  const aud = `${API_URL}/mcp/primitives/read`;
  const params = { subject_did: otherDid };
  const envelope = signEnvelope({
    iss: did,
    aud,
    method: "aithos.data.list_gamma_entries",
    params,
    sphereKey: { seed, verificationMethod: vm },
  });
  const r = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "leak",
      method: "aithos.data.list_gamma_entries",
      params: { ...params, _envelope: envelope },
    }),
  });
  const j = await r.json();
  assert(
    r.status === 403 && j.error?.code === -32042,
    "list_gamma_entries refuses cross-subject snooping (403)",
  );
}

console.log("\n=== Done ===");
if (process.exitCode === 1) console.error("FAILURE");
else console.log("ALL GREEN");
