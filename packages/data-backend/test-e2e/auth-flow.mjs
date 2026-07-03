// E2E test of the authenticated PDS flow.
//
// Generates a did:key locally, signs envelopes, hits the deployed API,
// validates: happy path, missing envelope, bad signature, replayed nonce.
//
// Run with: node test-e2e/auth-flow.mjs

import {
  signEnvelope,
  delegateMultibaseFromSeed,
} from "@aithos/protocol-core/envelope";
import { randomBytes } from "node:crypto";

const API_URL = process.env.PDS_API_URL;
if (!API_URL) throw new Error("Set PDS_API_URL to a dev PDS endpoint");

// ─── 1. Generate a did:key locally ───────────────────────────────────────────
const seed = new Uint8Array(randomBytes(32));
const pubkeyMultibase = delegateMultibaseFromSeed(seed);
const did = `did:key:${pubkeyMultibase}`;
const verificationMethod = `${did}#${pubkeyMultibase}`;

console.log(`Owner DID: ${did}`);
console.log(`Verification method: ${verificationMethod}\n`);

// ─── helpers ─────────────────────────────────────────────────────────────────

async function rpcCall(path, method, businessParams, opts = {}) {
  const aud = `${API_URL}${path}`;
  const envelope = opts.envelope ?? signEnvelope({
    iss: did,
    aud,
    method,
    params: businessParams,
    sphereKey: { seed, verificationMethod },
    ttlSeconds: 60,
  });

  const body = {
    jsonrpc: "2.0",
    id: opts.id ?? `req-${Math.random()}`,
    method,
    params: { ...businessParams, _envelope: envelope },
  };
  // For "no envelope" tests, opts.skipEnvelope strips it
  if (opts.skipEnvelope) {
    body.params = businessParams;
  }
  // For "bad signature" tests, opts.tamperSignature flips a byte
  if (opts.tamperSignature) {
    const v = envelope.proof.proofValue;
    const flipped = v.slice(0, -2) + (v.slice(-2) === "AA" ? "BB" : "AA");
    body.params._envelope.proof.proofValue = flipped;
  }

  const r = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await r.json();
  return { status: r.status, body: json };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("✗", msg);
    process.exitCode = 1;
  } else {
    console.log("✓", msg);
  }
}

// ─── 2. Happy path: create collection, insert, list, get, update, delete ────

const collectionName = `e2e_${Date.now()}`;
const collectionUrn = `urn:aithos:collection:${did}:${collectionName}`;

console.log("=== Happy path ===");

let r;

r = await rpcCall("/mcp/primitives/write", "aithos.data.create_collection", {
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
assert(r.status === 200 && r.body.result, "create_collection ok");

r = await rpcCall("/mcp/primitives/write", "aithos.data.insert_record", {
  collection_urn: collectionUrn,
  metadata: { name: "Test prospect", status: "lead" },
  payload: {
    alg: "xchacha20poly1305-ietf",
    nonce: "AAA",
    ciphertext: "TEST_CT",
    dek_wrapped_for_cmk: "TEST_DEK",
  },
});
assert(r.status === 200 && r.body.result?.record_id, "insert_record ok");
const recordId = r.body.result.record_id;

r = await rpcCall("/mcp/primitives/read", "aithos.data.list_records", {
  collection_urn: collectionUrn,
  limit: 10,
});
assert(
  r.status === 200 && r.body.result?.items?.length === 1,
  "list_records returns 1 item",
);

r = await rpcCall("/mcp/primitives/read", "aithos.data.get_record", {
  collection_urn: collectionUrn,
  record_id: recordId,
});
assert(
  r.status === 200 && r.body.result?.metadata?.name === "Test prospect",
  "get_record returns the record",
);

r = await rpcCall("/mcp/primitives/write", "aithos.data.update_record", {
  collection_urn: collectionUrn,
  record_id: recordId,
  metadata: { name: "Test prospect (updated)", status: "won" },
  payload: {
    alg: "xchacha20poly1305-ietf",
    nonce: "BBB",
    ciphertext: "TEST_CT2",
    dek_wrapped_for_cmk: "TEST_DEK2",
  },
});
assert(r.status === 200 && r.body.result?.modified_at, "update_record ok");

r = await rpcCall("/mcp/primitives/read", "aithos.data.get_record", {
  collection_urn: collectionUrn,
  record_id: recordId,
});
assert(
  r.body.result?.metadata?.status === "won",
  "update_record persisted (status: won)",
);

r = await rpcCall("/mcp/primitives/write", "aithos.data.delete_record", {
  collection_urn: collectionUrn,
  record_id: recordId,
});
assert(r.status === 200 && r.body.result?.deleted_at, "delete_record ok");

r = await rpcCall("/mcp/primitives/read", "aithos.data.get_record", {
  collection_urn: collectionUrn,
  record_id: recordId,
});
assert(
  r.status === 404 && r.body.error?.code === -32020,
  "deleted record returns AITHOS_NOT_FOUND",
);

// ─── 3. Negative auth tests ──────────────────────────────────────────────────

console.log("\n=== Negative auth tests ===");

// 3a. No envelope at all
r = await rpcCall(
  "/mcp/primitives/write",
  "aithos.data.create_collection",
  { subject_did: did, collection_name: "x", schema: "y", cmk_envelope: {} },
  { skipEnvelope: true },
);
assert(
  r.status === 401 && r.body.error?.code === -32010,
  "no envelope → 401 AITHOS_BAD_ENVELOPE",
);

// 3b. Tampered signature
r = await rpcCall(
  "/mcp/primitives/write",
  "aithos.data.create_collection",
  { subject_did: did, collection_name: "x", schema: "y", cmk_envelope: {} },
  { tamperSignature: true },
);
assert(
  r.status === 401 && r.body.error?.code === -32011,
  "tampered signature → 401 AITHOS_BAD_SIGNATURE",
);

// 3c. Mismatched method (envelope says read.collection but RPC says write)
{
  const aud = `${API_URL}/mcp/primitives/read`;
  const businessParams = { subject_did: did, collection_name: collectionName };
  const envelope = signEnvelope({
    iss: did,
    aud,
    method: "aithos.data.get_collection",
    params: businessParams,
    sphereKey: { seed, verificationMethod },
    ttlSeconds: 60,
  });
  // Send to a different method name
  const body = {
    jsonrpc: "2.0",
    id: "method-mismatch",
    method: "aithos.data.list_records",
    params: { ...businessParams, _envelope: envelope },
  };
  const rr = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await rr.json();
  assert(
    rr.status === 401 && j.error?.code === -32010,
    "method mismatch → 401 AITHOS_BAD_ENVELOPE",
  );
}

// 3d. Replayed nonce
{
  const params = {
    subject_did: did,
    collection_name: collectionName,
  };
  const envelope = signEnvelope({
    iss: did,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_collection",
    params,
    sphereKey: { seed, verificationMethod },
    ttlSeconds: 60,
  });
  // First call: should succeed
  const r1 = await rpcCall(
    "/mcp/primitives/read",
    "aithos.data.get_collection",
    params,
    { envelope, id: "replay-1" },
  );
  assert(r1.status === 200, "first call with envelope ok");
  // Second call with the SAME envelope (same nonce)
  const r2 = await rpcCall(
    "/mcp/primitives/read",
    "aithos.data.get_collection",
    params,
    { envelope, id: "replay-2" },
  );
  assert(
    r2.status === 401 && r2.body.error?.code === -32012,
    "replayed nonce → 401 AITHOS_REPLAY_DETECTED",
  );
}

// 3e. Wrong subject_did (caller signed as A but tries to act on subject B)
{
  const otherSeed = new Uint8Array(randomBytes(32));
  const otherDid = `did:key:${delegateMultibaseFromSeed(otherSeed)}`;

  const aud = `${API_URL}/mcp/primitives/read`;
  const businessParams = { subject_did: otherDid, collection_name: collectionName };
  const envelope = signEnvelope({
    iss: did, // signed as `did`
    aud,
    method: "aithos.data.get_collection",
    params: businessParams,
    sphereKey: { seed, verificationMethod },
    ttlSeconds: 60,
  });
  const body = {
    jsonrpc: "2.0",
    id: "subj-mismatch",
    method: "aithos.data.get_collection",
    params: { ...businessParams, _envelope: envelope },
  };
  const rr = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await rr.json();
  assert(
    rr.status === 403 && j.error?.code === -32042,
    "envelope.iss != subject_did → 403 AITHOS_INSUFFICIENT_SCOPE",
  );
}

console.log("\n=== Done ===");
if (process.exitCode === 1) {
  console.error("FAILURE");
} else {
  console.log("ALL GREEN");
}
