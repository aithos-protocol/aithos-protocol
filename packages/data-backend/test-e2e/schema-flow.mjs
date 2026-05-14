// E2E test of schema validation for aithos.contacts.v1.
//
// Validates that:
//   - Unknown schema in create_collection → -32070 SCHEMA_UNKNOWN
//   - Missing required field (name) → -32072 RECORD_INVALID
//   - Wrong type (tags as string instead of array) → -32072
//   - Wrong enum value (status: "foo") → -32072
//   - Bad email format → -32072
//   - Phone in metadata (it's an encrypted field!) → -32072
//   - Unknown field → -32072
//   - Valid record → 200
//   - Server overwrites client-supplied created_at (auto:on_insert) → 200, value differs

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { randomBytes } from "node:crypto";

import {
  signEnvelope,
  delegateMultibaseFromSeed,
} from "@aithos/protocol-core/envelope";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

const API_URL =
  process.env.PDS_API_URL ?? "https://slpknok0md.execute-api.eu-west-3.amazonaws.com";

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

console.log(`Owner: ${did}\n`);

// ─── 1. create_collection with unknown schema → -32070 ───────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.create_collection", {
    subject_did: did,
    collection_name: `bad_schema_${Date.now()}`,
    schema: "aithos.unknown.v1",
    cmk_envelope: { alg: "xchacha20poly1305-ietf", wraps: [] },
  });
  assert(
    r.status === 400 && r.body.error?.code === -32070,
    "unknown aithos.* schema → -32070 SCHEMA_UNKNOWN",
  );
}

// ─── 2. create a valid collection ────────────────────────────────────────────

const collectionName = `schema_e2e_${Date.now()}`;
const collectionUrn = `urn:aithos:collection:${did}:${collectionName}`;

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
  assert(r.status === 200, "create_collection with aithos.contacts.v1 ok");
}

const stubPayload = {
  alg: "xchacha20poly1305-ietf",
  nonce: "AAA",
  ciphertext: "CT",
  dek_wrapped_for_cmk: "DEK",
};

async function insertWith(metadata) {
  return call("/mcp/primitives/write", "aithos.data.insert_record", {
    collection_urn: collectionUrn,
    metadata,
    payload: stubPayload,
  });
}

// ─── 3. Insert without required `name` → -32072 ──────────────────────────────

{
  const r = await insertWith({ status: "lead" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "missing required field name → -32072 RECORD_INVALID",
  );
}

// ─── 4. Wrong type for tags ──────────────────────────────────────────────────

{
  const r = await insertWith({ name: "Test", tags: "not-an-array" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "wrong type for tags (string vs array) → -32072",
  );
}

// ─── 5. Wrong enum value for status ──────────────────────────────────────────

{
  const r = await insertWith({ name: "Test", status: "foo" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "status: 'foo' not in enum → -32072",
  );
}

// ─── 6. Bad email format ─────────────────────────────────────────────────────

{
  const r = await insertWith({ name: "Test", email: "not-an-email" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "bad email format → -32072",
  );
}

// ─── 7. Phone in metadata (it's encrypted!) ──────────────────────────────────

{
  const r = await insertWith({ name: "Test", phone: "+33612345678" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "encrypted field 'phone' in metadata → -32072",
  );
}

// ─── 8. Unknown field ────────────────────────────────────────────────────────

{
  const r = await insertWith({ name: "Test", unknown_field: "x" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "unknown field 'unknown_field' → -32072",
  );
}

// ─── 9. Bad phone_hash pattern ───────────────────────────────────────────────

{
  const r = await insertWith({ name: "Test", phone_hash: "wrong-format" });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "phone_hash not matching blake3:<hex> → -32072",
  );
}

// ─── 10. Valid full record ───────────────────────────────────────────────────

{
  const r = await insertWith({
    name: "Jean Dupont",
    email: "jean@example.com",
    phone_hash: `blake3:${"a".repeat(64)}`,
    status: "lead",
    tags: ["priority", "fr", "saastr-2026"],
    source: "linkedin",
    last_contacted_at: "2026-05-14T10:00:00Z",
  });
  assert(r.status === 200 && r.body.result?.record_id, "valid record → 200");
}

// ─── 11. Client-supplied created_at is silently overridden (auto:on_insert) ──

{
  const fakeDate = "1999-01-01T00:00:00Z";
  const r = await insertWith({
    name: "Override test",
    created_at: fakeDate, // schema says aithos:auto on_insert
  });
  assert(r.status === 200, "client-supplied created_at ignored (silentOverride default)");
  if (r.status === 200) {
    const rid = r.body.result.record_id;
    const got = await call("/mcp/primitives/read", "aithos.data.get_record", {
      collection_urn: collectionUrn,
      record_id: rid,
    });
    const actualCreatedAt = got.body.result?.metadata?.created_at;
    assert(
      actualCreatedAt && actualCreatedAt !== fakeDate,
      `created_at was server-set (got ${actualCreatedAt}, not ${fakeDate})`,
    );
  }
}

// ─── 12. Default value applied (status defaults to "lead") ───────────────────

{
  const r = await insertWith({ name: "Default test" });
  if (r.status === 200) {
    const rid = r.body.result.record_id;
    const got = await call("/mcp/primitives/read", "aithos.data.get_record", {
      collection_urn: collectionUrn,
      record_id: rid,
    });
    assert(
      got.body.result?.metadata?.status === "lead",
      "status defaults to 'lead' when omitted",
    );
  }
}

console.log("\n=== Done ===");
if (process.exitCode === 1) console.error("FAILURE");
else console.log("ALL GREEN");
