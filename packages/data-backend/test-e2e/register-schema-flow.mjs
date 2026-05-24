// E2E test of A2b vendor schema self-registration.
//
// Validates that:
//   - register_schema with a core (aithos.<bareword>) id → -32071 INVALID
//   - register_schema with malformed id (uppercase, missing v) → -32071
//   - register_schema with bad semver → -32071
//   - register_schema with a structurally bad doc → -32071
//   - register_schema with a doc > 10 KB → -32071
//   - register_schema with a valid vendor doc → 200, created:true
//   - Re-register the same doc (canonical hash match) → 200, created:false
//   - Re-register the same id with a DIFFERENT doc → -32082 IMMUTABLE
//   - get_schema(vendor id, subject_did) → returns the registered doc
//   - get_schema(vendor id, no subject_did) → -32602 invalid params
//   - get_schema(core id) → returns the bundled core schema, source:"core"
//   - insert_record on a collection whose vendor schema is now registered
//     REJECTS an unknown field (server-side enforcement is live)
//
// Run against a live PDS deployment :
//   PDS_API_URL=https://<...>.execute-api.eu-west-3.amazonaws.com \
//   node test-e2e/register-schema-flow.mjs

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

const vendorId = `aithos.x.e2e_${Date.now().toString(36)}.post.v1`;

function validVendorDoc() {
  return {
    "aithos:schema": vendorId,
    "aithos:version": "1.0.0",
    title: "E2E vendor schema",
    type: "object",
    additionalProperties: false,
    required: ["title"],
    properties: {
      title: {
        type: "string",
        minLength: 1,
        maxLength: 280,
        "aithos:indexable": true,
      },
      body: {
        type: "string",
        "aithos:encrypted": true,
      },
      created_at: {
        type: "string",
        format: "date-time",
        "aithos:indexable": true,
        "aithos:auto": "on_insert",
      },
    },
  };
}

// ─── 1. Core namespace → rejected ────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: { ...validVendorDoc(), "aithos:schema": "aithos.contacts.v2" },
  });
  assert(
    r.status === 400 && r.body.error?.code === -32071,
    "core aithos.<bareword>.v* rejected → -32071 SCHEMA_INVALID",
  );
}

// ─── 2. Malformed identifier (uppercase) ──────────────────────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: { ...validVendorDoc(), "aithos:schema": "aithos.x.AcMe.post.v1" },
  });
  assert(
    r.status === 400 && r.body.error?.code === -32071,
    "uppercase in vendor id rejected → -32071",
  );
}

// ─── 3. Bad semver ────────────────────────────────────────────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: { ...validVendorDoc(), "aithos:version": "latest" },
  });
  assert(
    r.status === 400 && r.body.error?.code === -32071,
    "non-semver aithos:version rejected → -32071",
  );
}

// ─── 4. Structurally invalid (field both indexable and encrypted) ────────────

{
  const doc = validVendorDoc();
  doc.properties.title["aithos:encrypted"] = true;
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: doc,
  });
  assert(
    r.status === 400 && r.body.error?.code === -32071,
    "indexable+encrypted on same field rejected → -32071",
  );
}

// ─── 5. Oversize doc (> 10 KB) ────────────────────────────────────────────────

{
  const doc = validVendorDoc();
  // Stuff a big description to push past 10 KB
  doc.description = "x".repeat(11_000);
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: doc,
  });
  assert(
    r.status === 400 && r.body.error?.code === -32071,
    "schema doc > 10 KB rejected → -32071",
  );
}

// ─── 6. Valid registration ────────────────────────────────────────────────────

let createdDocHash = null;
{
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: validVendorDoc(),
  });
  assert(
    r.status === 200 &&
      r.body.result?.schema_id === vendorId &&
      r.body.result?.created === true &&
      /^sha256:[0-9a-f]{64}$/.test(r.body.result?.doc_hash ?? ""),
    "valid vendor schema → 200, created:true, doc_hash returned",
  );
  createdDocHash = r.body.result?.doc_hash;
}

// ─── 7. Idempotent re-registration (same canonical doc) ──────────────────────

{
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: validVendorDoc(),
  });
  assert(
    r.status === 200 &&
      r.body.result?.created === false &&
      r.body.result?.doc_hash === createdDocHash,
    "re-register same doc → 200, created:false, identical doc_hash",
  );
}

// ─── 8. Immutability (same id, different doc) → -32082 ───────────────────────

{
  const doc = validVendorDoc();
  doc.properties.extra = { type: "string", "aithos:indexable": true };
  const r = await call("/mcp/primitives/write", "aithos.data.register_schema", {
    subject_did: did,
    schema_doc: doc,
  });
  assert(
    r.status === 400 && r.body.error?.code === -32082,
    "same id + different doc rejected → -32082 SCHEMA_IMMUTABLE",
  );
}

// ─── 9. get_schema(vendor, subject_did) returns the registered doc ────────────

{
  const r = await call("/mcp/primitives/read", "aithos.data.get_schema", {
    subject_did: did,
    schema: vendorId,
  });
  assert(
    r.status === 200 &&
      r.body.result?.source === "owner" &&
      r.body.result?.schema?.["aithos:schema"] === vendorId,
    "get_schema(vendor, owner) returns the registered doc",
  );
}

// ─── 10. get_schema(core) returns the bundled core schema ────────────────────

{
  const r = await call("/mcp/primitives/read", "aithos.data.get_schema", {
    schema: "aithos.contacts.v1",
    subject_did: did, // sent for envelope iss alignment; ignored by core lookup
  });
  assert(
    r.status === 200 &&
      r.body.result?.source === "core" &&
      r.body.result?.schema?.["aithos:schema"] === "aithos.contacts.v1",
    "get_schema(core) returns the bundled core schema with source:core",
  );
}

// ─── 11. get_schema(unknown vendor, subject_did) → -32070 ────────────────────

{
  const r = await call("/mcp/primitives/read", "aithos.data.get_schema", {
    subject_did: did,
    schema: "aithos.x.never.registered.v1",
  });
  assert(
    r.status === 400 && r.body.error?.code === -32070,
    "get_schema(unknown vendor) → -32070 SCHEMA_UNKNOWN",
  );
}

// ─── 12. Server-side enforcement is live for the registered schema ──────────

const collectionName = `vendor_e2e_${Date.now()}`;
const collectionUrn = `urn:aithos:collection:${did}:${collectionName}`;

{
  const r = await call("/mcp/primitives/write", "aithos.data.create_collection", {
    subject_did: did,
    collection_name: collectionName,
    schema: vendorId,
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
  assert(r.status === 200, "create_collection bound to registered vendor schema → 200");
}

const stubPayload = {
  alg: "xchacha20poly1305-ietf",
  nonce: "AAA",
  ciphertext: "CT",
  dek_wrapped_for_cmk: "DEK",
};

// Unknown field — server should now reject because the schema is registered.
{
  const r = await call("/mcp/primitives/write", "aithos.data.insert_record", {
    collection_urn: collectionUrn,
    metadata: { title: "ok", unknown_field: "boom" },
    payload: stubPayload,
  });
  assert(
    r.status === 400 && r.body.error?.code === -32072,
    "insert with unknown field is rejected (server-side enforcement is live) → -32072",
  );
}

// Valid record — should pass.
{
  const r = await call("/mcp/primitives/write", "aithos.data.insert_record", {
    collection_urn: collectionUrn,
    metadata: { title: "hello world" },
    payload: stubPayload,
  });
  assert(r.status === 200 && r.body.result?.record_id, "valid record on registered schema → 200");
}
