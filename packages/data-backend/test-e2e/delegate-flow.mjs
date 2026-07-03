// E2E test of the delegate flow.
//
// Scenario:
//   1. Owner (did:key) creates a collection.
//   2. Owner mints a WRITE mandate for app A (did:key).
//   3. Owner calls authorize_app — adds wrap + records mandate in collection.
//   4. App A inserts a record (mandate-signed envelope) → 200.
//   5. App A updates the record → 200.
//   6. App A reads the record → 200.
//   7. Owner mints a READ-only mandate for app B and authorize_app.
//   8. App B's insert attempt → 403 INSUFFICIENT_SCOPE.
//   9. App B's read → 200.
//  10. Owner revokes app A.
//  11. App A's read post-revoke → 403 MANDATE_REVOKED.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { randomBytes } from "node:crypto";
import { ulid } from "ulid";

import {
  signEnvelope,
  signEnvelopeWithMandate,
  delegateMultibaseFromSeed,
} from "@aithos/protocol-core/envelope";
import { canonicalize } from "@aithos/protocol-core/canonical";

// noble/ed25519 v2: wire sha512 into etc.sha512Sync so sign() works synchronously
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

async function rpcCall(path, body) {
  const r = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

// Manual mandate construction for did:key issuers (the high-level
// createMandate helper in protocol-core assumes Aithos identities with
// distinct sphere keys — which a did:key doesn't have).
function mintMandateManual({
  ownerSeed,
  ownerDid,
  granteePubkey,
  granteeLabel,
  scopes,
  ttlSeconds = 3600,
}) {
  const now = new Date();
  const notAfter = new Date(now.getTime() + ttlSeconds * 1000);
  const unsigned = {
    "aithos-mandate": "0.3.0",
    id: `mandate_${ulid()}`,
    issuer: ownerDid,
    issued_by_key: `${ownerDid}#public`,
    grantee: {
      id: `urn:aithos:app:${granteeLabel}@e2e`,
      label: granteeLabel,
      pubkey: granteePubkey,
    },
    actor_sphere: "public",
    scopes,
    not_before: now.toISOString(),
    not_after: notAfter.toISOString(),
    issued_at: now.toISOString(),
    nonce: base64url(randomBytes(9)),
    signature: {
      alg: "ed25519",
      key: `${ownerDid}#public`,
      value: "",
    },
  };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = ed.sign(bytes, ownerSeed);
  return { ...unsigned, signature: { ...unsigned.signature, value: base64url(sig) } };
}

// ─── Setup keys ──────────────────────────────────────────────────────────────

const ownerSeed = new Uint8Array(randomBytes(32));
const ownerMultibase = delegateMultibaseFromSeed(ownerSeed);
const ownerDid = `did:key:${ownerMultibase}`;
const ownerVm = `${ownerDid}#${ownerMultibase}`;

const appASeed = new Uint8Array(randomBytes(32));
const appAMultibase = delegateMultibaseFromSeed(appASeed);

const appBSeed = new Uint8Array(randomBytes(32));
const appBMultibase = delegateMultibaseFromSeed(appBSeed);

console.log(`Owner: ${ownerDid}`);
console.log(`App A pubkey: ${appAMultibase}`);
console.log(`App B pubkey: ${appBMultibase}\n`);

const collectionName = `delegate_e2e_${Date.now()}`;
const collectionUrn = `urn:aithos:collection:${ownerDid}:${collectionName}`;

// ─── 1. Owner creates collection ─────────────────────────────────────────────

{
  const params = {
    subject_did: ownerDid,
    collection_name: collectionName,
    schema: "aithos.contacts.v1",
    cmk_envelope: {
      alg: "xchacha20poly1305-ietf",
      wraps: [
        {
          recipient: `${ownerDid}#data-kex`,
          alg: "x25519-hkdf-sha256-aead",
          ephemeral_public: "z6stub",
          wrap_nonce: "AAA",
          wrapped_key: "BBB",
        },
      ],
    },
  };
  const envelope = signEnvelope({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.create_collection",
    params,
    sphereKey: { seed: ownerSeed, verificationMethod: ownerVm },
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "create",
    method: "aithos.data.create_collection",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "owner creates collection");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 2. Owner mints WRITE mandate for app A ──────────────────────────────────

const mandateWrite = mintMandateManual({
  ownerSeed,
  ownerDid,
  granteePubkey: appAMultibase,
  granteeLabel: "app-A",
  scopes: [`data.${collectionName}.write`],
});
console.log("Mandate A id:", mandateWrite.id);

// ─── 3. Owner authorizes app A ───────────────────────────────────────────────

{
  const params = {
    collection_urn: collectionUrn,
    mandate: mandateWrite,
    wrap: {
      recipient: `did:key:${appAMultibase}#${appAMultibase}-kex`,
      alg: "x25519-hkdf-sha256-aead",
      ephemeral_public: "z6stubA",
      wrap_nonce: "AAA",
      wrapped_key: "BBBA",
    },
  };
  const envelope = signEnvelope({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.authorize_app",
    params,
    sphereKey: { seed: ownerSeed, verificationMethod: ownerVm },
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "auth-a",
    method: "aithos.data.authorize_app",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "owner authorizes app A (write scope)");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 4. App A inserts record (mandate-signed) ────────────────────────────────

let recordId;
{
  const params = {
    collection_urn: collectionUrn,
    metadata: { name: "Prospect from app A", status: "lead" },
    payload: {
      alg: "xchacha20poly1305-ietf",
      nonce: "AAA",
      ciphertext: "CT_BY_A",
      dek_wrapped_for_cmk: "DEK_BY_A",
    },
  };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.insert_record",
    params,
    delegateKey: { seed: appASeed, pubkeyMultibase: appAMultibase },
    mandate: mandateWrite,
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "ins-a",
    method: "aithos.data.insert_record",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200 && r.body.result?.record_id, "app A inserts a record (delegate)");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
  recordId = r.body.result?.record_id;
}

// ─── 5. App A updates ────────────────────────────────────────────────────────

if (recordId) {
  const params = {
    collection_urn: collectionUrn,
    record_id: recordId,
    metadata: { name: "Updated by app A", status: "contact" },
    payload: {
      alg: "xchacha20poly1305-ietf",
      nonce: "BBB",
      ciphertext: "CT_v2",
      dek_wrapped_for_cmk: "DEK_v2",
    },
  };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.update_record",
    params,
    delegateKey: { seed: appASeed, pubkeyMultibase: appAMultibase },
    mandate: mandateWrite,
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "upd-a",
    method: "aithos.data.update_record",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "app A updates the record (delegate)");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 6. App A reads ──────────────────────────────────────────────────────────

if (recordId) {
  const params = { collection_urn: collectionUrn, record_id: recordId };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_record",
    params,
    delegateKey: { seed: appASeed, pubkeyMultibase: appAMultibase },
    mandate: mandateWrite,
  });
  const r = await rpcCall("/mcp/primitives/read", {
    jsonrpc: "2.0",
    id: "get-a",
    method: "aithos.data.get_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 200 && r.body.result?.metadata?.status === "contact",
    "app A reads the record (write scope implies read)",
  );
}

// ─── 7. Owner authorizes app B (read-only) ───────────────────────────────────

const mandateRead = mintMandateManual({
  ownerSeed,
  ownerDid,
  granteePubkey: appBMultibase,
  granteeLabel: "app-B",
  scopes: [`data.${collectionName}.read`],
});

{
  const params = {
    collection_urn: collectionUrn,
    mandate: mandateRead,
    wrap: {
      recipient: `did:key:${appBMultibase}#${appBMultibase}-kex`,
      alg: "x25519-hkdf-sha256-aead",
      ephemeral_public: "z6stubB",
      wrap_nonce: "AAB",
      wrapped_key: "BBBB",
    },
  };
  const envelope = signEnvelope({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.authorize_app",
    params,
    sphereKey: { seed: ownerSeed, verificationMethod: ownerVm },
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "auth-b",
    method: "aithos.data.authorize_app",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "owner authorizes app B (read-only)");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 8. App B tries to insert (insufficient scope) ───────────────────────────

{
  const params = {
    collection_urn: collectionUrn,
    metadata: { name: "Spy attempt", status: "lead" },
    payload: {
      alg: "xchacha20poly1305-ietf",
      nonce: "ZZZ",
      ciphertext: "EVIL",
      dek_wrapped_for_cmk: "EVIL",
    },
  };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.insert_record",
    params,
    delegateKey: { seed: appBSeed, pubkeyMultibase: appBMultibase },
    mandate: mandateRead,
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "ins-b",
    method: "aithos.data.insert_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 403 && r.body.error?.code === -32042,
    "app B (read-only) insert → 403 INSUFFICIENT_SCOPE",
  );
}

// ─── 9. App B reads ──────────────────────────────────────────────────────────

if (recordId) {
  const params = { collection_urn: collectionUrn, record_id: recordId };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_record",
    params,
    delegateKey: { seed: appBSeed, pubkeyMultibase: appBMultibase },
    mandate: mandateRead,
  });
  const r = await rpcCall("/mcp/primitives/read", {
    jsonrpc: "2.0",
    id: "get-b",
    method: "aithos.data.get_record",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "app B (read-only) reads the record");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 10. Owner revokes app A ─────────────────────────────────────────────────

{
  const params = {
    collection_urn: collectionUrn,
    mandate_id: mandateWrite.id,
    revocation: { revoked_at: new Date().toISOString(), reason: "test" },
  };
  const envelope = signEnvelope({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.revoke_app",
    params,
    sphereKey: { seed: ownerSeed, verificationMethod: ownerVm },
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "rev-a",
    method: "aithos.data.revoke_app",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "owner revokes app A");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 11. App A read after revoke ─────────────────────────────────────────────

if (recordId) {
  const params = { collection_urn: collectionUrn, record_id: recordId };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_record",
    params,
    delegateKey: { seed: appASeed, pubkeyMultibase: appAMultibase },
    mandate: mandateWrite,
  });
  const r = await rpcCall("/mcp/primitives/read", {
    jsonrpc: "2.0",
    id: "get-a-revoked",
    method: "aithos.data.get_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 403 && r.body.error?.code === -32041,
    "app A read after revoke → 403 MANDATE_REVOKED",
  );
}

console.log("\n=== Done ===");
if (process.exitCode === 1) console.error("FAILURE");
else console.log("ALL GREEN");
