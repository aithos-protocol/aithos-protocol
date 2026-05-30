// E2E test of the append-only (deposit) flow.
//
// Requires a DEPLOYED PDS. Run with:
//   PDS_API_URL=https://<api>.execute-api.eu-west-3.amazonaws.com \
//     node --import tsx test-e2e/append-flow.mjs
//
// Scenario (the "deposit without read" pattern behind Délie's magic link):
//   1. Owner (did:key) creates a collection.
//   2. Owner mints an APPEND mandate for depositor D1 — NO authorize_app
//      (an append mandate carries no CMK wrap; the depositor seals each DEK
//      to the owner's pubkey instead).
//   3. D1 inserts a deposit record (payload carries dek_wrapped_for_owner) → 200.
//   4. D1 get_record    → 403 INSUFFICIENT_SCOPE (append grants no read).
//   5. D1 list_records  → 403.
//   6. D1 update_record → 403.
//   7. D1 delete_record → 403.
//   8. Owner reads the deposit → 200, payload.dek_wrapped_for_owner present.
//   9. D2 (its own append mandate) get_record → 403 (isolation: append = no read).
//  10. Owner revokes D1 → 200 (works even without a wrap to strip).
//  11. D1 insert after revoke → 403 MANDATE_REVOKED.
//
// Payloads are opaque stubs: the PDS never inspects them, so this script
// exercises SCOPE ENFORCEMENT. The deposit/owner crypto round-trip itself is
// covered by @aithos/data-crypto unit tests (deposit.test.ts).

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

// Manual mandate construction for did:key issuers (mirrors delegate-flow.mjs).
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
    signature: { alg: "ed25519", key: `${ownerDid}#public`, value: "" },
  };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = ed.sign(bytes, ownerSeed);
  return { ...unsigned, signature: { ...unsigned.signature, value: base64url(sig) } };
}

// A stub deposit payload — opaque to the PDS. The real wire format carries
// dek_wrapped_for_owner instead of dek_wrapped_for_cmk.
function depositPayload(ownerDid, tag) {
  return {
    alg: "xchacha20poly1305-ietf",
    nonce: "AAA",
    ciphertext: `CT_${tag}`,
    dek_wrapped_for_owner: {
      recipient: `${ownerDid}#data-kex`,
      alg: "x25519-hkdf-sha256-aead",
      ephemeral_public: "z6stubEph",
      wrap_nonce: "AAA",
      wrapped_key: `WK_${tag}`,
    },
  };
}

// ─── Setup keys ──────────────────────────────────────────────────────────────

const ownerSeed = new Uint8Array(randomBytes(32));
const ownerMultibase = delegateMultibaseFromSeed(ownerSeed);
const ownerDid = `did:key:${ownerMultibase}`;
const ownerVm = `${ownerDid}#${ownerMultibase}`;

const d1Seed = new Uint8Array(randomBytes(32));
const d1Multibase = delegateMultibaseFromSeed(d1Seed);

const d2Seed = new Uint8Array(randomBytes(32));
const d2Multibase = delegateMultibaseFromSeed(d2Seed);

console.log(`Owner: ${ownerDid}`);
console.log(`Depositor D1: ${d1Multibase}`);
console.log(`Depositor D2: ${d2Multibase}\n`);

const collectionName = `append_e2e_${Date.now()}`;
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

// ─── 2. Owner mints APPEND mandate for D1 (no authorize_app) ─────────────────

const mandateD1 = mintMandateManual({
  ownerSeed,
  ownerDid,
  granteePubkey: d1Multibase,
  granteeLabel: "depositor-1",
  scopes: [`data.${collectionName}.append`],
});
console.log("Append mandate D1 id:", mandateD1.id);

// ─── 3. D1 inserts a deposit (no CMK wrap, no authorize_app) ─────────────────

let recordId;
{
  const params = {
    collection_urn: collectionUrn,
    metadata: { name: "Deposit by D1", status: "lead" },
    payload: depositPayload(ownerDid, "D1"),
  };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.insert_record",
    params,
    delegateKey: { seed: d1Seed, pubkeyMultibase: d1Multibase },
    mandate: mandateD1,
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "ins-d1",
    method: "aithos.data.insert_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 200 && r.body.result?.record_id,
    "D1 (append) inserts a deposit WITHOUT authorize_app",
  );
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
  recordId = r.body.result?.record_id;
}

// ─── 4–7. D1 cannot read / list / update / delete ────────────────────────────

async function expectForbidden(label, path, method, params) {
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}${path}`,
    method,
    params,
    delegateKey: { seed: d1Seed, pubkeyMultibase: d1Multibase },
    mandate: mandateD1,
  });
  const r = await rpcCall(path, {
    jsonrpc: "2.0",
    id: label,
    method,
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 403 && r.body.error?.code === -32042,
    `${label} → 403 INSUFFICIENT_SCOPE`,
  );
  if (!(r.status === 403)) console.error("  body:", JSON.stringify(r.body));
}

if (recordId) {
  await expectForbidden("D1 get_record", "/mcp/primitives/read", "aithos.data.get_record", {
    collection_urn: collectionUrn,
    record_id: recordId,
  });
  await expectForbidden("D1 list_records", "/mcp/primitives/read", "aithos.data.list_records", {
    collection_urn: collectionUrn,
  });
  await expectForbidden("D1 update_record", "/mcp/primitives/write", "aithos.data.update_record", {
    collection_urn: collectionUrn,
    record_id: recordId,
    metadata: { name: "tamper", status: "lead" },
    payload: depositPayload(ownerDid, "tamper"),
  });
  await expectForbidden("D1 delete_record", "/mcp/primitives/write", "aithos.data.delete_record", {
    collection_urn: collectionUrn,
    record_id: recordId,
  });
}

// ─── 8. Owner reads the deposit ──────────────────────────────────────────────

if (recordId) {
  const params = { collection_urn: collectionUrn, record_id: recordId };
  const envelope = signEnvelope({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_record",
    params,
    sphereKey: { seed: ownerSeed, verificationMethod: ownerVm },
  });
  const r = await rpcCall("/mcp/primitives/read", {
    jsonrpc: "2.0",
    id: "get-owner",
    method: "aithos.data.get_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 200 && r.body.result?.payload?.dek_wrapped_for_owner,
    "owner reads the deposit (payload carries dek_wrapped_for_owner)",
  );
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 9. D2 cannot read D1's deposit (isolation — append grants no read) ───────

{
  const mandateD2 = mintMandateManual({
    ownerSeed,
    ownerDid,
    granteePubkey: d2Multibase,
    granteeLabel: "depositor-2",
    scopes: [`data.${collectionName}.append`],
  });
  const params = { collection_urn: collectionUrn, record_id: recordId };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/read`,
    method: "aithos.data.get_record",
    params,
    delegateKey: { seed: d2Seed, pubkeyMultibase: d2Multibase },
    mandate: mandateD2,
  });
  const r = await rpcCall("/mcp/primitives/read", {
    jsonrpc: "2.0",
    id: "get-d2",
    method: "aithos.data.get_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 403 && r.body.error?.code === -32042,
    "D2 (append) cannot read D1's deposit → 403 (isolation)",
  );
}

// ─── 10. Owner revokes D1 (works without a wrap to strip) ─────────────────────

{
  const params = {
    collection_urn: collectionUrn,
    mandate_id: mandateD1.id,
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
    id: "rev-d1",
    method: "aithos.data.revoke_app",
    params: { ...params, _envelope: envelope },
  });
  assert(r.status === 200, "owner revokes D1's append mandate (no wrap needed)");
  if (r.status !== 200) console.error("  body:", JSON.stringify(r.body));
}

// ─── 11. D1 insert after revoke → MANDATE_REVOKED ─────────────────────────────

{
  const params = {
    collection_urn: collectionUrn,
    metadata: { name: "Deposit after revoke", status: "lead" },
    payload: depositPayload(ownerDid, "D1b"),
  };
  const envelope = signEnvelopeWithMandate({
    iss: ownerDid,
    aud: `${API_URL}/mcp/primitives/write`,
    method: "aithos.data.insert_record",
    params,
    delegateKey: { seed: d1Seed, pubkeyMultibase: d1Multibase },
    mandate: mandateD1,
  });
  const r = await rpcCall("/mcp/primitives/write", {
    jsonrpc: "2.0",
    id: "ins-d1-revoked",
    method: "aithos.data.insert_record",
    params: { ...params, _envelope: envelope },
  });
  assert(
    r.status === 403 && r.body.error?.code === -32041,
    "D1 insert after revoke → 403 MANDATE_REVOKED",
  );
  if (!(r.status === 403)) console.error("  body:", JSON.stringify(r.body));
}

console.log("\n=== Done ===");
if (process.exitCode === 1) console.error("FAILURE");
else console.log("ALL GREEN");
