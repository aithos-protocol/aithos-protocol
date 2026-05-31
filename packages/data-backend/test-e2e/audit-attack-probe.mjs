// Red-team test: try to access Alice's collection knowing ONLY her DID.
// We use the live PDS dev to attempt real attacks.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { randomBytes } from "node:crypto";

import {
  signEnvelope,
  delegateMultibaseFromSeed,
} from "@aithos/protocol-core/envelope";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

const API_URL = "https://slpknok0md.execute-api.eu-west-3.amazonaws.com";

// ─── Setup: Alice has a real collection ──────────────────────────────────────

const aliceSeed = new Uint8Array(randomBytes(32));
const aliceMb = delegateMultibaseFromSeed(aliceSeed);
const aliceDid = `did:key:${aliceMb}`;
const aliceVm = `${aliceDid}#${aliceMb}`;

console.log(`Alice DID (known publicly): ${aliceDid}`);

async function callAs(seed, mb, did, vm, path, method, params) {
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

// Alice creates a collection
const colName = `audit_${Date.now()}`;
const colUrn = `urn:aithos:collection:${aliceDid}:${colName}`;
{
  const r = await callAs(aliceSeed, aliceMb, aliceDid, aliceVm,
    "/mcp/primitives/write", "aithos.data.create_collection", {
      subject_did: aliceDid,
      collection_name: colName,
      schema: "aithos.contacts.v1",
      cmk_envelope: {
        alg: "xchacha20poly1305-ietf",
        wraps: [{
          recipient: `${aliceDid}#data-kex`,
          alg: "x25519-hkdf-sha256-aead",
          ephemeral_public: "z6stub", wrap_nonce: "AAA", wrapped_key: "BBB",
        }],
      },
    });
  console.log(`[setup] Alice create_collection: ${r.status === 200 ? "✓" : "✗ " + JSON.stringify(r.body)}`);
}

// ─── Attacker: knows Alice's DID, has THEIR OWN unrelated keypair ───────────

const evilSeed = new Uint8Array(randomBytes(32));
const evilMb = delegateMultibaseFromSeed(evilSeed);
const evilDid = `did:key:${evilMb}`;
const evilVm = `${evilDid}#${evilMb}`;

console.log(`\nEve's own DID: ${evilDid}`);
console.log(`Eve will now try to read/write Alice's collection knowing only Alice's DID...\n`);

// ATTACK 1: sign envelope claiming iss=Alice but with Eve's key
{
  const aud = `${API_URL}/mcp/primitives/read`;
  // Forge an envelope: iss=Alice but signed with Eve's key.
  // signEnvelope binds the signature to the verificationMethod, and
  // verifyEnvelope resolves vm against iss's DID doc. So signature MUST
  // match a key in Alice's DID doc. Eve doesn't have Alice's key, so the
  // signature won't verify.
  const envelope = signEnvelope({
    iss: aliceDid,                    // forged
    aud,
    method: "aithos.data.get_collection",
    params: { subject_did: aliceDid, collection_name: colName },
    sphereKey: { seed: evilSeed, verificationMethod: aliceVm }, // sign with Eve's key but claim Alice's vm
  });
  const r = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "attack-1",
      method: "aithos.data.get_collection",
      params: { subject_did: aliceDid, collection_name: colName, _envelope: envelope },
    }),
  });
  const body = await r.json();
  console.log(`ATTACK 1 (forge iss=Alice, sign with Eve's key):`);
  console.log(`  → status=${r.status}, code=${body.error?.code} (${body.error?.message?.slice(0, 60)})`);
  console.log(`  → ${body.error?.code === -32011 ? "✓ BLOCKED (signature mismatch)" : "✗ COMPROMISED!"}`);
}

// ATTACK 2: sign properly as Eve but claim subject_did=Alice
{
  const r = await callAs(evilSeed, evilMb, evilDid, evilVm,
    "/mcp/primitives/read", "aithos.data.get_collection", {
      subject_did: aliceDid,        // try to read Alice's collection
      collection_name: colName,
    });
  console.log(`\nATTACK 2 (sign as Eve, request subject_did=Alice):`);
  console.log(`  → status=${r.status}, code=${r.body.error?.code} (${r.body.error?.message?.slice(0, 80)})`);
  console.log(`  → ${r.body.error?.code === -32042 ? "✓ BLOCKED (requireSubjectMatch)" : "✗ COMPROMISED!"}`);
}

// ATTACK 3: sign as Eve, target Eve's own DID — does Eve see ANY of Alice's collections?
{
  const r = await callAs(evilSeed, evilMb, evilDid, evilVm,
    "/mcp/primitives/read", "aithos.data.list_collections", {
      subject_did: evilDid,         // Eve's own subject — but is there cross-talk?
    });
  console.log(`\nATTACK 3 (list Eve's own collections — should NOT see Alice's):`);
  const items = r.body.result?.items ?? [];
  console.log(`  → status=${r.status}, ${items.length} collection(s)`);
  const seesAlice = items.some(c => c.urn?.includes(aliceDid) || c.name === colName);
  console.log(`  → ${!seesAlice ? "✓ ISOLATED (no cross-tenant leak)" : "✗ LEAK: " + JSON.stringify(items)}`);
}

// ATTACK 4: list_records with collection_urn pointing to Alice's collection
{
  const r = await callAs(evilSeed, evilMb, evilDid, evilVm,
    "/mcp/primitives/read", "aithos.data.list_records", {
      collection_urn: colUrn,       // Alice's collection URN
    });
  console.log(`\nATTACK 4 (list_records with Alice's collection_urn):`);
  console.log(`  → status=${r.status}, code=${r.body.error?.code} (${r.body.error?.message?.slice(0, 80)})`);
  console.log(`  → ${r.body.error?.code === -32042 ? "✓ BLOCKED (requireSubjectMatch on parsed URN)" : "✗ COMPROMISED!"}`);
}

// ATTACK 5: try insert_record into Alice's collection
{
  const r = await callAs(evilSeed, evilMb, evilDid, evilVm,
    "/mcp/primitives/write", "aithos.data.insert_record", {
      collection_urn: colUrn,
      metadata: { name: "MALICIOUS" },
      payload: { alg: "x", nonce: "x", ciphertext: "x", dek_wrapped_for_cmk: "x" },
    });
  console.log(`\nATTACK 5 (insert_record into Alice's collection):`);
  console.log(`  → status=${r.status}, code=${r.body.error?.code} (${r.body.error?.message?.slice(0, 80)})`);
  console.log(`  → ${r.body.error?.code === -32042 ? "✓ BLOCKED" : "✗ COMPROMISED!"}`);
}

// ATTACK 6: try with no envelope at all
{
  const r = await fetch(`${API_URL}/mcp/primitives/read`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "attack-6",
      method: "aithos.data.list_collections",
      params: { subject_did: aliceDid },
    }),
  });
  const body = await r.json();
  console.log(`\nATTACK 6 (no envelope at all):`);
  console.log(`  → status=${r.status}, code=${body.error?.code} (${body.error?.message?.slice(0, 80)})`);
  console.log(`  → ${body.error?.code === -32010 ? "✓ BLOCKED (envelope required)" : "✗ COMPROMISED!"}`);
}

// ATTACK 7: replay a valid envelope (sniff scenario)
{
  const aud = `${API_URL}/mcp/primitives/read`;
  const envelope = signEnvelope({
    iss: aliceDid, aud,
    method: "aithos.data.list_collections",
    params: { subject_did: aliceDid },
    sphereKey: { seed: aliceSeed, verificationMethod: aliceVm },
  });
  // First call — should succeed.
  const r1 = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "attack-7a",
      method: "aithos.data.list_collections",
      params: { subject_did: aliceDid, _envelope: envelope },
    }),
  });
  // Replay the SAME envelope — should be rejected.
  const r2 = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "attack-7b",
      method: "aithos.data.list_collections",
      params: { subject_did: aliceDid, _envelope: envelope },
    }),
  });
  const body2 = await r2.json();
  console.log(`\nATTACK 7 (replay a sniffed valid envelope):`);
  console.log(`  → first call: ${r1.status === 200 ? "OK" : "fail"}`);
  console.log(`  → replay code=${body2.error?.code} (${body2.error?.message?.slice(0, 60)})`);
  console.log(`  → ${body2.error?.code === -32012 ? "✓ BLOCKED (replay cache)" : "✗ COMPROMISED!"}`);
}

// ATTACK 8: change params after signing (params_hash check)
{
  const aud = `${API_URL}/mcp/primitives/read`;
  const envelope = signEnvelope({
    iss: aliceDid, aud,
    method: "aithos.data.list_collections",
    params: { subject_did: aliceDid, limit: 5 },
    sphereKey: { seed: aliceSeed, verificationMethod: aliceVm },
  });
  // Send DIFFERENT params with the signed envelope
  const r = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "attack-8",
      method: "aithos.data.list_collections",
      params: { subject_did: aliceDid, limit: 9999, _envelope: envelope }, // tampered
    }),
  });
  const body = await r.json();
  console.log(`\nATTACK 8 (tamper params after signing — params_hash check):`);
  console.log(`  → code=${body.error?.code} (${body.error?.message?.slice(0, 80)})`);
  console.log(`  → ${body.error?.code === -32010 ? "✓ BLOCKED (params_hash mismatch)" : "✗ COMPROMISED!"}`);
}

console.log("\n=== End of red-team probe ===");
