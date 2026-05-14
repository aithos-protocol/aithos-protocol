// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Microbenchmark suite for @aithos/data-crypto.
 *
 * Run with: npm run bench
 *
 * Reports the per-operation latency of the constructions described in
 * spec/data/02-key-hierarchy.md, so we can confirm:
 *  - Authorize/revoke cost is O(1) on collection size.
 *  - Record encrypt/decrypt is fast enough for interactive UIs.
 *  - CMK rotation cost scales linearly in N records.
 */

import {
  authorizeApp,
  createCollection,
  decryptRecord,
  encryptRecord,
  generateX25519Keypair,
  rotateCMK,
  unwrapCMK,
  collectionUrnFor,
} from "../src/index.js";

function bench(name: string, iters: number, fn: () => void): void {
  // Warmup
  for (let i = 0; i < Math.min(iters, 10); i++) fn();
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) fn();
  const dt = performance.now() - t0;
  const perOp = dt / iters;
  console.log(
    `  ${name.padEnd(50)} ${perOp.toFixed(3)} ms/op  (${iters} iters, ${dt.toFixed(1)} ms total)`,
  );
}

const owner = generateX25519Keypair();
const app = generateX25519Keypair();
const subjectDid = "did:aithos:z6MkBench";
const collectionName = "contacts";
const ownerDidUrl = `${subjectDid}#data-kex`;
const appDidUrl = "did:key:z6MkBenchApp#kex";

const { collection, cmk } = createCollection({
  subjectDid,
  collectionName,
  schema: "aithos.contacts.v1",
  ownerRecipientDidUrl: ownerDidUrl,
  ownerPublicKey: owner.publicKey,
});

console.log("\n=== @aithos/data-crypto — benchmark ===\n");
console.log("Platform:", process.platform, "node", process.version, "\n");

console.log("CMK level");
bench("createCollection (with first wrap)", 100, () => {
  createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });
});

bench("unwrap CMK (owner)", 1000, () => {
  unwrapCMK({
    wrap: collection.cmkEnvelope.wraps[0],
    recipientPrivateKey: owner.privateKey,
    collectionUrn: collectionUrnFor(subjectDid, collectionName),
  });
});

console.log("\nAuthorize / revoke");
bench("authorizeApp (O(1) — independent of N records)", 100, () => {
  authorizeApp({
    collection,
    recipientDidUrl: `did:key:z6MkBenchAppN${Math.random()}#kex`,
    recipientPublicKey: app.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });
});

console.log("\nRecord level — payloads of various sizes");
const sizes = [
  { label: "100 B  (typical contact summary)", body: "x".repeat(100) },
  { label: "1 KB   (short note)", body: "x".repeat(1_000) },
  { label: "10 KB  (long conversation log)", body: "x".repeat(10_000) },
  { label: "100 KB (very long form response)", body: "x".repeat(100_000) },
];

for (const s of sizes) {
  const payload = { body: s.body };
  let encrypted = encryptRecord({
    subjectDid,
    collectionName,
    recordId: "record_01J9BENCH",
    payload,
    cmk,
  });
  bench(`encrypt ${s.label}`, 200, () => {
    encrypted = encryptRecord({
      subjectDid,
      collectionName,
      recordId: "record_01J9BENCH",
      payload,
      cmk,
    });
  });
  bench(`decrypt ${s.label}`, 200, () => {
    decryptRecord({
      subjectDid,
      collectionName,
      recordId: "record_01J9BENCH",
      encrypted,
      cmk,
    });
  });
}

console.log("\nCMK rotation — cost scales O(N) on records");
for (const n of [10, 100, 1000]) {
  // Setup: n records
  const records: { recordId: string; payload: ReturnType<typeof encryptRecord> }[] =
    [];
  for (let i = 0; i < n; i++) {
    const recordId = `record_01J9R${i}`;
    records.push({
      recordId,
      payload: encryptRecord({
        subjectDid,
        collectionName,
        recordId,
        payload: { body: "x".repeat(1000) },
        cmk,
      }),
    });
  }
  bench(`rotateCMK with ${n.toString().padStart(4)} records`, 5, () => {
    rotateCMK({
      collection,
      retainedRecipients: [
        { recipientDidUrl: ownerDidUrl, recipientPublicKey: owner.publicKey },
      ],
      records,
      unwrapperPrivateKey: owner.privateKey,
      unwrapperDidUrl: ownerDidUrl,
    });
  });
}

console.log("\nDone.\n");
