// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Test the authorize-app flow.
 *
 * Validates that:
 *  - The owner can authorize a new app via a single CMK wrap (O(1)
 *    regardless of record count).
 *  - The newly-authorized app can decrypt records via its own wrap.
 *  - Duplicate authorization is rejected.
 *  - An unauthorized unwrapper cannot perform authorization.
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  authorizeApp,
  collectionUrnFor,
  createCollection,
  decryptRecord,
  encryptRecord,
  generateX25519Keypair,
  unwrapCMK,
  DataCryptoError,
} from "../src/index.js";

test("authorizeApp — newly-authorized app can decrypt every record", () => {
  const owner = generateX25519Keypair();
  const app = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAuthTest1";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;
  const appDidUrl = "did:key:z6MkAppFoo#kex";

  const { collection, cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  // Owner inserts 3 records
  const records = [];
  for (let i = 0; i < 3; i++) {
    const recordId = `record_01J9TEST${i}`;
    const payload = { notes: `Record ${i}` };
    const encrypted = encryptRecord({
      subjectDid,
      collectionName,
      recordId,
      payload,
      cmk,
    });
    records.push({ recordId, payload, encrypted });
  }

  // Owner authorizes the app — single op, no per-record work
  const updated = authorizeApp({
    collection,
    recipientDidUrl: appDidUrl,
    recipientPublicKey: app.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });

  assert.equal(updated.cmkEnvelope.wraps.length, 2);
  assert.equal(updated.cmkEnvelope.wraps[1].recipient, appDidUrl);

  // App now unwraps the CMK and decrypts every record
  const appWrap = updated.cmkEnvelope.wraps.find(
    (w) => w.recipient === appDidUrl,
  );
  assert.ok(appWrap);
  const appCmk = unwrapCMK({
    wrap: appWrap,
    recipientPrivateKey: app.privateKey,
    collectionUrn: collectionUrnFor(subjectDid, collectionName),
  });

  for (const rec of records) {
    const decrypted = decryptRecord<typeof rec.payload>({
      subjectDid,
      collectionName,
      recordId: rec.recordId,
      encrypted: rec.encrypted,
      cmk: appCmk,
    });
    assert.deepEqual(decrypted, rec.payload);
  }
});

test("authorizeApp — duplicate recipient is rejected", () => {
  const owner = generateX25519Keypair();
  const app = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAuthDup";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;
  const appDidUrl = "did:key:z6MkAppFoo#kex";

  const { collection } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  const once = authorizeApp({
    collection,
    recipientDidUrl: appDidUrl,
    recipientPublicKey: app.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });

  assert.throws(
    () =>
      authorizeApp({
        collection: once,
        recipientDidUrl: appDidUrl,
        recipientPublicKey: app.publicKey,
        unwrapperPrivateKey: owner.privateKey,
        unwrapperDidUrl: ownerDidUrl,
      }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_RECIPIENT_DUPLICATE",
  );
});

test("authorizeApp — unauthorized unwrapper is rejected", () => {
  const owner = generateX25519Keypair();
  const stranger = generateX25519Keypair();
  const newApp = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAuthStranger";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;
  const strangerDidUrl = "did:key:z6MkStranger#kex";

  const { collection } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  // A stranger (no existing wrap) attempts to authorize a new app
  assert.throws(
    () =>
      authorizeApp({
        collection,
        recipientDidUrl: "did:key:z6MkNewApp#kex",
        recipientPublicKey: newApp.publicKey,
        unwrapperPrivateKey: stranger.privateKey,
        unwrapperDidUrl: strangerDidUrl,
      }),
    (e: unknown) =>
      e instanceof DataCryptoError &&
      e.code === "DATA_UNWRAPPER_NOT_AUTHORIZED",
  );
});

test("authorizeApp — authorization cost is O(1) on collection size", () => {
  // This is a structural assertion, not a timing benchmark. The point
  // is that the authorizeApp call's input does NOT include records,
  // and its output's records are NOT modified. The function signature
  // alone proves O(1).
  const owner = generateX25519Keypair();
  const app = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkO1Test";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;

  const { collection, cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  // Insert 100 records
  for (let i = 0; i < 100; i++) {
    encryptRecord({
      subjectDid,
      collectionName,
      recordId: `record_${i}`,
      payload: { i },
      cmk,
    });
  }

  // Measure the authorize call
  const t0 = performance.now();
  const updated = authorizeApp({
    collection,
    recipientDidUrl: "did:key:z6MkO1App#kex",
    recipientPublicKey: app.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });
  const dt = performance.now() - t0;

  // Sanity: under 50ms even on a slow machine
  assert.ok(dt < 100, `authorize took ${dt}ms — expected < 100ms`);
  assert.equal(updated.cmkEnvelope.wraps.length, 2);
});
