// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Revoke + rotateCMK flows.
 *
 * Validates that:
 *  - Revoking an app removes its wrap. The revoked app, even with the
 *    previously-unwrapped CMK in hand, cannot fetch new records from
 *    a PDS that enforces the wrap list (this test simulates only the
 *    crypto layer).
 *  - rotateCMK produces a new CMK envelope. The revoked app, even with
 *    the OLD CMK cached, cannot decrypt records that have been re-wrapped
 *    under the new CMK.
 *  - Retained recipients (owner, other apps) can decrypt under the new
 *    CMK.
 *  - Re-wrapping a record preserves the ciphertext bytes exactly.
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
  revokeApp,
  rotateCMK,
  unwrapCMK,
  DataCryptoError,
} from "../src/index.js";

test("revoke — removes wrap from envelope", () => {
  const owner = generateX25519Keypair();
  const app = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkRevoke1";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;
  const appDidUrl = "did:key:z6MkRevokeApp#kex";

  const { collection } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  const withApp = authorizeApp({
    collection,
    recipientDidUrl: appDidUrl,
    recipientPublicKey: app.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });
  assert.equal(withApp.cmkEnvelope.wraps.length, 2);

  const revoked = revokeApp({ collection: withApp, recipientDidUrl: appDidUrl });
  assert.equal(revoked.cmkEnvelope.wraps.length, 1);
  assert.equal(revoked.cmkEnvelope.wraps[0].recipient, ownerDidUrl);
});

test("revoke — cannot revoke the last recipient", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkRevokeLast";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;

  const { collection } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  assert.throws(
    () => revokeApp({ collection, recipientDidUrl: ownerDidUrl }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_NO_WRAPS_LEFT",
  );
});

test("revoke — recipient not found is an error", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkRevokeMissing";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;

  const { collection } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  assert.throws(
    () =>
      revokeApp({
        collection,
        recipientDidUrl: "did:key:z6MkNeverThere#kex",
      }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_RECIPIENT_NOT_FOUND",
  );
});

test("rotateCMK — revoked app with old CMK cannot decrypt new wraps", () => {
  const owner = generateX25519Keypair();
  const goodApp = generateX25519Keypair();
  const badApp = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkRotateAuth";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;
  const goodAppDidUrl = "did:key:z6MkGood#kex";
  const badAppDidUrl = "did:key:z6MkBad#kex";

  // Setup: owner + goodApp + badApp all authorized
  let { collection, cmk: initialCmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });
  collection = authorizeApp({
    collection,
    recipientDidUrl: goodAppDidUrl,
    recipientPublicKey: goodApp.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });
  collection = authorizeApp({
    collection,
    recipientDidUrl: badAppDidUrl,
    recipientPublicKey: badApp.publicKey,
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });

  // Insert 3 records using the initial CMK
  const recordIds = ["record_01J9R1", "record_01J9R2", "record_01J9R3"];
  const records = recordIds.map((recordId) => ({
    recordId,
    payload: { notes: `Hello ${recordId}` },
    encrypted: encryptRecord({
      subjectDid,
      collectionName,
      recordId,
      payload: { notes: `Hello ${recordId}` },
      cmk: initialCmk,
    }),
  }));

  // badApp obtains its CMK by unwrapping (cached)
  const badAppWrap = collection.cmkEnvelope.wraps.find(
    (w) => w.recipient === badAppDidUrl,
  );
  assert.ok(badAppWrap);
  const cachedBadCmk = unwrapCMK({
    wrap: badAppWrap,
    recipientPrivateKey: badApp.privateKey,
    collectionUrn: collectionUrnFor(subjectDid, collectionName),
  });

  // badApp verifies it can decrypt initially (sanity)
  for (const rec of records) {
    const decrypted = decryptRecord<typeof rec.payload>({
      subjectDid,
      collectionName,
      recordId: rec.recordId,
      encrypted: rec.encrypted,
      cmk: cachedBadCmk,
    });
    assert.deepEqual(decrypted, rec.payload);
  }

  // Revoke badApp and rotate
  const revoked = revokeApp({ collection, recipientDidUrl: badAppDidUrl });
  const rotated = rotateCMK({
    collection: revoked,
    retainedRecipients: [
      { recipientDidUrl: ownerDidUrl, recipientPublicKey: owner.publicKey },
      {
        recipientDidUrl: goodAppDidUrl,
        recipientPublicKey: goodApp.publicKey,
      },
    ],
    records: records.map((r) => ({
      recordId: r.recordId,
      payload: r.encrypted,
    })),
    unwrapperPrivateKey: owner.privateKey,
    unwrapperDidUrl: ownerDidUrl,
  });

  // After rotation: the wrap list contains only owner + goodApp
  assert.equal(rotated.collection.cmkEnvelope.wraps.length, 2);
  assert.ok(
    !rotated.collection.cmkEnvelope.wraps.some(
      (w) => w.recipient === badAppDidUrl,
    ),
  );

  // The records have the SAME ciphertext (best-effort forward secrecy
  // mode — only DEK wraps change). Verify byte equality.
  for (let i = 0; i < records.length; i++) {
    assert.equal(rotated.records[i].payload.ciphertext, records[i].encrypted.ciphertext);
    assert.equal(rotated.records[i].payload.nonce, records[i].encrypted.nonce);
    // dek_wrapped_for_cmk MUST differ (new CMK)
    assert.notEqual(
      rotated.records[i].payload.dek_wrapped_for_cmk,
      records[i].encrypted.dek_wrapped_for_cmk,
    );
  }

  // badApp with its cached OLD CMK CANNOT decrypt the rotated records
  // because the DEK is now wrapped under a new CMK.
  for (const rec of rotated.records) {
    assert.throws(
      () =>
        decryptRecord({
          subjectDid,
          collectionName,
          recordId: rec.recordId,
          encrypted: rec.payload,
          cmk: cachedBadCmk,
        }),
      (e: unknown) =>
        e instanceof DataCryptoError && e.code === "DATA_DEK_DECRYPT_FAILED",
    );
  }

  // goodApp, holding a wrap of the new CMK, CAN decrypt
  const goodAppWrapNew = rotated.collection.cmkEnvelope.wraps.find(
    (w) => w.recipient === goodAppDidUrl,
  );
  assert.ok(goodAppWrapNew);
  const newGoodCmk = unwrapCMK({
    wrap: goodAppWrapNew,
    recipientPrivateKey: goodApp.privateKey,
    collectionUrn: collectionUrnFor(subjectDid, collectionName),
  });
  for (let i = 0; i < records.length; i++) {
    const decrypted = decryptRecord<typeof records[number]["payload"]>({
      subjectDid,
      collectionName,
      recordId: rotated.records[i].recordId,
      encrypted: rotated.records[i].payload,
      cmk: newGoodCmk,
    });
    assert.deepEqual(decrypted, records[i].payload);
  }
});
