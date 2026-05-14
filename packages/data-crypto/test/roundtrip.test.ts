// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Test the core encrypt/decrypt roundtrip for a single record.
 *
 * Validates that:
 *  - A CMK can be generated, wrapped for the owner, and unwrapped back.
 *  - A record can be encrypted and decrypted by the owner.
 *  - The decrypted payload matches the original byte-for-byte (after
 *    canonicalization).
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  createCollection,
  encryptRecord,
  decryptRecord,
  generateX25519Keypair,
  unwrapCMK,
  collectionUrnFor,
} from "../src/index.js";

test("CMK roundtrip — owner wraps and unwraps the CMK", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkTestSubject1";
  const collectionName = "contacts";
  const ownerDidUrl = `${subjectDid}#data-kex`;

  const { collection, cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: ownerDidUrl,
    ownerPublicKey: owner.publicKey,
  });

  // Sanity
  assert.equal(cmk.length, 32);
  assert.equal(collection.cmkEnvelope.wraps.length, 1);
  assert.equal(collection.cmkEnvelope.wraps[0].recipient, ownerDidUrl);

  // Unwrap as owner — should match the original CMK
  const recovered = unwrapCMK({
    wrap: collection.cmkEnvelope.wraps[0],
    recipientPrivateKey: owner.privateKey,
    collectionUrn: collectionUrnFor(subjectDid, collectionName),
  });

  assert.equal(recovered.length, 32);
  assert.deepEqual(Array.from(recovered), Array.from(cmk));
});

test("record encrypt + decrypt roundtrip", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkTestSubject2";
  const collectionName = "contacts";

  const { cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const recordId = "record_01J9TESTROUND";
  const payload = {
    notes: "Important prospect met at SaaStr 2026.",
    conversation_log: [
      { at: "2026-05-14T10:00:00Z", from: "user", text: "Hello" },
      { at: "2026-05-14T10:01:00Z", from: "agent", text: "Hi there!" },
    ],
    form_responses: { company_size: "10-50", budget: "20k+" },
  };

  const encrypted = encryptRecord({
    subjectDid,
    collectionName,
    recordId,
    payload,
    cmk,
  });

  assert.equal(encrypted.alg, "xchacha20poly1305-ietf");
  assert.ok(encrypted.nonce.length > 0);
  assert.ok(encrypted.ciphertext.length > 0);
  assert.ok(encrypted.dek_wrapped_for_cmk.length > 0);

  const decrypted = decryptRecord<typeof payload>({
    subjectDid,
    collectionName,
    recordId,
    encrypted,
    cmk,
  });

  assert.deepEqual(decrypted, payload);
});

test("record with empty payload", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkTestEmpty";
  const collectionName = "contacts";

  const { cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const recordId = "record_01J9EMPTY";
  const payload = {};

  const encrypted = encryptRecord({
    subjectDid,
    collectionName,
    recordId,
    payload,
    cmk,
  });

  const decrypted = decryptRecord({
    subjectDid,
    collectionName,
    recordId,
    encrypted,
    cmk,
  });

  assert.deepEqual(decrypted, payload);
});

test("record with large payload (10 KB) roundtrip", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkTestBig";
  const collectionName = "contacts";

  const { cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const recordId = "record_01J9BIG";
  const big = "A".repeat(10_000);
  const payload = { notes: big };

  const encrypted = encryptRecord({
    subjectDid,
    collectionName,
    recordId,
    payload,
    cmk,
  });

  const decrypted = decryptRecord<typeof payload>({
    subjectDid,
    collectionName,
    recordId,
    encrypted,
    cmk,
  });

  assert.equal(decrypted.notes, big);
});
