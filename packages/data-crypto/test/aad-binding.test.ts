// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AAD binding enforcement tests.
 *
 * The AEAD additional-data binds ciphertexts to their context:
 *  - CMK wrap: (collection_urn, recipient_did_url)
 *  - DEK wrap: (subject_did, collection_name, record_id)
 *  - Record payload: (subject_did, collection_name, record_id)
 *
 * These tests prove that mismatched context causes decryption to fail
 * with an authenticated error rather than producing wrong plaintext.
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  collectionUrnFor,
  createCollection,
  decryptRecord,
  encryptRecord,
  generateX25519Keypair,
  unwrapCMK,
  DataCryptoError,
} from "../src/index.js";

test("AAD — cross-record ciphertext cannot be decrypted as another record", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAAD1";
  const collectionName = "contacts";

  const { cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const encryptedA = encryptRecord({
    subjectDid,
    collectionName,
    recordId: "record_01J9A",
    payload: { notes: "A" },
    cmk,
  });

  // Attempt to decrypt with the wrong recordId
  assert.throws(
    () =>
      decryptRecord({
        subjectDid,
        collectionName,
        recordId: "record_01J9B",
        encrypted: encryptedA,
        cmk,
      }),
    (e: unknown) => e instanceof DataCryptoError,
  );
});

test("AAD — cross-collection ciphertext cannot be decrypted as another collection", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAADCol";

  const { cmk: cmkA } = createCollection({
    subjectDid,
    collectionName: "contacts",
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const encrypted = encryptRecord({
    subjectDid,
    collectionName: "contacts",
    recordId: "record_01J9CROSS",
    payload: { notes: "in contacts" },
    cmk: cmkA,
  });

  // Even with the SAME cmk (which won't happen in practice — different
  // collections have different CMKs — but tests the AAD binding directly):
  // decrypt with mismatched collectionName must fail
  assert.throws(
    () =>
      decryptRecord({
        subjectDid,
        collectionName: "messages",
        recordId: "record_01J9CROSS",
        encrypted,
        cmk: cmkA,
      }),
    (e: unknown) => e instanceof DataCryptoError,
  );
});

test("AAD — cross-subject ciphertext cannot be decrypted under another subject", () => {
  const owner = generateX25519Keypair();
  const subjectA = "did:aithos:z6MkSubjA";
  const subjectB = "did:aithos:z6MkSubjB";

  const { cmk } = createCollection({
    subjectDid: subjectA,
    collectionName: "contacts",
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectA}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const encrypted = encryptRecord({
    subjectDid: subjectA,
    collectionName: "contacts",
    recordId: "record_01J9XSUBJ",
    payload: { notes: "for subject A" },
    cmk,
  });

  assert.throws(
    () =>
      decryptRecord({
        subjectDid: subjectB,
        collectionName: "contacts",
        recordId: "record_01J9XSUBJ",
        encrypted,
        cmk,
      }),
    (e: unknown) => e instanceof DataCryptoError,
  );
});

test("AAD — CMK wrap from one collection cannot be unwrapped as another", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkAADCMK";

  const { collection: collA } = createCollection({
    subjectDid,
    collectionName: "contacts",
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  // Attempt to unwrap with a different collection URN
  const wrongCollectionUrn = collectionUrnFor(subjectDid, "messages");
  assert.throws(
    () =>
      unwrapCMK({
        wrap: collA.cmkEnvelope.wraps[0],
        recipientPrivateKey: owner.privateKey,
        collectionUrn: wrongCollectionUrn,
      }),
    (e: unknown) => e instanceof DataCryptoError,
  );
});

test("AAD — tampered ciphertext is rejected", () => {
  const owner = generateX25519Keypair();
  const subjectDid = "did:aithos:z6MkTamper";
  const collectionName = "contacts";

  const { cmk } = createCollection({
    subjectDid,
    collectionName,
    schema: "aithos.contacts.v1",
    ownerRecipientDidUrl: `${subjectDid}#data-kex`,
    ownerPublicKey: owner.publicKey,
  });

  const encrypted = encryptRecord({
    subjectDid,
    collectionName,
    recordId: "record_01J9TAMPER",
    payload: { notes: "honest" },
    cmk,
  });

  // Flip one byte in the ciphertext
  const ctBytes = Buffer.from(encrypted.ciphertext, "base64");
  ctBytes[Math.floor(ctBytes.length / 2)] ^= 0xff;
  const tampered = {
    ...encrypted,
    ciphertext: ctBytes.toString("base64"),
  };

  assert.throws(
    () =>
      decryptRecord({
        subjectDid,
        collectionName,
        recordId: "record_01J9TAMPER",
        encrypted: tampered,
        cmk,
      }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_RECORD_DECRYPT_FAILED",
  );
});
