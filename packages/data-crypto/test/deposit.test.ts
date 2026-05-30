// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Append-only deposit round-trip and isolation tests.
 *
 * The deposit path seals each record's DEK to the OWNER's X25519 public
 * key (not the collection CMK). This proves:
 *  - the owner can read a deposit with its #data-kex private key;
 *  - a depositor holding only the owner's PUBLIC key can write but cannot
 *    read (no CMK, DEK discarded);
 *  - two depositors cannot read each other's deposits;
 *  - AAD binds the wrap to (subject, collection, record, recipient) — any
 *    mismatch fails closed;
 *  - the CMK read path and the deposit read path reject each other's
 *    record shapes with a precise error.
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";

import {
  decryptDepositedRecord,
  decryptRecord,
  encryptRecord,
  encryptRecordForRecipient,
  generateCMK,
  generateX25519Keypair,
  wrapDEKForRecipient,
  unwrapDEKForRecipient,
  generateDEK,
  DataCryptoError,
} from "../src/index.js";

const SUBJECT = "did:aithos:z6MkOwnerPraticien";
const COLLECTION = "mandats_patients";
const KEX_URL = `${SUBJECT}#data-kex`;

test("owner reads a deposit sealed to its public key", () => {
  const owner = generateX25519Keypair();
  const recordId = "record_01J0DEPOSIT0001";
  const payload = { kind: "ethos-mandate", value: "secret-bundle" };

  const enc = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId,
    payload,
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });

  assert.equal(enc.dek_wrapped_for_cmk, undefined);
  assert.ok(enc.dek_wrapped_for_owner, "deposit carries dek_wrapped_for_owner");

  const out = decryptDepositedRecord<typeof payload>({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId,
    encrypted: enc,
    recipientPrivateKey: owner.privateKey,
  });
  assert.deepEqual(out, payload);
});

test("a different key cannot open a deposit (depositor/operator is blind)", () => {
  const owner = generateX25519Keypair();
  const intruder = generateX25519Keypair();
  const recordId = "record_01J0DEPOSIT0002";

  const enc = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId,
    payload: { x: 1 },
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });

  assert.throws(
    () =>
      decryptDepositedRecord({
        subjectDid: SUBJECT,
        collectionName: COLLECTION,
        recordId,
        encrypted: enc,
        recipientPrivateKey: intruder.privateKey,
      }),
    (e: unknown) => e instanceof DataCryptoError,
  );
});

test("two depositors cannot read each other's deposits", () => {
  // Both deposit to the SAME owner collection; neither holds the owner key.
  const owner = generateX25519Keypair();
  const encA = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_A",
    payload: { who: "A" },
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });
  const encB = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_B",
    payload: { who: "B" },
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });
  // Owner reads both.
  assert.deepEqual(
    decryptDepositedRecord({
      subjectDid: SUBJECT,
      collectionName: COLLECTION,
      recordId: "record_A",
      encrypted: encA,
      recipientPrivateKey: owner.privateKey,
    }),
    { who: "A" },
  );
  assert.deepEqual(
    decryptDepositedRecord({
      subjectDid: SUBJECT,
      collectionName: COLLECTION,
      recordId: "record_B",
      encrypted: encB,
      recipientPrivateKey: owner.privateKey,
    }),
    { who: "B" },
  );
});

test("AAD binds the deposit to (collection, record) — mismatch fails", () => {
  const owner = generateX25519Keypair();
  const enc = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_bound",
    payload: { x: 1 },
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });
  // Wrong record id.
  assert.throws(() =>
    decryptDepositedRecord({
      subjectDid: SUBJECT,
      collectionName: COLLECTION,
      recordId: "record_OTHER",
      encrypted: enc,
      recipientPrivateKey: owner.privateKey,
    }),
  );
  // Wrong collection.
  assert.throws(() =>
    decryptDepositedRecord({
      subjectDid: SUBJECT,
      collectionName: "other_collection",
      recordId: "record_bound",
      encrypted: enc,
      recipientPrivateKey: owner.privateKey,
    }),
  );
});

test("DEK wrap-to-recipient round-trips on its own", () => {
  const owner = generateX25519Keypair();
  const dek = generateDEK();
  const wrap = wrapDEKForRecipient({
    dek,
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_w",
  });
  const back = unwrapDEKForRecipient({
    wrap,
    recipientPrivateKey: owner.privateKey,
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_w",
  });
  assert.deepEqual(back, dek);
});

test("CMK path and deposit path reject each other's record shapes", () => {
  const owner = generateX25519Keypair();
  const cmk = generateCMK();

  // A CMK-wrapped record cannot be read as a deposit.
  const cmkRec = encryptRecord({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_cmk",
    payload: { a: 1 },
    cmk,
  });
  assert.throws(
    () =>
      decryptDepositedRecord({
        subjectDid: SUBJECT,
        collectionName: COLLECTION,
        recordId: "record_cmk",
        encrypted: cmkRec,
        recipientPrivateKey: owner.privateKey,
      }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_RECORD_NOT_DEPOSIT",
  );

  // A deposit cannot be read with the CMK path.
  const depRec = encryptRecordForRecipient({
    subjectDid: SUBJECT,
    collectionName: COLLECTION,
    recordId: "record_dep",
    payload: { a: 1 },
    recipientPublicKey: owner.publicKey,
    recipientDidUrl: KEX_URL,
  });
  assert.throws(
    () =>
      decryptRecord({
        subjectDid: SUBJECT,
        collectionName: COLLECTION,
        recordId: "record_dep",
        encrypted: depRec,
        cmk,
      }),
    (e: unknown) =>
      e instanceof DataCryptoError && e.code === "DATA_RECORD_NOT_CMK_WRAPPED",
  );
});
