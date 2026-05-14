// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Collection-level operations: create, authorize a new app, revoke,
 * rotate the CMK.
 *
 * These operations manipulate the wrap list and (optionally) re-wrap
 * record DEKs. They do NOT persist anything — the POC keeps the
 * collection document in memory. The backend (Jalon 3) wraps these
 * primitives in RPC handlers.
 *
 * Spec ref: `spec/data/02-key-hierarchy.md` §§2.3.5, 2.3.6, 2.5.2.
 */

import { generateCMK, unwrapCMK, wrapCMKForRecipient } from "./cmk.js";
import { rewrapRecordDEK } from "./record.js";
import {
  DataCryptoError,
  type CMKEnvelope,
  type CollectionDoc,
  type RecordPayload,
  type WrapEntry,
} from "./types.js";

/* -------------------------------------------------------------------------- */
/*  Create                                                                    */
/* -------------------------------------------------------------------------- */

export interface CreateCollectionInput {
  readonly subjectDid: string;
  readonly collectionName: string;
  readonly schema: string;
  /** DID URL of the owner's `#data-kex` (or equivalent) verification method. */
  readonly ownerRecipientDidUrl: string;
  /** Owner's X25519 public key. */
  readonly ownerPublicKey: Uint8Array;
}

/**
 * Build a collection document with a fresh CMK wrapped for the owner.
 *
 * The resulting CollectionDoc is what the platform would persist as
 * the collection's metadata (modulo the additional server-managed
 * fields like record_count, gamma_ref).
 *
 * The output also includes the CMK in clear (in a separate field)
 * for the caller to use immediately for record encryption. The caller
 * SHOULD zero this CMK once they finish their immediate operations
 * and refetch via unwrapCMK as needed.
 */
export function createCollection(input: CreateCollectionInput): {
  collection: CollectionDoc;
  cmk: Uint8Array;
} {
  const cmk = generateCMK();

  const collectionUrn = collectionUrnFor(input.subjectDid, input.collectionName);

  const ownerWrap = wrapCMKForRecipient({
    cmk,
    recipientPublicKey: input.ownerPublicKey,
    recipientDidUrl: input.ownerRecipientDidUrl,
    collectionUrn,
  });

  const cmkEnvelope: CMKEnvelope = {
    alg: "xchacha20poly1305-ietf",
    wraps: [ownerWrap],
  };

  const collection: CollectionDoc = {
    subjectDid: input.subjectDid,
    collectionName: input.collectionName,
    schema: input.schema,
    createdAt: new Date().toISOString(),
    cmkEnvelope,
  };

  return { collection, cmk };
}

/* -------------------------------------------------------------------------- */
/*  Authorize a new app                                                       */
/* -------------------------------------------------------------------------- */

export interface AuthorizeAppInput {
  /** Current collection document. */
  readonly collection: CollectionDoc;
  /** DID URL of the new recipient (typically `did:key:…#kex` of the app). */
  readonly recipientDidUrl: string;
  /** The new recipient's X25519 public key. */
  readonly recipientPublicKey: Uint8Array;
  /**
   * X25519 private key of an existing authorized recipient (used to
   * unwrap the CMK before re-wrapping for the new recipient). Typically
   * the owner.
   */
  readonly unwrapperPrivateKey: Uint8Array;
  /** DID URL of the unwrapper — must match one of the existing wraps. */
  readonly unwrapperDidUrl: string;
}

/**
 * Add a new recipient to the collection's CMK wrap list.
 *
 * Cost: 1 X25519 keypair generation + 1 ECDH + 1 HKDF + 1 AEAD encrypt
 * for the new wrap, plus 1 ECDH + 1 HKDF + 1 AEAD decrypt to unwrap
 * the CMK. Constant in collection size — this is the O(1) property.
 *
 * Returns the updated collection document. The original is not mutated.
 *
 * Throws if:
 *   - The unwrapper has no wrap in the collection (cannot unwrap).
 *   - The recipient already has a wrap (no duplicates allowed).
 */
export function authorizeApp(input: AuthorizeAppInput): CollectionDoc {
  // Find the unwrapper's wrap
  const collectionUrn = collectionUrnFor(
    input.collection.subjectDid,
    input.collection.collectionName,
  );
  const unwrapperWrap = input.collection.cmkEnvelope.wraps.find(
    (w) => w.recipient === input.unwrapperDidUrl,
  );
  if (!unwrapperWrap) {
    throw new DataCryptoError(
      "DATA_UNWRAPPER_NOT_AUTHORIZED",
      `no existing wrap matches unwrapper "${input.unwrapperDidUrl}"`,
    );
  }

  // Refuse duplicate recipient
  if (
    input.collection.cmkEnvelope.wraps.some(
      (w) => w.recipient === input.recipientDidUrl,
    )
  ) {
    throw new DataCryptoError(
      "DATA_RECIPIENT_DUPLICATE",
      `recipient "${input.recipientDidUrl}" already authorized`,
    );
  }

  // Unwrap CMK using the unwrapper's private key
  const cmk = unwrapCMK({
    wrap: unwrapperWrap,
    recipientPrivateKey: input.unwrapperPrivateKey,
    collectionUrn,
  });

  try {
    // Build the new wrap for the new recipient
    const newWrap = wrapCMKForRecipient({
      cmk,
      recipientPublicKey: input.recipientPublicKey,
      recipientDidUrl: input.recipientDidUrl,
      collectionUrn,
    });

    // Return updated collection
    const newEnvelope: CMKEnvelope = {
      alg: input.collection.cmkEnvelope.alg,
      wraps: [...input.collection.cmkEnvelope.wraps, newWrap],
    };
    return {
      ...input.collection,
      cmkEnvelope: newEnvelope,
    };
  } finally {
    cmk.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Revoke                                                                    */
/* -------------------------------------------------------------------------- */

export interface RevokeAppInput {
  readonly collection: CollectionDoc;
  readonly recipientDidUrl: string;
}

/**
 * Remove a recipient from the wrap list.
 *
 * Does NOT rotate the CMK — the revoked grantee with cached CMK can still
 * decrypt prior ciphertexts they may have copied. For forward secrecy,
 * call `rotateCMK` (separately or as a chained operation).
 *
 * Throws if the collection would end up with zero wraps (the owner must
 * always retain access).
 */
export function revokeApp(input: RevokeAppInput): CollectionDoc {
  const newWraps = input.collection.cmkEnvelope.wraps.filter(
    (w) => w.recipient !== input.recipientDidUrl,
  );

  if (newWraps.length === input.collection.cmkEnvelope.wraps.length) {
    throw new DataCryptoError(
      "DATA_RECIPIENT_NOT_FOUND",
      `recipient "${input.recipientDidUrl}" was not in the wrap list`,
    );
  }
  if (newWraps.length === 0) {
    throw new DataCryptoError(
      "DATA_NO_WRAPS_LEFT",
      `cannot revoke last recipient — collection must have at least one authorized recipient`,
    );
  }

  return {
    ...input.collection,
    cmkEnvelope: {
      alg: input.collection.cmkEnvelope.alg,
      wraps: newWraps,
    },
  };
}

/* -------------------------------------------------------------------------- */
/*  Rotate CMK                                                                */
/* -------------------------------------------------------------------------- */

export interface RotateCMKInput {
  readonly collection: CollectionDoc;
  /** Private keys + DID URLs for all recipients that should remain authorized after rotation. */
  readonly retainedRecipients: readonly RotateRecipient[];
  /**
   * Records to re-wrap. The DEK of each record is unwrapped from the
   * old CMK and re-wrapped under the new CMK. The ciphertext is NOT
   * re-encrypted (best-effort forward secrecy mode; spec §2.3.6).
   */
  readonly records: readonly EncryptedRecordRef[];
  /**
   * The unwrapper for the old CMK. Typically the owner.
   * Must correspond to one of the existing wraps in `collection.cmkEnvelope`.
   */
  readonly unwrapperPrivateKey: Uint8Array;
  readonly unwrapperDidUrl: string;
}

export interface RotateRecipient {
  readonly recipientDidUrl: string;
  readonly recipientPublicKey: Uint8Array;
}

export interface EncryptedRecordRef {
  readonly recordId: string;
  readonly payload: RecordPayload;
}

export interface RotateCMKOutput {
  readonly collection: CollectionDoc;
  readonly records: readonly EncryptedRecordRef[];
}

/**
 * Rotate the CMK. Produces:
 * - A new CMK envelope wrapped for each retained recipient.
 * - Re-wrapped DEKs for every record (ciphertexts unchanged).
 *
 * Cost: O(N) on records (one rewrapRecordDEK per record). Plus
 * O(M) wraps for M retained recipients.
 *
 * Atomicity is the responsibility of the platform — this primitive
 * just produces the new state; persisting it transactionally is
 * outside the POC's scope.
 */
export function rotateCMK(input: RotateCMKInput): RotateCMKOutput {
  const collectionUrn = collectionUrnFor(
    input.collection.subjectDid,
    input.collection.collectionName,
  );

  // Unwrap old CMK
  const oldUnwrapperWrap = input.collection.cmkEnvelope.wraps.find(
    (w) => w.recipient === input.unwrapperDidUrl,
  );
  if (!oldUnwrapperWrap) {
    throw new DataCryptoError(
      "DATA_UNWRAPPER_NOT_AUTHORIZED",
      `no existing wrap for unwrapper "${input.unwrapperDidUrl}"`,
    );
  }
  const oldCmk = unwrapCMK({
    wrap: oldUnwrapperWrap,
    recipientPrivateKey: input.unwrapperPrivateKey,
    collectionUrn,
  });

  try {
    // Fresh CMK
    const newCmk = generateCMK();

    try {
      // New wraps
      const newWraps: WrapEntry[] = input.retainedRecipients.map((r) =>
        wrapCMKForRecipient({
          cmk: newCmk,
          recipientPublicKey: r.recipientPublicKey,
          recipientDidUrl: r.recipientDidUrl,
          collectionUrn,
        }),
      );

      if (newWraps.length === 0) {
        throw new DataCryptoError(
          "DATA_NO_WRAPS_LEFT",
          "rotateCMK requires at least one retained recipient",
        );
      }

      // Re-wrap each record's DEK under the new CMK
      const newRecords: EncryptedRecordRef[] = input.records.map((rec) => ({
        recordId: rec.recordId,
        payload: rewrapRecordDEK({
          subjectDid: input.collection.subjectDid,
          collectionName: input.collection.collectionName,
          recordId: rec.recordId,
          encrypted: rec.payload,
          oldCmk,
          newCmk,
        }),
      }));

      const newCollection: CollectionDoc = {
        ...input.collection,
        cmkEnvelope: {
          alg: input.collection.cmkEnvelope.alg,
          wraps: newWraps,
        },
      };

      return { collection: newCollection, records: newRecords };
    } finally {
      newCmk.fill(0);
    }
  } finally {
    oldCmk.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

export function collectionUrnFor(
  subjectDid: string,
  collectionName: string,
): string {
  return `urn:aithos:collection:${subjectDid}:${collectionName}`;
}
