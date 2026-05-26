// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Envelope replay protection.
 *
 * Stores `<iss>#<nonce>` keys in a small DynamoDB table with TTL on
 * `expires_at_epoch`. The atomic insertion is a conditional PutItem
 * (`attribute_not_exists(pk)`) — the same operation succeeds on first
 * sight and fails on replay.
 *
 * Spec ref: Ethos spec §11.5.
 */

import { PutCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import { ddb, NONCE_TABLE_NAME } from "../deps.js";

export interface AtomicAddNonceInput {
  readonly issuer: string;
  readonly nonce: string;
  /** Envelope expiration (unix seconds). Used for TTL. */
  readonly expiresAtEpoch: number;
}

/**
 * Return `true` if the nonce was just inserted (first sight), `false`
 * if it already exists (replay).
 */
export async function atomicAddNonce(
  input: AtomicAddNonceInput,
): Promise<boolean> {
  const pk = `${input.issuer}#${input.nonce}`;
  // TTL safety: keep a small margin past the envelope's `exp` so the
  // nonce stays in DDB long enough to defeat a late replay.
  const ttl = input.expiresAtEpoch + 60;

  try {
    await ddb.send(
      new PutCommand({
        TableName: NONCE_TABLE_NAME,
        Item: { pk, expires_at_epoch: ttl },
        ConditionExpression: "attribute_not_exists(pk)",
      }),
    );
    return true;
  } catch (e) {
    if (e instanceof ConditionalCheckFailedException) {
      return false;
    }
    throw e;
  }
}
